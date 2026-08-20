<?php

declare(strict_types=1);

namespace AdGo\Cluster\Controllers;

use AdGo\Cluster\CapabilityChecker;
use AdGo\Cluster\Cluster;
use AdGo\Cluster\RemoteTestQueue;
use CodeIgniter\Controller;
use CodeIgniter\HTTP\ResponseInterface;

/**
 * Server side of the NAT-safe remote connection-test relay - lets
 * cluster-ui's Settings -> Nodes/Databases "test" badge actually run a
 * check ON the target node itself, using data handed over the wire
 * (host/port/user/pass/database), rather than from wherever the admin's
 * browser session happens to be connected. See DbConnectionChecker/
 * NodeConnectionChecker's own checkParams() for why this must run on the
 * TARGET's own local network position: a Databases row's host is often
 * something like 127.0.0.1, meaningful only from that specific node.
 *
 * Two shapes, matching this cluster's own public/nat split (see README
 * "NAT pulling"):
 *
 * - PUBLIC target: reachable directly. cluster-ui calls testConnection()
 *   on the target node's own base URL with a signed request; the target
 *   runs the check right there and returns the result in the same
 *   response. Synchronous, same round-trip shape as cluster/time.
 *
 * - NAT target: NOT reachable directly, ever ("nothing can push IN to it,
 *   it pulls instead" - this project's own load-bearing rule). The
 *   requesting node instead ENQUEUES the request locally (RemoteTestQueue)
 *   and tells cluster-ui to poll for a result. The NAT node's own
 *   cluster:pull cycle - which already asks each public peer in turn for
 *   files/invalidations/db-rows every run - also asks pullTestRequests()
 *   here, claims whatever's addressed to it, runs the check locally
 *   (PullSync::pullTestRequests()), and reports back via testResult().
 *   Latency is bounded by that pull cadence, not instant - see this
 *   package's docs "Remote connection testing" section for the honest
 *   timing story.
 */
class RemoteTestController extends Controller
{
    /**
     * Public-target path: run a check right here, right now, and return
     * the result directly. Body: {"kind": "database"|"node", ...params}
     * - params match whichever checker CapabilityChecker::run() resolves
     * $kind to, since this just hands the decoded body straight through -
     * see that class's own docblock for why dispatch lives there and not
     * duplicated here.
     */
    public function testConnection(): ResponseInterface
    {
        $body = json_decode($this->request->getBody(), true);
        if (! is_array($body)) {
            return $this->response->setStatusCode(400)->setJSON(['ok' => false, 'error' => 'invalid body']);
        }

        $kind = (string) ($body['kind'] ?? '');

        return $this->response->setJSON((new CapabilityChecker())->run($kind, $body));
    }

    /**
     * NAT-target path, step 1: a NAT node's own pull cycle asks "what's
     * pending for me" - the caller's identity comes from its OWN verified
     * signature (Cluster::verifiedCallerName()), never a request
     * parameter, so one node can never read another's queued test
     * requests just by claiming to be them. Claiming (not just reading)
     * is deliberate - see RemoteTestQueue::claimPending()'s own docblock.
     */
    public function pullTestRequests(): ResponseInterface
    {
        $header = $this->request->getHeaderLine('Authorization');
        if ($header === '') {
            $header = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        }

        $callerName = (new Cluster())->verifiedCallerName($header);
        if ($callerName === null) {
            // Legacy bare-secret callers (no identity - see
            // verifiedCallerName()'s own docblock) simply never see
            // pending work through this endpoint; ClusterAuthFilter has
            // already let the request through, so this is "nothing for
            // you" rather than a second auth rejection.
            return $this->response->setJSON(['requests' => []]);
        }

        $claimed = (new RemoteTestQueue())->claimPending($callerName);

        return $this->response->setJSON(['requests' => $claimed]);
    }

    /**
     * NAT-target path, step 2: the NAT node reports back what it found
     * running a claimed request locally. Any signed cluster member may
     * post a result (same trust level ClusterAuthFilter already grants
     * every other cluster/* route) - the requestId itself is an
     * unguessable 16-byte hex token (see SettingsController's own
     * dispatchTest()), so there's nothing to gain by posting a result for
     * one you didn't legitimately claim.
     */
    public function testResult(): ResponseInterface
    {
        $body = json_decode($this->request->getBody(), true);
        if (! is_array($body) || ! isset($body['requestId'], $body['result']) || ! is_array($body['result'])) {
            return $this->response->setStatusCode(400)->setJSON(['ok' => false, 'error' => 'invalid body']);
        }

        (new RemoteTestQueue())->recordResult((string) $body['requestId'], $body['result']);

        return $this->response->setJSON(['ok' => true]);
    }
}

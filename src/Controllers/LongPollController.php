<?php

declare(strict_types=1);

namespace AdGo\Cluster\Controllers;

use AdGo\Cluster\Cluster;
use AdGo\Cluster\DbManifest;
use AdGo\Cluster\DbSyncSchema;
use AdGo\Cluster\DeletedFiles;
use AdGo\Cluster\RemoteTestQueue;
use AdGo\Cluster\SessionInvalidation;
use CodeIgniter\Controller;
use CodeIgniter\HTTP\ResponseInterface;

/**
 * Server side of the long-poll pull path - a NAT node's alternative to the
 * older once-a-minute cluster:pull (still supported, unchanged - see
 * PullCommand). Instead of five separate since-scoped GETs (invalidations/
 * files/deletions/db-rows/test-requests), the NAT node opens ONE connection
 * and this holds it for up to HOLD_SECONDS, checking every second whether
 * ANY channel has something new, replying the instant one does (or with an
 * empty/timedOut body once the hold expires). Cuts worst-case relay latency
 * for a NAT-to-NAT hop (see Cluster::manifestSince()'s own docblock on why
 * that hop exists at all) from "up to a full pull cadence" to "up to one
 * second", without needing the NAT node to make a new HTTP request every
 * second - a session it already holds open is the "incoming channel"
 * (server-initiated push into a NAT node is impossible by definition - it
 * has no reachable address, which is the entire reason this relay exists -
 * so this is the closest achievable inversion: one held connection instead
 * of many repeated ones).
 *
 * HOLD_SECONDS=28 stays safely under the tightest real max_execution_time
 * this cluster actually has (beta/upz: 30s, verified live 2026-08-20 - a
 * real 28s streaming response survived intact on both, flushed correctly
 * every second, not buffered by any front-end proxy).
 */
class LongPollController extends Controller
{
    private const HOLD_SECONDS = 28;

    // Bounded burst of this node's OWN outbound queue at the start of
    // every long-poll request - "a direct node starts the queue as soon
    // as the request comes in", decoupled from waiting for this node's
    // own next cron-triggered tasks:run tick. Capped in both job count and
    // wall-clock time so it can never eat meaningfully into the hold
    // budget above - a slow/stuck job should block THIS node's queue by
    // at most a few seconds, not the whole long-poll window.
    private const QUEUE_BURST_MAX_SECONDS = 3;
    private const QUEUE_BURST_MAX_JOBS    = 5;

    public function poll(): ResponseInterface
    {
        $header = $this->request->getHeaderLine('Authorization');
        if ($header === '') {
            $header = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        }

        $cluster    = new Cluster();
        $callerName = $cluster->verifiedCallerName($header);
        if ($callerName === null) {
            // ClusterAuthFilter already let this through (a legacy bare-
            // secret caller has no identity to claim test-requests under -
            // see RemoteTestController::pullTestRequests()'s own docblock,
            // same reasoning applies here) - "nothing for you" rather than
            // a second auth rejection.
            return $this->response->setJSON(['ok' => true, 'timedOut' => true] + $this->emptyPayload());
        }

        $this->burstOwnQueue();

        $since    = (int) $this->request->getPost('since');
        $deadline = microtime(true) + self::HOLD_SECONDS;

        while (true) {
            $payload = $this->collectPending($cluster, $callerName, $since);
            if ($this->hasAny($payload)) {
                return $this->response->setJSON(['ok' => true, 'timedOut' => false] + $payload);
            }
            if (microtime(true) >= $deadline) {
                break;
            }
            sleep(1);
        }

        return $this->response->setJSON(['ok' => true, 'timedOut' => true] + $this->emptyPayload());
    }

    /**
     * @return array{invalidations: array<string,int>, files: array<string,array>, deletions: array<string,int>, dbRows: list<array>, testRequests: list<array>}
     */
    private function collectPending(Cluster $cluster, string $callerName, int $since): array
    {
        $db = db_connect('default');

        return [
            'invalidations' => (new SessionInvalidation())->allSince($since),
            'files'         => $cluster->manifestSince($since),
            'deletions'     => (new DeletedFiles())->allSince($since),
            'dbRows'        => DbSyncSchema::collectRowsSince($db, new DbManifest(), $since),
            // Claims (read-and-clears - see RemoteTestQueue::claimPending()'s
            // own docblock) on every tick, not just the first: harmless
            // no-op when nothing's queued, and means a test request queued
            // WHILE this same long-poll is already waiting still gets
            // caught before the hold expires, not just on the next call.
            'testRequests'  => (new RemoteTestQueue())->claimPending($callerName),
        ];
    }

    private function hasAny(array $payload): bool
    {
        foreach ($payload as $channel) {
            if ($channel !== []) {
                return true;
            }
        }

        return false;
    }

    private function emptyPayload(): array
    {
        return ['invalidations' => [], 'files' => [], 'deletions' => [], 'dbRows' => [], 'testRequests' => []];
    }

    private function burstOwnQueue(): void
    {
        $queueName = (new Cluster())->queueName();
        $cmd       = 'php ' . escapeshellarg(ROOTPATH . 'spark') . ' queue:work ' . escapeshellarg($queueName)
            . ' --stop-when-empty -max-jobs ' . self::QUEUE_BURST_MAX_JOBS . ' -max-time ' . self::QUEUE_BURST_MAX_SECONDS;

        $proc = @proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (! is_resource($proc)) {
            return; // best-effort - the normal cron-triggered tasks:run still covers this node's queue regardless
        }
        // Bounded from the OUTSIDE too, not just via the child's own
        // -max-time - a child that ignores/mishandles that flag (a stuck
        // job, an unexpectedly slow environment) must never be able to
        // block this request past its own budget. proc_terminate() is a
        // SIGTERM, not a guaranteed-instant kill, but combined with the
        // child's own -max-time this is enough to keep the worst case
        // bounded to roughly QUEUE_BURST_MAX_SECONDS either way.
        $start = microtime(true);
        while (microtime(true) - $start < self::QUEUE_BURST_MAX_SECONDS + 1) {
            $status = proc_get_status($proc);
            if (! $status['running']) {
                break;
            }
            usleep(100000);
        }
        if (is_resource($proc)) {
            $status = proc_get_status($proc);
            if ($status['running']) {
                @proc_terminate($proc);
            }
        }
        foreach ($pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }
        if (is_resource($proc)) {
            @proc_close($proc);
        }
    }
}

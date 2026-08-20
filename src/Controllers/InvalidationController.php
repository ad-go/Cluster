<?php

declare(strict_types=1);

namespace AdGo\Cluster\Controllers;

use AdGo\Cluster\SessionInvalidation;
use CodeIgniter\Controller;
use CodeIgniter\HTTP\ResponseInterface;

/**
 * Receives a password-change broadcast from a peer
 * (BroadcastInvalidationJob on the sending side). Auth is the
 * ClusterAuthFilter (Bearer token), not Shield - this is node-to-node
 * traffic, never a logged-in user's browser request. Excluded from CSRF
 * (see app/Config/Filters.php's csrf except list) - a Bearer-token API
 * has no session to forge.
 */
class InvalidationController extends Controller
{
    public function receive(): ResponseInterface
    {
        // 503, not a silent 200 - a sender's BroadcastInvalidationJob
        // treats any non-2xx as a failure and retries on its own schedule
        // (BaseJob::$tries/$retryAfter), so a temporarily-disabled node
        // still catches up once cluster.sessionSyncEnabled goes back to
        // true, instead of the broadcast being silently dropped forever.
        if (! config('Cluster')->sessionSyncEnabled) {
            return $this->response->setStatusCode(503)->setJSON(['error' => 'session sync disabled on this node']);
        }

        $email     = (string) $this->request->getPost('email');
        $changedAt = (int) $this->request->getPost('changedAt');

        if ($email === '' || $changedAt <= 0) {
            return $this->response->setStatusCode(400)->setJSON(['error' => 'missing email or changedAt']);
        }

        (new SessionInvalidation())->recordInvalidation($email, $changedAt);

        return $this->response->setJSON(['ok' => true]);
    }
}

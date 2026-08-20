<?php

declare(strict_types=1);

namespace AdGo\Cluster\Filters;

use AdGo\Cluster\SessionInvalidation;
use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;

/**
 * Kills a session the moment its email's password has changed anywhere in
 * the cluster (see Cluster::broadcastPasswordChange()) - registered as a
 * GLOBAL 'before' filter (app/Config/Filters.php's $globals, not a
 * per-route alias) so every request checks this, not just the ones a
 * route author remembered to tag.
 *
 * Deliberately runs BEFORE Shield's own per-route 'session' filter: CI4
 * runs $globals['before'] ahead of route-specific before-filters, so
 * calling auth()->logout() here means Shield's OWN filter (on whichever
 * route this request actually hits) sees "not logged in" on the SAME
 * request and handles the normal redirect-to-login itself - this filter
 * never needs to duplicate that redirect logic.
 *
 * Registered as an app-level filter (see this package's README) - not
 * auto-applied, same reasoning as ClusterAuthFilter: a package can't
 * safely assume it owns the app's whole Filters.php. Assumes Shield's
 * auth()/session() helpers are available at runtime (same assumption
 * SsoController::start() already makes) - never reached otherwise, since
 * it's a no-op for a request with no logged-in Shield user at all.
 */
class SessionInvalidationFilter implements FilterInterface
{
    public function before(RequestInterface $request, $arguments = null)
    {
        // Master off switch (see Config\Cluster::$sessionSyncEnabled) - a
        // disabled node never kills a session over this, even if
        // invalidations.json already has entries from before it was
        // turned off (e.g. left over from when it was still on).
        if (! config('Cluster')->sessionSyncEnabled) {
            return null;
        }

        if (! function_exists('auth') || ! auth()->loggedIn()) {
            return null;
        }

        $identity = auth()->user()?->getEmailIdentity();
        $email    = $identity !== null ? (string) $identity->secret : '';
        if ($email === '') {
            return null;
        }

        $invalidatedAt = (new SessionInvalidation())->invalidatedAt($email);
        if ($invalidatedAt === null) {
            return null; // this email has never had a recorded password change on this node
        }

        // Stamped by app/Config/Events.php's own 'login' listener - missing
        // (0) means a session that predates this feature ever being
        // deployed, which is untrusted by definition and always loses to
        // ANY recorded invalidation, however old.
        $loginAt = (int) (session('cluster_login_at') ?? 0);

        if ($loginAt < $invalidatedAt) {
            auth()->logout();
        }

        return null;
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        // Nothing to do after - a killed session simply isn't logged in
        // for the rest of this request, same as one that never was.
    }
}

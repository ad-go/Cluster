<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use CodeIgniter\Router\RouteCollection;

/**
 * Deliberately NOT named src/Config/Routes.php - found live: CI4's own
 * `spark routes` command scans every autoloaded namespace for a file at
 * exactly that path and `require`s it directly as a procedural route-
 * definition script (the convention app/Config/Routes.php itself follows).
 * A class-based file at that same path gets required a second time - once
 * by that scan, once by normal autoloading - triggering "Cannot declare
 * class ... because the name is already in use". Any other path/class name
 * avoids the collision entirely; this one was chosen for clarity, not to
 * dodge the exact collision path specifically.
 *
 * Not auto-registered either way - CI4 has no dependency-package auto-
 * discovery for routes (deliberately: a required package shouldn't be able
 * to add routes to your app without you asking it to). Add one line to
 * app/Config/Routes.php instead (see this package's README):
 *
 *   \AdGo\Cluster\RouteRegistrar::register($routes);
 */
class RouteRegistrar
{
    public static function register(RouteCollection $routes): void
    {
        // Leading backslash required - found live: without it CI4's router
        // silently prepends the app's own default controller namespace
        // (App\Controllers\...), resolving to a class that doesn't exist,
        // instead of this package's actual fully-qualified one.
        $routes->post(
            'cluster/files',
            '\AdGo\Cluster\Controllers\FileReceiverController::receive',
            ['filter' => 'cluster-auth']
        );

        // Password-change invalidation broadcast receiver - same
        // peer-to-peer auth as cluster/files (see Cluster::
        // broadcastPasswordChange() / BroadcastInvalidationJob).
        $routes->post(
            'cluster/invalidate',
            '\AdGo\Cluster\Controllers\InvalidationController::receive',
            ['filter' => 'cluster-auth']
        );

        // cluster:pull's own server side (see AdGo\Cluster\Commands\
        // PullCommand and PullController's own docblock) - GET, not POST,
        // since a peer is only ever READING state here, never writing it.
        $routes->get(
            'cluster/pull-invalidations',
            '\AdGo\Cluster\Controllers\PullController::invalidations',
            ['filter' => 'cluster-auth']
        );
        $routes->get(
            'cluster/pull-files',
            '\AdGo\Cluster\Controllers\PullController::files',
            ['filter' => 'cluster-auth']
        );
        $routes->get(
            'cluster/pull-file',
            '\AdGo\Cluster\Controllers\PullController::file',
            ['filter' => 'cluster-auth']
        );

        // File deletion propagation (see Cluster::applyIncomingDeletion()'s
        // own docblock) - delete-file mirrors cluster/files' push receiver,
        // pull-deleted-files mirrors pull-files' GET+since pattern.
        $routes->post(
            'cluster/delete-file',
            '\AdGo\Cluster\Controllers\FileReceiverController::deleteFile',
            ['filter' => 'cluster-auth']
        );
        $routes->get(
            'cluster/pull-deleted-files',
            '\AdGo\Cluster\Controllers\PullController::deletedFiles',
            ['filter' => 'cluster-auth']
        );

        // DB sync (accounts/groups/permissions/profile/settings) - see
        // Commands\SyncDbCommand's own docblock. receive() is the push
        // side (POST, one write command per request); pull-db-rows mirrors
        // pull-files' GET+since pattern; db-block-hashes/db-block-rows are
        // the bulk catch-up path (a brand-new node's first sync, or
        // periodic self-healing) - see DbSyncSchema::computeBlockHashes().
        $routes->post(
            'cluster/sync-db-row',
            '\AdGo\Cluster\Controllers\DbSyncController::receive',
            ['filter' => 'cluster-auth']
        );
        $routes->get(
            'cluster/pull-db-rows',
            '\AdGo\Cluster\Controllers\DbSyncController::pullRows',
            ['filter' => 'cluster-auth']
        );
        $routes->get(
            'cluster/db-block-hashes',
            '\AdGo\Cluster\Controllers\DbSyncController::blockHashes',
            ['filter' => 'cluster-auth']
        );
        $routes->get(
            'cluster/db-block-rows',
            '\AdGo\Cluster\Controllers\DbSyncController::blockRows',
            ['filter' => 'cluster-auth']
        );

        // Long-poll pull - see LongPollController::poll()'s own docblock.
        // POST (not GET, unlike the other pull-* routes above): carries
        // `since` in the body, and unlike a normal idempotent read, this
        // request has a real server-side side effect worth not repeating
        // on a naive retry (RemoteTestQueue::claimPending() inside it
        // removes what it finds).
        $routes->post(
            'cluster/long-poll',
            '\AdGo\Cluster\Controllers\LongPollController::poll',
            ['filter' => 'cluster-auth']
        );

        // Clock-drift measurement (Cristian's algorithm) - see
        // AdGo\Cluster\Commands\TimeDriftCommand's own docblock. GET, same
        // reasoning as the pull-* routes above: read-only from the
        // caller's point of view.
        $routes->get(
            'cluster/time',
            '\AdGo\Cluster\Controllers\TimeController::now',
            ['filter' => 'cluster-auth']
        );

        // Real cross-node SSO handoff (see SsoController's own docblock).
        // start(): a logged-in user clicking "switch to node X" - filtered
        // by Shield's own 'session' alias, a logged-in human admin rather
        // than peer-to-peer traffic.
        // consume(): deliberately UNFILTERED - this is how a user arrives
        // WITHOUT a session yet; trust comes from verify()'s live
        // server-to-server round trip, not from being logged in already.
        // verify(): peer-to-peer only, same cluster-auth Bearer as every
        // other cluster/* route.
        $routes->get(
            'cluster/sso/start',
            '\AdGo\Cluster\Controllers\SsoController::start',
            ['filter' => 'session']
        );
        $routes->get(
            'cluster/sso/consume',
            '\AdGo\Cluster\Controllers\SsoController::consume'
        );
        $routes->post(
            'cluster/sso/verify',
            '\AdGo\Cluster\Controllers\SsoController::verify',
            ['filter' => 'cluster-auth']
        );

        // NAT-safe remote connection-test relay (see RemoteTestController's
        // own docblock) - testConnection() is the direct synchronous path
        // for a PUBLIC target; pullTestRequests()/testResult() are the
        // pull-then-push-back pair a NAT target's own cluster:pull cycle
        // uses instead, since nothing can reach a NAT node directly.
        $routes->post(
            'cluster/test-connection',
            '\AdGo\Cluster\Controllers\RemoteTestController::testConnection',
            ['filter' => 'cluster-auth']
        );
        $routes->get(
            'cluster/pull-test-requests',
            '\AdGo\Cluster\Controllers\RemoteTestController::pullTestRequests',
            ['filter' => 'cluster-auth']
        );
        $routes->post(
            'cluster/test-result',
            '\AdGo\Cluster\Controllers\RemoteTestController::testResult',
            ['filter' => 'cluster-auth']
        );
    }
}

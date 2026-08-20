<?php

declare(strict_types=1);

namespace AdGo\Cluster\Jobs;

use AdGo\Cluster\SshChecker;
use CodeIgniter\Queue\BaseJob;

/**
 * Runs SshChecker::checkAll() asynchronously - queued right after a
 * successful Shield login (see app/Config/Events.php's 'login' listener,
 * same place cluster_login_at gets stamped) rather than run inline in the
 * login request itself, since a real SSH handshake to every configured
 * node can take a few seconds and a login response shouldn't wait on it.
 * Consuming app must map this in app/Config/Queue.php:
 *
 *   public array $jobHandlers = [
 *       'cluster-ssh-connectivity-check' => \AdGo\Cluster\Jobs\SshConnectivityCheckJob::class,
 *   ];
 *
 * No $data needed - checkAll() already re-derives which nodes to check
 * from the Settings-stored SSH credentials at run time, not from
 * anything captured at enqueue time.
 *
 * $tries = 1, explicitly no retry - a failed check IS the useful result
 * here (a node that can't be reached right now), not a delivery failure
 * to recover from the way a broadcast job's failure is; SshChecker
 * itself never throws (every failure path is caught and recorded), so a
 * retry would only ever repeat the exact same login attempt. See
 * Commands\SshCheckCommand for the same check on a schedule instead of
 * per-login.
 */
class SshConnectivityCheckJob extends BaseJob
{
    protected int $tries = 1;

    public function process(): void
    {
        (new SshChecker())->checkAll();
    }
}

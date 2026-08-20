<?php

declare(strict_types=1);

namespace AdGo\Cluster\Commands;

use AdGo\Cluster\SshChecker;
use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;

/**
 * Runs SshChecker::checkAll() on a schedule - the OTHER of the two
 * triggers this feature has (see Jobs\SshConnectivityCheckJob for the
 * per-login one). Scheduled every minute, same cadence as sync-files/
 * queue:work/cluster:pull/cluster:sync-db (see this package's README) -
 * unlike cluster:time-drift (hourly, drift barely changes minute to
 * minute), whether a node is reachable over SSH right now is exactly the
 * kind of thing worth knowing within a minute of it changing.
 *
 * Purely a report/diagnostic, same shape as TimeDriftCommand - the real
 * work (the actual SSH login + exec, and recording the result) happens
 * in SshChecker/SshConnectivityLog, this command just triggers it and
 * prints a human-readable summary.
 */
class SshCheckCommand extends BaseCommand
{
    protected $group = 'Cluster';

    protected $name = 'cluster:ssh-check';

    protected $description = 'Test SSH connectivity to every node that has SSH credentials configured (Settings -> Nodes).';

    public function run(array $params)
    {
        $results = (new SshChecker())->checkAll();

        if ($results === []) {
            CLI::write('cluster:ssh-check: no node has SSH credentials configured, nothing to check.', 'yellow');

            return;
        }

        foreach ($results as $name => $entry) {
            if ($entry['ok']) {
                CLI::write(sprintf('%s: OK (%.3fs)', $name, $entry['latencySeconds'] ?? 0.0), 'green');
            } else {
                CLI::write("$name: FAILED - " . ($entry['error'] ?? 'unknown error'), 'red');
            }
        }
    }
}

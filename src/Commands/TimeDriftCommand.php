<?php

declare(strict_types=1);

namespace AdGo\Cluster\Commands;

use AdGo\Cluster\Cluster;
use AdGo\Cluster\TimeDrift;
use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Throwable;

/**
 * Estimates this node's clock offset against every configured peer, using
 * Cristian's algorithm via Cluster::measureDrift() (see that method's own
 * docblock, and this package's README "How clock drift is measured", for
 * the math and sign convention). This command is a standalone REPORT -
 * it records each measurement to writable/Cluster/time_drifts.json (via
 * TimeDrift) and prints it, for visibility/diagnosis. The actual mtime
 * CORRECTION applied to synced files lives elsewhere (PullCommand's
 * downloadFile(), Jobs\PushFileJob) and measures live at transfer time
 * rather than reading this command's cached output.
 *
 * Queries EVERY configured peer regardless of type ('public' or 'nat') -
 * see Cluster::allPeers()'s own docblock for why 'nat' peers aren't
 * skipped here the way sync-files/pull skip them for pushing.
 *
 * Scheduled hourly (see this package's README) - clock drift doesn't
 * meaningfully change minute-to-minute the way file/DB sync state does,
 * so it doesn't need the same everyMinute() cadence as the other four
 * commands. Its output is surfaced on the Dashboard via
 * Cluster::clockDriftSummary() (cluster-ui's "Clock drift" widget).
 */
class TimeDriftCommand extends BaseCommand
{
    protected $group = 'Cluster';

    protected $name = 'cluster:time-drift';

    protected $description = "Measure this node's clock offset against every configured peer (Cristian's algorithm).";

    public function run(array $params)
    {
        $config  = config('Cluster');
        $cluster = new Cluster($config);
        $store   = new TimeDrift($config);

        $peers = $cluster->allPeers();
        if ($peers === []) {
            CLI::write('cluster:time-drift: no peers configured, nothing to do.', 'yellow');

            return;
        }

        foreach ($peers as $peerName => $node) {
            try {
                $client = service('curlrequest', ['baseURI' => $node['baseURL'], 'timeout' => 10], null, null, false);

                $result = $cluster->measureDrift($client);
                $offset = $result['offset'];
                $rtt    = $result['rtt'];

                $store->record($peerName, [
                    'measuredAt'    => time(),
                    'rttSeconds'    => round($rtt, 4),
                    'offsetSeconds' => round($offset, 4),
                ]);

                CLI::write(
                    sprintf('%s: offset %+.3fs, rtt %.3fs', $peerName, $offset, $rtt),
                    abs($offset) > 2 ? 'yellow' : 'green'
                );
            } catch (Throwable $e) {
                $store->record($peerName, ['measuredAt' => time(), 'error' => $e->getMessage()]);
                CLI::write("$peerName: failed - " . $e->getMessage(), 'red');
            }
        }
    }
}

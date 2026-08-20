<?php

declare(strict_types=1);

namespace AdGo\Cluster\Commands;

use AdGo\Cluster\Cluster;
use AdGo\Cluster\Config\Cluster as ClusterConfig;
use AdGo\Cluster\PullSync;
use AdGo\Cluster\SyncState;
use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Throwable;

/**
 * The pull-side counterpart to sync-files/queue:work's push-only design -
 * closes the gap a 'nat' node has always had (it can push OUT fine, but
 * nothing can push files/invalidations IN to it, since nothing can reach
 * it - see this package's README "Not built yet", before this command
 * existed). Pulling doesn't have that problem: a 'nat' node still
 * initiates this connection OUTBOUND itself, to a peer it already knows
 * how to reach.
 *
 * Scheduled on EVERY node, not just 'nat' ones (see this package's
 * README) - for a 'public' node this is pure defense-in-depth, catching
 * anything a push attempt missed (a failed queue job that exhausted its
 * retries, a job lost to a crash mid-run) within one more minute, on top
 * of what push already delivers.
 *
 * Deliberately STATELESS - no per-peer "last pulled at" cursor file. Each
 * PASS asks every public peer for everything strictly newer than
 * (now - Config\Cluster::$pullLookbackSeconds), a rolling window wide
 * enough (default 180s) to tolerate a couple of missed CRON ticks with no
 * gap. Re-asking about a few seconds of already-applied state on every
 * normal pass is cheap: both SessionInvalidation::recordInvalidation()
 * ("newer wins") and the file hash-compare below are safe no-ops on a
 * repeat answer, not duplicates.
 *
 * Optionally loops MULTIPLE passes within one cron-triggered invocation
 * (Config\Cluster::$pullLoopSeconds, default 0 = disabled, exactly one
 * pass, unchanged from before this existed) - cron itself only fires
 * once a minute (codeigniter4/tasks has no finer built-in schedule), but
 * nothing stops the ONE process that single tick starts from staying
 * alive and re-checking every few seconds on its own before exiting -
 * "long-polling" in effect, without ever holding a connection open: each
 * check is a normal short request/response, so it costs nothing on the
 * SERVER side (unlike a real long-poll endpoint, which would tie up a
 * PHP-FPM worker for the whole wait). Needs no SSH, no persistent daemon,
 * no cron finer than once a minute - only that the host's CLI SAPI
 * tolerates a script running close to a minute, which cron-triggered
 * scripts generally can (CLI's own max_execution_time defaults to 0/
 * unlimited, unlike the web SAPI) - verify on a given host before raising
 * this value there. See this package's README for the exact tradeoff.
 *
 * Scheduled via app/Config/Tasks.php (see this package's README):
 *   $schedule->command('cluster:pull')->everyMinute();
 */
class PullCommand extends BaseCommand
{
    protected $group = 'Cluster';

    protected $name = 'cluster:pull';

    protected $description = 'Pull invalidations and changed files from every reachable peer, optionally looping within one cron tick.';

    public function run(array $params)
    {
        $config = config('Cluster');
        if (! $config->fileSyncEnabled && ! $config->sessionSyncEnabled) {
            CLI::write('cluster:pull: fileSyncEnabled and sessionSyncEnabled are both false, skipping.', 'yellow');

            return;
        }

        $cluster = new Cluster();
        $peers   = $cluster->publicPeers();

        if ($peers === []) {
            CLI::write('cluster:pull: no public peers configured, nothing to do.', 'yellow');

            return;
        }

        // Non-blocking: if a previous invocation is still mid-loop when
        // cron fires again (a slow peer, a host running behind), this
        // tick just skips rather than piling up a second overlapping
        // loop - the next tick after that tries again. Same flock()
        // convention as every state file in this package, just guarding
        // a run instead of a write.
        $lock = $this->acquireLock($cluster);
        if ($lock === null) {
            CLI::write('cluster:pull: another run is still in progress, skipping.', 'yellow');

            return;
        }

        try {
            $this->loop($config, $cluster, $peers);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /**
     * @param array<string, array{baseURL: string, type: string}> $peers
     */
    private function loop(ClusterConfig $config, Cluster $cluster, array $peers): void
    {
        $loopSeconds     = max(0, $config->pullLoopSeconds);
        $intervalSeconds = max(1, $config->pullLoopIntervalSeconds);
        // Stops with enough margin before the NEXT cron tick that a
        // slightly-slow final pass still finishes first - deliberately
        // not the full 60s a ->everyMinute() cadence implies.
        $deadline = $loopSeconds > 0 ? microtime(true) + $loopSeconds : null;

        $totalApplied  = 0;
        $totalDownloaded = 0;
        $totalDeleted  = 0;
        $totalDbRows   = 0;
        $totalTests    = 0;
        $totalErrors   = 0;
        $passes        = 0;

        do {
            [$applied, $downloaded, $deleted, $dbRows, $tests, $errors] = $this->pass($config, $cluster, $peers);
            $totalApplied    += $applied;
            $totalDownloaded += $downloaded;
            $totalDeleted    += $deleted;
            $totalDbRows     += $dbRows;
            $totalTests      += $tests;
            $totalErrors     += $errors;
            $passes++;

            // Only a disabled node's dependency check (top of run()) skips
            // entirely - once inside the loop, every pass logs, but only
            // when it actually did something. A silent "0 and 0" pass
            // every 5s for 55s would otherwise flood tasks_cron.log with
            // nothing anyone would ever read.
            if ($applied > 0 || $downloaded > 0 || $deleted > 0 || $dbRows > 0 || $tests > 0 || $errors > 0) {
                CLI::write(
                    sprintf('cluster:pull: pass %d - %d invalidation(s), %d file(s), %d deletion(s), %d db row(s), %d test(s) relayed, %d error(s).', $passes, $applied, $downloaded, $deleted, $dbRows, $tests, $errors),
                    $errors > 0 ? 'yellow' : 'green'
                );
            }

            if ($deadline === null) {
                break;
            }
            $remaining = $deadline - microtime(true);
            if ($remaining <= $intervalSeconds) {
                break;
            }
            sleep($intervalSeconds);
        } while (true);

        CLI::write(
            sprintf(
                'cluster:pull: done - %d pass(es), %d invalidation(s) applied, %d file(s) downloaded, %d file(s) deleted, %d db row(s) applied, %d test(s) relayed, %d error(s) total, across %d peer(s).',
                $passes,
                $totalApplied,
                $totalDownloaded,
                $totalDeleted,
                $totalDbRows,
                $totalTests,
                $totalErrors,
                count($peers)
            ),
            $totalErrors > 0 ? 'yellow' : 'green'
        );
    }

    /**
     * One full round against every peer - exactly what run() used to do
     * before looping existed.
     *
     * @param array<string, array{baseURL: string, type: string}> $peers
     *
     * @return array{0: int, 1: int, 2: int, 3: int, 4: int, 5: int} [invalidationsApplied, filesDownloaded, filesDeleted, dbRowsApplied, testsRelayed, peerErrors]
     */
    private function pass(ClusterConfig $config, Cluster $cluster, array $peers): array
    {
        $since = time() - max(1, $config->pullLookbackSeconds);
        $sync  = new PullSync();

        $invalidationsApplied = 0;
        $filesDownloaded      = 0;
        $filesDeleted         = 0;
        $dbRowsApplied        = 0;
        $testsRelayed         = 0;
        $errors               = 0;

        foreach ($peers as $peerName => $node) {
            try {
                $client = service('curlrequest', ['baseURI' => $node['baseURL'], 'timeout' => 20], null, null, false);

                // Each half is gated independently - a node with only
                // sessionSyncEnabled=false, say, still wants its files
                // pulled normally.
                if ($config->sessionSyncEnabled) {
                    $invalidationsApplied += $sync->pullInvalidations($client, $cluster, $since);
                }
                if ($config->fileSyncEnabled) {
                    // Measured once per peer per pass, not once per file -
                    // clock drift doesn't meaningfully change second-to-
                    // second, and a pass can download many files from one
                    // peer. Failure here isn't a pull failure - offset 0.0
                    // (today's pre-correction behavior) rather than letting
                    // a failed timing probe block the actual sync. See
                    // Cluster::measureDrift()/correctMtimeFromPeer()'s own
                    // docblocks for the math.
                    $driftOffset = 0.0;
                    try {
                        $driftOffset = $cluster->measureDrift($client)['offset'];
                    } catch (Throwable $e) {
                        // Intentionally swallowed - see comment above.
                    }

                    $filesDownloaded += $sync->pullFiles($client, $cluster, $since, $peerName, $driftOffset)['downloaded'];
                    // Deletions ride along with the same fileSyncEnabled
                    // gate as content pulling above - see
                    // pullDeletedFiles()'s own docblock.
                    $filesDeleted += $sync->pullDeletedFiles($client, $cluster, $since);
                }
                // No separate config flag - DB sync rides along with
                // fileSyncEnabled, matching SyncDbCommand's own reasoning
                // for not needing a dedicated on/off switch (yet).
                if ($config->fileSyncEnabled) {
                    $dbRowsApplied += $sync->pullDbRows($client, $cluster, $since, $peerName);
                }

                // Dashboard visibility for the pull side - see SyncState's
                // own docblock ("pull" half, added 2026-08-18). Recorded
                // once per peer per pass, success or failure, mirroring
                // how PushFileJob already records outgoing attempts either
                // way (a stuck/failing peer should stay visible, not just
                // disappear from the Dashboard).
                (new SyncState($config))->recordPull($peerName, true);
            } catch (Throwable $e) {
                $errors++;
                CLI::write("cluster:pull: $peerName failed - " . $e->getMessage(), 'red');
                (new SyncState($config))->recordPull($peerName, false);

                continue;
            }

            // Own try/catch, deliberately separate from the block above -
            // see RemoteTestController's own docblock for the full relay
            // shape. A failure here (this peer has no pending test
            // requests endpoint yet, say, on an older ad-go/cluster
            // version) must never count against this peer's own
            // file/invalidation/db-sync health in SyncState, which is
            // what the try/catch above already recorded successfully by
            // this point.
            try {
                $testsRelayed += $sync->pullTestRequests($client, $cluster);
            } catch (Throwable $e) {
                CLI::write("cluster:pull: $peerName test-relay failed - " . $e->getMessage(), 'yellow');
            }
        }

        return [$invalidationsApplied, $filesDownloaded, $filesDeleted, $dbRowsApplied, $testsRelayed, $errors];
    }

    /**
     * @return resource|null
     */
    private function acquireLock(Cluster $cluster)
    {
        $path = $cluster->lockPath();
        $dir  = dirname($path);
        if (! is_dir($dir) && ! mkdir($dir, 0775, true) && ! is_dir($dir)) {
            return null;
        }

        $handle = fopen($path, 'cb');
        if ($handle === false) {
            return null;
        }
        if (! flock($handle, LOCK_EX | LOCK_NB)) {
            fclose($handle);

            return null;
        }
        @chmod($path, 0664);

        return $handle;
    }
}

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
 * Long-poll counterpart to cluster:pull (still supported, unchanged - runs
 * alongside this, not replaced by it). Instead of one quick request/
 * response per channel every cron tick, opens ONE connection held
 * server-side for up to ~28s (see LongPollController::poll()'s own
 * docblock), checked every second, replying the instant something's ready
 * - cutting worst-case NAT-to-NAT relay latency from "up to a full pull
 * cadence" to "up to one second".
 *
 * Talks to exactly ONE public peer per round, not all of them - a single
 * connection is enough: SyncFilesCommand/SyncDbCommand already push every
 * change to EVERY configured public peer directly, from whichever node
 * originates it, NAT or public (Cluster::publicPeers() doesn't special-
 * case the caller's own type - see that method's own docblock). So any
 * ONE public peer already ends up with a complete picture of the whole
 * cluster within one push cycle, on its own, without this command needing
 * to ask all of them - full mesh is an emergent property of the existing
 * push design, not something built here. Verified live 2026-08-20 (see
 * this command's own git history) that querying every peer concurrently
 * found nothing a single peer wouldn't have.
 *
 * The peer used ROTATES every round (persisted cursor - writable/Cluster/
 * long_poll_rotation.json, same flock-JSON convention as every other
 * state file in this package), cycling through every configured public
 * peer in turn: momentary staleness on one peer (its own push-processing
 * cycle hasn't caught up yet, or one specific incoming push job is mid-
 * retry) self-heals on the NEXT round, which lands on a different peer -
 * same "eventually consistent, safe to re-ask" philosophy cluster:pull's
 * own rolling lookback window already relies on, just spread across peers
 * instead of across time.
 *
 * Runs the round TWICE per invocation (back-to-back, no sleep between -
 * the server-side hold itself already paces it, and each round advances
 * the rotation), so ONE cron-triggered tasks:run tick (the finest
 * granularity most hosting cron actually offers) still switches peer
 * roughly every ~28-30s instead of once a full minute, with zero crontab
 * changes needed - "at 30s, switch the direct node for the next one".
 *
 * Scheduled via app/Config/Tasks.php, same as cluster:pull:
 *   $schedule->command('cluster:long-poll')->everyMinute();
 */
class LongPollCommand extends BaseCommand
{
    protected $group = 'Cluster';

    protected $name = 'cluster:long-poll';

    protected $description = 'Long-poll one rotating public peer at a time for near-real-time pull.';

    // Must stay comfortably above the server's own hold (28s - see
    // LongPollController::HOLD_SECONDS) so a slow-but-legitimate response
    // isn't cut off client-side right as the server was about to answer.
    private const CLIENT_TIMEOUT_SECONDS = 40;

    // Two rounds, no sleep between - see this class's own docblock. A
    // hard ceiling on TOTAL time this invocation may run, so a slow tick
    // can never overlap into territory the NEXT cron-triggered tick would
    // also be running in.
    private const MAX_TOTAL_SECONDS = 55;

    public function run(array $params)
    {
        $config = config('Cluster');
        if (! $config->fileSyncEnabled && ! $config->sessionSyncEnabled) {
            CLI::write('cluster:long-poll: fileSyncEnabled and sessionSyncEnabled are both false, skipping.', 'yellow');

            return;
        }

        $cluster   = new Cluster();
        $peerNames = array_keys($cluster->publicPeers());

        if ($peerNames === []) {
            CLI::write('cluster:long-poll: no public peers configured, nothing to do.', 'yellow');

            return;
        }

        // Same non-blocking overlap guard as cluster:pull, but its OWN
        // separate lock file - unlike two copies of the SAME command,
        // cluster:pull and cluster:long-poll applying the same content
        // concurrently is completely safe (every apply*() method is
        // idempotent - a repeat is a cheap no-op, never a duplicate), so
        // there's no correctness reason to make them block each other;
        // sharing cluster:pull's own lock would just mean one transport
        // starves the other for no benefit.
        $lock = $this->acquireLock();
        if ($lock === null) {
            CLI::write('cluster:long-poll: another long-poll run is still in progress, skipping.', 'yellow');

            return;
        }

        try {
            $start  = microtime(true);
            $rounds = 0;
            do {
                $peerName = $this->nextPeer($peerNames);
                $this->round($config, $cluster, $peerName, $cluster->publicPeers()[$peerName]);
                $rounds++;
            } while ($rounds < 2 && (microtime(true) - $start) < self::MAX_TOTAL_SECONDS);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function round(ClusterConfig $config, Cluster $cluster, string $peerName, array $node): void
    {
        $since = time() - max(1, $config->pullLookbackSeconds);
        $sync  = new PullSync();

        $invalidationsApplied = 0;
        $filesDownloaded      = 0;
        $filesDeleted         = 0;
        $dbRowsApplied        = 0;
        $testsRelayed         = 0;
        $errors               = 0;

        try {
            $client   = service('curlrequest', ['baseURI' => $node['baseURL'], 'timeout' => self::CLIENT_TIMEOUT_SECONDS], null, null, false);
            $response = $client->post('cluster/long-poll', [
                'headers' => ['Authorization' => $cluster->authHeader()],
                'form_params' => ['since' => $since],
            ]);

            if ($response->getStatusCode() !== 200) {
                throw new \RuntimeException('long-poll HTTP ' . $response->getStatusCode());
            }

            $decoded = json_decode($response->getBody(), true);
            if (! is_array($decoded)) {
                throw new \RuntimeException('long-poll returned invalid JSON');
            }

            if ($config->sessionSyncEnabled) {
                $invalidationsApplied += $sync->applyInvalidations(is_array($decoded['invalidations'] ?? null) ? $decoded['invalidations'] : []);
            }
            if ($config->fileSyncEnabled) {
                $driftOffset = 0.0;
                try {
                    $driftOffset = $cluster->measureDrift($client)['offset'];
                } catch (Throwable $e) {
                    // Intentionally swallowed - same reasoning as
                    // PullCommand::pass()'s own identical catch.
                }

                $remoteFiles = is_array($decoded['files'] ?? null) ? $decoded['files'] : [];
                $filesDownloaded += $sync->applyFilesManifest($client, $cluster, $remoteFiles, $peerName, $driftOffset)['downloaded'];
                $filesDeleted    += $sync->applyDeletedFiles($cluster, is_array($decoded['deletions'] ?? null) ? $decoded['deletions'] : []);
                $dbRowsApplied   += $sync->applyDbRows(is_array($decoded['dbRows'] ?? null) ? $decoded['dbRows'] : [], $peerName);
            }

            (new SyncState($config))->recordPull($peerName, true);
        } catch (Throwable $e) {
            $errors++;
            CLI::write("cluster:long-poll: $peerName failed - " . $e->getMessage(), 'red');
            (new SyncState($config))->recordPull($peerName, false);

            if ($invalidationsApplied > 0 || $filesDownloaded > 0 || $filesDeleted > 0 || $dbRowsApplied > 0 || $errors > 0) {
                CLI::write(
                    sprintf('cluster:long-poll: %s - %d invalidation(s), %d file(s), %d deletion(s), %d db row(s), %d error(s).', $peerName, $invalidationsApplied, $filesDownloaded, $filesDeleted, $dbRowsApplied, $errors),
                    'yellow'
                );
            }

            return;
        }

        // Own try/catch, deliberately separate - same reasoning as
        // PullCommand::pass()'s own identical split.
        try {
            $testsRelayed += $sync->applyTestRequests($client, $cluster, is_array($decoded['testRequests'] ?? null) ? $decoded['testRequests'] : []);
        } catch (Throwable $e) {
            CLI::write("cluster:long-poll: $peerName test-relay failed - " . $e->getMessage(), 'yellow');
        }

        if ($invalidationsApplied > 0 || $filesDownloaded > 0 || $filesDeleted > 0 || $dbRowsApplied > 0 || $testsRelayed > 0) {
            CLI::write(
                sprintf('cluster:long-poll: %s - %d invalidation(s), %d file(s), %d deletion(s), %d db row(s), %d test(s) relayed.', $peerName, $invalidationsApplied, $filesDownloaded, $filesDeleted, $dbRowsApplied, $testsRelayed),
                'green'
            );
        }
    }

    /**
     * Advances and persists the rotation cursor, returning the peer name
     * to use THIS round. A peer removed from the registry since the last
     * run (cursor pointing past the end, or at a now-stale index) wraps
     * back to 0 rather than erroring.
     *
     * @param list<string> $peerNames
     */
    private function nextPeer(array $peerNames): string
    {
        $path = $this->rotationPath();
        $dir  = dirname($path);
        if (! is_dir($dir)) {
            @mkdir($dir, 0775, true);
        }

        $handle = @fopen($path, 'cb+');
        if ($handle === false) {
            // Best-effort - no persisted cursor available, always start
            // from the first configured peer rather than failing the run.
            return $peerNames[0];
        }

        flock($handle, LOCK_EX);
        $contents = stream_get_contents($handle);
        $state    = json_decode((string) $contents, true);
        $index    = is_array($state) ? (int) ($state['index'] ?? 0) : 0;

        $index    = ($index + 1) % count($peerNames);
        $peerName = $peerNames[$index];

        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode(['index' => $index, 'peer' => $peerName, 'at' => time()]));
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
        @chmod($path, 0664);

        return $peerName;
    }

    private function rotationPath(): string
    {
        return rtrim(WRITEPATH, '/\\') . '/' . trim(config('Cluster')->stateDir, '/\\') . '/long_poll_rotation.json';
    }

    /**
     * @return resource|null
     */
    private function acquireLock()
    {
        // Own file, deliberately distinct from Cluster::lockPath() (which
        // cluster:pull uses) - see run()'s own comment for why they must
        // NOT share one.
        $path = rtrim(WRITEPATH, '/\\') . '/' . trim(config('Cluster')->stateDir, '/\\') . '/long_poll.lock';
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

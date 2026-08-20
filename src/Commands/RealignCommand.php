<?php

declare(strict_types=1);

namespace AdGo\Cluster\Commands;

use AdGo\Cluster\Cluster;
use AdGo\Cluster\PullSync;
use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Throwable;

/**
 * Full reconciliation with every reachable peer, for a node that has been
 * offline long enough that cluster:pull's normal rolling window (default
 * 180s lookback) cannot bridge the gap - "live realignment of a long-
 * offline node" from the original spec. Not scheduled by default, same
 * convention as cluster:sync-db --bootstrap (which this also runs) -
 * meant to be run once, by hand, after a node comes back from an extended
 * outage:
 *
 *   php spark cluster:realign
 *
 * Two independent passes, each already covering its own worst case:
 *
 * - Files/deletions/invalidations: the SAME logic cluster:pull uses (see
 *   PullSync), just called with since=0 instead of the rolling window -
 *   PullController::files()/deletedFiles()/invalidations() already answer
 *   "everything currently known", the rolling window is purely a client-
 *   side courtesy against re-asking about already-seen state on every
 *   normal minute, not a server-side limit. Deletions are complete as
 *   long as the offline gap is under DeletedFiles' own tombstone
 *   retention (30 days); beyond that, a tombstone may already be pruned
 *   on every peer, and a file this node still has locally but every peer
 *   genuinely deleted can no longer be told apart from one only this node
 *   has ever had. See reportOrphanedFiles() below for how that residual
 *   case is surfaced - deliberately reported, not auto-deleted. This
 *   package never destroys file content without a specific, positive
 *   signal to do so (see Cluster::detectConflict()'s own "archived, never
 *   destroyed" rule for an ordinary conflict) - inferring a deletion from
 *   mere absence, across a gap long enough that the real tombstone is
 *   already gone, is exactly the kind of guess that rule exists to avoid.
 *
 * - DB rows: cluster:sync-db --bootstrap's own block-hash catch-up -
 *   efficient regardless of how long the gap was (compares one hash per
 *   block before transferring anything), and already covers every table
 *   Config\Cluster::$dbSyncGroup auto-discovered too, not just
 *   users/settings.
 */
class RealignCommand extends BaseCommand
{
    protected $group = 'Cluster';

    protected $name = 'cluster:realign';

    protected $description = 'Full reconciliation with every peer - for a node that has been offline long enough that the normal rolling pull window cannot bridge the gap.';

    protected $options = [
        '--skip-db' => 'Skip the cluster:sync-db --bootstrap pass (files/deletions/invalidations only).',
    ];

    public function run(array $params)
    {
        $config  = config('Cluster');
        $cluster = new Cluster($config);
        $peers   = $cluster->publicPeers();

        if ($peers === []) {
            CLI::write('cluster:realign: no public peers configured, nothing to do.', 'yellow');

            return;
        }

        CLI::write('cluster:realign: full reconciliation against ' . count($peers) . ' peer(s) starting - this transfers significantly more than a normal cluster:pull pass and can take a while.', 'yellow');

        $sync                  = new PullSync();
        $invalidationsApplied  = 0;
        $filesDownloaded       = 0;
        $filesDeleted          = 0;
        // peerName => that peer's full current manifest, kept around for
        // reportOrphanedFiles() below - no second round trip needed.
        $remoteManifests       = [];

        foreach ($peers as $peerName => $node) {
            try {
                // Generous timeout - since=0 can mean a genuinely large
                // response (the peer's ENTIRE manifest/tombstone/
                // invalidation history), unlike cluster:pull's normal
                // few-seconds-wide window.
                $client = service('curlrequest', ['baseURI' => $node['baseURL'], 'timeout' => 60], null, null, false);

                if ($config->sessionSyncEnabled) {
                    $invalidationsApplied += $sync->pullInvalidations($client, $cluster, 0);
                }
                if ($config->fileSyncEnabled) {
                    $driftOffset = 0.0;
                    try {
                        $driftOffset = $cluster->measureDrift($client)['offset'];
                    } catch (Throwable $e) {
                        // Intentionally swallowed - see PullCommand's own
                        // identical comment on this exact fallback.
                    }

                    $result                       = $sync->pullFiles($client, $cluster, 0, $peerName, $driftOffset);
                    $filesDownloaded              += $result['downloaded'];
                    $remoteManifests[$peerName]   = $result['remoteManifest'];
                    $filesDeleted                 += $sync->pullDeletedFiles($client, $cluster, 0);
                }

                CLI::write("cluster:realign: $peerName done.", 'green');
            } catch (Throwable $e) {
                CLI::write("cluster:realign: $peerName failed - " . $e->getMessage(), 'red');
            }
        }

        CLI::write(sprintf(
            'cluster:realign: files/invalidations pass done - %d invalidation(s) applied, %d file(s) downloaded, %d deletion(s) applied.',
            $invalidationsApplied,
            $filesDownloaded,
            $filesDeleted
        ), 'green');

        if ($config->fileSyncEnabled && $remoteManifests !== []) {
            $this->reportOrphanedFiles($cluster, $remoteManifests);
        }

        if (array_key_exists('skip-db', $params) || CLI::getOption('skip-db')) {
            CLI::write('cluster:realign: --skip-db given, skipping the DB pass.', 'yellow');

            return;
        }

        CLI::write('cluster:realign: running cluster:sync-db --bootstrap for the DB side...', 'yellow');
        $this->call('cluster:sync-db', ['bootstrap' => null]);
    }

    /**
     * Files present in THIS node's manifest but absent from EVERY peer's
     * CURRENT manifest - either genuinely local-only content (created
     * here, never successfully pushed), or a file every peer deleted
     * while this node was offline long enough for the tombstone to
     * already be pruned there too (see this class's own docblock).
     * Reported for a human to review, never deleted automatically.
     *
     * @param array<string, array<string, array{hash: string, mtime: int, size: int}>> $remoteManifests peerName => manifest
     */
    private function reportOrphanedFiles(Cluster $cluster, array $remoteManifests): void
    {
        $local    = $cluster->loadManifest();
        $orphaned = [];
        foreach (array_keys($local) as $path) {
            $seenOnAnyPeer = false;
            foreach ($remoteManifests as $manifest) {
                if (array_key_exists($path, $manifest)) {
                    $seenOnAnyPeer = true;
                    break;
                }
            }
            if (! $seenOnAnyPeer) {
                $orphaned[] = $path;
            }
        }

        if ($orphaned === []) {
            CLI::write('cluster:realign: no local-only files found - every locally-known path exists on at least one peer.', 'green');

            return;
        }

        CLI::write(
            count($orphaned) . ' local file(s) exist here but on NO reachable peer - review by hand, not deleted '
            . 'automatically (could be legitimate local-only content, or a deletion whose tombstone already expired '
            . 'elsewhere while this node was offline):',
            'yellow'
        );
        foreach ($orphaned as $path) {
            CLI::write("  - $path");
        }
    }
}

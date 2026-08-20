<?php

declare(strict_types=1);

namespace AdGo\Cluster\Commands;

use AdGo\Cluster\Cluster;
use AdGo\Cluster\DeletedFiles;
use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * Scans this node's configured syncPaths for files that are new or whose
 * content changed since the last scan (compared against the local
 * manifest, not a live comparison against every peer - that's the
 * "realignment" mechanism from the spec, not built here), and queues one
 * PushFileJob per changed file per public peer.
 *
 * Scheduled via app/Config/Tasks.php (see this package's README):
 *   $schedule->command('cluster:sync-files')->everyMinute();
 */
class SyncFilesCommand extends BaseCommand
{
    protected $group = 'Cluster';

    protected $name = 'cluster:sync-files';

    protected $description = 'Scan configured syncPaths for new/changed files and queue them for push to every public peer.';

    public function run(array $params)
    {
        if (! config('Cluster')->fileSyncEnabled) {
            CLI::write('cluster:sync-files: cluster.fileSyncEnabled=false, skipping.', 'yellow');

            return;
        }

        $cluster = new Cluster();
        $peers   = $cluster->publicPeers();

        if ($peers === []) {
            CLI::write('cluster:sync-files: no public peers configured, nothing to do.', 'yellow');

            return;
        }

        $manifest = $cluster->loadManifest();
        $queue    = service('queue');
        $queueName = $cluster->queueName();

        $seen     = [];
        $changed  = 0;
        $enqueued = 0;

        foreach ($cluster->syncDirs() as $dir) {
            if (! is_dir($dir)) {
                continue;
            }

            $dirLen   = strlen(rtrim($dir, '/\\')) + 1;
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
            );

            foreach ($iterator as $file) {
                if (! $file->isFile()) {
                    continue;
                }

                $relative       = str_replace('\\', '/', substr($file->getPathname(), $dirLen));
                $seen[$relative] = true;

                $hash  = (string) md5_file($file->getPathname());
                $known = $manifest[$relative] ?? null;

                // Same hash as last known state - nothing to do, whether
                // that state came from OUR OWN earlier push (see below) or
                // from having received this exact file from a peer (see
                // FileReceiverController::recordKnown()) - that second
                // case is what stops a re-push storm right back to whoever
                // just sent it.
                if ($known !== null && $known['hash'] === $hash) {
                    continue;
                }

                $manifest[$relative] = [
                    'hash'       => $hash,
                    'mtime'      => $file->getMTime(),
                    'size'       => $file->getSize(),
                    // See Cluster::manifestSince()'s own docblock - this
                    // node's own wall-clock "when did I learn this changed",
                    // kept separate from mtime (which stays the author's
                    // original value across every relay hop, for LWW).
                    'recordedAt' => time(),
                ];
                $changed++;

                foreach (array_keys($peers) as $peerName) {
                    $queue->push($queueName, 'cluster-push-file', ['path' => $relative, 'peer' => $peerName]);
                    $enqueued++;
                }
            }
        }

        // A manifest entry whose file is gone locally is a deletion -
        // recorded as a tombstone (DeletedFiles, so a 'nat' peer pulling
        // from this node picks it up too - see that class's own docblock)
        // and queued as one DeleteFileJob per public peer, same "one job
        // per changed thing per peer" shape the push loop above already
        // uses. If the same path reappears later with different content,
        // its hash simply won't match anything and it's detected as
        // changed regardless of whether a tombstone was ever recorded for
        // it - see Cluster::applyIncomingDeletion()'s own LWW-against-mtime
        // check for why a stale tombstone can never clobber a real
        // re-creation.
        $deleted = 0;
        $deletedAt = time();
        foreach (array_keys($manifest) as $relative) {
            if (isset($seen[$relative])) {
                continue;
            }

            unset($manifest[$relative]);
            $deleted++;
            (new DeletedFiles())->record($relative, $deletedAt);

            foreach (array_keys($peers) as $peerName) {
                $queue->push($queueName, 'cluster-delete-file', [
                    'path'      => $relative,
                    'deletedAt' => $deletedAt,
                    'peer'      => $peerName,
                ]);
                $enqueued++;
            }
        }

        $cluster->saveManifest($manifest);

        CLI::write(
            sprintf(
                'cluster:sync-files: %d changed file(s), %d deleted file(s), %d job(s) queued across %d peer(s).',
                $changed,
                $deleted,
                $enqueued,
                count($peers)
            ),
            'green'
        );
    }
}

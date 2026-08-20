<?php

declare(strict_types=1);

namespace AdGo\Cluster\Jobs;

use AdGo\Cluster\Cluster;
use AdGo\Cluster\Stats;
use AdGo\Cluster\SyncState;
use CodeIgniter\Queue\BaseJob;
use CURLFile;
use RuntimeException;
use Throwable;

/**
 * Pushes one local file to one peer over HTTPS multipart POST, per the
 * spec's "Transfer multipart prin HTTPS asincron" section. Consuming app
 * must map this in app/Config/Queue.php:
 *
 *   public array $jobHandlers = [
 *       'cluster-push-file' => \AdGo\Cluster\Jobs\PushFileJob::class,
 *   ];
 *
 * ($data = ['path' => <relative to WRITEPATH>, 'peer' => <node name>],
 * enqueued by AdGo\Cluster\Commands\SyncFilesCommand.)
 *
 * Throwing on any failure is deliberate, not an oversight - codeigniter4/
 * queue's worker (queue:work) catches it, applies BaseJob::$tries/
 * $retryAfter, and re-queues automatically. A silently-swallowed failure
 * here would just leave the peer missing the file with no record of why.
 */
class PushFileJob extends BaseJob
{
    protected int $tries = 5;

    protected int $retryAfter = 60;

    public function process(): void
    {
        $relativePath = (string) ($this->data['path'] ?? '');
        $peerName     = (string) ($this->data['peer'] ?? '');

        $cluster = new Cluster();
        $node    = $cluster->node($peerName);
        if ($node === null) {
            // Peer removed from config between enqueue and now - not a
            // failure worth retrying.
            return;
        }

        $localPath = null;
        foreach ($cluster->syncDirs() as $dir) {
            $candidate = $dir . '/' . $relativePath;
            if (is_file($candidate)) {
                $localPath = $candidate;
                break;
            }
        }
        if ($localPath === null) {
            // Deleted locally before this job ran - deletion propagation
            // isn't built yet (see README), so there's nothing to push.
            return;
        }

        $stats     = new Stats();
        $bytes     = (int) filesize($localPath);
        $startedAt = microtime(true);

        try {
            // getShared: false is required here, not cosmetic - queue:work
            // processes many jobs (possibly for different peers) in one PHP
            // process, and Services::curlrequest()'s shared-instance cache
            // would otherwise keep serving the FIRST job's baseURI to every
            // later job in the same run.
            $client = service('curlrequest', ['baseURI' => $node['baseURL'], 'timeout' => 30], null, null, false);

            // Live per-job, not cached - a queued job can sit for a while
            // before queue:work picks it up, so "applied before sending"
            // means measured right here, not at enqueue time. Failure
            // isn't a push failure - offset 0.0 (today's pre-correction
            // behavior) rather than let a failed timing probe block the
            // actual push. Reuses $client (same peer) instead of building
            // a second one just to time this GET.
            $offset = 0.0;
            try {
                $offset = $cluster->measureDrift($client)['offset'];
            } catch (Throwable $e) {
                // Intentionally swallowed - see comment above.
            }
            // Re-expressed in the TARGET peer's clock frame before it's
            // sent - see Cluster::correctMtimeForPeer()'s own docblock.
            // The receiver must NOT correct this again (see
            // FileReceiverController's own docblock on that invariant).
            $correctedMtime = $cluster->correctMtimeForPeer((int) filemtime($localPath), $offset);

            $response = $client->post('cluster/files', [
                'headers' => [
                    'Authorization' => $cluster->authHeader(),
                ],
                'multipart' => [
                    'path'           => $relativePath,
                    'mtime'          => (string) $correctedMtime,
                    // Informational only - tells the receiver this value
                    // is already drift-corrected (see
                    // FileReceiverController). Never round-trips into any
                    // decision on this sending side.
                    'driftCorrected' => '1',
                    'hash'           => (string) md5_file($localPath),
                    // Self-reported, not authenticated (see SyncState's own
                    // docblock) - purely so the receiving side's Dashboard
                    // can label who pushed a given file and when.
                    'peer'           => $cluster->thisNodeName(),
                    'file'           => new CURLFile($localPath, mime_content_type($localPath) ?: 'application/octet-stream', basename($localPath)),
                ],
            ]);

            $status = $response->getStatusCode();
            if ($status < 200 || $status >= 300) {
                throw new RuntimeException("push $relativePath to $peerName failed: HTTP $status - " . $response->getBody());
            }

            $stats->record([
                'time'       => time(),
                'peer'       => $peerName,
                'path'       => $relativePath,
                'bytes'      => $bytes,
                'durationMs' => (int) round((microtime(true) - $startedAt) * 1000),
                'ok'         => true,
                'error'      => null,
            ]);
            (new SyncState())->recordOutgoing($peerName, $relativePath, true);
        } catch (Throwable $e) {
            // Recorded on failure too (0 bytes "delivered", but the
            // attempt itself is what the Dashboard's error list needs) -
            // then rethrown so codeigniter4/queue's own retry/tries logic
            // still runs exactly as before; this doesn't swallow anything.
            $stats->record([
                'time'       => time(),
                'peer'       => $peerName,
                'path'       => $relativePath,
                'bytes'      => 0,
                'durationMs' => (int) round((microtime(true) - $startedAt) * 1000),
                'ok'         => false,
                'error'      => $e->getMessage(),
            ]);
            (new SyncState())->recordOutgoing($peerName, $relativePath, false);

            throw $e;
        }
    }
}

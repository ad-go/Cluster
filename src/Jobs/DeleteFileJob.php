<?php

declare(strict_types=1);

namespace AdGo\Cluster\Jobs;

use AdGo\Cluster\Cluster;
use AdGo\Cluster\Stats;
use AdGo\Cluster\SyncState;
use CodeIgniter\Queue\BaseJob;
use RuntimeException;
use Throwable;

/**
 * Tells one peer that one local path was deleted here. Consuming app must
 * map this in app/Config/Queue.php:
 *
 *   public array $jobHandlers = [
 *       'cluster-delete-file' => \AdGo\Cluster\Jobs\DeleteFileJob::class,
 *   ];
 *
 * ($data = ['path' => <relative to WRITEPATH>, 'deletedAt' => <unix ts,
 * captured once by SyncFilesCommand at detection time - NOT re-derived
 * here, so every peer this fans out to agrees on the exact same LWW
 * timestamp regardless of how long this job sat queued>, 'peer' => <node
 * name>], enqueued by AdGo\Cluster\Commands\SyncFilesCommand.)
 *
 * Same "throw on failure, let codeigniter4/queue retry" contract as
 * PushFileJob - this package's sibling/counterpart for file content.
 */
class DeleteFileJob extends BaseJob
{
    protected int $tries = 5;

    protected int $retryAfter = 60;

    public function process(): void
    {
        $relativePath = (string) ($this->data['path'] ?? '');
        $deletedAt    = (int) ($this->data['deletedAt'] ?? 0);
        $peerName     = (string) ($this->data['peer'] ?? '');

        $cluster = new Cluster();
        $node    = $cluster->node($peerName);
        if ($node === null) {
            // Peer removed from config between enqueue and now - not a
            // failure worth retrying.
            return;
        }

        $stats     = new Stats();
        $startedAt = microtime(true);

        try {
            $client = service('curlrequest', ['baseURI' => $node['baseURL'], 'timeout' => 30], null, null, false);

            $response = $client->post('cluster/delete-file', [
                'headers' => [
                    'Authorization' => $cluster->authHeader(),
                ],
                'form_params' => [
                    'path'      => $relativePath,
                    'deletedAt' => (string) $deletedAt,
                    // Self-reported, not authenticated - same caveat as
                    // PushFileJob's own 'peer' field (see SyncState's
                    // docblock).
                    'peer'      => $cluster->thisNodeName(),
                ],
            ]);

            $status = $response->getStatusCode();
            if ($status < 200 || $status >= 300) {
                throw new RuntimeException("delete $relativePath on $peerName failed: HTTP $status - " . $response->getBody());
            }

            $stats->record([
                'time'       => time(),
                'peer'       => $peerName,
                'path'       => $relativePath,
                'bytes'      => 0,
                'durationMs' => (int) round((microtime(true) - $startedAt) * 1000),
                'ok'         => true,
                'error'      => null,
            ]);
            (new SyncState())->recordOutgoing($peerName, $relativePath, true);
        } catch (Throwable $e) {
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

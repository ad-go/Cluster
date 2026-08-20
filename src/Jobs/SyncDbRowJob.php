<?php

declare(strict_types=1);

namespace AdGo\Cluster\Jobs;

use AdGo\Cluster\Cluster;
use AdGo\Cluster\DbSyncLog;
use CodeIgniter\Queue\BaseJob;
use RuntimeException;
use Throwable;

/**
 * Delivers one DB write command to one peer - the cross-node half of
 * SyncDbCommand's own detection scan. Consuming app must map this in
 * app/Config/Queue.php:
 *
 *   public array $jobHandlers = [
 *       'cluster-sync-db-row' => \AdGo\Cluster\Jobs\SyncDbRowJob::class,
 *   ];
 *
 * ($data = ['table' => ..., 'naturalKey' => ..., 'operation' => ...,
 * 'payload' => [...], 'timestamp' => <unix timestamp>, 'peer' => <node name>],
 * enqueued by Commands\SyncDbCommand.)
 *
 * This IS the "write log consumed by every peer, gone once the last one
 * has it" behavior by construction - each peer gets its own independent
 * job here, and codeigniter4/queue's own lifecycle (delete on success,
 * move to queue_jobs_failed after $tries is exhausted) is the only
 * tracking needed; no separate multi-consumer log table. Throwing on any
 * failure is deliberate, same reasoning as PushFileJob/
 * BroadcastInvalidationJob - queue:work's own retry/tries logic handles
 * redelivery.
 */
class SyncDbRowJob extends BaseJob
{
    protected int $tries = 5;

    protected int $retryAfter = 60;

    public function process(): void
    {
        $table      = (string) ($this->data['table'] ?? '');
        $naturalKey = (string) ($this->data['naturalKey'] ?? '');
        $operation  = (string) ($this->data['operation'] ?? 'upsert');
        $payload    = (array) ($this->data['payload'] ?? []);
        $timestamp  = (int) ($this->data['timestamp'] ?? 0);
        $peerName   = (string) ($this->data['peer'] ?? '');

        if ($table === '' || $naturalKey === '' || $peerName === '') {
            return;
        }

        $cluster = new Cluster();
        $node    = $cluster->node($peerName);
        if ($node === null) {
            // Peer removed from config between enqueue and now - not a
            // failure worth retrying.
            return;
        }

        $client = service('curlrequest', ['baseURI' => $node['baseURL'], 'timeout' => 15], null, null, false);

        try {
            $response = $client->post('cluster/sync-db-row', [
                'headers' => [
                    'Authorization' => $cluster->authHeader(),
                    'Content-Type'  => 'application/json',
                ],
                'body' => json_encode([
                    'table'      => $table,
                    'naturalKey' => $naturalKey,
                    'operation'  => $operation,
                    'payload'    => $payload,
                    'timestamp'  => $timestamp,
                    // Self-reported, not authenticated - same reasoning as
                    // PushFileJob's own 'peer' field (see SyncState's
                    // docblock): purely so the receiving side's Dashboard
                    // can label who sent this.
                    'peer'       => $cluster->thisNodeName(),
                ]),
            ]);

            $status = $response->getStatusCode();
            if ($status < 200 || $status >= 300) {
                throw new RuntimeException("sync-db-row $table:$naturalKey to $peerName failed: HTTP $status - " . $response->getBody());
            }
        } catch (Throwable $e) {
            (new DbSyncLog())->record([
                'time'       => time(),
                'direction'  => 'push-out',
                'peer'       => $peerName,
                'table'      => $table,
                'naturalKey' => $naturalKey,
                'operation'  => $operation,
                'ok'         => false,
                'error'      => $e->getMessage(),
                'queries'    => [],
            ]);

            throw $e; // unchanged behavior - queue:work's own retry/tries logic still applies
        }

        (new DbSyncLog())->record([
            'time'       => time(),
            'direction'  => 'push-out',
            'peer'       => $peerName,
            'table'      => $table,
            'naturalKey' => $naturalKey,
            'operation'  => $operation,
            'ok'         => true,
            'error'      => null,
            'queries'    => [],
        ]);
    }
}

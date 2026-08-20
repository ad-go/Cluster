<?php

declare(strict_types=1);

namespace AdGo\Cluster\Commands;

use AdGo\Cluster\Cluster;
use AdGo\Cluster\Config\Cluster as ClusterConfig;
use AdGo\Cluster\DbManifest;
use AdGo\Cluster\DbSyncSchema;
use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use CodeIgniter\Database\ConnectionInterface;
use Throwable;

/**
 * Detects local DB changes (accounts/identities/groups/permissions/
 * profile, settings - see DbSyncSchema's own docblock for exactly what's
 * included and why) and queues delivery to every peer. Same scan-and-diff
 * detection model as cluster:sync-files, over DB rows instead of a
 * filesystem directory - Shield's models are vendor code with no generic
 * "any row changed" event to hook, so this polls instead (scheduled every
 * minute, same cadence as the other four commands).
 *
 * Delivery is one Queue job per changed entity per PUBLIC peer
 * ('cluster-sync-db-row', see Jobs\SyncDbRowJob) - 'nat' peers catch up
 * via the pull counterpart instead (see PullCommand::pullDbRows()), same
 * push/pull split every other concern in this package already uses.
 *
 * This command only EXPORTS (local DB -> queued commands). Applying an
 * INCOMING command (from a push or a pull) happens synchronously at the
 * receiving end (Controllers\DbSyncController::receive() /
 * PullCommand::pullDbRows()), via the shared DbSyncSchema::
 * applyIncomingCommand() - there is no separate "import" step here.
 */
class SyncDbCommand extends BaseCommand
{
    protected $group = 'Cluster';

    protected $name = 'cluster:sync-db';

    protected $description = 'Detect local DB changes and queue delivery to every peer.';

    public function run(array $params)
    {
        $config   = config('Cluster');
        $cluster  = new Cluster($config);
        $manifest = new DbManifest($config);
        $db       = db_connect('default');
        $peers    = $cluster->publicPeers();

        if ($peers === []) {
            CLI::write('cluster:sync-db: no public peers configured, nothing to do.', 'yellow');

            return;
        }

        $changed = 0;

        foreach (DbSyncSchema::exportAllUserEmails($db) as $email) {
            $snapshot = DbSyncSchema::exportUser($db, $email);
            if ($snapshot === null) {
                continue;
            }
            $hash = DbSyncSchema::hashUserSnapshot($snapshot);
            $key  = 'users:' . $email;
            $known = $manifest->get($key);
            if ($known !== null && $known['hash'] === $hash) {
                continue;
            }

            $timestamp = $this->rowTimestamp($snapshot['users']['updated_at'] ?? null);
            $manifest->record($key, ['hash' => $hash, 'timestamp' => $timestamp]);
            $this->enqueueToEveryPeer($config, $peers, 'users', $email, $snapshot, $timestamp);
            $changed++;
        }

        foreach (DbSyncSchema::exportAllSettingIds($db) as $id) {
            $snapshot = DbSyncSchema::exportSetting($db, (string) $id['class'], (string) $id['key'], (string) $id['context']);
            if ($snapshot === null) {
                continue;
            }
            $hash = DbSyncSchema::hashSettingSnapshot($snapshot);
            $key  = 'settings:' . $id['class'] . ':' . $id['key'] . ':' . $id['context'];
            $known = $manifest->get($key);
            if ($known !== null && $known['hash'] === $hash) {
                continue;
            }

            $timestamp = $this->rowTimestamp($snapshot['updated_at'] ?? null);
            $manifest->record($key, ['hash' => $hash, 'timestamp' => $timestamp]);
            $this->enqueueToEveryPeer($config, $peers, 'settings', $key, $snapshot, $timestamp);
            $changed++;
        }

        // Config\Cluster::$dbSyncGroup - every table DbSyncSchema::
        // genericTables() auto-discovered in that whole connection group
        // (minus $dbExcludeTables and whatever's hardcoded elsewhere in
        // DbSyncSchema), same scan-and-diff detection and LWW timestamping
        // as settings above, just genuinely generic - see
        // DbSyncSchema::genericTables()/applyGenericSnapshot()'s own
        // docblocks.
        foreach (DbSyncSchema::genericTables() as $table => $keyColumn) {
            foreach (DbSyncSchema::exportAllGenericKeys($db, $table, $keyColumn) as $keyValue) {
                $snapshot = DbSyncSchema::exportGenericRow($db, $table, $keyColumn, $keyValue);
                if ($snapshot === null) {
                    continue;
                }
                $hash  = DbSyncSchema::hashSettingSnapshot($snapshot);
                $key   = $keyValue;
                $known = $manifest->get("$table:$key");
                if ($known !== null && $known['hash'] === $hash) {
                    continue;
                }

                $timestamp = $this->rowTimestamp($snapshot['updated_at'] ?? null);
                $manifest->record("$table:$key", ['hash' => $hash, 'timestamp' => $timestamp]);
                $this->enqueueToEveryPeer($config, $peers, $table, $key, $snapshot, $timestamp);
                $changed++;
            }
        }

        CLI::write("cluster:sync-db: $changed entit" . ($changed === 1 ? 'y' : 'ies') . ' changed, queued to ' . count($peers) . ' peer(s).', $changed > 0 ? 'green' : 'yellow');

        if (array_key_exists('bootstrap', $params) || CLI::getOption('bootstrap')) {
            $this->bootstrap($cluster, $peers, $db);
        }
    }

    /**
     * The LWW timestamp a change is broadcast with MUST be when the row
     * itself was actually last written, never the scan's own wall-clock
     * moment - found live 2026-08-19: using time() here let a stale peer's
     * routine re-broadcast of unchanged old data outrace (and silently
     * revert) a genuinely newer local change, just because that peer's own
     * cron tick happened to fire later. Same real-row-timestamp approach
     * DbSyncSchema::exportEntity() already uses correctly for the
     * bootstrap/block-hash path - this brings the everyday incremental
     * path (the one actually scheduled every minute) in line with it.
     */
    private function rowTimestamp(?string $updatedAt): int
    {
        $timestamp = $updatedAt !== null ? strtotime($updatedAt) : false;

        return $timestamp !== false ? $timestamp : time();
    }

    /**
     * @param array<string, array{baseURL: string, type: string}> $peers
     */
    private function enqueueToEveryPeer(ClusterConfig $config, array $peers, string $table, string $naturalKey, array $payload, int $timestamp): void
    {
        foreach (array_keys($peers) as $peerName) {
            service('queue')->push($config->queueName, 'cluster-sync-db-row', [
                'table'      => $table,
                'naturalKey' => $naturalKey,
                'operation'  => 'upsert',
                'payload'    => $payload,
                'timestamp'  => $timestamp,
                'peer'       => $peerName,
            ]);
        }
    }

    /**
     * Bulk catch-up (`cluster:sync-db --bootstrap`) - for a brand-new
     * node's first sync, or periodic self-healing. Not scheduled by
     * default (unlike the plain scan above) - heavier than the
     * incremental path, since it enumerates every row on both sides
     * rather than just what changed since last time.
     *
     * Compares block hashes against each peer first (see DbSyncSchema::
     * computeBlockHashes()) and only fetches full row data for blocks
     * that actually differ - the rsync/Merkle-tree-style saving this
     * mode exists for. Applies through the same DbSyncSchema::
     * applyIncomingCommand() as every other path, so row-level LWW
     * behaves identically here too - a peer's stale copy of a row this
     * node already won a conflict on simply won't overwrite it.
     *
     * @param array<string, array{baseURL: string, type: string}> $peers
     */
    private function bootstrap(Cluster $cluster, array $peers, ConnectionInterface $db): void
    {
        $manifest = new DbManifest();
        $fetched  = 0;

        $tables = array_merge(['users', 'settings'], array_keys(DbSyncSchema::genericTables()));

        foreach ($peers as $peerName => $node) {
            $client = service('curlrequest', ['baseURI' => $node['baseURL'], 'timeout' => 20], null, null, false);

            foreach ($tables as $table) {
                try {
                    $localHashes = DbSyncSchema::computeBlockHashes($db, $table);

                    $response = $client->get('cluster/db-block-hashes', [
                        'headers' => ['Authorization' => $cluster->authHeader()],
                        'query'   => ['table' => $table],
                    ]);
                    if ($response->getStatusCode() !== 200) {
                        continue;
                    }
                    $remoteHashes = (array) (json_decode($response->getBody(), true)['blocks'] ?? []);

                    foreach ($remoteHashes as $block => $remoteHash) {
                        if (($localHashes[$block] ?? '') === $remoteHash) {
                            continue;
                        }

                        $blockResponse = $client->get('cluster/db-block-rows', [
                            'headers' => ['Authorization' => $cluster->authHeader()],
                            'query'   => ['table' => $table, 'block' => $block],
                        ]);
                        if ($blockResponse->getStatusCode() !== 200) {
                            continue;
                        }
                        $rows = (array) (json_decode($blockResponse->getBody(), true)['rows'] ?? []);

                        foreach ($rows as $row) {
                            $result = DbSyncSchema::applyIncomingCommand($db, $manifest, [
                                'table'      => $table,
                                'naturalKey' => (string) ($row['naturalKey'] ?? ''),
                                'operation'  => 'upsert',
                                'payload'    => (array) ($row['payload'] ?? []),
                                'timestamp'  => (int) ($row['timestamp'] ?? 0),
                            ], 'pull', $peerName);
                            if ($result['applied']) {
                                $fetched++;
                            }
                        }
                    }
                } catch (Throwable $e) {
                    CLI::write("cluster:sync-db --bootstrap: $peerName/$table failed - " . $e->getMessage(), 'red');
                }
            }
        }

        CLI::write("cluster:sync-db --bootstrap: $fetched row(s) applied from mismatched blocks.", $fetched > 0 ? 'green' : 'yellow');
    }
}

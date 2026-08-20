<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use AdGo\Cluster\Config\Cluster as ClusterConfig;

/**
 * Bounded activity log of DB sync attempts (writable/Cluster/
 * db_sync_log.json) - same directory/flock()/ring-buffer convention as
 * Stats/ConflictLog. One entry per attempt to move ONE entity across the
 * wire, in any of the three directions this package moves them: pushing
 * OUT to a peer (Jobs\SyncDbRowJob), receiving a push IN from a peer
 * (Controllers\DbSyncController::receive()), or pulling FROM a peer
 * (Commands\PullCommand::pullDbRows()/Commands\SyncDbCommand's
 * --bootstrap). Cluster::dbSyncDashboardSummary() derives both the
 * per-peer "last synced" times AND the "recent activity" list the
 * Dashboard's "Database synchronization" card shows from this single log,
 * rather than a separate state file - cheap since it's capped and small.
 */
class DbSyncLog
{
    private const MAX_ENTRIES = 200;

    private ClusterConfig $config;

    public function __construct(?ClusterConfig $config = null)
    {
        $this->config = $config ?? config('Cluster');
    }

    public function path(): string
    {
        return rtrim(WRITEPATH, '/\\') . '/' . trim($this->config->stateDir, '/\\') . '/db_sync_log.json';
    }

    /**
     * @param array{time: int, direction: string, peer: string, table: string, naturalKey: string, operation: string, ok: bool, error: string|null, queries: list<string>} $entry
     */
    public function record(array $entry): void
    {
        $path = $this->path();
        $dir  = dirname($path);
        if (! is_dir($dir) && ! mkdir($dir, 0775, true) && ! is_dir($dir)) {
            return; // best-effort - a log write failing must never break the actual sync
        }

        $handle = fopen($path, 'cb+');
        if ($handle === false) {
            return;
        }

        flock($handle, LOCK_EX);
        $contents = stream_get_contents($handle);
        $entries  = json_decode((string) $contents, true);
        $entries  = is_array($entries) ? $entries : [];

        $entries[] = $entry;
        if (count($entries) > self::MAX_ENTRIES) {
            $entries = array_slice($entries, -self::MAX_ENTRIES);
        }

        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
        @chmod($path, 0664);
    }

    /**
     * Oldest-first, same order they were recorded.
     *
     * @return list<array{time: int, direction: string, peer: string, table: string, naturalKey: string, operation: string, ok: bool, error: string|null, queries: list<string>}>
     */
    public function all(): array
    {
        $path = $this->path();
        if (! is_file($path)) {
            return [];
        }

        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return [];
        }
        flock($handle, LOCK_SH);
        $contents = stream_get_contents($handle);
        flock($handle, LOCK_UN);
        fclose($handle);

        $entries = json_decode((string) $contents, true);

        return is_array($entries) ? $entries : [];
    }
}

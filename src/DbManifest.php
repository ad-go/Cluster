<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use AdGo\Cluster\Config\Cluster as ClusterConfig;

/**
 * This node's own record of "the last DB-sync entity state I know I've
 * either exported or applied" (writable/Cluster/db_manifest.json), keyed
 * by "<table>:<naturalKey>" (e.g. "users:k@1q.ro"). Two jobs, same file:
 * SyncDbCommand's own scan uses it to detect local changes (compare a
 * freshly-computed hash against what's recorded here); DbSyncSchema::
 * applyIncomingCommand() uses the recorded `timestamp` as the row-level
 * LWW comparison point for an incoming write. Same flock-JSON convention
 * as the file manifest/ConflictLog/TimeDrift.
 */
class DbManifest
{
    private ClusterConfig $config;

    public function __construct(?ClusterConfig $config = null)
    {
        $this->config = $config ?? config('Cluster');
    }

    public function path(): string
    {
        return rtrim(WRITEPATH, '/\\') . '/' . trim($this->config->stateDir, '/\\') . '/db_manifest.json';
    }

    /**
     * @return array{hash: string, timestamp: int, recordedAt?: int}|null
     */
    public function get(string $key): ?array
    {
        $entry = $this->all()[$key] ?? null;

        return is_array($entry) ? $entry : null;
    }

    /**
     * @param array{hash: string, timestamp: int} $entry
     */
    public function record(string $key, array $entry): void
    {
        $path = $this->path();
        $dir  = dirname($path);
        if (! is_dir($dir) && ! mkdir($dir, 0775, true) && ! is_dir($dir)) {
            return;
        }

        $handle = fopen($path, 'cb+');
        if ($handle === false) {
            return;
        }

        flock($handle, LOCK_EX);
        $contents = stream_get_contents($handle);
        $entries  = json_decode((string) $contents, true);
        $entries  = is_array($entries) ? $entries : [];

        // Stamped here, not by each caller - so it can never be forgotten
        // at a call site. `timestamp` (the row's own updated_at, passed in
        // by the caller) stays the LWW comparison point in
        // applyIncomingCommand()'s own stale-rejection check, unchanged -
        // `recordedAt` is a SEPARATE field, this node's own wall-clock
        // "when did I last touch this entry", used only by pullRows()'s
        // since-filtering. Same split, same reasoning, as Cluster::
        // manifestSince()'s own docblock - a row relayed through this node
        // (NAT peer applying it via pullDbRows(), or this node's own scan
        // re-discovering an already-applied change) keeps the ORIGINAL
        // timestamp for correctness, but a peer asking THIS node "what's
        // changed since X" needs to know when THIS node found out, not
        // when the row was first written anywhere in the cluster.
        $entry['recordedAt'] = time();
        $entries[$key]       = $entry;

        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
        @chmod($path, 0664);
    }

    /**
     * @return array<string, array{hash: string, timestamp: int, recordedAt?: int}>
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

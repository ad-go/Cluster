<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use AdGo\Cluster\Config\Cluster as ClusterConfig;

/**
 * Records every push attempt (success or failure) to a bounded JSON ring
 * buffer (writable/Cluster/stats.json - same directory/flock() convention
 * as Cluster::loadManifest()/saveManifest()), so something can answer
 * "how fast, how much traffic, how many errors" without re-deriving it
 * from the Queue package's own tables (queue_jobs_failed only holds jobs
 * that exhausted all retries, not a full history of every attempt, and
 * has nothing about bytes/duration at all).
 *
 * Not itself the Dashboard widget - see Cluster::dashboardSummary(),
 * which reads this alongside the manifest and node registry. Kept as a
 * separate file/class from Cluster.php because it's a genuinely distinct
 * concern (write-mostly activity log vs. read-mostly config/state), not
 * because the two ever need to vary independently.
 */
class Stats
{
    // Ring buffer, not a growing log - a node pushing many files stays
    // bounded instead of writable/Cluster/stats.json growing forever.
    // Large enough that a burst of activity between two dashboard loads
    // doesn't just show the last few seconds.
    private const MAX_ENTRIES = 300;

    private ClusterConfig $config;

    public function __construct(?ClusterConfig $config = null)
    {
        $this->config = $config ?? config('Cluster');
    }

    public function path(): string
    {
        return rtrim(WRITEPATH, '/\\') . '/' . trim($this->config->stateDir, '/\\') . '/stats.json';
    }

    /**
     * @param array{time: int, peer: string, path: string, bytes: int, durationMs: int, ok: bool, error: ?string} $entry
     */
    public function record(array $entry): void
    {
        $path = $this->path();
        $dir  = dirname($path);
        if (! is_dir($dir) && ! mkdir($dir, 0775, true) && ! is_dir($dir)) {
            return; // best-effort - a stats write failing must never break the actual push
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
        // See Cluster::saveManifest()'s own comment on this - setgid alone
        // doesn't make a freshly-created file group-writable, only
        // group-owned.
        @chmod($path, 0664);
    }

    /**
     * Oldest-first, same order they were recorded.
     *
     * @return list<array{time: int, peer: string, path: string, bytes: int, durationMs: int, ok: bool, error: ?string}>
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

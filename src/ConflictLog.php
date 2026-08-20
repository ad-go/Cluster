<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use AdGo\Cluster\Config\Cluster as ClusterConfig;

/**
 * Bounded activity log of resolved file conflicts (writable/Cluster/
 * conflicts.json - same directory/flock() convention as Stats/SyncState/
 * the manifest). NOT the preserved losing content itself - that's one
 * real file per conflict under writable/Cluster/conflicts/, written by
 * Cluster::preserveConflictLoser() alongside a call to record() here.
 * This is only the "when/where/who won" trail, same write-mostly-
 * activity-log role Stats already has for push attempts - kept as a
 * separate file/class for the same reason Stats is: a genuinely distinct
 * concern from the manifest's own read-mostly current-state role.
 */
class ConflictLog
{
    // Ring buffer, not a growing log - same reasoning as Stats::
    // MAX_ENTRIES. Conflicts are expected to be rare, so this bound
    // should rarely if ever actually get hit in practice.
    private const MAX_ENTRIES = 100;

    private ClusterConfig $config;

    public function __construct(?ClusterConfig $config = null)
    {
        $this->config = $config ?? config('Cluster');
    }

    public function path(): string
    {
        return rtrim(WRITEPATH, '/\\') . '/' . trim($this->config->stateDir, '/\\') . '/conflicts.json';
    }

    /**
     * @param array{time: int, path: string, winner: string, loser: string, archive: string} $entry
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
        // See Cluster::saveManifest()'s own comment on this - setgid alone
        // doesn't make a freshly-created file group-writable, only
        // group-owned.
        @chmod($path, 0664);
    }

    /**
     * Oldest-first, same order they were recorded.
     *
     * @return list<array{time: int, path: string, winner: string, loser: string, archive: string}>
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

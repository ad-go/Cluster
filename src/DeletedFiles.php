<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use AdGo\Cluster\Config\Cluster as ClusterConfig;

/**
 * Tombstones for locally-deleted files - writable/Cluster/deleted_files.json,
 * `relativePath => {deletedAt, recordedAt}` (unix timestamps - deletedAt is
 * the original event time, recordedAt is this node's own "when did I learn
 * this", see allSince()'s own docblock for why they're kept separate), same
 * flock-JSON convention as the manifest/SessionInvalidation/TimeDrift.
 * Exists because a deleted
 * path is, by definition, no longer IN the manifest - Cluster::
 * manifestSince() (the file-sync equivalent of "what changed") structurally
 * cannot report a deletion, since there's no entry left to compare a
 * timestamp against. This is the delete-side counterpart: a peer's
 * cluster:pull asks for tombstones newer than `since` the same way it
 * already asks for manifest entries newer than `since`.
 *
 * Written by two callers, same pattern as SessionInvalidation:
 * - Commands\SyncFilesCommand writes the LOCAL entry directly, the moment
 *   its scan notices a manifest entry whose file is gone from disk.
 * - Cluster::applyIncomingDeletion() writes an entry on every OTHER node
 *   that applies an incoming deletion (received via push OR pull) - this
 *   is what lets the tombstone keep propagating to THAT node's own pullers
 *   in turn, without any node needing to explicitly relay/forward anything
 *   (see that method's own docblock for why this project's specific
 *   full-mesh-among-public-nodes topology never needs an explicit relay
 *   chain beyond this).
 */
class DeletedFiles
{
    private ClusterConfig $config;

    public function __construct(?ClusterConfig $config = null)
    {
        $this->config = $config ?? config('Cluster');
    }

    public function path(): string
    {
        return rtrim(WRITEPATH, '/\\') . '/' . trim($this->config->stateDir, '/\\') . '/deleted_files.json';
    }

    public function record(string $relativePath, int $deletedAt): void
    {
        if ($relativePath === '') {
            return;
        }

        $path = $this->path();
        $dir  = dirname($path);
        if (! is_dir($dir) && ! mkdir($dir, 0775, true) && ! is_dir($dir)) {
            return; // best-effort - must never break the actual delete
        }

        $handle = fopen($path, 'cb+');
        if ($handle === false) {
            return;
        }

        flock($handle, LOCK_EX);
        $contents = stream_get_contents($handle);
        $entries  = json_decode((string) $contents, true);
        $entries  = is_array($entries) ? $entries : [];

        // {deletedAt, recordedAt} now, not a bare int - see allSince()'s
        // own docblock for why (recordedAt is what since-filtering needs;
        // deletedAt stays the LWW comparison point applyIncomingDeletion()
        // uses, unchanged across every relay hop). A pre-existing bare-int
        // entry (written before this field existed) is left as-is here -
        // normalizeEntry() below treats it as recordedAt===deletedAt until
        // it naturally gets rewritten by a real future delete of that path.
        $entries[$relativePath] = ['deletedAt' => $deletedAt, 'recordedAt' => time()];

        // Pruned on every write, not a background sweep - the retention
        // window (30 days) is far longer than any realistic
        // pullLookbackSeconds/cron-downtime gap this exists to cover, so
        // this only ever discards tombstones nobody could still need,
        // keeping the file from growing forever on a node with heavy
        // churn.
        $cutoff  = time() - (30 * 86400);
        $entries = array_filter($entries, static fn ($entry): bool => self::normalizeEntry($entry)['deletedAt'] > $cutoff);

        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
        @chmod($path, 0664);
    }

    /**
     * Every tombstone this node learned about strictly after $since - what
     * PullController exposes to a peer's cluster:pull command, same
     * rolling-window query shape as SessionInvalidation::allSince()/
     * Cluster::manifestSince(). Filters by `recordedAt` (this node's own
     * wall-clock "when did I learn this path was deleted"), not
     * `deletedAt` (the original event time, unchanged across relay hops)
     * - see record()'s own docblock for why: a NAT peer relaying this
     * tombstone through a public node needs "since I last checked", not
     * "since the delete originally happened anywhere in the cluster".
     * Still RETURNS `deletedAt` as the value (callers - a peer applying
     * this via applyIncomingDeletion() - need the original event time for
     * their own LWW comparison, not this node's recordedAt).
     *
     * @return array<string, int> relativePath => deletedAt
     */
    public function allSince(int $since): array
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
        if (! is_array($entries)) {
            return [];
        }

        $result = [];
        foreach ($entries as $relativePath => $raw) {
            $entry = self::normalizeEntry($raw);
            if ($entry['recordedAt'] > $since) {
                $result[$relativePath] = $entry['deletedAt'];
            }
        }

        return $result;
    }

    /**
     * A pre-existing entry written before {deletedAt, recordedAt} existed
     * is a bare int - treated as recordedAt===deletedAt (matches this
     * field's previous, only, behavior for that entry, until it's
     * naturally rewritten by a real future delete of that same path).
     *
     * @param mixed $raw
     *
     * @return array{deletedAt: int, recordedAt: int}
     */
    private static function normalizeEntry($raw): array
    {
        if (is_array($raw)) {
            return ['deletedAt' => (int) ($raw['deletedAt'] ?? 0), 'recordedAt' => (int) ($raw['recordedAt'] ?? $raw['deletedAt'] ?? 0)];
        }

        $value = (int) $raw;

        return ['deletedAt' => $value, 'recordedAt' => $value];
    }
}

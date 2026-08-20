<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use AdGo\Cluster\Config\Cluster as ClusterConfig;

/**
 * Per-user "sessions issued before this moment are no longer trusted"
 * timestamps, keyed by email - written to
 * writable/Cluster/invalidations.json (same directory/flock() convention
 * as Cluster::loadManifest()/Stats/SyncState).
 *
 * Keyed by EMAIL, not the Shield user ID: this cluster has no DB
 * replication (see this package's README "Not built yet") - every node
 * runs its own completely independent Shield database, so the same real
 * person's account has a DIFFERENT numeric ID on every node, even though
 * every node was bootstrapped with the same superadmin email. Email is
 * the only identifier that actually means the same thing across nodes.
 *
 * Written by two callers:
 * - Cluster::broadcastInvalidation() (shared by broadcastPasswordChange()
 *   AND broadcastLogout()) writes the LOCAL entry directly (no HTTP
 *   round-trip needed for the node where the change/logout happened).
 * - InvalidationController::receive() writes an entry on every OTHER node,
 *   from a peer's BroadcastInvalidationJob push.
 *
 * Read by SessionInvalidationFilter on every request: a logged-in
 * session whose own login timestamp (stamped by the 'login' Shield event
 * into session('cluster_login_at')) is older than this file's entry for
 * that session's email gets logged out immediately.
 */
class SessionInvalidation
{
    private ClusterConfig $config;

    public function __construct(?ClusterConfig $config = null)
    {
        $this->config = $config ?? config('Cluster');
    }

    public function path(): string
    {
        return rtrim(WRITEPATH, '/\\') . '/' . trim($this->config->stateDir, '/\\') . '/invalidations.json';
    }

    /**
     * Only ever moves a user's invalidation timestamp FORWARD - an
     * out-of-order delivery (a peer's queue job retries and lands after a
     * newer one already arrived) must never un-invalidate a session that a
     * more recent change already caught. That check is always against
     * `changedAt` (the original event time) - `recordedAt` (this node's
     * own "when did I learn this", used only by allSince()'s since-
     * filtering - see its own docblock) always advances to now on every
     * write, even one that doesn't move changedAt forward, since THIS node
     * still just (re-)learned about it.
     */
    public function recordInvalidation(string $email, int $changedAt): void
    {
        $email = strtolower(trim($email));
        if ($email === '') {
            return;
        }

        $path = $this->path();
        $dir  = dirname($path);
        if (! is_dir($dir) && ! mkdir($dir, 0775, true) && ! is_dir($dir)) {
            return; // best-effort - must never break the password-change request itself
        }

        $handle = fopen($path, 'cb+');
        if ($handle === false) {
            return;
        }

        flock($handle, LOCK_EX);
        $contents = stream_get_contents($handle);
        $entries  = json_decode((string) $contents, true);
        $entries  = is_array($entries) ? $entries : [];

        $existing = self::normalizeEntry($entries[$email] ?? null);
        if ($changedAt > $existing['changedAt']) {
            $entries[$email] = ['changedAt' => $changedAt, 'recordedAt' => time()];

            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, json_encode($entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            fflush($handle);
        }
        flock($handle, LOCK_UN);
        fclose($handle);
        // Same cross-user-write reasoning as SyncState/Stats/the manifest -
        // this file gets its first write from whichever user hits it
        // first (CLI queue worker for a remote broadcast vs. PHP-FPM for a
        // local password change), and setgid on writable/Cluster/ alone
        // doesn't make a freshly-created file group-writable.
        @chmod($path, 0664);
    }

    /**
     * Null if this email has never had a recorded password change on this
     * node (the common case - most users never trigger this at all).
     */
    public function invalidatedAt(string $email): ?int
    {
        $email = strtolower(trim($email));
        if ($email === '') {
            return null;
        }

        $path = $this->path();
        if (! is_file($path)) {
            return null;
        }

        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return null;
        }
        flock($handle, LOCK_SH);
        $contents = stream_get_contents($handle);
        flock($handle, LOCK_UN);
        fclose($handle);

        $entries = json_decode((string) $contents, true);
        if (! is_array($entries) || ! isset($entries[$email])) {
            return null;
        }

        return self::normalizeEntry($entries[$email])['changedAt'];
    }

    /**
     * Every entry this node learned about strictly after $since - what
     * PullController exposes to a peer's cluster:pull command (see that
     * command's own docblock for why this is a stateless rolling-window
     * query, not a per-peer cursor). Filters by `recordedAt` (this node's
     * own wall-clock "when did I learn this"), not `changedAt` (the
     * original event time, unchanged across relay hops) - see
     * recordInvalidation()'s own docblock for why: a NAT peer relaying
     * this through a public node needs "since I last checked", not "since
     * the password change/logout originally happened anywhere in the
     * cluster". Still RETURNS `changedAt` as the value (a peer applying
     * this needs the original event time for its own forward-only check).
     *
     * @return array<string, int> email => changedAt
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
        foreach ($entries as $email => $raw) {
            $entry = self::normalizeEntry($raw);
            if ($entry['recordedAt'] > $since) {
                $result[$email] = $entry['changedAt'];
            }
        }

        return $result;
    }

    /**
     * A pre-existing entry written before {changedAt, recordedAt} existed
     * is a bare int - treated as recordedAt===changedAt (matches this
     * field's previous, only, behavior for that entry, until it's
     * naturally rewritten by a real future invalidation for that email).
     *
     * @param mixed $raw
     *
     * @return array{changedAt: int, recordedAt: int}
     */
    private static function normalizeEntry($raw): array
    {
        if (is_array($raw)) {
            return ['changedAt' => (int) ($raw['changedAt'] ?? 0), 'recordedAt' => (int) ($raw['recordedAt'] ?? $raw['changedAt'] ?? 0)];
        }

        $value = (int) $raw;

        return ['changedAt' => $value, 'recordedAt' => $value];
    }
}

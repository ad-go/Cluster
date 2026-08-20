<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use AdGo\Cluster\Config\Cluster as ClusterConfig;

/**
 * Last-known-sync state per peer, in both directions - written to
 * writable/Cluster/sync_state.json (same directory/flock() convention as
 * Cluster::loadManifest()/Stats). Deliberately NOT a ring buffer like
 * Stats: this holds exactly one row per peer name (overwritten on every
 * attempt), because the Dashboard only ever needs "when did this specific
 * connection last sync", not a history - Stats already covers the
 * recent-activity/error history separately.
 *
 * Three independent halves:
 * - outgoing: peers THIS node pushes to (PushFileJob calls recordOutgoing()
 *   after every attempt, success or failure - dashboardSummary() only
 *   surfaces successful ones as "last sync", but a failing peer's row still
 *   updates 'time'/'ok' so a stuck connection is visible too).
 * - incoming: peers that pushed TO this node (FileReceiverController calls
 *   recordIncoming() after a successful write). This is what makes a 'nat'
 *   peer's activity visible at all - a nat node (like 'bak') is excluded
 *   from Cluster::publicPeers() since this node can never push TO it, but
 *   it can still push files IN, and the Dashboard has no other way to know
 *   that happened.
 * - pull: public peers THIS node pulled FROM (PullCommand calls
 *   recordPull() after every pass() attempt against a peer, success or
 *   failure - same "still record a failing attempt" reasoning as outgoing
 *   above). Added 2026-08-18: cluster:pull applied files/invalidations
 *   exactly as durably as push always did, but had no Dashboard visibility
 *   of its own until now (see README's former "Not built yet" entry on
 *   this).
 *
 * The peer name recorded on the incoming side is SELF-REPORTED by the
 * sender (a 'peer' field alongside path/hash/mtime in PushFileJob's
 * multipart POST) - the shared-secret Bearer auth this package uses
 * doesn't distinguish which peer is calling, only that the caller knows
 * the secret. This is fine for what it's used for (a Dashboard label), but
 * it is NOT an authenticated identity - FileReceiverController only
 * records it when the claimed name matches a node actually present in
 * this node's own registry, which stops typos/garbage from an
 * unconfigured caller but does not stop a configured peer from claiming
 * another configured peer's name.
 */
class SyncState
{
    private ClusterConfig $config;

    public function __construct(?ClusterConfig $config = null)
    {
        $this->config = $config ?? config('Cluster');
    }

    public function path(): string
    {
        return rtrim(WRITEPATH, '/\\') . '/' . trim($this->config->stateDir, '/\\') . '/sync_state.json';
    }

    public function recordOutgoing(string $peer, string $path, bool $ok): void
    {
        $this->update('outgoing', $peer, ['time' => time(), 'path' => $path, 'ok' => $ok]);
    }

    public function recordIncoming(string $peer, string $path): void
    {
        $this->update('incoming', $peer, ['time' => time(), 'path' => $path]);
    }

    public function recordPull(string $peer, bool $ok): void
    {
        $this->update('pull', $peer, ['time' => time(), 'ok' => $ok]);
    }

    /**
     * @param array<string, mixed> $row
     */
    private function update(string $direction, string $peer, array $row): void
    {
        if ($peer === '') {
            return;
        }

        $path = $this->path();
        $dir  = dirname($path);
        if (! is_dir($dir) && ! mkdir($dir, 0775, true) && ! is_dir($dir)) {
            return; // best-effort - must never break the actual push/receive
        }

        $handle = fopen($path, 'cb+');
        if ($handle === false) {
            return;
        }

        flock($handle, LOCK_EX);
        $contents = stream_get_contents($handle);
        $state    = json_decode((string) $contents, true);
        $state    = is_array($state) ? $state : [];
        $state['outgoing'] ??= [];
        $state['incoming'] ??= [];
        $state['pull'] ??= [];

        $state[$direction][$peer] = $row;

        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
        // This is the ONE file in this package guaranteed to be written by
        // both system users on every node (outgoing: whichever user runs
        // spark/cron; incoming: whichever user runs PHP-FPM/nginx) on its
        // very first write, not just eventually - setgid on writable/
        // Cluster/ fixes the file's GROUP but not its permission bits, so
        // whichever user creates it first can lock the other one out
        // depending on their umask. Found live 2026-08-18: the very first
        // real cross-user write here failed with EACCES. See
        // Cluster::saveManifest()'s matching comment.
        @chmod($path, 0664);
    }

    /**
     * @return array{
     *     outgoing: array<string, array{time: int, path: string, ok: bool}>,
     *     incoming: array<string, array{time: int, path: string}>,
     *     pull: array<string, array{time: int, ok: bool}>
     * }
     */
    public function all(): array
    {
        $empty = ['outgoing' => [], 'incoming' => [], 'pull' => []];

        $path = $this->path();
        if (! is_file($path)) {
            return $empty;
        }

        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return $empty;
        }
        flock($handle, LOCK_SH);
        $contents = stream_get_contents($handle);
        flock($handle, LOCK_UN);
        fclose($handle);

        $state = json_decode((string) $contents, true);
        if (! is_array($state)) {
            return $empty;
        }

        return [
            'outgoing' => is_array($state['outgoing'] ?? null) ? $state['outgoing'] : [],
            'incoming' => is_array($state['incoming'] ?? null) ? $state['incoming'] : [],
            'pull'     => is_array($state['pull'] ?? null) ? $state['pull'] : [],
        ];
    }
}

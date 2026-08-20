<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use AdGo\Cluster\Config\Cluster as ClusterConfig;
use CodeIgniter\HTTP\CURLRequest;
use RuntimeException;

/**
 * Shared primitives used by the scan command, the push job, and the
 * receiving controller: path resolution/safety, the local state manifest
 * (writable/Cluster/files_manifest.json - flock()-guarded per the spec's
 * own concurrency warning about parallel PHP-FPM requests corrupting a
 * shared JSON file), and the node registry.
 *
 * Deliberately NOT a CI4 Config class itself (that's Config\Cluster) -
 * this is behavior, Config\Cluster is data.
 */
class Cluster
{
    private ClusterConfig $config;

    public function __construct(?ClusterConfig $config = null)
    {
        $this->config = $config ?? config('Cluster');
    }

    public function thisNodeName(): string
    {
        return $this->config->thisNode;
    }

    public function secretToken(): string
    {
        return $this->config->secretToken;
    }

    public function queueName(): string
    {
        return $this->config->queueName;
    }

    /**
     * Builds the Authorization header value every outgoing peer-to-peer
     * call sends - see Config\Cluster::$signingPrivateKey's own docblock
     * for the full reasoning. Signs "$thisNode.$timestamp" with this
     * node's own RSA private key when one is configured; falls back to
     * the legacy bare shared-secret scheme otherwise (a node mid-rollout,
     * or one that's deliberately not been given a keypair).
     */
    public function authHeader(): string
    {
        $privateKeyPem = $this->config->signingPrivateKey !== '' ? base64_decode($this->config->signingPrivateKey, true) : false;
        if ($privateKeyPem === false || $privateKeyPem === '') {
            return 'Bearer ' . $this->secretToken();
        }

        $message   = $this->config->thisNode . '.' . time();
        $signature = '';
        if (! openssl_sign($message, $signature, $privateKeyPem, OPENSSL_ALGO_SHA256)) {
            // Never send an unsigned/garbage header just because signing
            // failed for some reason (a malformed key, an openssl
            // hiccup) - the legacy fallback is still a valid credential
            // as long as $secretToken is configured, so prefer that over
            // a request guaranteed to be rejected.
            return 'Bearer ' . $this->secretToken();
        }

        return 'Bearer ' . $message . '.' . base64_encode($signature);
    }

    /**
     * Verifies an incoming Authorization header - ClusterAuthFilter's
     * only real job. Two forms, tried in order:
     *
     * 1. "<nodeName>.<timestamp>.<base64 signature>" - the signed form.
     *    $nodeName's public key comes from THIS node's own $nodes
     *    registry, never from the request itself (an attacker claiming
     *    to be "h1q" doesn't get to also supply "h1q"'s key). Rejected
     *    if $nodeName isn't in the registry, has no publicKey on file, the
     *    signature doesn't verify, or $timestamp is more than 5 minutes
     *    from this node's own clock (bounds replay - a captured header
     *    stops being usable well before this project's own clock-drift
     *    tolerance would ever produce a false rejection).
     * 2. A bare shared secret (the legacy scheme, kept only as a rollout
     *    fallback - see Config\Cluster::$signingPrivateKey's docblock).
     *    Tried only when the header doesn't parse as form 1 at all, so a
     *    signed-but-invalid header is a hard reject, not a silent
     *    downgrade to the weaker check.
     */
    public function verifyAuthHeader(string $header): bool
    {
        $given = str_starts_with($header, 'Bearer ') ? substr($header, 7) : '';
        if ($given === '') {
            return false;
        }

        $parts = explode('.', $given, 3);
        if (count($parts) === 3) {
            [$nodeName, $timestampRaw, $signatureB64] = $parts;
            if (abs(time() - (int) $timestampRaw) > 300) {
                return false;
            }

            $publicKeyB64 = $this->config->nodes[$nodeName]['publicKey'] ?? '';
            if ($publicKeyB64 === '') {
                return false;
            }
            $publicKeyPem = base64_decode($publicKeyB64, true);
            $signature    = base64_decode($signatureB64, true);
            if ($publicKeyPem === false || $signature === false) {
                return false;
            }

            return openssl_verify($nodeName . '.' . $timestampRaw, $signature, $publicKeyPem, OPENSSL_ALGO_SHA256) === 1;
        }

        $expected = $this->secretToken();

        return $expected !== '' && hash_equals($expected, $given);
    }

    /**
     * Same verification as verifyAuthHeader() but returns the CALLER's own
     * verified node name instead of a bare bool - needed wherever a
     * receiving endpoint's behavior depends on WHICH peer is asking, not
     * just whether the request is legitimately from some cluster member
     * (see RemoteTestController::pullTestRequests(), which must return
     * only the pending queue entries addressed to whichever node is
     * actually calling). Only meaningful for the signed form (form 1 in
     * verifyAuthHeader()'s own docblock) - the legacy bare-secret fallback
     * carries no identity at all, so that path returns null even though
     * verifyAuthHeader() itself would accept it.
     */
    public function verifiedCallerName(string $header): ?string
    {
        $given = str_starts_with($header, 'Bearer ') ? substr($header, 7) : '';
        if ($given === '') {
            return null;
        }

        $parts = explode('.', $given, 3);
        if (count($parts) !== 3) {
            return null;
        }

        [$nodeName, $timestampRaw, $signatureB64] = $parts;
        if (abs(time() - (int) $timestampRaw) > 300) {
            return null;
        }

        $publicKeyB64 = $this->config->nodes[$nodeName]['publicKey'] ?? '';
        if ($publicKeyB64 === '') {
            return null;
        }
        $publicKeyPem = base64_decode($publicKeyB64, true);
        $signature    = base64_decode($signatureB64, true);
        if ($publicKeyPem === false || $signature === false) {
            return null;
        }

        return openssl_verify($nodeName . '.' . $timestampRaw, $signature, $publicKeyPem, OPENSSL_ALGO_SHA256) === 1
            ? $nodeName
            : null;
    }

    /**
     * Call this the moment a password change is actually saved (see
     * cluster-ui's ProfileController/UsersController) - records the
     * invalidation LOCALLY right away (so other sessions for this email
     * on THIS node are caught on their very next request, no network
     * round-trip needed) and queues one BroadcastInvalidationJob per
     * public peer so their sessions catch it too within about a minute
     * (queue:work is cron-driven, same cadence as file push - see
     * SyncFilesCommand). 'nat' peers are never reached (same reachability
     * constraint as file push - see README's "Not built yet"): a session
     * on an unreachable node won't be caught by this broadcast.
     */
    public function broadcastPasswordChange(string $email): void
    {
        $this->broadcastInvalidation($email);
    }

    /**
     * Call this the moment a user logs out (see cluster-ui's
     * AuthController::logoutAction()) - same underlying mechanism as
     * broadcastPasswordChange() above, just a different trigger. Kills
     * EVERY session for this email across the cluster, not only the one
     * that actually clicked logout: SessionInvalidationFilter has no
     * concept of "which session" - it only compares each session's own
     * login timestamp against this email's latest invalidation, which is
     * exactly the "logged out on one node -> logged out on every node"
     * behavior this exists for (including any session reached via the
     * cross-node SSO handoff - see SsoController).
     */
    public function broadcastLogout(string $email): void
    {
        $this->broadcastInvalidation($email);
    }

    /**
     * Call this the moment a superadmin deletes a user's account (see
     * cluster-ui's UsersController::delete()) - same underlying mechanism
     * as broadcastPasswordChange()/broadcastLogout() above. Without this,
     * a deleted account's existing sessions on OTHER nodes stayed alive
     * until each node's own session TTL expired there, even though the
     * account itself was already gone on this node (and, once
     * cluster:sync-db's next tick runs, on the deleting node's DB-synced
     * peers too - see DbSyncSchema's own docblock on why deletion
     * propagation there is a separate, not-yet-built concern from this).
     *
     * See broadcastAccountDeactivated() below for the (now built)
     * suspend/ban counterpart to this.
     */
    public function broadcastAccountRemoved(string $email): void
    {
        $this->broadcastInvalidation($email);
    }

    /**
     * Call this the moment a superadmin bans a user's account (see
     * cluster-ui's UsersController::ban()) - same underlying mechanism as
     * broadcastAccountRemoved() above, just for a reversible suspension
     * instead of a permanent deletion. Uses Shield's own built-in
     * Bannable trait (User::ban()/isBanned(), already checked by
     * Session::attempt() to refuse new logins) for the "can't log back
     * in" half; this call is what handles the OTHER half - an already
     * logged-in session, on this node or any other, doesn't just expire
     * on its own schedule once banned, it's killed on the very next
     * request everywhere, same as a password change or logout.
     */
    public function broadcastAccountDeactivated(string $email): void
    {
        $this->broadcastInvalidation($email);
    }

    /**
     * Shared by broadcastPasswordChange()/broadcastLogout()/
     * broadcastAccountRemoved() above - all three are "invalidate every
     * session for this email, as of now", just named for their own call
     * site's clarity. See broadcastPasswordChange()'s own docblock (still
     * applies verbatim here) for the local-write / per-peer-queue-job
     * mechanics.
     */
    private function broadcastInvalidation(string $email): void
    {
        // Master off switch (see Config\Cluster::$sessionSyncEnabled) - a
        // disabled node neither records its own local invalidation nor
        // broadcasts one to peers, matching "this node doesn't
        // participate in session sync at all" rather than half-applying
        // it locally while skipping the network side.
        if (! $this->config->sessionSyncEnabled) {
            return;
        }

        $email = strtolower(trim($email));
        if ($email === '') {
            return;
        }

        $changedAt = time();
        (new SessionInvalidation($this->config))->recordInvalidation($email, $changedAt);

        foreach (array_keys($this->publicPeers()) as $peerName) {
            service('queue')->push($this->config->queueName, 'cluster-broadcast-invalidation', [
                'email'     => $email,
                'changedAt' => $changedAt,
                'peer'      => $peerName,
            ]);
        }
    }

    /**
     * @return array{baseURL: string, type: string}|null
     */
    public function node(string $name): ?array
    {
        return $this->config->nodes[$name] ?? null;
    }

    /**
     * Peers this node pushes to directly - 'nat' nodes are excluded here
     * on purpose (they Pull instead; see README "Not built yet" - pushing
     * to one over plain HTTPS would just time out).
     *
     * @return array<string, array{baseURL: string, type: string}>
     */
    public function publicPeers(): array
    {
        $thisNode = $this->config->thisNode;

        return array_filter(
            $this->config->nodes,
            static fn (array $node, string $name): bool => $node['type'] === 'public' && $name !== $thisNode,
            ARRAY_FILTER_USE_BOTH
        );
    }

    /**
     * The mirror image of publicPeers(): nodes THIS node can never push to
     * (type 'nat', or anything not 'public') but that may still push files
     * IN - see SyncState's own docblock. Used only to label the Dashboard's
     * connections list; nothing in the push/scan path reads this.
     *
     * @return array<string, array{baseURL: string, type: string}>
     */
    public function natPeers(): array
    {
        $thisNode = $this->config->thisNode;

        return array_filter(
            $this->config->nodes,
            static fn (array $node, string $name): bool => $node['type'] !== 'public' && $name !== $thisNode,
            ARRAY_FILTER_USE_BOTH
        );
    }

    /**
     * Every OTHER configured node regardless of type - unlike
     * publicPeers()/natPeers(), reachability isn't assumed from topology
     * here (see TimeDriftCommand: two 'nat' peers on the same LAN can
     * often reach each other directly even though neither can push files
     * to the other over the public internet, so excluding 'nat' entries
     * would silently miss real, useful measurements).
     *
     * @return array<string, array{baseURL: string, type: string}>
     */
    public function allPeers(): array
    {
        $thisNode = $this->config->thisNode;

        return array_filter(
            $this->config->nodes,
            static fn (array $node, string $name): bool => $name !== $thisNode,
            ARRAY_FILTER_USE_BOTH
        );
    }

    /**
     * The full registry, this node included - unlike allPeers(), which
     * exists to answer "who do I talk to". Used by cluster-ui's Settings
     * page to render one row per node, this one too.
     *
     * @return array<string, array{baseURL: string, type: string}>
     */
    public function allNodes(): array
    {
        return $this->config->nodes;
    }

    /**
     * One-shot clock-offset measurement against whatever peer $client is
     * already scoped to (Cristian's algorithm - see this package's README
     * "How clock drift is measured") - queries cluster/time on that SAME
     * client. Every call site (TimeDriftCommand, PullCommand::pass(),
     * PushFileJob::process()) already builds a peer-scoped CURLRequest for
     * its own purposes, so this never constructs its own - avoids a
     * redundant second client/connection just to time one request.
     *
     * Throws on any failure (unreachable, timeout, non-200, bad body) -
     * callers decide what "measurement failed" means for them (compare
     * TimeDriftCommand, which surfaces the exact error, against
     * correctMtimeFromPeer()/correctMtimeForPeer()'s callers in
     * PullCommand/PushFileJob, which fall back to offset 0.0 rather than
     * let a failed timing probe block the actual file transfer).
     *
     * @return array{offset: float, rtt: float, peerTime: float}
     */
    public function measureDrift(CURLRequest $client): array
    {
        $t0       = microtime(true);
        $response = $client->get('cluster/time', [
            'headers' => ['Authorization' => $this->authHeader()],
        ]);
        $t1 = microtime(true);

        if ($response->getStatusCode() !== 200) {
            throw new RuntimeException('cluster/time HTTP ' . $response->getStatusCode());
        }

        $body     = json_decode($response->getBody(), true);
        $peerTime = (float) ($body['time'] ?? 0);
        $rtt      = $t1 - $t0;
        $offset   = ($peerTime + $rtt / 2) - $t1;

        return ['offset' => $offset, 'rtt' => $rtt, 'peerTime' => $peerTime];
    }

    /**
     * Converts a peer-reported mtime into THIS node's clock frame - see
     * this package's README "How clock drift is measured" for the sign
     * convention/derivation. Used right after a pull download, before the
     * value is used in detectConflict()/finalizeIncomingFile() - so a
     * genuine two-sided conflict is judged by corrected timestamps, not
     * raw ones a few seconds of clock skew could flip the wrong way.
     */
    public function correctMtimeFromPeer(int $claimedMtime, float $offset): int
    {
        return (int) round($claimedMtime - $offset);
    }

    /**
     * Converts this node's OWN raw mtime into the TARGET peer's clock
     * frame - mirror of correctMtimeFromPeer(). Used right before a push,
     * so the value the peer touch()'s onto disk is already correct there.
     * The receiving side must NOT apply any further correction of its own
     * (see FileReceiverController's own docblock on this invariant) -
     * doing so would double-correct an already-corrected value.
     */
    public function correctMtimeForPeer(int $localMtime, float $offset): int
    {
        return (int) round($localMtime + $offset);
    }

    /**
     * @return list<string> absolute directories under WRITEPATH that get scanned/received into
     */
    public function syncDirs(): array
    {
        return array_map(
            static fn (string $relative): string => rtrim(WRITEPATH, '/\\') . '/' . trim($relative, '/\\'),
            $this->config->syncPaths
        );
    }

    /**
     * Resolves a peer-supplied relative path to a local absolute path,
     * refusing anything that would escape the configured sync directories
     * (path traversal via "../", an absolute path, or a path that simply
     * isn't under any configured syncPaths entry). Returns null rather
     * than throwing - callers (the receiving controller) treat null as
     * "reject the request", not a fatal error worth a 500.
     */
    public function resolveIncomingPath(string $relative): ?string
    {
        $relative = str_replace('\\', '/', $relative);
        if ($relative === '' || str_starts_with($relative, '/') || str_contains($relative, '..')) {
            return null;
        }

        foreach ($this->syncDirs() as $dir) {
            $candidate = $dir . '/' . $relative;
            // realpath() only resolves existing paths - the parent
            // directory (not the file itself, which may not exist yet on
            // the receiving side) is what must be confirmed to stay inside
            // $dir.
            $parent = dirname($candidate);
            if (! is_dir($parent) && ! @mkdir($parent, 0775, true) && ! is_dir($parent)) {
                continue;
            }
            $realParent = realpath($parent);
            $realDir    = realpath($dir);
            if ($realParent === false || $realDir === false || ! str_starts_with($realParent, $realDir)) {
                continue;
            }

            return $candidate;
        }

        return null;
    }

    /**
     * Resolves a peer-supplied relative path to a local absolute path of a
     * file that must ALREADY exist under one of the configured syncDirs -
     * the read-side counterpart to resolveIncomingPath() (a write target
     * that may not exist yet). Used by PullController::file() to validate
     * a peer's cluster:pull download request. Same traversal protections
     * (".." and a leading "/" are rejected outright); realpath()'s own
     * resolution then confirms the result actually stays inside the
     * specific syncDir it matched, not just textually looks like it does.
     */
    public function resolveExistingSyncPath(string $relative): ?string
    {
        $relative = str_replace('\\', '/', $relative);
        if ($relative === '' || str_starts_with($relative, '/') || str_contains($relative, '..')) {
            return null;
        }

        foreach ($this->syncDirs() as $dir) {
            $candidate = $dir . '/' . $relative;
            if (! is_file($candidate)) {
                continue;
            }

            $real    = realpath($candidate);
            $realDir = realpath($dir);
            if ($real === false || $realDir === false || ! str_starts_with($real, $realDir . DIRECTORY_SEPARATOR)) {
                continue;
            }

            return $candidate;
        }

        return null;
    }

    /**
     * Every manifest entry this node learned about (locally or via a
     * peer) strictly after $since - what PullController exposes as the
     * "what's changed" list for a peer's cluster:pull command to compare
     * against its OWN manifest and selectively download.
     *
     * Filters by `recordedAt` (this node's own wall-clock time when the
     * entry was last written), NOT `mtime` (the file's original author
     * timestamp, preserved unchanged across every hop for LWW correctness
     * - see detectConflict()). Those two used to be conflated here, which
     * broke exactly the case a NAT node relies on: a NAT peer (bak) can
     * only ever push to a `public` peer (h1q/beta/upz - see
     * publicPeers()), never to another NAT peer (res) directly, so res
     * only ever sees bak's changes secondhand, via whichever public node
     * relayed them. mtime survives that hop unchanged (by design, for LWW),
     * but the ORIGINAL mtime can already be older than a later hop's own
     * rolling `since` window by the time it arrives there - three
     * cron-driven ~60s cadences chain on the way (bak's own scan, bak's
     * own queue-worker tick, res's own pull tick), which can approach or
     * exceed the default 180s `pullLookbackSeconds` in the worst case,
     * silently dropping the file from res's pull even though res has
     * genuinely never seen it. `recordedAt` tracks "when did THIS node's
     * copy of the entry last change" instead, which is correct at every
     * hop independently, regardless of the original mtime. Falls back to
     * `mtime` for a legacy entry written before this field existed (a
     * one-time gap for entries mid-flight at upgrade time, self-heals on
     * their next real change).
     *
     * @return array<string, array{hash: string, mtime: int, size: int, recordedAt: int}>
     */
    public function manifestSince(int $since): array
    {
        return array_filter(
            $this->loadManifest(),
            static fn (array $entry): bool => (int) ($entry['recordedAt'] ?? $entry['mtime'] ?? 0) > $since
        );
    }

    /**
     * Shared bookkeeping for a file whose bytes just landed at $targetPath,
     * whichever way they got there - FileReceiverController's own
     * $file->move() destination for a push, or a plain file_put_contents()
     * destination for a cluster:pull download. Sets mtime to match the
     * sender's claimed value, then records the file's actual on-disk
     * hash/size/mtime as "known" (see recordKnown()'s own docblock on why
     * that's what stops a re-push storm - the exact same reasoning applies
     * to a pulled file: without it, this node's own next scan would see it
     * as new and immediately push it right back out).
     *
     * @return array{hash: string, size: int, mtime: int}
     */
    public function finalizeIncomingFile(string $relativePath, string $targetPath, int $claimedMtime): array
    {
        if ($claimedMtime > 0) {
            @touch($targetPath, $claimedMtime);
        }

        $hash        = (string) md5_file($targetPath);
        $size        = (int) filesize($targetPath);
        $actualMtime = (int) filemtime($targetPath);

        $this->recordKnown($relativePath, $hash, $actualMtime, $size);

        return ['hash' => $hash, 'size' => $size, 'mtime' => $actualMtime];
    }

    /**
     * Detects whether an incoming file (about to overwrite $targetPath)
     * genuinely CONFLICTS with a local change - both sides independently
     * diverged from the last state they agreed on, to DIFFERENT content -
     * and if so, resolves it Last-Write-Wins by mtime (same LWW
     * philosophy this project's own original spec already used for DB
     * writes). Called by FileReceiverController (push) and PullCommand's
     * downloadFile() (pull) BEFORE the incoming bytes touch $targetPath,
     * so the loser's content can still be preserved (see
     * preserveConflictLoser()) rather than silently destroyed.
     *
     * Three non-conflict cases, all resolved as "incoming wins" (the
     * ordinary, overwhelmingly common path - nothing here changes
     * behavior for a file nobody's touched concurrently):
     * - $targetPath doesn't exist locally yet (a brand new file).
     * - The manifest never recorded this path before (nothing to compare
     *   against - can't tell "changed" from "always different").
     * - Local's current hash still matches the manifest's last-known
     *   value (nothing changed locally since the last time this node
     *   agreed with a peer on this file).
     * - The incoming content is byte-for-byte identical to what's
     *   already on disk (both sides ended up with the same result
     *   independently - nothing to resolve).
     *
     * One more non-conflict case, resolved as "local wins" (the sender's
     * copy is the stale one, not this node's - not a real conflict,
     * just an out-of-order delivery the sender will self-correct on its
     * own next scan/pull once ITS local hash stops matching ITS OWN
     * manifest):
     * - The INCOMING hash matches the manifest's last-known value (the
     *   sender hasn't actually changed anything; THIS node is the one
     *   that diverged).
     *
     * Only when BOTH sides diverged to DIFFERENT content is it a real
     * conflict, decided by comparing the sender's claimed mtime against
     * this node's own filemtime() - ties go to the incoming side
     * (arbitrary but deterministic: "whatever just arrived wins a draw",
     * rather than favoring whichever node happened to scan first).
     *
     * @return array{conflict: bool, incomingWins: bool}
     */
    public function detectConflict(string $relativePath, string $targetPath, string $incomingHash, int $claimedMtime): array
    {
        $manifest = $this->loadManifest();
        $known    = $manifest[$relativePath] ?? null;

        if ($known === null || ! is_file($targetPath)) {
            return ['conflict' => false, 'incomingWins' => true];
        }

        $localHash = (string) md5_file($targetPath);

        if ($localHash === $known['hash'] || $localHash === $incomingHash) {
            return ['conflict' => false, 'incomingWins' => true];
        }

        if ($incomingHash === $known['hash']) {
            return ['conflict' => false, 'incomingWins' => false];
        }

        $localMtime   = (int) filemtime($targetPath);
        $incomingWins = $claimedMtime >= $localMtime;

        return ['conflict' => true, 'incomingWins' => $incomingWins];
    }

    /**
     * Where a conflict's LOSING content is archived instead of being
     * silently destroyed - one real file per conflict, never overwritten
     * (the timestamp in the name guarantees that), so a human can always
     * recover it by hand if the automatic LWW call was wrong for their
     * case. $source is a label only (a peer name, or 'local') - purely
     * for a human reading the filename/log, not parsed back by anything.
     */
    public function conflictPath(string $relativePath, string $source): string
    {
        $safeName = str_replace(['/', '\\'], '__', $relativePath);
        $safeSource = preg_replace('/[^a-zA-Z0-9_-]/', '_', $source);

        return rtrim(WRITEPATH, '/\\') . '/' . trim($this->config->stateDir, '/\\')
            . '/conflicts/' . $safeName . '__' . time() . '__' . $safeSource . '.conflict';
    }

    /**
     * Copies the losing side's bytes to conflictPath() and records the
     * event in ConflictLog, for the Dashboard/CLI to surface later - see
     * this package's README "Not built yet" for why the Dashboard side
     * of that isn't built yet, even though the archive + log already are.
     */
    public function preserveConflictLoser(string $relativePath, string $loserSourcePath, string $loserLabel, string $winnerLabel): void
    {
        $archivePath = $this->conflictPath($relativePath, $loserLabel);
        $dir         = dirname($archivePath);
        if (! is_dir($dir) && ! @mkdir($dir, 0775, true) && ! is_dir($dir)) {
            return; // best-effort - must never break the actual sync
        }

        if (! @copy($loserSourcePath, $archivePath)) {
            return;
        }
        @chmod($archivePath, 0664);

        (new ConflictLog($this->config))->record([
            'time'    => time(),
            'path'    => $relativePath,
            'winner'  => $winnerLabel,
            'loser'   => $loserLabel,
            'archive' => basename($archivePath),
        ]);
    }

    public function manifestPath(): string
    {
        return rtrim(WRITEPATH, '/\\') . '/' . trim($this->config->stateDir, '/\\') . '/files_manifest.json';
    }

    /**
     * flock() target guarding cluster:pull's optional multi-pass loop
     * (Config\Cluster::$pullLoopSeconds) against two overlapping
     * invocations - see PullCommand's own docblock for why that can
     * happen (a slow peer, a host running behind) even though cron only
     * ever fires it once a minute.
     */
    public function lockPath(): string
    {
        return rtrim(WRITEPATH, '/\\') . '/' . trim($this->config->stateDir, '/\\') . '/pull.lock';
    }

    /**
     * @return array<string, array{hash: string, mtime: int, size: int}>
     */
    public function loadManifest(): array
    {
        $path = $this->manifestPath();
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

        $decoded = json_decode((string) $contents, true);

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * @param array<string, array{hash: string, mtime: int, size: int}> $manifest
     */
    public function saveManifest(array $manifest): void
    {
        $path = $this->manifestPath();
        $dir  = dirname($path);
        if (! is_dir($dir) && ! mkdir($dir, 0775, true) && ! is_dir($dir)) {
            throw new RuntimeException("Could not create $dir");
        }

        $handle = fopen($path, 'cb');
        if ($handle === false) {
            throw new RuntimeException("Could not open $path for writing");
        }
        flock($handle, LOCK_EX);
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
        // This file is written by BOTH the scanner (whichever user runs
        // spark cluster:sync-files - typically cron/CLI) and the receiving
        // controller (whichever user runs PHP-FPM/nginx) - two different
        // system users on every node in this cluster (see the h1q setgid
        // fix in CI4cluster.asc's own notes). setgid on writable/Cluster/
        // only fixes the file's GROUP; it does not make the file
        // group-writable if whichever user creates it has a stricter
        // umask. Found live 2026-08-18 on the newer sync_state.json (same
        // exact class of bug, just not yet hit here because manifest
        // writes had always happened to occur same-user-first so far).
        @chmod($path, 0664);
    }

    /**
     * Records a file's current state as "known" - called both after a
     * local change is scanned+enqueued (scanner) AND after an incoming
     * push is written to disk (receiver). The receiver call is what
     * prevents a re-push storm: without it, this node's OWN next scan
     * would see the just-received file as "new" (not in ITS manifest yet)
     * and immediately queue it right back out to every peer, including
     * the one that just sent it.
     */
    public function recordKnown(string $relativePath, string $hash, int $mtime, int $size): void
    {
        $manifest                = $this->loadManifest();
        $manifest[$relativePath] = ['hash' => $hash, 'mtime' => $mtime, 'size' => $size, 'recordedAt' => time()];
        $this->saveManifest($manifest);
    }

    /**
     * Shared bookkeeping for an incoming "this path was deleted elsewhere"
     * tombstone - FileReceiverController::deleteFile()'s push-receive
     * destination, or cluster:pull's own pullDeletedFiles() - same
     * "shared between push and pull" split finalizeIncomingFile() already
     * uses for regular file content.
     *
     * Last-Write-Wins against LOCAL state, not against another tombstone:
     * if this node's own manifest shows the path was touched (created or
     * modified) AFTER $deletedAt, the deletion is stale - reject it and
     * leave local alone, the same "sender is the stale one" philosophy
     * detectConflict() already uses for content conflicts. Unlike a
     * content conflict, there is deliberately no self-heal push-back here
     * (see this package's README) - the rejecting node's own file is
     * unchanged, so its own manifest already matches it and nothing marks
     * it "worth re-pushing" to correct the stale sender. Accepted as a
     * rare-race limitation rather than building an explicit push-back path
     * for it.
     *
     * On success, re-records the tombstone into THIS node's own
     * DeletedFiles - not a no-op duplicate: it's what lets the deletion
     * keep propagating to whoever pulls FROM this node next, without any
     * node needing to explicitly relay/forward anything (see DeletedFiles'
     * own docblock).
     *
     * @return array{applied: bool, reason: string}
     */
    public function applyIncomingDeletion(string $relativePath, int $deletedAt): array
    {
        $targetPath = $this->resolveIncomingPath($relativePath);
        if ($targetPath === null) {
            return ['applied' => false, 'reason' => 'path not allowed'];
        }

        $manifest = $this->loadManifest();
        $known    = $manifest[$relativePath] ?? null;

        if ($known !== null && (int) $known['mtime'] > $deletedAt) {
            return ['applied' => false, 'reason' => 'local is newer'];
        }

        if (is_file($targetPath)) {
            @unlink($targetPath);
        }
        unset($manifest[$relativePath]);
        $this->saveManifest($manifest);

        (new DeletedFiles($this->config))->record($relativePath, $deletedAt);

        return ['applied' => true, 'reason' => 'deleted'];
    }

    /**
     * Everything the Dashboard's "File synchronization" card needs,
     * gathered in one call rather than several - the file-tree walk is the
     * expensive part, no reason to redo it per widget. "synced" here means
     * "this node's own manifest already has this exact content", true
     * whether THIS node pushed it out or received it from a peer - NOT
     * "every peer definitely has it too", since no per-peer delivery
     * confirmation is tracked (see README "Not built yet": conflict
     * resolution).
     *
     * @return array{
     *     configured: bool,
     *     thisNode: string,
     *     syncPaths: list<string>,
     *     totalFiles: int,
     *     totalDirs: int,
     *     syncedFiles: int,
     *     pendingFiles: int,
     *     peers: array<string, array{baseURL: string, type: string, lastSyncAt: ?int, lastSyncOk: ?bool, lastPullAt: ?int, lastPullOk: ?bool}>,
     *     natConnections: array<string, array{baseURL: string, lastSyncAt: ?int, lastSyncPath: ?string}>,
     *     recentAttempts: int,
     *     recentOk: int,
     *     recentErrors: int,
     *     recentBytes: int,
     *     avgSpeedBps: float,
     *     lastErrorEntries: list<array{time: int, peer: string, path: string, bytes: int, durationMs: int, ok: bool, error: ?string}>
     * }
     */
    /**
     * Per-node topology data for a Dashboard network graph (cluster-ui) -
     * every configured peer (public and nat alike, see allPeers()), each
     * joined with:
     * - totalBytes/avgSpeedBps/attempts/errors: aggregated from Stats'
     *   ring buffer of recent PUSH attempts TO that peer (PushFileJob/
     *   DeleteFileJob both record here) - real per-peer transfer volume
     *   and throughput, not the single global average dashboardSummary()
     *   exposes.
     * - lastSyncAt/lastSyncOk (push OUT), lastPushInAt (push IN, nat peers
     *   only), lastPullAt/lastPullOk (pull): straight from SyncState, same
     *   fields dashboardSummary()'s own peers/natConnections arrays
     *   already expose separately - unified into one array per node here
     *   instead, since a topology graph wants one node object per peer,
     *   not two differently-shaped arrays split by type.
     *
     * @return array{
     *     thisNode: string,
     *     configured: bool,
     *     nodes: array<string, array{
     *         baseURL: string, type: string,
     *         totalBytes: int, avgSpeedBps: float, attempts: int, errors: int,
     *         filesSynced: int, lastTransferBytes: int,
     *         lastSyncAt: ?int, lastSyncOk: ?bool,
     *         lastPushInAt: ?int,
     *         lastPullAt: ?int, lastPullOk: ?bool
     *     }>
     * }
     */
    public function networkSummary(): array
    {
        $stats = (new Stats($this->config))->all();

        $byPeer = [];
        foreach ($stats as $entry) {
            $peer = (string) ($entry['peer'] ?? '');
            if ($peer === '') {
                continue;
            }
            $byPeer[$peer] ??= ['bytes' => 0, 'durationMs' => 0, 'attempts' => 0, 'errors' => 0, 'files' => 0, 'lastBytes' => 0];
            $byPeer[$peer]['attempts']++;
            if ($entry['ok']) {
                $byPeer[$peer]['bytes']      += (int) $entry['bytes'];
                $byPeer[$peer]['durationMs'] += (int) $entry['durationMs'];
                $byPeer[$peer]['files']++;
                // $stats is oldest-first (Stats' own ring-buffer order), so
                // the last ok=true entry seen while iterating in order is
                // naturally the most recent one - no separate sort needed.
                $byPeer[$peer]['lastBytes'] = (int) $entry['bytes'];
            } else {
                $byPeer[$peer]['errors']++;
            }
        }

        $syncState = (new SyncState($this->config))->all();
        $allPeers  = $this->allPeers();

        $nodes = array_combine(
            array_keys($allPeers),
            array_map(
                static function (array $node, string $name) use ($byPeer, $syncState): array {
                    $agg         = $byPeer[$name] ?? ['bytes' => 0, 'durationMs' => 0, 'attempts' => 0, 'errors' => 0, 'files' => 0, 'lastBytes' => 0];
                    $avgSpeedBps = $agg['durationMs'] > 0 ? $agg['bytes'] / ($agg['durationMs'] / 1000) : 0.0;

                    $outgoing = $syncState['outgoing'][$name] ?? null;
                    $incoming = $syncState['incoming'][$name] ?? null;
                    $pull     = $syncState['pull'][$name] ?? null;

                    return [
                        'baseURL'          => $node['baseURL'],
                        'type'             => $node['type'],
                        'totalBytes'       => $agg['bytes'],
                        'avgSpeedBps'      => $avgSpeedBps,
                        'attempts'         => $agg['attempts'],
                        'errors'           => $agg['errors'],
                        'filesSynced'      => $agg['files'],
                        'lastTransferBytes' => $agg['lastBytes'],
                        'lastSyncAt'       => $outgoing['time'] ?? null,
                        'lastSyncOk'       => $outgoing['ok'] ?? null,
                        'lastPushInAt'     => $incoming['time'] ?? null,
                        'lastPullAt'       => $pull['time'] ?? null,
                        'lastPullOk'       => $pull['ok'] ?? null,
                    ];
                },
                $allPeers,
                array_keys($allPeers)
            )
        );

        return [
            'thisNode'   => $this->config->thisNode,
            'configured' => $this->config->thisNode !== '' && $this->config->secretToken !== '',
            'nodes'      => $nodes,
        ];
    }

    public function dashboardSummary(): array
    {
        $totalFiles   = 0;
        $totalDirs    = 0;
        $syncedFiles  = 0;
        $pendingFiles = 0;
        $manifest     = $this->loadManifest();

        foreach ($this->syncDirs() as $dir) {
            if (! is_dir($dir)) {
                continue;
            }

            $dirLen   = strlen(rtrim($dir, '/\\')) + 1;
            // SELF_FIRST is required, not cosmetic - the default
            // (LEAVES_ONLY) never yields directories at all, only files,
            // which silently kept totalDirs at 0 regardless of the real
            // tree shape (found by test, not live - see git history).
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iterator as $item) {
                if ($item->isDir()) {
                    $totalDirs++;

                    continue;
                }

                $totalFiles++;
                $relative = str_replace('\\', '/', substr($item->getPathname(), $dirLen));
                $known    = $manifest[$relative] ?? null;

                if ($known !== null && $known['hash'] === md5_file($item->getPathname())) {
                    $syncedFiles++;
                } else {
                    $pendingFiles++;
                }
            }
        }

        $stats              = (new Stats($this->config))->all();
        $recentOkEntries    = array_values(array_filter($stats, static fn (array $e): bool => $e['ok']));
        $recentErrorEntries = array_values(array_filter($stats, static fn (array $e): bool => ! $e['ok']));

        $recentBytes      = array_sum(array_column($recentOkEntries, 'bytes'));
        $recentDurationMs = array_sum(array_column($recentOkEntries, 'durationMs'));
        $avgSpeedBps      = $recentDurationMs > 0 ? $recentBytes / ($recentDurationMs / 1000) : 0.0;

        $syncState = (new SyncState($this->config))->all();

        // array_map() called with multiple array arguments always returns a
        // plain 0-indexed array, discarding the (string) peer-name keys -
        // array_combine() puts them back. Found by the standalone test, not
        // live (see git history): a first pass without it silently produced
        // ['0' => [...], '1' => [...]] instead of ['beta' => [...], ...].
        $publicPeers = $this->publicPeers();
        $peers       = array_combine(
            array_keys($publicPeers),
            array_map(
                static function (array $node, string $name) use ($syncState): array {
                    $row               = $syncState['outgoing'][$name] ?? null;
                    $node['lastSyncAt'] = $row['time'] ?? null;
                    $node['lastSyncOk'] = $row['ok'] ?? null;

                    // Pull is push's independent counterpart against the
                    // SAME public peer (see SyncState's own docblock,
                    // "pull" half) - a separate pair of fields, not a
                    // replacement for lastSyncAt/lastSyncOk above, since a
                    // peer can be pushed to and pulled from at different
                    // times.
                    $pullRow            = $syncState['pull'][$name] ?? null;
                    $node['lastPullAt'] = $pullRow['time'] ?? null;
                    $node['lastPullOk'] = $pullRow['ok'] ?? null;

                    return $node;
                },
                $publicPeers,
                array_keys($publicPeers)
            )
        );

        $natPeers       = $this->natPeers();
        $natConnections = array_combine(
            array_keys($natPeers),
            array_map(
                static function (array $node, string $name) use ($syncState): array {
                    $row = $syncState['incoming'][$name] ?? null;

                    return [
                        'baseURL'      => $node['baseURL'],
                        'lastSyncAt'   => $row['time'] ?? null,
                        'lastSyncPath' => $row['path'] ?? null,
                    ];
                },
                $natPeers,
                array_keys($natPeers)
            )
        );

        return [
            'configured'       => $this->config->thisNode !== '' && $this->config->secretToken !== '',
            'thisNode'         => $this->config->thisNode,
            'syncPaths'        => $this->config->syncPaths,
            'totalFiles'       => $totalFiles,
            'totalDirs'        => $totalDirs,
            'syncedFiles'      => $syncedFiles,
            'pendingFiles'     => $pendingFiles,
            'peers'            => $peers,
            'natConnections'   => $natConnections,
            'recentAttempts'   => count($stats),
            'recentOk'         => count($recentOkEntries),
            'recentErrors'     => count($recentErrorEntries),
            'recentBytes'      => $recentBytes,
            'avgSpeedBps'      => $avgSpeedBps,
            'lastErrorEntries' => array_slice(array_reverse($recentErrorEntries), 0, 10),
        ];
    }

    /**
     * Data source for a Dashboard "Clock drift" widget (cluster-ui) -
     * simple pass-through over TimeDrift::all(), joined with each peer's
     * baseURL/type from the node registry so the view doesn't need a
     * second lookup. Reflects whatever `cluster:time-drift`'s own last run
     * measured (see Commands\TimeDriftCommand and this package's README,
     * "How clock drift is measured") - this method does not measure
     * anything itself, it only reports the most recent cached result per
     * peer, which may be stale if that command hasn't run recently (each
     * entry's own `measuredAt` tells the view exactly how stale).
     *
     * @return array<string, array{baseURL: string, type: string, measuredAt: int|null, offsetSeconds: float|null, rttSeconds: float|null, error: string|null}>
     */
    public function clockDriftSummary(): array
    {
        $drifts = (new TimeDrift($this->config))->all();
        $peers  = $this->allPeers();

        return array_combine(
            array_keys($peers),
            array_map(
                static function (array $node, string $name) use ($drifts): array {
                    $entry = $drifts[$name] ?? null;

                    return [
                        'baseURL'       => $node['baseURL'],
                        'type'          => $node['type'],
                        'measuredAt'    => $entry['measuredAt'] ?? null,
                        'offsetSeconds' => $entry['offsetSeconds'] ?? null,
                        'rttSeconds'    => $entry['rttSeconds'] ?? null,
                        'error'         => $entry['error'] ?? null,
                    ];
                },
                $peers,
                array_keys($peers)
            )
        );
    }

    /**
     * Data source for the Dashboard's "Database synchronization" card
     * (cluster-ui) - mirrors dashboardSummary()'s own shape/reasoning, just
     * over DbSyncLog/DbManifest instead of Stats/the file manifest. Per-
     * peer "last synced" is derived by scanning the (capped, oldest-first)
     * log for each peer's most recent entry per direction, rather than a
     * separate state file - cheap since the log is small and bounded.
     *
     * @return array{
     *     configured: bool, thisNode: string, totalSynced: int,
     *     peers: array<string, array{baseURL: string, type: string, lastSyncAt: int|null, lastSyncOk: bool|null}>,
     *     natConnections: array<string, array{baseURL: string, lastPushInAt: int|null, lastPullAt: int|null, lastPullOk: bool|null}>,
     *     recentAttempts: int, recentOk: int, recentErrors: int,
     *     recentLog: list<array>, lastErrorEntries: list<array>
     * }
     */
    public function dbSyncDashboardSummary(): array
    {
        $manifest = (new DbManifest($this->config))->all();
        $log      = (new DbSyncLog($this->config))->all();

        $lastByPeer = [];
        foreach ($log as $entry) {
            $peer = (string) ($entry['peer'] ?? '');
            if ($peer === '') {
                continue;
            }
            $lastByPeer[$peer] ??= ['pushOutAt' => null, 'pushOutOk' => null, 'pushInAt' => null, 'pullAt' => null, 'pullOk' => null];

            // $log is oldest-first, so a plain overwrite while iterating in
            // order naturally leaves the MOST RECENT entry per direction
            // once the loop finishes - no explicit "is this newer" check
            // needed.
            if ($entry['direction'] === 'push-out') {
                $lastByPeer[$peer]['pushOutAt'] = $entry['time'];
                $lastByPeer[$peer]['pushOutOk'] = $entry['ok'];
            } elseif ($entry['direction'] === 'push-in') {
                $lastByPeer[$peer]['pushInAt'] = $entry['time'];
            } elseif ($entry['direction'] === 'pull') {
                $lastByPeer[$peer]['pullAt'] = $entry['time'];
                $lastByPeer[$peer]['pullOk'] = $entry['ok'];
            }
        }

        $publicPeers = $this->publicPeers();
        $peers       = array_combine(
            array_keys($publicPeers),
            array_map(
                static function (array $node, string $name) use ($lastByPeer): array {
                    $info               = $lastByPeer[$name] ?? [];
                    $node['lastSyncAt'] = $info['pushOutAt'] ?? null;
                    $node['lastSyncOk'] = $info['pushOutOk'] ?? null;

                    return $node;
                },
                $publicPeers,
                array_keys($publicPeers)
            )
        );

        $natPeers       = $this->natPeers();
        $natConnections = array_combine(
            array_keys($natPeers),
            array_map(
                static function (array $node, string $name) use ($lastByPeer): array {
                    $info = $lastByPeer[$name] ?? [];

                    return [
                        'baseURL'      => $node['baseURL'],
                        'lastPushInAt' => $info['pushInAt'] ?? null,
                        'lastPullAt'   => $info['pullAt'] ?? null,
                        'lastPullOk'   => $info['pullOk'] ?? null,
                    ];
                },
                $natPeers,
                array_keys($natPeers)
            )
        );

        $errorEntries = array_values(array_filter($log, static fn (array $e): bool => ! $e['ok']));

        return [
            'configured'       => $this->config->thisNode !== '' && $this->config->secretToken !== '',
            'thisNode'         => $this->config->thisNode,
            'totalSynced'      => count($manifest),
            'peers'            => $peers,
            'natConnections'   => $natConnections,
            'recentAttempts'   => count($log),
            'recentOk'         => count($log) - count($errorEntries),
            'recentErrors'     => count($errorEntries),
            // Newest-first for display - $log itself stays oldest-first
            // (the ring buffer's own natural order, matching Stats).
            'recentLog'        => array_slice(array_reverse($log), 0, 30),
            'lastErrorEntries' => array_slice(array_reverse($errorEntries), 0, 10),
        ];
    }

    /**
     * Per-table size, row count, and DB-sync traffic for the Dashboard's
     * table sunburst. Row count and the table list itself are
     * driver-agnostic (CI4's own listTables()/countAllResults()); size is
     * best-effort and driver-specific (SQLite's dbstat virtual table,
     * MySQL's information_schema, Postgres' pg_total_relation_size) -
     * 'sizeSupported' tells the caller whether it could be determined at
     * all on this node's driver/build, so the UI can omit that ring
     * instead of showing all-zero.
     *
     * @return array{tables: array<string, array{records: int, sizeBytes: int|null, trafficBytes: int}>, sizeSupported: bool}
     */
    public function tableStats(): array
    {
        $db = db_connect('default');

        [$sizeByTable, $sizeSupported] = $this->tableSizesBestEffort($db);
        $trafficByTable = $this->dbSyncTrafficByTable();

        $excluded = ['migrations'];

        $tables = [];
        foreach ($db->listTables() as $table) {
            $table = (string) $table;
            if (in_array($table, $excluded, true) || str_starts_with($table, 'sqlite_')) {
                continue;
            }

            try {
                $records = (int) $db->table($table)->countAllResults();
            } catch (\Throwable $e) {
                continue; // an unreadable/system table - skip rather than fail the whole call
            }

            $tables[$table] = [
                'records'      => $records,
                'sizeBytes'    => $sizeByTable[$table] ?? null,
                'trafficBytes' => $trafficByTable[$table] ?? 0,
            ];
        }

        return ['tables' => $tables, 'sizeSupported' => $sizeSupported];
    }

    /**
     * @return array{0: array<string, int>, 1: bool} table name => size in
     *                                                bytes, and whether
     *                                                this driver/build
     *                                                supports it at all
     */
    private function tableSizesBestEffort(\CodeIgniter\Database\ConnectionInterface $db): array
    {
        $sizeByTable = [];

        try {
            if ($db->DBDriver === 'SQLite3') {
                // dbstat is a virtual table only present when SQLite was
                // compiled with SQLITE_ENABLE_DBSTAT_VTAB - present on
                // h1q/bak/res (confirmed live 2026-08-19), not guaranteed
                // on every shared-hosting PHP build (beta/upz), hence the
                // try/catch rather than a hard dependency. Restricted to
                // real tables (excludes each table's own indexes, which
                // also appear as rows in dbstat) via the sqlite_master
                // subquery, so this is data-page size, not data+index.
                $result = $db->query(
                    "SELECT name, SUM(pgsize) AS sz FROM dbstat WHERE name IN (SELECT name FROM sqlite_master WHERE type='table') GROUP BY name"
                );
                foreach ($result->getResultArray() as $row) {
                    $sizeByTable[(string) $row['name']] = (int) $row['sz'];
                }
            } elseif ($db->DBDriver === 'MySQLi') {
                $result = $db->query(
                    'SELECT table_name AS name, (data_length + index_length) AS sz FROM information_schema.tables WHERE table_schema = DATABASE()'
                );
                foreach ($result->getResultArray() as $row) {
                    $sizeByTable[(string) $row['name']] = (int) $row['sz'];
                }
            } elseif ($db->DBDriver === 'Postgre') {
                $result = $db->query(
                    'SELECT relname AS name, pg_total_relation_size(relid) AS sz FROM pg_catalog.pg_statio_user_tables'
                );
                foreach ($result->getResultArray() as $row) {
                    $sizeByTable[(string) $row['name']] = (int) $row['sz'];
                }
            } else {
                return [[], false]; // unsupported driver (OCI8/SQLSRV) - unknown, not fatal
            }
        } catch (\Throwable $e) {
            return [[], false]; // this build's driver doesn't support the query above - unknown, not fatal
        }

        return [$sizeByTable, true];
    }

    /**
     * DbSyncLog's 'table' field is the logical entity DbSyncSchema knows
     * about ('users'/'settings'), but one 'users' snapshot's queries can
     * touch up to 5 different PHYSICAL tables (users/auth_identities/
     * auth_groups_users/auth_permissions_users/user_profiles) in a single
     * log entry - so physical-table attribution is parsed out of the
     * actual SQL text (DbSyncLog's 'queries', the real SQL CI4 ran - see
     * DbSyncSchema::applyIncomingCommand()) rather than hardcoded, which
     * also means this needs no update if DbSyncSchema ever grows more
     * tables. Counts bytes of SQL text WRITTEN applying incoming push-in/
     * pull commands only - this node's own outgoing exports are a read,
     * not a logged write, so pure-export traffic isn't counted here.
     *
     * @return array<string, int> physical table name => total bytes
     */
    private function dbSyncTrafficByTable(): array
    {
        $traffic = [];
        foreach ((new DbSyncLog($this->config))->all() as $entry) {
            foreach ((array) ($entry['queries'] ?? []) as $query) {
                $query = (string) $query;
                if (preg_match('/^\s*(?:INSERT INTO|UPDATE|DELETE FROM)\s+[`"]?(\w+)[`"]?/i', $query, $m) === 1) {
                    $traffic[$m[1]] = ($traffic[$m[1]] ?? 0) + strlen($query);
                }
            }
        }

        return $traffic;
    }

    /**
     * Per-PEER DB-sync activity for the Dashboard's "Database tables" card
     * and network-tree chart - complements tableStats() (per-TABLE) with
     * the same underlying DbSyncLog, just grouped by peer instead of by
     * parsed table name. 'avgSpeedBps' is necessarily an approximation:
     * DbSyncLog entries (unlike Stats') don't record a transfer duration,
     * so this divides total traffic bytes by the wall-clock span between
     * that peer's first and last logged entry - a whole-lifetime average
     * throughput, not a per-transfer speed. 0 (not an error) when a peer
     * has fewer than 2 entries, since a span needs at least two points.
     *
     * @return array<string, array{baseURL: string, type: string, commandCount: int, trafficBytes: int, avgSpeedBps: float}>
     */
    public function dbSyncNodeStats(): array
    {
        $byPeer = [];
        foreach ((new DbSyncLog($this->config))->all() as $entry) {
            $peer = (string) ($entry['peer'] ?? '');
            if ($peer === '') {
                continue;
            }
            $byPeer[$peer] ??= ['commands' => 0, 'bytes' => 0, 'firstTime' => null, 'lastTime' => null];
            $byPeer[$peer]['commands']++;
            foreach ((array) ($entry['queries'] ?? []) as $query) {
                $byPeer[$peer]['bytes'] += strlen((string) $query);
            }
            $time = (int) ($entry['time'] ?? 0);
            if ($byPeer[$peer]['firstTime'] === null || $time < $byPeer[$peer]['firstTime']) {
                $byPeer[$peer]['firstTime'] = $time;
            }
            if ($byPeer[$peer]['lastTime'] === null || $time > $byPeer[$peer]['lastTime']) {
                $byPeer[$peer]['lastTime'] = $time;
            }
        }

        $peers = $this->allPeers();

        return array_combine(
            array_keys($peers),
            array_map(
                static function (array $node, string $name) use ($byPeer): array {
                    $agg     = $byPeer[$name] ?? ['commands' => 0, 'bytes' => 0, 'firstTime' => null, 'lastTime' => null];
                    $spanSec = $agg['firstTime'] !== null && $agg['lastTime'] > $agg['firstTime']
                        ? $agg['lastTime'] - $agg['firstTime']
                        : 0;

                    return [
                        'baseURL'      => $node['baseURL'],
                        'type'         => $node['type'],
                        'commandCount' => $agg['commands'],
                        'trafficBytes' => $agg['bytes'],
                        'avgSpeedBps'  => $spanSec > 0 ? $agg['bytes'] / $spanSec : 0.0,
                    ];
                },
                $peers,
                array_keys($peers)
            )
        );
    }
}

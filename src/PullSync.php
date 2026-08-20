<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use AdGo\Cluster\DbSyncSchema;
use CodeIgniter\HTTP\CURLRequest;
use RuntimeException;

/**
 * The actual peer-reconciliation calls (invalidations/files/deletions/DB
 * rows, one peer at a time) - extracted from Commands\PullCommand so
 * Commands\RealignCommand can reuse the exact same logic against a wider
 * window (since=0, i.e. "everything", rather than the normal rolling
 * lookback) without duplicating it. Every method here is peer-scoped and
 * $since-scoped, not schedule- or loop-aware - that orchestration stays in
 * each command.
 */
class PullSync
{
    public function pullInvalidations(CURLRequest $client, Cluster $cluster, int $since): int
    {
        $response = $client->get('cluster/pull-invalidations', [
            'headers' => ['Authorization' => $cluster->authHeader()],
            'query'   => ['since' => $since],
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new RuntimeException('pull-invalidations HTTP ' . $response->getStatusCode());
        }

        $body = json_decode($response->getBody(), true);

        return $this->applyInvalidations(is_array($body['invalidations'] ?? null) ? $body['invalidations'] : []);
    }

    /**
     * Post-fetch half of pullInvalidations() above, factored out so
     * LongPollController's own bundled response (invalidations/files/
     * deletions/dbRows/testRequests all in ONE payload, not five separate
     * round trips - see that controller's own docblock) can apply an
     * already-fetched batch without re-issuing the HTTP call.
     *
     * @param array<string, int> $invalidations email => changedAt
     */
    public function applyInvalidations(array $invalidations): int
    {
        $store   = new SessionInvalidation();
        $applied = 0;
        foreach ($invalidations as $email => $changedAt) {
            $store->recordInvalidation((string) $email, (int) $changedAt);
            $applied++;
        }

        return $applied;
    }

    public function pullDbRows(CURLRequest $client, Cluster $cluster, int $since, string $peerName): int
    {
        $response = $client->get('cluster/pull-db-rows', [
            'headers' => ['Authorization' => $cluster->authHeader()],
            'query'   => ['since' => $since],
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new RuntimeException('pull-db-rows HTTP ' . $response->getStatusCode());
        }

        $body = json_decode($response->getBody(), true);

        return $this->applyDbRows(is_array($body['rows'] ?? null) ? $body['rows'] : [], $peerName);
    }

    /**
     * Post-fetch half of pullDbRows() above - see applyInvalidations()'s
     * own docblock for why this is factored out.
     *
     * @param list<array{table: string, naturalKey: string, timestamp: int, payload: array}> $rows
     */
    public function applyDbRows(array $rows, string $peerName): int
    {
        $db       = db_connect('default');
        $manifest = new DbManifest();
        $applied  = 0;
        foreach ($rows as $row) {
            $result = DbSyncSchema::applyIncomingCommand($db, $manifest, [
                'table'      => (string) ($row['table'] ?? ''),
                'naturalKey' => (string) ($row['naturalKey'] ?? ''),
                'operation'  => 'upsert',
                'payload'    => (array) ($row['payload'] ?? []),
                'timestamp'  => (int) ($row['timestamp'] ?? 0),
            ], 'pull', $peerName);
            if ($result['applied']) {
                $applied++;
            }
        }

        return $applied;
    }

    /**
     * @return array{downloaded: int, remoteManifest: array<string, array{hash: string, mtime: int, size: int}>}
     *               remoteManifest is returned alongside the count so a
     *               caller doing a full realign (see RealignCommand) can
     *               compare it against local state afterward without a
     *               second round trip.
     */
    public function pullFiles(CURLRequest $client, Cluster $cluster, int $since, string $peerName, float $driftOffset): array
    {
        $response = $client->get('cluster/pull-files', [
            'headers' => ['Authorization' => $cluster->authHeader()],
            'query'   => ['since' => $since],
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new RuntimeException('pull-files HTTP ' . $response->getStatusCode());
        }

        $body = json_decode($response->getBody(), true);

        return $this->applyFilesManifest($client, $cluster, is_array($body['files'] ?? null) ? $body['files'] : [], $peerName, $driftOffset);
    }

    /**
     * Post-fetch half of pullFiles() above - see applyInvalidations()'s
     * own docblock for why this is factored out. $remote is manifest
     * METADATA only (hash/mtime/size), never file bytes - those are always
     * a separate per-path GET (cluster/pull-file), whether reached via the
     * old since-scoped endpoint or a long-poll response bundle.
     *
     * @param array<string, array{hash: string, mtime: int, size: int}> $remote
     */
    public function applyFilesManifest(CURLRequest $client, Cluster $cluster, array $remote, string $peerName, float $driftOffset): array
    {
        $localManifest = $cluster->loadManifest();

        $downloaded = 0;
        foreach ($remote as $relativePath => $meta) {
            $remoteHash = (string) ($meta['hash'] ?? '');
            $known      = $localManifest[$relativePath] ?? null;

            // Already have this exact content, whether we pushed it
            // ourselves earlier or already pulled/received it before -
            // same "nothing to do" check sync-files itself uses.
            if ($known !== null && $known['hash'] === $remoteHash) {
                continue;
            }

            $this->downloadFile($client, $cluster, (string) $relativePath, $peerName, $driftOffset);
            $downloaded++;
        }

        return ['downloaded' => $downloaded, 'remoteManifest' => $remote];
    }

    public function pullDeletedFiles(CURLRequest $client, Cluster $cluster, int $since): int
    {
        $response = $client->get('cluster/pull-deleted-files', [
            'headers' => ['Authorization' => $cluster->authHeader()],
            'query'   => ['since' => $since],
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new RuntimeException('pull-deleted-files HTTP ' . $response->getStatusCode());
        }

        $body = json_decode($response->getBody(), true);

        return $this->applyDeletedFiles($cluster, is_array($body['deletions'] ?? null) ? $body['deletions'] : []);
    }

    /**
     * Post-fetch half of pullDeletedFiles() above - see
     * applyInvalidations()'s own docblock for why this is factored out.
     *
     * @param array<string, int> $deletions relativePath => deletedAt
     */
    public function applyDeletedFiles(Cluster $cluster, array $deletions): int
    {
        $applied = 0;
        foreach ($deletions as $relativePath => $deletedAt) {
            $result = $cluster->applyIncomingDeletion((string) $relativePath, (int) $deletedAt);
            if ($result['applied']) {
                $applied++;
            }
        }

        return $applied;
    }

    /**
     * NAT-safe remote connection-test relay, step 1 from the puller's own
     * side - see RemoteTestController's own docblock for the full shape.
     * Asks ONE public peer "anything queued for me", runs whatever comes
     * back locally (this IS "locally": this method executes on the NAT
     * node itself, exactly the point of the whole relay), then reports
     * each result back to that SAME peer. Rides along with every normal
     * cluster:pull pass, not gated by fileSyncEnabled/sessionSyncEnabled -
     * an independent concern from file/session sync, same as clock-drift
     * measurement already is.
     *
     * @return int requests executed (successfully reported back), for
     *             PullCommand's own pass-summary log line
     */
    public function pullTestRequests(CURLRequest $client, Cluster $cluster): int
    {
        $response = $client->get('cluster/pull-test-requests', [
            'headers' => ['Authorization' => $cluster->authHeader()],
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new RuntimeException('pull-test-requests HTTP ' . $response->getStatusCode());
        }

        $body = json_decode($response->getBody(), true);

        return $this->applyTestRequests($client, $cluster, is_array($body['requests'] ?? null) ? $body['requests'] : []);
    }

    /**
     * Post-fetch half of pullTestRequests() above - see
     * applyInvalidations()'s own docblock for why this is factored out.
     * Still needs $client/$cluster: unlike the other apply*() methods
     * (purely local writes), this one runs the check locally THEN reports
     * back to the peer over HTTP - the "relay" in NAT-safe relay.
     *
     * @param list<array{id: string, payload: array}> $requests
     */
    public function applyTestRequests(CURLRequest $client, Cluster $cluster, array $requests): int
    {
        $executed = 0;
        foreach ($requests as $request) {
            $requestId = (string) ($request['id'] ?? '');
            $payload   = (array) ($request['payload'] ?? []);
            if ($requestId === '') {
                continue;
            }

            // Same single dispatch point RemoteTestController's own
            // synchronous public-target path uses - see CapabilityChecker's
            // own docblock for why this used to be a second copy of the
            // same if/elseif here.
            $kind   = (string) ($payload['kind'] ?? '');
            $result = (new \AdGo\Cluster\CapabilityChecker())->run($kind, $payload);

            $client->post('cluster/test-result', [
                'headers' => ['Authorization' => $cluster->authHeader()],
                'json'    => ['requestId' => $requestId, 'result' => $result],
            ]);
            $executed++;
        }

        return $executed;
    }

    private function downloadFile(CURLRequest $client, Cluster $cluster, string $relativePath, string $peerName, float $driftOffset): void
    {
        $response = $client->get('cluster/pull-file', [
            'headers' => ['Authorization' => $cluster->authHeader()],
            'query'   => ['path' => $relativePath],
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new RuntimeException("pull-file $relativePath HTTP " . $response->getStatusCode());
        }

        $targetPath = $cluster->resolveIncomingPath($relativePath);
        if ($targetPath === null) {
            // Peer sent a path that doesn't resolve under our own
            // syncDirs - never trust it, same rejection FileReceiverController
            // already applies to a pushed path.
            return;
        }

        $tmpPath = sys_get_temp_dir() . '/cluster_pull_' . bin2hex(random_bytes(8));
        file_put_contents($tmpPath, $response->getBody());

        $claimedMtime = (int) $response->getHeaderLine('X-Cluster-Mtime');
        // Re-expressed in THIS node's own clock frame before it's used for
        // anything - see Cluster::correctMtimeFromPeer()'s own docblock.
        // A genuine two-sided conflict is judged by drift-corrected
        // timestamps, not the peer's raw clock reading.
        $correctedMtime = $cluster->correctMtimeFromPeer($claimedMtime, $driftOffset);
        // Computed from the actually-downloaded bytes, not trusted from
        // the X-Cluster-Hash header - same reasoning as
        // FileReceiverController's own incoming-hash computation: a
        // conflict decision needs the real content, not a claim that
        // could itself be wrong/corrupted in transit.
        $incomingHash = (string) md5_file($tmpPath);
        $resolution   = $cluster->detectConflict($relativePath, $targetPath, $incomingHash, $correctedMtime);

        if ($resolution['conflict']) {
            // Archive the LOSER before anything overwrites it - same
            // reasoning as FileReceiverController's own push-side gate.
            $cluster->preserveConflictLoser(
                $relativePath,
                $resolution['incomingWins'] ? $targetPath : $tmpPath,
                $resolution['incomingWins'] ? 'local' : $peerName,
                $resolution['incomingWins'] ? $peerName : 'local'
            );
        }

        if (! $resolution['incomingWins']) {
            // Local wins - leave $targetPath and the manifest untouched
            // (same self-correcting reasoning as FileReceiverController's
            // own local-wins branch: this node's own next scan re-pushes
            // the winner on its own). The downloaded tmp copy was already
            // archived above if this was a real conflict; discard it
            // either way, it's not going anywhere.
            @unlink($tmpPath);

            return;
        }

        if (! @rename($tmpPath, $targetPath)) {
            // rename() can fail across filesystems (sys_get_temp_dir() vs
            // WRITEPATH aren't guaranteed to be the same device) - copy
            // always works, at the cost of one extra read+write.
            copy($tmpPath, $targetPath);
            @unlink($tmpPath);
        }

        $cluster->finalizeIncomingFile($relativePath, $targetPath, $correctedMtime);
    }
}

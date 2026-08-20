<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use AdGo\Cluster\Config\Cluster as ClusterConfig;

/**
 * State for the NAT-safe remote connection-test relay (see
 * RemoteTestController's own docblock for the full request/response
 * shape) - writable/Cluster/remote_test_queue.json, same flock()-guarded
 * JSON convention as every other state file here.
 *
 * Two independent halves in one file (small, low-volume, no reason to
 * split):
 * - "pending": requests THIS node is holding on behalf of a NAT target
 *   that hasn't pulled them yet, keyed by target node name -> list. A NAT
 *   node's own cluster:pull cycle claims (reads-and-clears) its own
 *   entries when it next asks this node - see claimPending().
 * - "results": completed test results THIS node itself asked for,
 *   keyed by requestId, written by testResult() once the target node's
 *   pull cycle reports back. cluster-ui's Settings page polls result()
 *   until an entry shows up or its own client-side timeout gives up.
 */
class RemoteTestQueue
{
    private ClusterConfig $config;

    // Anything older than this is pruned on the next write - a NAT node
    // whose pull cycle never reaches this peer (down, misconfigured,
    // pullLoopSeconds=0 and a full minute between cron ticks) would
    // otherwise leave an ever-growing pending list; a browser that gave
    // up polling long ago has no way to say so, so completed results
    // need the same bound. Generous relative to the ~90s client-side
    // poll timeout (see settings.js) - never prunes something still
    // being actively waited on under normal conditions.
    private const MAX_AGE_SECONDS = 900;

    public function __construct(?ClusterConfig $config = null)
    {
        $this->config = $config ?? config('Cluster');
    }

    public function path(): string
    {
        return rtrim(WRITEPATH, '/\\') . '/' . trim($this->config->stateDir, '/\\') . '/remote_test_queue.json';
    }

    /**
     * @param array<string, mixed> $payload
     */
    public function enqueue(string $targetNode, string $requestId, array $payload): void
    {
        $this->mutate(static function (array $state) use ($targetNode, $requestId, $payload): array {
            $state['pending'][$targetNode] ??= [];
            $state['pending'][$targetNode][] = [
                'id'       => $requestId,
                'payload'  => $payload,
                'queuedAt' => time(),
            ];

            return $state;
        });
    }

    /**
     * Reads AND clears $targetNode's own pending list in one flock()'d
     * write - a request claimed here is gone from "pending" whether or
     * not the caller (the NAT node's own pull cycle) actually manages to
     * execute and report every one of them; a node that dies mid-batch
     * simply leaves those specific results never arriving, which the
     * requester's own client-side poll timeout already handles, rather
     * than retrying forever into an ever-growing list.
     *
     * @return list<array{id: string, payload: array<string, mixed>, queuedAt: int}>
     */
    public function claimPending(string $targetNode): array
    {
        $claimed = [];
        $this->mutate(static function (array $state) use ($targetNode, &$claimed): array {
            $claimed = $state['pending'][$targetNode] ?? [];
            unset($state['pending'][$targetNode]);

            return $state;
        });

        return $claimed;
    }

    /**
     * @param array<string, mixed> $result
     */
    public function recordResult(string $requestId, array $result): void
    {
        $this->mutate(static function (array $state) use ($requestId, $result): array {
            $state['results'][$requestId] = [
                'result'     => $result,
                'receivedAt' => time(),
            ];

            return $state;
        });
    }

    /**
     * @return array<string, mixed>|null null while still pending/unknown
     */
    public function result(string $requestId): ?array
    {
        $state = $this->read();

        return $state['results'][$requestId]['result'] ?? null;
    }

    /**
     * @param callable(array{pending: array<string, list<array<string, mixed>>>, results: array<string, array{result: array<string, mixed>, receivedAt: int}>}): array $mutator
     */
    private function mutate(callable $mutator): void
    {
        $path = $this->path();
        $dir  = dirname($path);
        if (! is_dir($dir) && ! mkdir($dir, 0775, true) && ! is_dir($dir)) {
            return; // best-effort - a queue write failing must never break the actual test request/response
        }

        $handle = fopen($path, 'cb+');
        if ($handle === false) {
            return;
        }

        flock($handle, LOCK_EX);
        $contents = stream_get_contents($handle);
        $state    = json_decode((string) $contents, true);
        $state    = is_array($state) ? $state : [];
        $state['pending'] ??= [];
        $state['results'] ??= [];

        $state = $mutator($state);
        $state = $this->prune($state);

        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
        @chmod($path, 0664);
    }

    /**
     * @return array{pending: array<string, list<array<string, mixed>>>, results: array<string, array{result: array<string, mixed>, receivedAt: int}>}
     */
    private function read(): array
    {
        $path = $this->path();
        if (! is_file($path)) {
            return ['pending' => [], 'results' => []];
        }

        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return ['pending' => [], 'results' => []];
        }
        flock($handle, LOCK_SH);
        $contents = stream_get_contents($handle);
        flock($handle, LOCK_UN);
        fclose($handle);

        $state = json_decode((string) $contents, true);
        $state = is_array($state) ? $state : [];
        $state['pending'] ??= [];
        $state['results'] ??= [];

        return $state;
    }

    /**
     * @param array{pending: array<string, list<array<string, mixed>>>, results: array<string, array{result: array<string, mixed>, receivedAt: int}>} $state
     *
     * @return array{pending: array<string, list<array<string, mixed>>>, results: array<string, array{result: array<string, mixed>, receivedAt: int}>}
     */
    private function prune(array $state): array
    {
        $cutoff = time() - self::MAX_AGE_SECONDS;

        foreach ($state['pending'] as $target => $entries) {
            $state['pending'][$target] = array_values(array_filter(
                $entries,
                static fn (array $e): bool => (int) ($e['queuedAt'] ?? 0) >= $cutoff
            ));
            if ($state['pending'][$target] === []) {
                unset($state['pending'][$target]);
            }
        }

        foreach ($state['results'] as $requestId => $entry) {
            if ((int) ($entry['receivedAt'] ?? 0) < $cutoff) {
                unset($state['results'][$requestId]);
            }
        }

        return $state;
    }
}

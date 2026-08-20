<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use AdGo\Cluster\Config\Cluster as ClusterConfig;

/**
 * Short-lived, single-use tickets behind the real cross-node SSO handoff
 * (see SsoController) - written to writable/Cluster/sso_tickets.json (same
 * directory/flock() convention as every other state file here).
 *
 * Deliberately NOT the same JWT the Dashboard's "Sessions synchronization"
 * card issues at login: that one's TTL matches the whole browser session
 * (~2h), and putting a credential that long-lived into a URL query string
 * - which browsers, proxies, and access logs all see - is a real exposure
 * window. A ticket here is a random opaque string with no meaning on its
 * own: the target node can only redeem it by asking the ISSUING node to
 * confirm it (SsoController::verify(), over the same Bearer-authed peer
 * channel every other cluster/* route already uses), and it's short-lived
 * (Config\Cluster::$ssoTicketTtlSeconds, default 60s - just long enough
 * for one browser redirect) AND single-use: consume() deletes it the
 * moment it's read, so a replayed/observed ticket can never work twice.
 */
class SsoTicketStore
{
    private ClusterConfig $config;

    public function __construct(?ClusterConfig $config = null)
    {
        $this->config = $config ?? config('Cluster');
    }

    public function path(): string
    {
        return rtrim(WRITEPATH, '/\\') . '/' . trim($this->config->stateDir, '/\\') . '/sso_tickets.json';
    }

    /**
     * $returnPath travels WITH the ticket (not as a separate query-string
     * param on the consume() redirect) for the same reason $email does -
     * it's read back only from the verified server-to-server response
     * (see SsoController::verify()/consume()), never trusted from a raw
     * URL a browser could carry. Added 2026-08-19 so switching nodes lands
     * on the same page instead of always the dashboard.
     */
    public function issue(string $email, string $returnPath = '/'): string
    {
        $email  = strtolower(trim($email));
        $ticket = bin2hex(random_bytes(32));
        $ttl    = max(1, $this->config->ssoTicketTtlSeconds);

        $this->withStore(function (array $tickets) use ($ticket, $email, $returnPath, $ttl): array {
            $tickets[$ticket] = ['email' => $email, 'returnPath' => $returnPath, 'expiresAt' => time() + $ttl];

            return $tickets;
        });

        return $ticket;
    }

    /**
     * Redeems a ticket - null if it never existed, already got redeemed,
     * or expired.
     *
     * @return array{email: string, returnPath: string}|null
     */
    public function consume(string $ticket): ?array
    {
        $result = null;

        $this->withStore(function (array $tickets) use ($ticket, &$result): array {
            $row = $tickets[$ticket] ?? null;
            if ($row !== null) {
                unset($tickets[$ticket]);
                if ((int) ($row['expiresAt'] ?? 0) > time()) {
                    $result = ['email' => (string) $row['email'], 'returnPath' => (string) ($row['returnPath'] ?? '/')];
                }
            }

            return $tickets;
        });

        return $result;
    }

    /**
     * @param callable(array<string, array{email: string, expiresAt: int}>): array<string, array{email: string, expiresAt: int}> $mutator
     */
    private function withStore(callable $mutator): void
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
        $tickets  = json_decode((string) $contents, true);
        $tickets  = is_array($tickets) ? $tickets : [];

        // Pruned on every access (issue AND consume), not just a
        // background sweep - the only two things that ever touch this
        // file, so this is the only place stale entries could ever be
        // removed. Keeps the file from growing forever from tickets that
        // were issued but never redeemed.
        $now     = time();
        $tickets = array_filter($tickets, static fn (array $row): bool => ($row['expiresAt'] ?? 0) > $now);

        $tickets = $mutator($tickets);

        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($tickets, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
        // Same cross-user-write reasoning as every other state file here
        // (see SyncState's own docblock) - issue() typically runs under
        // PHP-FPM (a browser click), consume()/verify() could run under
        // either PHP-FPM (a peer's verify POST) or nothing CLI-driven at
        // all in this particular file's case, but the pattern is kept for
        // consistency and because it's cheap insurance either way.
        @chmod($path, 0664);
    }
}

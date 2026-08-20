<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use CodeIgniter\Settings\Settings;
use phpseclib3\Net\SSH2;
use Throwable;

/**
 * Real read-AND-write crontab test over SSH, same phpseclib3 connection
 * pattern NodeConnectionChecker::checkSsh() already uses (login, no
 * system ssh binary assumed - see that method's own docblock for why).
 * Always goes over SSH, even when "testing yourself" - unlike a plain
 * local `exec('crontab -l')` shortcut, this proves the SAME thing FTP/
 * SSH deploy checks already prove for a node testing its own row:
 * that a REAL network round trip to this node's own registered SSH
 * credentials (Nodes.ssh* - crontab has no separate protocol/credential
 * set of its own, it rides on whatever SSH access is already configured)
 * actually works end to end, not just that a local shell happens to
 * exist. Reuses `Nodes.ssh*`, never `Nodes.ftp*` - crontab management
 * has no FTP/FTPS equivalent.
 *
 * Read-only would only prove `crontab -l` works, not that this account
 * can actually MANAGE its cron jobs - the thing an admin actually cares
 * about (deploy tooling on this project writes Tasks-schedule-equivalent
 * cron lines by hand on nodes without `codeigniter4/tasks`' own
 * scheduler). Proven by writing the crontab's OWN current content back
 * unchanged via `crontab -`, then re-reading and comparing - a true
 * round trip, not just "the write command exited 0" (which would still
 * pass even if it wrote garbage). Content travels base64-encoded inside
 * a single `exec()` call (phpseclib3's SSH2 runs one command per call,
 * no stdin-piping API) - base64's alphabet has no shell metacharacters,
 * so it's safe to embed directly inside single quotes with no further
 * escaping.
 *
 * A NODE WITH NO EXISTING CRONTAB IS DELIBERATELY NOT WRITE-TESTED:
 * `crontab -l` on an account with no crontab file at all exits non-zero
 * ("no crontab for USER") rather than returning empty content; running
 * `crontab -` with empty stdin in that case would CREATE a new empty
 * crontab file where none existed - a real state change, not the no-op
 * round trip this check is supposed to be. Read access is still
 * confirmed and reported in that case, write is reported as "not
 * exercised" rather than faked or skipped silently.
 */
class CronConnectionChecker
{
    /**
     * @return array{ok: bool, detail?: string, error?: string, ms: float}
     */
    public function checkNode(string $node, ?Settings $settings = null): array
    {
        $settings = $settings ?? service('settings');

        return $this->checkParams([
            'host' => (string) ($settings->get('Nodes.sshHost', $node) ?? ''),
            'port' => (string) ($settings->get('Nodes.sshPort', $node) ?? ''),
            'user' => (string) ($settings->get('Nodes.sshUser', $node) ?? ''),
            'pass' => (string) ($settings->get('Nodes.sshPass', $node) ?? ''),
        ]);
    }

    /**
     * @param array{host?: string, port?: string|int, user?: string, pass?: string} $params
     *
     * @return array{ok: bool, detail?: string, error?: string, ms: float}
     */
    public function checkParams(array $params): array
    {
        $host = trim((string) ($params['host'] ?? ''));
        if ($host === '') {
            return ['ok' => false, 'error' => 'No SSH host configured for this node.', 'ms' => 0.0];
        }
        $port = (int) ($params['port'] ?: 22);
        $user = (string) ($params['user'] ?? '');
        $pass = (string) ($params['pass'] ?? '');

        $start = microtime(true);
        try {
            $ssh      = new SSH2($host, $port, 10);
            $loggedIn = $ssh->login($user, $pass);
            if (! $loggedIn) {
                return ['ok' => false, 'error' => 'Authentication failed.', 'ms' => $this->msSince($start)];
            }

            $before     = (string) $ssh->exec('crontab -l 2>&1');
            $readStatus = $ssh->getExitStatus();

            if ($readStatus !== 0) {
                $ssh->disconnect();
                // "no crontab for USER" is a legitimate empty state, not a
                // failure - crontab(1)'s own message for it, present on
                // every cron implementation this project's nodes run
                // (verified live 2026-08-19). Anything else (crontab
                // binary missing, permission denied by the OS/cron.allow)
                // is a real failure.
                if (stripos($before, 'no crontab') !== false) {
                    return ['ok' => true, 'detail' => 'Read access confirmed - no existing crontab, write not exercised.', 'ms' => $this->msSince($start)];
                }

                return ['ok' => false, 'error' => 'crontab -l failed: ' . trim($before), 'ms' => $this->msSince($start)];
            }

            $encoded     = base64_encode($before);
            $ssh->exec("echo '{$encoded}' | base64 -d | crontab - 2>&1");
            $writeStatus = $ssh->getExitStatus();
            if ($writeStatus !== 0) {
                $ssh->disconnect();

                return ['ok' => false, 'error' => 'crontab write-back failed (exit ' . $writeStatus . ').', 'ms' => $this->msSince($start)];
            }

            $after = (string) $ssh->exec('crontab -l 2>&1');
            $ssh->disconnect();

            if ($after !== $before) {
                // Round trip changed something - never report success on a
                // mismatch, even though the write command itself exited 0.
                return ['ok' => false, 'error' => 'crontab content changed after round-trip write - reverted state may not match.', 'ms' => $this->msSince($start)];
            }

            $lines = trim($before) === '' ? 0 : count(explode("\n", trim($before)));

            return ['ok' => true, 'detail' => "read+write confirmed, {$lines} line(s), content unchanged", 'ms' => $this->msSince($start)];
        } catch (Throwable $e) {
            return ['ok' => false, 'error' => $e->getMessage(), 'ms' => $this->msSince($start)];
        }
    }

    private function msSince(float $start): float
    {
        return round((microtime(true) - $start) * 1000, 1);
    }
}

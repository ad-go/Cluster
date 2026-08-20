<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use CodeIgniter\Settings\Settings;
use phpseclib3\Net\SSH2;
use Throwable;

/**
 * Real connect-and-prove-usable test against whatever deploy credentials
 * are CURRENTLY saved for a node in cluster-ui's Settings -> Nodes table -
 * whichever protocol (`Nodes.protocol`) is presently selected for that row
 * (FTP, FTPS explicit/AUTH TLS, SSH, or SCP - see SettingsController::
 * NODE_PROTOCOLS in ad-go/cluster-ui), using that protocol's own
 * independent credential set (`Nodes.ftp*` or `Nodes.ssh*`).
 *
 * checkNode() (local Settings lookup) and checkParams() (raw parameters,
 * no Settings involved) are separate entry points onto the SAME connect
 * logic - checkParams() exists specifically so RemoteTestController can
 * run a check using parameters that arrived OVER THE WIRE from a
 * different node (see that class's own docblock for why credentials must
 * be tested from the TARGET node's own local network position), without
 * duplicating the connect/try/catch logic a second time.
 *
 * Same "on-demand, not a scheduled/queued check" role DbConnectionChecker
 * has for the Databases table - triggered only from cluster-ui's Nodes
 * table node-name badge/modal, not from a Queue job or Tasks schedule.
 * SSH/SCP connectivity IS already covered by a scheduled/queued check
 * elsewhere (see SshChecker, triggered after login and every minute,
 * writing to writable/Cluster/ssh_connections.json) - this class
 * deliberately does NOT duplicate that persistent-log side effect; an
 * on-demand modal click proving "does THIS click work right now" has no
 * need for a history file, unlike the standing health check SshChecker
 * already is.
 */
class NodeConnectionChecker
{
    /**
     * @return array{ok: bool, protocol?: string, detail?: string, error?: string, ms: float}
     */
    public function checkNode(string $node, ?Settings $settings = null): array
    {
        $settings = $settings ?? service('settings');
        $protocol = (string) ($settings->get('Nodes.protocol', $node) ?? 'FTP');
        $family   = in_array($protocol, ['SSH', 'SCP'], true) ? 'ssh' : 'ftp';

        return $this->checkParams([
            'protocol' => $protocol,
            'host'     => (string) ($settings->get('Nodes.' . $family . 'Host', $node) ?? ''),
            'port'     => (string) ($settings->get('Nodes.' . $family . 'Port', $node) ?? ''),
            'user'     => (string) ($settings->get('Nodes.' . $family . 'User', $node) ?? ''),
            'pass'     => (string) ($settings->get('Nodes.' . $family . 'Pass', $node) ?? ''),
        ]);
    }

    /**
     * @param array{protocol?: string, host?: string, port?: string|int, user?: string, pass?: string} $params
     *
     * @return array{ok: bool, protocol?: string, detail?: string, error?: string, ms: float}
     */
    public function checkParams(array $params): array
    {
        $protocol = (string) ($params['protocol'] ?? 'FTP');

        return in_array($protocol, ['SSH', 'SCP'], true)
            ? $this->checkSsh($protocol, $params)
            : $this->checkFtp($protocol, $params);
    }

    /**
     * @param array{host?: string, port?: string|int, user?: string, pass?: string} $params
     */
    private function checkSsh(string $protocol, array $params): array
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

            // Cheap, side-effect-free - same proof-of-usability SshChecker
            // itself uses: confirms the shell actually runs commands, not
            // only that the handshake/auth succeeded.
            $ssh->exec('true');
            $exitStatus = $ssh->getExitStatus();
            $ssh->disconnect();

            if ($exitStatus !== 0) {
                return ['ok' => false, 'error' => "Login succeeded but exec failed (exit $exitStatus).", 'ms' => $this->msSince($start)];
            }

            return ['ok' => true, 'protocol' => $protocol, 'detail' => "$user@$host:$port", 'ms' => $this->msSince($start)];
        } catch (Throwable $e) {
            return ['ok' => false, 'error' => $e->getMessage(), 'ms' => $this->msSince($start)];
        }
    }

    /**
     * @param array{host?: string, port?: string|int, user?: string, pass?: string} $params
     */
    private function checkFtp(string $protocol, array $params): array
    {
        $host = trim((string) ($params['host'] ?? ''));
        if ($host === '') {
            return ['ok' => false, 'error' => 'No FTP host configured for this node.', 'ms' => 0.0];
        }
        $port = (int) ($params['port'] ?: 21);
        $user = (string) ($params['user'] ?? '');
        $pass = (string) ($params['pass'] ?? '');

        // PHP's bundled ext-ftp, not a shell-out to a system ftp/curl
        // binary - same reasoning SshChecker gives for phpseclib over a
        // system ssh binary: no assumption about what's actually on the
        // shared hosting box beyond core PHP extensions. Not every build
        // has ext-ftp enabled, so this is checked, not assumed.
        if (! function_exists('ftp_connect')) {
            return ['ok' => false, 'error' => 'PHP ext-ftp is not available on this node.', 'ms' => 0.0];
        }

        $start  = microtime(true);
        $useTls = str_starts_with($protocol, 'FTPS');
        // @ - both ftp_connect()/ftp_ssl_connect() emit a PHP warning (not
        // an exception) on failure; the false return is the only reliable
        // signal, same shape as every native ftp_* call below.
        $conn = $useTls ? @ftp_ssl_connect($host, $port, 10) : @ftp_connect($host, $port, 10);
        if ($conn === false) {
            return ['ok' => false, 'error' => 'Could not connect to the FTP host.', 'ms' => $this->msSince($start)];
        }

        $loggedIn = @ftp_login($conn, $user, $pass);
        if (! $loggedIn) {
            @ftp_close($conn);

            return ['ok' => false, 'error' => 'FTP authentication failed.', 'ms' => $this->msSince($start)];
        }

        // Proof-of-usability, same idea as SSH's 'true' exec above - a
        // real round-trip command, not just an accepted login.
        $pwd = @ftp_pwd($conn);
        // @ - ftp_close() itself can emit a PHP warning closing an FTPS
        // (explicit TLS) control channel on some server/OpenSSL
        // combinations ("SSL_read on shutdown: unexpected eof while
        // reading") - benign, the actual test result above is already
        // captured by this point, found live 2026-08-19 testing against a
        // real FTPS node.
        @ftp_close($conn);

        if ($pwd === false) {
            return ['ok' => false, 'error' => 'Login succeeded but PWD failed.', 'ms' => $this->msSince($start)];
        }

        return ['ok' => true, 'protocol' => $protocol, 'detail' => $pwd, 'ms' => $this->msSince($start)];
    }

    private function msSince(float $start): float
    {
        return round((microtime(true) - $start) * 1000, 1);
    }
}

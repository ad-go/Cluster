<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use CodeIgniter\Settings\Settings;
use Throwable;

/**
 * Real connect-and-query test against whatever database credentials are
 * CURRENTLY saved for a node in cluster-ui's Settings -> Databases table
 * (`Databases.{type}Host` etc., one of five independent per-driver
 * credential sets - see SettingsController::DATABASE_PROPS's own docblock
 * in ad-go/cluster-ui) - same "prove it actually works, not just that
 * config exists" idea as SshChecker, for the Databases table instead of
 * the Nodes table's SSH credentials.
 *
 * Deliberately builds a RAW CI4 database config array and connects with it
 * directly (Config\Database::connect() accepts an array, not just a
 * registered group name) rather than looking up one of this app's own
 * configured connection groups ('default'/'cluster'/'production' at
 * most) - a Databases row can hold credentials for a driver this
 * particular app has no matching Config\Database group for at all (e.g.
 * testing 'postgres' on a node that only ever runs MySQLi/SQLite3 itself).
 *
 * checkNode() (local Settings lookup) and checkParams() (raw parameters,
 * no Settings involved at all) are separate entry points onto the SAME
 * connect-and-test logic - checkParams() exists specifically so
 * RemoteTestController can run a check using parameters that arrived
 * OVER THE WIRE from a different node (see that class's own docblock for
 * why a Databases/Nodes row's credentials must be tested from the TARGET
 * node's own local network position, not wherever the admin's browser
 * session happens to be), without that controller needing its own
 * second copy of the connect/try/catch logic.
 *
 * Triggered from cluster-ui's Databases table: clicking a node's name
 * badge opens a modal that calls SettingsController::testDatabase().
 */
class DbConnectionChecker
{
    // Maps the Databases table's own 'type' values (cluster-ui's
    // SettingsController::DATABASE_TYPES) to CI4's actual DBDriver class
    // names - the two don't share spelling (mysql -> MySQLi, postgres ->
    // Postgre, oci8 -> OCI8).
    private const DRIVER_CLASS = [
        'mysql'    => 'MySQLi',
        'postgres' => 'Postgre',
        'sqlite3'  => 'SQLite3',
        'oci8'     => 'OCI8',
        'sqlsrv'   => 'SQLSRV',
    ];

    /**
     * @return array{ok: bool, driver?: string, version?: string, error?: string, ms: float}
     */
    public function checkNode(string $node, ?Settings $settings = null): array
    {
        $settings = $settings ?? service('settings');
        $type     = (string) ($settings->get('Databases.type', $node) ?? 'mysql');

        return $this->checkParams([
            'driverType' => $type,
            'host'       => (string) ($settings->get('Databases.' . $type . 'Host', $node) ?? ''),
            'port'       => (string) ($settings->get('Databases.' . $type . 'Port', $node) ?? ''),
            'user'       => (string) ($settings->get('Databases.' . $type . 'User', $node) ?? ''),
            'pass'       => (string) ($settings->get('Databases.' . $type . 'Pass', $node) ?? ''),
            'database'   => (string) ($settings->get('Databases.' . $type . 'Database', $node) ?? ''),
        ]);
    }

    /**
     * @param array{driverType?: string, host?: string, port?: string|int, user?: string, pass?: string, database?: string} $params
     *
     * @return array{ok: bool, driver?: string, version?: string, error?: string, ms: float}
     */
    public function checkParams(array $params): array
    {
        $type   = (string) ($params['driverType'] ?? 'mysql');
        $driver = self::DRIVER_CLASS[$type] ?? self::DRIVER_CLASS['mysql'];

        $config = [
            'DSN'          => '',
            'hostname'     => (string) ($params['host'] ?? ''),
            'username'     => (string) ($params['user'] ?? ''),
            'password'     => (string) ($params['pass'] ?? ''),
            'database'     => (string) ($params['database'] ?? ''),
            'DBDriver'     => $driver,
            'DBPrefix'     => '',
            'pConnect'     => false,
            'DBDebug'      => true,
            'charset'      => 'utf8mb4',
            'DBCollat'     => 'utf8mb4_general_ci',
            'swapPre'      => '',
            'encrypt'      => false,
            'compress'     => false,
            'strictOn'     => false,
            'failover'     => [],
            'port'         => (int) ($params['port'] ?: 0),
        ];

        $start = microtime(true);
        try {
            // $getShared=false - a shared/cached connection here would
            // silently reuse a PRIOR test's (possibly now-stale or
            // differently-credentialed) connection instead of proving
            // THESE exact currently-saved values actually connect.
            $db = \Config\Database::connect($config, false);
            $db->initialize();

            return [
                'ok'      => true,
                'driver'  => $driver,
                'version' => (string) $db->getVersion(),
                'ms'      => round((microtime(true) - $start) * 1000, 1),
            ];
        } catch (Throwable $e) {
            return [
                'ok'    => false,
                'error' => $e->getMessage(),
                'ms'    => round((microtime(true) - $start) * 1000, 1),
            ];
        }
    }
}

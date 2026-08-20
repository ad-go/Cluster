<?php

declare(strict_types=1);

namespace AdGo\Cluster;

use CodeIgniter\Database\ConnectionInterface;

/**
 * The one place table-specific knowledge lives for DB sync (see this
 * package's README "How the database is synced"). No schema changes
 * anywhere - every table here uses a node-local autoincrement `id` that
 * differs per node for the SAME logical record, so each table's own
 * already-existing natural/business key (email; class+key+context) is
 * what identifies a row across nodes, exactly like session invalidation
 * and SSO already key everything by email rather than Shield's numeric
 * user ID.
 *
 * A "user" snapshot is exported/applied as ONE unit spanning users +
 * auth_identities + auth_groups_users + auth_permissions_users +
 * user_profiles - not one row at a time - because every one of those
 * tables' foreign keys (`user_id`) is node-local and meaningless outside
 * the node that assigned it; the snapshot resolves that FK exactly once
 * (by email) rather than needing a separate remap step per table.
 *
 * Hard-excluded from Config\Cluster::$dbSyncGroup's whole-database
 * discovery, regardless of $dbExcludeTables (see HARD_EXCLUDED_TABLES
 * below), and not handled here at all: migrations/sqlite_sequence
 * (node-local deployment bookkeeping, never portable), queue_jobs/
 * queue_jobs_failed (relocated to their own connection - see
 * Config\Database's $cluster group), auth_logins/auth_token_logins/
 * auth_remember_tokens (audit logs and per-device tokens with no
 * cross-node sync value).
 */
class DbSyncSchema
{
    /**
     * @return array{email: string, users: array, identities: list<array>, groups: list<string>, permissions: list<string>, profile: array|null}|null
     */
    public static function exportUser(ConnectionInterface $db, string $email): ?array
    {
        $email = strtolower(trim($email));

        $identityRow = $db->table('auth_identities')
            ->where('type', 'email_password')
            ->where('secret', $email)
            ->get()->getRowArray();
        if ($identityRow === null) {
            return null;
        }
        $userId = (int) $identityRow['user_id'];

        $user = $db->table('users')->where('id', $userId)->get()->getRowArray();
        if ($user === null) {
            return null;
        }
        unset($user['id']);

        $identities = $db->table('auth_identities')->where('user_id', $userId)->get()->getResultArray();
        foreach ($identities as &$identity) {
            unset($identity['id'], $identity['user_id']);
        }
        unset($identity);

        $groups = array_values(array_column(
            $db->table('auth_groups_users')->where('user_id', $userId)->get()->getResultArray(),
            'group'
        ));
        $permissions = array_values(array_column(
            $db->table('auth_permissions_users')->where('user_id', $userId)->get()->getResultArray(),
            'permission'
        ));

        $profile = $db->table('user_profiles')->where('user_id', $userId)->get()->getRowArray();
        if ($profile !== null) {
            unset($profile['id'], $profile['user_id']);
        }

        return [
            'email'       => $email,
            'users'       => $user,
            'identities'  => $identities,
            'groups'      => $groups,
            'permissions' => $permissions,
            'profile'     => $profile,
        ];
    }

    /**
     * @return list<string> every distinct email currently known to this node
     */
    public static function exportAllUserEmails(ConnectionInterface $db): array
    {
        $rows = $db->table('auth_identities')
            ->select('secret')
            ->where('type', 'email_password')
            ->get()->getResultArray();

        return array_values(array_unique(array_map(
            static fn (array $row): string => strtolower(trim((string) $row['secret'])),
            $rows
        )));
    }

    /**
     * Insert-or-update a user's full snapshot. Brand new email -> a new
     * `users` row via Shield's own UserModel (respects its own defaults/
     * validation, same as how a real signup or CI4install.php's
     * installSuperadminHere() creates one). Existing email -> mutable
     * fields updated in place, but `created_at` is NEVER overwritten from
     * an incoming snapshot - that's this node's own record of when it
     * first learned about the account, not portable state.
     *
     * `secret2` (the bcrypt hash) is written VERBATIM from the payload -
     * it is already hashed by the originating node; re-hashing it here
     * would break login. This is the one place password data crosses
     * nodes, over the same Bearer-HTTPS channel every other peer-to-peer
     * call already uses - intentional, since "the same login works
     * everywhere" is the actual point of this feature.
     */
    /**
     * @param list<string> $queryLog appended with the real SQL text of
     *                               every write this call makes - see
     *                               applyIncomingCommand()'s own docblock,
     *                               this is what the Dashboard's "Database
     *                               synchronization" card shows as
     *                               "recent SQL commands"
     */
    public static function applyUserSnapshot(ConnectionInterface $db, array $snapshot, array &$queryLog = []): void
    {
        $email = strtolower(trim((string) ($snapshot['email'] ?? '')));
        if ($email === '') {
            return;
        }

        $existingIdentity = $db->table('auth_identities')
            ->where('type', 'email_password')
            ->where('secret', $email)
            ->get()->getRowArray();

        if ($existingIdentity === null) {
            $userModel = new \CodeIgniter\Shield\Models\UserModel();
            $userEntity = new \CodeIgniter\Shield\Entities\User((array) ($snapshot['users'] ?? []));
            $userModel->save($userEntity);
            $userId = (int) $userModel->getInsertID();
            $queryLog[] = $db->showLastQuery();
        } else {
            $userId = (int) $existingIdentity['user_id'];
            $fields = (array) ($snapshot['users'] ?? []);
            unset($fields['created_at']);
            if ($fields !== []) {
                $db->table('users')->where('id', $userId)->update($fields);
                $queryLog[] = $db->showLastQuery();
            }
        }

        foreach ((array) ($snapshot['identities'] ?? []) as $incoming) {
            $type = (string) ($incoming['type'] ?? '');
            $name = (string) ($incoming['name'] ?? '');
            if ($type === '') {
                continue;
            }
            $secret = (string) ($incoming['secret'] ?? '');
            // Match by (type, secret) when there IS a secret - that's the
            // ACTUAL unique constraint Shield enforces on auth_identities
            // (found live 2026-08-18: matching by (user_id, type, name)
            // alone let a concurrent delivery race hit "UNIQUE constraint
            // failed: auth_identities.type, auth_identities.secret" -
            // this is the real key, (user_id, type, name) was only ever a
            // proxy for it). Falls back to (user_id, type, name) for
            // identity types with no meaningful secret to match on.
            $existing = $secret !== ''
                ? $db->table('auth_identities')->where('type', $type)->where('secret', $secret)->get()->getRowArray()
                : $db->table('auth_identities')->where('user_id', $userId)->where('type', $type)->where('name', $name)->get()->getRowArray();
            $data = $incoming;
            $data['user_id'] = $userId;
            if ($existing !== null) {
                unset($data['created_at']);
                $db->table('auth_identities')->where('id', $existing['id'])->update($data);
            } else {
                $db->table('auth_identities')->insert($data);
            }
            $queryLog[] = $db->showLastQuery();
        }

        self::replaceMembership($db, 'auth_groups_users', 'group', $userId, (array) ($snapshot['groups'] ?? []), $queryLog);
        self::replaceMembership($db, 'auth_permissions_users', 'permission', $userId, (array) ($snapshot['permissions'] ?? []), $queryLog);

        $profile = $snapshot['profile'] ?? null;
        if (is_array($profile) && $profile !== []) {
            $existingProfile = $db->table('user_profiles')->where('user_id', $userId)->get()->getRowArray();
            $data = $profile;
            $data['user_id'] = $userId;
            if ($existingProfile !== null) {
                unset($data['created_at']);
                $db->table('user_profiles')->where('id', $existingProfile['id'])->update($data);
            } else {
                $db->table('user_profiles')->insert($data);
            }
            $queryLog[] = $db->showLastQuery();
        }
    }

    /**
     * Full diff-based replace (add missing, REMOVE stale) - unlike
     * generic file deletion (explicitly out of scope elsewhere), a
     * snapshot's group/permission list is a complete declaration of
     * current membership, so reconciling removals here is correct and
     * security-relevant (revoking superadmin on one node should revoke
     * it everywhere).
     *
     * @param list<string> $wanted
     * @param list<string> $queryLog
     */
    private static function replaceMembership(ConnectionInterface $db, string $table, string $column, int $userId, array $wanted, array &$queryLog): void
    {
        $current = array_values(array_column(
            $db->table($table)->where('user_id', $userId)->get()->getResultArray(),
            $column
        ));

        foreach (array_diff($wanted, $current) as $add) {
            $db->table($table)->insert([
                'user_id'  => $userId,
                $column    => $add,
                'created_at' => date('Y-m-d H:i:s'),
            ]);
            $queryLog[] = $db->showLastQuery();
        }
        foreach (array_diff($current, $wanted) as $remove) {
            $db->table($table)->where('user_id', $userId)->where($column, $remove)->delete();
            $queryLog[] = $db->showLastQuery();
        }
    }

    /**
     * Stable across identical content regardless of array order - groups/
     * permissions/identities are sorted before hashing so re-exporting
     * unchanged data (just enumerated in a different order) never looks
     * like a change.
     *
     * Also strips `last_active` (users) and `last_used_at` (each identity)
     * before hashing - found live 2026-08-18: these drift on their own
     * (Shield touches them on ordinary authenticated activity, unrelated
     * to any account-data change worth syncing), so leaving them in the
     * hash made every account look "changed" on nearly every cron tick -
     * a constant, unnecessary re-broadcast storm, not a one-off. The
     * actual DB columns are still synced as part of the payload (no
     * information lost) - only the CHANGE-DETECTION hash ignores them.
     */
    public static function hashUserSnapshot(array $snapshot): string
    {
        $normalized               = $snapshot;
        $normalized['groups']     = self::sorted($normalized['groups'] ?? []);
        $normalized['permissions'] = self::sorted($normalized['permissions'] ?? []);
        unset($normalized['users']['last_active']);
        foreach ($normalized['identities'] ?? [] as &$identity) {
            unset($identity['last_used_at']);
        }
        unset($identity);
        usort($normalized['identities'], static fn (array $a, array $b): int => (($a['type'] ?? '') . ($a['name'] ?? '')) <=> (($b['type'] ?? '') . ($b['name'] ?? '')));

        return md5((string) json_encode($normalized));
    }

    /**
     * The Settings package's own table has lived in the 'cluster'
     * connection group since 2026-08-19 (see app/Config/Settings.php's
     * 'group' and CI4install.php's patchSettingsClusterGroup() /
     * runSettingsMigrationAgainstClusterGroup() /cluster.md's own
     * writeup) - never in whatever connection a caller happens to pass
     * around for OTHER tables (users, generic app tables, both still on
     * 'default'). exportSetting()/exportAllSettingIds()/
     * applySettingSnapshot() below all deliberately ignore their own
     * $db parameter and connect here instead - found live 2026-08-19 as
     * "no such table: settings" on every node's cluster:sync-db cron the
     * very first minute after that migration landed, since every call
     * site here still passed db_connect('default').
     */
    private static function settingsDb(): ConnectionInterface
    {
        return db_connect('cluster');
    }

    /**
     * @return array{class: string, key: string, value: string, type: string, context: string, created_at?: string, updated_at?: string}|null
     */
    public static function exportSetting(ConnectionInterface $db, string $class, string $key, string $context): ?array
    {
        $row = self::settingsDb()->table('settings')
            ->where('class', $class)->where('key', $key)->where('context', $context)
            ->get()->getRowArray();
        if ($row === null) {
            return null;
        }
        unset($row['id']);

        return $row;
    }

    /**
     * @return list<array{class: string, key: string, context: string}>
     */
    public static function exportAllSettingIds(ConnectionInterface $db): array
    {
        return self::settingsDb()->table('settings')->select('class, key, context')->get()->getResultArray();
    }

    /**
     * @param list<string> $queryLog
     */
    public static function applySettingSnapshot(ConnectionInterface $db, array $snapshot, array &$queryLog = []): void
    {
        $settingsDb = self::settingsDb();
        $existing   = $settingsDb->table('settings')
            ->where('class', $snapshot['class'] ?? '')
            ->where('key', $snapshot['key'] ?? '')
            ->where('context', $snapshot['context'] ?? '')
            ->get()->getRowArray();

        $data = $snapshot;
        if ($existing !== null) {
            unset($data['created_at']);
            $settingsDb->table('settings')->where('id', $existing['id'])->update($data);
        } else {
            $settingsDb->table('settings')->insert($data);
        }
        $queryLog[] = $settingsDb->showLastQuery();
    }

    public static function hashSettingSnapshot(array $snapshot): string
    {
        return md5((string) json_encode($snapshot));
    }

    /**
     * Every table hardcoded elsewhere in this class (users' own five
     * tables, settings, and this package's own relocated queue tables) or
     * otherwise never a sensible wholesale-sync candidate (node-local
     * deployment bookkeeping) - excluded from $dbSyncGroup's discovery
     * below regardless of $dbExcludeTables, so a group pointed at the SAME
     * physical database users/settings/queue already live in (a valid,
     * if slightly redundant, config) can never double-handle any of them.
     * See this class's own top-of-file docblock for the fuller reasoning
     * on why each of these is out of scope for generic handling.
     */
    private const HARD_EXCLUDED_TABLES = [
        'migrations', 'sqlite_sequence',
        'users', 'auth_identities', 'auth_logins', 'auth_token_logins',
        'auth_remember_tokens', 'auth_groups_users', 'auth_permissions_users', 'user_profiles',
        'settings',
        'queue_jobs', 'queue_jobs_failed',
    ];

    /**
     * @var array<string, string>|null per-process cache - see the docblock
     *                                  below on why this is safe to keep
     *                                  for the life of one request/CLI run
     */
    private static ?array $genericTablesCache = null;

    private static ?string $genericTablesCacheGroup = null;

    /**
     * Discovers every table Config\Cluster::$dbSyncGroup's connection
     * group actually has, minus HARD_EXCLUDED_TABLES and
     * Config\Cluster::$dbExcludeTables, keeping only tables that pass BOTH
     * of $dbSyncGroup's own documented requirements (single-column,
     * non-integer-typed primary key; a real `updated_at` column) - see
     * that property's own docblock in Config\Cluster for the full
     * reasoning. A table failing either check is skipped and logged via
     * error_log(), not included with a wrong/guessed key and not a fatal
     * error for the whole sync run.
     *
     * Driver-agnostic by construction (listTables()/getFieldData()/
     * getIndexData() are all public CI4\BaseConnection methods, not
     * MySQL-specific raw SQL) - same "whatever driver a node's .env sets"
     * philosophy Config\Database's own $cluster group docblock already
     * commits to elsewhere in this project. One real MySQL-specific gap:
     * CI4's getFieldData() exposes MySQL's PRIMARY/not-PRIMARY flag but
     * not its own "is this AUTO_INCREMENT" Extra flag on any driver, so
     * this can only reject an integer-typed PK by column TYPE, not confirm
     * whether it truly auto-increments - a manually-assigned, never-
     * shared integer id would also get skipped here as a false negative.
     * That's the safe direction to be wrong in for a wholesale, no-per-
     * table-config feature: skipping a genuinely-fine table just means it
     * needs `id` renamed/retyped or its data reachable a different way,
     * not that a table with node-local ids about to collide across nodes
     * gets silently synced as if they were the same id.
     *
     * Cached per-process (a `static` property naturally resets every
     * fresh PHP-FPM/CLI process, so this never goes stale ACROSS
     * requests) because this is called several times per sync-db run
     * (SyncDbCommand's own three loops, plus DbSyncController's several
     * table-membership checks within the same request) and a schema
     * rarely changes mid-run - repeating six SHOW-COLUMNS/SHOW-INDEX-
     * style round trips per table on every single call would be pure
     * waste for data that cannot have changed since the first call this
     * same process already made.
     *
     * @return array<string, string> table => natural-key (primary key)
     *                                column
     */
    public static function genericTables(): array
    {
        $group = trim(config('Cluster')->dbSyncGroup);

        if ($group === '') {
            return [];
        }

        if (self::$genericTablesCache !== null && self::$genericTablesCacheGroup === $group) {
            return self::$genericTablesCache;
        }

        $exclude = array_merge(self::HARD_EXCLUDED_TABLES, config('Cluster')->dbExcludeTables);

        $tables = [];
        try {
            $db = db_connect($group);
            foreach ($db->listTables() as $tableName) {
                if (in_array($tableName, $exclude, true)) {
                    continue;
                }

                $keyColumn = self::discoverNaturalKey($db, $tableName);
                if ($keyColumn === null) {
                    continue; // reason already logged by discoverNaturalKey()
                }

                $tables[$tableName] = $keyColumn;
            }
        } catch (\Throwable $e) {
            error_log("DbSyncSchema::genericTables(): could not connect to/inspect group '$group' - $e");

            return [];
        }

        self::$genericTablesCache      = $tables;
        self::$genericTablesCacheGroup = $group;

        return $tables;
    }

    /**
     * @return string|null the table's primary-key column name, or null
     *                      (logged) if it doesn't meet $dbSyncGroup's
     *                      requirements - see genericTables()'s own
     *                      docblock
     */
    private static function discoverNaturalKey(ConnectionInterface $db, string $table): ?string
    {
        $indexes = $db->getIndexData($table);
        $primary = null;
        foreach ($indexes as $index) {
            if (($index->type ?? '') === 'PRIMARY') {
                $primary = $index;
                break;
            }
        }

        if ($primary === null || count($primary->fields ?? []) !== 1) {
            error_log("DbSyncSchema: skipping table '$table' - no single-column primary key (dbSyncGroup requires exactly one).");

            return null;
        }
        $keyColumn = $primary->fields[0];

        $fields        = $db->getFieldData($table);
        $keyField      = null;
        $hasUpdatedAt  = false;
        foreach ($fields as $field) {
            if (($field->name ?? '') === $keyColumn) {
                $keyField = $field;
            }
            if (($field->name ?? '') === 'updated_at') {
                $hasUpdatedAt = true;
            }
        }

        $integerTypes = ['int', 'bigint', 'mediumint', 'smallint', 'tinyint'];
        $keyType      = strtolower((string) ($keyField->type ?? ''));
        foreach ($integerTypes as $intType) {
            if (str_contains($keyType, $intType)) {
                error_log("DbSyncSchema: skipping table '$table' - primary key '$keyColumn' is an integer type ($keyType), almost certainly a node-local autoincrement id, not a portable natural key.");

                return null;
            }
        }

        if (! $hasUpdatedAt) {
            error_log("DbSyncSchema: skipping table '$table' - no `updated_at` column (dbSyncGroup requires one for Last-Write-Wins, same as every other synced table).");

            return null;
        }

        return $keyColumn;
    }

    /**
     * The connection $dbSyncGroup's own discovered tables actually live
     * in - deliberately ignores whatever $db a caller passes to
     * exportAllGenericKeys()/exportGenericRow()/applyGenericSnapshot()
     * below and connects here instead, same reasoning and same pattern
     * settingsDb() above already established for the 'settings' table:
     * every caller up the stack (SyncDbCommand, DbSyncController,
     * PullSync) still passes db_connect('default') for historical/
     * users-table reasons, and making every one of those call sites aware
     * of a second, table-dependent connection would be a much larger and
     * more error-prone change than centralizing the redirect in the one
     * place that already knows which table needs which connection.
     */
    private static function genericDb(): ConnectionInterface
    {
        return db_connect(config('Cluster')->dbSyncGroup);
    }

    /**
     * @return list<string> every distinct natural-key value currently in
     *                       this table
     */
    public static function exportAllGenericKeys(ConnectionInterface $db, string $table, string $keyColumn): array
    {
        $rows = self::genericDb()->table($table)->select($keyColumn)->get()->getResultArray();

        return array_values(array_unique(array_map(
            static fn (array $row): string => (string) $row[$keyColumn],
            $rows
        )));
    }

    public static function exportGenericRow(ConnectionInterface $db, string $table, string $keyColumn, string $keyValue): ?array
    {
        $row = self::genericDb()->table($table)->where($keyColumn, $keyValue)->get()->getRowArray();
        if ($row === null) {
            return null;
        }
        // The physical id (if this table has a plain autoincrement PK
        // alongside its own real natural key) is node-local, same
        // reasoning as every other table here - never portable, and
        // applyGenericSnapshot() below always upserts by $keyColumn, never
        // by it.
        unset($row['id']);

        return $row;
    }

    /**
     * @param list<string> $queryLog
     */
    public static function applyGenericSnapshot(ConnectionInterface $db, string $table, string $keyColumn, array $snapshot, array &$queryLog = []): void
    {
        $db = self::genericDb();

        $keyValue = $snapshot[$keyColumn] ?? null;
        if ($keyValue === null) {
            return;
        }

        $existing = $db->table($table)->where($keyColumn, $keyValue)->get()->getRowArray();

        $data = $snapshot;
        if ($existing !== null) {
            // created_at, like every other table here, is this node's own
            // record of when it first learned about the row - never
            // overwritten from an incoming snapshot (same rule
            // applyUserSnapshot()/applySettingSnapshot() already follow).
            unset($data['created_at']);
            $db->table($table)->where($keyColumn, $keyValue)->update($data);
        } else {
            $db->table($table)->insert($data);
        }
        $queryLog[] = $db->showLastQuery();
    }

    /**
     * @param list<string> $values
     *
     * @return list<string>
     */
    private static function sorted(array $values): array
    {
        sort($values);

        return $values;
    }

    /**
     * Number of buckets a table's natural keys are split into for bulk
     * catch-up (see computeBlockHashes()/entitiesInBlock()) - a brand-new
     * node's first sync, or periodic self-healing, compares one hash per
     * block against a peer instead of transferring every row, and only
     * fetches the blocks that actually differ (rsync/Merkle-tree style).
     * Fixed and small on purpose: this project's actual row counts are in
     * the tens, not millions - the win is avoiding a full transfer on a
     * mostly-already-synced catch-up, not sub-linear scan cost.
     */
    public const BLOCK_COUNT = 16;

    public static function blockIndexForKey(string $naturalKey): int
    {
        return crc32($naturalKey) % self::BLOCK_COUNT;
    }

    /**
     * @return array<int, string> blockIndex => hash, one entry per block, always BLOCK_COUNT entries
     */
    public static function computeBlockHashes(ConnectionInterface $db, string $table): array
    {
        $perBlock = self::bucketEntityHashes($db, $table);

        $hashes = [];
        for ($block = 0; $block < self::BLOCK_COUNT; $block++) {
            $pairs = $perBlock[$block] ?? [];
            ksort($pairs);
            $parts = [];
            foreach ($pairs as $naturalKey => $hash) {
                $parts[] = "$naturalKey:$hash";
            }
            $hashes[$block] = md5(implode('|', $parts));
        }

        return $hashes;
    }

    /**
     * Shared by DbSyncController::pullRows() and LongPollController::poll()
     * - every manifest entry recorded (locally or via relay - see
     * DbManifest::record()'s own docblock) strictly after $since, with its
     * current snapshot attached, in the exact wire shape
     * pullDbRows()/applyIncomingCommand() already expect. Filters by
     * `recordedAt` (this node's own "when did I learn this"), not
     * `timestamp` (the row's original updated_at) - same reasoning as
     * Cluster::manifestSince()'s own docblock.
     *
     * @return list<array{table: string, naturalKey: string, timestamp: int, payload: array}>
     */
    public static function collectRowsSince(ConnectionInterface $db, DbManifest $manifest, int $since): array
    {
        $rows = [];
        foreach ($manifest->all() as $manifestKey => $entry) {
            if ((int) ($entry['recordedAt'] ?? $entry['timestamp'] ?? 0) < $since) {
                continue;
            }
            [$table, $naturalKey] = array_pad(explode(':', $manifestKey, 2), 2, '');
            if ($table === '' || $naturalKey === '') {
                continue;
            }

            $exported = self::exportEntity($db, $table, $naturalKey);
            if ($exported === null) {
                continue;
            }

            $rows[] = [
                'table'      => $table,
                'naturalKey' => $naturalKey,
                'timestamp'  => (int) $entry['timestamp'],
                'payload'    => $exported['payload'],
            ];
        }

        return $rows;
    }

    /**
     * @return array{payload: array, timestamp: int}|null the entity's current snapshot plus its own row's updated_at (falls back to now if absent), for block-catch-up transfer
     */
    public static function exportEntity(ConnectionInterface $db, string $table, string $naturalKey): ?array
    {
        if ($table === 'users') {
            $snapshot = self::exportUser($db, $naturalKey);
        } elseif ($table === 'settings') {
            [$class, $key, $context] = array_pad(explode(':', $naturalKey, 3), 3, '');
            $snapshot = self::exportSetting($db, $class, $key, $context);
        } elseif (array_key_exists($table, self::genericTables())) {
            $snapshot = self::exportGenericRow($db, $table, self::genericTables()[$table], $naturalKey);
        } else {
            return null;
        }

        if ($snapshot === null) {
            return null;
        }

        $updatedAt = $snapshot['users']['updated_at'] ?? $snapshot['updated_at'] ?? null;
        $timestamp = $updatedAt !== null ? strtotime((string) $updatedAt) : false;

        return ['payload' => $snapshot, 'timestamp' => $timestamp !== false ? $timestamp : time()];
    }

    /**
     * @return list<string> natural keys currently in the given block
     */
    public static function naturalKeysInBlock(ConnectionInterface $db, string $table, int $block): array
    {
        $perBlock = self::bucketEntityHashes($db, $table);

        return array_keys($perBlock[$block] ?? []);
    }

    /**
     * @return array<int, array<string, string>> blockIndex => [naturalKey => entityHash]
     */
    private static function bucketEntityHashes(ConnectionInterface $db, string $table): array
    {
        $perBlock = [];

        if ($table === 'users') {
            foreach (self::exportAllUserEmails($db) as $email) {
                $snapshot = self::exportUser($db, $email);
                if ($snapshot === null) {
                    continue;
                }
                $perBlock[self::blockIndexForKey($email)][$email] = self::hashUserSnapshot($snapshot);
            }
        } elseif ($table === 'settings') {
            foreach (self::exportAllSettingIds($db) as $id) {
                $key      = $id['class'] . ':' . $id['key'] . ':' . $id['context'];
                $snapshot = self::exportSetting($db, (string) $id['class'], (string) $id['key'], (string) $id['context']);
                if ($snapshot === null) {
                    continue;
                }
                $perBlock[self::blockIndexForKey($key)][$key] = self::hashSettingSnapshot($snapshot);
            }
        } elseif (array_key_exists($table, self::genericTables())) {
            $keyColumn = self::genericTables()[$table];
            foreach (self::exportAllGenericKeys($db, $table, $keyColumn) as $keyValue) {
                $snapshot = self::exportGenericRow($db, $table, $keyColumn, $keyValue);
                if ($snapshot === null) {
                    continue;
                }
                $perBlock[self::blockIndexForKey($keyValue)][$keyValue] = self::hashSettingSnapshot($snapshot);
            }
        }

        return $perBlock;
    }

    /**
     * Applies one incoming write command (from either the push receiver
     * or a pull) - shared by both, so there is exactly one place row-level
     * LWW is decided. Positive timestamps only; ties go to incoming (same
     * convention as file conflict resolution's own tie-break).
     *
     * @param array{table: string, naturalKey: string, operation: string, payload: array, timestamp: int} $command
     *
     * @return array{applied: bool, reason?: string}
     */
    /**
     * @param string $direction 'push-in' (Controllers\DbSyncController::receive()),
     *                          'pull' (Commands\PullCommand::pullDbRows()/
     *                          Commands\SyncDbCommand's --bootstrap) - just a
     *                          label for the Dashboard's activity log, no
     *                          behavioral difference between them here
     */
    public static function applyIncomingCommand(ConnectionInterface $db, DbManifest $manifest, array $command, string $direction = 'push-in', string $peer = ''): array
    {
        $table      = (string) ($command['table'] ?? '');
        $naturalKey = (string) ($command['naturalKey'] ?? '');
        $timestamp  = (int) ($command['timestamp'] ?? 0);
        $payload    = (array) ($command['payload'] ?? []);
        $operation  = (string) ($command['operation'] ?? 'upsert');

        if ($table === '' || $naturalKey === '') {
            return ['applied' => false, 'reason' => 'missing table/naturalKey'];
        }

        $manifestKey = "$table:$naturalKey";
        $known       = $manifest->get($manifestKey);

        if ($known !== null && $timestamp < (int) $known['timestamp']) {
            return ['applied' => false, 'reason' => 'stale'];
        }

        $queryLog = [];

        try {
            $generic = self::genericTables();
            if ($table === 'users') {
                self::applyUserSnapshot($db, $payload, $queryLog);
                $hash = self::hashUserSnapshot($payload);
            } elseif ($table === 'settings') {
                self::applySettingSnapshot($db, $payload, $queryLog);
                $hash = self::hashSettingSnapshot($payload);
            } elseif (array_key_exists($table, $generic)) {
                self::applyGenericSnapshot($db, $table, $generic[$table], $payload, $queryLog);
                $hash = self::hashSettingSnapshot($payload);
            } else {
                return ['applied' => false, 'reason' => 'unknown table'];
            }
        } catch (\Throwable $e) {
            (new DbSyncLog())->record([
                'time'       => time(),
                'direction'  => $direction,
                'peer'       => $peer,
                'table'      => $table,
                'naturalKey' => $naturalKey,
                'operation'  => $operation,
                'ok'         => false,
                'error'      => $e->getMessage(),
                'queries'    => $queryLog,
            ]);

            throw $e; // unchanged behavior - the caller's own retry logic (queue, or a 500 to the pusher) still applies
        }

        $manifest->record($manifestKey, ['hash' => $hash, 'timestamp' => $timestamp]);

        (new DbSyncLog())->record([
            'time'       => time(),
            'direction'  => $direction,
            'peer'       => $peer,
            'table'      => $table,
            'naturalKey' => $naturalKey,
            'operation'  => $operation,
            'ok'         => true,
            'error'      => null,
            'queries'    => $queryLog,
        ]);

        return ['applied' => true];
    }
}

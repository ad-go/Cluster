<?php

declare(strict_types=1);

namespace AdGo\Cluster\Config;

use CodeIgniter\Config\BaseConfig;

/**
 * Published into the consuming app as app/Config/Cluster.php (extend this
 * class there, same convention codeigniter4/settings and codeigniter4/queue
 * use), or used as-is if the app never publishes its own copy.
 */
class Cluster extends BaseConfig
{
    /**
     * This node's own name, as it appears as a KEY in every peer's $nodes.
     * .env: cluster.thisNode
     */
    public string $thisNode = '';

    /**
     * Shared secret every node's Authorization: Bearer header must match -
     * identical on every node, same idea as auth.jwtSecret already is for
     * this cluster's user sessions.
     * .env: cluster.secretToken
     */
    public string $secretToken = '';

    /**
     * Peer nodes, keyed by name. Populated from cluster.nodes in .env (see
     * nodesFromEnv()) - BaseConfig's normal .env auto-override only ever
     * recurses into an array property's EXISTING keys, so it can't populate
     * a genuinely dynamic node list like this one; CI4install.php hit the
     * identical problem with Config\App::$proxyIPs.
     *
     * 'type' is 'public' (has a real HTTPS base URL, reachable directly) or
     * 'nat' (behind a firewall, only ever Pulls - not implemented yet, see
     * README "Not built yet"). 'publicKey' is that peer's RSA public key
     * (see $signingPrivateKey below) - '' for a peer whose registry entry
     * hasn't been upgraded to the 4-segment form yet.
     *
     * @var array<string, array{baseURL: string, type: string, publicKey: string}>
     */
    public array $nodes = [];

    /**
     * This node's OWN RSA private key (2048-bit, base64 of its PEM
     * export) - signs every outgoing peer-to-peer request (see
     * Cluster::authHeader()). Every OTHER node verifies that signature
     * against the matching entry's 'publicKey' in ITS OWN $nodes, not
     * against anything this node sends alongside the signature itself.
     *
     * Added 2026-08-19 to close the "shared-secret blast radius" gap
     * this package's own README used to describe: a single
     * $secretToken, identical on every node, meant leaking any ONE
     * node's .env compromised every node's ability to authenticate as
     * every OTHER node too - a real concern in THIS project's full-mesh
     * topology specifically, since verifying an incoming call from any
     * peer required already holding that same one global value. Per-node
     * asymmetric keys fix this the way the original hardening writeup
     * described: leaking this node's private key only ever lets an
     * attacker impersonate THIS node, never any other - every other
     * node's own key is never present here at all, only their public
     * halves (harmless to leak by design).
     *
     * RSA-2048/SHA256 (openssl_sign()/openssl_verify()), not Ed25519 -
     * found live 2026-08-19 that beta's shared-hosting PHP build has
     * neither the sodium extension nor OpenSSL Ed25519 curve support,
     * while plain RSA keygen/sign/verify worked everywhere tested
     * (h1q/bak/res/beta/upz) - portability across every node this
     * package actually needs to run on mattered more here than Ed25519's
     * smaller keys/signatures.
     *
     * '' (unset) means this node can't sign at all - every outgoing call
     * falls back to the legacy Authorization: Bearer $secretToken scheme
     * (see Cluster::authHeader()), and ClusterAuthFilter accepts that
     * from a peer with no publicKey on file for the same reason. This is
     * a rollout safety net, not a permanent second path - once every
     * node in $nodes carries a real publicKey, $secretToken stops being
     * sufficient on its own to authenticate as anyone.
     * .env: cluster.signingPrivateKey
     */
    public string $signingPrivateKey = '';

    /**
     * Paths kept in sync, relative to WRITEPATH. Defaults to writable/share/
     * - the directory CI4install.php's own install already creates on
     * every node for exactly this purpose (see ARCHITECTURE_REALISTIC.md),
     * not a new one this package invents. An array so more can be added
     * later without a breaking config change.
     * .env: cluster.syncPaths (comma-separated)
     */
    public array $syncPaths = ['share'];

    /**
     * Where this package keeps its own state (manifest of known file
     * hashes, per the spec: "Cluster va stoca datele interne in
     * WRITABLE/Cluster/ in fisiere json"). Relative to WRITEPATH.
     */
    public string $stateDir = 'Cluster';

    /**
     * Queue name jobs are pushed to (see Config\Queue::$jobHandlers -
     * consuming app must map 'cluster-push-file' to
     * AdGo\Cluster\Jobs\PushFileJob::class there; this package can't edit
     * that array itself).
     */
    public string $queueName = 'cluster-files';

    /**
     * How far back (in seconds) PullCommand's cluster:pull asks each peer
     * for "what's changed" on every run. A ROLLING WINDOW, not a per-peer
     * cursor - deliberately: a cursor file would need the same flock()/
     * cross-user-write care as every other state file here (see
     * SyncState's docblock on that class of bug), just to buy something a
     * wide-enough window already gives for free. cluster:pull is scheduled
     * ->everyMinute() (same as sync-files/queue:work), so the default here
     * (180s = 3x that cadence) tolerates up to two consecutive missed runs
     * with no gap, at the cost of re-asking about a few extra seconds of
     * already-seen state on every normal run - cheap, since the answer is
     * "nothing new" for anything already pulled (the SAME "newer wins"/
     * hash-compare merge these values already use makes a repeat answer a
     * safe no-op, not a duplicate).
     * .env: cluster.pullLookbackSeconds
     */
    public int $pullLookbackSeconds = 180;

    /**
     * How long (in seconds) ONE cluster:pull invocation keeps re-checking
     * every peer internally before it actually exits, instead of doing a
     * single pass and stopping. `0` (the default) preserves the original
     * one-pass-then-exit behavior exactly - nothing changes for a node
     * that doesn't set this.
     *
     * Why this exists: cron itself only ever fires cluster:pull once a
     * minute (codeigniter4/tasks has no finer built-in schedule, and many
     * hosting-panel cron UIs cap at one-minute granularity too, with no
     * SSH to add staggered entries around that). But nothing stops the
     * ONE process that single tick starts from staying alive and
     * re-checking every Config\Cluster::$pullLoopIntervalSeconds on its
     * own before exiting - cutting worst-case reaction time from ~60s
     * down to roughly that interval, for ANY node, without SSH, a
     * persistent daemon, or a more flexible cron. Each recheck is a
     * normal short request/response (see PullController) - unlike a real
     * long-poll endpoint, this never holds a connection open, so it costs
     * the SERVER side nothing extra either.
     *
     * Keep this comfortably under 60s (the default cron cadence) so a
     * slow final pass still finishes before the next tick fires -
     * PullCommand stops looping once fewer than
     * $pullLoopIntervalSeconds remain, not right at the limit itself, but
     * a CLI SAPI's own script timeout still varies by host (CLI's
     * max_execution_time defaults to unlimited, unlike the web SAPI, but
     * some shared hosts impose their own watchdog on cron-triggered
     * scripts regardless) - verify a given host tolerates the value
     * before relying on it there.
     * .env: cluster.pullLoopSeconds
     */
    public int $pullLoopSeconds = 0;

    /**
     * How often (in seconds), within one cluster:pull loop, each recheck
     * happens - see $pullLoopSeconds above. Irrelevant while that's 0.
     * .env: cluster.pullLoopIntervalSeconds
     */
    public int $pullLoopIntervalSeconds = 5;

    /**
     * How long (in seconds) a cross-node SSO handoff ticket stays
     * redeemable (see SsoTicketStore/SsoController) - just long enough for
     * a browser redirect round trip, deliberately short: unlike the
     * Dashboard's own display JWT (TTL matches the whole session, ~2h),
     * this value ends up in a URL query string a browser/proxy/access log
     * can see, so it's kept to barely more than one HTTP round trip needs,
     * and single-use regardless (see SsoTicketStore::consume()).
     * .env: cluster.ssoTicketTtlSeconds
     */
    public int $ssoTicketTtlSeconds = 60;

    /**
     * Master on/off switch for this node's file replication - scanning,
     * pushing, pulling, AND receiving/serving (a peer pushing a file IN,
     * or pulling one out, both get a 503 while this is false; see
     * FileReceiverController/PullController). Deliberately a per-node
     * .env flag, not a Settings-panel toggle: SessionInvalidationFilter's
     * session-sync counterpart runs on every single request, and a DB
     * read there on every page load is real overhead a once-per-process
     * .env value doesn't have - and unlike Settings, a plain .env edit
     * takes effect on the very next request, no cache to clear.
     * .env: cluster.fileSyncEnabled
     */
    public bool $fileSyncEnabled = true;

    /**
     * Master on/off switch for this node's password-change session
     * invalidation - broadcasting, pulling, receiving, AND the filter
     * that actually kills a session (SessionInvalidationFilter no-ops
     * entirely while this is false, even if invalidations.json already
     * has entries from before it was turned off). Same .env-not-Settings
     * reasoning as $fileSyncEnabled above.
     * .env: cluster.sessionSyncEnabled
     */
    public bool $sessionSyncEnabled = true;

    /**
     * A whole EXTRA connection group to sync wholesale, beyond users/
     * settings - which need bespoke handling (users spans 5 tables as one
     * snapshot; settings has its own composite class+key+context key) and
     * stay hardcoded in DbSyncSchema regardless of this setting. Every
     * OTHER table in this group gets discovered automatically (see
     * DbSyncSchema::genericTables()) - no per-table config, unlike this
     * property's predecessor (see the removal note below). Additive by
     * design, per an explicit 2026-08-19 requirement: nothing this
     * package already syncs (users/settings, or any table this discovery
     * already found on a previous run) is ever dropped because of what
     * this property does or doesn't contain - it only ever adds tables to
     * what gets synced, never removes any.
     *
     * Auto-discovery's own requirements, checked per table (see
     * DbSyncSchema::genericTables() for exactly how): a SINGLE-column
     * primary key whose SQL type is NOT an integer type (int/bigint/
     * mediumint/smallint/tinyint) - an autoincrement id is node-local and
     * meaningless across nodes for the SAME logical row (two nodes would
     * each mint a different one for "the same" insert), so a table whose
     * only identifying column is one of those is skipped, not guessed at.
     * A normal `updated_at` column is also required, for the same
     * Last-Write-Wins reasoning $dbExcludeTables's predecessor already
     * needed one for. A table failing either check is skipped with a
     * clear log entry (error_log), never a hard failure and never
     * silently included with the wrong key - this package's standing
     * "report rather than guess" rule (see cluster:realign's own
     * orphaned-file reporting for the same philosophy elsewhere).
     *
     * '' (the default) disables this entirely - genericTables() returns
     * only whatever's already synced with no group-wide discovery at all,
     * so a node that never sets this behaves exactly as before this
     * feature existed.
     *
     * REMOVED 2026-08-19: this property used to be $dbSyncTables, an
     * array<string, string> of table => explicit natural-key column
     * (.env: cluster.dbSyncTables = "products:sku,invoices:invoice_number"),
     * requiring one .env line PER extra table. Confirmed unused on every
     * live node before removal (grepped every deployed .env - none had it
     * set), so this is a clean repurpose, not a breaking change to
     * anything actually running. Whole-group discovery replaces it
     * entirely rather than living alongside it - one mechanism for "sync
     * more than users/settings", not two.
     *
     * .env: cluster.dbSyncGroup = production
     */
    public string $dbSyncGroup = '';

    /**
     * Tables to leave OUT of $dbSyncGroup's auto-discovery - the
     * counterpart to it, not to anything else. Only ever removes a
     * CANDIDATE table $dbSyncGroup's own discovery would otherwise have
     * picked up; it has no power over users/settings or any table this
     * discovery already found and started syncing on some earlier run -
     * per the same additive requirement $dbSyncGroup's own docblock
     * describes, this can shrink tomorrow's candidate list, never revoke
     * sync from something already syncing today.
     *
     * @var list<string>
     *
     * .env: cluster.dbExcludeTables = "sessions,cache,audit_log"
     */
    public array $dbExcludeTables = [];

    public function __construct()
    {
        parent::__construct();

        if ($this->nodes === []) {
            $this->nodes = $this->nodesFromEnv();
        }

        $syncPaths = env('cluster.syncPaths');
        if (is_string($syncPaths) && trim($syncPaths) !== '') {
            $this->syncPaths = array_values(array_filter(array_map('trim', explode(',', $syncPaths))));
        }

        if ($this->dbSyncGroup === '') {
            $group = env('cluster.dbSyncGroup');
            $this->dbSyncGroup = is_string($group) ? trim($group) : '';
        }

        if ($this->dbExcludeTables === []) {
            $this->dbExcludeTables = $this->dbExcludeTablesFromEnv();
        }
    }

    // cluster.dbExcludeTables = "sessions,cache,audit_log" - same
    // "BaseConfig's .env auto-override can't populate a genuinely dynamic
    // array key set" problem nodesFromEnv() below already has, same fix.
    private function dbExcludeTablesFromEnv(): array
    {
        $raw = env('cluster.dbExcludeTables');
        if (! is_string($raw) || trim($raw) === '') {
            return [];
        }

        return array_values(array_filter(array_map('trim', explode(',', $raw))));
    }

    // cluster.nodes = "beta|https://beta.romania-fulfillment.ro/|public,upz|https://beta.upz.ro/|public"
    // name|baseURL|type[|publicKey] - a 4th, optional segment added
    // 2026-08-19 (see $signingPrivateKey above): that peer's RSA public
    // key, base64 of its PEM export. Omitted (3-segment entry, unchanged
    // from before this existed) means Cluster::verifyAuthHeader() can
    // only fall back to the legacy shared-secret check for that peer.
    private function nodesFromEnv(): array
    {
        $raw = env('cluster.nodes');
        if (! is_string($raw) || trim($raw) === '') {
            return [];
        }

        $nodes = [];
        foreach (explode(',', $raw) as $entry) {
            $parts = array_map('trim', explode('|', $entry));
            if (count($parts) < 2 || $parts[0] === '' || $parts[1] === '') {
                continue;
            }
            [$name, $baseUrl] = $parts;
            $type      = $parts[2] ?? 'public';
            $publicKey = $parts[3] ?? '';
            $nodes[$name] = ['baseURL' => rtrim($baseUrl, '/') . '/', 'type' => $type, 'publicKey' => $publicKey];
        }

        return $nodes;
    }
}

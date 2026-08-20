<?php

declare(strict_types=1);

namespace AdGo\Cluster;

/**
 * The ONE place every "run a capability check" call funnels through,
 * whatever kind of check it is and wherever it's actually executing -
 * this node testing itself, RemoteTestController::testConnection()
 * running a check for a PUBLIC peer that asked over a signed HTTPS call,
 * or PullSync::pullTestRequests() running a check a NAT node claimed
 * during its own pull cycle. All three call sites used to independently
 * hardcode their own `if ($kind === 'database') ... elseif ($kind ===
 * 'node') ...` branch - found live 2026-08-19 doing the actual count: the
 * exact same two-way branch, written three times, in three different
 * files, that would all need editing in lockstep every time a capability
 * was added or changed. This class is that one edit point instead.
 *
 * Every registered checker exposes the SAME `checkParams(array $params):
 * array` shape (see DbConnectionChecker/NodeConnectionChecker/
 * CronConnectionChecker's own docblocks) - raw parameters that arrived
 * either from this node's own Settings lookup (SettingsController::
 * runLocalTest()) or literally over the wire from another node
 * (RemoteTestController/PullSync), never a second Settings lookup on the
 * executing side. That's what makes a single untyped `array $params`
 * dispatch safe here: every checker already treats "params" as arbitrary
 * external input, whether they arrived from this process's own Settings
 * or a signed HTTP body.
 *
 * Adding a new capability later ("etc." - more protocols are explicitly
 * expected, see this class's own commit message) means ONE new line in
 * CHECKERS below and a new checker class with a matching checkParams() -
 * nothing in RemoteTestController, PullSync, or SettingsController needs
 * to change to pick it up.
 */
class CapabilityChecker
{
    private const CHECKERS = [
        'database' => DbConnectionChecker::class,
        'node'     => NodeConnectionChecker::class,
        'cron'     => CronConnectionChecker::class,
    ];

    /**
     * @param array<string, mixed> $params
     *
     * @return array{ok: bool, ms: float, error?: string}
     */
    public function run(string $kind, array $params): array
    {
        $checkerClass = self::CHECKERS[$kind] ?? null;
        if ($checkerClass === null) {
            return ['ok' => false, 'error' => "Unknown capability kind '{$kind}'.", 'ms' => 0.0];
        }

        return (new $checkerClass())->checkParams($params);
    }

    /**
     * @return list<string> registered kind names, e.g. for a future
     *                      "what can this node even test" UI affordance
     */
    public function kinds(): array
    {
        return array_keys(self::CHECKERS);
    }
}

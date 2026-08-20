# Cluster

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Unofficial package](https://img.shields.io/badge/status-unofficial-orange.svg)](#)

Multi-master file, session, and database replication for CodeIgniter 4 — keeps a set of
nodes in sync over plain HTTPS, with no shared database and no shared session store.

*Unofficial — not affiliated with, or endorsed by, the CodeIgniter Foundation.*

## Features

- **File replication** — creates, changes, and deletes propagate to every peer within a
  minute, with drift-corrected Last-Write-Wins conflict resolution and no content silently lost
- **Session invalidation** — a password change, logout, account deletion, or ban kills that
  user's sessions cluster-wide, keyed by email since every node has its own Shield database
- **NAT-friendly pulling** — `cluster:pull` closes the gap for nodes that can't be pushed to,
  with an optional faster-than-cron reaction loop
- **Cross-node SSO** — a short-lived, single-use ticket handoff, no shared signing secret
- **Clock drift correction** — measured per peer and applied at transfer time, so conflict
  resolution isn't fooled by a few seconds of skew
- **Database sync** — accounts, groups, permissions, and settings, incremental plus a bulk
  block-hash catch-up mode for a new or long-offline node; point one `.env` line at a whole
  extra connection group and every table in it with a real natural key joins automatically,
  additively — nothing already syncing is ever dropped
- **Live realignment** — `cluster:realign` fully reconciles a node against every peer after an
  extended outage, beyond `cluster:pull`'s normal rolling window
- **Per-node signed authentication** — every peer-to-peer request is signed with that node's
  own RSA key, not a single value shared cluster-wide
- **SSH connectivity checks** — a real login-and-exec probe (via
  [phpseclib](https://github.com/phpseclib/phpseclib), not the rarely-available `ssh2`
  extension) against every node with SSH credentials on file, right after login and every minute
- **On-demand capability tests, NAT-safe** — `CapabilityChecker` is the single dispatch point
  every "does this connection actually work" check funnels through (database, FTP/FTPS/SSH/SCP
  deploy access), one registry entry per capability so adding another later
  never touches the call sites. Works even for a node with no public URL: the request relays
  through that node's own next `cluster:pull` cycle rather than needing to be reachable directly
  — see [ad-go/cluster-ui](https://github.com/ad-go/cluster-ui)'s Settings → Nodes/Databases
  test badges, the only current callers.
- **Dashboard-ready summaries** — `Cluster::networkSummary()`/`tableStats()` feed
  [ad-go/cluster-ui](https://github.com/ad-go/cluster-ui)'s network graph and table sunburst

See this package's own `src/` (each class/method's docblock is the authoritative reference)
for how each of these actually works under the hood — the in-app docs page this section used
to link to was removed from `ad-go/cluster-ui` 2026-08-20.

## Getting started

### Prerequisites

- A CodeIgniter 4 app
- [Tasks](https://github.com/codeigniter4/tasks) — needed to schedule `cluster:pull`/
  `cluster:long-poll`/`cluster:ssh-check`/`cluster:sync-db`/`cluster:time-drift`, all cron-triggered
- [Queue](https://github.com/codeigniter4/queue) — needed for the async push jobs (file pushes,
  DB row broadcasts, session-invalidation broadcasts, SSH connectivity checks) `queue:work` processes
- [Shield](https://github.com/codeigniter4/shield) — needed for session-based invalidation and
  the SSO handoff's session-authenticated leg

### Installation

This package **requires** [ad-go/cluster-ui](https://github.com/ad-go/cluster-ui) — not just a
suggestion. The SSH connectivity check reads node credentials from the Settings → Nodes table,
and cluster-ui's UI is the only thing that ever writes them; installing the mechanism layer
without a way to configure it isn't useful on its own. cluster-ui itself ships a **Composer
plugin**, not just plain PHP classes — it copies its own `app/` and `public/assets/` straight
into your project root and runs `php spark migrate` on every `composer install`/`update` that
touches it (see its own README for why a plugin, not a `composer.json` script, is what a
dependency needs for this). Composer 2.2+ will refuse to run a new dependency's plugin until
you say you trust it — the exact commands below handle that up front.

**Neither package is on Packagist** — both need a repository entry pointing at GitHub:

```console
composer config repositories.ad-go-cluster git https://github.com/ad-go/cluster.git
composer config repositories.ad-go-cluster-ui git https://github.com/ad-go/cluster-ui.git
composer config allow-plugins.ad-go/cluster-ui true
composer config minimum-stability dev
composer config prefer-stable true
composer require ad-go/cluster:@dev
```

**`"type": "git"`, not `"type": "vcs"`** — found live 2026-08-20, from-scratch-installing on
several different hosts in the same day: `"vcs"` hands resolution to Composer's
`GitHubDriver`, which talks to `api.github.com` to build a dist-zip URL — fine normally, but
that API is rate-limited to 60 unauthenticated requests/hour *per source IP*, trivially
exhausted by repeated reinstalls of a project this size. Once exhausted, `GitHubDriver` can't
build a dist URL and falls back to a `git clone git@github.com:...` (SSH) source install —
which then fails outright on any host with no SSH key configured for GitHub, `git` itself
missing, or both (all three encountered live). Plain `"git"` skips `GitHubDriver` and the API
entirely: a bare `git clone` of the exact HTTPS URL given, every time, no rate limit, no
protocol-switching surprises. (Needs a real `git` binary on the installing host either way —
`apt-get install git`/equivalent if it's missing, as it was on one node tested.)

**`minimum-stability`/`prefer-stable` project-wide, not `ad-go/cluster-ui:@dev` tacked onto
the `require` line** — the more "obvious" fix backfires: `@dev` on a *root*-required package
doesn't propagate its dev-stability exemption down to a package only ever pulled in
*transitively* (`ad-go/cluster`'s own `composer.json` requires `ad-go/cluster-ui`, not this
project's root one), so `ad-go/cluster:@dev` alone genuinely does fail with "`ad-go/cluster-ui
dev-main ... does not match your minimum-stability`" — but adding `ad-go/cluster-ui:@dev`
explicitly to fix that, tested live the same day, makes it a *root* requirement too, which
pushed Composer onto the git-clone-over-SSH path above even with `"type": "git"` repositories
in one specific configuration tried. The two `composer config` lines above lift the stability
floor cluster-wide (with `prefer-stable` still preferring a tagged release over a dev branch
for any *other* package that has one) without ever making `ad-go/cluster-ui` a root
requirement, leaving its resolution exactly as transitive-only as it always was. This also
pulls in [phpseclib](https://github.com/phpseclib/phpseclib) (for the SSH check) and cluster-ui's
own dependencies (whose plugin copies its UI into place and migrates automatically, per above).

Neither package is on Packagist yet, which is the real remaining friction here — publishing both
(free, GitHub-webhook-synced) would drop the two `composer config repositories...` lines
entirely and let plain `composer require ad-go/cluster` resolve the transitive `ad-go/cluster-ui`
requirement the normal way, the same as any two ordinary Packagist packages. Not done as of this
writing.

**From an archive**, if you'd rather not use Composer at all: download this repo as a zip (or a
release), extract it into `vendor/ad-go/cluster/` by hand, **and** do the same for
[ad-go/cluster-ui](https://github.com/ad-go/cluster-ui)'s own archive per its README — its
Composer plugin only runs on an actual `composer install`/`update`, so installing from a plain
archive means copying its `app/`/`public/assets/` into your project root yourself and running
`php spark migrate`, exactly as its own "From an archive" instructions describe. You'll also
need [phpseclib/phpseclib](https://github.com/phpseclib/phpseclib) (plus its own
`paragonie/constant_time_encoding` dependency) available on your autoload path some other way -
the Composer route above is meaningfully simpler for that reason alone.

Neither package auto-registers routes, filters, or scheduler entries into your app — wire up
`Routes.php`, `Filters.php`, `Queue.php`'s job handlers, the scheduler, and `.env`, then call
`Cluster::broadcast*()` wherever a password changes, a user logs out, or an account is
deleted/banned. See `RouteRegistrar::register()`/`Config\Cluster`'s own docblocks for the
exact wiring, or `cluster_install.php`'s `patchFiltersSecurity()`/`patchQueueJobHandlers()`/
`patchTasksSchedule()` for a working reference implementation.

## Not built yet

- Nothing tracked here right now — residual edge cases each feature above still has (e.g. a
  deletion older than the tombstone retention window surviving an extended outage) are
  documented at each relevant class/method's own docblock instead of a separate page

## License

MIT — see [LICENSE](LICENSE).

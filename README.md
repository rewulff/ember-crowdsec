# ember-crowdsec

CrowdSec Bouncer Tab plugin for [alexandre-daubois/ember](https://github.com/alexandre-daubois/ember) (Caddy TUI). Live decisions + alerts pulled from a local CrowdSec LAPI, with a hotkey to **unban** an IP directly from the TUI. Every write action is journalled to a per-host audit log.

> The plugin is **not read-only** — `d` deletes a decision after a confirm dialog with the offending IP and scenario in the prompt. See "Killer feature" below. (A `w`-hotkey for whitelisting existed in v0.1.x and was removed in v0.2.0 — it was structurally broken; allow-functionality belongs in Engine postoverflow allowlists, see "Whitelisting: use Engine-Allowlists" below.)

## Status

MVP. Pinned to `ember v1.3.0` because the plugin API is marked EXPERIMENTAL upstream.

## Architecture

- One Caddy host = one LAPI = one `ember-custom` binary running on the same LXC. The plugin connects to LAPI via `localhost` (this is by design — the LAPI is not exposed externally).
- **Auth split**: read decisions via the bouncer **X-Api-Key** (LAPI rejects JWT on `/v1/decisions` with 401 "token rejected twice"); read alerts and run delete actions via the machine-account **JWT**. Verified against `crowdsecurity/crowdsec/pkg/apiserver/controllers/controller.go` lines 113-145, plus a smoke against CT 122 on 2026-05-07.
- Fetch: tick-based polling. Decisions and alerts run in parallel goroutines on each tick.
- Render: Bubble Tea / lipgloss. Decisions sorted by remaining TTL desc, alerts by created_at desc, header + per-section badges, status-count badge in the tab-bar.

## Pre-requisite

You need a working Caddy + CrowdSec stack on the host the plugin will run on. If you already have that running, skip ahead. If you don't: a complete setup guide (custom xcaddy build, CrowdSec install, bouncer wiring, hardening, common pitfalls) lives in [`docs/CADDY-CROWDSEC-SETUP.md`](docs/CADDY-CROWDSEC-SETUP.md). Setup time end-to-end is ~2-4 hours.

## Setup

> **Security caveat — read first.** This plugin sends `MACHINE_PASSWORD` and `BOUNCER_KEY` over plaintext HTTP whenever the configured LAPI URL starts with `http://`. It is therefore designed for **localhost-only** LAPI access (`http://127.0.0.1:8080`). Never combine `EMBER_PLUGIN_CROWDSEC_LAPI_URL=http://<remote-host>` with `EMBER_PLUGIN_CROWDSEC_INSECURE_TLS=true` — that combination, or a plaintext HTTP URL pointing off-host, leaks both credentials over the wire on every fetch and every login refresh. If you really need a remote LAPI, terminate it through a TLS-aware tunnel (Wireguard, NetBird, SSH local-forward) so the plugin still talks `http://127.0.0.1:<port>` but the bytes leave the box encrypted.

### 1. Provision two credentials on the LAPI host

```sh
# On the LXC running CrowdSec:

# Machine account — drives JWT for alerts + delete:
cscli machines add ember-tui --auto -f -

# Bouncer credential — drives X-Api-Key for /v1/decisions:
cscli bouncers add ember-tui-bouncer
```

`--auto -f -` on `machines add` writes credentials to stdout and overwrites without prompting (`--auto` would otherwise refuse if `/etc/crowdsec/local_api_credentials.yaml` already exists). Note both the machine password and the bouncer key — both are required by the plugin.

### 2. Build the custom Ember binary

```sh
git clone https://github.com/rewulff/ember-crowdsec.git
cd ember-crowdsec
go build -o ember-custom ./cmd/ember-custom
```

The output binary is a full Ember TUI with the CrowdSec plugin compiled in (Go's blank-import pattern, same approach Caddy itself uses for plugins).

Or, in one step without a manual clone:

```sh
go install github.com/rewulff/ember-crowdsec/cmd/ember-custom@v0.1.0
```

The binary lands in `$(go env GOBIN)` (or `$(go env GOPATH)/bin` if `GOBIN` is unset).

> **Which tag to install?** `@v0.1.0` is the supported stock-pinned release that works with Ember `v1.3.0` out of the box. The `main` branch is rolling and assumes upstream Ember PRs that haven't landed yet (`go install ...@main` builds, but the new UX features are no-ops until a future Ember release ships them). See [`ROADMAP.md`](ROADMAP.md) for v0.1.0 → v0.2.0 migration. v0.2.0 removed the `w` (whitelist) hotkey — see "Whitelisting: use Engine-Allowlists" below.

### 3. Run with environment configuration

```sh
EMBER_PLUGIN_CROWDSEC_LAPI_URL=http://127.0.0.1:8080 \
EMBER_PLUGIN_CROWDSEC_MACHINE_ID=ember-tui \
EMBER_PLUGIN_CROWDSEC_MACHINE_PASSWORD='...' \
EMBER_PLUGIN_CROWDSEC_BOUNCER_KEY='...' \
./ember-custom --addr http://127.0.0.1:2019
```

`--addr` is the standard Ember flag pointing at the Caddy admin endpoint.

### Production layout (recommended on the LAPI host)

For a permanent install on the Caddy/LAPI host the inline-env quickstart above is fine for a one-shot try, but it puts the credentials on the shell history and the audit log under `/root/`. Use FHS-ish paths instead:

```
/usr/local/bin/ember-custom            # the binary
/usr/local/bin/ember-crowdsec          # convenience wrapper, loads env then exec's the binary
/etc/ember-crowdsec/env                # mode 0600, owned by root
/var/log/ember-crowdsec/               # mode 0700
/var/log/ember-crowdsec/audit.log      # mode 0600, written by the plugin
```

`/etc/ember-crowdsec/env` is a plain `KEY=VALUE` file (no `export`) sourced by the wrapper:

```sh
EMBER_PLUGIN_CROWDSEC_LAPI_URL=http://127.0.0.1:8080
EMBER_PLUGIN_CROWDSEC_MACHINE_ID=ember-tui
EMBER_PLUGIN_CROWDSEC_MACHINE_PASSWORD=...
EMBER_PLUGIN_CROWDSEC_BOUNCER_KEY=...
EMBER_PLUGIN_CROWDSEC_ALERTS_SINCE=24h
EMBER_PLUGIN_CROWDSEC_AUDIT_LOG=/var/log/ember-crowdsec/audit.log
```

`/usr/local/bin/ember-crowdsec` is a tiny POSIX-sh wrapper:

```sh
#!/bin/sh
# Convenience wrapper: load /etc/ember-crowdsec/env then exec the binary.
set -a
. /etc/ember-crowdsec/env
set +a
exec /usr/local/bin/ember-custom "$@"
```

Operator entrypoint then becomes one command:

```sh
ember-crowdsec
```

The wrapper keeps the plugin a TUI (no systemd/openrc service) — it requires a TTY and is started ad-hoc whenever a human wants to look at the LAPI state.

## Configuration

All env-vars use the prefix `EMBER_PLUGIN_CROWDSEC_` (the plugin name is `crowdsec`). Ember strips the prefix and lowercases the key before passing it via `PluginConfig.Options`.

| Env-var | Required | Default | Notes |
|---|---|---|---|
| `EMBER_PLUGIN_CROWDSEC_LAPI_URL` | yes | — | e.g. `http://127.0.0.1:8080` |
| `EMBER_PLUGIN_CROWDSEC_MACHINE_ID` | yes | — | from `cscli machines add` |
| `EMBER_PLUGIN_CROWDSEC_MACHINE_PASSWORD` | yes | — | from `cscli machines add`. Quote shell-special chars. |
| `EMBER_PLUGIN_CROWDSEC_BOUNCER_KEY` | yes | — | from `cscli bouncers add`. Used for `GET /v1/decisions` only. |
| `EMBER_PLUGIN_CROWDSEC_AUDIT_LOG` | no | `~/.ember-crowdsec-audit.log` | append-only JSON-Lines log, mode 0600. |
| `EMBER_PLUGIN_CROWDSEC_ALERTS_SINCE` | no | `24h` | Go duration string |
| `EMBER_PLUGIN_CROWDSEC_FETCH_INTERVAL` | no | (Ember default) | Validated as duration; tick-rate handled by Ember |
| `EMBER_PLUGIN_CROWDSEC_INSECURE_TLS` | no | `false` | Set `true` if LAPI uses a self-signed cert |

## Killer feature: unban from the TUI

The CrowdSec tab is interactive:

| Key | Mode | Effect |
|---|---|---|
| `↑/↓` (or `j/k`) | normal | Move the decision cursor |
| `c` | normal | Toggle CAPI inclusion (see "Origin filter" below) |
| `d` | normal | Confirm-unban prompt — **only on `crowdsec` / `cscli` decisions** |
| `y / Y` | confirm-unban | Run the unban |
| `n / N / Esc` | confirm-unban | Cancel |

The confirm dialog shows the IP, origin and scenario inline so accidental hits are unlikely. While in confirm-mode the plugin **consumes every keystroke** so that other tabs/global shortcuts don't fire mid-flow.

> **No more `w` (whitelist)?** Correct — removed in v0.2.0 (Forgejo [#13](https://forgejo.routetohome.renewulff.de/formin/ember-crowdsec/issues/13)). The hotkey produced a `type=whitelist` decision via `POST /v1/alerts`, which the Caddy bouncer reads as a block (the existence of any decision is a block marker; see "Whitelisting: use Engine-Allowlists" below). Use Engine-side postoverflow allowlists instead.

### Origin filter (default = your decisions only)

CrowdSec LAPI's `GET /v1/decisions` returns **all** active bans by default — local engine + CAPI Threat Intel feed + community blocklists (firehol, tor, ...). On a busy node this can be 50.000+ rows, which buries the operator-relevant decisions you actually want to see.

The plugin filters server-side by default with `?origins=crowdsec,cscli`, i.e. only:

- **`crowdsec`** — bans your own engine produced from log scenarios
- **`cscli`** — manual `cscli decisions add` entries

Press **`c`** to toggle the filter off — the next fetch then returns the full feed. The header line shows the current state:

```
CrowdSec — 12 decisions, 4 alerts (last fetch 14:23:45, filter: local+manual, c: include CAPI)
```

after pressing `c`:

```
CrowdSec — 50217 decisions, 4 alerts (last fetch 14:23:55, filter: ALL, c: hide CAPI)
```

### Why `d` is blocked on CAPI / list decisions

CAPI and community-list rows live in CrowdSec's central feed. `DELETE /v1/decisions/{id}` succeeds locally on those, but the next CAPI sync re-pulls the same row — the unban is effectively a no-op and the operator sees the ban "come back". The plugin therefore blocks `d` on any non-`crowdsec`/`cscli` origin and shows:

```
Cannot unban CAPI decision (will re-pull). Use an Engine allowlist instead.
```

For genuine allow-functionality on CAPI / list-sourced IPs, edit `/etc/crowdsec/postoverflows/s01-whitelist/<name>.yaml` and `systemctl reload crowdsec` — see "Whitelisting: use Engine-Allowlists" below.

### Audit log

Each unban attempt is journalled — successes **and** failures — to the path in `EMBER_PLUGIN_CROWDSEC_AUDIT_LOG`. Format is JSON-Lines, mode 0600, append-only:

```json
{"ts":"2026-05-07T12:34:56Z","action":"unban","ip":"1.2.3.4","decision_id":12345,"status":"ok"}
{"ts":"2026-05-07T12:36:11Z","action":"unban","ip":"9.9.9.9","decision_id":9999,"status":"error","error":"delete decision 9999: status 500: boom"}
```

If the audit-log file cannot be opened or written, the plugin keeps running but the renderer surfaces `audit log write failed: ...` in its status line so you notice. The journal touches privileged actions — keep the file on a restrictive filesystem and don't sync it off-host without redaction.

## Whitelisting: use Engine-Allowlists, not Decisions

> **Heads-up on the `w` hotkey.** We initially framed this as a bouncer issue — that was wrong. After maintainer feedback on [hslatman/caddy-crowdsec-bouncer#116](https://github.com/hslatman/caddy-crowdsec-bouncer/issues/116) we updated this section. Thanks to @hslatman for the clarification.

`cscli decisions add --type whitelist` is **not an officially supported decision type**. CrowdSec's CLI accepts the string, but the only documented decision types are `ban`, `captcha`, and `throttle` — any bouncer reading from `/v1/decisions` treats the **existence of a decision** as a block marker, regardless of the `type` field. From `hslatman/caddy-crowdsec-bouncer` `internal/core/store.go`:

> the existence of at least a single Decision means that the IP should not be allowed

That is a defensible design choice for a block-list bouncer, not a bug. The TUI's `w` hotkey was therefore structurally unhelpful for real allow-functionality — it produced a `type=whitelist` decision that bouncers see as a block, which on a Caddy host could trigger a `LePresidente/http-generic-403-bf` self-ban loop on the very IP you tried to allow.

**Do this instead.** Allow-functionality in CrowdSec belongs in the Engine via centralized allowlists: <https://docs.crowdsec.net/docs/local_api/centralized_allowlists/>. The on-disk path is `/etc/crowdsec/postoverflows/s01-whitelist/<name>.yaml`; reload with `systemctl reload crowdsec` after edits.

The `w` hotkey was removed in v0.2.0 (see [#13](https://forgejo.routetohome.renewulff.de/formin/ember-crowdsec/issues/13)). For allow-functionality, edit `/etc/crowdsec/postoverflows/s01-whitelist/<name>.yaml` and `systemctl reload crowdsec`.

## Multi-instance support

This plugin is single-instance by design. It assumes a 1:1 mapping between a Caddy instance and its CrowdSec LAPI, with the plugin running on the same host (localhost LAPI). The plugin does **not** opt into Ember's `MultiInstancePlugin` interface — when used with `ember --addr` repeated (multi-instance mode introduced in Ember 1.4.0), Ember will disable the plugin and emit a warning. Use one Ember-plus-plugin process per Caddy/LAPI pair if you need to monitor multiple instances.

## Caveat

LAPI is only reachable from `localhost` on the CrowdSec host by default. This plugin is therefore designed to **run on the same host as the CrowdSec agent** (typically the same LXC that serves Caddy). Cross-host LAPI access requires opening the LAPI port + extra TLS hardening — explicitly out of scope for the MVP.

## Module path

The module path is `github.com/rewulff/ember-crowdsec`. `go install github.com/rewulff/ember-crowdsec/cmd/ember-custom@v0.1.0` builds the custom Ember binary in one step — no clone, no token, no `GOPRIVATE` needed.

## Out of scope (MVP)

- Streaming-endpoint instead of polling
- Recent Bans sub-tab via MultiRenderer
- Prometheus exporter via `Exporter` interface
- Filter/sort via `HandleKey` (IP/origin/scenario)
- Detail-view for alerts
- Bulk operations (multiple IPs unbanned in one keystroke)
- CI / linting

These will land in a follow-up release sprint once the plugin API stabilizes upstream.

## Background

Long-form write-up on the design decisions (CrowdSec's strict bouncer-key/JWT split, the CAPI-versus-local-decisions filter, why the kill-switch on CAPI unbans): [Ember + CrowdSec — Ein TUI-Plugin gegen die 50.000-Decisions-Wand](https://wulffit.de/artikel/ember-crowdsec) (German, 2026-05-08).

## License

MIT — see [LICENSE](LICENSE).

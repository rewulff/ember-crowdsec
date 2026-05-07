# ember-crowdsec

CrowdSec Bouncer Tab plugin for [alexandre-daubois/ember](https://github.com/alexandre-daubois/ember) (Caddy TUI). Live decisions + alerts pulled from a local CrowdSec LAPI, with hotkeys to **unban** and **whitelist** an IP directly from the TUI. Every write action is journalled to a per-host audit log.

> The plugin is **not read-only** — `d` deletes a decision, `w` installs a whitelist entry. Both go through a confirm dialog with the offending IP and scenario in the prompt. See "Killer feature" below.

## Status

MVP. Pinned to `ember v1.3.0` because the plugin API is marked EXPERIMENTAL upstream.

## Architecture

- One Caddy host = one LAPI = one `ember-custom` binary running on the same LXC. The plugin connects to LAPI via `localhost` (this is by design — the LAPI is not exposed externally).
- **Auth split**: read decisions via the bouncer **X-Api-Key** (LAPI rejects JWT on `/v1/decisions` with 401 "token rejected twice"); read alerts and run delete/whitelist actions via the machine-account **JWT**. Verified against `crowdsecurity/crowdsec/pkg/apiserver/controllers/controller.go` lines 113-145, plus a smoke against CT 122 on 2026-05-07.
- Fetch: tick-based polling. Decisions and alerts run in parallel goroutines on each tick.
- Render: Bubble Tea / lipgloss. Decisions sorted by remaining TTL desc, alerts by created_at desc, header + per-section badges, status-count badge in the tab-bar.

## Setup

> **Security caveat — read first.** This plugin sends `MACHINE_PASSWORD` and `BOUNCER_KEY` over plaintext HTTP whenever the configured LAPI URL starts with `http://`. It is therefore designed for **localhost-only** LAPI access (`http://127.0.0.1:8080`). Never combine `EMBER_PLUGIN_CROWDSEC_LAPI_URL=http://<remote-host>` with `EMBER_PLUGIN_CROWDSEC_INSECURE_TLS=true` — that combination, or a plaintext HTTP URL pointing off-host, leaks both credentials over the wire on every fetch and every login refresh. If you really need a remote LAPI, terminate it through a TLS-aware tunnel (Wireguard, NetBird, SSH local-forward) so the plugin still talks `http://127.0.0.1:<port>` but the bytes leave the box encrypted.

### 1. Provision two credentials on the LAPI host

```sh
# On the LXC running CrowdSec:

# Machine account — drives JWT for alerts, delete, whitelist:
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
go install github.com/rewulff/ember-crowdsec/cmd/ember-custom@latest
```

The binary lands in `$(go env GOBIN)` (or `$(go env GOPATH)/bin` if `GOBIN` is unset).

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

## Killer feature: unban + whitelist from the TUI

The CrowdSec tab is interactive:

| Key | Mode | Effect |
|---|---|---|
| `↑/↓` (or `j/k`) | normal | Move the decision cursor |
| `c` | normal | Toggle CAPI inclusion (see "Origin filter" below) |
| `d` | normal | Confirm-unban prompt — **only on `crowdsec` / `cscli` decisions** |
| `w` | normal | Whitelist input flow (duration default `24h`); allowed on all origins |
| `y / Y` | confirm-unban / confirm-whitelist | Run the action |
| `n / N / Esc` | any confirm | Cancel |
| `Enter` | input-duration | Advance to confirm-whitelist |
| printable + `Backspace` | input-duration | Edit the duration buffer |

Every confirm dialog shows the IP, origin and scenario inline so accidental hits are unlikely. While in any non-normal mode the plugin **consumes every keystroke** so that other tabs/global shortcuts don't fire mid-flow.

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
Cannot unban CAPI decision (will re-pull). Use w (whitelist) instead.
```

`w` (whitelist) **is** the right action here — a `type=whitelist` decision beats any ban regardless of origin, including CAPI rows. Whitelist remains allowed on every selected decision.

The whitelist body mirrors what `cscli decisions add --type whitelist` sends: a `POST /v1/alerts` with one alert containing one decision (`type=whitelist`, `origin=ember-tui`). Verified against `crowdsec/cmd/crowdsec-cli/clidecision/decisions.go` `cli.add()` lines 256-388 (master @ 2026-05-07).

### Audit log

Each unban / whitelist attempt is journalled — successes **and** failures — to the path in `EMBER_PLUGIN_CROWDSEC_AUDIT_LOG`. Format is JSON-Lines, mode 0600, append-only:

```json
{"ts":"2026-05-07T12:34:56Z","action":"unban","ip":"1.2.3.4","decision_id":12345,"status":"ok"}
{"ts":"2026-05-07T12:35:08Z","action":"whitelist","ip":"5.6.7.8","duration":"24h","reason":"manual whitelist via ember-tui","status":"ok"}
{"ts":"2026-05-07T12:36:11Z","action":"unban","ip":"9.9.9.9","decision_id":9999,"status":"error","error":"delete decision 9999: status 500: boom"}
```

If the audit-log file cannot be opened or written, the plugin keeps running but the renderer surfaces `audit log write failed: ...` in its status line so you notice. The journal touches privileged actions — keep the file on a restrictive filesystem and don't sync it off-host without redaction.

## Caveat

LAPI is only reachable from `localhost` on the CrowdSec host by default. This plugin is therefore designed to **run on the same host as the CrowdSec agent** (typically the same LXC that serves Caddy). Cross-host LAPI access requires opening the LAPI port + extra TLS hardening — explicitly out of scope for the MVP.

## Module path

The module path is `github.com/rewulff/ember-crowdsec`. `go install github.com/rewulff/ember-crowdsec/cmd/ember-custom@latest` builds the custom Ember binary in one step — no clone, no token, no `GOPRIVATE` needed.

## Out of scope (MVP)

- Multi-instance plugin (one ember-crowdsec per Caddy LXC for now)
- Streaming-endpoint instead of polling
- Recent Bans sub-tab via MultiRenderer
- Prometheus exporter via `Exporter` interface
- Filter/sort via `HandleKey` (IP/origin/scenario)
- Detail-view for alerts
- Bulk operations (multiple IPs unbanned/whitelisted in one keystroke)
- CI / linting

These will land in a follow-up release sprint once the plugin API stabilizes upstream.

## License

MIT — see [LICENSE](LICENSE).

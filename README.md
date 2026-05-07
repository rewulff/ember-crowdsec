# ember-crowdsec

CrowdSec Bouncer Tab plugin for [alexandre-daubois/ember](https://github.com/alexandre-daubois/ember) (Caddy TUI). Read-only Decisions + Alerts pulled from a local CrowdSec LAPI via machine-account JWT authentication.

## Status

MVP skeleton — read-only TUI tab. Pinned to `ember v1.3.0` because the plugin API is marked EXPERIMENTAL upstream.

## Architecture

- One Caddy host = one LAPI = one ember-custom binary running on the same LXC. The plugin connects to LAPI via `localhost` (this is by design — the LAPI is not exposed externally).
- Auth: machine-account login (`POST /v1/watchers/login`) returns a JWT used for both `/v1/decisions` and `/v1/alerts`. Token cache + automatic refresh 60s before expiry; one retry on 401/403.
- Fetch: tick-based polling. Decisions and alerts are fetched in parallel goroutines on each tick.
- Render: Bubble Tea / lipgloss. Two sections (Decisions sorted by remaining TTL desc, Alerts sorted by created_at desc), header + per-section badges, status-count badge in the tab-bar shows active decision count.

## Setup

### 1. Create a machine account on the LAPI host

```sh
# On the LXC running CrowdSec:
cscli machines add ember-tui --auto
# Note the machine_id and password printed.
```

The credentials also land in `/etc/crowdsec/local_api_credentials.yaml` for reference.

### 2. Build the custom Ember binary

```sh
git clone https://forgejo.routetohome.renewulff.de/formin/ember-crowdsec.git
cd ember-crowdsec
go build -o ember-custom ./cmd/ember-custom
```

The output binary is a full Ember TUI with the CrowdSec plugin compiled in (Go's blank-import pattern, same approach Caddy itself uses for plugins).

### 3. Run with environment configuration

```sh
EMBER_PLUGIN_CROWDSEC_LAPI_URL=http://127.0.0.1:8080 \
EMBER_PLUGIN_CROWDSEC_MACHINE_ID=ember-tui \
EMBER_PLUGIN_CROWDSEC_MACHINE_PASSWORD='...' \
./ember-custom --addr http://127.0.0.1:2019
```

`--addr` is the standard Ember flag pointing at the Caddy admin endpoint.

## Configuration

All env-vars use the prefix `EMBER_PLUGIN_CROWDSEC_` (the plugin name is `crowdsec`). Ember strips the prefix and lowercases the key before passing it via `PluginConfig.Options`.

| Env-var | Required | Default | Notes |
|---|---|---|---|
| `EMBER_PLUGIN_CROWDSEC_LAPI_URL` | yes | — | e.g. `http://127.0.0.1:8080` |
| `EMBER_PLUGIN_CROWDSEC_MACHINE_ID` | yes | — | from `cscli machines add` |
| `EMBER_PLUGIN_CROWDSEC_MACHINE_PASSWORD` | yes | — | from `cscli machines add`. Quote shell-special chars. |
| `EMBER_PLUGIN_CROWDSEC_ALERTS_SINCE` | no | `24h` | Go duration string |
| `EMBER_PLUGIN_CROWDSEC_FETCH_INTERVAL` | no | (Ember default) | Validated as duration; tick-rate handled by Ember |
| `EMBER_PLUGIN_CROWDSEC_INSECURE_TLS` | no | `false` | Set `true` if LAPI uses a self-signed cert |

## Caveat

LAPI is only reachable from `localhost` on the CrowdSec host by default. This plugin is therefore designed to **run on the same host as the CrowdSec agent** (typically the same LXC that serves Caddy). Cross-host LAPI access requires opening the LAPI port + extra TLS hardening — explicitly out of scope for the MVP.

## Module path

The module is `forgejo.routetohome.renewulff.de/formin/ember-crowdsec`. Go's resolver fetches over HTTPS, so a Forgejo token in `~/.netrc` (or `GOPRIVATE=forgejo.routetohome.renewulff.de` plus a credential helper) is required for `go get` from another machine. Local builds work without that because the source is already checked out.

## Out of scope (MVP)

- Multi-instance plugin (one ember-crowdsec per Caddy LXC for now)
- Streaming-endpoint instead of polling
- Recent Bans sub-tab via MultiRenderer
- Prometheus exporter via `Exporter` interface
- Filter/sort via `HandleKey`
- Detail-view for alerts
- CI / tests

These will land in a follow-up release sprint once the plugin API stabilizes upstream.

## License

TBD (mirrors Ember's eventual choice once their license is finalized; placeholder until then).

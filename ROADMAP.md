# Roadmap

This plugin sits on top of [alexandre-daubois/ember](https://github.com/alexandre-daubois/ember). The plugin's UX depends on what Ember itself exposes to plugins. Two release lines are planned:

- **v0.1.0** — works against stock Ember `v1.3.0`, with documented caveats
- **v0.2.0** — full UX, after two upstream PRs land and a new Ember release ships

## v0.1.0 (planned, MVP) — pinned to Ember v1.3.0

The goal of v0.1.0 is to make the plugin installable from any Go-toolchain machine via `go install github.com/rewulff/ember-crowdsec/cmd/ember-custom@v0.1.0` without local forks or `replace`-directives.

### What works

- Decisions tab with origin filter (`?origins=crowdsec,cscli` by default)
- Alerts list (last 24h)
- Hotkey `c` — toggle CAPI / community-list inclusion
- Hotkey `d` — confirm-unban prompt for `crowdsec` / `cscli` decisions only (CAPI/list decisions are blocked because the next CAPI sync would re-pull them)
- Hotkey `w` — whitelist input flow with **stepped duration selection** (see caveat below)
- Status-count badge on the tab title (active local decisions count)
- Per-host JSON-Lines audit log of every write action (mode 0600, append-only, symlink-defended via `O_NOFOLLOW`)
- Two parallel auth stacks: bouncer X-Api-Key for `GET /v1/decisions`, machine-account JWT for alerts and writes

### Caveats with Ember v1.3.0

These are limitations imposed by the stock Ember plugin API, not by the plugin itself. All three are addressed in upstream PRs and will be lifted in v0.2.0.

| Limitation | Why | Workaround in v0.1.0 | Resolved in |
|---|---|---|---|
| **Whitelist duration is stepped, not free-form** | Ember's tab-switch hotkey reserves digits `1..9` globally; the plugin never sees them | `↑/↓` to select duration from `30m / 1h / 4h / 12h / 24h / 7d`, `Enter` to confirm | [PR upstream #N](TBD) — digit forwarding to active plugin tab |
| **Plugin hotkey hints render inline in the tab body** | Ember v1.3.0 has no plugin-side footer override, only the `?`-overlay (which is unreachable from plugin tabs because plugins receive `?` first) | One row of inline help text at the bottom of the plugin's render area | [PR upstream #N](TBD) — `FooterRenderer` optional interface |
| **No direct tab addressing from plugin modals** | Reaching tab N from inside a confirm dialog requires `Esc` first, then the digit | Use `Tab`/`Shift+Tab` to cycle, or `Esc` then digit | [PR upstream #N](TBD) — `t`-prefix tab-select mode |

### Pre-requisite

This plugin is designed to run **on the same host as the CrowdSec LAPI** (typically the Caddy LXC). It connects to the LAPI via `http://127.0.0.1:8080` and is not designed for off-host LAPI access. Setup details in [`docs/CADDY-CROWDSEC-SETUP.md`](docs/CADDY-CROWDSEC-SETUP.md).

## v0.2.0 (planned) — after upstream Plugin API patches land

Triggered by the merge of two upstream PRs and a subsequent Ember release that ships them.

### Upstream dependencies

| PR | Purpose | Status |
|---|---|---|
| [alexandre-daubois/ember#68](https://github.com/alexandre-daubois/ember/pull/68) | `fix(app)`: log unregister errors and retry on Caddy-busy to prevent broken-pipe loops | open as of 2026-05-08 |
| [alexandre-daubois/ember#TBD](TBD) | `feat(ui+plugin)`: t-prefix tab-select, digit forwarding, FooterRenderer interface | submitted after #68 review feedback |

### What changes from v0.1.0

- **Free-form whitelist duration input** — type `48h` directly into the buffer
- **Plugin hotkey hints in the global footer** instead of an inline help row (one row of plugin tab real-estate returned to content)
- **`t`-prefix tab-select** from any mode, even from inside a confirm dialog (`t 5` jumps to tab 5)
- **No more broken-pipe noise** in Caddy stderr after unclean ember exits — ember's retry loop handles transient Caddy-busy and the README documents `--log-listen 127.0.0.1:9210` as the idempotent-restart workaround for the `kill -9` case

### Migration

For users on v0.1.0:

```sh
# Once Ember vX.Y is released with the patches:
go install github.com/rewulff/ember-crowdsec/cmd/ember-custom@v0.2.0
# That's it. Same env-vars, same setup, same audit log.
```

The plugin's external surface (env-vars, audit-log format, hotkey labels) is stable across v0.1.0 → v0.2.0.

## Beyond v0.2.0 (no commitment, ideas)

- Multi-instance plugin: one ember-custom session can monitor multiple Caddy LXCs by switching their LAPI endpoints
- Streaming-endpoint (`/v1/decisions/stream`) instead of polling for high-decision-volume nodes
- Recent-Bans sub-tab via Ember's `MultiRenderer`
- Prometheus exporter via `Exporter`-interface — surface plugin metrics on Ember's `--expose :PORT`
- Filter / sort within the decision list via `HandleKey` (by IP, origin, scenario)
- Detail-view for a selected alert (events list, raw scenario hash)
- CI: `go test`, `go vet`, lint via GitHub Actions
- Bulk operations: select multiple decisions, unban / whitelist as one action

## How to influence the roadmap

If you're using this plugin and one of the v0.2.0 caveats is hurting your operator workflow, the most direct lever is to comment on the relevant upstream PR — that's the gating dependency, not anything on this side. The plugin is ready; we wait on Ember's plugin API to grow.

For plugin-internal bugs / improvements, file an issue on `formin/ember-crowdsec` (Forgejo) or `rewulff/ember-crowdsec` (GitHub mirror).

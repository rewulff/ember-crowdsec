# Roadmap

This plugin sits on top of [alexandre-daubois/ember](https://github.com/alexandre-daubois/ember). The plugin's UX depends on what Ember itself exposes to plugins. Three release lines so far:

- **v0.1.0** — MVP, pinned to Ember `v1.3.0`
- **v0.2.0** — Scroll-Window UX, Ember `v1.4.0`, `w`-hotkey removed
- **v0.3.0** — adopt `FooterRenderer` when Ember `v1.5.0` ships

## v0.1.0 (released) — pinned to Ember v1.3.0

The goal of v0.1.0 was to make the plugin installable from any Go-toolchain machine via `go install github.com/rewulff/ember-crowdsec/cmd/ember-custom@v0.1.0` without local forks or `replace`-directives.

### What works

- Decisions tab with origin filter (`?origins=crowdsec,cscli` by default)
- Alerts list (last 24h)
- Hotkey `c` — toggle CAPI / community-list inclusion
- Hotkey `d` — confirm-unban prompt for `crowdsec` / `cscli` decisions only (CAPI/list decisions are blocked because the next CAPI sync would re-pull them)
- Hotkey `w` — whitelist input flow with **stepped duration selection** (removed in v0.2.0, see below)
- Status-count badge on the tab title (active local decisions count)
- Per-host JSON-Lines audit log of every write action (mode 0600, append-only, symlink-defended via `O_NOFOLLOW`)
- Two parallel auth stacks: bouncer X-Api-Key for `GET /v1/decisions`, machine-account JWT for alerts and writes

### Caveats with Ember v1.3.0

These were limitations imposed by the stock Ember plugin API in v0.1.0, not by the plugin itself.

| Limitation | Why | Workaround in v0.1.0 | Status |
|---|---|---|---|
| **Whitelist duration is stepped, not free-form** | Ember's tab-switch hotkey reserves digits `1..9` globally; the plugin never sees them | `↑/↓` to select duration from `30m / 1h / 4h / 12h / 24h / 7d`, `Enter` to confirm | Obsolete — `w` hotkey removed in v0.2.0 |
| **Plugin hotkey hints render inline in the tab body** | Ember v1.3.0 has no plugin-side footer override, only the `?`-overlay (which is unreachable from plugin tabs because plugins receive `?` first) | One row of inline help text at the bottom of the plugin's render area | Tracked for v0.3.0 (`FooterRenderer` adoption, see below) |
| **Broken-pipe loops in Caddy stderr after unclean ember exits** | Ember v1.3.0 left dangling net-log writers after the sink-cleanup failed under contention | `--log-listen 127.0.0.1:9210` as idempotent-restart workaround for the `kill -9` case | Resolved in Ember v1.4.0 ([PR #68](https://github.com/alexandre-daubois/ember/pull/68)) — picked up in v0.2.0 |

### Pre-requisite

This plugin is designed to run **on the same host as the CrowdSec LAPI** (typically the Caddy LXC). It connects to the LAPI via `http://127.0.0.1:8080` and is not designed for off-host LAPI access. Setup details in [`docs/CADDY-CROWDSEC-SETUP.md`](docs/CADDY-CROWDSEC-SETUP.md).

## v0.2.0 (planned) — Ember v1.4.0 + UX cleanup

Pinned to Ember **v1.4.0** (released 2026-05-11).

### What's new

- **Scroll-Window for the Decisions tab** — the list of decisions now scrolls vertically with `↑/↓`; `↑ N earlier` / `↓ N more` markers indicate hidden entries on either side. Resolves the 5-decision-cap visible in v0.1.0 ([#7](https://forgejo.routetohome.renewulff.de/formin/ember-crowdsec/issues/7)).
- **Ember v1.4.0 dependency** — single-instance stance documented. The plugin opts out of the `MultiInstancePlugin` marker, so Ember in multi-instance mode will disable the plugin with a warning. v1.4.0 also includes Ember [PR #68](https://github.com/alexandre-daubois/ember/pull/68) (sink-cleanup retry fix), which removes the broken-pipe-loop class of bug seen pre-v1.4 ([#10](https://forgejo.routetohome.renewulff.de/formin/ember-crowdsec/issues/10), [#11](https://forgejo.routetohome.renewulff.de/formin/ember-crowdsec/issues/11)).
- **README "Whitelisting" section reworked** — after maintainer feedback in [hslatman/caddy-crowdsec-bouncer#116](https://github.com/hslatman/caddy-crowdsec-bouncer/issues/116). New framing: `cscli decisions add --type whitelist` is not an officially supported decision type; allow-functionality belongs in CrowdSec's engine via postoverflow YAMLs, not in any bouncer ([#12](https://forgejo.routetohome.renewulff.de/formin/ember-crowdsec/issues/12), [#15](https://forgejo.routetohome.renewulff.de/formin/ember-crowdsec/issues/15)).

### Breaking change

- **`w` (whitelist) hotkey removed.** It produced a `type=whitelist` decision via `POST /v1/alerts` that CrowdSec does not treat as allow — every bouncer reads it as a block-marker (the existence of any decision is a block). Replacement: edit `/etc/crowdsec/postoverflows/s01-whitelist/<name>.yaml` and `systemctl reload crowdsec`. Audit-log entries with `action: whitelist` from v0.1.x persist; new writes only emit `action: unban` ([#13](https://forgejo.routetohome.renewulff.de/formin/ember-crowdsec/issues/13), [#16](https://forgejo.routetohome.renewulff.de/formin/ember-crowdsec/pulls/16)).

### Migration from v0.1.0

```sh
go install github.com/rewulff/ember-crowdsec/cmd/ember-custom@v0.2.0
```

Same env-vars, same audit-log format. The `w` hotkey is gone — any operator muscle memory that hit `w` should be redirected to the postoverflow YAML path above.

### Out of scope for v0.2.0

- `FooterRenderer` adoption (replace inline-footer-row with global footer override) — needs Ember v1.5.0 with [PR #70](https://github.com/alexandre-daubois/ember/pull/70) released as a tagged version. Tracked in [#14](https://forgejo.routetohome.renewulff.de/formin/ember-crowdsec/issues/14).

## v0.3.0 (planned) — `FooterRenderer` adoption after Ember v1.5.0

Triggers in order:

- [ ] Upstream Ember releases `v1.5.0` (contains [PR #70](https://github.com/alexandre-daubois/ember/pull/70), already merged in main).
- [ ] `go.mod` bump from `v1.4.0` → `v1.5.x` (chore-issue analog to [#10](https://forgejo.routetohome.renewulff.de/formin/ember-crowdsec/issues/10)).
- [ ] Plugin implements `pkg/plugin.FooterRenderer` — moves the inline `↑/↓ select · c CAPI · d unban` hint into the global Ember footer; one extra decision row gained in the tab body.
- [ ] Live-verify on CT 122.

Tracked in [#14](https://forgejo.routetohome.renewulff.de/formin/ember-crowdsec/issues/14).

## Beyond v0.3.0 (no commitment, ideas)

- Multi-instance plugin: one ember-custom session can monitor multiple Caddy LXCs by switching their LAPI endpoints
- Streaming-endpoint (`/v1/decisions/stream`) instead of polling for high-decision-volume nodes
- Recent-Bans sub-tab via Ember's `MultiRenderer`
- Prometheus exporter via `Exporter`-interface — surface plugin metrics on Ember's `--expose :PORT`
- Filter / sort within the decision list via `HandleKey` (by IP, origin, scenario)
- Detail-view for a selected alert (events list, raw scenario hash)
- CI: `go test`, `go vet`, lint via GitHub Actions / Forgejo Actions
- Bulk operations: select multiple decisions, unban as one action

## How to influence the roadmap

If you're using this plugin and one of the open caveats is hurting your operator workflow, the most direct lever is to comment on the relevant upstream Ember PR — that's the gating dependency, not anything on this side. The plugin is ready; we wait on Ember's plugin API to grow.

For plugin-internal bugs / improvements, file an issue on `formin/ember-crowdsec` (Forgejo) or `rewulff/ember-crowdsec` (GitHub mirror).

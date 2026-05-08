package plugin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	emberplugin "github.com/alexandre-daubois/ember/pkg/plugin"
)

// CrowdSecPlugin is the Ember plugin entry point. It implements:
//   - emberplugin.Plugin   (Name + Provision)
//   - emberplugin.Fetcher  (Fetch via fetcher.fetchAll)
//   - emberplugin.Renderer (Update/View/HandleKey/StatusCount/HelpBindings)
type CrowdSecPlugin struct {
	auth    *authClient
	fetch   *fetcher
	actions *actionsClient
	audit   *auditLog
	render  *renderer
	cfg     pluginCfg
}

// pluginCfg is the parsed Provision-time configuration.
type pluginCfg struct {
	lapiURL     string
	machineID   string
	password    string
	bouncerKey  string // X-Api-Key for GET /v1/decisions (Read-path)
	auditLog    string // append-only JSON-Lines log path
	alertsSince time.Duration
	insecureTLS bool
}

// init registers the plugin in Ember's global registry. Per ember v1.3.0
// pkg/plugin/registry.go the name must be lowercase, no whitespace, no
// underscores. "crowdsec" passes.
func init() {
	emberplugin.Register(&CrowdSecPlugin{})
}

// Name returns the plugin identifier. Drives env-var prefix
// EMBER_PLUGIN_CROWDSEC_*.
func (p *CrowdSecPlugin) Name() string { return "crowdsec" }

// Provision is called once at startup. cfg.Options carries lowercased keys
// from the EMBER_PLUGIN_CROWDSEC_* env vars (Ember strips prefix + lowercases).
// cfg.CaddyAddr is the Caddy admin URL — unused by this plugin (LAPI is the
// data source, not Caddy itself).
func (p *CrowdSecPlugin) Provision(_ context.Context, cfg emberplugin.PluginConfig) error {
	parsed, err := parseOptions(cfg.Options)
	if err != nil {
		return err
	}
	p.cfg = parsed

	p.auth = newAuthClient(parsed.lapiURL, parsed.machineID, parsed.password, parsed.insecureTLS)
	p.fetch = newFetcher(p.auth, parsed.lapiURL, parsed.bouncerKey, parsed.alertsSince)
	p.actions = newActionsClient(p.auth, parsed.lapiURL)

	audit, err := newAuditLog(parsed.auditLog)
	if err != nil {
		// Audit-log creation must not block plugin startup. Surface via
		// renderer status instead so the user sees it in-tab.
		p.audit = &auditLog{disabled: true, lastErr: err}
	} else {
		p.audit = audit
	}

	p.render = newRenderer(p.actions, p.audit, p.fetch)
	return nil
}

// Fetch is invoked by Ember on each tick. Partial-failure errors live on the
// returned snapshot.Err so the renderer can surface them in-tab; we only
// return a top-level error if the plugin isn't provisioned yet.
func (p *CrowdSecPlugin) Fetch(ctx context.Context) (any, error) {
	if p.fetch == nil {
		return snapshot{Err: errors.New("plugin not provisioned")}, nil
	}
	return p.fetch.fetchAll(ctx), nil
}

// Update receives the snapshot from Fetch and forwards to the renderer.
// Returns the plugin itself (which satisfies emberplugin.Renderer).
func (p *CrowdSecPlugin) Update(data any, width, height int) emberplugin.Renderer {
	if p.render == nil {
		// Defensive: Ember may call Update before Provision in some startup
		// paths. Lazy-init with nil action/audit/fetch deps — write
		// actions and the CAPI toggle are disabled until Provision wires
		// them up.
		p.render = newRenderer(nil, nil, nil)
	}
	p.render.update(data, width, height)
	return p
}

// View renders the tab content. Defensive against nil/zero data.
func (p *CrowdSecPlugin) View(width, height int) string {
	if p.render == nil {
		return "CrowdSec plugin not yet provisioned."
	}
	return p.render.view(width, height)
}

// HandleKey delegates to the renderer which manages the unban/whitelist mode
// state machine. Returns true to keep the keystroke from bubbling up to Ember
// when the renderer is in a confirm/input mode (keyboard lock-out).
func (p *CrowdSecPlugin) HandleKey(msg tea.KeyMsg) bool {
	if p.render == nil {
		return false
	}
	return p.render.handleKey(msg)
}

// StatusCount returns the badge text shown next to the tab title. Active
// decision count, or empty string if zero (Ember collapses empty badges).
func (p *CrowdSecPlugin) StatusCount() string {
	if p.render == nil {
		return ""
	}
	n := p.render.activeDecisionCount()
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

// HelpBindings returns per-tab footer shortcuts. Iteration 2 added unban
// (d) + whitelist (w); Iteration 3 adds the CAPI inclusion toggle (c) so
// the operator can flip between "decisions on MY caddy" (default,
// origins=crowdsec,cscli) and the full feed view including CAPI Threat
// Intel + community blocklists.
func (p *CrowdSecPlugin) HelpBindings() []emberplugin.HelpBinding {
	return []emberplugin.HelpBinding{
		{Key: "↑/↓", Desc: "select decision"},
		{Key: "c", Desc: "toggle CAPI"},
		{Key: "d", Desc: "unban (local+cscli only)"},
		{Key: "w", Desc: "whitelist"},
	}
}

// FooterText satisfies emberplugin.FooterRenderer. Returns the plugin's
// hotkey hint while the renderer is in normal mode. Confirm/input modes
// have their own inline prompts ("[y/N]", "Enter to confirm") and let
// the default Ember footer surface; doubling up would be visual noise
// and the global hotkeys don't apply during the keyboard-locked dialog
// anyway. Width is unused for now (hint fits comfortably in 80 cols).
func (p *CrowdSecPlugin) FooterText(_ int) string {
	if p.render == nil {
		return ""
	}
	return p.render.footerText()
}

// parseOptions extracts and validates Provision-time options.
func parseOptions(opts map[string]string) (pluginCfg, error) {
	cfg := pluginCfg{
		alertsSince: 24 * time.Hour,
	}

	cfg.lapiURL = opts["lapi_url"]
	if cfg.lapiURL == "" {
		return cfg, errors.New("EMBER_PLUGIN_CROWDSEC_LAPI_URL is required (e.g. http://127.0.0.1:8080)")
	}
	cfg.machineID = opts["machine_id"]
	if cfg.machineID == "" {
		return cfg, errors.New("EMBER_PLUGIN_CROWDSEC_MACHINE_ID is required (run: cscli machines add ember-tui --auto)")
	}
	cfg.password = opts["machine_password"]
	if cfg.password == "" {
		return cfg, errors.New("EMBER_PLUGIN_CROWDSEC_MACHINE_PASSWORD is required")
	}

	// Bouncer-Key is mandatory: GET /v1/decisions on CrowdSec LAPI accepts
	// X-Api-Key only (verified via smoke against CT 122 on 2026-05-07: JWT
	// against /v1/decisions yields 401 "token rejected twice"). The plugin
	// uses two auth stacks in parallel — JWT for alerts/actions, bouncer-key
	// for decisions read.
	cfg.bouncerKey = opts["bouncer_key"]
	if cfg.bouncerKey == "" {
		return cfg, errors.New("EMBER_PLUGIN_CROWDSEC_BOUNCER_KEY is required (run: cscli bouncers add ember-tui-bouncer)")
	}

	// Audit-log path: writeable file for delete/whitelist actions. Default
	// to the user's home directory so we don't require root for the MVP.
	cfg.auditLog = opts["audit_log"]
	if cfg.auditLog == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			cfg.auditLog = ".ember-crowdsec-audit.log"
		} else {
			cfg.auditLog = filepath.Join(home, ".ember-crowdsec-audit.log")
		}
	}

	if v := opts["alerts_since"]; v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("EMBER_PLUGIN_CROWDSEC_ALERTS_SINCE: %w", err)
		}
		cfg.alertsSince = d
	}

	if v := opts["insecure_tls"]; v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return cfg, fmt.Errorf("EMBER_PLUGIN_CROWDSEC_INSECURE_TLS: %w", err)
		}
		cfg.insecureTLS = b
	}

	// fetch_interval is consumed by Ember's tick scheduler, not by us — but
	// validate the format so the user gets an early error.
	if v := opts["fetch_interval"]; v != "" {
		if _, err := time.ParseDuration(v); err != nil {
			return cfg, fmt.Errorf("EMBER_PLUGIN_CROWDSEC_FETCH_INTERVAL: %w", err)
		}
	}

	return cfg, nil
}

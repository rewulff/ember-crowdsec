package plugin

import (
	"context"
	"errors"
	"fmt"
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
	auth   *authClient
	fetch  *fetcher
	render *renderer
	cfg    pluginCfg
}

// pluginCfg is the parsed Provision-time configuration.
type pluginCfg struct {
	lapiURL     string
	machineID   string
	password    string
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
	p.fetch = newFetcher(p.auth, parsed.lapiURL, parsed.alertsSince)
	p.render = newRenderer()
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
		// paths. Lazy-init an empty renderer so View doesn't panic.
		p.render = newRenderer()
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

// HandleKey is a no-op for the MVP — no filter/sort/details yet.
func (p *CrowdSecPlugin) HandleKey(_ tea.KeyMsg) bool {
	return false
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

// HelpBindings returns per-tab footer shortcuts. MVP has none beyond Ember's
// global "?".
func (p *CrowdSecPlugin) HelpBindings() []emberplugin.HelpBinding {
	return nil
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
		// Accept legacy key for convenience.
		cfg.password = opts["password"]
	}
	if cfg.password == "" {
		return cfg, errors.New("EMBER_PLUGIN_CROWDSEC_MACHINE_PASSWORD is required")
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

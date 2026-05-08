package plugin

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// renderMode is the renderer's keyboard state machine. Only "normal" lets
// keys pass through to Ember; the confirm/input modes lock the keyboard
// to the local handler.
type renderMode int

const (
	modeNormal renderMode = iota
	modeConfirmUnban
	modeInputDuration
	modeConfirmWhitelist
)

// statusFadeAfter controls how long the status line stays visible before
// fading. 5 s is enough to read "Unbanned 1.2.3.4" without leaving stale
// state on screen indefinitely.
const statusFadeAfter = 5 * time.Second

// helpFooterText is the inline hotkey hint rendered at the bottom of the
// plugin tab. Ember's global help-overlay (?) only surfaces plugin
// HelpBindings on core tabs, not on the plugin's own tab — so the plugin
// renders its own hint to keep hotkeys discoverable. Suppressed during
// confirm/input modes, which carry their own prompts.
const helpFooterText = "↑/↓ select · c toggle CAPI · d unban (local only) · w whitelist"

// renderer holds the latest snapshot, the mode-state for the
// unban/whitelist UX, and lipgloss styles. Safe for concurrent use:
// Ember calls Update from the fetch goroutine and View+HandleKey from
// the TUI goroutine.
type renderer struct {
	mu      sync.RWMutex
	snap    snapshot
	hasData bool

	// fetcher is the source for the includeCAPI toggle state. Renderer
	// reads it for header text and for the 'd' (unban) origin guard, and
	// flips it on hotkey 'c'. May be nil in unit tests that bypass
	// Provision; both reads and writes guard against nil.
	fetch *fetcher

	actions *actionsClient
	audit   *auditLog

	// Selection / mode state.
	selectedIdx     int
	mode            renderMode
	durationBuf     string // built up in modeInputDuration
	pendingDecision *Decision
	statusLine      string
	statusAt        time.Time

	titleStyle       lipgloss.Style
	tableHeaderStyle lipgloss.Style
	selectedRowStyle lipgloss.Style
	greyStyle        lipgloss.Style
	dangerStyle      lipgloss.Style
	dialogStyle      lipgloss.Style
	okStyle          lipgloss.Style
}

// Theme constants mirror ember-fork/internal/ui/styles.go (Bold + ember
// AdaptiveColor for titles, subtle for muted/header rows, Reverse() for
// selected rows, RoundedBorder + ember for popups). Replicated locally
// because internal/ui is not importable from third-party plugin code.
// Keep in lock-step with upstream styles.go to honour the maintainer's
// design language.
var (
	emberSubtle = lipgloss.AdaptiveColor{Light: "#7A6652", Dark: "#A0896E"}
	emberAccent = lipgloss.AdaptiveColor{Light: "#CC4400", Dark: "#FF6B35"}
	emberRed    = lipgloss.AdaptiveColor{Light: "#CC0000", Dark: "#FF4444"}
	emberGreen  = lipgloss.AdaptiveColor{Light: "#228B22", Dark: "#44CC44"}
)

func newRenderer(actions *actionsClient, audit *auditLog, fetch *fetcher) *renderer {
	return &renderer{
		actions:     actions,
		audit:       audit,
		fetch:       fetch,
		durationBuf: "24h",
		// titleStyle = Embers titleStyle: Bold + ember-accent. Used for
		// the tab header line and the section labels ("Decisions ...",
		// "Recent alerts"). Mirrors styles.go:11-13.
		titleStyle: lipgloss.NewStyle().Bold(true).Foreground(emberAccent),
		// tableHeaderStyle = Embers tableHeaderStyle: Bold + subtle FG +
		// bottom-border in subtle. Applied to the column-header row of
		// the Decisions and Alerts tables so the look matches Caddy /
		// Certs / Upstreams. Mirrors styles.go:20-25.
		tableHeaderStyle: lipgloss.NewStyle().
			Bold(true).
			Foreground(emberSubtle).
			BorderBottom(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(emberSubtle),
		// selectedRowStyle = Embers selectedRowStyle: Reverse(true).
		// Width is set per-render-call (see renderDecisions) so the
		// row inverts the FULL line, not just the visible content.
		// Render-arg never contains a "\n" (newline-discipline lesson
		// from iter-10..12: lipgloss inserts ANSI resets relative to
		// embedded newlines, and xtermjs in Proxmox web VNC then
		// renders the next line shifted). Mirrors styles.go:27-28.
		selectedRowStyle: lipgloss.NewStyle().Reverse(true),
		// greyStyle = Embers greyStyle: subtle FG. For "(none)" hints
		// and "... N more" overflow lines. Mirrors styles.go:32.
		greyStyle: lipgloss.NewStyle().Foreground(emberSubtle),
		// dangerStyle = Embers dangerStyle: Bold + red FG. For error
		// banners. Mirrors styles.go:34.
		dangerStyle: lipgloss.NewStyle().Bold(true).Foreground(emberRed),
		// dialogStyle = Embers boxStyle: RoundedBorder + ember-accent
		// border. Used for confirm/input overlays. Mirrors styles.go:15-18.
		dialogStyle: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(emberAccent).
			Padding(0, 1),
		// okStyle = Embers okStyle: green FG. Used for status-line
		// success messages. Mirrors styles.go:40-41.
		okStyle: lipgloss.NewStyle().Foreground(emberGreen),
	}
}

// update stores the latest snapshot. Width/height are accepted but currently
// unused (we render at full available width using padding-only layout).
// Selection is clamped if the underlying decision list shrinks.
func (r *renderer) update(data any, _, _ int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if snap, ok := data.(snapshot); ok {
		r.snap = snap
		r.hasData = true
		if r.selectedIdx >= len(r.snap.Decisions) {
			r.selectedIdx = len(r.snap.Decisions) - 1
		}
		if r.selectedIdx < 0 {
			r.selectedIdx = 0
		}
	}
}

// view renders the tab. Defensive against pre-provision/empty calls.
func (r *renderer) view(width, height int) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}

	var b strings.Builder

	if !r.hasData {
		b.WriteString(r.titleStyle.Render("CrowdSec — waiting for first fetch..."))
		b.WriteString("\n")
		return b.String()
	}

	// Filter hint reflects the current includeCAPI toggle. Default is
	// origins=crowdsec,cscli (local engine + manual cscli) which is the
	// "decisions on MY caddy" view. Pressing 'c' switches to ALL origins
	// (incl. CAPI Threat Intel + community lists) which can be 50k+ rows.
	filterHint := "filter: local+manual, c: include CAPI"
	if r.includeCAPI() {
		filterHint = "filter: ALL, c: hide CAPI"
	}
	hdr := fmt.Sprintf("CrowdSec — %d decisions, %d alerts (last fetch %s, %s)",
		len(r.snap.Decisions),
		len(r.snap.Alerts),
		r.snap.FetchedAt.Local().Format("15:04:05"),
		filterHint,
	)
	// Title-line gets Embers Bold+ember-accent treatment. Render-arg holds
	// no embedded newline; the "\n" is appended via WriteString so lipgloss
	// can't insert reset sequences mid-line (iter-10..12 lesson).
	b.WriteString(r.titleStyle.Render(hdr))
	b.WriteString("\n")

	if r.snap.Err != nil {
		b.WriteString(r.dangerStyle.Render("Error: " + r.snap.Err.Error()))
		b.WriteString("\n\n")
	}

	b.WriteString(r.titleStyle.Render("Decisions (top 20 by remaining TTL)"))
	b.WriteString("\n")
	b.WriteString(r.renderDecisions(20, width))
	b.WriteString("\n")

	b.WriteString(r.titleStyle.Render("Recent alerts"))
	b.WriteString("\n")
	b.WriteString(r.renderAlerts(20, width))

	if dialog := r.renderDialog(); dialog != "" {
		b.WriteString("\n")
		b.WriteString(dialog)
		b.WriteString("\n")
	}

	if status := r.renderStatus(); status != "" {
		b.WriteString("\n")
		b.WriteString(status)
		b.WriteString("\n")
	}

	// Footer is now surfaced via Ember's FooterRenderer hook (see
	// CrowdSecPlugin.FooterText / footerText below) — no inline render
	// here. The plugin's struct method delegates to footerText() which
	// reads the same r.mode gating.

	// Trailing spacer lines stabilise the tab's vertical extent for
	// Ember's tab-layout engine. After iter-9 removed the inline help
	// footer, this tab produced ~2 lines fewer than the dense core tabs
	// (Caddy, Logs, ...) and Ember subtly re-scaled the content, making
	// it look "minimal kleiner" than the others. Two reserved newlines
	// here restore parity without re-introducing footer text.
	b.WriteString("\n\n")

	return b.String()
}

// footerText returns the hotkey hint string the plugin advertises through
// emberplugin.FooterRenderer. Empty in confirm/input modes so Ember's
// default footer (or any other context-sensitive hint) shows through.
// Goroutine-safe: takes r.mu.RLock for the mode read.
func (r *renderer) footerText() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.mode != modeNormal {
		return ""
	}
	return helpFooterText
}

func (r *renderer) renderDecisions(limit, width int) string {
	if len(r.snap.Decisions) == 0 {
		b := r.greyStyle.Render("  (none)")
		return b + "\n"
	}
	var b strings.Builder
	// Header mirrors Embers tableHeaderStyle pattern (Bold + subtle FG +
	// bottom-border): see ember-fork upstreamtable.go:60 / certificates.go:57.
	// Render-arg has NO embedded newline — the "\n" is added separately via
	// WriteString. iter-10..12 lesson: lipgloss inserts ANSI sequences
	// relative to embedded newlines, xtermjs in Proxmox web VNC then
	// renders the next visual line shifted/overlapping. Width(width) makes
	// the bottom-border span the full tab width like the core tabs.
	header := fmt.Sprintf(" %-19s %-12s %-30s %s", "VALUE", "ORIGIN", "SCENARIO", "TTL-REM")
	b.WriteString(r.tableHeaderStyle.Width(width).Render(header))
	b.WriteString("\n")

	n := len(r.snap.Decisions)
	if n > limit {
		n = limit
	}
	for i := 0; i < n; i++ {
		d := r.snap.Decisions[i]
		ttl := formatDuration(d.RemainingTTL())
		val := truncate(d.Value, 19)
		origin := truncate(d.Origin, 12)
		scenario := truncate(d.Scenario, 30)
		// Embers prefix convention (upstreamtable.go:166-168, certificates.go:116-119):
		// prefix is a single character — " " for unselected, ">" for selected.
		// One space gap to the value follows from the format string itself.
		prefix := " "
		if i == r.selectedIdx {
			prefix = ">"
		}
		line := fmt.Sprintf("%s%-19s %-12s %-30s %s", prefix, val, origin, scenario, ttl)
		if i == r.selectedIdx {
			// selectedRowStyle = Reverse(true). Width(width) extends the
			// inversion to the full tab width so the highlight reaches the
			// right edge (Embers pattern: certificates.go:130, etc.).
			// Render-arg has NO "\n" — the trailing newline is appended via
			// WriteString below.
			b.WriteString(r.selectedRowStyle.Width(width).Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	if len(r.snap.Decisions) > limit {
		more := fmt.Sprintf("  ... %d more", len(r.snap.Decisions)-limit)
		b.WriteString(r.greyStyle.Render(more))
		b.WriteString("\n")
	}
	return b.String()
}

func (r *renderer) renderAlerts(limit, width int) string {
	if len(r.snap.Alerts) == 0 {
		return r.greyStyle.Render("  (none)") + "\n"
	}
	var b strings.Builder
	// Same tableHeaderStyle treatment as renderDecisions; render-arg has
	// no embedded newline (newline-discipline).
	header := fmt.Sprintf(" %-7s %-30s %-19s %s", "ID", "SCENARIO", "SOURCE", "CREATED")
	b.WriteString(r.tableHeaderStyle.Width(width).Render(header))
	b.WriteString("\n")

	n := len(r.snap.Alerts)
	if n > limit {
		n = limit
	}
	for i := 0; i < n; i++ {
		a := r.snap.Alerts[i]
		src := a.Source.Value
		if src == "" {
			src = a.Source.IP
		}
		created := truncateRFC3339(a.CreatedAt)
		// Alerts list has no selection cursor (read-only), so all rows
		// stay plain — matching Embers logtable.go non-selected branch.
		b.WriteString(fmt.Sprintf(" %-7d %-30s %-19s %s",
			a.ID,
			truncate(a.Scenario, 30),
			truncate(src, 19),
			created,
		))
		b.WriteString("\n")
	}
	if len(r.snap.Alerts) > limit {
		more := fmt.Sprintf("  ... %d more", len(r.snap.Alerts)-limit)
		b.WriteString(r.greyStyle.Render(more))
		b.WriteString("\n")
	}
	return b.String()
}

// renderDialog returns the confirm/input overlay for the current mode, or
// empty string in normal mode. Caller holds r.mu.RLock.
func (r *renderer) renderDialog() string {
	switch r.mode {
	case modeConfirmUnban:
		if r.pendingDecision == nil {
			return ""
		}
		d := r.pendingDecision
		body := fmt.Sprintf("Unban %s (origin %s, scenario %s)? [y/N]",
			d.Value, d.Origin, d.Scenario)
		return r.dialogStyle.Render(body)
	case modeInputDuration:
		body := fmt.Sprintf("Whitelist duration: %s_  (Enter to confirm, Esc to cancel)", r.durationBuf)
		return r.dialogStyle.Render(body)
	case modeConfirmWhitelist:
		if r.pendingDecision == nil {
			return ""
		}
		body := fmt.Sprintf("Whitelist %s for %s? [y/N]",
			r.pendingDecision.Value, r.durationBuf)
		return r.dialogStyle.Render(body)
	}
	return ""
}

// renderStatus returns the status line if recent enough, else empty. Caller
// holds r.mu.RLock.
func (r *renderer) renderStatus() string {
	if r.statusLine == "" {
		return ""
	}
	if time.Since(r.statusAt) > statusFadeAfter {
		return ""
	}
	// okStyle = green for success, dangerStyle = bold-red for error.
	// Status messages never contain a newline so Render-arg is single-line
	// (newline-discipline).
	style := r.okStyle
	if strings.HasPrefix(r.statusLine, "error:") || strings.HasPrefix(r.statusLine, "audit log") {
		style = r.dangerStyle
	}
	return style.Render(r.statusLine)
}

func (r *renderer) activeDecisionCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.snap.Decisions)
}

// includeCAPI returns the fetcher's CAPI-toggle state. Defensive against
// nil fetcher (unit tests that build a renderer directly without going
// through Provision).
func (r *renderer) includeCAPI() bool {
	if r.fetch == nil {
		return false
	}
	return r.fetch.IncludeCAPI()
}

// originLocal reports whether a decision can be unbanned from this LAPI.
// CrowdSec's CAPI / community-list pipeline is read-only by design —
// DELETE on those returns 200 but the next CAPI sync re-pulls the same
// row, effective no-op. The rule mirrors the server-side filter set:
// only origin in {crowdsec, cscli} is operator-controlled and genuinely
// unbannable. CAPI, lists:firehol, lists:tor, ... must be whitelisted
// instead (whitelist beats ban regardless of origin).
func originLocal(origin string) bool {
	return origin == "crowdsec" || origin == "cscli"
}

// handleKey is the keyboard state machine. Returns true if Ember should
// suppress the key (i.e. don't let it bubble up to global tab-bar
// shortcuts). All confirm/input modes return true for every key to enforce
// keyboard lock-out.
func (r *renderer) handleKey(msg tea.KeyMsg) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch r.mode {
	case modeConfirmUnban:
		return r.handleConfirmUnban(msg)
	case modeInputDuration:
		return r.handleInputDuration(msg)
	case modeConfirmWhitelist:
		return r.handleConfirmWhitelist(msg)
	default:
		return r.handleNormal(msg)
	}
}

func (r *renderer) handleNormal(msg tea.KeyMsg) bool {
	switch msg.String() {
	case "up", "k":
		if r.selectedIdx > 0 {
			r.selectedIdx--
		}
		return true
	case "down", "j":
		if r.selectedIdx < len(r.snap.Decisions)-1 {
			r.selectedIdx++
		}
		return true
	case "c":
		// Toggle CAPI inclusion. Next Fetch tick observes the new state;
		// no forced re-fetch — header already updates immediately so the
		// user sees the intent took effect.
		if r.fetch == nil {
			r.setStatus("error: fetcher not wired")
			return true
		}
		now := !r.fetch.IncludeCAPI()
		r.fetch.SetIncludeCAPI(now)
		if now {
			r.setStatus("CAPI included — next fetch shows ALL origins")
		} else {
			r.setStatus("Filter: local+manual — CAPI hidden")
		}
		return true
	case "d":
		d := r.currentDecision()
		if d == nil {
			r.setStatus("no decision selected")
			return true
		}
		// Block unban on non-local origins. CAPI / community lists are
		// pulled from the central feed — DELETE locally is meaningless
		// because the next CAPI sync re-pulls the row. Whitelist (which
		// has type=whitelist and beats any ban regardless of origin) is
		// the correct override; suggest it via the status line and stay
		// in normal mode (no confirm dialog).
		if !originLocal(d.Origin) {
			r.setStatus(fmt.Sprintf(
				"Cannot unban %s decision (will re-pull). Use w (whitelist) instead.",
				d.Origin,
			))
			return true
		}
		r.pendingDecision = d
		r.mode = modeConfirmUnban
		return true
	case "w":
		if d := r.currentDecision(); d != nil {
			r.pendingDecision = d
			if r.durationBuf == "" {
				r.durationBuf = "24h"
			}
			r.mode = modeInputDuration
		} else {
			r.setStatus("no decision selected")
		}
		return true
	}
	return false
}

func (r *renderer) handleConfirmUnban(msg tea.KeyMsg) bool {
	switch msg.String() {
	case "y", "Y":
		d := r.pendingDecision
		r.mode = modeNormal
		r.pendingDecision = nil
		if d == nil || r.actions == nil {
			r.setStatus("error: no action client")
			return true
		}
		// Release the lock for the network call — we already captured the
		// snapshot we need into local vars. Re-acquire to update status.
		ip := d.Value
		id := d.ID
		r.mu.Unlock()
		err := r.actions.DeleteDecision(context.Background(), id)
		r.mu.Lock()
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		r.audit.recordUnban(id, ip, errMsg)
		if err != nil {
			r.setStatus(fmt.Sprintf("error: unban %s: %v", ip, err))
		} else {
			r.setStatus(fmt.Sprintf("Unbanned %s", ip))
		}
		r.surfaceAuditError()
		return true
	case "n", "N", "esc":
		r.mode = modeNormal
		r.pendingDecision = nil
		return true
	}
	// Other keys: ignore but consume so they don't leak to Ember.
	return true
}

func (r *renderer) handleInputDuration(msg tea.KeyMsg) bool {
	switch msg.String() {
	case "enter":
		if _, err := time.ParseDuration(r.durationBuf); err != nil {
			r.setStatus(fmt.Sprintf("error: invalid duration %q", r.durationBuf))
			return true
		}
		r.mode = modeConfirmWhitelist
		return true
	case "esc":
		r.mode = modeNormal
		r.pendingDecision = nil
		return true
	case "backspace":
		if len(r.durationBuf) > 0 {
			r.durationBuf = r.durationBuf[:len(r.durationBuf)-1]
		}
		return true
	}
	// Append printable single-char keys. Bubble Tea reports them as their
	// literal string ("a", "1", "h", ...). Filter anything multi-char that
	// isn't a known printable name.
	s := msg.String()
	if len(s) == 1 && s[0] >= 0x20 && s[0] < 0x7f {
		r.durationBuf += s
	}
	return true
}

func (r *renderer) handleConfirmWhitelist(msg tea.KeyMsg) bool {
	switch msg.String() {
	case "y", "Y":
		d := r.pendingDecision
		duration := r.durationBuf
		r.mode = modeNormal
		r.pendingDecision = nil
		if d == nil || r.actions == nil {
			r.setStatus("error: no action client")
			return true
		}
		ip := d.Value
		r.mu.Unlock()
		err := r.actions.WhitelistIP(context.Background(), ip, duration, "manual whitelist via ember-tui")
		r.mu.Lock()
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		r.audit.recordWhitelist(ip, duration, "manual whitelist via ember-tui", errMsg)
		if err != nil {
			r.setStatus(fmt.Sprintf("error: whitelist %s: %v", ip, err))
		} else {
			r.setStatus(fmt.Sprintf("Whitelisted %s for %s", ip, duration))
		}
		r.surfaceAuditError()
		return true
	case "n", "N", "esc":
		r.mode = modeNormal
		r.pendingDecision = nil
		return true
	}
	return true
}

// currentDecision returns the currently-selected Decision (pointer into the
// snapshot slice), or nil if the list is empty. Caller holds r.mu.
func (r *renderer) currentDecision() *Decision {
	if len(r.snap.Decisions) == 0 {
		return nil
	}
	if r.selectedIdx < 0 || r.selectedIdx >= len(r.snap.Decisions) {
		return nil
	}
	d := r.snap.Decisions[r.selectedIdx]
	return &d
}

// setStatus updates the status line and timestamp. Caller holds r.mu.
func (r *renderer) setStatus(s string) {
	r.statusLine = s
	r.statusAt = time.Now()
}

// surfaceAuditError prepends an audit-log warning to the status line if the
// log is broken. Caller holds r.mu.
func (r *renderer) surfaceAuditError() {
	if r.audit == nil {
		return
	}
	if err := r.audit.LastErr(); err != nil {
		// Don't overwrite the action result; just append.
		r.statusLine += "  (audit log write failed: " + err.Error() + ")"
	}
}

// --- helpers ---------------------------------------------------------------

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return "."
	}
	return s[:n-1] + "."
}

func truncateRFC3339(s string) string {
	// RFC3339: 2026-05-07T14:23:45Z → 2026-05-07 14:23:45
	if len(s) < 19 {
		return s
	}
	return s[:10] + " " + s[11:19]
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours()) / 24
	hrs := int(d.Hours()) % 24
	return fmt.Sprintf("%dd%dh", days, hrs)
}

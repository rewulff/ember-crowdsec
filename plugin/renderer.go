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

	headerStyle  lipgloss.Style
	sectionStyle lipgloss.Style
	errorStyle   lipgloss.Style
	dimStyle     lipgloss.Style
	selectedStyle lipgloss.Style
	dialogStyle  lipgloss.Style
	statusStyle  lipgloss.Style
}

func newRenderer(actions *actionsClient, audit *auditLog, fetch *fetcher) *renderer {
	return &renderer{
		actions:       actions,
		audit:         audit,
		fetch:         fetch,
		durationBuf:   "24h",
		headerStyle:   lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12")),
		sectionStyle:  lipgloss.NewStyle().Bold(true).Underline(true),
		errorStyle:    lipgloss.NewStyle().Foreground(lipgloss.Color("9")),
		dimStyle:      lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
		// Cursor-marker style instead of Reverse: lipgloss.Reverse on the
		// whole line eats the leading whitespace indent and shifts the
		// selected row visually leftwards (Issue #3). Bold + accent colour
		// keeps the selection obvious without changing the row's geometry,
		// and the "▸ " cursor marker (replacing the two-space indent of
		// non-selected rows) gives an unambiguous visual cue for the
		// active line. Reuses the same accent shade as headerStyle for
		// stylistic coherence.
		selectedStyle: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12")),
		dialogStyle: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("11")).
			Padding(0, 1),
		statusStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("10")),
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
		b.WriteString(r.headerStyle.Render("CrowdSec — waiting for first fetch..."))
		b.WriteString("\n")
		// Pre-data: still show the footer so the user knows what's bound
		// before the first snapshot arrives.
		if r.mode == modeNormal {
			b.WriteString("\n")
			b.WriteString(r.dimStyle.Render(helpFooterText))
			b.WriteString("\n")
		}
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
	b.WriteString(r.headerStyle.Render(hdr))
	b.WriteString("\n")

	if r.snap.Err != nil {
		b.WriteString(r.errorStyle.Render("Error: " + r.snap.Err.Error()))
		b.WriteString("\n\n")
	}

	b.WriteString(r.sectionStyle.Render("Decisions (top 20 by remaining TTL)"))
	b.WriteString("\n")
	b.WriteString(r.renderDecisions(20))
	b.WriteString("\n")

	b.WriteString(r.sectionStyle.Render("Recent alerts"))
	b.WriteString("\n")
	b.WriteString(r.renderAlerts(20))

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

	// Inline help footer. Only shown in normal mode — confirm/input dialogs
	// have their own "[y/N]" / "Enter to confirm" hints, doubling up would
	// be visual noise.
	if r.mode == modeNormal {
		b.WriteString("\n")
		b.WriteString(r.dimStyle.Render(helpFooterText))
		b.WriteString("\n")
	}

	return b.String()
}

func (r *renderer) renderDecisions(limit int) string {
	if len(r.snap.Decisions) == 0 {
		return r.dimStyle.Render("  (none)") + "\n"
	}
	var b strings.Builder
	header := fmt.Sprintf("  %-19s %-12s %-30s %s\n", "VALUE", "ORIGIN", "SCENARIO", "TTL-REM")
	b.WriteString(r.dimStyle.Render(header))

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
		// Prefix swap keeps both selected and non-selected lines exactly
		// the same width so the column grid stays aligned. "▸ " is the
		// active marker, "  " (two spaces) is the inactive indent.
		prefix := "  "
		if i == r.selectedIdx {
			prefix = "▸ "
		}
		line := fmt.Sprintf("%s%-19s %-12s %-30s %s", prefix, val, origin, scenario, ttl)
		if i == r.selectedIdx {
			b.WriteString(r.selectedStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	if len(r.snap.Decisions) > limit {
		b.WriteString(r.dimStyle.Render(fmt.Sprintf("  ... %d more\n", len(r.snap.Decisions)-limit)))
	}
	return b.String()
}

func (r *renderer) renderAlerts(limit int) string {
	if len(r.snap.Alerts) == 0 {
		return r.dimStyle.Render("  (none)") + "\n"
	}
	var b strings.Builder
	header := fmt.Sprintf("  %-7s %-30s %-19s %s\n", "ID", "SCENARIO", "SOURCE", "CREATED")
	b.WriteString(r.dimStyle.Render(header))

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
		b.WriteString(fmt.Sprintf("  %-7d %-30s %-19s %s\n",
			a.ID,
			truncate(a.Scenario, 30),
			truncate(src, 19),
			created,
		))
	}
	if len(r.snap.Alerts) > limit {
		b.WriteString(r.dimStyle.Render(fmt.Sprintf("  ... %d more\n", len(r.snap.Alerts)-limit)))
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
	style := r.statusStyle
	if strings.HasPrefix(r.statusLine, "error:") || strings.HasPrefix(r.statusLine, "audit log") {
		style = r.errorStyle
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

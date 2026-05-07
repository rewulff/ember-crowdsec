package plugin

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// renderer holds the latest snapshot and lipgloss styles. Safe for concurrent
// use: Ember calls Update from the fetch goroutine and View from the TUI
// goroutine.
type renderer struct {
	mu      sync.RWMutex
	snap    snapshot
	hasData bool

	headerStyle  lipgloss.Style
	sectionStyle lipgloss.Style
	errorStyle   lipgloss.Style
	dimStyle     lipgloss.Style
}

func newRenderer() *renderer {
	return &renderer{
		headerStyle:  lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12")),
		sectionStyle: lipgloss.NewStyle().Bold(true).Underline(true),
		errorStyle:   lipgloss.NewStyle().Foreground(lipgloss.Color("9")),
		dimStyle:     lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
	}
}

// update stores the latest snapshot. Width/height are accepted but currently
// unused (we render at full available width using padding-only layout).
func (r *renderer) update(data any, _, _ int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if snap, ok := data.(snapshot); ok {
		r.snap = snap
		r.hasData = true
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
		return b.String()
	}

	hdr := fmt.Sprintf("CrowdSec — %d active decisions, %d alerts (last fetch %s)",
		len(r.snap.Decisions),
		len(r.snap.Alerts),
		r.snap.FetchedAt.Local().Format("15:04:05"),
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
		b.WriteString(fmt.Sprintf("  %-19s %-12s %-30s %s\n", val, origin, scenario, ttl))
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

func (r *renderer) activeDecisionCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.snap.Decisions)
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

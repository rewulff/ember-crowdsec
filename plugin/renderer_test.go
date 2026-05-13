package plugin

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// mkDecisions builds n synthetic decisions with stable values 10.0.0.1..10.0.0.n,
// origin "cscli", and scenario "ssh-bf". Used by the scroll-window tests to
// avoid depending on the mock LAPI for renderer-only behaviour.
func mkDecisions(n int) []Decision {
	out := make([]Decision, n)
	for i := 0; i < n; i++ {
		out[i] = Decision{
			ID:       int64(i + 1),
			Origin:   "cscli",
			Type:     "ban",
			Scope:    "Ip",
			Value:    fmt.Sprintf("10.0.0.%d", i+1),
			Scenario: "ssh-bf",
			Duration: "4h0m0s",
		}
	}
	return out
}

// newTestRenderer builds a renderer with minimal lipgloss styles wired up so
// renderDecisions can run without going through newRenderer's full setup.
// We populate just the styles renderDecisions touches.
func newTestRenderer() *renderer {
	return &renderer{
		titleStyle:       lipgloss.NewStyle(),
		tableHeaderStyle: lipgloss.NewStyle(),
		selectedRowStyle: lipgloss.NewStyle().Reverse(true),
		greyStyle:        lipgloss.NewStyle(),
	}
}

// TestScrollWindow_MidList: with a 15-element list and scrollOffset=6 / limit=5,
// the visible window is indices [6..10]. Selected row 10 must appear with the
// ">" prefix, "↑ 6 earlier" must be there, "↓ 4 more" must be there, and
// out-of-window values must NOT appear.
func TestScrollWindow_MidList(t *testing.T) {
	t.Parallel()

	r := newTestRenderer()
	r.snap = snapshot{Decisions: mkDecisions(15)}
	r.hasData = true
	r.selectedIdx = 10
	r.scrollOffset.Store(6)

	out := r.renderDecisions(5, 80)

	// Selected row 10 = "10.0.0.11" must be there, preceded by ">".
	if !strings.Contains(out, "10.0.0.11") {
		t.Errorf("missing selected decision 10.0.0.11 in window\n%s", out)
	}
	if !strings.Contains(out, ">10.0.0.11") {
		t.Errorf("selected row missing '>' prefix\n%s", out)
	}
	if !strings.Contains(out, "↑ 6 earlier") {
		t.Errorf("missing '↑ 6 earlier' marker\n%s", out)
	}
	if !strings.Contains(out, "↓ 4 more") {
		t.Errorf("missing '↓ 4 more' marker\n%s", out)
	}
	// Out-of-window indices 0/3/5 must NOT appear.
	for _, idx := range []int{1, 4, 6} { // values 10.0.0.1 / .4 / .6 = indices 0/3/5
		needle := fmt.Sprintf("10.0.0.%d ", idx)
		if strings.Contains(out, needle) {
			t.Errorf("out-of-window value %q leaked into output\n%s", needle, out)
		}
	}
}

// TestScrollWindow_Top: at the very top of the list, no "↑" marker, but
// "↓ N more" with the rest of the list count.
func TestScrollWindow_Top(t *testing.T) {
	t.Parallel()

	r := newTestRenderer()
	r.snap = snapshot{Decisions: mkDecisions(15)}
	r.hasData = true
	r.selectedIdx = 0
	r.scrollOffset.Store(0)

	out := r.renderDecisions(5, 80)

	if strings.Contains(out, "↑") {
		t.Errorf("'↑' marker present at top of list\n%s", out)
	}
	if !strings.Contains(out, "↓ 10 more") {
		t.Errorf("missing '↓ 10 more' marker at top\n%s", out)
	}
}

// TestDownKey_ScrollsWindow: with lastDecisionsCap=5, selectedIdx=4,
// scrollOffset=0, pressing "j" must advance both selectedIdx to 5 AND push
// scrollOffset to 1 (cursor crossed bottom of window).
func TestDownKey_ScrollsWindow(t *testing.T) {
	t.Parallel()

	r := newTestRenderer()
	r.snap = snapshot{Decisions: mkDecisions(15)}
	r.hasData = true
	r.selectedIdx = 4
	r.scrollOffset.Store(0)
	r.lastDecisionsCap.Store(5)

	r.mu.Lock()
	consumed := r.handleNormal(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	r.mu.Unlock()

	if !consumed {
		t.Fatal("handleNormal('j') returned false, want true")
	}
	if r.selectedIdx != 5 {
		t.Errorf("selectedIdx = %d, want 5", r.selectedIdx)
	}
	if got := r.scrollOffset.Load(); got != 1 {
		t.Errorf("scrollOffset = %d, want 1 (cursor crossed bottom of window)", got)
	}
}

// TestUpdate_NoFlickerOnTickRefresh: the most important test — TL-finding.
// When the same list is pushed via update() (typical tick-poll with no
// underlying change), scrollOffset MUST NOT snap to selectedIdx; the visible
// window must stay where the user parked it.
func TestUpdate_NoFlickerOnTickRefresh(t *testing.T) {
	t.Parallel()

	r := newTestRenderer()
	r.snap = snapshot{Decisions: mkDecisions(15)}
	r.hasData = true
	r.selectedIdx = 8
	r.scrollOffset.Store(4)

	// Same list pushed again via update().
	r.update(snapshot{Decisions: mkDecisions(15)}, 0, 0)

	if got := r.scrollOffset.Load(); got != 4 {
		t.Errorf("scrollOffset = %d after no-op tick refresh, want 4 (no snap to selectedIdx)", got)
	}
	if r.selectedIdx != 8 {
		t.Errorf("selectedIdx = %d after no-op refresh, want 8", r.selectedIdx)
	}
}

// TestUpdate_ClampOnShrink: when the list shrinks below scrollOffset, both
// scrollOffset and selectedIdx must clamp to valid indices.
func TestUpdate_ClampOnShrink(t *testing.T) {
	t.Parallel()

	r := newTestRenderer()
	r.snap = snapshot{Decisions: mkDecisions(15)}
	r.hasData = true
	r.selectedIdx = 12
	r.scrollOffset.Store(10)

	// Shrink to 3 decisions.
	r.update(snapshot{Decisions: mkDecisions(3)}, 0, 0)

	if got := r.scrollOffset.Load(); got > 2 || got < 0 {
		t.Errorf("scrollOffset = %d after shrink to 3, want 0..2", got)
	}
	if r.selectedIdx > 2 || r.selectedIdx < 0 {
		t.Errorf("selectedIdx = %d after shrink to 3, want 0..2", r.selectedIdx)
	}
}

// TestHandleNormal_PreFirstRenderFallback: if view() never ran,
// lastDecisionsCap is still 0. handleNormal must use the sectionMinRows
// fallback so navigation does not panic and scrollOffset stays sane.
func TestHandleNormal_PreFirstRenderFallback(t *testing.T) {
	t.Parallel()

	r := newTestRenderer()
	r.snap = snapshot{Decisions: mkDecisions(10)}
	r.hasData = true
	// lastDecisionsCap left at 0 — view() never ran.

	// 6× down. With fallback limit = sectionMinRows = 5, after the cursor
	// reaches index 5 the window pushes; after index 6 it pushes once more.
	for i := 0; i < 6; i++ {
		r.mu.Lock()
		r.handleNormal(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
		r.mu.Unlock()
	}

	if r.selectedIdx != 6 {
		t.Errorf("selectedIdx after 6×down = %d, want 6", r.selectedIdx)
	}
	off := r.scrollOffset.Load()
	if off <= 0 || int(off) > r.selectedIdx {
		t.Errorf("scrollOffset = %d after 6×down with fallback limit, want >0 and <=selectedIdx=%d", off, r.selectedIdx)
	}
}

// TestView_ResizeShrinksLimit: if the terminal is resized smaller so the
// cursor falls outside the visible window, view()'s resize-correction must
// lift scrollOffset just enough to keep selectedIdx in the new window.
func TestView_ResizeShrinksLimit(t *testing.T) {
	t.Parallel()

	r := newRenderer(nil, nil, nil) // need full style setup for view()
	r.snap = snapshot{Decisions: mkDecisions(15)}
	r.hasData = true
	r.selectedIdx = 10
	r.scrollOffset.Store(6)

	// First render with a large height — cursor at 10, window [6..15]
	// after limit clamp to 10 (sectionMaxRows). Cursor is visible.
	_ = r.view(120, 80)
	// scrollOffset should be unchanged or only mildly adjusted; cursor at
	// 10 fits inside any window starting at <=6 with limit >=5.

	// Now simulate a tiny terminal. computeSectionCaps(10,false) returns
	// (sectionMinRows, sectionMinRows) = (5,5) — limit drops to 5.
	// scrollOffset=6 + limit=5 = window [6..11). selectedIdx=10 is inside.
	// So set up the worse case: limit shrinks to 3 (cursor outside).
	// We can't actually get limit=3 from computeSectionCaps without
	// rewriting it, so directly assert the principle: after view() with
	// limit=10 (height=80), the window must contain the cursor.
	off := r.scrollOffset.Load()
	limit := r.lastDecisionsCap.Load()
	if int(off+limit) <= r.selectedIdx {
		t.Errorf("after view(120,80): scrollOffset=%d limit=%d, cursor %d not in window", off, limit, r.selectedIdx)
	}

	// Force a worst-case scenario: artificially set lastDecisionsCap to a
	// small value and selectedIdx outside, then re-render with the small
	// limit. The resize-correction inside view() runs every call.
	r.scrollOffset.Store(0)
	r.selectedIdx = 10
	// view() will compute decisionsCap from height; height=24 yields cap=5.
	_ = r.view(120, 24)
	off = r.scrollOffset.Load()
	limit = r.lastDecisionsCap.Load()
	if limit <= 0 {
		t.Fatalf("lastDecisionsCap = %d, want >0 after view()", limit)
	}
	if int(off) > r.selectedIdx || int(off+limit) <= r.selectedIdx {
		t.Errorf("after view(120,24): scrollOffset=%d limit=%d, cursor %d not in window [%d,%d)",
			off, limit, r.selectedIdx, off, off+limit)
	}
}

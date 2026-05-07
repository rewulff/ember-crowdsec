package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	emberplugin "github.com/alexandre-daubois/ember/pkg/plugin"
)

// ---------------------------------------------------------------------------
// Mock LAPI infrastructure
// ---------------------------------------------------------------------------

// mockLAPI bundles a httptest.Server with hit counters and tunable behaviour.
// Goal: zero external deps (stdlib only) and full control over auth + payload
// shape so the three test paths (happy-path, JWT refresh, 401 retry) can be
// exercised in isolation.
type mockLAPI struct {
	srv *httptest.Server

	// Counters — atomic so we can read them while the server is alive.
	loginHits           atomic.Int32
	decisionsHits       atomic.Int32
	alertsHits          atomic.Int32
	deleteDecisionsHits atomic.Int32
	postAlertsHits      atomic.Int32

	// Behaviour knobs.
	tokenLifetime         time.Duration // sent as `expire` in login response
	expectMachineID       string
	expectMachinePassword string
	expectBouncerKey      string
	currentToken          atomic.Value // string — issued JWT, rotates per login

	// failNextDecisions, when >0, causes the decisions handler to return 401
	// that many times before serving 200. Lets us exercise the one-retry
	// path in fetcher.authedGet.
	failNextDecisions atomic.Int32

	// failNextDelete, when >0, causes DELETE /v1/decisions/{id} to return
	// 500 that many times. Used to verify audit-log captures failures.
	failNextDelete atomic.Int32

	// alertsScenario is exposed so tests can assert it appears in View output.
	alertsScenario string
	// decisionValues are the IPs returned in /v1/decisions; tests assert at
	// least one of them shows up in View output.
	decisionValues []string

	// Captured POST /v1/alerts bodies for whitelist verification.
	postedAlertsMu sync.Mutex
	postedAlerts   [][]alertCreateRequest

	// lastDecisionsQuery captures the raw query string of the most recent
	// GET /v1/decisions, so origin-filter tests can assert on it without
	// shipping a custom transport.
	lastDecisionsMu    sync.Mutex
	lastDecisionsQuery string
}

func newMockLAPI(t *testing.T) *mockLAPI {
	t.Helper()
	m := &mockLAPI{
		tokenLifetime:         30 * time.Minute,
		expectMachineID:       "ember-tui-test",
		expectMachinePassword: "s3cret-mock",
		expectBouncerKey:      "bouncer-key-mock",
		alertsScenario:        "crowdsecurity/http-bf",
		decisionValues:        []string{"203.0.113.10", "198.51.100.42", "192.0.2.7"},
	}
	m.currentToken.Store("")

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/watchers/login", m.handleLogin)
	mux.HandleFunc("/v1/decisions", m.handleDecisions)        // GET (bouncer)
	mux.HandleFunc("/v1/decisions/", m.handleDecisionDelete)  // DELETE /v1/decisions/{id}
	mux.HandleFunc("/v1/alerts", m.handleAlerts)              // GET (jwt) + POST (jwt)

	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockLAPI) URL() string { return m.srv.URL }

func (m *mockLAPI) handleLogin(w http.ResponseWriter, r *http.Request) {
	m.loginHits.Add(1)
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}

	var body loginRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if body.MachineID != m.expectMachineID || body.Password != m.expectMachinePassword {
		http.Error(w, "bad creds", http.StatusUnauthorized)
		return
	}

	// Rotate token so the refresh test can detect the change side-effect on
	// the wire (different Bearer per login). Counter alone is sufficient for
	// the assertion, but the rotation also guards against silent token reuse
	// bugs in authClient.
	tok := fmt.Sprintf("dummy-jwt-%d", m.loginHits.Load())
	m.currentToken.Store(tok)

	resp := loginResponse{
		Code:   200,
		Token:  tok,
		Expire: time.Now().Add(m.tokenLifetime).UTC().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// requireBearer returns true if the request carries a Bearer header matching
// the currently issued token. On mismatch it writes 401 and returns false.
func (m *mockLAPI) requireBearer(w http.ResponseWriter, r *http.Request) bool {
	want, _ := m.currentToken.Load().(string)
	got := r.Header.Get("Authorization")
	if want == "" || got != "Bearer "+want {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (m *mockLAPI) handleDecisions(w http.ResponseWriter, r *http.Request) {
	m.decisionsHits.Add(1)

	// Forced-fail mode for the bouncer-key invalid-test. We still consume
	// the X-Api-Key check AFTER the forced fail so the path validates the
	// bouncer credential separately.
	if remaining := m.failNextDecisions.Load(); remaining > 0 {
		m.failNextDecisions.Add(-1)
		http.Error(w, "forced 401", http.StatusUnauthorized)
		return
	}

	// Auth: bouncer X-Api-Key header. Fetcher must NOT send Authorization.
	if got := r.Header.Get("X-Api-Key"); got != m.expectBouncerKey {
		http.Error(w, "invalid api key", http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Authorization") != "" {
		http.Error(w, "decisions does not accept Bearer", http.StatusUnauthorized)
		return
	}

	// Capture raw query for tests asserting on the origins filter.
	m.lastDecisionsMu.Lock()
	m.lastDecisionsQuery = r.URL.RawQuery
	m.lastDecisionsMu.Unlock()

	// Mimic LAPI's server-side origin filter. ?origins=a,b restricts the
	// response to those origins; absent param returns all origins. Three
	// decisions: two operator-controlled (crowdsec + cscli) + one CAPI/list
	// row to exercise the CAPI-block + filter paths.
	all := []Decision{
		{
			ID: 1, Origin: "crowdsec", Type: "ban", Scope: "Ip",
			Value: m.decisionValues[0], Scenario: "crowdsecurity/http-bf", Duration: "4h0m0s",
		},
		{
			ID: 2, Origin: "cscli", Type: "ban", Scope: "Ip",
			Value: m.decisionValues[1], Scenario: "manual", Duration: "1h0m0s",
		},
		{
			ID: 3, Origin: "lists:firehol", Type: "ban", Scope: "Ip",
			Value: m.decisionValues[2], Scenario: "lists/firehol_cybercrime", Duration: "10m0s",
		},
	}

	out := all
	if originsParam := r.URL.Query().Get("origins"); originsParam != "" {
		allowed := map[string]bool{}
		for _, o := range strings.Split(originsParam, ",") {
			allowed[strings.TrimSpace(o)] = true
		}
		out = out[:0]
		for _, d := range all {
			if allowed[d.Origin] {
				out = append(out, d)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// lastDecisionsQueryStr returns a thread-safe copy of the most recent
// GET /v1/decisions raw query string.
func (m *mockLAPI) lastDecisionsQueryStr() string {
	m.lastDecisionsMu.Lock()
	defer m.lastDecisionsMu.Unlock()
	return m.lastDecisionsQuery
}

func (m *mockLAPI) handleAlerts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		m.handleAlertsGet(w, r)
	case http.MethodPost:
		m.handleAlertsPost(w, r)
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func (m *mockLAPI) handleAlertsGet(w http.ResponseWriter, r *http.Request) {
	m.alertsHits.Add(1)
	if !m.requireBearer(w, r) {
		return
	}

	// Briefing requires assertion on `since` query-param presence.
	if since := r.URL.Query().Get("since"); since == "" {
		http.Error(w, "missing since", http.StatusBadRequest)
		return
	}

	out := []Alert{
		{
			ID:         101,
			Scenario:   m.alertsScenario,
			Message:    "http brute-force from 203.0.113.10",
			CreatedAt:  time.Now().UTC().Format(time.RFC3339),
			Source:     AlertSource{IP: "203.0.113.10", Value: "203.0.113.10", Scope: "Ip"},
			EventCount: 42,
		},
		{
			ID:         102,
			Scenario:   "crowdsecurity/ssh-bf",
			Message:    "ssh brute-force from 198.51.100.42",
			CreatedAt:  time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339),
			Source:     AlertSource{IP: "198.51.100.42", Value: "198.51.100.42", Scope: "Ip"},
			EventCount: 7,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// handleAlertsPost mocks the cscli "decisions add" path (whitelist + manual
// bans). Captures the body for assertion in tests.
func (m *mockLAPI) handleAlertsPost(w http.ResponseWriter, r *http.Request) {
	m.postAlertsHits.Add(1)
	if !m.requireBearer(w, r) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var alerts []alertCreateRequest
	if err := json.Unmarshal(body, &alerts); err != nil {
		http.Error(w, "bad alert body: "+err.Error(), http.StatusBadRequest)
		return
	}
	m.postedAlertsMu.Lock()
	m.postedAlerts = append(m.postedAlerts, alerts)
	m.postedAlertsMu.Unlock()

	// CrowdSec swagger says POST /v1/alerts returns 201 with []string of
	// created alert IDs. We mimic that for realism.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode([]string{"42"})
}

// handleDecisionDelete mocks DELETE /v1/decisions/{id}. failNextDelete>0
// returns 500 to exercise the audit-log-on-failure path.
func (m *mockLAPI) handleDecisionDelete(w http.ResponseWriter, r *http.Request) {
	m.deleteDecisionsHits.Add(1)
	if r.Method != http.MethodDelete {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if remaining := m.failNextDelete.Load(); remaining > 0 {
		m.failNextDelete.Add(-1)
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	}
	if !m.requireBearer(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"nbDeleted": "1"})
}

// firstPostedAlert returns the first captured POST /v1/alerts body, or nil
// if none. Concurrent-safe.
func (m *mockLAPI) firstPostedAlert() []alertCreateRequest {
	m.postedAlertsMu.Lock()
	defer m.postedAlertsMu.Unlock()
	if len(m.postedAlerts) == 0 {
		return nil
	}
	return m.postedAlerts[0]
}

// provisionPlugin builds a CrowdSecPlugin pointed at the mock LAPI. The
// audit log is anchored under t.TempDir() so tests are independent.
func provisionPlugin(t *testing.T, m *mockLAPI) *CrowdSecPlugin {
	t.Helper()
	p := &CrowdSecPlugin{}
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	cfg := emberplugin.PluginConfig{
		CaddyAddr: "http://127.0.0.1:2019", // unused by plugin; populated for realism
		Options: map[string]string{
			"lapi_url":         m.URL(),
			"machine_id":       m.expectMachineID,
			"machine_password": m.expectMachinePassword,
			"bouncer_key":      m.expectBouncerKey,
			"alerts_since":     "24h",
			"insecure_tls":     "false",
			"audit_log":        auditPath,
		},
	}
	if err := p.Provision(context.Background(), cfg); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return p
}

// auditLines reads back the audit log from the plugin's audit-log path
// and returns one parsed entry per line.
func auditLines(t *testing.T, p *CrowdSecPlugin) []auditEntry {
	t.Helper()
	if p.audit == nil || p.audit.path == "" {
		return nil
	}
	f, err := os.Open(p.audit.path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()
	var out []auditEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e auditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("parse audit line %q: %v", sc.Text(), err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan audit log: %v", err)
	}
	return out
}

// fetchAndUpdate calls Fetch + Update so the renderer state reflects the
// snapshot. Mirrors the production loop without going through Ember's tick
// scheduler.
func fetchAndUpdate(t *testing.T, p *CrowdSecPlugin) snapshot {
	t.Helper()
	data, err := p.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	snap, ok := data.(snapshot)
	if !ok {
		t.Fatalf("Fetch returned %T, want snapshot", data)
	}
	p.Update(snap, 100, 30)
	return snap
}

// ---------------------------------------------------------------------------
// Test 1: Happy path
// ---------------------------------------------------------------------------

func TestLAPI_HappyPath(t *testing.T) {
	t.Parallel()

	m := newMockLAPI(t)
	p := provisionPlugin(t, m)

	snap := fetchAndUpdate(t, p)

	if snap.Err != nil {
		t.Fatalf("snapshot.Err = %v, want nil", snap.Err)
	}
	// Default filter is origins=crowdsec,cscli (Iteration 3). Mock returns
	// 2 of 3 mock decisions (firehol-list is filtered out server-side).
	if got, want := len(snap.Decisions), 2; got != want {
		t.Fatalf("decisions count = %d, want %d (default filter dropped firehol-list)", got, want)
	}
	if got, want := len(snap.Alerts), 2; got != want {
		t.Fatalf("alerts count = %d, want %d", got, want)
	}

	// Login exactly once for the first fetch.
	if got := m.loginHits.Load(); got != 1 {
		t.Errorf("loginHits = %d, want 1", got)
	}

	view := p.View(100, 30)

	// At least one of the kept decision IPs must surface in View output.
	// Skip the firehol IP (m.decisionValues[2]) which the default filter
	// removes server-side.
	foundIP := false
	for _, ip := range m.decisionValues[:2] {
		if strings.Contains(view, ip) {
			foundIP = true
			break
		}
	}
	if !foundIP {
		t.Errorf("View did not contain any decision IP from %v\nview:\n%s", m.decisionValues[:2], view)
	}

	// Alerts scenario must surface.
	if !strings.Contains(view, m.alertsScenario) {
		t.Errorf("View missing alerts scenario %q\nview:\n%s", m.alertsScenario, view)
	}

	// StatusCount() must equal the number of active decisions ("2").
	if got, want := p.StatusCount(), "2"; got != want {
		t.Errorf("StatusCount = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// Test 2: JWT refresh on near-expiry
// ---------------------------------------------------------------------------

// authClient.Token() refreshes when time.Until(expiresAt) <= 60s. Rather than
// shipping a 70+s sleep into the test suite (which would defeat -race speed),
// we drive the same code path by stamping the cached expiresAt to "expired"
// between fetches. This is white-box testing: same package, deliberate access
// to internal state. The contract being verified is "second fetch performs a
// fresh login when the cached token is no longer fresh", which is exactly
// what authClient.loginLocked is invoked for.
func TestLAPI_JWTRefreshOnExpiry(t *testing.T) {
	t.Parallel()

	m := newMockLAPI(t)
	p := provisionPlugin(t, m)

	// First fetch — triggers initial login.
	_ = fetchAndUpdate(t, p)
	if got := m.loginHits.Load(); got != 1 {
		t.Fatalf("after first fetch loginHits = %d, want 1", got)
	}
	firstToken, _ := m.currentToken.Load().(string)

	// Force the cached token into the refresh window. Setting expiresAt to
	// 30s in the future lands inside the 60s pre-expiry refresh band so the
	// next Token() call MUST relogin. We hold the lock to mirror authClient
	// invariants — even though no concurrent code is running, the lock
	// also documents the intent.
	p.auth.mu.Lock()
	p.auth.expiresAt = time.Now().Add(30 * time.Second)
	p.auth.mu.Unlock()

	// Second fetch — must trigger a fresh login.
	_ = fetchAndUpdate(t, p)
	if got := m.loginHits.Load(); got != 2 {
		t.Fatalf("after second fetch loginHits = %d, want 2 (refresh did not happen)", got)
	}
	secondToken, _ := m.currentToken.Load().(string)
	if firstToken == secondToken {
		t.Errorf("token did not rotate after refresh: first=%q second=%q", firstToken, secondToken)
	}

	// Both fetches must have populated decisions+alerts hits (parallel, so 2 each).
	if got, want := m.decisionsHits.Load(), int32(2); got != want {
		t.Errorf("decisionsHits = %d, want %d", got, want)
	}
	if got, want := m.alertsHits.Load(), int32(2); got != want {
		t.Errorf("alertsHits = %d, want %d", got, want)
	}
}

// ---------------------------------------------------------------------------
// Test 3: Decisions bouncer-key invalid → no retry, error surfaces
// ---------------------------------------------------------------------------

// The bouncer key is static (cscli bouncers add output) and not refreshable
// from inside the plugin. Therefore a 401 on /v1/decisions must NOT trigger
// any kind of refresh — instead the snapshot's Err field carries a clear
// "bouncer key invalid" message, and alerts (which use JWT) still succeed.
func TestDecisions_BouncerKeyInvalid_NoRetry(t *testing.T) {
	t.Parallel()

	m := newMockLAPI(t)
	m.failNextDecisions.Store(1)

	p := provisionPlugin(t, m)

	snap := fetchAndUpdate(t, p)

	if snap.Err == nil {
		t.Fatalf("snapshot.Err = nil, want a 'bouncer key invalid' error")
	}
	if !strings.Contains(snap.Err.Error(), "bouncer key invalid") {
		t.Errorf("snapshot.Err = %q, want contains 'bouncer key invalid'", snap.Err.Error())
	}
	if got := m.decisionsHits.Load(); got != 1 {
		t.Errorf("decisionsHits = %d, want 1 (no retry)", got)
	}
	if got, want := len(snap.Alerts), 2; got != want {
		t.Errorf("alerts count = %d, want %d (alerts must still succeed)", got, want)
	}
}

// ---------------------------------------------------------------------------
// Test 4: Decisions request must use X-Api-Key, not Authorization Bearer
// ---------------------------------------------------------------------------

// Whitebox check: the decisions handler asserts both that the X-Api-Key is
// present AND that no Authorization header was sent. If the fetcher
// regresses and slaps a Bearer on /v1/decisions, the mock returns 401 and
// the snapshot.Err would not be nil.
func TestDecisions_BouncerKeyHeader(t *testing.T) {
	t.Parallel()

	m := newMockLAPI(t)
	p := provisionPlugin(t, m)

	snap := fetchAndUpdate(t, p)

	if snap.Err != nil {
		t.Fatalf("snapshot.Err = %v, want nil (decisions auth header regressed?)", snap.Err)
	}
	// Iter 3 default filter drops the firehol-list mock; expect 2 kept.
	if got, want := len(snap.Decisions), 2; got != want {
		t.Fatalf("decisions count = %d, want %d", got, want)
	}
}

// ---------------------------------------------------------------------------
// Test 5: Delete decision happy path + audit
// ---------------------------------------------------------------------------

func TestDelete_HappyPath(t *testing.T) {
	t.Parallel()

	m := newMockLAPI(t)
	p := provisionPlugin(t, m)

	if err := p.actions.DeleteDecision(context.Background(), 4242); err != nil {
		t.Fatalf("DeleteDecision: %v", err)
	}
	if got, want := m.deleteDecisionsHits.Load(), int32(1); got != want {
		t.Errorf("deleteDecisionsHits = %d, want %d", got, want)
	}

	// Audit-log must be NOT empty even though the renderer wasn't involved
	// — actions API doesn't auto-audit, so we drive it via the renderer
	// path in TestRenderer_UnbanFlow. Here we exercise it directly:
	p.audit.recordUnban(4242, "1.2.3.4", "")

	entries := auditLines(t, p)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	if entries[0].Action != "unban" || entries[0].Status != "ok" || entries[0].DecisionID != 4242 {
		t.Errorf("audit entry = %+v, want unban/ok/4242", entries[0])
	}
}

// ---------------------------------------------------------------------------
// Test 6: Whitelist happy path + body verification + audit
// ---------------------------------------------------------------------------

func TestWhitelist_HappyPath(t *testing.T) {
	t.Parallel()

	m := newMockLAPI(t)
	p := provisionPlugin(t, m)

	if err := p.actions.WhitelistIP(context.Background(), "5.6.7.8", "12h", "test-reason"); err != nil {
		t.Fatalf("WhitelistIP: %v", err)
	}
	if got, want := m.postAlertsHits.Load(), int32(1); got != want {
		t.Errorf("postAlertsHits = %d, want %d", got, want)
	}

	posted := m.firstPostedAlert()
	if len(posted) != 1 {
		t.Fatalf("posted alerts = %d, want 1", len(posted))
	}
	alert := posted[0]
	if len(alert.Decisions) != 1 {
		t.Fatalf("alert.decisions = %d, want 1", len(alert.Decisions))
	}
	dec := alert.Decisions[0]
	if dec.Type == nil || *dec.Type != "whitelist" {
		t.Errorf("decision type = %v, want %q", dec.Type, "whitelist")
	}
	if dec.Value == nil || *dec.Value != "5.6.7.8" {
		t.Errorf("decision value = %v, want %q", dec.Value, "5.6.7.8")
	}
	if dec.Duration == nil || *dec.Duration != "12h" {
		t.Errorf("decision duration = %v, want %q", dec.Duration, "12h")
	}
	if dec.Origin == nil || *dec.Origin != "ember-tui" {
		t.Errorf("decision origin = %v, want %q", dec.Origin, "ember-tui")
	}
	if alert.Source == nil || alert.Source.IP != "5.6.7.8" {
		t.Errorf("alert.source.ip = %v, want %q", alert.Source, "5.6.7.8")
	}

	// Drive the audit through the renderer-style helper to lock in the wire
	// format check.
	p.audit.recordWhitelist("5.6.7.8", "12h", "test-reason", "")
	entries := auditLines(t, p)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Action != "whitelist" || e.IP != "5.6.7.8" || e.Duration != "12h" || e.Status != "ok" {
		t.Errorf("audit entry = %+v, want whitelist/5.6.7.8/12h/ok", e)
	}
}

// ---------------------------------------------------------------------------
// Test 7: Audit is also written on action failure
// ---------------------------------------------------------------------------

func TestAuditLog_AlsoOnFailure(t *testing.T) {
	t.Parallel()

	m := newMockLAPI(t)
	m.failNextDelete.Store(99) // every delete returns 500
	p := provisionPlugin(t, m)

	err := p.actions.DeleteDecision(context.Background(), 9999)
	if err == nil {
		t.Fatalf("DeleteDecision returned nil, want error")
	}
	p.audit.recordUnban(9999, "9.9.9.9", err.Error())

	entries := auditLines(t, p)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	if entries[0].Status != "error" || entries[0].Error == "" {
		t.Errorf("audit entry status = %q error = %q, want error/non-empty", entries[0].Status, entries[0].Error)
	}
}

// ---------------------------------------------------------------------------
// Test 8: Renderer end-to-end unban flow via key events
// ---------------------------------------------------------------------------

// Drives the Bubble Tea key sequence d → y to verify the renderer locks
// keyboard input, fires DeleteDecision, and writes an "ok" audit entry.
func TestRenderer_UnbanFlow(t *testing.T) {
	t.Parallel()

	m := newMockLAPI(t)
	p := provisionPlugin(t, m)
	_ = fetchAndUpdate(t, p)

	// Press 'd' on first decision (top of list after sort by TTL).
	if !p.HandleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}}) {
		t.Fatal("HandleKey('d') returned false, want true (selection lock-out)")
	}
	if !p.HandleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}}) {
		t.Fatal("HandleKey('y') returned false, want true")
	}

	if got, want := m.deleteDecisionsHits.Load(), int32(1); got != want {
		t.Errorf("deleteDecisionsHits = %d, want %d", got, want)
	}
	entries := auditLines(t, p)
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	if entries[0].Action != "unban" || entries[0].Status != "ok" {
		t.Errorf("audit entry = %+v, want unban/ok", entries[0])
	}
}

// ---------------------------------------------------------------------------
// Test 9: Renderer whitelist flow with duration input
// ---------------------------------------------------------------------------

func TestRenderer_WhitelistFlow(t *testing.T) {
	t.Parallel()

	m := newMockLAPI(t)
	p := provisionPlugin(t, m)
	_ = fetchAndUpdate(t, p)

	// w → backspace*3 → "1h" → enter → y
	keys := []tea.KeyMsg{
		{Type: tea.KeyRunes, Runes: []rune{'w'}},
		{Type: tea.KeyBackspace}, // erase "h"
		{Type: tea.KeyBackspace}, // erase "4"
		{Type: tea.KeyBackspace}, // erase "2"
		{Type: tea.KeyRunes, Runes: []rune{'1'}},
		{Type: tea.KeyRunes, Runes: []rune{'h'}},
		{Type: tea.KeyEnter},
		{Type: tea.KeyRunes, Runes: []rune{'y'}},
	}
	for i, k := range keys {
		if !p.HandleKey(k) {
			t.Fatalf("HandleKey #%d %v returned false, want true", i, k)
		}
	}

	if got, want := m.postAlertsHits.Load(), int32(1); got != want {
		t.Errorf("postAlertsHits = %d, want %d", got, want)
	}
	posted := m.firstPostedAlert()
	if len(posted) != 1 || len(posted[0].Decisions) != 1 {
		t.Fatalf("posted alert shape unexpected: %+v", posted)
	}
	if d := posted[0].Decisions[0]; d.Duration == nil || *d.Duration != "1h" {
		t.Errorf("decision duration = %v, want %q", d.Duration, "1h")
	}

	entries := auditLines(t, p)
	if len(entries) != 1 || entries[0].Action != "whitelist" || entries[0].Duration != "1h" {
		t.Errorf("audit = %+v, want whitelist/1h", entries)
	}
}

// ---------------------------------------------------------------------------
// Test 10: Default fetch carries origins=crowdsec,cscli filter
// ---------------------------------------------------------------------------

// Locks in the Iteration 3 default: GET /v1/decisions must server-side filter
// to the operator-controlled origins. Without this, on a busy CrowdSec node
// the response can be 50k+ rows (CAPI Threat Intel + community lists) and
// overwhelms the TUI for the wrong reason.
func TestFetcher_DefaultOriginsFilter(t *testing.T) {
	t.Parallel()

	m := newMockLAPI(t)
	p := provisionPlugin(t, m)

	snap := fetchAndUpdate(t, p)

	if snap.Err != nil {
		t.Fatalf("snapshot.Err = %v, want nil", snap.Err)
	}
	q := m.lastDecisionsQueryStr()
	values, err := url.ParseQuery(q)
	if err != nil {
		t.Fatalf("parse query %q: %v", q, err)
	}
	got := values.Get("origins")
	if got != "crowdsec,cscli" {
		t.Errorf("origins query param = %q, want %q (raw query: %q)", got, "crowdsec,cscli", q)
	}
	// Mock filters server-side, so the firehol-list row is dropped.
	if n := len(snap.Decisions); n != 2 {
		t.Errorf("decisions = %d, want 2 after default filter", n)
	}
	for _, d := range snap.Decisions {
		if !originLocal(d.Origin) {
			t.Errorf("default fetch returned non-local origin %q (decision %d)", d.Origin, d.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 11: showCAPI=true drops the origins filter
// ---------------------------------------------------------------------------

// When the user toggles 'c' on, the next fetch must not carry an origins
// param. Mock returns all 3 decisions in this case (incl. firehol-list).
func TestFetcher_ShowCAPI_NoFilter(t *testing.T) {
	t.Parallel()

	m := newMockLAPI(t)
	p := provisionPlugin(t, m)

	p.fetch.SetIncludeCAPI(true)

	snap := fetchAndUpdate(t, p)

	if snap.Err != nil {
		t.Fatalf("snapshot.Err = %v, want nil", snap.Err)
	}
	q := m.lastDecisionsQueryStr()
	values, err := url.ParseQuery(q)
	if err != nil {
		t.Fatalf("parse query %q: %v", q, err)
	}
	if got := values.Get("origins"); got != "" {
		t.Errorf("origins query param = %q, want empty when includeCAPI=true (raw: %q)", got, q)
	}
	if n := len(snap.Decisions); n != 3 {
		t.Errorf("decisions = %d, want 3 with no filter (incl. firehol-list)", n)
	}
}

// ---------------------------------------------------------------------------
// Test 12: Hotkey 'c' toggles includeCAPI and updates the header
// ---------------------------------------------------------------------------

// Verifies the renderer-side wiring: pressing 'c' must flip the fetcher's
// atomic and the header text must reflect the new state immediately.
func TestRenderer_ToggleCAPI(t *testing.T) {
	t.Parallel()

	m := newMockLAPI(t)
	p := provisionPlugin(t, m)
	_ = fetchAndUpdate(t, p)

	if p.fetch.IncludeCAPI() {
		t.Fatal("includeCAPI default = true, want false")
	}
	view := p.View(120, 40)
	if !strings.Contains(view, "filter: local+manual, c: include CAPI") {
		t.Errorf("default view header missing filter hint:\n%s", view)
	}

	if !p.HandleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}}) {
		t.Fatal("HandleKey('c') returned false, want true (key consumed)")
	}
	if !p.fetch.IncludeCAPI() {
		t.Fatal("after 'c' includeCAPI = false, want true")
	}
	view = p.View(120, 40)
	if !strings.Contains(view, "filter: ALL, c: hide CAPI") {
		t.Errorf("after-toggle view header missing CAPI-on hint:\n%s", view)
	}

	// Toggle back.
	if !p.HandleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}}) {
		t.Fatal("HandleKey('c') second press returned false")
	}
	if p.fetch.IncludeCAPI() {
		t.Fatal("after second 'c' includeCAPI = true, want false")
	}
}

// ---------------------------------------------------------------------------
// Test 13: 'd' on a CAPI/list decision is blocked with a status hint
// ---------------------------------------------------------------------------

// Selects the firehol-list row (only visible when CAPI is included), presses
// 'd', and asserts: no confirm dialog opens, mode stays normal, status line
// suggests whitelist, and no DELETE request was sent.
func TestRenderer_BlockUnbanCAPI(t *testing.T) {
	t.Parallel()

	m := newMockLAPI(t)
	p := provisionPlugin(t, m)
	p.fetch.SetIncludeCAPI(true) // need the firehol row visible
	_ = fetchAndUpdate(t, p)

	// Locate the non-local decision in the snapshot order; sort is by TTL
	// desc so the 10m firehol row is last.
	idx := -1
	for i, d := range p.render.snap.Decisions {
		if !originLocal(d.Origin) {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("no non-local decision in snapshot: %+v", p.render.snap.Decisions)
	}
	p.render.mu.Lock()
	p.render.selectedIdx = idx
	p.render.mu.Unlock()

	beforeDeletes := m.deleteDecisionsHits.Load()
	beforeAuditLines := len(auditLines(t, p))

	if !p.HandleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}}) {
		t.Fatal("HandleKey('d') returned false, want true (key consumed)")
	}

	// Mode must stay normal — no confirm dialog.
	p.render.mu.RLock()
	mode := p.render.mode
	status := p.render.statusLine
	pending := p.render.pendingDecision
	p.render.mu.RUnlock()
	if mode != modeNormal {
		t.Errorf("mode = %v after blocked 'd', want modeNormal", mode)
	}
	if pending != nil {
		t.Errorf("pendingDecision = %+v after blocked 'd', want nil", pending)
	}
	if !strings.Contains(status, "Cannot unban") || !strings.Contains(status, "whitelist") {
		t.Errorf("status line = %q, want hint about whitelist", status)
	}
	if got := m.deleteDecisionsHits.Load(); got != beforeDeletes {
		t.Errorf("DELETE was sent (%d -> %d) but block should prevent it", beforeDeletes, got)
	}
	if got := len(auditLines(t, p)); got != beforeAuditLines {
		t.Errorf("audit log grew (%d -> %d) on blocked unban; nothing should be recorded", beforeAuditLines, got)
	}
}

// ---------------------------------------------------------------------------
// Test 14: 'd' on a local (crowdsec) decision still opens the confirm dialog
// ---------------------------------------------------------------------------

// Sister-test to TestRenderer_BlockUnbanCAPI: makes sure we did not over-block
// — origin "crowdsec" must still produce the confirm dialog. Pressing 'n'
// cancels so we don't actually hit DELETE here.
func TestRenderer_AllowUnbanLocal(t *testing.T) {
	t.Parallel()

	m := newMockLAPI(t)
	p := provisionPlugin(t, m)
	_ = fetchAndUpdate(t, p)

	// Top-of-list after sort by TTL desc is the 4h crowdsec decision.
	if !p.HandleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}}) {
		t.Fatal("HandleKey('d') returned false")
	}

	p.render.mu.RLock()
	mode := p.render.mode
	pending := p.render.pendingDecision
	p.render.mu.RUnlock()

	if mode != modeConfirmUnban {
		t.Fatalf("mode = %v after 'd' on local decision, want modeConfirmUnban", mode)
	}
	if pending == nil || !originLocal(pending.Origin) {
		t.Fatalf("pendingDecision = %+v, want non-nil with local origin", pending)
	}

	// Cancel so we don't fire DELETE.
	if !p.HandleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}}) {
		t.Fatal("HandleKey('n') returned false")
	}
	if got := m.deleteDecisionsHits.Load(); got != 0 {
		t.Errorf("DELETE was sent despite cancel, got %d hits", got)
	}
}

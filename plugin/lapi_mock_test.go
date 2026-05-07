package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
	loginHits     atomic.Int32
	decisionsHits atomic.Int32
	alertsHits    atomic.Int32

	// Behaviour knobs.
	tokenLifetime         time.Duration // sent as `expire` in login response
	expectMachineID       string
	expectMachinePassword string
	currentToken          atomic.Value // string — issued JWT, rotates per login

	// failNextDecisions, when >0, causes the decisions handler to return 401
	// that many times before serving 200. Lets us exercise the one-retry
	// path in fetcher.authedGet.
	failNextDecisions atomic.Int32

	// alertsScenario is exposed so tests can assert it appears in View output.
	alertsScenario string
	// decisionValues are the IPs returned in /v1/decisions; tests assert at
	// least one of them shows up in View output.
	decisionValues []string
}

func newMockLAPI(t *testing.T) *mockLAPI {
	t.Helper()
	m := &mockLAPI{
		tokenLifetime:         30 * time.Minute,
		expectMachineID:       "ember-tui-test",
		expectMachinePassword: "s3cret-mock",
		alertsScenario:        "crowdsecurity/http-bf",
		decisionValues:        []string{"203.0.113.10", "198.51.100.42", "192.0.2.7"},
	}
	m.currentToken.Store("")

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/watchers/login", m.handleLogin)
	mux.HandleFunc("/v1/decisions", m.handleDecisions)
	mux.HandleFunc("/v1/alerts", m.handleAlerts)

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

	// Forced-fail mode for the 401-retry test. We still consume bearer-check
	// AFTER the forced fail so the retry path validates against a proper
	// Bearer on the second call.
	if remaining := m.failNextDecisions.Load(); remaining > 0 {
		m.failNextDecisions.Add(-1)
		http.Error(w, "forced 401", http.StatusUnauthorized)
		return
	}

	if !m.requireBearer(w, r) {
		return
	}

	// Three decisions: two long-lived bans + one short. Plugin sorts by TTL
	// desc so order in render is 4h > 1h > 10m.
	out := []Decision{
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (m *mockLAPI) handleAlerts(w http.ResponseWriter, r *http.Request) {
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

// provisionPlugin builds a CrowdSecPlugin pointed at the mock LAPI.
func provisionPlugin(t *testing.T, m *mockLAPI) *CrowdSecPlugin {
	t.Helper()
	p := &CrowdSecPlugin{}
	cfg := emberplugin.PluginConfig{
		CaddyAddr: "http://127.0.0.1:2019", // unused by plugin; populated for realism
		Options: map[string]string{
			"lapi_url":         m.URL(),
			"machine_id":       m.expectMachineID,
			"machine_password": m.expectMachinePassword,
			"alerts_since":     "24h",
			"insecure_tls":     "false",
		},
	}
	if err := p.Provision(context.Background(), cfg); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return p
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
	if got, want := len(snap.Decisions), 3; got != want {
		t.Fatalf("decisions count = %d, want %d", got, want)
	}
	if got, want := len(snap.Alerts), 2; got != want {
		t.Fatalf("alerts count = %d, want %d", got, want)
	}

	// Login exactly once for the first fetch.
	if got := m.loginHits.Load(); got != 1 {
		t.Errorf("loginHits = %d, want 1", got)
	}

	view := p.View(100, 30)

	// At least one decision IP must surface in View output.
	foundIP := false
	for _, ip := range m.decisionValues {
		if strings.Contains(view, ip) {
			foundIP = true
			break
		}
	}
	if !foundIP {
		t.Errorf("View did not contain any decision IP from %v\nview:\n%s", m.decisionValues, view)
	}

	// Alerts scenario must surface.
	if !strings.Contains(view, m.alertsScenario) {
		t.Errorf("View missing alerts scenario %q\nview:\n%s", m.alertsScenario, view)
	}

	// StatusCount() must equal the number of active decisions ("3").
	if got, want := p.StatusCount(), "3"; got != want {
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
// Test 3: One-shot 401 retry
// ---------------------------------------------------------------------------

// fetcher.authedGet retries exactly once on 401/403 after invalidating the
// cached token. We seed the mock so the first decisions GET returns 401, the
// fetcher invalidates + relogs in, and the second attempt succeeds. End state:
// snapshot has decisions populated, login hit twice, no top-level error.
func TestLAPI_RetryOn401(t *testing.T) {
	t.Parallel()

	m := newMockLAPI(t)
	m.failNextDecisions.Store(1) // first call to /v1/decisions returns 401

	p := provisionPlugin(t, m)

	snap := fetchAndUpdate(t, p)

	if snap.Err != nil {
		t.Fatalf("snapshot.Err = %v, want nil after retry", snap.Err)
	}
	if got, want := len(snap.Decisions), 3; got != want {
		t.Fatalf("decisions count = %d, want %d", got, want)
	}
	if got := m.loginHits.Load(); got != 2 {
		t.Errorf("loginHits = %d, want 2 (initial + post-401 retry)", got)
	}
	// /v1/decisions hit twice: first 401, second 200.
	if got, want := m.decisionsHits.Load(), int32(2); got != want {
		t.Errorf("decisionsHits = %d, want %d", got, want)
	}

	// View must still contain a real decision IP after the retry.
	view := p.View(100, 30)
	if !strings.Contains(view, m.decisionValues[0]) {
		t.Errorf("View missing decision IP %q after retry\nview:\n%s", m.decisionValues[0], view)
	}
}

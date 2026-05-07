package plugin

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// authClient handles machine-account login + JWT caching/refresh against the
// CrowdSec LAPI. Safe for concurrent use.
type authClient struct {
	base       string // e.g. http://127.0.0.1:8080
	machineID  string
	password   string
	httpClient *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// newAuthClient constructs an authClient. Caller verifies non-empty fields.
func newAuthClient(base, machineID, password string, insecureTLS bool) *authClient {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTLS}, //nolint:gosec // opt-in via env
		// Conservative defaults — LAPI is on localhost so latency is sub-ms.
		MaxIdleConns:        5,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     30 * time.Second,
	}
	return &authClient{
		base:      base,
		machineID: machineID,
		password:  password,
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: tr,
		},
	}
}

// Token returns a valid JWT, refreshing if the cached one is missing or within
// 60s of expiry. Refresh uses /v1/watchers/login again (CrowdSec's
// /v1/refresh_token requires the JWT but is functionally equivalent for a
// machine-account; re-login keeps the code simpler and avoids a second
// failure path during MVP).
func (a *authClient) Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.token != "" && time.Until(a.expiresAt) > 60*time.Second {
		return a.token, nil
	}
	if err := a.loginLocked(ctx); err != nil {
		return "", err
	}
	return a.token, nil
}

// Invalidate marks the cached token as expired so the next Token() call
// triggers a fresh login. Used when LAPI returns 401/403 unexpectedly.
func (a *authClient) Invalidate() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.token = ""
	a.expiresAt = time.Time{}
}

// loginLocked performs POST /v1/watchers/login. Caller must hold a.mu.
func (a *authClient) loginLocked(ctx context.Context) error {
	body, err := json.Marshal(loginRequest{
		MachineID: a.machineID,
		Password:  a.password,
	})
	if err != nil {
		return fmt.Errorf("marshal login: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+"/v1/watchers/login", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ember-crowdsec/0.1")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("login http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Body is intentionally NOT included: a hostile or misrouted LAPI
		// (e.g. EMBER_PLUGIN_CROWDSEC_LAPI_URL pointed at the wrong host)
		// could echo the request payload — including the machine password —
		// back into the response, which would then leak via err.Error()
		// into the renderer status line and the audit log.
		return fmt.Errorf("login: status %d", resp.StatusCode)
	}

	var lr loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return fmt.Errorf("decode login response: %w", err)
	}
	if lr.Token == "" {
		return errors.New("login: empty token in response")
	}

	exp, err := time.Parse(time.RFC3339, lr.Expire)
	if err != nil {
		// LAPI sometimes uses RFC3339Nano with timezone offsets; fall back to
		// a conservative 30-min lifetime.
		exp = time.Now().Add(30 * time.Minute)
	}

	a.token = lr.Token
	a.expiresAt = exp
	return nil
}

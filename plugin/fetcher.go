package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// defaultDecisionOrigins is the server-side filter applied to /v1/decisions
// by default. CrowdSec LAPI returns ALL origins otherwise (local engine +
// CAPI Threat Intel feed + community blocklists), which on a busy node hits
// 50k+ rows and drowns the operator-relevant local + cscli-manual entries.
// Iteration 3: filter to the two origins the operator actually controls.
const defaultDecisionOrigins = "crowdsec,cscli"

// maxLapiBodySize caps the response body of every LAPI call. Worst-case
// observed payload on rwu's setup with CAPI toggle enabled is ~5 MB (50k+
// decisions); 16 MiB leaves headroom while preventing a hostile or buggy
// LAPI from triggering OOM via an unbounded io.ReadAll.
const maxLapiBodySize = 16 << 20

// fetcher pulls decisions + alerts from LAPI in parallel. Decisions go via
// the bouncer X-Api-Key (LAPI restricts /v1/decisions to bouncer auth);
// alerts go via the machine-account JWT from authClient.
//
// Iteration 3: includeCAPI is a thread-safe toggle the renderer flips with
// hotkey `c`. When false (default), GET /v1/decisions carries
// `?origins=crowdsec,cscli`; when true, no origins filter is sent and ALL
// decisions (incl. CAPI + lists) come back.
type fetcher struct {
	auth        *authClient
	base        string
	bouncerKey  string
	alertsSince time.Duration
	httpClient  *http.Client
	includeCAPI atomic.Bool
}

func newFetcher(auth *authClient, base, bouncerKey string, alertsSince time.Duration) *fetcher {
	return &fetcher{
		auth:        auth,
		base:        base,
		bouncerKey:  bouncerKey,
		alertsSince: alertsSince,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			// Reuse auth's transport via Client wrapper would couple them;
			// keep separate so InsecureSkipVerify policy stays in one place
			// (auth) and a stale fetcher Client doesn't outlive a config
			// reload. Both clients hit localhost so cost is negligible.
			Transport: auth.httpClient.Transport,
		},
	}
}

// IncludeCAPI returns the current toggle state. Renderer reads this to pick
// the header text and to know whether `d` should be blocked on the selected
// row's origin.
func (f *fetcher) IncludeCAPI() bool {
	return f.includeCAPI.Load()
}

// SetIncludeCAPI flips the toggle; the next Fetch call observes the new
// value. No re-fetch is forced — Ember's tick scheduler triggers within
// fetch_interval (default 10s).
func (f *fetcher) SetIncludeCAPI(v bool) {
	f.includeCAPI.Store(v)
}

// fetchAll runs decisions + alerts in parallel. Returns a snapshot with
// whatever succeeded; partial failure surfaces via the .Err field on the
// returned snapshot if BOTH calls fail.
func (f *fetcher) fetchAll(ctx context.Context) snapshot {
	snap := snapshot{FetchedAt: time.Now()}

	var (
		wg          sync.WaitGroup
		decisions   []Decision
		alerts      []Alert
		decErr      error
		alertErr    error
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		decisions, decErr = f.fetchDecisions(ctx)
	}()
	go func() {
		defer wg.Done()
		alerts, alertErr = f.fetchAlerts(ctx)
	}()
	wg.Wait()

	snap.Decisions = decisions
	snap.Alerts = alerts

	switch {
	case decErr != nil && alertErr != nil:
		snap.Err = fmt.Errorf("decisions: %v; alerts: %v", decErr, alertErr)
	case decErr != nil:
		snap.Err = fmt.Errorf("decisions: %w", decErr)
	case alertErr != nil:
		snap.Err = fmt.Errorf("alerts: %w", alertErr)
	}

	// Sort decisions by remaining TTL desc so the longest-lived bans are at
	// the top; sort alerts by created_at desc.
	sort.SliceStable(snap.Decisions, func(i, j int) bool {
		return snap.Decisions[i].RemainingTTL() > snap.Decisions[j].RemainingTTL()
	})
	sort.SliceStable(snap.Alerts, func(i, j int) bool {
		return snap.Alerts[i].CreatedAt > snap.Alerts[j].CreatedAt
	})
	return snap
}

func (f *fetcher) fetchDecisions(ctx context.Context) ([]Decision, error) {
	// LAPI default returns active decisions only. Auth is X-Api-Key (bouncer)
	// — JWT yields 401. No retry on 401 here: the bouncer key is static and
	// not refreshable from inside the plugin; surface the error so the user
	// can fix the env-var.
	//
	// Server-side origin filter: by default we restrict to the local engine
	// and manual cscli decisions. Toggle via hotkey `c` (renderer) flips
	// includeCAPI=true and the next call drops the filter entirely.
	path := "/v1/decisions"
	if !f.includeCAPI.Load() {
		path += "?origins=" + url.QueryEscape(defaultDecisionOrigins)
	}
	body, err := f.bouncerGet(ctx, path)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 || string(body) == "null" {
		return []Decision{}, nil // LAPI returns "null" when empty
	}
	var out []Decision
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode decisions: %w", err)
	}
	return out, nil
}

func (f *fetcher) fetchAlerts(ctx context.Context) ([]Alert, error) {
	q := url.Values{}
	if f.alertsSince > 0 {
		// LAPI's /v1/alerts accepts since=<duration>. Format like "24h".
		q.Set("since", f.alertsSince.String())
	}
	path := "/v1/alerts"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	body, err := f.authedGet(ctx, path, nil)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 || string(body) == "null" {
		return []Alert{}, nil
	}
	var out []Alert
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode alerts: %w", err)
	}
	return out, nil
}

// bouncerGet performs a GET with the bouncer X-Api-Key header. The bouncer
// credential is static so no refresh path; a 401 is reported as-is.
func (f *fetcher) bouncerGet(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.base+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Api-Key", f.bouncerKey)
	req.Header.Set("User-Agent", "ember-crowdsec/0.1")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("bouncer key invalid (status %d): %s", resp.StatusCode, string(raw))
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(raw))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxLapiBodySize))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}

// authedGet performs a JWT-authenticated GET. On 401/403 it invalidates the
// cached token and retries exactly once.
func (f *fetcher) authedGet(ctx context.Context, path string, _ url.Values) ([]byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		token, err := f.auth.Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("auth: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.base+path, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", "ember-crowdsec/0.1")

		resp, err := f.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("http: %w", err)
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			f.auth.Invalidate()
			continue // retry once with fresh token
		}
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(raw))
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxLapiBodySize))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}
		return body, nil
	}
	return nil, errors.New("auth: token rejected twice")
}

package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// actionsClient implements the killer-feature write-path (unban + whitelist)
// against the CrowdSec LAPI. Auth is the machine-account JWT — DELETE and
// POST on /v1/decisions/{id} resp. /v1/alerts require Bearer (X-Api-Key
// would yield 401 same as the bouncer-key on read endpoints in reverse).
type actionsClient struct {
	auth       *authClient
	base       string
	httpClient *http.Client
	origin     string // origin tag stamped on whitelist decisions
}

const (
	defaultWhitelistOrigin = "ember-tui"
	whitelistType          = "whitelist"
	whitelistScope         = "Ip"
)

func newActionsClient(auth *authClient, base string) *actionsClient {
	return &actionsClient{
		auth: auth,
		base: base,
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: auth.httpClient.Transport,
		},
		origin: defaultWhitelistOrigin,
	}
}

// DeleteDecision removes a single active decision by its numeric ID. LAPI
// returns 200 with {"nbDeleted":"1"} on success. Best-effort: even if the
// response body cannot be decoded we treat HTTP 200 as success.
func (a *actionsClient) DeleteDecision(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("invalid decision id %d", id)
	}
	path := "/v1/decisions/" + strconv.FormatInt(id, 10)

	body, status, err := a.authedDo(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("delete decision %d: %s", id, sanitizeAPIError(status, body))
	}
	return nil
}

// WhitelistIP installs a new whitelist decision for the given IP via the
// /v1/alerts endpoint (cscli's "decisions add --type whitelist" path). The
// alert is constructed with the same skeleton cscli uses (verified against
// crowdsecurity/crowdsec cmd/crowdsec-cli/clidecision/decisions.go cli.add()
// lines 256-388, master @ 2026-05-07): a single Source, a single Decision,
// empty Events slice, simulated=false. CreatedAt / StartAt / StopAt are all
// "now" RFC3339 — duration on the inner decision drives expiry.
//
// Body fields not provided by us (kept absent or omitempty): scenario_hash,
// scenario_version, simulated — set to empty/false matching cscli defaults.
func (a *actionsClient) WhitelistIP(ctx context.Context, ip, duration, reason string) error {
	if ip == "" {
		return errors.New("whitelist: ip required")
	}
	if duration == "" {
		duration = "24h"
	}
	if _, err := time.ParseDuration(duration); err != nil {
		return fmt.Errorf("whitelist: invalid duration %q: %w", duration, err)
	}
	if reason == "" {
		reason = "manual whitelist via ember-tui"
	}

	now := time.Now().UTC().Format(time.RFC3339)
	scope := whitelistScope
	value := ip
	dType := whitelistType
	dDur := duration
	dOrigin := a.origin

	// LAPI's swagger requires pointer fields on Alert/Decision/Source for
	// presence-detection (cscli uses the generated client, we hand-build the
	// JSON to avoid the dependency). Marshalling a struct with explicit
	// fields is equivalent for the wire format.
	alert := alertCreateRequest{
		Capacity:        intPtr(0),
		Decisions: []alertCreateDecision{
			{
				Type:     &dType,
				Value:    &value,
				Duration: &dDur,
				Scope:    &scope,
				Origin:   &dOrigin,
				Scenario: &reason,
			},
		},
		Events:          []alertCreateEvent{},
		EventsCount:     intPtr(1),
		Leakspeed:       strPtr("0"),
		Message:         &reason,
		Scenario:        &reason,
		ScenarioHash:    strPtr(""),
		ScenarioVersion: strPtr(""),
		Simulated:       boolPtr(false),
		Source: &alertCreateSource{
			IP:    ip,
			Scope: &scope,
			Value: &value,
		},
		StartAt:   &now,
		StopAt:    &now,
		CreatedAt: now,
	}

	payload, err := json.Marshal([]alertCreateRequest{alert})
	if err != nil {
		return fmt.Errorf("marshal whitelist alert: %w", err)
	}
	body, status, err := a.authedDo(ctx, http.MethodPost, "/v1/alerts", payload)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return fmt.Errorf("whitelist %s: %s", ip, sanitizeAPIError(status, body))
	}
	return nil
}

// authedDo runs an HTTP request with JWT-Bearer auth + one-shot 401 retry.
// payload may be nil for GET/DELETE. Returns the raw response body and
// status code.
func (a *actionsClient) authedDo(ctx context.Context, method, path string, payload []byte) ([]byte, int, error) {
	for attempt := 0; attempt < 2; attempt++ {
		token, err := a.auth.Token(ctx)
		if err != nil {
			return nil, 0, fmt.Errorf("auth: %w", err)
		}

		var bodyReader io.Reader
		if payload != nil {
			bodyReader = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, a.base+path, bodyReader)
		if err != nil {
			return nil, 0, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", "ember-crowdsec/0.1")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := a.httpClient.Do(req)
		if err != nil {
			return nil, 0, fmt.Errorf("http: %w", err)
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.auth.Invalidate()
			if attempt == 0 {
				continue
			}
			return raw, resp.StatusCode, fmt.Errorf("auth: token rejected twice")
		}
		return raw, resp.StatusCode, nil
	}
	return nil, 0, errors.New("auth: token rejected twice")
}

// sanitizeAPIError formats a LAPI error response without leaking arbitrary
// body content into the error string (which feeds the renderer status line
// and the audit log). LAPI's standard error envelope is
// {"message":"...","errors":"..."} — when present we surface only the
// short message field. On any decode failure we fall back to the bare
// status code so HTML stack-traces, internal paths, or echoed credentials
// stay out of err.Error().
func sanitizeAPIError(statusCode int, body []byte) string {
	if len(body) == 0 {
		return fmt.Sprintf("status %d", statusCode)
	}
	var env struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &env); err == nil && env.Message != "" {
		const max = 200
		msg := env.Message
		if len(msg) > max {
			msg = msg[:max] + "..."
		}
		return fmt.Sprintf("status %d: %s", statusCode, msg)
	}
	return fmt.Sprintf("status %d", statusCode)
}

func intPtr(i int32) *int32   { return &i }
func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

// alertCreateRequest mirrors models.Alert from CrowdSec's swagger. Only the
// fields cscli's "decisions add" path populates are present here; other
// fields are unused/empty by design.
type alertCreateRequest struct {
	Capacity        *int32                `json:"capacity"`
	Decisions       []alertCreateDecision `json:"decisions"`
	Events          []alertCreateEvent    `json:"events"`
	EventsCount     *int32                `json:"events_count"`
	Leakspeed       *string               `json:"leakspeed"`
	Message         *string               `json:"message"`
	Scenario        *string               `json:"scenario"`
	ScenarioHash    *string               `json:"scenario_hash"`
	ScenarioVersion *string               `json:"scenario_version"`
	Simulated       *bool                 `json:"simulated"`
	Source          *alertCreateSource    `json:"source"`
	StartAt         *string               `json:"start_at"`
	StopAt          *string               `json:"stop_at"`
	CreatedAt       string                `json:"created_at,omitempty"`
}

type alertCreateDecision struct {
	Type     *string `json:"type"`
	Value    *string `json:"value"`
	Duration *string `json:"duration"`
	Scope    *string `json:"scope"`
	Origin   *string `json:"origin"`
	Scenario *string `json:"scenario,omitempty"`
}

type alertCreateSource struct {
	IP    string  `json:"ip"`
	Scope *string `json:"scope"`
	Value *string `json:"value"`
}

// alertCreateEvent is a placeholder — cscli sends an empty events slice for
// manual alerts. We mirror that behaviour: never populate, just emit `[]`.
type alertCreateEvent struct {
	Timestamp *string `json:"timestamp,omitempty"`
}

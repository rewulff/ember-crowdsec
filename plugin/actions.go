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

// actionsClient implements the write-path (unban) against the CrowdSec
// LAPI. Auth is the machine-account JWT — DELETE on /v1/decisions/{id}
// requires Bearer (X-Api-Key would yield 401 same as the bouncer-key on
// read endpoints in reverse).
//
// The plugin previously also exposed a WhitelistIP path via POST /v1/alerts
// (cscli "decisions add --type whitelist"). That path was removed in v0.3.0
// (Forgejo #13 + hslatman/caddy-crowdsec-bouncer#116): bouncers treat the
// existence of any decision as a block marker, so a type=whitelist decision
// is read as a block by the Caddy bouncer — not an allow. Engine-side
// postoverflow allowlists (/etc/crowdsec/postoverflows/s01-whitelist/<n>.yaml
// + systemctl reload crowdsec) are the supported allow-mechanism.
type actionsClient struct {
	auth       *authClient
	base       string
	httpClient *http.Client
}

func newActionsClient(auth *authClient, base string) *actionsClient {
	return &actionsClient{
		auth: auth,
		base: base,
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: auth.httpClient.Transport,
		},
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

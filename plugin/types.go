// Package plugin implements the Ember plugin "crowdsec" — a TUI tab that
// displays active CrowdSec decisions and recent alerts pulled from a local
// LAPI via machine-account JWT authentication.
package plugin

import "time"

// Decision mirrors the relevant fields of a CrowdSec LAPI decision returned by
// GET /v1/decisions. Numeric fields (id, duration_seconds) are intentionally
// kept as strings/duration-of-string to match LAPI's flexible JSON encoding.
type Decision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`   // crowdsec, lists:firehol_cybercrime, cscli, ...
	Type     string `json:"type"`     // ban, captcha, throttle
	Scope    string `json:"scope"`    // Ip, Range, Country, AS, ...
	Value    string `json:"value"`    // the IP/range/country code
	Scenario string `json:"scenario"` // crowdsecurity/http-bf, manual, ...
	Duration string `json:"duration"` // "4h0m0s" remaining TTL
	Until    string `json:"until"`    // RFC3339 expiry (optional, depends on LAPI version)
}

// RemainingTTL parses the "duration" field into a time.Duration. Returns 0 if
// parsing fails (defensive; LAPI sometimes emits "0s" or empty strings).
func (d Decision) RemainingTTL() time.Duration {
	if d.Duration == "" {
		return 0
	}
	dur, err := time.ParseDuration(d.Duration)
	if err != nil {
		return 0
	}
	return dur
}

// Alert mirrors the relevant fields of a CrowdSec LAPI alert returned by
// GET /v1/alerts. The full payload contains nested events/source/decisions —
// for the MVP we only surface the top-level summary.
type Alert struct {
	ID        int64       `json:"id"`
	Scenario  string      `json:"scenario"`
	Message   string      `json:"message"`
	StartAt   string      `json:"start_at"`     // RFC3339
	StopAt    string      `json:"stop_at"`      // RFC3339, may equal start_at
	CreatedAt string      `json:"created_at"`   // RFC3339
	Source    AlertSource `json:"source"`
	// EventCount is sometimes called events_count in LAPI; kept optional.
	EventCount int `json:"events_count,omitempty"`
}

// AlertSource is the offending entity for an alert.
type AlertSource struct {
	IP       string `json:"ip"`
	Range    string `json:"range"`
	AsName   string `json:"as_name"`
	AsNumber string `json:"as_number"`
	Cn       string `json:"cn"` // country code
	Scope    string `json:"scope"`
	Value    string `json:"value"`
}

// loginRequest is the body for POST /v1/watchers/login.
type loginRequest struct {
	MachineID string `json:"machine_id"`
	Password  string `json:"password"`
	Scenarios []string `json:"scenarios,omitempty"`
}

// loginResponse is the response from POST /v1/watchers/login.
type loginResponse struct {
	Code   int    `json:"code"`
	Expire string `json:"expire"` // RFC3339
	Token  string `json:"token"`
}

// snapshot is the data type passed from Fetch() to Renderer.Update().
type snapshot struct {
	Decisions []Decision
	Alerts    []Alert
	FetchedAt time.Time
	Err       error // last fetch error, if any (nil on success)
}

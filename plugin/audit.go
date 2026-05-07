package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// auditLog appends one JSON object per write-action to a local file. The
// log is opened lazily on first write and held open for the lifetime of the
// plugin process. File mode 0600 by construction — write-actions touch
// privileged endpoints and the journal MUST NOT be world-readable.
//
// Every action is recorded — successes AND failures. The plugin cannot
// pretend an attempted unban didn't happen just because LAPI returned 500.
type auditLog struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	disabled bool   // true if open failed; subsequent writes silently no-op (lastErr surfaces in renderer)
	lastErr  error  // last error opening or writing
}

// auditEntry is one line in the JSON-Lines log.
type auditEntry struct {
	TS         string `json:"ts"`
	Action     string `json:"action"`             // "unban" | "whitelist"
	IP         string `json:"ip,omitempty"`
	DecisionID int64  `json:"decision_id,omitempty"`
	Duration   string `json:"duration,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Status     string `json:"status"`             // "ok" | "error"
	Error      string `json:"error,omitempty"`
}

// newAuditLog opens (or creates) the audit file with mode 0600. The parent
// directory is created if missing. Returns an error if the path is unwriteable
// — the caller can choose to wrap it with a disabled instance to keep the
// plugin running without a log.
func newAuditLog(path string) (*auditLog, error) {
	if path == "" {
		return nil, errors.New("audit log path is empty")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("audit log: mkdir parent: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit log: open %s: %w", path, err)
	}
	// Defensive: re-chmod in case file pre-existed with looser perms.
	_ = os.Chmod(path, 0o600)
	return &auditLog{path: path, file: f}, nil
}

// recordUnban logs an unban attempt. errMsg is empty on success.
func (l *auditLog) recordUnban(decisionID int64, ip string, errMsg string) {
	if l == nil {
		return
	}
	status := "ok"
	if errMsg != "" {
		status = "error"
	}
	l.write(auditEntry{
		TS:         time.Now().UTC().Format(time.RFC3339),
		Action:     "unban",
		IP:         ip,
		DecisionID: decisionID,
		Status:     status,
		Error:      errMsg,
	})
}

// recordWhitelist logs a whitelist attempt. errMsg is empty on success.
func (l *auditLog) recordWhitelist(ip, duration, reason, errMsg string) {
	if l == nil {
		return
	}
	status := "ok"
	if errMsg != "" {
		status = "error"
	}
	l.write(auditEntry{
		TS:       time.Now().UTC().Format(time.RFC3339),
		Action:   "whitelist",
		IP:       ip,
		Duration: duration,
		Reason:   reason,
		Status:   status,
		Error:    errMsg,
	})
}

// write serialises an entry as a single JSON line. On error the lastErr
// field is set so the renderer can surface "audit log write failed" in the
// status line, but we never panic or block the calling action.
func (l *auditLog) write(e auditEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.disabled || l.file == nil {
		return
	}
	raw, err := json.Marshal(e)
	if err != nil {
		l.lastErr = err
		return
	}
	raw = append(raw, '\n')
	if _, err := l.file.Write(raw); err != nil {
		l.lastErr = err
	}
}

// LastErr returns the most recent open/write error (or nil). Concurrent-safe.
func (l *auditLog) LastErr() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastErr
}

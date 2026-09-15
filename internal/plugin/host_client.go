package plugin

import (
	"encoding/json"
	"net/http"
	"time"
)

const (
	MethodHostHTTPDoCallback         = "host.http.do"
	MethodHostLogCallback            = "host.log"
	MethodHostAuthListCallback       = "host.auth.list"
	MethodHostAuthGetCallback        = "host.auth.get"
	MethodHostAuthGetRuntimeCallback = "host.auth.get_runtime"
)

// HostClient is the narrow host-callback surface required by quota
// observation and maintenance. It intentionally excludes credential writes
// and arbitrary model execution.
type HostClient interface {
	ListAuths() ([]HostAuthEntry, error)
	GetAuth(authIndex string) (HostAuthDocument, error)
	GetAuthRuntime(authIndex string) (HostAuthEntry, error)
	Do(request HostHTTPRequest) (HostHTTPResponse, error)
	Log(level, message string, fields map[string]any)
}

type HostAuthEntry struct {
	ID             string    `json:"id,omitempty"`
	AuthIndex      string    `json:"auth_index,omitempty"`
	Name           string    `json:"name,omitempty"`
	Type           string    `json:"type,omitempty"`
	Provider       string    `json:"provider,omitempty"`
	Status         string    `json:"status,omitempty"`
	StatusMessage  string    `json:"status_message,omitempty"`
	Disabled       bool      `json:"disabled,omitempty"`
	Unavailable    bool      `json:"unavailable,omitempty"`
	RuntimeOnly    bool      `json:"runtime_only,omitempty"`
	Priority       int       `json:"priority,omitempty"`
	Email          string    `json:"email,omitempty"`
	Account        string    `json:"account,omitempty"`
	AccountType    string    `json:"account_type,omitempty"`
	BaseURL        string    `json:"base_url,omitempty"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
	LastRefresh    time.Time `json:"last_refresh,omitempty"`
	NextRetryAfter time.Time `json:"next_retry_after,omitempty"`
}

type HostAuthDocument struct {
	AuthIndex string          `json:"auth_index"`
	Name      string          `json:"name,omitempty"`
	Path      string          `json:"path,omitempty"`
	JSON      json.RawMessage `json:"json"`
}

type HostHTTPRequest struct {
	Method         string      `json:"method"`
	URL            string      `json:"url"`
	Headers        http.Header `json:"headers,omitempty"`
	Body           []byte      `json:"body,omitempty"`
	HostCallbackID string      `json:"host_callback_id,omitempty"`
}

type HostHTTPResponse struct {
	// CPA's current RPC result marshals pluginapi.HTTPResponse without JSON
	// tags, so the wire keys are StatusCode/Headers/Body.
	StatusCode int
	Headers    http.Header
	Body       []byte
}

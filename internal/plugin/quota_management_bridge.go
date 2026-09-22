package plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"cpa-key-policy/internal/policy"
)

const (
	quotaTransportHost       = "host-callback"
	quotaTransportManagement = "management-bridge"

	quotaManagementRequestTimeout = 65 * time.Second
	quotaManagementResponseLimit  = 4 << 20
)

type codexAuthProxy struct {
	Present bool
	Value   string
}

type codexMaintenanceTarget struct {
	AuthID      string
	AuthIndex   string
	Credentials codexCredentials
	Proxy       codexAuthProxy
}

func (t codexMaintenanceTarget) transport() string {
	if t.Proxy.Present {
		return quotaTransportManagement
	}
	return quotaTransportHost
}

func parseCodexAuthProxy(raw json.RawMessage) (codexAuthProxy, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return codexAuthProxy{}, errors.New("credential document is not a JSON object")
	}
	for _, unsupported := range []string{"proxy", "proxy-url"} {
		value, exists := doc[unsupported]
		if !exists || string(value) == "null" {
			continue
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return codexAuthProxy{}, errors.New("unsupported proxy field has a non-string value")
		}
		if strings.TrimSpace(text) != "" {
			return codexAuthProxy{}, errors.New("unsupported proxy field is present")
		}
	}
	rawValue, exists := doc["proxy_url"]
	if !exists || string(rawValue) == "null" {
		return codexAuthProxy{}, nil
	}
	var value string
	if err := json.Unmarshal(rawValue, &value); err != nil {
		return codexAuthProxy{}, errors.New("proxy_url must be a string")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return codexAuthProxy{}, nil
	}
	normalized, err := normalizeCodexProxyURL(value)
	if err != nil {
		return codexAuthProxy{}, err
	}
	return codexAuthProxy{Present: true, Value: normalized}, nil
}

func normalizeCodexProxyURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("proxy_url is empty")
	}
	for _, r := range raw {
		if unicode.IsControl(r) {
			return "", errors.New("proxy_url contains control characters")
		}
	}
	switch strings.ToLower(raw) {
	case "direct":
		return "direct", nil
	case "none":
		return "none", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Opaque != "" {
		return "", errors.New("proxy_url is invalid")
	}
	parsed.Scheme = strings.ToLower(strings.TrimSpace(parsed.Scheme))
	switch parsed.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", errors.New("proxy_url uses an unsupported scheme")
	}
	if strings.TrimSpace(parsed.Hostname()) == "" {
		return "", errors.New("proxy_url host is empty")
	}
	if parsed.User != nil {
		if containsControl(parsed.User.Username()) {
			return "", errors.New("proxy_url credentials contain control characters")
		}
		if password, ok := parsed.User.Password(); ok && containsControl(password) {
			return "", errors.New("proxy_url credentials contain control characters")
		}
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Path != "" {
		return "", errors.New("proxy_url must not contain a path, query, or fragment")
	}
	if port := parsed.Port(); port != "" {
		value, errPort := strconv.Atoi(port)
		if errPort != nil || value < 1 || value > 65535 {
			return "", errors.New("proxy_url port is invalid")
		}
	}
	parsed.Path = ""
	return parsed.String(), nil
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func normalizeQuotaManagementBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("management base URL is empty")
	}
	for _, r := range raw {
		if unicode.IsControl(r) {
			return "", errors.New("management base URL contains control characters")
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Opaque != "" {
		return "", errors.New("management base URL is invalid")
	}
	parsed.Scheme = strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("management base URL must use HTTP or HTTPS")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("management base URL must be a loopback origin")
	}
	hostname := parsed.Hostname()
	if hostname != "127.0.0.1" && hostname != "::1" {
		return "", errors.New("management base URL must use a literal loopback address")
	}
	if port := parsed.Port(); port != "" {
		value, errPort := strconv.Atoi(port)
		if errPort != nil || value < 1 || value > 65535 {
			return "", errors.New("management base URL port is invalid")
		}
	}
	parsed.Path = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

type quotaManagementBridgeError struct {
	Code   string
	Status int
	Err    error
}

func (e quotaManagementBridgeError) Error() string {
	if e.Err != nil {
		return e.Code + ": " + e.Err.Error()
	}
	return e.Code
}

func (e quotaManagementBridgeError) Unwrap() error { return e.Err }

type quotaManagementBridge struct {
	client *http.Client

	mu                sync.Mutex
	pausedFingerprint string
	lastError         string
}

func newQuotaManagementBridge() *quotaManagementBridge {
	transport := &http.Transport{}
	if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = defaultTransport.Clone()
	}
	transport.Proxy = nil
	return &quotaManagementBridge{client: &http.Client{
		Transport: transport,
		Timeout:   quotaManagementRequestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (b *quotaManagementBridge) reset() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.pausedFingerprint = ""
	b.lastError = ""
	b.mu.Unlock()
}

func quotaManagementSettingsFingerprint(settings policy.QuotaManagementSettings) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(settings.BaseURL) + "\x00" + settings.Key))
	return hex.EncodeToString(sum[:])
}

func quotaManagementReady(settings policy.QuotaManagementSettings) bool {
	if !settings.Enabled || strings.TrimSpace(settings.Key) == "" {
		return false
	}
	_, err := normalizeQuotaManagementBaseURL(settings.BaseURL)
	return err == nil
}

func (b *quotaManagementBridge) status(settings policy.QuotaManagementSettings) (string, string) {
	if !settings.Enabled {
		return "disabled", ""
	}
	if !quotaManagementReady(settings) {
		return "unconfigured", ""
	}
	fingerprint := quotaManagementSettingsFingerprint(settings)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pausedFingerprint == fingerprint {
		return "paused", b.lastError
	}
	return "ready", ""
}

func (b *quotaManagementBridge) pause(settings policy.QuotaManagementSettings, code string) {
	b.mu.Lock()
	b.pausedFingerprint = quotaManagementSettingsFingerprint(settings)
	b.lastError = code
	b.mu.Unlock()
}

func (b *quotaManagementBridge) isPaused(settings policy.QuotaManagementSettings) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pausedFingerprint == quotaManagementSettingsFingerprint(settings)
}

func (b *quotaManagementBridge) do(ctx context.Context, settings policy.QuotaManagementSettings, method, path string, payload any, allowDisabled, allowPaused bool) ([]byte, int, error) {
	if b == nil {
		return nil, 0, quotaManagementBridgeError{Code: "management_bridge_unavailable"}
	}
	if !allowDisabled && !settings.Enabled {
		return nil, 0, quotaManagementBridgeError{Code: "management_bridge_disabled"}
	}
	baseURL, err := normalizeQuotaManagementBaseURL(settings.BaseURL)
	if err != nil || strings.TrimSpace(settings.Key) == "" {
		return nil, 0, quotaManagementBridgeError{Code: "management_bridge_unconfigured"}
	}
	if !allowPaused && b.isPaused(settings) {
		return nil, 0, quotaManagementBridgeError{Code: "management_bridge_auth_paused"}
	}
	var body io.Reader
	if payload != nil {
		raw, errMarshal := json.Marshal(payload)
		if errMarshal != nil {
			return nil, 0, quotaManagementBridgeError{Code: "management_bridge_request_invalid", Err: errMarshal}
		}
		body = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, baseURL+path, body)
	if err != nil {
		return nil, 0, quotaManagementBridgeError{Code: "management_bridge_request_invalid"}
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+settings.Key)
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := b.client.Do(request)
	if err != nil {
		return nil, 0, quotaManagementBridgeError{Code: "management_bridge_transport_failed"}
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, quotaManagementResponseLimit+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, response.StatusCode, quotaManagementBridgeError{Code: "management_bridge_read_failed"}
	}
	if len(raw) > quotaManagementResponseLimit {
		return nil, response.StatusCode, quotaManagementBridgeError{Code: "management_bridge_response_too_large"}
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		b.pause(settings, "management_bridge_auth_failed")
		return nil, response.StatusCode, quotaManagementBridgeError{Code: "management_bridge_auth_failed", Status: response.StatusCode}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, response.StatusCode, quotaManagementBridgeError{Code: "management_bridge_http_failed", Status: response.StatusCode}
	}
	return raw, response.StatusCode, nil
}

func (b *quotaManagementBridge) test(ctx context.Context, settings policy.QuotaManagementSettings) error {
	_, _, err := b.do(ctx, settings, http.MethodGet, "/v0/management/plugins", nil, true, true)
	if err != nil {
		return err
	}
	b.reset()
	return nil
}

type quotaManagementAPICallRequest struct {
	AuthIndex string            `json:"auth_index"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	ProxyURL  string            `json:"proxy_url"`
	Header    map[string]string `json:"header"`
	Data      string            `json:"data,omitempty"`
}

type quotaManagementAPICallResponse struct {
	StatusCode int         `json:"status_code"`
	Header     http.Header `json:"header"`
	Body       string      `json:"body"`
}

func (b *quotaManagementBridge) doUpstream(ctx context.Context, settings policy.QuotaManagementSettings, target codexMaintenanceTarget, method, endpoint string, body []byte) (HostHTTPResponse, error) {
	if !target.Proxy.Present || strings.TrimSpace(target.Proxy.Value) == "" || strings.TrimSpace(target.AuthIndex) == "" {
		return HostHTTPResponse{}, quotaManagementBridgeError{Code: "management_bridge_target_invalid"}
	}
	payload := quotaManagementAPICallRequest{
		AuthIndex: target.AuthIndex,
		Method:    method,
		URL:       endpoint,
		ProxyURL:  target.Proxy.Value,
		Header: map[string]string{
			"Authorization":      "Bearer $TOKEN$",
			"Chatgpt-Account-Id": target.Credentials.AccountID,
			"Content-Type":       "application/json",
			"User-Agent":         codexQuotaUserAgent,
		},
		Data: string(body),
	}
	raw, _, err := b.do(ctx, settings, http.MethodPost, "/v0/management/api-call", payload, false, false)
	if err != nil {
		return HostHTTPResponse{}, err
	}
	var response quotaManagementAPICallResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return HostHTTPResponse{}, quotaManagementBridgeError{Code: "management_bridge_response_invalid"}
	}
	if response.StatusCode < 100 || response.StatusCode > 599 {
		return HostHTTPResponse{}, quotaManagementBridgeError{Code: "management_bridge_response_invalid"}
	}
	if response.Header == nil {
		response.Header = make(http.Header)
	}
	return HostHTTPResponse{StatusCode: response.StatusCode, Headers: response.Header, Body: []byte(response.Body)}, nil
}

func bridgeErrorCode(err error) string {
	var bridgeErr quotaManagementBridgeError
	if errors.As(err, &bridgeErr) && bridgeErr.Code != "" {
		return bridgeErr.Code
	}
	return "management_bridge_failed"
}

func bridgeErrorDefinitelyNotSent(err error) bool {
	switch bridgeErrorCode(err) {
	case "management_bridge_disabled", "management_bridge_unconfigured", "management_bridge_auth_paused", "management_bridge_auth_failed", "management_bridge_target_invalid", "management_bridge_request_invalid":
		return true
	default:
		return false
	}
}

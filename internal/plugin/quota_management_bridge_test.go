package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"cpa-key-policy/internal/policy"
)

func TestParseCodexAuthProxyUsesOnlyCanonicalTopLevelField(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		present bool
		value   string
		wantErr bool
	}{
		{name: "missing", raw: `{"metadata":{"proxy_url":"http://nested.invalid:8080"}}`},
		{name: "http", raw: `{"proxy_url":"http://user:pass@127.0.0.1:8080"}`, present: true, value: "http://user:pass@127.0.0.1:8080"},
		{name: "socks5h", raw: `{"proxy_url":"SOCKS5H://[::1]:1080"}`, present: true, value: "socks5h://[::1]:1080"},
		{name: "direct", raw: `{"proxy_url":"DIRECT"}`, present: true, value: "direct"},
		{name: "none", raw: `{"proxy_url":"none"}`, present: true, value: "none"},
		{name: "unsupported alias", raw: `{"proxy-url":"http://127.0.0.1:8080"}`, wantErr: true},
		{name: "non string", raw: `{"proxy_url":123}`, wantErr: true},
		{name: "bad scheme", raw: `{"proxy_url":"ftp://127.0.0.1:21"}`, wantErr: true},
		{name: "bad port", raw: `{"proxy_url":"http://127.0.0.1:70000"}`, wantErr: true},
		{name: "path", raw: `{"proxy_url":"http://127.0.0.1:8080/tunnel"}`, wantErr: true},
		{name: "root path", raw: `{"proxy_url":"http://127.0.0.1:8080/"}`, wantErr: true},
		{name: "encoded control", raw: `{"proxy_url":"http://user:%0Apass@127.0.0.1:8080"}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseCodexAuthProxy(json.RawMessage(test.raw))
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr=%v", err, test.wantErr)
			}
			if err == nil && (got.Present != test.present || got.Value != test.value) {
				t.Fatalf("proxy = %#v, want present=%v value=%q", got, test.present, test.value)
			}
		})
	}
}

func TestNormalizeQuotaManagementBaseURLAcceptsOnlyLiteralLoopbackOrigin(t *testing.T) {
	for _, valid := range []string{"http://127.0.0.1:8317", "https://[::1]:9443/"} {
		if _, err := normalizeQuotaManagementBaseURL(valid); err != nil {
			t.Fatalf("valid base URL %q rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"http://localhost:8317", "http://0.0.0.0:8317", "http://127.0.0.1:8317/path",
		"http://user:pass@127.0.0.1:8317", "http://127.0.0.1:8317?x=1", "ftp://127.0.0.1:21",
	} {
		if _, err := normalizeQuotaManagementBaseURL(invalid); err == nil {
			t.Fatalf("invalid base URL %q accepted", invalid)
		}
	}
}

func TestQuotaManagementBridgeAPIRequestUsesMarkerAndExplicitProxy(t *testing.T) {
	var received quotaManagementAPICallRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/management/api-call" || r.Method != http.MethodPost {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer management-secret" {
			t.Fatalf("outer authorization = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(quotaManagementAPICallResponse{
			StatusCode: http.StatusTooManyRequests,
			Header:     http.Header{"Retry-After": []string{"17"}},
			Body:       `{"error":"limited"}`,
		})
	}))
	defer server.Close()

	bridge := newQuotaManagementBridge()
	settings := policy.QuotaManagementSettings{Enabled: true, BaseURL: server.URL, Key: "management-secret"}
	target := codexMaintenanceTarget{
		AuthID:    "account-a.json",
		AuthIndex: "idx-a",
		Credentials: codexCredentials{
			AccessToken: "must-not-be-sent",
			AccountID:   "acct-a",
		},
		Proxy: codexAuthProxy{Present: true, Value: "http://proxy-user:proxy-pass@127.0.0.1:18080"},
	}
	response, err := bridge.doUpstream(context.Background(), settings, target, http.MethodGet, codexQuotaEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusTooManyRequests || response.Headers.Get("Retry-After") != "17" {
		t.Fatalf("inner response = %#v", response)
	}
	if received.AuthIndex != "idx-a" || received.Method != http.MethodGet || received.URL != codexQuotaEndpoint || received.ProxyURL != target.Proxy.Value {
		t.Fatalf("api-call request = %#v", received)
	}
	if received.Header["Authorization"] != "Bearer $TOKEN$" || received.Header["Chatgpt-Account-Id"] != "acct-a" {
		t.Fatalf("inner headers = %#v", received.Header)
	}
	raw, _ := json.Marshal(received)
	if strings.Contains(string(raw), "must-not-be-sent") || strings.Contains(string(raw), "management-secret") {
		t.Fatalf("api-call body leaked a credential: %s", raw)
	}
}

func TestQuotaManagementBridgePausesAfterManagementAuthFailure(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	bridge := newQuotaManagementBridge()
	settings := policy.QuotaManagementSettings{Enabled: true, BaseURL: server.URL, Key: "wrong"}
	request := quotaManagementAPICallRequest{AuthIndex: "idx-a", Method: http.MethodGet, URL: codexQuotaEndpoint, ProxyURL: "direct", Header: map[string]string{"Authorization": "Bearer $TOKEN$"}}
	for i := 0; i < 2; i++ {
		_, _, err := bridge.do(context.Background(), settings, http.MethodPost, "/v0/management/api-call", request, false, false)
		if err == nil {
			t.Fatal("management auth failure was accepted")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("paused bridge made %d management requests, want 1", calls)
	}
	state, code := bridge.status(settings)
	if state != "paused" || code != "management_bridge_auth_failed" {
		t.Fatalf("bridge status = %q %q", state, code)
	}
}

func TestQuotaManagementBridgeDoesNotFollowRedirect(t *testing.T) {
	redirected := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected++ }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL, http.StatusFound)
	}))
	defer source.Close()

	bridge := newQuotaManagementBridge()
	settings := policy.QuotaManagementSettings{Enabled: true, BaseURL: source.URL, Key: "secret"}
	if err := bridge.test(context.Background(), settings); err == nil {
		t.Fatal("redirecting management endpoint was accepted")
	}
	if redirected != 0 {
		t.Fatalf("management client followed redirect %d times", redirected)
	}
}

func TestQuotaManagementActivationSwitchBlocksOnlyBridgePOST(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	methods := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request quotaManagementAPICallRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		methods = append(methods, request.Method)
		mu.Unlock()
		body := string(quotaBody(now.Add(time.Minute), 10))
		if request.Method == http.MethodPost {
			body = `{"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`
		}
		_ = json.NewEncoder(w).Encode(quotaManagementAPICallResponse{StatusCode: http.StatusOK, Header: make(http.Header), Body: body})
	}))
	defer server.Close()

	app, _ := configureBoundApp(t, "quota-fill-first", false)
	host := newFakeQuotaHost(now)
	var document map[string]any
	if err := json.Unmarshal(host.documents["idx-a"].JSON, &document); err != nil {
		t.Fatal(err)
	}
	document["proxy_url"] = "direct"
	raw, _ := json.Marshal(document)
	host.documents["idx-a"] = HostAuthDocument{AuthIndex: "idx-a", Name: "account-a-team.json", JSON: raw}
	attachTestQuotaHost(app, host, now)
	app.quota.verifyDelay = 0
	globalActivation := true
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{QuotaActivationEnabled: &globalActivation}); err != nil {
		t.Fatal(err)
	}
	bridgeEnabled := true
	bridgeActivation := false
	baseURL := server.URL
	key := "management-secret"
	if _, err := app.store.UpdateQuotaManagementSettings(policy.QuotaManagementSettingsPatch{Enabled: &bridgeEnabled, ActivationEnabled: &bridgeActivation, BaseURL: &baseURL, Key: &key}); err != nil {
		t.Fatal(err)
	}
	app.quota.mu.Lock()
	runtime := app.quota.runtime.Auths["account-a-team"]
	runtime.AuthID = "account-a-team"
	runtime.AuthIndex = "idx-a"
	runtime.CredentialFingerprint = codexCredentialFingerprint(codexCredentials{AccountID: "acct-a"})
	runtime.Provider = "codex"
	runtime.InManagedPool = true
	runtime.InMaintenanceScope = true
	runtime.InActivationScope = true
	runtime.QueryEligible = true
	runtime.Activation = quotaActivationState{Status: "ready", CycleID: "cycle-a", Windows: []quotaWindowKind{quotaWindowShort}}
	app.quota.runtime.Auths["account-a-team"] = runtime
	app.quota.mu.Unlock()
	targetInfo := codexMaintenanceTarget{AuthID: "account-a-team", AuthIndex: "idx-a", Credentials: codexCredentials{AccessToken: "access-a", AccountID: "acct-a", ExpiresAt: now.Add(time.Hour)}, Proxy: codexAuthProxy{Present: true, Value: "direct"}}

	app.quota.tryActivate(host, host.entries[0], targetInfo, []quotaWindowKind{quotaWindowShort}, now, false)
	mu.Lock()
	if len(methods) != 0 {
		t.Fatalf("disabled management activation sent requests: %v", methods)
	}
	mu.Unlock()
	app.quota.mu.Lock()
	if got := app.quota.runtime.Auths["account-a-team"].Activation.Attempts; got != 0 {
		t.Fatalf("disabled management activation consumed %d attempts", got)
	}
	app.quota.mu.Unlock()

	bridgeActivation = true
	if _, err := app.store.UpdateQuotaManagementSettings(policy.QuotaManagementSettingsPatch{ActivationEnabled: &bridgeActivation}); err != nil {
		t.Fatal(err)
	}
	app.quota.tryActivate(host, host.entries[0], targetInfo, []quotaWindowKind{quotaWindowShort}, now.Add(time.Minute), false)
	mu.Lock()
	defer mu.Unlock()
	if len(methods) < 2 || methods[0] != http.MethodPost || methods[1] != http.MethodGet {
		t.Fatalf("enabled management activation methods = %v, want POST then verification GET", methods)
	}
	_, hostGET, hostPOST := host.counts()
	if hostGET != 0 || hostPOST != 0 {
		t.Fatalf("bridge activation fell back to host callback: GET=%d POST=%d", hostGET, hostPOST)
	}
}

func TestLookupManualQuotaRefreshUsesManagementBridgeForProxyAuth(t *testing.T) {
	clock := time.Date(2026, 9, 22, 15, 0, 0, 0, time.UTC)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request quotaManagementAPICallRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Method != http.MethodGet || request.AuthIndex != "idx-a" || request.ProxyURL != "direct" {
			t.Fatalf("manual refresh request = %#v", request)
		}
		requests++
		_ = json.NewEncoder(w).Encode(quotaManagementAPICallResponse{StatusCode: http.StatusOK, Header: make(http.Header), Body: string(quotaBody(clock, 20))})
	}))
	defer server.Close()

	app, secret := configureBoundApp(t, policy.BindingStrategyRoundRobin, false)
	defer app.Shutdown()
	keyConfig := app.store.FindByID("bound-key")
	keyConfig.AllowQuotaRefresh = true
	if err := app.store.UpsertKey(*keyConfig, false); err != nil {
		t.Fatal(err)
	}
	enabled := true
	baseURL := server.URL
	managementKey := "management-secret"
	if _, err := app.store.UpdateQuotaManagementSettings(policy.QuotaManagementSettingsPatch{Enabled: &enabled, BaseURL: &baseURL, Key: &managementKey}); err != nil {
		t.Fatal(err)
	}
	host := newFakeQuotaHost(clock)
	var document map[string]any
	if err := json.Unmarshal(host.documents["idx-a"].JSON, &document); err != nil {
		t.Fatal(err)
	}
	document["proxy_url"] = "direct"
	raw, _ := json.Marshal(document)
	host.documents["idx-a"] = HostAuthDocument{AuthIndex: "idx-a", Name: "account-a-team.json", JSON: raw}
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }
	app.quota.mu.Lock()
	app.quota.host = host
	app.quota.mu.Unlock()
	app.quota.syncRosterOnly()
	if err := app.quota.persist(); err != nil {
		t.Fatal(err)
	}

	app.quota.bridge.pause(app.store.QuotaManagementSettings(), "management_bridge_auth_failed")
	paused := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, ""))
	if len(paused.AuthQuotas.Accounts) != 1 || paused.AuthQuotas.Accounts[0].CanRefresh || paused.AuthQuotas.Accounts[0].RefreshStatus != "transport_unavailable" {
		t.Fatalf("paused bridge refresh state = %#v", paused.AuthQuotas)
	}
	app.quota.bridge.reset()
	payload := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, ""))
	if len(payload.AuthQuotas.Accounts) != 1 || !payload.AuthQuotas.Accounts[0].CanRefresh {
		t.Fatalf("proxy auth lookup = %#v", payload.AuthQuotas)
	}
	response := quotaRefreshRequestForTest(t, app, secret, payload.AuthQuotas.Accounts[0].Ref, "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("manual proxy refresh = %d body=%s", response.StatusCode, response.Body)
	}
	if requests != 1 {
		t.Fatalf("management requests = %d, want 1", requests)
	}
	_, hostGET, hostPOST := host.counts()
	if hostGET != 0 || hostPOST != 0 {
		t.Fatalf("manual proxy refresh fell back to host callback: GET=%d POST=%d", hostGET, hostPOST)
	}
}

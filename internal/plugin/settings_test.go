package plugin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestSchedulerSettingsManagementAndRestartPersistence(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	app := configureSettingsApp(t, statePath)

	patchResponse := callManagementForTest(t, app, http.MethodPatch, "/v0/management/plugins/cpa-key-policy/settings", []byte(`{
		"global_weighted_round_robin": true,
		"auth_concurrency_limits": {"auth-a.json": 4},
		"session_affinity_idle_ttl_seconds": 900,
		"session_affinity_max_entries": 321,
		"quota_check_interval": "17m",
		"quota_cache_ttl": "43m",
		"quota_activation_enabled": true,
		"quota_activation_scope": "all-codex",
		"quota_activation_model": "custom-activation-model"
	}`))
	assertGlobalWeightedSetting(t, patchResponse, http.StatusOK, true)
	assertRuntimeSettings(t, patchResponse, 4, 900, 321)
	assertQuotaSettings(t, patchResponse, "17m", "43m", true, "all-codex", "custom-activation-model")

	getResponse := callManagementForTest(t, app, http.MethodGet, "/v0/management/plugins/cpa-key-policy/settings", nil)
	assertGlobalWeightedSetting(t, getResponse, http.StatusOK, true)

	restarted := configureSettingsApp(t, statePath)
	restartedResponse := callManagementForTest(t, restarted, http.MethodGet, "/v0/management/plugins/cpa-key-policy/settings", nil)
	assertGlobalWeightedSetting(t, restartedResponse, http.StatusOK, true)
	assertRuntimeSettings(t, restartedResponse, 4, 900, 321)
	assertQuotaSettings(t, restartedResponse, "17m", "43m", true, "all-codex", "custom-activation-model")
}

func TestQuotaManagementSettingsPersistRedactTestAndClear(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v0/management/plugins" {
			t.Fatalf("connection test request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer management-secret" {
			t.Fatalf("connection test authorization = %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"plugins": []any{}})
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "state.json")
	app := configureSettingsApp(t, statePath)
	patch, _ := json.Marshal(map[string]any{
		"quota_management_enabled":            true,
		"quota_management_activation_enabled": true,
		"quota_management_base_url":           server.URL,
		"quota_management_key":                "management-secret",
	})
	response := callManagementForTest(t, app, http.MethodPatch, "/v0/management/plugins/cpa-key-policy/settings", patch)
	assertQuotaManagementSettings(t, response, true, true, server.URL, true)
	if strings.Contains(string(response.Body), "management-secret") || strings.Contains(string(response.Body), "quota_management_key\"") {
		t.Fatalf("settings response leaked management key: %s", response.Body)
	}

	testResponse := callManagementForTest(t, app, http.MethodPost, "/v0/management/plugins/cpa-key-policy/quota-management/test", nil)
	if testResponse.StatusCode != http.StatusOK {
		t.Fatalf("connection test = %d body=%s", testResponse.StatusCode, testResponse.Body)
	}

	if ordinary := callManagementForTest(t, app, http.MethodPatch, "/v0/management/plugins/cpa-key-policy/settings", []byte(`{"quota_cache_ttl":"41m"}`)); ordinary.StatusCode != http.StatusOK {
		t.Fatalf("ordinary quota update = %d body=%s", ordinary.StatusCode, ordinary.Body)
	}
	restarted := configureSettingsApp(t, statePath)
	restartedResponse := callManagementForTest(t, restarted, http.MethodGet, "/v0/management/plugins/cpa-key-policy/settings", nil)
	assertQuotaManagementSettings(t, restartedResponse, true, true, server.URL, true)

	clearResponse := callManagementForTest(t, restarted, http.MethodPatch, "/v0/management/plugins/cpa-key-policy/settings", []byte(`{"quota_management_enabled":false,"quota_management_key":""}`))
	assertQuotaManagementSettings(t, clearResponse, false, true, server.URL, false)
}

func TestQuotaManagementSettingsRejectUnsafeBaseAndBaseChangeWithoutKey(t *testing.T) {
	app := configureSettingsApp(t, filepath.Join(t.TempDir(), "state.json"))
	unsafe := callManagementForTest(t, app, http.MethodPatch, "/v0/management/plugins/cpa-key-policy/settings", []byte(`{"quota_management_base_url":"http://localhost:8317","quota_management_key":"secret"}`))
	if unsafe.StatusCode != http.StatusBadRequest {
		t.Fatalf("unsafe base status = %d body=%s", unsafe.StatusCode, unsafe.Body)
	}
	first := callManagementForTest(t, app, http.MethodPatch, "/v0/management/plugins/cpa-key-policy/settings", []byte(`{"quota_management_base_url":"http://127.0.0.1:8318","quota_management_key":"secret"}`))
	if first.StatusCode != http.StatusOK {
		t.Fatalf("initial base update = %d body=%s", first.StatusCode, first.Body)
	}
	missingKey := callManagementForTest(t, app, http.MethodPatch, "/v0/management/plugins/cpa-key-policy/settings", []byte(`{"quota_management_base_url":"http://127.0.0.1:8319"}`))
	if missingKey.StatusCode != http.StatusBadRequest {
		t.Fatalf("base change without key status = %d body=%s", missingKey.StatusCode, missingKey.Body)
	}
}

func TestQuotaManagementRouteReturnsRuntimeStatus(t *testing.T) {
	app := configureSettingsApp(t, filepath.Join(t.TempDir(), "state.json"))
	response := callManagementForTest(t, app, http.MethodGet, "/v0/management/plugins/cpa-key-policy/quota-status", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("quota status = %d, body=%s", response.StatusCode, response.Body)
	}
	var payload struct {
		QuotaCheckInterval     string `json:"quota_check_interval"`
		QuotaCacheTTL          string `json:"quota_cache_ttl"`
		QuotaActivationEnabled bool   `json:"quota_activation_enabled"`
		QuotaActivationScope   string `json:"quota_activation_scope"`
		QuotaActivationModel   string `json:"quota_activation_model"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.QuotaCheckInterval != "30m" || payload.QuotaCacheTTL != "30m" || payload.QuotaActivationEnabled || payload.QuotaActivationScope != "managed-pools" || payload.QuotaActivationModel != "gpt-5.6-luna" {
		t.Fatalf("quota payload = %+v", payload)
	}
}

func TestQuotaManagementRegistrationAvoidsCPAReservedQuotaRoute(t *testing.T) {
	const reservedPath = "/plugins/cpa-key-policy/quota"
	const statusPath = "/plugins/cpa-key-policy/quota-status"
	foundStatus := false
	for _, route := range configureSettingsApp(t, filepath.Join(t.TempDir(), "state.json")).managementRegistration().Routes {
		if route.Path == reservedPath {
			t.Fatalf("quota status route conflicts with CPA v7.2.159 reserved path %q", reservedPath)
		}
		if route.Method == http.MethodGet && route.Path == statusPath {
			foundStatus = true
		}
	}
	if !foundStatus {
		t.Fatalf("quota status route %q is not registered", statusPath)
	}
}

func TestSchedulerSettingsRejectsInvalidConcurrencyLimit(t *testing.T) {
	app := configureSettingsApp(t, filepath.Join(t.TempDir(), "state.json"))
	response := callManagementForTest(t, app, http.MethodPatch, "/v0/management/plugins/cpa-key-policy/settings", []byte(`{"auth_concurrency_limits":{"auth-a.json":-1}}`))
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid setting status = %d, want 400; body=%s", response.StatusCode, response.Body)
	}
}

func TestSchedulerSettingsRejectsMissingValue(t *testing.T) {
	app := configureSettingsApp(t, filepath.Join(t.TempDir(), "state.json"))
	response := callManagementForTest(t, app, http.MethodPatch, "/v0/management/plugins/cpa-key-policy/settings", []byte(`{}`))
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺少设置时状态码 = %d，期望 %d，响应体 = %s", response.StatusCode, http.StatusBadRequest, response.Body)
	}
}

func configureSettingsApp(t *testing.T, statePath string) *App {
	t.Helper()
	app := NewApp()
	configYAML := []byte("enabled: true\nstate_file: \"" + filepath.ToSlash(statePath) + "\"\nglobal_weighted_round_robin: false\n")
	request, err := json.Marshal(LifecycleRequest{ConfigYAML: configYAML})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.HandleMethod(MethodPluginReconfigure, request); err != nil {
		t.Fatalf("配置调度设置测试应用失败: %v", err)
	}
	return app
}

func callManagementForTest(t *testing.T, app *App, method, path string, body []byte) ManagementResponse {
	t.Helper()
	request, err := json.Marshal(ManagementRequest{Method: method, Path: path, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := app.HandleMethod(MethodManagementHandle, request)
	if err != nil {
		t.Fatal(err)
	}
	return managementResponseFromEnvelope(t, raw)
}

func assertGlobalWeightedSetting(t *testing.T, response ManagementResponse, expectedStatus int, expectedValue bool) {
	t.Helper()
	if response.StatusCode != expectedStatus {
		t.Fatalf("设置接口状态码 = %d，期望 %d，响应体 = %s", response.StatusCode, expectedStatus, response.Body)
	}
	var payload struct {
		GlobalWeightedRoundRobin bool `json:"global_weighted_round_robin"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		t.Fatalf("解析设置接口响应失败: %v，响应体 = %s", err, response.Body)
	}
	if payload.GlobalWeightedRoundRobin != expectedValue {
		t.Fatalf("全局加权轮询 = %v，期望 %v", payload.GlobalWeightedRoundRobin, expectedValue)
	}
}

func assertRuntimeSettings(t *testing.T, response ManagementResponse, authLimit, idleTTL, maxEntries int) {
	t.Helper()
	var payload struct {
		AuthConcurrencyLimits         map[string]int `json:"auth_concurrency_limits"`
		SessionAffinityIdleTTLSeconds int            `json:"session_affinity_idle_ttl_seconds"`
		SessionAffinityMaxEntries     int            `json:"session_affinity_max_entries"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.AuthConcurrencyLimits["auth-a.json"] != authLimit ||
		payload.SessionAffinityIdleTTLSeconds != idleTTL ||
		payload.SessionAffinityMaxEntries != maxEntries {
		t.Fatalf("runtime settings = %+v", payload)
	}
}

func assertQuotaSettings(t *testing.T, response ManagementResponse, interval, ttl string, enabled bool, scope, model string) {
	t.Helper()
	var payload struct {
		QuotaCheckInterval     string `json:"quota_check_interval"`
		QuotaCacheTTL          string `json:"quota_cache_ttl"`
		QuotaActivationEnabled bool   `json:"quota_activation_enabled"`
		QuotaActivationScope   string `json:"quota_activation_scope"`
		QuotaActivationModel   string `json:"quota_activation_model"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.QuotaCheckInterval != interval || payload.QuotaCacheTTL != ttl || payload.QuotaActivationEnabled != enabled || payload.QuotaActivationScope != scope || payload.QuotaActivationModel != model {
		t.Fatalf("quota settings = %+v", payload)
	}
}

func assertQuotaManagementSettings(t *testing.T, response ManagementResponse, enabled, activation bool, baseURL string, configured bool) {
	t.Helper()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("management settings status = %d body=%s", response.StatusCode, response.Body)
	}
	var payload struct {
		Enabled           bool   `json:"quota_management_enabled"`
		ActivationEnabled bool   `json:"quota_management_activation_enabled"`
		BaseURL           string `json:"quota_management_base_url"`
		KeyConfigured     bool   `json:"quota_management_key_configured"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Enabled != enabled || payload.ActivationEnabled != activation || payload.BaseURL != baseURL || payload.KeyConfigured != configured {
		t.Fatalf("quota management settings = %+v", payload)
	}
}

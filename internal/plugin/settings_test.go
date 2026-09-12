package plugin

import (
	"encoding/json"
	"net/http"
	"path/filepath"
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
		"quota_activation_scope": "all-codex"
	}`))
	assertGlobalWeightedSetting(t, patchResponse, http.StatusOK, true)
	assertRuntimeSettings(t, patchResponse, 4, 900, 321)
	assertQuotaSettings(t, patchResponse, "17m", "43m", true, "all-codex")

	getResponse := callManagementForTest(t, app, http.MethodGet, "/v0/management/plugins/cpa-key-policy/settings", nil)
	assertGlobalWeightedSetting(t, getResponse, http.StatusOK, true)

	restarted := configureSettingsApp(t, statePath)
	restartedResponse := callManagementForTest(t, restarted, http.MethodGet, "/v0/management/plugins/cpa-key-policy/settings", nil)
	assertGlobalWeightedSetting(t, restartedResponse, http.StatusOK, true)
	assertRuntimeSettings(t, restartedResponse, 4, 900, 321)
	assertQuotaSettings(t, restartedResponse, "17m", "43m", true, "all-codex")
}

func TestQuotaManagementRouteReturnsRuntimeStatus(t *testing.T) {
	app := configureSettingsApp(t, filepath.Join(t.TempDir(), "state.json"))
	response := callManagementForTest(t, app, http.MethodGet, "/v0/management/plugins/cpa-key-policy/quota", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("quota status = %d, body=%s", response.StatusCode, response.Body)
	}
	var payload struct {
		QuotaCheckInterval     string `json:"quota_check_interval"`
		QuotaCacheTTL          string `json:"quota_cache_ttl"`
		QuotaActivationEnabled bool   `json:"quota_activation_enabled"`
		QuotaActivationScope   string `json:"quota_activation_scope"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.QuotaCheckInterval != "30m" || payload.QuotaCacheTTL != "30m" || payload.QuotaActivationEnabled || payload.QuotaActivationScope != "managed-pools" {
		t.Fatalf("quota payload = %+v", payload)
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

func assertQuotaSettings(t *testing.T, response ManagementResponse, interval, ttl string, enabled bool, scope string) {
	t.Helper()
	var payload struct {
		QuotaCheckInterval     string `json:"quota_check_interval"`
		QuotaCacheTTL          string `json:"quota_cache_ttl"`
		QuotaActivationEnabled bool   `json:"quota_activation_enabled"`
		QuotaActivationScope   string `json:"quota_activation_scope"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.QuotaCheckInterval != interval || payload.QuotaCacheTTL != ttl || payload.QuotaActivationEnabled != enabled || payload.QuotaActivationScope != scope {
		t.Fatalf("quota settings = %+v", payload)
	}
}

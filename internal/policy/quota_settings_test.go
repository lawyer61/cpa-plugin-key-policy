package policy

import (
	"path/filepath"
	"testing"
)

func TestQuotaRuntimeSettingsDefaultsArePassive(t *testing.T) {
	settings, err := normalizeRuntimeSettings(RuntimeSettings{})
	if err != nil {
		t.Fatal(err)
	}
	if settings.QuotaCheckInterval != "30m" || settings.QuotaCacheTTL != "30m" {
		t.Fatalf("durations = %q / %q", settings.QuotaCheckInterval, settings.QuotaCacheTTL)
	}
	if settings.QuotaActivationEnabled || settings.QuotaActivationScope != DefaultQuotaActivationScope {
		t.Fatalf("activation defaults = enabled:%v scope:%q", settings.QuotaActivationEnabled, settings.QuotaActivationScope)
	}
	if settings.QuotaActivationModel != "gpt-5.6-luna" {
		t.Fatalf("activation model = %q", settings.QuotaActivationModel)
	}
}

func TestQuotaRuntimeSettingsValidateDurationsAndScope(t *testing.T) {
	for _, settings := range []RuntimeSettings{
		{QuotaCheckInterval: "30s", QuotaCacheTTL: "30m"},
		{QuotaCheckInterval: "30m", QuotaCacheTTL: "bad"},
		{QuotaCheckInterval: "30m", QuotaCacheTTL: "30m", QuotaActivationScope: "host-everything"},
	} {
		if _, err := normalizeRuntimeSettings(settings); err == nil {
			t.Fatalf("settings unexpectedly valid: %#v", settings)
		}
	}
}

func TestQuotaRuntimeSettingsRejectExplicitEmptyValues(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte("quota_check_interval: ''\n"),
		[]byte("quota_cache_ttl: null\n"),
		[]byte("quota_activation_model: '  '\n"),
	} {
		if _, err := DecodeConfig(raw); err == nil {
			t.Fatalf("explicit empty setting accepted: %q", raw)
		}
	}
	store := NewStore()
	if err := store.Configure(DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	empty := "  "
	if _, err := store.UpdateRuntimeSettings(RuntimeSettingsPatch{QuotaCheckInterval: &empty}); err == nil {
		t.Fatal("empty quota_check_interval patch accepted")
	}
	if got := store.RuntimeSettings().QuotaCheckInterval; got != DefaultQuotaCheckInterval {
		t.Fatalf("invalid patch changed setting to %q", got)
	}
	if _, err := store.UpdateRuntimeSettings(RuntimeSettingsPatch{QuotaActivationModel: &empty}); err == nil {
		t.Fatal("empty quota_activation_model patch accepted")
	}
	if got := store.RuntimeSettings().QuotaActivationModel; got != DefaultQuotaActivationModel {
		t.Fatalf("invalid patch changed activation model to %q", got)
	}
}

func TestQuotaRuntimeSettingsPersistAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewStore()
	if err := store.Configure(Config{Enabled: true, StateFile: path}); err != nil {
		t.Fatal(err)
	}
	check := "17m"
	ttl := "43m"
	enabled := true
	scope := "all-codex"
	model := "custom-activation-model"
	if _, err := store.UpdateRuntimeSettings(RuntimeSettingsPatch{
		QuotaCheckInterval:     &check,
		QuotaCacheTTL:          &ttl,
		QuotaActivationEnabled: &enabled,
		QuotaActivationScope:   &scope,
		QuotaActivationModel:   &model,
	}); err != nil {
		t.Fatal(err)
	}
	reloaded := NewStore()
	if err := reloaded.Configure(Config{Enabled: true, StateFile: path}); err != nil {
		t.Fatal(err)
	}
	settings := reloaded.RuntimeSettings()
	if settings.QuotaCheckInterval != "17m" || settings.QuotaCacheTTL != "43m" || !settings.QuotaActivationEnabled || settings.QuotaActivationScope != scope || settings.QuotaActivationModel != model {
		t.Fatalf("reloaded settings = %#v", settings)
	}
}

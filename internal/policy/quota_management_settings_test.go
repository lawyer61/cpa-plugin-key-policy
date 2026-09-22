package policy

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func quotaManagementTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	cfg := DefaultConfig()
	cfg.StateFile = path
	store := NewStore()
	if err := store.Configure(cfg); err != nil {
		t.Fatalf("configure: %v", err)
	}
	return store, path
}

func TestQuotaManagementSettingsDefaultsAndLegacyState(t *testing.T) {
	store, path := quotaManagementTestStore(t)
	got := store.QuotaManagementSettings()
	if got != (QuotaManagementSettings{BaseURL: DefaultQuotaManagementBaseURL}) {
		t.Fatalf("defaults = %+v", got)
	}

	legacyPath := filepath.Join(t.TempDir(), "legacy-state.json")
	if err := SaveState(legacyPath, nil, nil, nil, nil); err != nil {
		t.Fatalf("save legacy-shaped state: %v", err)
	}
	reloaded := NewStore()
	cfg := DefaultConfig()
	cfg.StateFile = legacyPath
	if err := reloaded.Configure(cfg); err != nil {
		t.Fatalf("configure legacy state: %v", err)
	}
	if got := reloaded.QuotaManagementSettings(); got != (QuotaManagementSettings{BaseURL: DefaultQuotaManagementBaseURL}) {
		t.Fatalf("legacy defaults = %+v", got)
	}

	if state, err := LoadState(path); err != nil {
		t.Fatalf("load seeded state: %v", err)
	} else if state.QuotaManagement == nil {
		t.Fatal("seeded state omitted quota management defaults")
	}
}

func TestQuotaManagementSettingsPersistAndReload(t *testing.T) {
	store, path := quotaManagementTestStore(t)
	enabled := true
	activation := true
	baseURL := "  http://127.0.0.1:9900  "
	key := "  management-secret  "
	got, err := store.UpdateQuotaManagementSettings(QuotaManagementSettingsPatch{
		Enabled:           &enabled,
		ActivationEnabled: &activation,
		BaseURL:           &baseURL,
		Key:               &key,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	want := QuotaManagementSettings{
		Enabled:           true,
		ActivationEnabled: true,
		BaseURL:           "http://127.0.0.1:9900",
		Key:               "management-secret",
	}
	if got != want {
		t.Fatalf("updated settings = %+v, want %+v", got, want)
	}

	reloaded := NewStore()
	cfg := DefaultConfig()
	cfg.StateFile = path
	if err := reloaded.Configure(cfg); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.QuotaManagementSettings(); got != want {
		t.Fatalf("reloaded settings = %+v, want %+v", got, want)
	}
	state, err := LoadState(path)
	if err != nil {
		t.Fatalf("load persisted state: %v", err)
	}
	if state.QuotaManagement == nil || *state.QuotaManagement != want {
		t.Fatalf("persisted private settings = %+v, want %+v", state.QuotaManagement, want)
	}
}

func TestQuotaManagementSettingsPatchSemantics(t *testing.T) {
	store, _ := quotaManagementTestStore(t)
	enabled := true
	key := "secret"
	if _, err := store.UpdateQuotaManagementSettings(QuotaManagementSettingsPatch{Enabled: &enabled, Key: &key}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	original := store.QuotaManagementSettings()

	activation := true
	if _, err := store.UpdateQuotaManagementSettings(QuotaManagementSettingsPatch{ActivationEnabled: &activation}); err != nil {
		t.Fatalf("enable activation while master enabled: %v", err)
	}
	if got := store.QuotaManagementSettings(); got.Key != original.Key {
		t.Fatalf("nil key patch changed key: %+v", got)
	}

	disabled := false
	if _, err := store.UpdateQuotaManagementSettings(QuotaManagementSettingsPatch{Enabled: &disabled}); err != nil {
		t.Fatalf("disable master: %v", err)
	}
	if got := store.QuotaManagementSettings(); !got.ActivationEnabled || got.Key != original.Key {
		t.Fatalf("disabling master lost saved values: %+v", got)
	}

	cleared := ""
	if got, err := store.UpdateQuotaManagementSettings(QuotaManagementSettingsPatch{Key: &cleared}); err != nil {
		t.Fatalf("clear key: %v", err)
	} else if got.Key != "" || got.Enabled {
		t.Fatalf("cleared settings = %+v", got)
	}
}

func TestQuotaManagementSettingsRequiresKeyForEnableAndBaseURLChange(t *testing.T) {
	store, _ := quotaManagementTestStore(t)
	enabled := true
	if _, err := store.UpdateQuotaManagementSettings(QuotaManagementSettingsPatch{Enabled: &enabled}); err == nil {
		t.Fatal("enabling without an existing key unexpectedly succeeded")
	}

	key := "secret"
	if _, err := store.UpdateQuotaManagementSettings(QuotaManagementSettingsPatch{Key: &key}); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	newURL := "http://127.0.0.1:9901"
	if _, err := store.UpdateQuotaManagementSettings(QuotaManagementSettingsPatch{BaseURL: &newURL}); err == nil {
		t.Fatal("base URL change without replacement key unexpectedly succeeded")
	}
	if got := store.QuotaManagementSettings(); got.BaseURL != DefaultQuotaManagementBaseURL || got.Key != key {
		t.Fatalf("rejected URL change mutated state: %+v", got)
	}
	if _, err := store.UpdateQuotaManagementSettings(QuotaManagementSettingsPatch{BaseURL: &newURL, Key: &key}); err != nil {
		t.Fatalf("base URL change with replacement key: %v", err)
	}
}

func TestQuotaManagementSettingsSurviveUsageAndRuntimeSaves(t *testing.T) {
	store, path := quotaManagementTestStore(t)
	enabled := true
	key := "secret"
	if _, err := store.UpdateQuotaManagementSettings(QuotaManagementSettingsPatch{Enabled: &enabled, Key: &key}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	if err := SaveUsageOnly(path, map[string]*UsageState{}); err != nil {
		t.Fatalf("save usage only: %v", err)
	}
	if state, err := LoadState(path); err != nil {
		t.Fatalf("load after usage save: %v", err)
	} else if state.QuotaManagement == nil || state.QuotaManagement.Key != key {
		t.Fatalf("usage save lost private key: %+v", state.QuotaManagement)
	}

	weighted := true
	if _, err := store.UpdateRuntimeSettings(RuntimeSettingsPatch{GlobalWeightedRoundRobin: &weighted}); err != nil {
		t.Fatalf("runtime update: %v", err)
	}
	if got := store.QuotaManagementSettings(); got.Key != key || !got.Enabled {
		t.Fatalf("runtime update lost private settings: %+v", got)
	}
	if state, err := LoadState(path); err != nil {
		t.Fatalf("load after runtime update: %v", err)
	} else if state.QuotaManagement == nil || state.QuotaManagement.Key != key {
		t.Fatalf("runtime update lost private key: %+v", state.QuotaManagement)
	}

	if err := SaveState(path, store.Keys(), map[string]*UsageState{}, store.AliasesSnapshot(), store.ClassifyRulesSnapshot()); err != nil {
		t.Fatalf("generic full state save: %v", err)
	}
	if state, err := LoadState(path); err != nil {
		t.Fatalf("load after generic full save: %v", err)
	} else if state.QuotaManagement == nil || state.QuotaManagement.Key != key {
		t.Fatalf("generic full save lost private key: %+v", state.QuotaManagement)
	}
}

func TestQuotaManagementSettingsNotInPublicStatus(t *testing.T) {
	store, _ := quotaManagementTestStore(t)
	enabled := true
	key := "management-secret"
	if _, err := store.UpdateQuotaManagementSettings(QuotaManagementSettingsPatch{Enabled: &enabled, Key: &key}); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	raw, err := json.Marshal(store.Status())
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	for _, forbidden := range [][]byte{
		[]byte("management-secret"),
		[]byte("quota_management"),
		[]byte(`"base_url"`),
		[]byte(`"activation_enabled"`),
	} {
		if bytes.Contains(raw, forbidden) {
			t.Fatalf("public status contains forbidden field/value %q: %s", forbidden, raw)
		}
	}
}

package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeSettingsPersistAndEmptyAuthLimitsRemainAuthoritative(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewStore()
	if err := store.Configure(Config{
		Enabled:                       true,
		StateFile:                     path,
		GlobalWeightedRoundRobin:      true,
		AuthConcurrencyLimits:         map[string]int{"auth-a.json": 4},
		SessionAffinityIdleTTLSeconds: 900,
		SessionAffinityMaxEntries:     321,
	}); err != nil {
		t.Fatal(err)
	}
	state, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if state.AuthConcurrencyLimits == nil || (*state.AuthConcurrencyLimits)["auth-a.json"] != 4 {
		t.Fatalf("persisted auth limits = %#v", state.AuthConcurrencyLimits)
	}
	if state.SessionAffinityIdleTTLSeconds == nil || *state.SessionAffinityIdleTTLSeconds != 900 {
		t.Fatalf("persisted idle ttl = %#v", state.SessionAffinityIdleTTLSeconds)
	}
	if state.SessionAffinityMaxEntries == nil || *state.SessionAffinityMaxEntries != 321 {
		t.Fatalf("persisted max entries = %#v", state.SessionAffinityMaxEntries)
	}

	empty := map[string]int{}
	if _, err := store.UpdateRuntimeSettings(RuntimeSettingsPatch{AuthConcurrencyLimits: &empty}); err != nil {
		t.Fatal(err)
	}
	state, err = LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if state.AuthConcurrencyLimits == nil || len(*state.AuthConcurrencyLimits) != 0 {
		t.Fatalf("cleared auth limits lost authoritative empty map: %#v", state.AuthConcurrencyLimits)
	}
}

func TestLegacyStateWithoutRuntimeSettingsUsesConfigDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := SaveState(path, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	store := NewStore()
	if err := store.Configure(Config{
		Enabled:                       true,
		StateFile:                     path,
		AuthConcurrencyLimits:         map[string]int{"auth-a.json": 2},
		SessionAffinityIdleTTLSeconds: 77,
		SessionAffinityMaxEntries:     88,
	}); err != nil {
		t.Fatal(err)
	}
	settings := store.RuntimeSettings()
	if settings.AuthConcurrencyLimits["auth-a.json"] != 2 || settings.SessionAffinityIdleTTLSeconds != 77 || settings.SessionAffinityMaxEntries != 88 {
		t.Fatalf("legacy fallback settings = %+v", settings)
	}
}

func TestRuntimeSettingsValidation(t *testing.T) {
	tests := []Config{
		{Enabled: true, StateFile: filepath.Join(t.TempDir(), "negative-auth.json"), AuthConcurrencyLimits: map[string]int{"auth": -1}},
		{Enabled: true, StateFile: filepath.Join(t.TempDir(), "empty-auth.json"), AuthConcurrencyLimits: map[string]int{" ": 1}},
		{Enabled: true, StateFile: filepath.Join(t.TempDir(), "negative-ttl.json"), SessionAffinityIdleTTLSeconds: -1},
		{Enabled: true, StateFile: filepath.Join(t.TempDir(), "negative-cap.json"), SessionAffinityMaxEntries: -1},
		{Enabled: true, StateFile: filepath.Join(t.TempDir(), "negative-key.json"), Keys: []KeyConfig{{ID: "key", Enabled: true, MaxConcurrentRequests: -1}}},
	}
	for index, cfg := range tests {
		if err := NewStore().Configure(cfg); err == nil {
			t.Fatalf("case %d accepted invalid settings", index)
		}
	}
}

func TestSaveUsageOnlyPreservesRuntimeSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewStore()
	if err := store.Configure(Config{
		Enabled:                       true,
		StateFile:                     path,
		AuthConcurrencyLimits:         map[string]int{"auth-a.json": 3},
		SessionAffinityIdleTTLSeconds: 123,
		SessionAffinityMaxEntries:     456,
		QuotaActivationModel:          "preserved-model",
	}); err != nil {
		t.Fatal(err)
	}
	if err := SaveUsageOnly(path, map[string]*UsageState{}); err != nil {
		t.Fatal(err)
	}
	state, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if state.AuthConcurrencyLimits == nil || (*state.AuthConcurrencyLimits)["auth-a.json"] != 3 ||
		state.SessionAffinityIdleTTLSeconds == nil || *state.SessionAffinityIdleTTLSeconds != 123 ||
		state.SessionAffinityMaxEntries == nil || *state.SessionAffinityMaxEntries != 456 ||
		state.QuotaActivationModel == nil || *state.QuotaActivationModel != "preserved-model" {
		raw, _ := os.ReadFile(path)
		t.Fatalf("settings not preserved: %s", raw)
	}
}

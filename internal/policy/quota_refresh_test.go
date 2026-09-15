package policy

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeKeyCannotEnableQuotaRefresh(t *testing.T) {
	hash, err := HashKey("native-secret")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{{
			ID:                "native",
			Enabled:           true,
			Native:            true,
			KeyHash:           hash,
			CallerScope:       CallerScopeForKey("native-secret"),
			AccountBinding:    &AccountBinding{Allow: []string{"codex-*"}},
			AllowQuotaRefresh: true,
		}},
	}
	if _, err := DecodeConfig(nil); err != nil {
		t.Fatal(err)
	}
	if err := normalizeConfig(&cfg); err == nil || !strings.Contains(err.Error(), "cannot allow quota refresh") {
		t.Fatalf("native quota refresh validation error=%v", err)
	}
}

func TestQuotaRefreshPermissionPersistsAndLegacyDefaultIsFalse(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	store := NewStore()
	if err := store.Configure(Config{Enabled: true, StateFile: statePath}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertKey(KeyConfig{
		ID:                "derived",
		Enabled:           true,
		KeyHash:           hashForPolicyTest(t, "cpa-derived"),
		AllowQuotaRefresh: true,
	}, true); err != nil {
		t.Fatal(err)
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Keys) != 1 || !state.Keys[0].AllowQuotaRefresh {
		t.Fatalf("persisted keys=%#v", state.Keys)
	}
	legacy, err := DecodeConfig([]byte("enabled: true\nkeys:\n  - id: old\n    enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy.Keys) != 1 || legacy.Keys[0].AllowQuotaRefresh {
		t.Fatalf("legacy default=%#v", legacy.Keys)
	}
}

func hashForPolicyTest(t *testing.T, secret string) string {
	t.Helper()
	hash, err := HashKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

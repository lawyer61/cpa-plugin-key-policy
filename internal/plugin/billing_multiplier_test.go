package plugin

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"cpa-key-policy/internal/policy"
)

func TestManagementBillingMultiplierRoundTripAndLegacyPatchPreservation(t *testing.T) {
	app := NewApp()
	configYAML := []byte(`
enabled: true
state_file: "` + filepath.ToSlash(filepath.Join(t.TempDir(), "state.json")) + `"
aliases:
  - alias: priced
    targets:
      - provider: codex
        target_model: gpt-test
    billing_mode: tokens
    input_price_per_million: 1
    billing_multiplier: 1.5
`)
	request, _ := json.Marshal(LifecycleRequest{ConfigYAML: configYAML})
	if _, err := app.HandleMethod(MethodPluginReconfigure, request); err != nil {
		t.Fatal(err)
	}

	response := app.createKey([]byte(`{
  "id": "custom-multiplier",
  "models": [{
    "alias": "priced",
    "provider": "codex",
    "target_model": "gpt-test",
    "billing_mode": "tokens",
    "input_price_per_million": 1,
    "billing_multiplier": 2
  }]
}`))
	if response.StatusCode != 201 {
		t.Fatalf("create status = %d, body = %s", response.StatusCode, response.Body)
	}
	key := app.store.FindByID("custom-multiplier")
	if key == nil || len(key.Models) != 1 || key.Models[0].BillingMultiplier == nil || *key.Models[0].BillingMultiplier != 2 {
		t.Fatalf("created multiplier = %+v", key)
	}
	if got := app.store.RecordUsage("custom-multiplier", "priced", "gpt-test", false, policy.UsageDetail{InputTokens: 1_000_000}); got != 2 {
		t.Fatalf("created key cost = %v, want 2", got)
	}

	// Simulate a pre-v0.10 client that resubmits model pricing without the new
	// field. The existing per-key multiplier override must survive.
	response = app.patchKey([]byte(`{
  "id": "custom-multiplier",
  "models": [{
    "alias": "priced",
    "provider": "codex",
    "target_model": "gpt-test",
    "billing_mode": "tokens",
    "input_price_per_million": 3
  }]
}`))
	if response.StatusCode != 200 {
		t.Fatalf("legacy patch status = %d, body = %s", response.StatusCode, response.Body)
	}
	key = app.store.FindByID("custom-multiplier")
	if key == nil || key.Models[0].BillingMultiplier == nil || *key.Models[0].BillingMultiplier != 2 {
		t.Fatalf("legacy patch cleared multiplier: %+v", key)
	}
	if got := app.store.RecordUsage("custom-multiplier", "priced", "gpt-test", false, policy.UsageDetail{InputTokens: 1_000_000}); got != 6 {
		t.Fatalf("legacy patch cost = %v, want 6", got)
	}
}

func TestManagementRejectsNonPositiveBillingMultiplier(t *testing.T) {
	app := NewApp()
	if err := app.store.Configure(policy.Config{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state.json")}); err != nil {
		t.Fatal(err)
	}
	response := app.upsertAlias([]byte(`{
  "alias": "bad",
  "targets": [{"provider":"codex","target_model":"gpt-test"}],
  "billing_mode": "tokens",
  "billing_multiplier": 0
}`))
	if response.StatusCode != 400 {
		t.Fatalf("status = %d, body = %s", response.StatusCode, response.Body)
	}
}

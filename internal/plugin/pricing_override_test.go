package plugin

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"cpa-key-policy/internal/policy"
)

func TestManagementCreatePersistsPerKeyPricingForExistingAlias(t *testing.T) {
	app := NewApp()
	configYAML := []byte(`
enabled: true
state_file: "` + filepath.ToSlash(filepath.Join(t.TempDir(), "state.json")) + `"
aliases:
  - alias: gemini-flash
    targets:
      - provider: antigravity
        target_model: gemini-2.5-flash
    billing_mode: per_call
    per_call_usd: 0.5
`)
	request, _ := json.Marshal(LifecycleRequest{ConfigYAML: configYAML})
	if _, err := app.HandleMethod(MethodPluginReconfigure, request); err != nil {
		t.Fatal(err)
	}

	response := app.createKey([]byte(`{
  "id": "antigravity-priced",
  "models": [{
    "alias": "gemini-flash",
    "provider": "antigravity",
    "target_model": "gemini-2.5-flash",
    "billing_mode": "tokens",
    "input_price_per_million": 0.025,
    "output_price_per_million": 0.1
  }]
}`))
	if response.StatusCode != 201 {
		t.Fatalf("create status = %d, body = %s", response.StatusCode, response.Body)
	}
	key := app.store.FindByID("antigravity-priced")
	if key == nil || len(key.Models) != 1 {
		t.Fatalf("created key = %+v", key)
	}
	model := key.Models[0]
	if model.BillingMode != "tokens" || model.InputPricePerMillion != 0.025 || model.OutputPricePerMillion != 0.1 {
		t.Fatalf("created model pricing = %+v", model)
	}

	response = app.patchKey([]byte(`{
  "id": "antigravity-priced",
  "models": [{
    "alias": "gemini-flash",
    "provider": "antigravity",
    "target_model": "gemini-2.5-flash",
    "billing_mode": "tokens",
    "input_price_per_million": 0.05,
    "output_price_per_million": 0.2
  }]
}`))
	if response.StatusCode != 200 {
		t.Fatalf("patch status = %d, body = %s", response.StatusCode, response.Body)
	}
	key = app.store.FindByID("antigravity-priced")
	if key == nil || len(key.Models) != 1 {
		t.Fatalf("patched key = %+v", key)
	}
	model = key.Models[0]
	if model.InputPricePerMillion != 0.05 || model.OutputPricePerMillion != 0.2 {
		t.Fatalf("patched model pricing = %+v", model)
	}

	cost := app.store.RecordUsage("antigravity-priced", "gemini-flash", "gemini-2.5-flash", false, policy.UsageDetail{
		InputTokens:  1_000_000,
		OutputTokens: 1_000_000,
		TotalTokens:  2_000_000,
	})
	if cost != 0.25 {
		t.Fatalf("cost = %v, want 0.25", cost)
	}
}

package policy

import (
	"path/filepath"
	"testing"
)

func TestUpsertKeyWithModelPricingPersistsPerKeyOverride(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	store := NewStore()
	if err := store.Configure(Config{
		Enabled:   true,
		StateFile: statePath,
		Aliases: []AliasMapping{{
			Alias:       "gemini-flash",
			Targets:     []AliasTarget{{Provider: "antigravity", TargetModel: "gemini-2.5-flash"}},
			BillingMode: "per_call",
			PerCallUSD:  0.50,
		}},
		Keys: []KeyConfig{{
			ID: "default-price", Enabled: true, KeyHash: "default",
			Aliases: []KeyAliasRef{{Alias: "gemini-flash"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.UpsertKeyWithModelPricing(KeyConfig{
		ID: "custom-price", Enabled: true, KeyHash: "custom",
		Models: []ModelRule{{
			Alias: "gemini-flash", Provider: "antigravity", TargetModel: "gemini-2.5-flash",
			BillingMode: "tokens", InputPricePerMillion: 0.025, OutputPricePerMillion: 0.10,
		}},
	}, true); err != nil {
		t.Fatal(err)
	}

	aliases := store.AliasesSnapshot()
	if len(aliases) != 1 || aliases[0].BillingMode != "per_call" || aliases[0].PerCallUSD != 0.50 {
		t.Fatalf("global alias default changed: %+v", aliases)
	}
	byID := map[string]KeyConfig{}
	for _, key := range store.Keys() {
		byID[key.ID] = key
	}
	custom := byID["custom-price"]
	if len(custom.Models) != 1 {
		t.Fatalf("custom models = %+v", custom.Models)
	}
	model := custom.Models[0]
	if model.BillingMode != "tokens" || model.InputPricePerMillion != 0.025 || model.OutputPricePerMillion != 0.10 {
		t.Fatalf("custom model pricing = %+v", model)
	}
	defaultModel := byID["default-price"].Models[0]
	if defaultModel.BillingMode != "per_call" || defaultModel.PerCallUSD != 0.50 {
		t.Fatalf("default key should still inherit global pricing: %+v", defaultModel)
	}

	cost := store.RecordUsage("custom-price", "gemini-flash", "gemini-2.5-flash", false, UsageDetail{
		InputTokens: 1_000_000, OutputTokens: 1_000_000, TotalTokens: 2_000_000,
	})
	if !nearly(cost, 0.125) {
		t.Fatalf("custom key cost = %v, want 0.125", cost)
	}

	reloaded := NewStore()
	if err := reloaded.Configure(Config{Enabled: true, StateFile: statePath}); err != nil {
		t.Fatal(err)
	}
	loaded, ok := reloaded.FindByID("custom-price"), false
	if loaded != nil {
		ok = true
	}
	if !ok || len(loaded.Models) != 1 {
		t.Fatalf("reloaded custom key = %+v", loaded)
	}
	if got := loaded.Models[0]; got.BillingMode != "tokens" || got.InputPricePerMillion != 0.025 || got.OutputPricePerMillion != 0.10 {
		t.Fatalf("reloaded custom model pricing = %+v", got)
	}
}

func TestOrdinaryUpsertKeepsExistingPricingOverrides(t *testing.T) {
	store := NewStore()
	statePath := filepath.Join(t.TempDir(), "state.json")
	mode := "tokens"
	inputPrice := 0.025
	outputPrice := 0.10
	if err := store.Configure(Config{
		Enabled:   true,
		StateFile: statePath,
		Aliases: []AliasMapping{{
			Alias:       "gemini-flash",
			Targets:     []AliasTarget{{Provider: "antigravity", TargetModel: "gemini-2.5-flash"}},
			BillingMode: "per_call",
			PerCallUSD:  0.5,
		}},
		Keys: []KeyConfig{{
			ID: "custom", Enabled: true, KeyHash: "x",
			Aliases: []KeyAliasRef{{
				Alias: "gemini-flash", BillingMode: &mode,
				InputPricePerMillion: &inputPrice, OutputPricePerMillion: &outputPrice,
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	key := store.FindByID("custom")
	if key == nil {
		t.Fatal("key not found")
	}
	key.Enabled = false
	if err := store.UpsertKey(*key, true); err != nil {
		t.Fatal(err)
	}
	reloaded := store.FindByID("custom")
	if reloaded == nil || len(reloaded.Models) != 1 {
		t.Fatalf("reloaded key = %+v", reloaded)
	}
	got := reloaded.Models[0]
	if got.BillingMode != "tokens" || got.InputPricePerMillion != 0.025 || got.OutputPricePerMillion != 0.10 {
		t.Fatalf("ordinary upsert changed pricing override: %+v", got)
	}
}

func TestAntigravityReasoningTokensUseOutputPrice(t *testing.T) {
	store := NewStore()
	if err := store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{{
			ID: "antigravity", Enabled: true, KeyHash: "ag",
			Models: []ModelRule{{
				Alias: "gemini-pro", Provider: "antigravity", TargetModel: "gemini-2.5-pro",
				BillingMode: "tokens", InputPricePerMillion: 1, OutputPricePerMillion: 2,
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	cost := store.RecordUsage("antigravity", "gemini-pro", "gemini-2.5-pro", false, UsageDetail{
		InputTokens: 1_000_000, OutputTokens: 500_000, ReasoningTokens: 250_000, TotalTokens: 1_750_000,
	})
	if !nearly(cost, 2.50) {
		t.Fatalf("cost = %v, want 2.50", cost)
	}
	_, rows, ok := store.AliasUsageFor("antigravity")
	if !ok || len(rows) != 1 {
		t.Fatalf("usage rows = %+v, ok=%v", rows, ok)
	}
	if rows[0].Daily.OutputTokens != 750_000 || rows[0].Weekly.OutputTokens != 750_000 {
		t.Fatalf("billed output tokens = daily %d weekly %d, want 750000", rows[0].Daily.OutputTokens, rows[0].Weekly.OutputTokens)
	}
}

package policy

import (
	"math"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func multiplierPtr(value float64) *float64 { return &value }

func TestBillingMultiplierInheritanceOverrideAndPersistence(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	globalMultiplier := 1.5
	overrideMultiplier := 2.0
	one := 1.0
	store := NewStore()
	if err := store.Configure(Config{
		Enabled:   true,
		StateFile: statePath,
		Aliases: []AliasMapping{{
			Alias: "priced", Targets: []AliasTarget{{Provider: "codex", TargetModel: "gpt-test"}},
			BillingMode: "tokens", InputPricePerMillion: 1, BillingMultiplier: &globalMultiplier,
		}},
		Keys: []KeyConfig{
			{ID: "inherit", Enabled: true, KeyHash: "inherit", Aliases: []KeyAliasRef{{Alias: "priced"}}},
			{ID: "override", Enabled: true, KeyHash: "override", Aliases: []KeyAliasRef{{Alias: "priced", BillingMultiplier: &overrideMultiplier}}},
			{ID: "explicit-one", Enabled: true, KeyHash: "one", Aliases: []KeyAliasRef{{Alias: "priced", BillingMultiplier: &one}}},
		},
	}); err != nil {
		t.Fatal(err)
	}

	detail := UsageDetail{InputTokens: 1_000_000, TotalTokens: 1_000_000}
	if got := store.RecordUsage("inherit", "priced", "gpt-test", false, detail); !nearly(got, 1.5) {
		t.Fatalf("inherited multiplier cost = %v, want 1.5", got)
	}
	if got := store.RecordUsage("override", "priced", "gpt-test", false, detail); !nearly(got, 2) {
		t.Fatalf("override multiplier cost = %v, want 2 (replacement, not stacking)", got)
	}
	if got := store.RecordUsage("explicit-one", "priced", "gpt-test", false, detail); !nearly(got, 1) {
		t.Fatalf("explicit one multiplier cost = %v, want 1", got)
	}
	if err := store.FlushUsage(); err != nil {
		t.Fatal(err)
	}

	reloaded := NewStore()
	if err := reloaded.Configure(Config{Enabled: true, StateFile: statePath}); err != nil {
		t.Fatal(err)
	}
	key := reloaded.FindByID("override")
	if key == nil || len(key.Models) != 1 || key.Models[0].BillingMultiplier == nil || *key.Models[0].BillingMultiplier != 2 {
		t.Fatalf("reloaded effective multiplier = %+v", key)
	}
	summary := reloaded.UsageSummaryFor(*key)
	if !nearly(summary.DailyUSD, 2) || !nearly(summary.WeeklyUSD, 2) {
		t.Fatalf("reloaded usage = daily %v weekly %v, want 2/2", summary.DailyUSD, summary.WeeklyUSD)
	}
}

func TestBillingMultiplierScalesTokenCacheAndPerCallOnce(t *testing.T) {
	store := NewStore()
	tokenMultiplier := 1.5
	perCallMultiplier := 2.0
	if err := store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Aliases: []AliasMapping{
			{
				Alias: "tokens", Targets: []AliasTarget{{Provider: "codex", TargetModel: "gpt-test"}},
				BillingMode: "tokens", InputPricePerMillion: 3, OutputPricePerMillion: 15,
				CacheReadPricePerMillion: 0.3, BillingMultiplier: &tokenMultiplier,
			},
			{
				Alias: "call", Targets: []AliasTarget{{Provider: "xai", TargetModel: "image-test"}},
				BillingMode: "per_call", PerCallUSD: 0.025, BillingMultiplier: &perCallMultiplier,
			},
		},
		Keys: []KeyConfig{{
			ID: "scaled", Enabled: true, KeyHash: "scaled",
			Aliases: []KeyAliasRef{{Alias: "tokens"}, {Alias: "call"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	cost := store.RecordUsage("scaled", "tokens", "gpt-test", false, UsageDetail{
		InputTokens: 1_000_000, OutputTokens: 500_000, CachedTokens: 200_000, TotalTokens: 1_500_000,
	})
	if !nearly(cost, 14.94) {
		t.Fatalf("token cost = %v, want 14.94", cost)
	}
	if got := store.RecordUsage("scaled", "call", "image-test", false, UsageDetail{}); !nearly(got, 0.05) {
		t.Fatalf("per-call cost = %v, want 0.05", got)
	}
	_, rows, ok := store.AliasUsageFor("scaled")
	if !ok || len(rows) != 2 {
		t.Fatalf("usage rows = %+v, ok=%v", rows, ok)
	}
	for _, row := range rows {
		switch row.Alias {
		case "tokens":
			if !nearly(row.Daily.TotalUSD, 14.94) || !nearly(row.Daily.CacheCostUSD, 0.09) {
				t.Fatalf("scaled token row = %+v", row.Daily)
			}
			if row.Daily.CacheReadTokens != 200_000 || row.Daily.InputTokens != 800_000 || row.Daily.OutputTokens != 500_000 || row.Daily.CallCount != 1 {
				t.Fatalf("token counters were scaled or changed: %+v", row.Daily)
			}
		case "call":
			if !nearly(row.Daily.TotalUSD, 0.05) || row.Daily.CallCount != 1 {
				t.Fatalf("scaled per-call row = %+v", row.Daily)
			}
		}
	}
}

func TestBillingMultiplierChangeDoesNotRepriceHistory(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	firstMultiplier := 1.5
	if err := store.Configure(Config{
		Enabled: true, StateFile: filepath.Join(t.TempDir(), "state.json"),
		Aliases: []AliasMapping{{
			Alias: "call", Targets: []AliasTarget{{Provider: "codex", TargetModel: "gpt-test"}},
			BillingMode: "per_call", PerCallUSD: 2, BillingMultiplier: &firstMultiplier,
		}},
		Keys: []KeyConfig{{ID: "history", Enabled: true, KeyHash: "history", Aliases: []KeyAliasRef{{Alias: "call"}}}},
	}); err != nil {
		t.Fatal(err)
	}
	if got := store.RecordUsage("history", "call", "gpt-test", false, UsageDetail{}); !nearly(got, 3) {
		t.Fatalf("first cost = %v, want 3", got)
	}
	secondMultiplier := 2.0
	if err := store.UpsertAlias(AliasMapping{
		Alias: "call", Targets: []AliasTarget{{Provider: "codex", TargetModel: "gpt-test"}},
		BillingMode: "per_call", PerCallUSD: 2, BillingMultiplier: &secondMultiplier,
	}); err != nil {
		t.Fatal(err)
	}
	if got := store.RecordUsage("history", "call", "gpt-test", false, UsageDetail{}); !nearly(got, 4) {
		t.Fatalf("second cost = %v, want 4", got)
	}
	key := store.FindByID("history")
	summary := store.UsageSummaryFor(*key)
	if !nearly(summary.DailyUSD, 7) || !nearly(summary.WeeklyUSD, 7) || summary.DailyCallCount != 2 {
		t.Fatalf("history was repriced: %+v", summary)
	}
}

func TestBillingMultiplierValidationAndLegacyDefault(t *testing.T) {
	base := `
enabled: true
aliases:
  - alias: priced
    targets:
      - provider: codex
        target_model: gpt-test
    input_price_per_million: 1
`
	cfg, err := DecodeConfig([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore()
	if err := store.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	if len(store.AliasesSnapshot()) != 1 || store.AliasesSnapshot()[0].BillingMultiplier != nil {
		t.Fatalf("legacy alias should preserve an omitted multiplier: %+v", store.AliasesSnapshot())
	}
	if err := store.UpsertKey(KeyConfig{
		ID: "legacy", Enabled: true, KeyHash: "legacy", Aliases: []KeyAliasRef{{Alias: "priced"}},
	}, false); err != nil {
		t.Fatal(err)
	}
	if got := store.RecordUsage("legacy", "priced", "gpt-test", false, UsageDetail{InputTokens: 1_000_000}); !nearly(got, 1) {
		t.Fatalf("legacy omitted multiplier cost = %v, want 1", got)
	}

	for _, value := range []string{"0", "-1", ".nan", ".inf"} {
		raw := base + "    billing_multiplier: " + value + "\n"
		if _, err := DecodeConfig([]byte(raw)); err == nil || !strings.Contains(err.Error(), "billing_multiplier") {
			t.Fatalf("billing_multiplier %s error = %v", value, err)
		}
	}

	for _, value := range []*float64{multiplierPtr(math.NaN()), multiplierPtr(math.Inf(1)), multiplierPtr(0)} {
		cfg := Config{Enabled: true, Aliases: []AliasMapping{{
			Alias: "bad", Targets: []AliasTarget{{Provider: "codex", TargetModel: "gpt-test"}}, BillingMultiplier: value,
		}}}
		if err := normalizeConfig(&cfg); err == nil {
			t.Fatalf("accepted invalid multiplier %v", *value)
		}
	}
}

func TestAliasUpdateWithoutMultiplierPreservesExistingValue(t *testing.T) {
	store := NewStore()
	multiplier := 1.5
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := store.Configure(Config{Enabled: true, StateFile: statePath, Aliases: []AliasMapping{{
		Alias: "priced", Targets: []AliasTarget{{Provider: "codex", TargetModel: "gpt-test"}}, BillingMultiplier: &multiplier,
	}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAlias(AliasMapping{
		Alias: "priced", Targets: []AliasTarget{{Provider: "codex", TargetModel: "gpt-test-2"}}, BillingMode: "tokens",
	}); err != nil {
		t.Fatal(err)
	}
	aliases := store.AliasesSnapshot()
	if len(aliases) != 1 || aliases[0].BillingMultiplier == nil || *aliases[0].BillingMultiplier != 1.5 {
		t.Fatalf("omitted update cleared multiplier: %+v", aliases)
	}
}

func TestRecordResponseCostUsesBillingMultiplierWithoutCreatingASecondPath(t *testing.T) {
	multiplier := 1.5
	store := NewStore()
	if err := store.Configure(Config{
		Enabled: true, StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{{
			ID: "response", Enabled: true, KeyHash: hashForUsageTest(t, "response-secret"),
			Models: []ModelRule{{
				Alias: "priced", Provider: "codex", TargetModel: "gpt-test",
				InputPricePerMillion: 1, BillingMultiplier: &multiplier,
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"Authorization": {"Bearer response-secret"}}
	cost := store.RecordResponseCost(headers, nil, "priced", []byte(`{"usage":{"prompt_tokens":1000000,"completion_tokens":0}}`))
	if !nearly(cost, 1.5) {
		t.Fatalf("response helper cost = %v, want 1.5", cost)
	}
	key := store.FindByID("response")
	if summary := store.UsageSummaryFor(*key); !nearly(summary.DailyUSD, 1.5) || summary.DailyCallCount != 1 {
		t.Fatalf("response helper usage = %+v", summary)
	}
}

func TestNonFiniteScaledCostIsNotPersistedOrSilentlyZeroed(t *testing.T) {
	multiplier := 2.0
	store := NewStore()
	if err := store.Configure(Config{
		Enabled: true, StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{{
			ID: "overflow", Enabled: true, KeyHash: "overflow",
			Models: []ModelRule{{
				Alias: "priced", Provider: "codex", TargetModel: "gpt-test",
				InputPricePerMillion: math.MaxFloat64, BillingMultiplier: &multiplier,
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	cost := store.RecordUsage("overflow", "priced", "gpt-test", false, UsageDetail{InputTokens: 1_000_000})
	if !math.IsInf(cost, 1) {
		t.Fatalf("overflow cost = %v, want +Inf signal", cost)
	}
	key := store.FindByID("overflow")
	if summary := store.UsageSummaryFor(*key); summary.DailyUSD != 0 || summary.DailyCallCount != 0 {
		t.Fatalf("non-finite cost reached the ledger: %+v", summary)
	}
}

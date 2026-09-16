package policy

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newClockedStore(t *testing.T, now time.Time) (*Store, time.Time) {
	t.Helper()
	tm := now
	store := NewStore()
	store.SetClock(func() time.Time { return tm })
	err := store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{
			{
				ID: "team-a", Enabled: true,
				KeyHash:    hashForUsageTest(t, "cpa_usage"),
				KeyPreview: "cpa_us..._age",
				Models: []ModelRule{
					{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex",
						InputPricePerMillion: 1, OutputPricePerMillion: 2},
				},
				DailyLimitUSD:  1.00,
				WeeklyLimitUSD: 5.00,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, tm
}

func hashForUsageTest(t *testing.T, key string) string {
	t.Helper()
	h, err := HashKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestUsageRecordAndOverLimitDaily(t *testing.T) {
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	store, tm := newClockedStore(t, now)
	headers := map[string][]string{"Authorization": {"Bearer cpa_usage"}}

	// 500K prompt × $1/M = $0.50 → under the $1 daily limit.
	_ = store.RecordResponseCost(headers, nil, "fast", []byte(`{"usage":{"prompt_tokens":500000,"completion_tokens":0}}`))
	d := store.Authenticate("POST", "/v1/chat/completions", headers, nil, []byte(`{"model":"fast"}`))
	if !d.Allowed {
		t.Fatalf("first request should be allowed: %+v", d)
	}
	// Another $0.50 → total $1.00, equals the daily limit. Billing is
	// post-hoc: this request itself was allowed (the prior Authenticate
	// passed), but the NEXT request now sees daily_usd >= limit and is
	// rejected (Authenticate is a pre-request gate on accumulated usage).
	_ = store.RecordResponseCost(headers, nil, "fast", []byte(`{"usage":{"prompt_tokens":500000,"completion_tokens":0}}`))
	d = store.Authenticate("POST", "/v1/chat/completions", headers, nil, []byte(`{"model":"fast"}`))
	if d.Allowed || !d.CostLimited || d.Reason != "daily_exceeded" {
		t.Fatalf("at-limit request should be rejected on the next Authenticate: %+v", d)
	}
	// Crossing UTC midnight resets the daily window.
	tm = tm.Add(14 * time.Hour) // next day
	store.SetClock(func() time.Time { return tm })
	d = store.Authenticate("POST", "/v1/chat/completions", headers, nil, []byte(`{"model":"fast"}`))
	if !d.Allowed {
		t.Fatalf("after midnight should be allowed again: %+v", d)
	}
}

func TestUsageUnlimitedKeyNeverBlocked(t *testing.T) {
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	err := store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{{
			ID: "free", Enabled: true,
			KeyHash: hashForUsageTest(t, "cpa_free"),
			Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex",
				InputPricePerMillion: 10, OutputPricePerMillion: 10}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hdr := map[string][]string{"Authorization": {"Bearer cpa_free"}}
	for i := 0; i < 50; i++ {
		_ = store.RecordResponseCost(hdr, nil, "fast", []byte(`{"usage":{"prompt_tokens":1000000,"completion_tokens":1000000}}`))
		d := store.Authenticate("POST", "/v1/chat/completions", hdr, nil, []byte(`{"model":"fast"}`))
		if !d.Allowed {
			t.Fatalf("unlimited key blocked at iter %d: %+v", i, d)
		}
	}
}

func TestUsageUnpricedAliasNotBilled(t *testing.T) {
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	err := store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{{
			ID: "cheap", Enabled: true, DailyLimitUSD: 0.01,
			KeyHash: hashForUsageTest(t, "cpa_cheap"),
			Models:  []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex"}}, // no prices
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hdr := map[string][]string{"Authorization": {"Bearer cpa_cheap"}}
	_ = store.RecordResponseCost(hdr, nil, "fast", []byte(`{"usage":{"prompt_tokens":99999999,"completion_tokens":99999999}}`))
	d := store.Authenticate("POST", "/v1/chat/completions", hdr, nil, []byte(`{"model":"fast"}`))
	if !d.Allowed {
		t.Fatalf("unpriced alias should never exceed: %+v", d)
	}
}

func TestUsageStreamingBilledWhenUsageFrame(t *testing.T) {
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	err := store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{{
			ID: "streamy", Enabled: true, DailyLimitUSD: 0.01,
			KeyHash: hashForUsageTest(t, "cpa_stream"),
			Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex",
				InputPricePerMillion: 1, OutputPricePerMillion: 1}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hdr := map[string][]string{"Authorization": {"Bearer cpa_stream"}}

	// A streaming response whose host passed us an SSE body WITH a final usage
	// frame is billed (post-hoc billing applies to streams too).
	sse := []byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: {\"usage\":{\"prompt_tokens\":1000000,\"completion_tokens\":0}}\n\ndata: [DONE]\n\n")
	_ = store.RecordResponseCost(hdr, nil, "fast", sse)
	d := store.Authenticate("POST", "/v1/chat/completions", hdr, nil, []byte(`{"model":"fast"}`))
	// 1M tokens × $1/M = $1.00 >= $0.01 limit → rejected.
	if d.Allowed || !d.CostLimited || d.Reason != "daily_exceeded" {
		t.Fatalf("streaming with usage frame should be billed & blocked: %+v", d)
	}

	// A streaming body the host passes WITHOUT any usage frame is not billed.
	store2 := NewStore()
	store2.SetClock(func() time.Time { return now })
	if err := store2.Configure(Config{
		Enabled: true, StateFile: filepath.Join(t.TempDir(), "state2.json"),
		Keys: []KeyConfig{{
			ID: "streamy2", Enabled: true, DailyLimitUSD: 0.01,
			KeyHash: hashForUsageTest(t, "cpa_stream2"),
			Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex",
				InputPricePerMillion: 1, OutputPricePerMillion: 1}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	hdr2 := map[string][]string{"Authorization": {"Bearer cpa_stream2"}}
	_ = store2.RecordResponseCost(hdr2, nil, "fast", nil)
	_ = store2.RecordResponseCost(hdr2, nil, "fast", []byte(`data: {"delta":"hi"}`))
	d = store2.Authenticate("POST", "/v1/chat/completions", hdr2, nil, []byte(`{"model":"fast"}`))
	if !d.Allowed {
		t.Fatalf("streaming without usage frame should not be billed: %+v", d)
	}
}

func TestUsageSummaryReflectsUsage(t *testing.T) {
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	store, _ := newClockedStore(t, now)
	hdr := map[string][]string{"Authorization": {"Bearer cpa_usage"}}
	_ = store.RecordResponseCost(hdr, nil, "fast", []byte(`{"usage":{"prompt_tokens":200000,"completion_tokens":100000}}`))
	keys := store.Keys()
	var key KeyConfig
	for _, k := range keys {
		if k.ID == "team-a" {
			key = k
		}
	}
	s := store.UsageSummaryFor(key)
	// 200K×$1/M + 100K×$2/M = $0.20 + $0.20 = $0.40
	if !nearly(s.DailyUSD, 0.40) || !nearly(s.WeeklyUSD, 0.40) {
		t.Fatalf("summary = %+v, want 0.40/0.40", s)
	}
	if s.DailyLimitUSD != 1.0 || s.WeeklyLimitUSD != 5.0 {
		t.Fatalf("limits = %+v", s)
	}
	if s.DailyResetAt.IsZero() {
		t.Fatal("daily_reset_at should be set")
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["weekly_history_incomplete_until"]; ok {
		t.Fatalf("complete history emitted a zero incomplete timestamp: %s", raw)
	}
	if _, ok := payload["last_usage_reset_at"]; ok {
		t.Fatalf("never-reset key emitted a zero reset timestamp: %s", raw)
	}
}

func TestUsagePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	mk := func(clock func() time.Time) *Store {
		s := NewStore()
		s.SetClock(clock)
		if err := s.Configure(Config{
			Enabled: true, StateFile: path,
			Keys: []KeyConfig{{
				ID: "team-a", Enabled: true, DailyLimitUSD: 1.0,
				KeyHash: hashForUsageTest(t, "cpa_usage"),
				Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex",
					InputPricePerMillion: 1, OutputPricePerMillion: 0}},
			}},
		}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	s1 := mk(func() time.Time { return now })
	hdr := map[string][]string{"Authorization": {"Bearer cpa_usage"}}
	_ = s1.RecordResponseCost(hdr, nil, "fast", []byte(`{"usage":{"prompt_tokens":800000,"completion_tokens":0}}`))
	if err := s1.FlushUsage(); err != nil {
		t.Fatal(err)
	}

	// "Restart": a fresh store loads from the same state file.
	s2 := mk(func() time.Time { return now })
	keys := s2.Keys()
	var key KeyConfig
	for _, k := range keys {
		if k.ID == "team-a" {
			key = k
		}
	}
	s := s2.UsageSummaryFor(key)
	if !nearly(s.DailyUSD, 0.80) {
		t.Fatalf("usage after restart = %+v, want 0.80", s)
	}
	// Over-limit is enforced post-restart (0.80 < 1.0, allowed; then bill to >1).
	d := s2.Authenticate("POST", "/v1/chat/completions", hdr, nil, []byte(`{"model":"fast"}`))
	if !d.Allowed {
		t.Fatalf("should be allowed at 0.80/1.0: %+v", d)
	}
}

// newCacheStore builds a store with one key whose alias has an explicit
// cache-read price, for cache-stat accounting tests.
func newCacheStore(t *testing.T, now time.Time, provider string) *Store {
	t.Helper()
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	if err := store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{{
			ID: "cache-key", Enabled: true,
			KeyHash:    hashForUsageTest(t, "cpa_cache"),
			KeyPreview: "cpa_ca...che",
			Models: []ModelRule{{
				Alias: "fast", Provider: provider, TargetModel: "m",
				InputPricePerMillion:     3,
				OutputPricePerMillion:    15,
				CacheReadPricePerMillion: 0.30,
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

// TestCacheStatsAccumulatedAndHitRate: a subset-provider record (1M input incl
// 200K cached + 500K output @ $3/$15/$0.30) → total $9.96, cacheCost $0.06,
// cacheRead 200K, nonCacheInput 800K. Hit-rate = 200K/(200K+800K) = 20%.
func TestCacheStatsAccumulatedAndHitRate(t *testing.T) {
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	store := newCacheStore(t, now, "openai")
	cost := store.RecordUsage("cache-key", "fast", "m", false, UsageDetail{
		InputTokens: 1_000_000, OutputTokens: 500_000, CachedTokens: 200_000,
	})
	if !nearly(cost, 9.96) {
		t.Fatalf("cost = %v, want 9.96", cost)
	}
	key := store.Keys()[0]
	s := store.UsageSummaryFor(key)
	if !nearly(s.DailyCacheCostUSD, 0.06) {
		t.Fatalf("daily cache cost = %v, want 0.06", s.DailyCacheCostUSD)
	}
	if s.DailyCacheReadTokens != 200_000 {
		t.Fatalf("daily cache read tokens = %d, want 200000", s.DailyCacheReadTokens)
	}
	if s.DailyInputTokens != 800_000 {
		t.Fatalf("daily non-cache input tokens = %d, want 800000", s.DailyInputTokens)
	}
	// Hit-rate = cacheRead / (cacheRead + input) = 200K / 1M = 0.2.
	if got := float64(s.DailyCacheReadTokens) / float64(s.DailyCacheReadTokens+s.DailyInputTokens); !nearly(got, 0.2) {
		t.Fatalf("hit-rate = %v, want 0.2", got)
	}
	// Weekly window mirrors daily for a same-day single record.
	if !nearly(s.WeeklyCacheCostUSD, 0.06) || s.WeeklyCacheReadTokens != 200_000 {
		t.Fatalf("weekly cache stats = %+v, want 0.06/200000", s)
	}
}

// TestCacheStatsResetAtMidnight: cache counters reset when the daily window
// rolls across UTC midnight. SetClock rebuilds the in-memory ledger (matching
// how the existing daily-limit test models a clock jump), so we re-record after
// advancing the clock and assert the daily cache stats reflect ONLY the new
// day's record. (Cross-day weekly accumulation is covered by the persist test,
// which survives the ledger rebuild via the state file.)
func TestCacheStatsResetAtMidnight(t *testing.T) {
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	store := newCacheStore(t, now, "openai")
	_ = store.RecordUsage("cache-key", "fast", "m", false, UsageDetail{
		InputTokens: 1_000_000, OutputTokens: 500_000, CachedTokens: 200_000,
	})
	store.SetClock(func() time.Time { return now.Add(14 * time.Hour) }) // next UTC day
	// A new day-2 record: 1M input (200K cached), no output.
	_ = store.RecordUsage("cache-key", "fast", "m", false, UsageDetail{
		InputTokens: 1_000_000, OutputTokens: 0, CachedTokens: 200_000,
	})

	s := store.UsageSummaryFor(store.Keys()[0])
	// Daily = day-2 only: 200K cacheRead, 0.06 cacheCost, 800K nonCache input.
	if s.DailyCacheReadTokens != 200_000 || !nearly(s.DailyCacheCostUSD, 0.06) || s.DailyInputTokens != 800_000 {
		t.Fatalf("daily cache stats after midnight = %+v, want 200000/0.06/800000", s)
	}
	// Day-1's 500K output must NOT leak into the new daily window.
	if !nearly(s.DailyUSD, 2.46) { // 800K*3 + 200K*0.30 = 2.4 + 0.06
		t.Fatalf("daily total after midnight = %v, want 2.46 (day-2 only)", s.DailyUSD)
	}
}

// TestCacheStatsAdditiveExcludesCreation: for an additive provider (Claude),
// cache-creation (write) tokens must NOT be counted in cacheRead — only reads.
// 800K input + 200K cacheRead + 100K cacheCreation + 500K output @ $3/$15/$0.30.
func TestCacheStatsAdditiveExcludesCreation(t *testing.T) {
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	store := newCacheStore(t, now, "claude")
	_ = store.RecordUsage("cache-key", "fast", "m", false, UsageDetail{
		InputTokens:         800_000,
		OutputTokens:        500_000,
		CacheReadTokens:     200_000,
		CacheCreationTokens: 100_000,
	})
	s := store.UsageSummaryFor(store.Keys()[0])
	if s.DailyCacheReadTokens != 200_000 {
		t.Fatalf("daily cacheRead = %d, want 200000 (creation excluded)", s.DailyCacheReadTokens)
	}
	// nonCache input = input + creation = 900K (additive bills creation at input price).
	if s.DailyInputTokens != 900_000 {
		t.Fatalf("daily non-cache input = %d, want 900000", s.DailyInputTokens)
	}
}

// TestCacheStatsPersistAcrossRestart: cache counters survive a state-file
// reload, so the UI keeps showing cache spend/hit-rate after a plugin restart.
func TestCacheStatsPersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	mk := func() *Store {
		s := NewStore()
		s.SetClock(func() time.Time { return now })
		if err := s.Configure(Config{
			Enabled: true, StateFile: path,
			Keys: []KeyConfig{{
				ID: "cache-key", Enabled: true,
				KeyHash: hashForUsageTest(t, "cpa_cache"),
				Models: []ModelRule{{
					Alias: "fast", Provider: "openai", TargetModel: "m",
					InputPricePerMillion:     3,
					OutputPricePerMillion:    15,
					CacheReadPricePerMillion: 0.30,
				}},
			}},
		}); err != nil {
			t.Fatal(err)
		}
		return s
	}
	s1 := mk()
	_ = s1.RecordUsage("cache-key", "fast", "m", false, UsageDetail{
		InputTokens: 1_000_000, OutputTokens: 500_000, CachedTokens: 200_000,
	})
	if err := s1.FlushUsage(); err != nil {
		t.Fatal(err)
	}
	s2 := mk()
	got := s2.UsageSummaryFor(s2.Keys()[0])
	if !nearly(got.DailyCacheCostUSD, 0.06) || got.DailyCacheReadTokens != 200_000 || got.DailyInputTokens != 800_000 {
		t.Fatalf("cache stats after restart = %+v, want 0.06/200000/800000", got)
	}
}

// newPerCallStore builds a store with one key whose alias is billed per-call at
// perCallUSD, under a daily dollar limit, for per-call billing tests.
func newPerCallStore(t *testing.T, perCallUSD, dailyLimit float64) *Store {
	t.Helper()
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	if err := store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{{
			ID: "percall", Enabled: true, DailyLimitUSD: dailyLimit,
			KeyHash: hashForUsageTest(t, "cpa_percall"),
			Models: []ModelRule{{
				Alias:       "fast",
				Provider:    "codex",
				TargetModel: "gpt-5-codex",
				BillingMode: "per_call",
				PerCallUSD:  perCallUSD,
				// Token prices are dormant under per_call but kept to verify they
				// are NOT used.
				InputPricePerMillion:  999,
				OutputPricePerMillion: 999,
			}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

// TestPerCallBillsFixedUSD: each successful request charges PerCallUSD
// regardless of token counts; token prices are ignored. Two $0.50 calls hit
// the $1.00 daily limit, so the next Authenticate is rejected.
func TestPerCallBillsFixedUSD(t *testing.T) {
	store := newPerCallStore(t, 0.50, 1.00)
	hdr := map[string][]string{"Authorization": {"Bearer cpa_percall"}}

	// A "successful" usage record with huge token counts — per_call must charge
	// the fixed $0.50, NOT the (dormant) token price.
	cost := store.RecordUsage("percall", "fast", "gpt-5-codex", false, UsageDetail{
		InputTokens: 1_000_000, OutputTokens: 1_000_000,
	})
	if !nearly(cost, 0.50) {
		t.Fatalf("per_call cost = %v, want 0.50", cost)
	}
	d := store.Authenticate("POST", "/v1/chat/completions", hdr, nil, []byte(`{"model":"fast"}`))
	if !d.Allowed {
		t.Fatalf("first call should be allowed: %+v", d)
	}
	// Second $0.50 → total $1.00 == limit. Next Authenticate rejected.
	_ = store.RecordUsage("percall", "fast", "gpt-5-codex", false, UsageDetail{})
	d = store.Authenticate("POST", "/v1/chat/completions", hdr, nil, []byte(`{"model":"fast"}`))
	if d.Allowed || !d.CostLimited || d.Reason != "daily_exceeded" {
		t.Fatalf("after two per_call charges, next should be daily_exceeded: %+v", d)
	}
	// CallCount reflects two successful calls.
	s := store.UsageSummaryFor(store.Keys()[0])
	if s.DailyCallCount != 2 {
		t.Fatalf("daily call count = %d, want 2", s.DailyCallCount)
	}
}

// TestTokenModeFreeAliasStillCounts: a token-mode alias whose configured
// input/output/cache prices are all 0 (priced=true but free) must still
// record token + call counters. Previously both RecordResponseCost and
// RecordUsage gated RecordCost on `cost > 0`, dropping free-but-priced
// requests entirely so their usage volume / hit-rate was invisible.
func TestTokenModeFreeAliasStillCounts(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	hash, err := HashKey("cpa_free2")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(Config{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state.json"), Keys: []KeyConfig{{
		ID: "free", Enabled: true, KeyHash: hash,
		Models: []ModelRule{{
			Alias: "fast", Provider: "anthropic", TargetModel: "m",
			InputPricePerMillion:     0,
			OutputPricePerMillion:    0,
			CacheReadPricePerMillion: 0,
		}},
	}}}); err != nil {
		t.Fatal(err)
	}
	// usage.handle path (RecordUsage): non-zero tokens, all prices 0.
	cost := store.RecordUsage("free", "fast", "m", false, UsageDetail{
		InputTokens: 1_000_000, OutputTokens: 500_000, CacheReadTokens: 200_000,
	})
	if cost != 0 {
		t.Fatalf("cost = %v, want 0 (free alias)", cost)
	}
	sum := store.UsageSummaryFor(store.Keys()[0])
	if sum.DailyCallCount != 1 {
		t.Fatalf("DailyCallCount = %d, want 1 (free call must still count)", sum.DailyCallCount)
	}
	if sum.DailyInputTokens != 1_000_000 {
		t.Fatalf("DailyInputTokens = %d, want 1000000 (Anthropic input excludes cache reads)", sum.DailyInputTokens)
	}
	if sum.DailyCacheReadTokens != 200_000 {
		t.Fatalf("DailyCacheReadTokens = %d, want 200000 (cache tokens must count even when free)", sum.DailyCacheReadTokens)
	}
}

// TestAllowModelsEndpointPerKey: a key with AllowModelsEndpoint=true may reach
// GET /v1/models (allowed); a key with it false (default) is 401. We cannot
// filter the list contents per key (CPA limitation), only hide/show it.
func TestAllowModelsEndpointPerKey(t *testing.T) {
	// Distinct secrets per key so Authenticate resolves the intended config
	// (sharing one hash makes map iteration order non-deterministic).
	store := NewStore()
	hashA, _ := HashKey("cpa_a")
	hashB, _ := HashKey("cpa_b")
	if err := store.Configure(Config{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state2.json"), Keys: []KeyConfig{
		{ID: "hidden", Enabled: true, KeyHash: hashA, Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex"}}},
		{ID: "open", Enabled: true, KeyHash: hashB, Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex"}}, AllowModelsEndpoint: true},
	}}); err != nil {
		t.Fatal(err)
	}
	dHidden := store.Authenticate("GET", "/v1/models", http.Header{"Authorization": {"Bearer cpa_a"}}, nil, nil)
	if dHidden.Allowed || dHidden.Reason != "models_endpoint_disabled" {
		t.Fatalf("hidden key (secret a) = %+v, want models_endpoint_disabled", dHidden)
	}
	dOpen := store.Authenticate("GET", "/v1/models", http.Header{"Authorization": {"Bearer cpa_b"}}, nil, nil)
	if !dOpen.Allowed || dOpen.Reason != "models_endpoint_allowed" {
		t.Fatalf("open key (secret b) = %+v, want Allowed + models_endpoint_allowed", dOpen)
	}
}

// TestPerCallFailedNotBilled: a failed request charges nothing and does not
// increment CallCount (per-call only applies to HTTP-200 outcomes).
func TestPerCallFailedNotBilled(t *testing.T) {
	store := newPerCallStore(t, 0.50, 1.00)
	cost := store.RecordUsage("percall", "fast", "gpt-5-codex", true, UsageDetail{
		InputTokens: 1_000_000, OutputTokens: 1_000_000,
	})
	if cost != 0 {
		t.Fatalf("failed per_call cost = %v, want 0", cost)
	}
	s := store.UsageSummaryFor(store.Keys()[0])
	if s.DailyCallCount != 0 || !nearly(s.DailyUSD, 0) {
		t.Fatalf("failed call should not count: %+v", s)
	}
}

// TestPerCallZeroStillCounts: PerCallUSD=0 is allowed (free calls). Cost is 0
// but CallCount still increments, and the key never exceeds a dollar limit.
func TestPerCallZeroStillCounts(t *testing.T) {
	store := newPerCallStore(t, 0, 0.01)
	for i := 0; i < 5; i++ {
		cost := store.RecordUsage("percall", "fast", "gpt-5-codex", false, UsageDetail{})
		if cost != 0 {
			t.Fatalf("free per_call cost = %v, want 0", cost)
		}
	}
	s := store.UsageSummaryFor(store.Keys()[0])
	if s.DailyCallCount != 5 {
		t.Fatalf("daily call count = %d, want 5", s.DailyCallCount)
	}
	// No dollar spend → never blocked even with a tiny limit.
	hdr := map[string][]string{"Authorization": {"Bearer cpa_percall"}}
	d := store.Authenticate("POST", "/v1/chat/completions", hdr, nil, []byte(`{"model":"fast"}`))
	if !d.Allowed {
		t.Fatalf("free per_call should never exceed dollar limit: %+v", d)
	}
}

// TestAliasUsageBreakdown: per-alias daily/weekly windows accumulate
// independently, configured-but-unused aliases appear as zero rows, output
// tokens are tracked, and an alias that was billed then removed from the key's
// config appears as a residual with InConfig=false.
func TestAliasUsageBreakdown(t *testing.T) {
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "state.json")
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	mkCfg := func(models []ModelRule) Config {
		return Config{Enabled: true, StateFile: statePath, Keys: []KeyConfig{{
			ID: "team-a", Enabled: true,
			KeyHash: hashForUsageTest(t, "cpa_usage"),
			Models:  models,
		}}}
	}
	fast := ModelRule{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex",
		InputPricePerMillion: 1, OutputPricePerMillion: 2}
	slow := ModelRule{Alias: "slow", Provider: "codex", TargetModel: "o4-mini",
		InputPricePerMillion: 1, OutputPricePerMillion: 1}
	if err := store.Configure(mkCfg([]ModelRule{fast, slow})); err != nil {
		t.Fatal(err)
	}

	// Bill fast: 200K input + 100K output @ $1/$2 = $0.20 + $0.20 = $0.40.
	_ = store.RecordUsage("team-a", "fast", "gpt-5-codex", false, UsageDetail{
		InputTokens: 200_000, OutputTokens: 100_000,
	})
	// Bill slow so it has history, then remove it from the key's config below.
	_ = store.RecordUsage("team-a", "slow", "o4-mini", false, UsageDetail{
		InputTokens: 50_000, OutputTokens: 0,
	})
	// Update the key to ONLY fast (mirrors the management PATCH path:
	// the alias is removed from config but the usage ledger keeps its history).
	// In the new architecture, keys reference global aliases by name, so we
	// update teamA.Aliases to only reference "fast".
	teamA := store.Keys()[0]
	teamA.Aliases = []KeyAliasRef{{Alias: "fast"}}
	teamA.Models = nil
	if err := store.UpsertKey(teamA, true); err != nil {
		t.Fatal(err)
	}

	_, rows, ok := store.AliasUsageFor("team-a")
	if !ok {
		t.Fatal("key not found")
	}
	byAlias := map[string]AliasUsageEntry{}
	for _, r := range rows {
		byAlias[r.Alias] = r
	}
	if len(rows) != 2 {
		t.Fatalf("row count = %d, want 2 (fast+slow residual)", len(rows))
	}
	// fast: configured, billed $0.40 daily & weekly, 1 call, 200K input, 100K output.
	f := byAlias["fast"]
	if !f.InConfig || !nearly(f.Daily.TotalUSD, 0.40) || !nearly(f.Weekly.TotalUSD, 0.40) {
		t.Fatalf("fast row = %+v, want in_config=true $0.40/$0.40", f)
	}
	if f.Daily.CallCount != 1 || f.Daily.InputTokens != 200_000 || f.Daily.OutputTokens != 100_000 {
		t.Fatalf("fast daily counters = %+v, want 1/200000/100000", f.Daily)
	}
	if f.Provider != "codex" || f.TargetModel != "gpt-5-codex" {
		t.Fatalf("fast config fields = %+v", f)
	}
	// slow: removed from config but has historical usage → InConfig=false, residual data.
	s := byAlias["slow"]
	if s.InConfig {
		t.Fatalf("slow should be in_config=false after removal: %+v", s)
	}
	if !nearly(s.Daily.TotalUSD, 0.05) || s.Daily.InputTokens != 50_000 || s.Daily.CallCount != 1 {
		t.Fatalf("slow residual daily = %+v, want $0.05 / 50000 / 1 call", s.Daily)
	}
	// Sorted by alias.
	if rows[0].Alias != "fast" || rows[1].Alias != "slow" {
		t.Fatalf("rows not sorted by alias: %+v", rows)
	}
}

// TestAliasUsageUnknownKey: a missing key id returns ok=false.
func TestAliasUsageUnknownKey(t *testing.T) {
	store := NewStore()
	if err := store.Configure(Config{Enabled: true, StateFile: filepath.Join(t.TempDir(), "s.json")}); err != nil {
		t.Fatal(err)
	}
	_, _, ok := store.AliasUsageFor("nope")
	if ok {
		t.Fatal("unknown key should return ok=false")
	}
}

// TestAliasUsageLegacyStateMigrates: a state file written in the legacy
// single-window ByAlias format (map[string]UsageWindow) loads into the new
// v2 day-bucket form: a legacy bare alias window confirmed to be today lands
// in today's bucket and therefore contributes to both daily and seven-day views.
func TestAliasUsageLegacyStateMigrates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	// Hand-write a legacy state file: by_alias is map[string]UsageWindow.
	legacy := map[string]any{
		"version": 1,
		"keys": []map[string]any{{
			"id": "team-a", "enabled": true,
			"key_hash": hashForUsageTest(t, "cpa_usage"),
			"models": []map[string]any{{
				"alias": "fast", "provider": "codex", "target_model": "gpt-5-codex",
			}},
		}},
		"usage": map[string]any{
			"team-a": map[string]any{
				"daily":  map[string]any{"total_usd": 0.80, "window_start": "2026-06-29T00:00:00Z"},
				"weekly": map[string]any{"total_usd": 0.80, "window_start": "2026-06-29T00:00:00Z"},
				// Legacy single-window per-alias entry.
				"by_alias": map[string]any{
					"fast": map[string]any{"total_usd": 0.80, "call_count": 2, "input_tokens": 800000, "window_start": "2026-06-29T00:00:00Z"},
				},
			},
		},
		"updated_at": "2026-06-29T10:00:00Z",
	}
	raw, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	if err := store.Configure(Config{Enabled: true, StateFile: path}); err != nil {
		t.Fatal(err)
	}

	_, rows, ok := store.AliasUsageFor("team-a")
	if !ok {
		t.Fatal("key not found after migration")
	}
	if len(rows) != 1 || rows[0].Alias != "fast" {
		t.Fatalf("rows = %+v, want one fast row", rows)
	}
	fast := rows[0]
	// fast is in config → InConfig=true; legacy window migrated into Daily.
	if !fast.InConfig {
		t.Fatalf("fast should be in_config=true: %+v", fast)
	}
	if !nearly(fast.Daily.TotalUSD, 0.80) || fast.Daily.CallCount != 2 || fast.Daily.InputTokens != 800_000 {
		t.Fatalf("migrated daily = %+v, want 0.80/2/800000", fast.Daily)
	}
	if !nearly(fast.Weekly.TotalUSD, 0.80) || fast.Weekly.CallCount != 2 {
		t.Fatalf("migrated seven-day alias = %+v", fast.Weekly)
	}
	// Persisting then reloading keeps the new dual-window shape (round-trip).
	if err := store.FlushUsage(); err != nil {
		t.Fatal(err)
	}
	raw2, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var check struct {
		UsageSchemaVersion int `json:"usage_schema_version"`
		Usage              map[string]struct {
			Days map[string]UsageDay `json:"days"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw2, &check); err != nil {
		t.Fatal(err)
	}
	if check.UsageSchemaVersion != CurrentUsageSchemaVersion {
		t.Fatalf("usage schema = %d", check.UsageSchemaVersion)
	}
	day, ok := check.Usage["team-a"].Days["2026-06-29"]
	if !ok {
		t.Fatal("migrated day not persisted")
	}
	a, ok := day.ByAlias["fast"]
	if !ok || !nearly(a.TotalUSD, 0.80) {
		t.Fatalf("round-trip alias = %+v, want 0.80", a)
	}
}

// increment CallCount (the counter is mode-agnostic for successful requests).
func TestCallCountIncrementedTokenMode(t *testing.T) {
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	if err := store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{{
			ID: "tok", Enabled: true,
			KeyHash: hashForUsageTest(t, "cpa_tok"),
			Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "m",
				InputPricePerMillion: 1, OutputPricePerMillion: 1}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	_ = store.RecordUsage("tok", "fast", "m", false, UsageDetail{InputTokens: 100_000, OutputTokens: 0})
	_ = store.RecordUsage("tok", "fast", "m", false, UsageDetail{InputTokens: 0, OutputTokens: 100_000})
	s := store.UsageSummaryFor(store.Keys()[0])
	if s.DailyCallCount != 2 {
		t.Fatalf("token-mode daily call count = %d, want 2", s.DailyCallCount)
	}
}

func TestUsageSevenUTCDaysContainsTodayAndRollsOneDay(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	if err := store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{{
			ID: "seven-days", Enabled: true,
			KeyHash: hashForUsageTest(t, "cpa_seven_days"),
			Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "m",
				InputPricePerMillion: 1}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	// Sep 9 is D-7 for the Sep 16 query and must be excluded.
	store.RecordUsage("seven-days", "fast", "m", false, UsageDetail{InputTokens: 1_000_000})
	now = time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	store.RecordUsage("seven-days", "fast", "m", false, UsageDetail{InputTokens: 2_000_000})
	now = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	store.RecordUsage("seven-days", "fast", "m", false, UsageDetail{InputTokens: 4_000_000})

	key, summary, aliases, ok := store.UsageDetailsFor("seven-days")
	if !ok || key.ID != "seven-days" {
		t.Fatal("key not found")
	}
	if !nearly(summary.DailyUSD, 4) || !nearly(summary.WeeklyUSD, 6) {
		t.Fatalf("summary = %+v, want daily=4 weekly=6", summary)
	}
	if summary.WeeklyUSD < summary.DailyUSD {
		t.Fatalf("weekly must contain daily: %+v", summary)
	}
	if summary.DailyInputTokens != 4_000_000 || summary.WeeklyInputTokens != 6_000_000 || summary.DailyCallCount != 1 || summary.WeeklyCallCount != 2 {
		t.Fatalf("counter range mismatch: %+v", summary)
	}
	if summary.WindowMode != "utc-days-7" || !summary.WeeklyHistoryComplete {
		t.Fatalf("window metadata = %+v", summary)
	}
	if got, want := summary.WeeklyWindowStart, time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("weekly_window_start = %v, want %v", got, want)
	}
	if got, want := summary.WeeklyNextRollAt, time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("weekly_next_roll_at = %v, want %v", got, want)
	}
	if len(aliases) != 1 || !nearly(aliases[0].Daily.TotalUSD, 4) || !nearly(aliases[0].Weekly.TotalUSD, 6) {
		t.Fatalf("alias windows = %+v, want daily=4 weekly=6", aliases)
	}

	// The next UTC midnight rolls out Sep 10 only; Sep 16 remains.
	now = time.Date(2026, 9, 17, 0, 1, 0, 0, time.UTC)
	summary = store.UsageSummaryFor(key)
	if summary.DailyUSD != 0 || !nearly(summary.WeeklyUSD, 4) {
		t.Fatalf("after one-day roll = %+v, want daily=0 weekly=4", summary)
	}
}

func TestUsageUsesUTCDatesWhenClockHasNonUTCLocation(t *testing.T) {
	shanghai := time.FixedZone("UTC+8", 8*60*60)
	now := time.Date(2026, 9, 17, 7, 30, 0, 0, shanghai) // Sep 16 23:30 UTC
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	if err := store.Configure(Config{
		Enabled: true, StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{{ID: "utc", Enabled: true, KeyHash: hashForUsageTest(t, "cpa_utc"),
			Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "m", InputPricePerMillion: 1}}}},
	}); err != nil {
		t.Fatal(err)
	}
	store.RecordUsage("utc", "fast", "m", false, UsageDetail{InputTokens: 1_000_000})
	now = time.Date(2026, 9, 17, 8, 30, 0, 0, shanghai) // Sep 17 00:30 UTC
	store.RecordUsage("utc", "fast", "m", false, UsageDetail{InputTokens: 2_000_000})

	s := store.UsageSummaryFor(store.Keys()[0])
	if !nearly(s.DailyUSD, 2) || !nearly(s.WeeklyUSD, 3) {
		t.Fatalf("UTC boundary summary = %+v, want daily=2 weekly=3", s)
	}
	if got, want := s.DailyResetAt, time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("daily_reset_at = %v, want %v", got, want)
	}
}

func TestWeeklyLimitUsesSameSevenUTCDaysAndRecoversWhenOldestDayRollsOut(t *testing.T) {
	now := time.Date(2026, 12, 26, 12, 0, 0, 0, time.UTC)
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	if err := store.Configure(Config{
		Enabled: true, StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{{ID: "limited", Enabled: true, KeyHash: hashForUsageTest(t, "cpa_weekly_limit"), WeeklyLimitUSD: 5,
			Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "m", InputPricePerMillion: 1}}}},
	}); err != nil {
		t.Fatal(err)
	}
	store.RecordUsage("limited", "fast", "m", false, UsageDetail{InputTokens: 3_000_000})
	now = time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)
	store.RecordUsage("limited", "fast", "m", false, UsageDetail{InputTokens: 2_000_000})
	hdr := http.Header{"Authorization": {"Bearer cpa_weekly_limit"}}
	decision := store.Authenticate("POST", "/v1/chat/completions", hdr, nil, []byte(`{"model":"fast"}`))
	if decision.Allowed || decision.Reason != "weekly_exceeded" {
		t.Fatalf("at seven-day limit = %+v", decision)
	}
	if summary := store.UsageSummaryFor(imgKey(store, "limited")); !nearly(summary.WeeklyUSD, 5) || !nearly(summary.DailyUSD, 2) {
		t.Fatalf("limit summary = %+v", summary)
	}

	// Jan 2's range starts Dec 27, so the Dec 26 charge rolls out while Jan 1
	// remains. The exact same value used by the UI now admits the request.
	now = time.Date(2027, 1, 2, 0, 1, 0, 0, time.UTC)
	decision = store.Authenticate("POST", "/v1/chat/completions", hdr, nil, []byte(`{"model":"fast"}`))
	if !decision.Allowed {
		t.Fatalf("after oldest day rolls out = %+v", decision)
	}
	if summary := store.UsageSummaryFor(imgKey(store, "limited")); !nearly(summary.WeeklyUSD, 2) || summary.DailyUSD != 0 {
		t.Fatalf("rolled summary = %+v", summary)
	}
}

func TestLegacyUsageMigrationBacksUpAndKeepsOnlyConfirmedToday(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	legacy := map[string]any{
		"version": 1,
		"keys": []map[string]any{{
			"id": "team-a", "enabled": true,
			"key_hash": hashForUsageTest(t, "cpa_legacy_v2"),
			"models": []map[string]any{{
				"alias": "fast", "provider": "codex", "target_model": "m",
				"input_price_per_million": 1,
			}},
		}},
		"usage": map[string]any{
			"team-a": map[string]any{
				"daily": map[string]any{
					"total_usd": 3.0, "window_start": "2026-09-16T00:00:00Z",
					"input_tokens": 3000000, "call_count": 3,
				},
				"weekly": map[string]any{
					"total_usd": 9.0, "window_start": "2026-09-13T04:00:00Z",
				},
				"by_alias": map[string]any{
					"fast": map[string]any{
						"daily":  map[string]any{"total_usd": 2.5, "input_tokens": 2500000, "call_count": 2, "window_start": "2026-09-16T00:00:00Z"},
						"weekly": map[string]any{"total_usd": 8.5, "window_start": "2026-09-13T04:00:00Z"},
					},
				},
			},
		},
		"updated_at": "2026-09-16T10:00:00Z",
	}
	raw, _ := json.MarshalIndent(legacy, "", "  ")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 9, 16, 17, 54, 0, 0, time.UTC)
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	if err := store.Configure(Config{Enabled: true, StateFile: path}); err != nil {
		t.Fatal(err)
	}

	backups, err := filepath.Glob(path + ".pre-usage-v2.*.bak")
	if err != nil || len(backups) != 1 {
		t.Fatalf("migration backups = %v, err=%v", backups, err)
	}
	if info, err := os.Stat(backups[0]); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode: info=%v err=%v", info, err)
	}

	key, summary, aliases, ok := store.UsageDetailsFor("team-a")
	if !ok || key.ID != "team-a" {
		t.Fatal("migrated key missing")
	}
	if !nearly(summary.DailyUSD, 3) || !nearly(summary.WeeklyUSD, 3) {
		t.Fatalf("migrated totals = %+v, want confirmed today only", summary)
	}
	if summary.WeeklyHistoryComplete {
		t.Fatalf("migrated history should be incomplete: %+v", summary)
	}
	wantIncompleteUntil := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	if summary.WeeklyHistoryIncompleteUntil == nil || !summary.WeeklyHistoryIncompleteUntil.Equal(wantIncompleteUntil) {
		t.Fatalf("incomplete_until = %v, want %v", summary.WeeklyHistoryIncompleteUntil, wantIncompleteUntil)
	}
	if len(aliases) != 1 || !nearly(aliases[0].Daily.TotalUSD, 2.5) || !nearly(aliases[0].Weekly.TotalUSD, 2.5) {
		t.Fatalf("migrated alias = %+v", aliases)
	}

	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(persisted, &doc); err != nil {
		t.Fatal(err)
	}
	if got := int(doc["usage_schema_version"].(float64)); got != CurrentUsageSchemaVersion {
		t.Fatalf("usage_schema_version = %d, want %d", got, CurrentUsageSchemaVersion)
	}
	teamUsage := doc["usage"].(map[string]any)["team-a"].(map[string]any)
	if _, ok := teamUsage["weekly"]; ok {
		t.Fatalf("legacy weekly was persisted into v2: %s", persisted)
	}
	if _, ok := teamUsage["days"]; !ok {
		t.Fatalf("v2 day buckets missing: %s", persisted)
	}

	// A v2 reload is not a second migration and does not duplicate today's usage.
	if err := store.Configure(Config{Enabled: true, StateFile: path}); err != nil {
		t.Fatal(err)
	}
	backups, _ = filepath.Glob(path + ".pre-usage-v2.*.bak")
	if len(backups) != 1 {
		t.Fatalf("migration repeated, backups=%v", backups)
	}
	summary = store.UsageSummaryFor(imgKey(store, "team-a"))
	if !nearly(summary.DailyUSD, 3) || !nearly(summary.WeeklyUSD, 3) {
		t.Fatalf("reload duplicated usage: %+v", summary)
	}

	// At M+6 UTC midnight, no unknown pre-migration day remains in range.
	now = wantIncompleteUntil
	summary = store.UsageSummaryFor(imgKey(store, "team-a"))
	if !summary.WeeklyHistoryComplete || summary.WeeklyHistoryIncompleteUntil != nil {
		t.Fatalf("history flag did not expire: %+v", summary)
	}
}

func TestUnknownUsageSchemaIsRejectedWithoutOverwritingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	original := []byte(`{"version":1,"usage_schema_version":99,"keys":[],"updated_at":"2026-09-16T00:00:00Z"}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore()
	if err := store.Configure(Config{Enabled: true, StateFile: path}); err == nil {
		t.Fatal("unknown usage schema should be rejected")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatalf("unknown state was overwritten: %s", after)
	}
}

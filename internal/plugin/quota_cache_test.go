package plugin

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestParseCodexQuotaHeadersClassifiesByWindowLength(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	headers := http.Header{
		"X-Codex-Primary-Used-Percent":          []string{"40"},
		"X-Codex-Primary-Window-Minutes":        []string{"10080"},
		"X-Codex-Primary-Reset-After-Seconds":   []string{"3600"},
		"X-Codex-Secondary-Used-Percent":        []string{"20"},
		"X-Codex-Secondary-Window-Minutes":      []string{"300"},
		"X-Codex-Secondary-Reset-After-Seconds": []string{"1800"},
		"X-Codex-Allowed":                       []string{"true"},
	}
	observation, ok := parseCodexQuotaHeaders(headers, now)
	if !ok {
		t.Fatal("expected quota observation")
	}
	if observation.Long == nil || observation.Long.Kind != quotaWindowWeekly || observation.Long.WindowSeconds != quotaWeeklySeconds {
		t.Fatalf("long = %#v", observation.Long)
	}
	if observation.Short == nil || observation.Short.Kind != quotaWindowShort || observation.Short.WindowSeconds != quotaFiveHourSeconds {
		t.Fatalf("short = %#v", observation.Short)
	}
	if got := observation.Long.ResetAt; !got.Equal(now.Add(time.Hour)) {
		t.Fatalf("long reset = %v", got)
	}
	if !observation.ExplicitAvailable {
		t.Fatal("allowed=true should be positive explicit evidence")
	}
}

func TestPassiveRelativeResetNeedsResponseTimeAnchor(t *testing.T) {
	requestedAt := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	headers := http.Header{
		"X-Codex-Secondary-Used-Percent":        []string{"20"},
		"X-Codex-Secondary-Window-Minutes":      []string{"10080"},
		"X-Codex-Secondary-Reset-After-Seconds": []string{"7200"},
	}
	observation, ok := parseCodexQuotaHeadersAt(headers, requestedAt, time.Time{})
	if !ok || observation.Long == nil {
		t.Fatalf("observation = %#v, ok=%v", observation, ok)
	}
	if !observation.Long.ResetAt.IsZero() {
		t.Fatalf("relative reset was anchored without a response timestamp: %v", observation.Long.ResetAt)
	}
	cache := newQuotaCache(func() time.Time { return requestedAt })
	cache.observe("auth-a", "idx-a", "passive-http", observation)
	if class, _ := cache.classify("auth-a", 30*time.Minute, requestedAt); class != quotaAvailabilityUnknown {
		t.Fatalf("class = %v, want unknown", class)
	}
}

func TestQuotaCacheRejectsMalformedPositiveEvidence(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	for name, raw := range map[string][]byte{
		"nan":           []byte(`{"rate_limit":{"allowed":true,"secondary_window":{"used_percent":"NaN","limit_window_seconds":604800,"reset_after_seconds":60}}}`),
		"over-100":      []byte(`{"rate_limit":{"allowed":true,"secondary_window":{"used_percent":101,"limit_window_seconds":604800,"reset_after_seconds":60}}}`),
		"missing-reset": []byte(`{"rate_limit":{"allowed":true,"secondary_window":{"used_percent":20,"limit_window_seconds":604800}}}`),
	} {
		t.Run(name, func(t *testing.T) {
			observation, err := parseCodexQuotaPayload(raw, now)
			if err != nil {
				t.Fatal(err)
			}
			cache := newQuotaCache(func() time.Time { return now })
			cache.observe("auth-a", "idx-a", "quota-get", observation)
			if class, _ := cache.classify("auth-a", 30*time.Minute, now); class != quotaAvailabilityUnknown {
				t.Fatalf("class = %v, observation=%#v", class, observation)
			}
		})
	}
}

func TestQuotaCacheIsBounded(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	cache := newQuotaCache(func() time.Time { return now })
	used := 1.0
	for index := 0; index < quotaCacheCapacity+20; index++ {
		observation := quotaObservation{
			Provider:   "codex",
			ObservedAt: now.Add(time.Duration(index) * time.Second),
			Long: &quotaWindow{
				Kind: quotaWindowWeekly, UsedPercent: &used, WindowSeconds: quotaWeeklySeconds, ResetAt: now.Add(24 * time.Hour),
			},
		}
		cache.observe(fmt.Sprintf("auth-%05d", index), "", "passive-http", observation)
	}
	if got := len(cache.snapshot()); got != quotaCacheCapacity {
		t.Fatalf("cache size = %d, want %d", got, quotaCacheCapacity)
	}
}

func TestParseCodexQuotaPayloadMonthlyAndShort(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	raw := []byte(`{"plan_type":"pro","rate_limit":{"allowed":true,"primary_window":{"used_percent":90,"limit_window_seconds":18000,"reset_after_seconds":300},"secondary_window":{"used_percent":25,"limit_window_seconds":2592000,"reset_after_seconds":7200}}}`)
	observation, err := parseCodexQuotaPayload(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if observation.PlanType != "pro" || observation.Short == nil || observation.Long == nil {
		t.Fatalf("observation = %#v", observation)
	}
	if observation.Long.Kind != quotaWindowMonthly || observation.Long.remainingPercent() != 75 {
		t.Fatalf("long = %#v", observation.Long)
	}
	if observation.Short.Kind != quotaWindowShort || observation.Short.Exhausted {
		t.Fatalf("short = %#v", observation.Short)
	}
}

func TestQuotaCacheOlderObservationDoesNotOverwriteNewer(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	cache := newQuotaCache(func() time.Time { return now })
	usedNew := 10.0
	usedOld := 80.0
	newer := quotaObservation{Provider: "codex", ObservedAt: now, ExplicitAvailable: true, Long: &quotaWindow{Kind: quotaWindowWeekly, UsedPercent: &usedNew, WindowSeconds: quotaWeeklySeconds, ResetAt: now.Add(24 * time.Hour)}}
	older := quotaObservation{Provider: "codex", ObservedAt: now.Add(-time.Minute), ExplicitAvailable: true, Long: &quotaWindow{Kind: quotaWindowWeekly, UsedPercent: &usedOld, WindowSeconds: quotaWeeklySeconds, ResetAt: now.Add(time.Hour)}}
	if !cache.observe("auth-a", "idx-a", "quota-get", newer) {
		t.Fatal("newer observation rejected")
	}
	if cache.observe("auth-a", "idx-a", "passive-http", older) {
		t.Fatal("older observation replaced newer state")
	}
	got, _ := cache.get("auth-a")
	if got.Long == nil || *got.Long.UsedPercent != usedNew {
		t.Fatalf("cached = %#v", got)
	}
}

func TestQuotaCacheOlderIdentityConfirmationDoesNotReplaceNewerQuota(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	cache := newQuotaCache(func() time.Time { return now })
	used := 20.0
	passive := quotaObservation{Provider: "codex", ObservedAt: now, Long: &quotaWindow{Kind: quotaWindowWeekly, UsedPercent: &used, WindowSeconds: quotaWeeklySeconds, ResetAt: now.Add(time.Hour)}}
	cache.observe("auth-a", "idx-a", "passive-http", passive)
	identity := quotaObservation{Provider: "codex", ObservedAt: now.Add(-time.Hour), CredentialFingerprint: "fingerprint-a"}
	if cache.observe("auth-a", "idx-a", "roster-confirmed", identity) {
		t.Fatal("older identity-only record replaced quota evidence")
	}
	got, _ := cache.get("auth-a")
	if got.CredentialFingerprint != "fingerprint-a" || got.Long == nil || got.Long.ResetAt != passive.Long.ResetAt {
		t.Fatalf("cached = %#v", got)
	}
}

func TestQuotaCacheExplicitExhaustionNeedsNewPositiveEvidence(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	clock := now
	cache := newQuotaCache(func() time.Time { return clock })
	cache.markExplicitExhausted("auth-a", "idx-a", now, now.Add(time.Minute), "429")
	clock = now.Add(2 * time.Hour)
	if class, _ := cache.classify("auth-a", 30*time.Minute, clock); class != quotaAvailabilityExhausted {
		t.Fatalf("class after reset/ttl = %v, want exhausted", class)
	}
	used := 1.0
	partial := quotaObservation{Provider: "codex", ObservedAt: clock, Long: &quotaWindow{Kind: quotaWindowWeekly, UsedPercent: &used, WindowSeconds: quotaWeeklySeconds, ResetAt: clock.Add(24 * time.Hour)}}
	cache.observe("auth-a", "idx-a", "quota-get", partial)
	if class, _ := cache.classify("auth-a", 30*time.Minute, clock); class != quotaAvailabilityExhausted {
		t.Fatalf("partial class = %v, want exhausted", class)
	}
	positive := partial
	positive.ObservedAt = clock.Add(time.Second)
	positive.ExplicitAvailable = true
	cache.observe("auth-a", "idx-a", "quota-get", positive)
	if class, _ := cache.classify("auth-a", 30*time.Minute, positive.ObservedAt); class != quotaAvailabilityReady {
		t.Fatalf("positive class = %v, want ready", class)
	}
}

func TestQuotaCacheFreshnessAndResetCrossingBecomeUnknown(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	cache := newQuotaCache(func() time.Time { return now })
	used := 50.0
	observation := quotaObservation{Provider: "codex", ObservedAt: now, ExplicitAvailable: true, Long: &quotaWindow{Kind: quotaWindowWeekly, UsedPercent: &used, WindowSeconds: quotaWeeklySeconds, ResetAt: now.Add(time.Hour)}}
	cache.observe("auth-a", "idx-a", "quota-get", observation)
	if class, _ := cache.classify("auth-a", 30*time.Minute, now.Add(29*time.Minute)); class != quotaAvailabilityReady {
		t.Fatalf("fresh class = %v", class)
	}
	if class, _ := cache.classify("auth-a", 30*time.Minute, now.Add(31*time.Minute)); class != quotaAvailabilityUnknown {
		t.Fatalf("stale class = %v", class)
	}
	if class, _ := cache.classify("auth-a", 2*time.Hour, now.Add(time.Hour)); class != quotaAvailabilityUnknown {
		t.Fatalf("reset-crossed class = %v", class)
	}
}

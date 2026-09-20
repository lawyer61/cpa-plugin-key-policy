package plugin

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"cpa-key-policy/internal/policy"
)

type stagedRuntimeQuotaHost struct {
	*fakeQuotaHost
	mu       sync.Mutex
	runtimes []HostAuthEntry
}

func (h *stagedRuntimeQuotaHost) GetAuthRuntime(authIndex string) (HostAuthEntry, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.runtimes) == 0 {
		return h.fakeQuotaHost.GetAuthRuntime(authIndex)
	}
	runtime := h.runtimes[0]
	h.runtimes = h.runtimes[1:]
	return runtime, nil
}

func TestQuotaExpiredHostUnavailableResumesReviewAndActivation(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{
		QuotaActivationEnabled: &enabled,
		QuotaActivationScope:   &scope,
	}); err != nil {
		t.Fatal(err)
	}

	clock := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	entry := host.entries[0]
	entry.Status = "error"
	entry.Unavailable = true
	entry.NextRetryAfter = clock.Add(-time.Minute)
	host.entries[0] = entry
	host.runtime[entry.AuthIndex] = entry
	host.getResponses = []HostHTTPResponse{
		{StatusCode: http.StatusOK, Body: shortQuotaBody(0)},
		{StatusCode: http.StatusOK, Body: shortQuotaBody(0)},
		{StatusCode: http.StatusOK, Body: shortQuotaBody(1)},
	}
	attachTestQuotaHost(app, host, clock)
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }
	app.quota.testDurations = func() (time.Duration, time.Duration) {
		return 30 * time.Minute, 30 * time.Minute
	}
	app.quota.verifyDelay = 0

	app.quota.runRound()
	_, get, post := host.counts()
	if get != 1 || post != 0 {
		t.Fatalf("expired host cooldown baseline: GET=%d POST=%d, want GET=1 POST=0", get, post)
	}
	app.quota.mu.Lock()
	runtime := app.quota.runtime.Auths[entry.ID]
	app.quota.mu.Unlock()
	if !runtime.InMaintenanceScope || !runtime.InActivationScope || runtime.ExclusionReason != "host_unavailable" {
		t.Fatalf("expired host cooldown runtime = %#v", runtime)
	}

	clock = clock.Add(31 * time.Minute)
	app.quota.runRound()
	_, get, post = host.counts()
	if get != 3 || post != 1 {
		t.Fatalf("expired host cooldown activation: GET=%d POST=%d, want GET=3 POST=1", get, post)
	}
	app.quota.mu.Lock()
	activation := app.quota.runtime.Auths[entry.ID].Activation
	app.quota.mu.Unlock()
	if activation.Status != "confirmed" || activation.LastResult != "verified" {
		t.Fatalf("activation = %#v", activation)
	}
}

func TestQuotaExpiredHostUnavailableWithoutLazyEvidenceDoesNotActivate(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{
		QuotaActivationEnabled: &enabled,
		QuotaActivationScope:   &scope,
	}); err != nil {
		t.Fatal(err)
	}

	clock := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	entry := host.entries[0]
	entry.Status = "error"
	entry.Unavailable = true
	entry.NextRetryAfter = clock.Add(-time.Minute)
	host.entries[0] = entry
	host.runtime[entry.AuthIndex] = entry
	host.getResponses = []HostHTTPResponse{
		{StatusCode: http.StatusOK, Body: shortQuotaBody(25)},
		{StatusCode: http.StatusOK, Body: shortQuotaBody(25)},
	}
	attachTestQuotaHost(app, host, clock)
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }

	app.quota.runRound()
	clock = clock.Add(31 * time.Minute)
	app.quota.runRound()
	_, get, post := host.counts()
	if get != 2 || post != 0 {
		t.Fatalf("non-lazy positive quota evidence: GET=%d POST=%d, want GET=2 POST=0", get, post)
	}
}

func TestQuotaActivationRejectsMixedUnavailableDeadlines(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	used := 0.0
	observation := quotaObservation{
		Provider:          "codex",
		ExplicitAvailable: true,
		ObservedAt:        now,
		Short: &quotaWindow{
			Kind:          quotaWindowShort,
			UsedPercent:   &used,
			WindowSeconds: quotaFiveHourSeconds,
			ResetAt:       now.Add(5 * time.Hour),
		},
		Long: &quotaWindow{
			Kind:          quotaWindowWeekly,
			UsedPercent:   &used,
			WindowSeconds: quotaWeeklySeconds,
			ResetAt:       now.Add(7 * 24 * time.Hour),
		},
	}
	entry := HostAuthEntry{Unavailable: true, NextRetryAfter: now.Add(-time.Minute)}
	live := HostAuthEntry{Unavailable: true, NextRetryAfter: now.Add(time.Hour)}
	if quotaActivationCanUseExpiredHostUnavailable(entry, live, observation, now) {
		t.Fatal("activation accepted a still-active live runtime cooldown")
	}
}

func TestQuotaActivationOverrideRequiresExplicitAvailability(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	used := 0.0
	observation := quotaObservation{
		Provider:   "codex",
		ObservedAt: now,
		Short: &quotaWindow{
			Kind:          quotaWindowShort,
			UsedPercent:   &used,
			WindowSeconds: quotaFiveHourSeconds,
			ResetAt:       now.Add(5 * time.Hour),
		},
		Long: &quotaWindow{
			Kind:          quotaWindowWeekly,
			UsedPercent:   &used,
			WindowSeconds: quotaWeeklySeconds,
			ResetAt:       now.Add(7 * 24 * time.Hour),
		},
	}
	expired := HostAuthEntry{Unavailable: true, NextRetryAfter: now.Add(-time.Minute)}
	if quotaActivationCanUseExpiredHostUnavailable(expired, expired, observation, now) {
		t.Fatal("activation accepted quota windows without an explicit available signal")
	}
}

func TestQuotaRefreshRechecksLiveHostCooldownBeforeGET(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{
		QuotaActivationEnabled: &enabled,
		QuotaActivationScope:   &scope,
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	base := newFakeQuotaHost(now)
	expired := base.entries[0]
	expired.Status = "error"
	expired.Unavailable = true
	expired.NextRetryAfter = now.Add(-time.Minute)
	future := expired
	future.NextRetryAfter = now.Add(time.Hour)
	base.entries[0] = expired
	host := &stagedRuntimeQuotaHost{
		fakeQuotaHost: base,
		runtimes:      []HostAuthEntry{expired, future},
	}
	app.quota.mu.Lock()
	app.quota.host = host
	app.quota.mu.Unlock()
	app.quota.now = func() time.Time { return now }
	app.quota.cache.now = func() time.Time { return now }

	app.quota.runRound()
	_, get, post := base.counts()
	if get != 0 || post != 0 {
		t.Fatalf("runtime cooldown changed before review: GET=%d POST=%d", get, post)
	}
	app.quota.mu.Lock()
	runtime := app.quota.runtime.Auths[expired.ID]
	app.quota.mu.Unlock()
	if runtime.QueryEligible || runtime.InActivationScope || !runtime.InMaintenanceScope || runtime.ExclusionReason != "host_unavailable" {
		t.Fatalf("runtime cooldown change did not pause review: %#v", runtime)
	}
	if !runtime.NextCheckAt.Equal(future.NextRetryAfter) {
		t.Fatalf("next_check_at=%s, want renewed host deadline %s", runtime.NextCheckAt, future.NextRetryAfter)
	}
}

func TestQuotaExpiredHostUnavailablePreservesActivationRecovery(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{
		QuotaActivationEnabled: &enabled,
		QuotaActivationScope:   &scope,
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(now)
	entry := host.entries[0]
	entry.Status = "error"
	entry.Unavailable = true
	entry.NextRetryAfter = now.Add(-time.Minute)
	host.entries[0] = entry
	host.runtime[entry.AuthIndex] = entry
	app.quota.mu.Lock()
	app.quota.runtime.Auths[entry.ID] = quotaAuthRuntime{
		AuthID: entry.ID,
		Activation: quotaActivationState{
			Status:   "verify_pending",
			CycleID:  "cycle",
			Attempts: 1,
			RecoveryObservations: map[quotaWindowKind]quotaWindowBaseline{
				quotaWindowShort: {Kind: quotaWindowShort, ObservedAt: now.Add(-time.Hour)},
			},
		},
	}
	app.quota.mu.Unlock()

	app.quota.applyRoster(host, host.entries, app.store.RuntimeSettings(), app.store.Keys())
	app.quota.mu.Lock()
	activation := app.quota.runtime.Auths[entry.ID].Activation
	app.quota.mu.Unlock()
	if len(activation.RecoveryObservations) != 1 {
		t.Fatalf("expired host marker cleared bounded recovery evidence: %#v", activation)
	}
}

func TestQuotaHostUnavailableWaitsForRetryDeadlineBeforeRead(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{
		QuotaActivationEnabled: &enabled,
		QuotaActivationScope:   &scope,
	}); err != nil {
		t.Fatal(err)
	}

	clock := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	entry := host.entries[0]
	entry.Status = "error"
	entry.Unavailable = true
	entry.NextRetryAfter = clock.Add(time.Hour)
	host.entries[0] = entry
	host.runtime[entry.AuthIndex] = entry
	host.getResponses = []HostHTTPResponse{{StatusCode: http.StatusOK, Body: quotaBody(clock.Add(62*time.Minute), 10)}}
	attachTestQuotaHost(app, host, clock)
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }
	app.quota.testDurations = func() (time.Duration, time.Duration) {
		return 30 * time.Minute, 30 * time.Minute
	}

	app.quota.runRound()
	_, get, post := host.counts()
	if get != 0 || post != 0 {
		t.Fatalf("active host cooldown performed upstream work: GET=%d POST=%d", get, post)
	}
	app.quota.mu.Lock()
	runtime := app.quota.runtime.Auths[entry.ID]
	app.quota.mu.Unlock()
	if !runtime.InMaintenanceScope || runtime.InActivationScope || runtime.QueryEligible || runtime.ExclusionReason != "host_unavailable" {
		t.Fatalf("active host cooldown scope split = %#v", runtime)
	}
	if !runtime.NextCheckAt.Equal(entry.NextRetryAfter) {
		t.Fatalf("active host cooldown next_check_at=%s, want %s", runtime.NextCheckAt, entry.NextRetryAfter)
	}
	statusAuths := app.quota.status()["auths"].([]map[string]any)
	if len(statusAuths) != 1 || statusAuths[0]["query_eligible"] != false || statusAuths[0]["in_maintenance_scope"] != true || statusAuths[0]["in_activation_scope"] != false {
		t.Fatalf("active host cooldown status = %#v", statusAuths)
	}

	clock = clock.Add(31 * time.Minute)
	app.quota.runRound()
	_, get, post = host.counts()
	if get != 0 || post != 0 {
		t.Fatalf("pre-deadline review performed upstream work: GET=%d POST=%d", get, post)
	}

	clock = clock.Add(31 * time.Minute)
	app.quota.runRound()
	_, get, post = host.counts()
	if get != 1 || post != 0 {
		t.Fatalf("post-deadline review: GET=%d POST=%d, want GET=1 POST=0", get, post)
	}
}

func TestQuotaHostUnavailableWithoutRetryDeadlineDoesNotProbe(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{
		QuotaActivationEnabled: &enabled,
		QuotaActivationScope:   &scope,
	}); err != nil {
		t.Fatal(err)
	}

	clock := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	entry := host.entries[0]
	entry.Status = "error"
	entry.Unavailable = true
	host.entries[0] = entry
	host.runtime[entry.AuthIndex] = entry
	attachTestQuotaHost(app, host, clock)

	app.quota.runRound()
	_, get, post := host.counts()
	if get != 0 || post != 0 {
		t.Fatalf("host unavailable without retry deadline performed upstream work: GET=%d POST=%d", get, post)
	}
	app.quota.mu.Lock()
	runtime := app.quota.runtime.Auths[entry.ID]
	app.quota.mu.Unlock()
	if !runtime.InMaintenanceScope || runtime.InActivationScope || runtime.QueryEligible || runtime.ExclusionReason != "host_unavailable" {
		t.Fatalf("host unavailable without retry deadline scope split = %#v", runtime)
	}
}

func TestQuotaRosterKeepsLaterPluginBackoffThanHostRetryDeadline(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{
		QuotaActivationEnabled: &enabled,
		QuotaActivationScope:   &scope,
	}); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(now)
	entry := host.entries[0]
	entry.Status = "error"
	entry.Unavailable = true
	entry.NextRetryAfter = now.Add(time.Hour)
	host.entries[0] = entry
	host.runtime[entry.AuthIndex] = entry
	later := now.Add(2 * time.Hour)
	app.quota.mu.Lock()
	app.quota.runtime.Auths[entry.ID] = quotaAuthRuntime{AuthID: entry.ID, NextCheckAt: later}
	app.quota.mu.Unlock()
	attachTestQuotaHost(app, host, now)

	app.quota.runRound()
	app.quota.mu.Lock()
	runtime := app.quota.runtime.Auths[entry.ID]
	app.quota.mu.Unlock()
	if !runtime.NextCheckAt.Equal(later) {
		t.Fatalf("next_check_at=%s, want later plugin deadline %s", runtime.NextCheckAt, later)
	}
}

func TestQuotaExpiredHostUnavailableDoesNotBypassPerAuthProxyExclusion(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{
		QuotaActivationEnabled: &enabled,
		QuotaActivationScope:   &scope,
	}); err != nil {
		t.Fatal(err)
	}

	clock := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	entry := host.entries[0]
	entry.Status = "error"
	entry.Unavailable = true
	entry.NextRetryAfter = clock.Add(-time.Minute)
	host.entries[0] = entry
	host.runtime[entry.AuthIndex] = entry
	document := host.documents[entry.AuthIndex]
	var credential map[string]any
	if err := json.Unmarshal(document.JSON, &credential); err != nil {
		t.Fatal(err)
	}
	credential["proxy_url"] = "http://127.0.0.1:8080"
	document.JSON, _ = json.Marshal(credential)
	host.documents[entry.AuthIndex] = document
	attachTestQuotaHost(app, host, clock)

	app.quota.runRound()
	_, get, post := host.counts()
	if get != 0 || post != 0 {
		t.Fatalf("per-auth proxy exclusion performed upstream work: GET=%d POST=%d", get, post)
	}
	app.quota.mu.Lock()
	runtime := app.quota.runtime.Auths[entry.ID]
	app.quota.mu.Unlock()
	if runtime.InMaintenanceScope || runtime.InActivationScope || runtime.QueryEligible || runtime.ExclusionReason != "per_auth_proxy_unsupported" {
		t.Fatalf("per-auth proxy exclusion runtime = %#v", runtime)
	}
}

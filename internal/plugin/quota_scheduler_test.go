package plugin

import (
	"testing"
	"time"
)

func TestQuotaFillFirstUsesEarliestLongResetThenRemaining(t *testing.T) {
	app, plain := configureBoundApp(t, "quota-fill-first", false)
	now := time.Now().UTC()
	seedQuotaForTest(app, "account-a-late", now, now.Add(3*time.Hour), 10, nil)
	seedQuotaForTest(app, "account-a-early-low", now, now.Add(time.Hour), 80, nil)
	seedQuotaForTest(app, "account-a-early-high", now, now.Add(time.Hour), 20, nil)
	request := boundSchedulerRequest(plain)
	request.Candidates = []SchedulerAuthCandidate{
		{ID: "account-a-late", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
		{ID: "account-a-early-low", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
		{ID: "account-a-early-high", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
	}
	if got := schedulerPickForTest(t, app, request).AuthID; got != "account-a-early-high" {
		t.Fatalf("quota fill first selected %q", got)
	}
}

func TestQuotaFillFirstShortWindowOnlyControlsAvailability(t *testing.T) {
	app, plain := configureBoundApp(t, "quota-fill-first", false)
	now := time.Now().UTC()
	exhausted := 100.0
	seedQuotaForTest(app, "account-a-earliest", now, now.Add(time.Hour), 10, &exhausted)
	seedQuotaForTest(app, "account-a-later", now, now.Add(2*time.Hour), 20, nil)
	request := boundSchedulerRequest(plain)
	request.Candidates = []SchedulerAuthCandidate{
		{ID: "account-a-earliest", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
		{ID: "account-a-later", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
	}
	if got := schedulerPickForTest(t, app, request).AuthID; got != "account-a-later" {
		t.Fatalf("short-window exhausted auth was not excluded, got %q", got)
	}
}

func TestQuotaFillFirstFallsBackWithinLegalPoolWhenAllUnknown(t *testing.T) {
	app, plain := configureBoundApp(t, "quota-fill-first", false)
	request := boundSchedulerRequest(plain)
	request.Candidates = []SchedulerAuthCandidate{
		{ID: "account-a-z", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
		{ID: "account-a-a", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
		{ID: "account-b-outside", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
	}
	if got := schedulerPickForTest(t, app, request).AuthID; got != "account-a-a" {
		t.Fatalf("unknown fallback selected %q", got)
	}
}

func TestQuotaFillFirstStaleObservationsUseStableFillFirstFallback(t *testing.T) {
	app, plain := configureBoundApp(t, "quota-fill-first", false)
	now := time.Now().UTC()
	seedQuotaForTest(app, "account-a-z", now.Add(-31*time.Minute), now.Add(time.Hour), 10, nil)
	seedQuotaForTest(app, "account-a-a", now.Add(-31*time.Minute), now.Add(4*time.Hour), 90, nil)
	request := boundSchedulerRequest(plain)
	request.Candidates = []SchedulerAuthCandidate{
		{ID: "account-a-z", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
		{ID: "account-a-a", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
	}
	if got := schedulerPickForTest(t, app, request).AuthID; got != "account-a-a" {
		t.Fatalf("stale Unknown fallback selected %q", got)
	}
}

func TestQuotaFillFirstPreservesReadyAffinityAndRebindsWhenUnknown(t *testing.T) {
	app, plain := configureBoundApp(t, "quota-fill-first", false)
	key := app.store.FindByID("bound-key")
	key.SessionAffinity = true
	if err := app.store.UpsertKey(*key, false); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	seedQuotaForTest(app, "account-a-1", now, now.Add(2*time.Hour), 10, nil)
	seedQuotaForTest(app, "account-a-2", now, now.Add(time.Hour), 20, nil)
	request := boundSchedulerRequest(plain)
	request.Options.Metadata["canonical_session_id"] = "session-1"
	request.Candidates = []SchedulerAuthCandidate{
		{ID: "account-a-1", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
		{ID: "account-a-2", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
	}
	first := schedulerPickForTest(t, app, request).AuthID
	if first != "account-a-2" {
		t.Fatalf("first = %q", first)
	}
	proposal := schedulerAffinityProposalKey("bound-key", "fast", first, request.Options.Metadata, true)
	app.affinity.resolveProposal(proposal, true)
	seedQuotaForTest(app, "account-a-1", now.Add(time.Second), now.Add(30*time.Minute), 10, nil)
	if got := schedulerPickForTest(t, app, request).AuthID; got != first {
		t.Fatalf("ready affinity moved from %q to %q", first, got)
	}
	unknownUsed := 10.0
	app.quota.cache.observe(first, "idx-2", "quota-get", quotaObservation{
		Provider:   "codex",
		ObservedAt: now.Add(2 * time.Second),
		Long:       &quotaWindow{Kind: quotaWindowWeekly, UsedPercent: &unknownUsed, WindowSeconds: quotaWeeklySeconds},
	})
	if got := schedulerPickForTest(t, app, request).AuthID; got != "account-a-1" {
		t.Fatalf("unknown affinity did not rebind to ready auth, got %q", got)
	}
}

func TestQuotaFillFirstAllExplicitlyExhaustedFailsClosed(t *testing.T) {
	app, plain := configureBoundApp(t, "quota-fill-first", false)
	now := time.Now().UTC()
	app.quota.cache.markExplicitExhausted("account-a-1", "idx-1", now, now.Add(time.Hour), "429")
	request := boundSchedulerRequest(plain)
	request.Candidates = []SchedulerAuthCandidate{{ID: "account-a-1", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}}}
	if err := schedulerErrorForTest(t, app, request); err.Code != "quota_exhausted" {
		t.Fatalf("error = %+v", err)
	}
}

func seedQuotaForTest(app *App, authID string, observedAt, resetAt time.Time, longUsed float64, shortUsed *float64) {
	observation := quotaObservation{
		Provider:          "codex",
		ObservedAt:        observedAt,
		ExplicitAvailable: true,
		Long: &quotaWindow{
			Kind:          quotaWindowWeekly,
			UsedPercent:   &longUsed,
			WindowSeconds: quotaWeeklySeconds,
			ResetAt:       resetAt,
		},
	}
	if shortUsed != nil {
		value := *shortUsed
		observation.Short = &quotaWindow{Kind: quotaWindowShort, UsedPercent: &value, WindowSeconds: quotaFiveHourSeconds, ResetAt: observedAt.Add(time.Hour)}
	}
	app.quota.cache.observe(authID, "idx-"+authID, "quota-get", observation)
}

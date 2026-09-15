package plugin

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"cpa-key-policy/internal/policy"
)

type fakeQuotaHost struct {
	mu           sync.Mutex
	entries      []HostAuthEntry
	runtime      map[string]HostAuthEntry
	documents    map[string]HostAuthDocument
	getResponses []HostHTTPResponse
	listCalls    int
	getCalls     int
	postCalls    int
	requests     []HostHTTPRequest
}

type advancingQuotaHost struct {
	*fakeQuotaHost
	clock *time.Time
	step  time.Duration
}

func (h *advancingQuotaHost) Do(request HostHTTPRequest) (HostHTTPResponse, error) {
	response, err := h.fakeQuotaHost.Do(request)
	if request.Method == http.MethodGet {
		*h.clock = h.clock.Add(h.step)
	}
	return response, err
}

func (f *fakeQuotaHost) ListAuths() ([]HostAuthEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	return append([]HostAuthEntry(nil), f.entries...), nil
}

func (f *fakeQuotaHost) GetAuth(authIndex string) (HostAuthDocument, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.documents[authIndex], nil
}

func (f *fakeQuotaHost) GetAuthRuntime(authIndex string) (HostAuthEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runtime[authIndex], nil
}

func (f *fakeQuotaHost) Do(request HostHTTPRequest) (HostHTTPResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, request)
	if request.Method == http.MethodPost {
		f.postCalls++
		return HostHTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)}, nil
	}
	f.getCalls++
	if len(f.getResponses) == 0 {
		return HostHTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{"rate_limit":{"allowed":true}}`)}, nil
	}
	response := f.getResponses[0]
	f.getResponses = f.getResponses[1:]
	return response, nil
}

func (f *fakeQuotaHost) Log(string, string, map[string]any) {}

func (f *fakeQuotaHost) counts() (list, get, post int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listCalls, f.getCalls, f.postCalls
}

func TestQuotaRoundDoesNothingForLegacyConfiguration(t *testing.T) {
	app := NewApp()
	host := newFakeQuotaHost(time.Now())
	app.quota.mu.Lock()
	app.quota.host = host
	app.quota.mu.Unlock()
	app.quota.runRound()
	list, get, post := host.counts()
	if list != 0 || get != 0 || post != 0 {
		t.Fatalf("legacy config caused host work: list=%d get=%d post=%d", list, get, post)
	}
}

func TestPassiveNativeObservationAppearsWithoutTakingMaintenanceScope(t *testing.T) {
	app := configuredQuotaTestApp(t)
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	app.quota.now = func() time.Time { return now }
	app.quota.cache.now = func() time.Time { return now }
	app.quota.recordUsage(UsageHandleRequest{
		Provider:    "codex",
		AuthID:      "native-only.json",
		AuthIndex:   "idx-native",
		RequestedAt: now,
		ResponseHeaders: http.Header{
			"Date":                                  []string{now.Format(http.TimeFormat)},
			"X-Codex-Allowed":                       []string{"true"},
			"X-Codex-Primary-Used-Percent":          []string{"10"},
			"X-Codex-Primary-Window-Minutes":        []string{"300"},
			"X-Codex-Primary-Reset-After-Seconds":   []string{"3600"},
			"X-Codex-Secondary-Used-Percent":        []string{"20"},
			"X-Codex-Secondary-Window-Minutes":      []string{"10080"},
			"X-Codex-Secondary-Reset-After-Seconds": []string{"7200"},
		},
	})
	status := app.quota.status()
	auths := status["auths"].([]map[string]any)
	if len(auths) != 1 || auths[0]["auth_id"] != "native-only.json" || auths[0]["availability"] != "ready" || auths[0]["freshness"] != "fresh" || auths[0]["observable"] != true || auths[0]["in_maintenance_scope"] != false {
		t.Fatalf("passive auth status = %#v", auths)
	}
}

func TestQuotaManagedPoolRefreshesButDoesNotActivateByDefault(t *testing.T) {
	app, _ := configureBoundApp(t, "quota-fill-first", false)
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(now)
	host.getResponses = []HostHTTPResponse{{StatusCode: http.StatusOK, Body: quotaBody(now, 10)}}
	attachTestQuotaHost(app, host, now)
	app.quota.runRound()
	list, get, post := host.counts()
	if list != 1 || get != 1 || post != 0 {
		t.Fatalf("managed refresh counts: list=%d get=%d post=%d", list, get, post)
	}
	if class, _ := app.quota.cache.classify("account-a-team", 30*time.Minute, now); class != quotaAvailabilityReady {
		t.Fatalf("class = %v", class)
	}
}

func TestQuotaRoundAdvancesExpiredNextCheckWhenFreshPassiveObservationSkipsProbe(t *testing.T) {
	app, _ := configureBoundApp(t, "quota-fill-first", false)
	clock := time.Date(2026, 9, 13, 16, 54, 24, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	host.getResponses = []HostHTTPResponse{
		{StatusCode: http.StatusOK, Body: quotaBody(clock, 10)},
		{StatusCode: http.StatusOK, Body: quotaBody(clock.Add(time.Hour), 11)},
	}
	attachTestQuotaHost(app, host, clock)
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }
	app.quota.testDurations = func() (time.Duration, time.Duration) {
		return 30 * time.Minute, 30 * time.Minute
	}

	app.quota.runRound()
	clock = time.Date(2026, 9, 13, 17, 7, 1, 0, time.UTC)
	app.quota.recordUsage(UsageHandleRequest{
		Provider:    "codex",
		AuthID:      "account-a-team",
		AuthIndex:   "idx-a",
		RequestedAt: clock,
		ResponseHeaders: http.Header{
			"Date":                                  []string{clock.Format(http.TimeFormat)},
			"X-Codex-Allowed":                       []string{"true"},
			"X-Codex-Primary-Used-Percent":          []string{"10"},
			"X-Codex-Primary-Window-Minutes":        []string{"300"},
			"X-Codex-Primary-Reset-After-Seconds":   []string{"3600"},
			"X-Codex-Secondary-Used-Percent":        []string{"20"},
			"X-Codex-Secondary-Window-Minutes":      []string{"10080"},
			"X-Codex-Secondary-Reset-After-Seconds": []string{"7200"},
		},
	})

	clock = time.Date(2026, 9, 13, 17, 24, 25, 0, time.UTC)
	app.quota.runRound()
	_, get, post := host.counts()
	if get != 1 || post != 0 {
		t.Fatalf("fresh passive evidence caused extra upstream work: GET=%d POST=%d", get, post)
	}

	status := app.quota.status()
	auths := status["auths"].([]map[string]any)
	if len(auths) != 1 {
		t.Fatalf("auth status count = %d, want 1", len(auths))
	}
	next, ok := auths[0]["next_check_at"].(time.Time)
	if !ok {
		t.Fatalf("next_check_at type = %T, want time.Time", auths[0]["next_check_at"])
	}
	want := time.Date(2026, 9, 13, 17, 54, 25, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("next_check_at = %s, want next maintenance round %s", next.Format(time.RFC3339), want.Format(time.RFC3339))
	}
	observation := auths[0]["observation"].(map[string]any)
	if observation["source"] != "passive-http" {
		t.Fatalf("observation source = %v, want passive-http", observation["source"])
	}

	clock = time.Date(2026, 9, 13, 17, 54, 26, 0, time.UTC)
	app.quota.runRound()
	_, get, post = host.counts()
	if get != 2 || post != 0 {
		t.Fatalf("next maintenance round work: GET=%d POST=%d, want GET=2 POST=0", get, post)
	}
	status = app.quota.status()
	auths = status["auths"].([]map[string]any)
	observation = auths[0]["observation"].(map[string]any)
	if observation["source"] != "quota-get" {
		t.Fatalf("observation source after next round = %v, want quota-get", observation["source"])
	}
}

func TestQuotaRoundAlignsProcessedAuthDeadlinesWithNextGlobalRound(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{
		QuotaActivationEnabled: &enabled,
		QuotaActivationScope:   &scope,
	}); err != nil {
		t.Fatal(err)
	}

	clock := time.Date(2026, 9, 13, 18, 24, 51, 0, time.UTC)
	base := newFakeQuotaHost(clock)
	for i, id := range []string{"account-b-team", "account-c-team"} {
		index := "idx-" + string(rune('b'+i))
		entry := HostAuthEntry{ID: id, AuthIndex: index, Name: id + ".json", Provider: "codex", Status: "active"}
		base.entries = append(base.entries, entry)
		base.runtime[index] = entry
		base.documents[index] = HostAuthDocument{
			AuthIndex: index,
			Name:      entry.Name,
			JSON:      quotaCredentialJSON(clock, "team", "acct-"+id, "access-"+id, "refresh-"+id),
		}
	}
	base.getResponses = []HostHTTPResponse{
		{StatusCode: http.StatusOK, Body: quotaBody(clock, 10)},
		{StatusCode: http.StatusOK, Body: quotaBody(clock, 10)},
		{StatusCode: http.StatusOK, Body: quotaBody(clock, 10)},
	}
	host := &advancingQuotaHost{fakeQuotaHost: base, clock: &clock, step: 2 * time.Minute}
	app.quota.mu.Lock()
	app.quota.host = host
	app.quota.mu.Unlock()
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }
	app.quota.testDurations = func() (time.Duration, time.Duration) {
		return 30 * time.Minute, 30 * time.Minute
	}

	app.quota.runRound()
	nextGlobalRound := clock.Add(30 * time.Minute)
	status := app.quota.status()
	auths := status["auths"].([]map[string]any)
	for _, auth := range auths {
		next, ok := auth["next_check_at"].(time.Time)
		if !ok {
			t.Fatalf("%s next_check_at type = %T, want time.Time", auth["auth_id"], auth["next_check_at"])
		}
		if next.Before(nextGlobalRound) {
			t.Fatalf("%s next_check_at=%s, but the loop cannot start the next global round before %s", auth["auth_id"], next.Format(time.RFC3339), nextGlobalRound.Format(time.RFC3339))
		}
	}
	_, get, post := host.counts()
	if get != 3 || post != 0 {
		t.Fatalf("deadline alignment changed upstream work: GET=%d POST=%d", get, post)
	}
}

func TestQuotaGetHonorsRetryAfterBeyondCheckInterval(t *testing.T) {
	app, _ := configureBoundApp(t, "quota-fill-first", false)
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(now)
	host.getResponses = []HostHTTPResponse{{StatusCode: http.StatusTooManyRequests, Headers: http.Header{"Retry-After": []string{"3600"}}}}
	attachTestQuotaHost(app, host, now)
	app.quota.runRound()
	app.quota.mu.Lock()
	next := app.quota.runtime.Auths["account-a-team"].NextCheckAt
	app.quota.mu.Unlock()
	want := now.Add(time.Hour)
	if !next.Equal(want) {
		t.Fatalf("next check = %v, want Retry-After %v", next, want)
	}
	if observation, ok := app.quota.cache.get("account-a-team"); ok && observation.ExplicitExhausted {
		t.Fatalf("quota GET 429 was misclassified as model exhaustion: %#v", observation)
	}
}

func TestQuotaAllCodexIncludesIdleAuthWithoutQuotaKey(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{QuotaActivationEnabled: &enabled, QuotaActivationScope: &scope}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(now)
	host.getResponses = []HostHTTPResponse{{StatusCode: http.StatusOK, Body: quotaBody(now, 10)}}
	attachTestQuotaHost(app, host, now)
	app.quota.runRound()
	_, get, _ := host.counts()
	if get != 1 {
		t.Fatalf("all-codex idle auth GETs = %d, want 1", get)
	}
	status := app.quota.status()
	auths := status["auths"].([]map[string]any)
	if len(auths) != 1 || auths[0]["in_activation_scope"] != true {
		t.Fatalf("auth status = %#v", auths)
	}
}

func TestQuotaLoopReconfigureDoesNotPostponeDueRound(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{
		QuotaActivationEnabled: &enabled,
		QuotaActivationScope:   &scope,
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	host := newFakeQuotaHost(now)
	host.getResponses = []HostHTTPResponse{
		{StatusCode: http.StatusOK, Body: quotaBody(now, 0)},
		{StatusCode: http.StatusOK, Body: quotaBody(now.Add(150*time.Second), 0)},
		{StatusCode: http.StatusOK, Body: quotaBody(now.Add(150*time.Second), 1)},
	}
	app.quota.testDurations = func() (time.Duration, time.Duration) {
		return 80 * time.Millisecond, 80 * time.Millisecond
	}
	app.quota.verifyDelay = 0
	app.quota.setHostClient(host)
	t.Cleanup(app.Shutdown)

	deadline := time.Now().Add(2 * time.Second)
	for {
		app.quota.configure(app.store.StatePath(), false)
		_, get, post := host.counts()
		if get >= 3 && post >= 1 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	_, get, post := host.counts()
	if get < 3 || post != 1 {
		t.Fatalf("continuous reconfigure counts: GET=%d POST=%d, want at least 3 GETs and exactly 1 POST", get, post)
	}
	app.quota.mu.Lock()
	lastRoundAt := app.quota.runtime.LastRoundAt
	activation := app.quota.runtime.Auths[host.entries[0].ID].Activation
	app.quota.mu.Unlock()
	if lastRoundAt.IsZero() {
		t.Fatal("quota round completed no work after continuous reconfigure")
	}
	if activation.Status != "confirmed" {
		t.Fatalf("activation status = %q, want confirmed", activation.Status)
	}
}

func TestQuotaLoopStartupAlignsPersistedDeadlineWithFirstGlobalRound(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{
		QuotaActivationEnabled: &enabled,
		QuotaActivationScope:   &scope,
	}); err != nil {
		t.Fatal(err)
	}

	clock := time.Date(2026, 9, 13, 18, 40, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }
	app.quota.testDurations = func() (time.Duration, time.Duration) {
		return time.Hour, 30 * time.Minute
	}
	app.quota.mu.Lock()
	app.quota.runtime.Auths["account-a-team"] = quotaAuthRuntime{
		AuthID:      "account-a-team",
		AuthIndex:   "idx-a",
		Provider:    "codex",
		NextCheckAt: clock.Add(-time.Minute),
	}
	app.quota.mu.Unlock()
	app.quota.setHostClient(host)
	t.Cleanup(app.Shutdown)

	deadline := time.Now().Add(time.Second)
	var auth map[string]any
	for time.Now().Before(deadline) {
		status := app.quota.status()
		auths := status["auths"].([]map[string]any)
		if len(auths) == 1 {
			seen, _ := auths[0]["last_roster_seen_at"].(time.Time)
			if seen.Equal(clock) {
				auth = auths[0]
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	if auth == nil {
		t.Fatal("startup roster sync did not complete")
	}
	next, ok := auth["next_check_at"].(time.Time)
	if !ok {
		t.Fatalf("next_check_at type = %T, want time.Time", auth["next_check_at"])
	}
	want := clock.Add(time.Hour)
	if !next.Equal(want) {
		t.Fatalf("startup next_check_at=%s, want first global round %s", next.Format(time.RFC3339), want.Format(time.RFC3339))
	}
	_, get, post := host.counts()
	if get != 0 || post != 0 {
		t.Fatalf("startup performed upstream work: GET=%d POST=%d", get, post)
	}
}

func TestQuotaRoundDeadlineOnlyMovesEarlier(t *testing.T) {
	now := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	original := now.Add(30 * time.Minute)
	tests := []struct {
		name             string
		current          time.Time
		previousInterval time.Duration
		nextInterval     time.Duration
		previouslyNeeded bool
		needed           bool
		restart          bool
		at               time.Time
		want             time.Time
	}{
		{name: "enable waits one interval", nextInterval: 30 * time.Minute, needed: true, at: now, want: original},
		{name: "same interval keeps deadline", current: original, previousInterval: 30 * time.Minute, nextInterval: 30 * time.Minute, previouslyNeeded: true, needed: true, at: now.Add(10 * time.Minute), want: original},
		{name: "longer interval cannot postpone", current: original, previousInterval: 30 * time.Minute, nextInterval: time.Hour, previouslyNeeded: true, needed: true, at: now.Add(10 * time.Minute), want: original},
		{name: "shorter interval may advance", current: original, previousInterval: 30 * time.Minute, nextInterval: 5 * time.Minute, previouslyNeeded: true, needed: true, at: now.Add(10 * time.Minute), want: now.Add(15 * time.Minute)},
		{name: "due deadline stays due", current: original, previousInterval: 30 * time.Minute, nextInterval: time.Hour, previouslyNeeded: true, needed: true, at: now.Add(31 * time.Minute), want: original},
		{name: "explicit re-enable restarts full interval", current: original, previousInterval: 30 * time.Minute, nextInterval: 30 * time.Minute, previouslyNeeded: true, needed: true, restart: true, at: now.Add(10 * time.Minute), want: now.Add(40 * time.Minute)},
		{name: "disable clears deadline", current: original, previousInterval: 30 * time.Minute, nextInterval: 30 * time.Minute, previouslyNeeded: true, at: now.Add(10 * time.Minute)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := quotaRoundDeadline(test.current, test.previousInterval, test.nextInterval, test.previouslyNeeded, test.needed, test.restart, test.at)
			if !got.Equal(test.want) {
				t.Fatalf("deadline = %v, want %v", got, test.want)
			}
		})
	}
}

func TestQuotaConfigureKeepsRestartRequestWhenWakeIsAlreadyQueued(t *testing.T) {
	app := configuredQuotaTestApp(t)
	for {
		select {
		case <-app.quota.configCh:
		default:
			goto drained
		}
	}
drained:
	app.quota.configure(app.store.StatePath(), false)
	app.quota.configure(app.store.StatePath(), true)
	if !app.quota.takeRestartRoundDeadline() {
		t.Fatal("coalesced config wake dropped the explicit re-enable deadline restart")
	}
}

func TestPluginReconfigureRestartsDeadlineOnlyWhenQuotaFeatureBecomesNeeded(t *testing.T) {
	app := NewApp()
	configure := func(statePath string, activationEnabled bool) {
		t.Helper()
		configYAML := []byte("enabled: true\nstate_file: \"" + filepath.ToSlash(statePath) + "\"\nquota_activation_enabled: " + strconv.FormatBool(activationEnabled) + "\nkeys: []\n")
		raw, err := json.Marshal(LifecycleRequest{ConfigYAML: configYAML})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := app.HandleMethod(MethodPluginReconfigure, raw); err != nil {
			t.Fatal(err)
		}
	}

	configure(filepath.Join(t.TempDir(), "disabled.json"), false)
	if app.quota.takeRestartRoundDeadline() {
		t.Fatal("disabled quota feature requested a deadline restart")
	}

	enabledPath := filepath.Join(t.TempDir(), "enabled.json")
	configure(enabledPath, true)
	if !app.quota.takeRestartRoundDeadline() {
		t.Fatal("false-to-true plugin reconfigure did not request a full deadline restart")
	}

	configure(enabledPath, true)
	if app.quota.takeRestartRoundDeadline() {
		t.Fatal("ordinary enabled reconfigure requested another full deadline restart")
	}
}

func TestQuotaRosterRequiresConfirmedCredentialsAndMatchingRouteGroup(t *testing.T) {
	app, _ := configureBoundApp(t, "quota-fill-first", false)
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(now)
	attachTestQuotaHost(app, host, now)
	team := host.entries[0]
	free := HostAuthEntry{ID: "account-a-free", AuthIndex: "idx-free", Name: "account-a-free.json", Provider: "codex", Status: "active"}
	unresolved := HostAuthEntry{ID: "account-a-disk", Name: "account-a-disk.json", Provider: "codex", Status: "active"}
	host.entries = []HostAuthEntry{team, free, unresolved}
	host.runtime[free.AuthIndex] = free
	host.documents[free.AuthIndex] = HostAuthDocument{AuthIndex: free.AuthIndex, Name: free.Name, JSON: quotaCredentialJSON(now, "free", "acct-free", "access-free", "refresh-free")}
	eligible := app.quota.applyRoster(host, host.entries, app.store.RuntimeSettings(), app.store.Keys())
	if len(eligible) != 1 || eligible[0].ID != team.ID {
		t.Fatalf("eligible = %#v", eligible)
	}
	app.quota.mu.Lock()
	teamRuntime := app.quota.runtime.Auths[team.ID]
	freeRuntime := app.quota.runtime.Auths[free.ID]
	unresolvedRuntime := app.quota.runtime.Auths[unresolved.ID]
	app.quota.mu.Unlock()
	if !teamRuntime.InManagedPool || !teamRuntime.InMaintenanceScope {
		t.Fatalf("team runtime = %#v", teamRuntime)
	}
	if freeRuntime.InManagedPool || freeRuntime.InMaintenanceScope || freeRuntime.ExclusionReason != "out_of_scope" {
		t.Fatalf("free runtime = %#v", freeRuntime)
	}
	if unresolvedRuntime.InMaintenanceScope || unresolvedRuntime.ExclusionReason != "runtime_unresolvable" {
		t.Fatalf("unresolved runtime = %#v", unresolvedRuntime)
	}
}

func TestQuotaRosterTokenRefreshPreservesStateAndAccountReplacementClearsIt(t *testing.T) {
	app, _ := configureBoundApp(t, "quota-fill-first", false)
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(now)
	host.getResponses = []HostHTTPResponse{{StatusCode: http.StatusOK, Body: quotaBody(now, 10)}}
	attachTestQuotaHost(app, host, now)
	app.quota.runRound()
	authID := host.entries[0].ID
	app.quota.mu.Lock()
	runtime := app.quota.runtime.Auths[authID]
	runtime.Baselines = map[quotaWindowKind]quotaWindowBaseline{quotaWindowWeekly: {Kind: quotaWindowWeekly, ResetAt: now.Add(7 * 24 * time.Hour)}}
	runtime.Activation = quotaActivationState{Status: "confirmed", CycleID: "cycle-a", Attempts: 1}
	stableFingerprint := runtime.CredentialFingerprint
	app.quota.runtime.Auths[authID] = runtime
	app.quota.mu.Unlock()

	host.mu.Lock()
	host.documents["idx-a"] = HostAuthDocument{AuthIndex: "idx-a", JSON: quotaCredentialJSON(now, "team", "acct-a", "rotated-access", "rotated-refresh")}
	host.mu.Unlock()
	app.quota.syncRosterOnly()
	app.quota.mu.Lock()
	runtime = app.quota.runtime.Auths[authID]
	app.quota.mu.Unlock()
	if runtime.CredentialFingerprint != stableFingerprint || runtime.Activation.CycleID != "cycle-a" || len(runtime.Baselines) != 1 {
		t.Fatalf("normal token refresh reset runtime state: %#v", runtime)
	}

	host.mu.Lock()
	host.documents["idx-a"] = HostAuthDocument{AuthIndex: "idx-a", JSON: quotaCredentialJSON(now, "team", "acct-other", "other-access", "other-refresh")}
	host.mu.Unlock()
	app.quota.syncRosterOnly()
	app.quota.mu.Lock()
	runtime = app.quota.runtime.Auths[authID]
	app.quota.mu.Unlock()
	if runtime.CredentialFingerprint == stableFingerprint || runtime.Activation.CycleID != "" || len(runtime.Baselines) != 0 {
		t.Fatalf("account replacement retained old state: %#v", runtime)
	}
	if class, _ := app.quota.cache.classify(authID, 30*time.Minute, now); class != quotaAvailabilityUnknown {
		t.Fatalf("replacement inherited old quota class %v", class)
	}
}

func TestQuotaLazyWindowRequiresBaselineThenActivatesAndVerifies(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{QuotaActivationEnabled: &enabled, QuotaActivationScope: &scope}); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	host.getResponses = []HostHTTPResponse{
		{StatusCode: http.StatusOK, Body: quotaBody(clock, 0)},
		{StatusCode: http.StatusOK, Body: quotaBody(clock.Add(31*time.Minute), 0)},
		{StatusCode: http.StatusOK, Body: quotaBody(clock.Add(31*time.Minute), 1)},
	}
	attachTestQuotaHost(app, host, clock)
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }
	app.quota.verifyDelay = 0
	app.quota.runRound()
	if _, _, post := host.counts(); post != 0 {
		t.Fatalf("first observation posted %d activation(s)", post)
	}
	clock = clock.Add(31 * time.Minute)
	app.quota.runRound()
	_, get, post := host.counts()
	if get != 3 || post != 1 {
		t.Fatalf("activation counts: get=%d post=%d", get, post)
	}
	app.quota.mu.Lock()
	activation := app.quota.runtime.Auths["account-a-team"].Activation
	app.quota.mu.Unlock()
	if activation.Status != "confirmed" || activation.SendIntent || activation.TotalTokens != 2 {
		t.Fatalf("activation = %#v", activation)
	}
	if current := app.concurrency.authCurrent("account-a-team"); current != 0 {
		t.Fatalf("activation leaked auth slot: %d", current)
	}
	if _, err := app.quota.runtimeStore.load(); err != nil {
		t.Fatalf("persisted runtime state: %v", err)
	}
}

func TestQuotaShortLazyWindowUsesResponsesActivationProtocol(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	model := "custom-activation-model"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{QuotaActivationEnabled: &enabled, QuotaActivationScope: &scope, QuotaActivationModel: &model}); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 9, 14, 11, 18, 33, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	host.getResponses = []HostHTTPResponse{
		{StatusCode: http.StatusOK, Body: shortQuotaBody(0)},
		{StatusCode: http.StatusOK, Body: shortQuotaBody(0)},
		{StatusCode: http.StatusOK, Body: shortQuotaBody(1)},
	}
	attachTestQuotaHost(app, host, clock)
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }
	app.quota.verifyDelay = 0

	app.quota.runRound()
	if _, _, post := host.counts(); post != 0 {
		t.Fatalf("first short-window observation posted %d activation(s)", post)
	}
	clock = clock.Add(31 * time.Minute)
	app.quota.runRound()

	host.mu.Lock()
	requests := append([]HostHTTPRequest(nil), host.requests...)
	host.mu.Unlock()
	var activationRequest *HostHTTPRequest
	for i := range requests {
		if requests[i].Method == http.MethodPost {
			copy := requests[i]
			activationRequest = &copy
			break
		}
	}
	if activationRequest == nil {
		t.Fatal("strict moving five-hour reset did not send an activation request")
	}
	if activationRequest.URL != "https://chatgpt.com/backend-api/codex/responses" {
		t.Fatalf("activation URL = %q", activationRequest.URL)
	}
	var payload map[string]any
	if err := json.Unmarshal(activationRequest.Body, &payload); err != nil {
		t.Fatalf("decode activation payload: %v", err)
	}
	if stream, ok := payload["stream"].(bool); !ok || !stream {
		t.Fatalf("activation stream = %#v, want true", payload["stream"])
	}
	if store, ok := payload["store"].(bool); !ok || store {
		t.Fatalf("activation store = %#v, want false", payload["store"])
	}
	if payload["model"] != model {
		t.Fatalf("activation model = %#v", payload["model"])
	}
}

func TestQuotaRejectedActivationRetriesAfterActivationModelChanges(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	model := "gpt-5.6-luna"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{
		QuotaActivationEnabled: &enabled,
		QuotaActivationScope:   &scope,
		QuotaActivationModel:   &model,
	}); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 9, 14, 12, 18, 44, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	host.getResponses = []HostHTTPResponse{
		{StatusCode: http.StatusOK, Body: shortQuotaBody(0)},
		{StatusCode: http.StatusOK, Body: shortQuotaBody(1)},
	}
	attachTestQuotaHost(app, host, clock)
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }
	app.quota.verifyDelay = 0
	app.quota.mu.Lock()
	app.quota.runtime.Auths["account-a-team"] = quotaAuthRuntime{
		AuthID:                "account-a-team",
		AuthIndex:             "idx-a",
		Provider:              "codex",
		InMaintenanceScope:    true,
		InActivationScope:     true,
		CredentialFingerprint: codexCredentialFingerprint(codexCredentials{AccountID: "acct-a"}),
		Baselines: map[quotaWindowKind]quotaWindowBaseline{
			quotaWindowShort: {Kind: quotaWindowShort, ResetAt: clock.Add(5*time.Hour - 31*time.Minute), WindowSeconds: quotaFiveHourSeconds, ObservedAt: clock.Add(-31 * time.Minute)},
		},
		Activation: quotaActivationState{
			Protocol:      codexActivationProtocol,
			Status:        "deferred",
			CycleID:       "old-model-cycle",
			Windows:       []quotaWindowKind{quotaWindowShort},
			Attempts:      quotaMaxActivationTries,
			LastAttemptAt: clock.Add(-31 * time.Minute),
			RetryAllowed:  true,
			LastResult:    "http_404",
		},
	}
	app.quota.mu.Unlock()

	app.quota.runRound()
	_, get, post := host.counts()
	if get != 2 || post != 1 {
		t.Fatalf("activation model migration counts: get=%d post=%d", get, post)
	}
	app.quota.mu.Lock()
	activation := app.quota.runtime.Auths["account-a-team"].Activation
	app.quota.mu.Unlock()
	if activation.Model != model || activation.Status != "confirmed" || activation.Attempts != 1 || activation.LastResult != "verified" {
		t.Fatalf("migrated activation = %#v", activation)
	}
}

func TestQuotaLegacyCompact404StateRetriesOnceWithCurrentProtocol(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{QuotaActivationEnabled: &enabled, QuotaActivationScope: &scope}); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 9, 14, 11, 48, 40, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	host.getResponses = []HostHTTPResponse{
		{StatusCode: http.StatusOK, Body: shortQuotaBody(0)},
		{StatusCode: http.StatusOK, Body: shortQuotaBody(1)},
	}
	attachTestQuotaHost(app, host, clock)
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }
	app.quota.verifyDelay = 0
	app.quota.mu.Lock()
	app.quota.runtime.Auths["account-a-team"] = quotaAuthRuntime{
		AuthID:                "account-a-team",
		AuthIndex:             "idx-a",
		Provider:              "codex",
		InMaintenanceScope:    true,
		InActivationScope:     true,
		CredentialFingerprint: codexCredentialFingerprint(codexCredentials{AccountID: "acct-a"}),
		Baselines: map[quotaWindowKind]quotaWindowBaseline{
			quotaWindowShort: {
				Kind:          quotaWindowShort,
				ResetAt:       clock.Add(5*time.Hour - 31*time.Minute),
				UsedPercent:   0,
				WindowSeconds: quotaFiveHourSeconds,
				ObservedAt:    clock.Add(-31 * time.Minute),
			},
		},
		Activation: quotaActivationState{
			Status:        "watching",
			CycleID:       "legacy-compact-cycle",
			Windows:       []quotaWindowKind{quotaWindowShort},
			Attempts:      quotaMaxActivationTries,
			LastAttemptAt: clock.Add(-12 * time.Hour),
			RetryAllowed:  true,
			LastResult:    "http_404",
		},
	}
	app.quota.mu.Unlock()

	app.quota.runRound()
	_, get, post := host.counts()
	if get != 2 || post != 1 {
		t.Fatalf("legacy compact 404 migration counts: get=%d post=%d", get, post)
	}
	app.quota.mu.Lock()
	activation := app.quota.runtime.Auths["account-a-team"].Activation
	app.quota.mu.Unlock()
	if activation.Status != "confirmed" || activation.Attempts != 1 || activation.LastResult != "verified" {
		t.Fatalf("migrated activation = %#v", activation)
	}
}

func TestQuotaCurrentProtocol404AtLimitIsNotMigratedAgain(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{QuotaActivationEnabled: &enabled, QuotaActivationScope: &scope}); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 9, 14, 12, 18, 44, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	host.getResponses = []HostHTTPResponse{{StatusCode: http.StatusOK, Body: shortQuotaBody(0)}}
	attachTestQuotaHost(app, host, clock)
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }
	app.quota.mu.Lock()
	app.quota.runtime.Auths["account-a-team"] = quotaAuthRuntime{
		AuthID:                "account-a-team",
		AuthIndex:             "idx-a",
		Provider:              "codex",
		InMaintenanceScope:    true,
		InActivationScope:     true,
		CredentialFingerprint: codexCredentialFingerprint(codexCredentials{AccountID: "acct-a"}),
		Baselines: map[quotaWindowKind]quotaWindowBaseline{
			quotaWindowShort: {Kind: quotaWindowShort, ResetAt: clock.Add(5*time.Hour - 31*time.Minute), WindowSeconds: quotaFiveHourSeconds, ObservedAt: clock.Add(-31 * time.Minute)},
		},
		Activation: quotaActivationState{
			Protocol:      codexActivationProtocol,
			Model:         "gpt-5.6-luna",
			Status:        "deferred",
			CycleID:       "current-protocol-cycle",
			Windows:       []quotaWindowKind{quotaWindowShort},
			Attempts:      quotaMaxActivationTries,
			LastAttemptAt: clock.Add(-31 * time.Minute),
			RetryAllowed:  true,
			LastResult:    "http_404",
		},
	}
	app.quota.mu.Unlock()

	app.quota.runRound()
	_, get, post := host.counts()
	if get != 1 || post != 0 {
		t.Fatalf("current protocol attempt budget was reset: get=%d post=%d", get, post)
	}
	app.quota.mu.Lock()
	activation := app.quota.runtime.Auths["account-a-team"].Activation
	app.quota.mu.Unlock()
	if activation.Attempts != quotaMaxActivationTries || activation.Protocol != codexActivationProtocol || activation.Status != "attempts_exhausted" {
		t.Fatalf("current protocol activation changed unexpectedly: %#v", activation)
	}
}

func TestQuotaConfirmedActivationIsNotOverwrittenByWatching(t *testing.T) {
	app := configuredQuotaTestApp(t)
	now := time.Date(2026, 9, 14, 12, 30, 0, 0, time.UTC)
	used := 1.0
	app.quota.mu.Lock()
	app.quota.runtime.Auths["account-a-team"] = quotaAuthRuntime{
		AuthID: "account-a-team",
		Baselines: map[quotaWindowKind]quotaWindowBaseline{
			quotaWindowShort: {Kind: quotaWindowShort, ResetAt: now.Add(4 * time.Hour), UsedPercent: 1, WindowSeconds: quotaFiveHourSeconds, ObservedAt: now.Add(-time.Minute)},
		},
		Activation: quotaActivationState{Status: "confirmed", CycleID: "confirmed-cycle", Windows: []quotaWindowKind{quotaWindowShort}, Attempts: 1, LastResult: "verified"},
	}
	app.quota.mu.Unlock()

	lazy := app.quota.processObservation("account-a-team", "idx-a", "fingerprint-a", quotaObservation{
		Provider:   "codex",
		ObservedAt: now,
		Short:      &quotaWindow{Kind: quotaWindowShort, UsedPercent: &used, WindowSeconds: quotaFiveHourSeconds, ResetAt: now.Add(4 * time.Hour)},
	}, now)
	if len(lazy) != 0 {
		t.Fatalf("active window classified lazy: %v", lazy)
	}
	app.quota.mu.Lock()
	activation := app.quota.runtime.Auths["account-a-team"].Activation
	app.quota.mu.Unlock()
	if activation.Status != "confirmed" || activation.LastResult != "verified" {
		t.Fatalf("confirmed activation was overwritten: %#v", activation)
	}
}

func TestReadActivationUsageFromResponsesSSE(t *testing.T) {
	var state quotaActivationState
	readActivationUsage([]byte("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":2,\"total_tokens\":5}}}\n\n"), &state)
	if state.InputTokens != 3 || state.OutputTokens != 2 || state.TotalTokens != 5 {
		t.Fatalf("SSE activation usage = %#v", state)
	}
}

func TestQuotaUncertainSuccessfulPOSTIsVerifiedWithoutAutomaticResend(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{QuotaActivationEnabled: &enabled, QuotaActivationScope: &scope}); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	host.getResponses = []HostHTTPResponse{
		{StatusCode: http.StatusOK, Body: quotaBody(clock, 0)},
		{StatusCode: http.StatusOK, Body: quotaBody(clock.Add(31*time.Minute), 0)},
		{StatusCode: http.StatusOK, Body: quotaBody(clock.Add(31*time.Minute), 0)},
		{StatusCode: http.StatusOK, Body: quotaBody(clock.Add(62*time.Minute), 0)},
	}
	attachTestQuotaHost(app, host, clock)
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }
	app.quota.verifyDelay = 0
	app.quota.runRound()
	clock = clock.Add(31 * time.Minute)
	app.quota.runRound()
	if _, _, post := host.counts(); post != 1 {
		t.Fatalf("first activation POSTs = %d", post)
	}
	clock = clock.Add(31 * time.Minute)
	app.quota.runRound()
	if _, _, post := host.counts(); post != 1 {
		t.Fatalf("uncertain 2xx activation was automatically resent: %d POSTs", post)
	}
}

func TestQuotaActivationSharesAuthConcurrencyLimit(t *testing.T) {
	app, _ := configureBoundApp(t, "quota-fill-first", false)
	enabled := true
	scope := "all-codex"
	limits := map[string]int{"account-a-team": 1}
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{QuotaActivationEnabled: &enabled, QuotaActivationScope: &scope, AuthConcurrencyLimits: &limits}); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	host.getResponses = []HostHTTPResponse{
		{StatusCode: http.StatusOK, Body: quotaBody(clock, 0)},
		{StatusCode: http.StatusOK, Body: quotaBody(clock.Add(31*time.Minute), 0)},
	}
	attachTestQuotaHost(app, host, clock)
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }
	app.quota.verifyDelay = 0
	app.quota.runRound()
	if _, ok := app.concurrency.acquireKey("business-1", "bound-key", 0); !ok {
		t.Fatal("acquire business key")
	}
	if _, ok := app.concurrency.acquireAuth("business-1", "account-a-team", 1); !ok {
		t.Fatal("acquire business auth")
	}
	clock = clock.Add(31 * time.Minute)
	app.quota.runRound()
	if _, _, post := host.counts(); post != 0 {
		t.Fatalf("activation bypassed auth concurrency: post=%d", post)
	}
	app.concurrency.complete("business-1")
}

func TestQuotaPersistenceFailureBlocksActivationPOST(t *testing.T) {
	app := configuredQuotaTestApp(t)
	enabled := true
	scope := "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{QuotaActivationEnabled: &enabled, QuotaActivationScope: &scope}); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	host.getResponses = []HostHTTPResponse{
		{StatusCode: http.StatusOK, Body: quotaBody(clock, 0)},
		{StatusCode: http.StatusOK, Body: quotaBody(clock.Add(31*time.Minute), 0)},
	}
	attachTestQuotaHost(app, host, clock)
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }
	app.quota.runRound()
	app.quota.mu.Lock()
	app.quota.persistenceBlocked = true
	app.quota.persistenceError = "corrupt runtime state"
	app.quota.mu.Unlock()
	clock = clock.Add(31 * time.Minute)
	app.quota.runRound()
	if _, _, post := host.counts(); post != 0 {
		t.Fatalf("persistence-blocked manager posted %d activation(s)", post)
	}
}

func TestQuotaRuntimePruningKeepsUncertainSendHistory(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	auths := map[string]quotaAuthRuntime{
		"old": {AuthID: "old", OutOfScopeAt: now.Add(-quotaRuntimeRetention - time.Hour)},
		"pending": {
			AuthID: "pending", OutOfScopeAt: now.Add(-quotaRuntimeRetention - time.Hour),
			Activation: quotaActivationState{Status: "verify_pending", SendIntent: true},
		},
	}
	removed := pruneQuotaRuntimesLocked(auths, now)
	if _, ok := removed["old"]; !ok {
		t.Fatal("old inactive runtime was not pruned")
	}
	if _, ok := auths["pending"]; !ok {
		t.Fatal("uncertain send history was pruned")
	}
}

func configuredQuotaTestApp(t *testing.T) *App {
	t.Helper()
	app := NewApp()
	statePath := filepath.ToSlash(filepath.Join(t.TempDir(), "state.json"))
	raw, _ := json.Marshal(LifecycleRequest{ConfigYAML: []byte("enabled: true\nstate_file: \"" + statePath + "\"\nkeys: []\n")})
	if _, err := app.HandleMethod(MethodPluginReconfigure, raw); err != nil {
		t.Fatal(err)
	}
	return app
}

func attachTestQuotaHost(app *App, host *fakeQuotaHost, now time.Time) {
	app.quota.mu.Lock()
	app.quota.host = host
	app.quota.mu.Unlock()
	app.quota.now = func() time.Time { return now }
	app.quota.cache.now = func() time.Time { return now }
}

func newFakeQuotaHost(now time.Time) *fakeQuotaHost {
	entry := HostAuthEntry{ID: "account-a-team", AuthIndex: "idx-a", Name: "account-a-team.json", Provider: "codex", Status: "active"}
	credential := quotaCredentialJSON(now, "team", "acct-a", "access-a", "refresh-a")
	return &fakeQuotaHost{
		entries:   []HostAuthEntry{entry},
		runtime:   map[string]HostAuthEntry{"idx-a": entry},
		documents: map[string]HostAuthDocument{"idx-a": {AuthIndex: "idx-a", Name: entry.Name, JSON: credential}},
	}
}

func quotaCredentialJSON(now time.Time, planType, accountID, accessToken, refreshToken string) []byte {
	return []byte(`{"type":"codex","plan_type":"` + planType + `","access_token":"` + accessToken + `","refresh_token":"` + refreshToken + `","account_id":"` + accountID + `","expired":"` + now.Add(24*time.Hour).Format(time.RFC3339) + `"}`)
}

func quotaBody(observedAt time.Time, used float64) []byte {
	resetAt := observedAt.Add(7 * 24 * time.Hour).Format(time.RFC3339)
	return []byte(`{"plan_type":"team","rate_limit":{"allowed":true,"primary_window":{"used_percent":10,"limit_window_seconds":18000,"reset_after_seconds":3600},"secondary_window":{"used_percent":` + formatFloat(used) + `,"limit_window_seconds":604800,"reset_at":"` + resetAt + `"}}}`)
}

func shortQuotaBody(used float64) []byte {
	return []byte(`{"plan_type":"team","rate_limit":{"allowed":true,"primary_window":{"used_percent":` + formatFloat(used) + `,"limit_window_seconds":18000,"reset_after_seconds":18000},"secondary_window":{"used_percent":10,"limit_window_seconds":604800,"reset_after_seconds":604800}}}`)
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

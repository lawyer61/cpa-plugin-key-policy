package policy

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	plain := "cpa_test_key"
	hash, err := HashKey(plain)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore()
	err = store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{
			{
				ID:         "team-a",
				Name:       "Team A",
				Enabled:    true,
				KeyHash:    hash,
				KeyPreview: PreviewKey(plain),
				RPM:        1,
				Models: []ModelRule{
					{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex"},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, plain
}

func TestStoreAuthenticateUnknownKeyFallsThrough(t *testing.T) {
	store, _ := newTestStore(t)
	decision := store.Authenticate("POST", "/v1/chat/completions", http.Header{"Authorization": {"Bearer other"}}, nil, []byte(`{"model":"fast"}`))
	if decision.Known || decision.Allowed {
		t.Fatalf("decision = %+v, want unknown fallthrough", decision)
	}
}

func TestStoreAuthenticateAllowedAndRoute(t *testing.T) {
	store, plain := newTestStore(t)
	headers := http.Header{"Authorization": {"Bearer " + plain}}
	decision := store.Authenticate("POST", "/v1/chat/completions", headers, nil, []byte(`{"model":"fast"}`))
	if !decision.Known || !decision.Allowed || decision.Rule.TargetModel != "gpt-5-codex" {
		t.Fatalf("decision = %+v, want allowed", decision)
	}
	rule, keyID, ok := store.Route(headers, nil, "fast")
	if !ok || keyID != "team-a" || rule.Provider != "codex" {
		t.Fatalf("Route() = %+v, %q, %v", rule, keyID, ok)
	}
}

func TestStoreAuthenticateRejectsUnauthorizedModel(t *testing.T) {
	store, plain := newTestStore(t)
	decision := store.Authenticate("POST", "/v1/chat/completions", http.Header{"Authorization": {"Bearer " + plain}}, nil, []byte(`{"model":"slow"}`))
	if !decision.Known || decision.Allowed || decision.Reason != "model_not_allowed" {
		t.Fatalf("decision = %+v, want model_not_allowed", decision)
	}
}

func TestStoreAuthenticateRejectsModelsEndpoint(t *testing.T) {
	store, plain := newTestStore(t)
	decision := store.Authenticate("GET", "/v1/models", http.Header{"Authorization": {"Bearer " + plain}}, nil, nil)
	if !decision.Known || decision.Allowed || decision.Reason != "models_endpoint_disabled" {
		t.Fatalf("decision = %+v, want models endpoint denied", decision)
	}
}

func TestStoreAuthenticateRateLimits(t *testing.T) {
	store, plain := newTestStore(t)
	headers := http.Header{"Authorization": {"Bearer " + plain}}
	_ = store.Authenticate("POST", "/v1/chat/completions", headers, nil, []byte(`{"model":"fast"}`))
	decision := store.Authenticate("POST", "/v1/chat/completions", headers, nil, []byte(`{"model":"fast"}`))
	if !decision.RateLimited || decision.Allowed {
		t.Fatalf("decision = %+v, want rate limited", decision)
	}
}

// perCallImageStore builds a store with one per_call-billed image alias, used
// to exercise the deferred after-auth charge for image/video endpoints.
func perCallImageStore(t *testing.T) (*Store, string) {
	t.Helper()
	plain := "cpa_image_key"
	hash, err := HashKey(plain)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore()
	err = store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{
			{
				ID:      "img-team",
				Name:    "Image Team",
				Enabled: true,
				KeyHash: hash,
				Models: []ModelRule{
					{Alias: "grok-imagine-image-quality", Provider: "xai", TargetModel: "grok-imagine-image-quality", BillingMode: "per_call", PerCallUSD: 2},
					{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex"},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, plain
}

// imgTeamKey returns the configured KeyConfig for the per_call image test key.
func imgTeamKey(store *Store) KeyConfig {
	k := store.findByID("img-team")
	if k == nil {
		panic("img-team key not found")
	}
	return *k
}

func TestPerCallImageChargeIsDeferredUntilAfterAdmission(t *testing.T) {
	store, plain := perCallImageStore(t)
	headers := http.Header{"Authorization": {"Bearer " + plain}}
	decision := store.Authenticate("POST", "/v1/images/generations", headers, nil, []byte(`{"model":"grok-imagine-image-quality","prompt":"a boat"}`))
	if !decision.Allowed {
		t.Fatalf("decision = %+v, want Allowed without access-time charge", decision)
	}
	if sum := store.UsageSummaryFor(imgTeamKey(store)); sum.DailyUSD != 0 {
		t.Fatalf("usage before deferred charge = %+v, want zero", sum)
	}
	if !store.ChargeDeferredPerCall("img-team", "/v1/images/generations", "grok-imagine-image-quality", "grok-imagine-image-quality") {
		t.Fatal("deferred image charge did not match")
	}
	sum := store.UsageSummaryFor(imgTeamKey(store))
	if sum.DailyUSD != 2 || sum.DailyCallCount != 1 {
		t.Fatalf("summary = %+v, want DailyUSD=2, DailyCallCount=1", sum)
	}
}

func TestPerCallVideoChargeSupportsPathSubresources(t *testing.T) {
	store, plain := perCallImageStore(t)
	headers := http.Header{"Authorization": {"Bearer " + plain}}
	body := []byte(`{"model":"grok-imagine-image-quality","prompt":"a clip"}`)
	// Path-parameter video subresource (/v1/videos/<id>) must also charge after
	// concurrency admission.
	decision := store.Authenticate("GET", "/v1/videos/req_123", headers, nil, body)
	if !decision.Allowed {
		t.Fatalf("decision = %+v, want Allowed without access-time charge", decision)
	}
	if !store.ChargeDeferredPerCall("img-team", "/v1/videos/req_123", "grok-imagine-image-quality", "grok-imagine-image-quality") {
		t.Fatal("deferred video charge did not match")
	}
	sum := store.UsageSummaryFor(imgTeamKey(store))
	if sum.DailyUSD != 2 {
		t.Fatalf("summary.DailyUSD = %v, want 2", sum.DailyUSD)
	}
}

func TestDeferredPerCallChargeIgnoresChatEndpoints(t *testing.T) {
	store, plain := perCallImageStore(t)
	headers := http.Header{"Authorization": {"Bearer " + plain}}
	// Same per_call alias, but on a chat endpoint — usage.handle bills it.
	decision := store.Authenticate("POST", "/v1/chat/completions", headers, nil, []byte(`{"model":"grok-imagine-image-quality"}`))
	if !decision.Allowed {
		t.Fatalf("decision = %+v, want Allowed and no deferred charge on chat path", decision)
	}
	if store.ChargeDeferredPerCall("img-team", "/v1/chat/completions", "grok-imagine-image-quality", "grok-imagine-image-quality") {
		t.Fatal("chat endpoint matched deferred image/video charge")
	}
	sum := store.UsageSummaryFor(imgTeamKey(store))
	if sum.DailyUSD != 0 {
		t.Fatalf("summary.DailyUSD = %v, want 0 (chat not pre-charged)", sum.DailyUSD)
	}
}

func TestDeferredPerCallChargeIgnoresTokenModeImage(t *testing.T) {
	store, plain := perCallImageStore(t)
	headers := http.Header{"Authorization": {"Bearer " + plain}}
	// Image endpoint, but the alias is token-billed ("fast") — pre-charge only
	// applies to per_call aliases. Token-mode images would be billed by tokens
	// if CPA reported usage, and pre-charging a fixed USD would be wrong.
	decision := store.Authenticate("POST", "/v1/images/generations", headers, nil, []byte(`{"model":"fast","prompt":"x"}`))
	if !decision.Allowed {
		t.Fatalf("decision = %+v, want Allowed and no fixed charge for token-mode alias", decision)
	}
	if store.ChargeDeferredPerCall("img-team", "/v1/images/generations", "fast", "gpt-5-codex") {
		t.Fatal("token-billed image alias matched fixed deferred charge")
	}
	sum := store.UsageSummaryFor(imgTeamKey(store))
	if sum.DailyUSD != 0 {
		t.Fatalf("summary.DailyUSD = %v, want 0 (token mode not pre-charged)", sum.DailyUSD)
	}
}

func TestIsImageVideoEndpoint(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/v1/images/generations", true},
		{"/v1/images/edits", true},
		{"/openai/v1/images/generations", true},
		{"/v1/videos", true},
		{"/v1/videos/generations", true},
		{"/v1/videos/req_abc", true},
		{"/openai/v1/videos/extensions", true},
		{"/v1/chat/completions", false},
		{"/v1/models", false},
		{"/v1/responses", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsImageVideoEndpoint(c.path); got != c.want {
			t.Errorf("IsImageVideoEndpoint(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// TestConfigureDoesNotResurrectKeysMissingFromState verifies that persisted
// state remains authoritative during reconfigure. Retaining an in-memory key
// that was removed from state would keep a revoked credential usable.
func TestConfigureDoesNotResurrectKeysMissingFromState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	onDiskHash, err := HashKey("cpa_on_disk")
	if err != nil {
		t.Fatal(err)
	}
	revokedHash, err := HashKey("cpa_revoked")
	if err != nil {
		t.Fatal(err)
	}
	// Seed initial state with one key on disk.
	s1 := NewStore()
	if err := s1.Configure(Config{Enabled: true, StateFile: path, Keys: []KeyConfig{
		{ID: "on-disk", Enabled: true, KeyHash: onDiskHash, Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex"}}},
	}}); err != nil {
		t.Fatal(err)
	}
	// Add a second key via the management API (persisted to disk).
	if err := s1.UpsertKey(KeyConfig{ID: "in-mem", Enabled: true, KeyHash: revokedHash, Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex"}}}, true); err != nil {
		t.Fatal(err)
	}
	// Simulate a stale disk snapshot: write a state containing only "on-disk".
	if err := SaveState(path, []KeyConfig{{ID: "on-disk", Enabled: true, KeyHash: onDiskHash, Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex"}}}}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	// Reconfigure with the same path. The persisted state lacks "in-mem", so it
	// must be removed from the active authentication index.
	if err := s1.Configure(Config{Enabled: true, StateFile: path}); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, k := range s1.Keys() {
		ids[k.ID] = true
	}
	if !ids["on-disk"] || ids["in-mem"] {
		t.Fatalf("after reconfigure, keys = %v, want only on-disk", ids)
	}
	if s1.FindByAPIKey("cpa_revoked") != nil {
		t.Fatal("credential removed from persisted state remained authenticatable")
	}
}

// TestConfigureFlushesBeforeReload (Bug 2): a reconfigure must flush any
// un-persisted in-memory usage to the OLD state path before loading, so a
// pending usage change is not lost when the disk snapshot is stale. We verify
// by recording usage, NOT calling FlushUsage, then reconfiguring with the same
// path: the usage must survive because Configure flushes first.
func TestConfigureFlushesBeforeReload(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	hash, err := HashKey("cpa_flush")
	if err != nil {
		t.Fatal(err)
	}
	s := NewStore()
	s.SetClock(func() time.Time { return now })
	if err := s.Configure(Config{Enabled: true, StateFile: path, Keys: []KeyConfig{
		{ID: "k", Enabled: true, KeyHash: hash, Models: []ModelRule{{Alias: "fast", Provider: "openai", TargetModel: "m", InputPricePerMillion: 3, OutputPricePerMillion: 15}}},
	}}); err != nil {
		t.Fatal(err)
	}
	s.StartUsageFlusher()
	// Record usage but do NOT flush manually. Without the Bug 2 fix, this
	// in-memory usage has never been written to disk, so a reconfigure that
	// LoadState's the (empty-usage) disk would lose it.
	_ = s.RecordUsage("k", "fast", "m", false, UsageDetail{InputTokens: 1_000_000, OutputTokens: 500_000})
	// Reconfigure with the same path. Bug 2 fix: Configure flushes first.
	if err := s.Configure(Config{Enabled: true, StateFile: path, Keys: []KeyConfig{
		{ID: "k", Enabled: true, KeyHash: hash, Models: []ModelRule{{Alias: "fast", Provider: "openai", TargetModel: "m", InputPricePerMillion: 3, OutputPricePerMillion: 15}}},
	}}); err != nil {
		t.Fatal(err)
	}
	sum := s.UsageSummaryFor(imgKey(s, "k"))
	if sum.DailyUSD <= 0 {
		t.Fatalf("after reconfigure, DailyUSD = %v, want >0 (usage should have been flushed before reload)", sum.DailyUSD)
	}
}

// TestFlushUsagePreservesDiskKeys (Bug 3): the periodic usage flush must not
// overwrite the on-disk key list. We seed a key on disk, then call FlushUsage
// on a store whose in-memory key set differs (missing the key). The disk key
// must survive because FlushUsage only writes usage, not keys.
func TestFlushUsagePreservesDiskKeys(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	hash, err := HashKey("cpa_p3")
	if err != nil {
		t.Fatal(err)
	}
	// Seed state with one key on disk.
	seed := NewStore()
	seed.SetClock(func() time.Time { return now })
	if err := seed.Configure(Config{Enabled: true, StateFile: path, Keys: []KeyConfig{
		{ID: "survivor", Enabled: true, KeyHash: hash, Models: []ModelRule{{Alias: "fast", Provider: "openai", TargetModel: "m", InputPricePerMillion: 3, OutputPricePerMillion: 15}}},
	}}); err != nil {
		t.Fatal(err)
	}
	// Build a second store pointed at the same path but with NO keys in memory,
	// then record usage and flush. Bug 3 fix: FlushUsage preserves disk keys.
	s := NewStore()
	s.SetClock(func() time.Time { return now })
	if err := s.Configure(Config{Enabled: true, StateFile: path}); err != nil {
		t.Fatal(err)
	}
	// s now has the disk key (loaded). Remove it from memory to simulate a
	// truncated in-memory snapshot, then flush usage.
	s.mu.Lock()
	delete(s.keys, "survivor")
	s.mu.Unlock()
	if err := s.FlushUsage(); err != nil {
		t.Fatal(err)
	}
	// Reload from disk: the key must still be there.
	chk := NewStore()
	chk.SetClock(func() time.Time { return now })
	if err := chk.Configure(Config{Enabled: true, StateFile: path}); err != nil {
		t.Fatal(err)
	}
	if chk.findByID("survivor") == nil {
		t.Fatalf("disk key 'survivor' was wiped by FlushUsage; Bug 3 regression")
	}
}

func TestSaveUsageOnlyDoesNotOverwriteCorruptState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	original := []byte(`{"keys":`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveUsageOnly(path, map[string]*UsageState{}); err == nil {
		t.Fatal("SaveUsageOnly accepted a corrupt state file")
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(original) {
		t.Fatalf("corrupt state was overwritten: %q", current)
	}
}

// TestKeysSnapshotSortedByID (Bug 5): Keys() returns a deterministic order
// sorted by ID, not random map-iteration order.
func TestKeysSnapshotSortedByID(t *testing.T) {
	hash, err := HashKey("cpa_sort")
	if err != nil {
		t.Fatal(err)
	}
	s := NewStore()
	if err := s.Configure(Config{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state.json"), Keys: []KeyConfig{
		{ID: "zeta", Enabled: true, KeyHash: hash, Models: []ModelRule{{Alias: "a", Provider: "x", TargetModel: "m"}}},
		{ID: "alpha", Enabled: true, KeyHash: hash, Models: []ModelRule{{Alias: "a", Provider: "x", TargetModel: "m"}}},
		{ID: "mid", Enabled: true, KeyHash: hash, Models: []ModelRule{{Alias: "a", Provider: "x", TargetModel: "m"}}},
	}}); err != nil {
		t.Fatal(err)
	}
	got := s.Keys()
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	want := []string{"alpha", "mid", "zeta"}
	for i, w := range want {
		if got[i].ID != w {
			t.Fatalf("Keys()[%d].ID = %q, want %q (full order: %v)", i, got[i].ID, w, keyIDs(got))
		}
	}
	// Run several times: order must be stable (regression check for map
	// iteration randomness creeping back).
	for i := 0; i < 20; i++ {
		ks := s.Keys()
		for j, w := range want {
			if ks[j].ID != w {
				t.Fatalf("iter %d Keys()[%d].ID = %q, want %q", i, j, ks[j].ID, w)
			}
		}
	}
}

func keyIDs(ks []KeyConfig) []string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = k.ID
	}
	return out
}

func TestStopUsageFlusherWaitsForWorkerExit(t *testing.T) {
	store, _ := newTestStore(t)
	store.StartUsageFlusher()
	store.mu.RLock()
	flusher := store.flusher
	store.mu.RUnlock()
	if flusher == nil {
		t.Fatal("usage flusher was not started")
	}
	store.StopUsageFlusher()
	select {
	case <-flusher.doneCh:
	default:
		t.Fatal("StopUsageFlusher returned before worker exit")
	}
}

func TestStopUsageFlusherFlushesWithoutWorker(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "state.json")
	hash, err := HashKey("cpa_shutdown_flush")
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	if err := store.Configure(Config{Enabled: true, StateFile: path, Keys: []KeyConfig{
		{ID: "shutdown-key", Enabled: true, KeyHash: hash, Models: []ModelRule{{Alias: "fast", Provider: "openai", TargetModel: "m", BillingMode: "per_call", PerCallUSD: 1}}},
	}}); err != nil {
		t.Fatal(err)
	}
	store.RecordUsage("shutdown-key", "fast", "m", false, UsageDetail{})

	// A failed reconfigure can leave no worker running while the plugin keeps
	// serving. Shutdown must still persist usage recorded after that point.
	store.StopUsageFlusher()

	state, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	usage := state.Usage["shutdown-key"]
	if usage == nil {
		t.Fatal("persisted usage missing")
	}
	day := usage.Days[usageDayKey(now)]
	if day == nil || day.Total.TotalUSD != 1 || day.Total.CallCount != 1 {
		t.Fatalf("persisted usage = %#v, want one $1 call", usage)
	}
}

// imgKey returns the KeyConfig for id (helper for tests that need a value, not
// a pointer, for UsageSummaryFor).
func imgKey(s *Store, id string) KeyConfig {
	k := s.findByID(id)
	if k == nil {
		panic("key not found: " + id)
	}
	return *k
}

func TestResetUsagePersistsOneDerivedKeyAndPreservesLimitsAndRPM(t *testing.T) {
	now := time.Date(2026, 9, 16, 18, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "state.json")
	hashA, _ := HashKey("cpa_reset_a")
	hashB, _ := HashKey("cpa_reset_b")
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	if err := store.Configure(Config{Enabled: true, StateFile: path, Keys: []KeyConfig{
		{ID: "a", Name: "A", Enabled: true, KeyHash: hashA, RPM: 10, DailyLimitUSD: 3, WeeklyLimitUSD: 9,
			Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "m", BillingMode: "per_call", PerCallUSD: 1}}},
		{ID: "b", Name: "B", Enabled: true, KeyHash: hashB,
			Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "m", BillingMode: "per_call", PerCallUSD: 2}}},
	}}); err != nil {
		t.Fatal(err)
	}
	store.RecordUsage("a", "fast", "m", false, UsageDetail{})
	store.RecordUsage("b", "fast", "m", false, UsageDetail{})
	beforeB := store.UsageSummaryFor(imgKey(store, "b"))
	hdr := http.Header{"Authorization": {"Bearer cpa_reset_a"}}
	if decision := store.Authenticate("POST", "/v1/chat/completions", hdr, nil, []byte(`{"model":"fast"}`)); !decision.Allowed {
		t.Fatalf("authenticate = %+v", decision)
	}
	rpmBefore := store.limiter.Snapshot()["a"]

	result, err := store.ResetUsage("a")
	if err != nil {
		t.Fatal(err)
	}
	if !result.ResetAt.Equal(now) || result.Usage.DailyUSD != 0 || result.Usage.WeeklyUSD != 0 {
		t.Fatalf("reset result = %+v", result)
	}
	if !result.Usage.WeeklyHistoryComplete || result.Usage.LastUsageResetAt == nil || !result.Usage.LastUsageResetAt.Equal(now) {
		t.Fatalf("reset metadata = %+v", result.Usage)
	}
	if got := store.limiter.Snapshot()["a"]; got != rpmBefore {
		t.Fatalf("RPM changed from %d to %d", rpmBefore, got)
	}
	keyA := imgKey(store, "a")
	if keyA.DailyLimitUSD != 3 || keyA.WeeklyLimitUSD != 9 {
		t.Fatalf("limits changed: %+v", keyA)
	}
	if got := store.UsageSummaryFor(imgKey(store, "b")); !nearly(got.DailyUSD, beforeB.DailyUSD) || !nearly(got.WeeklyUSD, beforeB.WeeklyUSD) {
		t.Fatalf("other key changed: %+v", got)
	}

	// Successful reset is durable without waiting for the background flusher.
	restarted := NewStore()
	restarted.SetClock(func() time.Time { return now })
	if err := restarted.Configure(Config{Enabled: true, StateFile: path}); err != nil {
		t.Fatal(err)
	}
	got := restarted.UsageSummaryFor(imgKey(restarted, "a"))
	if got.DailyUSD != 0 || got.WeeklyUSD != 0 || got.LastUsageResetAt == nil || !got.LastUsageResetAt.Equal(now) {
		t.Fatalf("restarted reset usage = %+v", got)
	}

	// A request that settles after the reset is billed into the new ledger.
	restarted.RecordUsage("a", "fast", "m", false, UsageDetail{})
	got = restarted.UsageSummaryFor(imgKey(restarted, "a"))
	if !nearly(got.DailyUSD, 1) || !nearly(got.WeeklyUSD, 1) {
		t.Fatalf("post-reset settlement = %+v", got)
	}
}

func TestResetUsageRejectsNativeKeyAndAllowsDisabledDerivedKey(t *testing.T) {
	now := time.Date(2026, 9, 16, 18, 0, 0, 0, time.UTC)
	hashNative, _ := HashKey("native")
	hashDisabled, _ := HashKey("derived")
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	if err := store.Configure(Config{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state.json"), Keys: []KeyConfig{
		{ID: "native", Enabled: true, Native: true, KeyHash: hashNative, CallerScope: CallerScopeForKey("native"), AccountBinding: &AccountBinding{Allow: []string{"codex-*.json"}}},
		{ID: "disabled", Enabled: false, KeyHash: hashDisabled},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResetUsage("native"); !errors.Is(err, ErrNativeKeyUsageReset) {
		t.Fatalf("native reset error = %v", err)
	}
	if _, err := store.ResetUsage("disabled"); err != nil {
		t.Fatalf("disabled derived reset: %v", err)
	}
	if imgKey(store, "disabled").Enabled {
		t.Fatal("reset must not enable a disabled key")
	}
}

func TestResetUsagePersistenceFailureLeavesLiveUsage(t *testing.T) {
	now := time.Date(2026, 9, 16, 18, 0, 0, 0, time.UTC)
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	if err := store.Configure(Config{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state.json"), Keys: []KeyConfig{{
		ID: "a", Enabled: true, KeyHash: hashForUsageTest(t, "cpa_reset_fail"),
		Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "m", BillingMode: "per_call", PerCallUSD: 1}},
	}}}); err != nil {
		t.Fatal(err)
	}
	store.RecordUsage("a", "fast", "m", false, UsageDetail{})
	store.mu.Lock()
	store.statePath = "/proc/1/mem"
	store.mu.Unlock()
	if _, err := store.ResetUsage("a"); err == nil {
		t.Fatal("reset should fail when state cannot be atomically replaced")
	}
	got := store.UsageSummaryFor(imgKey(store, "a"))
	if !nearly(got.DailyUSD, 1) || !nearly(got.WeeklyUSD, 1) || got.LastUsageResetAt != nil {
		t.Fatalf("failed reset mutated live usage: %+v", got)
	}
}

func TestConfigureStopsWhenFinalUsageFlushFails(t *testing.T) {
	now := time.Date(2026, 9, 16, 18, 0, 0, 0, time.UTC)
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	if err := store.Configure(Config{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state.json"), Keys: []KeyConfig{{
		ID: "old", Enabled: true, KeyHash: hashForUsageTest(t, "cpa_old"),
		Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "m", BillingMode: "per_call", PerCallUSD: 1}},
	}}}); err != nil {
		t.Fatal(err)
	}
	store.RecordUsage("old", "fast", "m", false, UsageDetail{})
	store.mu.Lock()
	store.statePath = "/proc/1/mem"
	store.mu.Unlock()
	err := store.Configure(Config{Enabled: true, StateFile: filepath.Join(t.TempDir(), "new-state.json")})
	if err == nil {
		t.Fatal("configure should not load a new state after the old usage flush fails")
	}
	if key := store.FindByID("old"); key == nil {
		t.Fatal("failed configure replaced the live key set")
	}
	if got := store.UsageSummaryFor(imgKey(store, "old")); !nearly(got.DailyUSD, 1) {
		t.Fatalf("failed configure lost live usage: %+v", got)
	}
}

func TestBlockedFlushCannotResurrectUsageAfterReset(t *testing.T) {
	now := time.Date(2026, 9, 16, 18, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "state.json")
	store := NewStore()
	store.SetClock(func() time.Time { return now })
	if err := store.Configure(Config{Enabled: true, StateFile: path, Keys: []KeyConfig{{
		ID: "a", Enabled: true, KeyHash: hashForUsageTest(t, "cpa_stale_flush"),
		Models: []ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "m", BillingMode: "per_call", PerCallUSD: 1}},
	}}}); err != nil {
		t.Fatal(err)
	}
	store.RecordUsage("a", "fast", "m", false, UsageDetail{})

	// Hold disk serialization so FlushUsage blocks after taking its read gate.
	// ResetUsage needs the write gate, therefore it cannot persist zero first
	// and then be overwritten by an already-captured stale flush snapshot.
	store.persistMu.Lock()
	flushDone := make(chan error, 1)
	go func() { flushDone <- store.FlushUsage() }()
	deadline := time.Now().Add(time.Second)
	for {
		if store.usageGate.TryLock() {
			store.usageGate.Unlock()
			if time.Now().After(deadline) {
				store.persistMu.Unlock()
				t.Fatal("flush did not acquire the usage read gate")
			}
			runtime.Gosched()
			continue
		}
		break
	}
	resetDone := make(chan error, 1)
	go func() {
		_, err := store.ResetUsage("a")
		resetDone <- err
	}()
	store.persistMu.Unlock()
	if err := <-flushDone; err != nil {
		t.Fatal(err)
	}
	if err := <-resetDone; err != nil {
		t.Fatal(err)
	}

	restarted := NewStore()
	restarted.SetClock(func() time.Time { return now })
	if err := restarted.Configure(Config{Enabled: true, StateFile: path}); err != nil {
		t.Fatal(err)
	}
	got := restarted.UsageSummaryFor(imgKey(restarted, "a"))
	if got.DailyUSD != 0 || got.WeeklyUSD != 0 || got.LastUsageResetAt == nil {
		t.Fatalf("stale flush resurrected reset usage: %+v", got)
	}
}

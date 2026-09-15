package plugin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"cpa-key-policy/internal/policy"
)

func lookupRequestWithCallbackForTest(t *testing.T, app *App, secret, callbackID string) ManagementResponse {
	t.Helper()
	rawRequest, _ := json.Marshal(ManagementRequest{
		Method:         http.MethodGet,
		Path:           "/v0/resource/plugins/cpa-key-policy/lookup/data",
		Headers:        http.Header{"Authorization": {"Bearer " + secret}},
		HostCallbackID: callbackID,
	})
	rawResponse, err := app.HandleMethod(MethodManagementHandle, rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	return managementResponseFromEnvelope(t, rawResponse)
}

func quotaRefreshRequestForTest(t *testing.T, app *App, secret, ref, callbackID string) ManagementResponse {
	t.Helper()
	rawRequest, _ := json.Marshal(ManagementRequest{
		Method: http.MethodGet,
		Path:   "/v0/resource/plugins/cpa-key-policy/lookup/quota-refresh",
		Headers: http.Header{
			"Authorization":              {"Bearer " + secret},
			"X-Key-Policy-Quota-Refresh": {"1"},
			"X-Key-Policy-Auth-Ref":      {ref},
		},
		HostCallbackID: callbackID,
	})
	rawResponse, err := app.HandleMethod(MethodManagementHandle, rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	return managementResponseFromEnvelope(t, rawResponse)
}

func prepareLookupQuotaApp(t *testing.T, allowRefresh bool, clock *time.Time, host HostClient) (*App, string) {
	t.Helper()
	app, secret := configureBoundApp(t, policy.BindingStrategyRoundRobin, false)
	key := app.store.FindByID("bound-key")
	key.AllowQuotaRefresh = allowRefresh
	if err := app.store.UpsertKey(*key, false); err != nil {
		t.Fatal(err)
	}
	app.quota.now = func() time.Time { return *clock }
	app.quota.cache.now = func() time.Time { return *clock }
	app.quota.mu.Lock()
	app.quota.host = host
	app.quota.mu.Unlock()
	app.quota.syncRosterOnly()
	if err := app.quota.persist(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	return app, secret
}

func lookupQuotaPayloadForTest(t *testing.T, response ManagementResponse) lookupResponse {
	t.Helper()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("lookup status=%d body=%s", response.StatusCode, response.Body)
	}
	var payload lookupResponse
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.AuthQuotas == nil {
		t.Fatalf("lookup omitted auth_quotas: %s", response.Body)
	}
	return payload
}

func TestLookupQuotaUsesRosterBindingAndStaticRouteIntersection(t *testing.T) {
	clock := time.Date(2030, 9, 15, 10, 0, 0, 0, time.UTC)
	teamID := "codex-alice@example.com-team.json"
	freeID := "codex-bob@example.com-free.json"
	outOfBindingID := "other-carol@example.com-team.json"
	host := &fakeQuotaHost{
		entries: []HostAuthEntry{
			{ID: teamID, AuthIndex: "idx-team", Provider: "codex", Status: "active"},
			{ID: freeID, AuthIndex: "idx-free", Provider: "codex", Status: "active"},
			{ID: outOfBindingID, AuthIndex: "idx-other", Provider: "codex", Status: "active"},
		},
		runtime: map[string]HostAuthEntry{
			"idx-team":  {ID: teamID, AuthIndex: "idx-team", Provider: "codex", Status: "active"},
			"idx-free":  {ID: freeID, AuthIndex: "idx-free", Provider: "codex", Status: "active"},
			"idx-other": {ID: outOfBindingID, AuthIndex: "idx-other", Provider: "codex", Status: "active"},
		},
		documents: map[string]HostAuthDocument{
			"idx-team":  {AuthIndex: "idx-team", JSON: quotaCredentialJSON(clock, "team", "acct-team", "access-team", "refresh-team")},
			"idx-free":  {AuthIndex: "idx-free", JSON: quotaCredentialJSON(clock, "free", "acct-free", "access-free", "refresh-free")},
			"idx-other": {AuthIndex: "idx-other", JSON: quotaCredentialJSON(clock, "team", "acct-other", "access-other", "refresh-other")},
		},
	}
	app, secret := prepareLookupQuotaApp(t, true, &clock, host)
	key := app.store.FindByID("bound-key")
	key.AccountBinding = &policy.AccountBinding{Allow: []string{"codex-*"}, Strategy: policy.BindingStrategyRoundRobin}
	if err := app.store.UpsertKey(*key, false); err != nil {
		t.Fatal(err)
	}
	app.quota.syncRosterOnly()
	app.quota.mu.Lock()
	fingerprint := app.quota.runtime.Auths[teamID].CredentialFingerprint
	app.quota.mu.Unlock()
	observation, err := parseCodexQuotaPayload(quotaBody(clock, 25), clock)
	if err != nil {
		t.Fatal(err)
	}
	observation.CredentialFingerprint = fingerprint
	app.quota.cache.observe(teamID, "idx-team", "passive-http", observation)

	first := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, "callback-1"))
	if first.AuthQuotas.Status != "ready" || len(first.AuthQuotas.Accounts) != 1 {
		t.Fatalf("auth quotas=%#v", first.AuthQuotas)
	}
	account := first.AuthQuotas.Accounts[0]
	if account.Tier != "team" || account.Provider != "codex" || account.Ref == "" || account.Label == "" || account.Short == nil || account.Long == nil {
		t.Fatalf("account=%#v", account)
	}
	if account.Short.UsedPercent == nil || *account.Short.UsedPercent != 10 || account.Long.UsedPercent == nil || *account.Long.UsedPercent != 25 {
		t.Fatalf("quota windows=%#v %#v", account.Short, account.Long)
	}
	body := string(lookupRequestWithCallbackForTest(t, app, secret, "callback-2").Body)
	for _, forbidden := range []string{teamID, freeID, outOfBindingID, "alice@example.com", "idx-team", "acct-team", fingerprint, "credential_fingerprint", "auth_id", "auth_index", "plan_type"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("lookup leaked %q: %s", forbidden, body)
		}
	}
	second := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, "callback-3"))
	if second.AuthQuotas.Accounts[0].Ref != account.Ref {
		t.Fatal("anonymous auth reference changed between reads")
	}

	otherSecret := "cpa_other_lookup"
	if err := app.store.UpsertKey(policy.KeyConfig{
		ID:             "other-key",
		Name:           "Other",
		Enabled:        true,
		KeyHash:        hashForTest(t, otherSecret),
		AccountBinding: &policy.AccountBinding{Allow: []string{"codex-*"}, Strategy: policy.BindingStrategyRoundRobin},
		Models:         []policy.ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex", Group: "team"}},
	}, false); err != nil {
		t.Fatal(err)
	}
	other := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, otherSecret, "callback-4"))
	if len(other.AuthQuotas.Accounts) != 1 || other.AuthQuotas.Accounts[0].Ref == account.Ref {
		t.Fatalf("cross-key anonymous refs were linkable: %#v", other.AuthQuotas.Accounts)
	}
}

func TestLookupQuotaDeduplicatesOneUpstreamAccountAcrossAuthFiles(t *testing.T) {
	clock := time.Date(2030, 9, 15, 10, 15, 0, 0, time.UTC)
	activeID := "account-a-active-team"
	disabledID := "account-a-disabled-team"
	active := HostAuthEntry{ID: activeID, AuthIndex: "idx-active", Provider: "codex", Status: "active"}
	disabled := HostAuthEntry{ID: disabledID, AuthIndex: "idx-disabled", Provider: "codex", Status: "disabled", Disabled: true}
	host := &fakeQuotaHost{
		entries: []HostAuthEntry{disabled, active},
		runtime: map[string]HostAuthEntry{
			"idx-active":   active,
			"idx-disabled": disabled,
		},
		documents: map[string]HostAuthDocument{
			"idx-active":   {AuthIndex: "idx-active", JSON: quotaCredentialJSON(clock, "team", "acct-shared", "access-active", "refresh-active")},
			"idx-disabled": {AuthIndex: "idx-disabled", JSON: quotaCredentialJSON(clock, "team", "acct-shared", "access-disabled", "refresh-disabled")},
		},
	}
	app, secret := prepareLookupQuotaApp(t, true, &clock, host)
	payload := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, "callback"))
	if len(payload.AuthQuotas.Accounts) != 1 {
		t.Fatalf("shared upstream account rendered %d cards: %#v", len(payload.AuthQuotas.Accounts), payload.AuthQuotas.Accounts)
	}
	account := payload.AuthQuotas.Accounts[0]
	if account.Status != "active" || !account.CanRefresh {
		t.Fatalf("eligible duplicate was not preferred: %#v", account)
	}
	view := app.quota.lookupQuotaView(*app.store.FindByID("bound-key"), true)
	target := view.targets[account.Ref]
	if target.authID != activeID || target.operationID != quotaOperationIdentity(target.fingerprint, activeID) {
		t.Fatalf("deduplicated target=%#v", target)
	}
	host.mu.Lock()
	host.entries[0], host.entries[1] = host.entries[1], host.entries[0]
	host.mu.Unlock()
	app.quota.syncRosterOnly()
	reordered := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, "callback"))
	if len(reordered.AuthQuotas.Accounts) != 1 || reordered.AuthQuotas.Accounts[0].Ref != account.Ref {
		t.Fatalf("roster order changed deduplicated account: %#v", reordered.AuthQuotas.Accounts)
	}
	app.quota.mu.Lock()
	fingerprint := app.quota.runtime.Auths[activeID].CredentialFingerprint
	app.quota.mu.Unlock()
	backoff := clock.Add(20 * time.Minute)
	app.quota.setQuotaBackoff(activeID, fingerprint, backoff)
	app.quota.mu.Lock()
	activeBackoff := app.quota.runtime.Auths[activeID].QuotaBackoffUntil
	disabledBackoff := app.quota.runtime.Auths[disabledID].QuotaBackoffUntil
	app.quota.mu.Unlock()
	if !activeBackoff.Equal(backoff) || !disabledBackoff.Equal(backoff) {
		t.Fatalf("shared-account backoff active=%s disabled=%s", activeBackoff, disabledBackoff)
	}
}

func TestLookupQuotaStaticRoutesFailClosedOnAmbiguousTarget(t *testing.T) {
	key := policy.KeyConfig{
		Enabled: true,
		Models: []policy.ModelRule{
			{Alias: "fast", Provider: "codex", TargetModel: "same", Group: "team"},
			{Alias: "fast", Provider: "codex", TargetModel: "same", Group: "plus"},
			{Alias: "other", Provider: "codex", TargetModel: "distinct", Group: "free"},
			{Alias: "ag", Provider: "antigravity", TargetModel: "gemini"},
		},
	}
	routes := lookupQuotaRoutesForKey(key)
	if !routes.hasCodex || routes.allowAnyGroup {
		t.Fatalf("routes=%#v", routes)
	}
	if _, ok := routes.groups["team"]; ok {
		t.Fatal("ambiguous team/plus target granted a static route")
	}
	if _, ok := routes.groups["plus"]; ok {
		t.Fatal("ambiguous team/plus target granted a static route")
	}
	if _, ok := routes.groups["free"]; !ok {
		t.Fatal("independent unambiguous route was not retained")
	}
	if len(routes.unsupported) != 1 || routes.unsupported[0] != "antigravity" {
		t.Fatalf("unsupported providers=%v", routes.unsupported)
	}
}

func TestLookupQuotaHidesStaleRosterAndPersistsAnonymousSecret(t *testing.T) {
	clock := time.Date(2030, 9, 15, 10, 30, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	app, secret := prepareLookupQuotaApp(t, false, &clock, host)
	fresh := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, "callback"))
	if len(fresh.AuthQuotas.Accounts) != 1 {
		t.Fatalf("fresh accounts=%#v", fresh.AuthQuotas.Accounts)
	}
	ref := fresh.AuthQuotas.Accounts[0].Ref
	path := quotaRuntimePath(app.store.StatePath())
	doc, err := newQuotaRuntimeStore(path).load()
	if err != nil {
		t.Fatal(err)
	}
	secretBytes, ok := decodeQuotaAuthRefSecret(doc.AuthRefSecret)
	if !ok {
		t.Fatal("persisted runtime omitted a valid auth reference secret")
	}
	runtime := doc.Auths["account-a-team"]
	key := app.store.FindByID("bound-key")
	if quotaAuthRef(secretBytes, *key, runtime) != ref {
		t.Fatal("persisted secret did not reproduce the anonymous reference")
	}

	clock = clock.Add(61 * time.Minute)
	stale := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, "callback"))
	if stale.AuthQuotas.Status != "roster_unavailable" || len(stale.AuthQuotas.Accounts) != 0 {
		t.Fatalf("stale roster remained visible=%#v", stale.AuthQuotas)
	}
	quotaBody, err := json.Marshal(stale.AuthQuotas)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(quotaBody), "0001-") {
		t.Fatalf("public quota lookup rendered a zero-value year: %s", quotaBody)
	}
	if stale.AuthQuotas.UnsupportedProviders == nil {
		t.Fatal("unsupported_providers serialized as null")
	}
}

func TestQuotaRuntimeLoadRequiresCurrentProcessRosterSync(t *testing.T) {
	clock := time.Date(2030, 9, 15, 10, 35, 0, 0, time.UTC)
	path := t.TempDir() + "/quota-runtime.json"
	doc := quotaRuntimeDocument{
		Version:        quotaRuntimeVersion,
		LastRosterSync: clock,
		Observations:   make(map[string]quotaObservation),
		Auths: map[string]quotaAuthRuntime{
			"account-a-team": {
				AuthID:                "account-a-team",
				AuthIndex:             "idx-a",
				Provider:              "codex",
				CredentialFingerprint: "fingerprint-a",
				RosterConfirmed:       true,
				LastRosterSeenAt:      clock,
			},
		},
	}
	if _, err := ensureQuotaAuthRefSecret(&doc); err != nil {
		t.Fatal(err)
	}
	if err := newQuotaRuntimeStore(path).save(doc); err != nil {
		t.Fatal(err)
	}
	manager := newQuotaManager(nil, nil, func() time.Time { return clock })
	manager.loadRuntime(path)
	manager.mu.Lock()
	loadedSync := manager.runtime.LastRosterSync
	_, retained := manager.runtime.Auths["account-a-team"]
	manager.mu.Unlock()
	if !loadedSync.IsZero() || !retained {
		t.Fatalf("loaded roster trusted=%s retained=%v", loadedSync, retained)
	}
}

type failingListQuotaHost struct {
	HostClient
}

func (f failingListQuotaHost) ListAuths() ([]HostAuthEntry, error) {
	return nil, errors.New("roster unavailable")
}

func TestLookupQuotaHidesRosterImmediatelyAfterSyncFailure(t *testing.T) {
	clock := time.Date(2030, 9, 15, 10, 40, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	app, secret := prepareLookupQuotaApp(t, false, &clock, host)
	if payload := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, "callback")); payload.AuthQuotas.Status != "ready" {
		t.Fatalf("initial roster status=%q", payload.AuthQuotas.Status)
	}
	app.quota.mu.Lock()
	app.quota.host = failingListQuotaHost{HostClient: host}
	app.quota.mu.Unlock()
	app.quota.syncRosterOnly()
	payload := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, "callback"))
	if payload.AuthQuotas.Status != "roster_unavailable" || len(payload.AuthQuotas.Accounts) != 0 {
		t.Fatalf("failed roster sync remained visible=%#v", payload.AuthQuotas)
	}
}

func TestLookupQuotaDoesNotProjectEvidenceFromAnotherAccountInstance(t *testing.T) {
	clock := time.Date(2030, 9, 15, 10, 42, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	app, secret := prepareLookupQuotaApp(t, false, &clock, host)
	observation, err := parseCodexQuotaPayload(quotaBody(clock, 27), clock)
	if err != nil {
		t.Fatal(err)
	}
	observation.CredentialFingerprint = "replaced-account-instance"
	app.quota.cache.observe("account-a-team", "idx-a", "passive-http", observation)
	payload := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, "callback"))
	if len(payload.AuthQuotas.Accounts) != 1 {
		t.Fatalf("accounts=%#v", payload.AuthQuotas.Accounts)
	}
	account := payload.AuthQuotas.Accounts[0]
	if account.Short != nil || account.Long != nil || account.ObservedAt != "" || account.Availability != "unknown" || account.Freshness != "unknown" {
		t.Fatalf("stale account-instance evidence leaked=%#v", account)
	}
}

func TestLookupQuotaKeepsConfirmedDisabledAccountButDisablesRefresh(t *testing.T) {
	clock := time.Date(2030, 9, 15, 10, 45, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	host.entries[0].Disabled = true
	host.entries[0].Status = "disabled"
	host.runtime["idx-a"] = host.entries[0]
	app, secret := prepareLookupQuotaApp(t, true, &clock, host)
	payload := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, "callback"))
	if len(payload.AuthQuotas.Accounts) != 1 {
		t.Fatalf("disabled account not visible=%#v", payload.AuthQuotas)
	}
	account := payload.AuthQuotas.Accounts[0]
	if account.Status != "disabled" || account.CanRefresh || account.RefreshStatus != "unavailable" || account.ObservedAt != "" {
		t.Fatalf("disabled account=%#v", account)
	}
}

func TestLookupManualQuotaRefreshUpdatesSharedCacheWithoutActivation(t *testing.T) {
	clock := time.Date(2030, 9, 15, 11, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	host.getResponses = []HostHTTPResponse{{StatusCode: http.StatusOK, Body: quotaBody(clock, 30)}}
	app, secret := prepareLookupQuotaApp(t, true, &clock, host)
	key := app.store.FindByID("bound-key")
	key.AccountBinding.Strategy = policy.BindingStrategyQuotaFillFirst
	if err := app.store.UpsertKey(*key, false); err != nil {
		t.Fatal(err)
	}
	app.quota.syncRosterOnly()
	app.quota.mu.Lock()
	runtime := app.quota.runtime.Auths["account-a-team"]
	runtime.Activation = quotaActivationState{Status: "verify_pending", CycleID: "existing", Attempts: 3, LastResult: "http_200"}
	app.quota.runtime.Auths["account-a-team"] = runtime
	app.quota.mu.Unlock()
	payload := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, "lookup-callback"))
	ref := payload.AuthQuotas.Accounts[0].Ref

	response := quotaRefreshRequestForTest(t, app, secret, ref, "refresh-callback")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", response.StatusCode, response.Body)
	}
	_, gets, posts := host.counts()
	if gets != 1 || posts != 0 {
		t.Fatalf("manual refresh made GET=%d POST=%d", gets, posts)
	}
	host.mu.Lock()
	request := host.requests[0]
	host.mu.Unlock()
	if request.Method != http.MethodGet || request.URL != codexQuotaEndpoint || request.HostCallbackID != "refresh-callback" {
		t.Fatalf("host request=%#v", request)
	}
	observation, ok := app.quota.cache.get("account-a-team")
	if !ok || observation.Source != "lookup-manual" || observation.Long == nil || observation.Long.UsedPercent == nil || *observation.Long.UsedPercent != 30 {
		t.Fatalf("manual observation=%#v", observation)
	}
	app.quota.mu.Lock()
	after := app.quota.runtime.Auths["account-a-team"].Activation
	app.quota.mu.Unlock()
	if after.Status != "verify_pending" || after.CycleID != "existing" || after.Attempts != 3 || after.LastResult != "http_200" {
		t.Fatalf("manual refresh changed activation=%#v", after)
	}
	if !app.quota.needsReview("account-a-team", 30*time.Minute, clock) {
		t.Fatal("manual evidence incorrectly satisfied a pending background review")
	}
	second := quotaRefreshRequestForTest(t, app, secret, ref, "refresh-callback-2")
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second refresh=%d %s", second.StatusCode, second.Body)
	}
	_, gets, _ = host.counts()
	if gets != 1 {
		t.Fatalf("cooldown sent another GET: %d", gets)
	}
}

func TestLookupManualQuotaRefreshPermissionAndOpaqueReferenceFailClosed(t *testing.T) {
	clock := time.Date(2030, 9, 15, 12, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	app, secret := prepareLookupQuotaApp(t, false, &clock, host)
	payload := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, "callback"))
	if payload.AuthQuotas.Accounts[0].CanRefresh || payload.AuthQuotas.Accounts[0].RefreshStatus != "permission_disabled" {
		t.Fatalf("disabled permission account=%#v", payload.AuthQuotas.Accounts[0])
	}
	response := quotaRefreshRequestForTest(t, app, secret, payload.AuthQuotas.Accounts[0].Ref, "callback")
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("permission response=%d %s", response.StatusCode, response.Body)
	}
	key := app.store.FindByID("bound-key")
	key.AllowQuotaRefresh = true
	if err := app.store.UpsertKey(*key, false); err != nil {
		t.Fatal(err)
	}
	response = quotaRefreshRequestForTest(t, app, secret, "not-a-real-ref", "callback")
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("opaque ref response=%d %s", response.StatusCode, response.Body)
	}
	_, gets, posts := host.counts()
	if gets != 0 || posts != 0 {
		t.Fatalf("unauthorized refresh caused upstream work: GET=%d POST=%d", gets, posts)
	}
	withoutCallback := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, ""))
	if withoutCallback.AuthQuotas.Accounts[0].CanRefresh || withoutCallback.AuthQuotas.Accounts[0].RefreshStatus != "transport_unavailable" {
		t.Fatalf("missing callback transport account=%#v", withoutCallback.AuthQuotas.Accounts[0])
	}
}

func TestLookupManualQuotaGET429RetainsEvidenceAndDoesNotMarkExhausted(t *testing.T) {
	clock := time.Date(2030, 9, 15, 13, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	host.getResponses = []HostHTTPResponse{{StatusCode: http.StatusTooManyRequests, Headers: http.Header{"Retry-After": {"3600"}}}}
	app, secret := prepareLookupQuotaApp(t, true, &clock, host)
	app.quota.mu.Lock()
	runtime := app.quota.runtime.Auths["account-a-team"]
	fingerprint := runtime.CredentialFingerprint
	runtime.Activation = quotaActivationState{Status: "watching", CycleID: "keep-me", Attempts: 2}
	app.quota.runtime.Auths["account-a-team"] = runtime
	app.quota.mu.Unlock()
	old, err := parseCodexQuotaPayload(quotaBody(clock, 40), clock)
	if err != nil {
		t.Fatal(err)
	}
	old.CredentialFingerprint = fingerprint
	app.quota.cache.observe("account-a-team", "idx-a", "passive-http", old)
	payload := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, "lookup"))
	response := quotaRefreshRequestForTest(t, app, secret, payload.AuthQuotas.Accounts[0].Ref, "refresh")
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("429 response=%d %s", response.StatusCode, response.Body)
	}
	after, ok := app.quota.cache.get("account-a-team")
	if !ok || after.ExplicitExhausted || after.Long == nil || after.Long.UsedPercent == nil || *after.Long.UsedPercent != 40 {
		t.Fatalf("429 corrupted cache=%#v", after)
	}
	app.quota.mu.Lock()
	runtime = app.quota.runtime.Auths["account-a-team"]
	app.quota.mu.Unlock()
	if !runtime.QuotaBackoffUntil.Equal(clock.Add(time.Hour)) {
		t.Fatalf("backoff=%s", runtime.QuotaBackoffUntil)
	}
	if runtime.Activation.CycleID != "keep-me" || runtime.Activation.Attempts != 2 {
		t.Fatalf("429 changed activation=%#v", runtime.Activation)
	}
}

type blockingLookupQuotaHost struct {
	*fakeQuotaHost
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (h *blockingLookupQuotaHost) Do(request HostHTTPRequest) (HostHTTPResponse, error) {
	h.once.Do(func() { close(h.started) })
	<-h.release
	return h.fakeQuotaHost.Do(request)
}

func TestLookupManualQuotaTimeoutKeepsOperationSlotUntilHostReturns(t *testing.T) {
	clock := time.Date(2030, 9, 15, 14, 0, 0, 0, time.UTC)
	base := newFakeQuotaHost(clock)
	base.getResponses = []HostHTTPResponse{{StatusCode: http.StatusOK, Body: quotaBody(clock, 20)}}
	host := &blockingLookupQuotaHost{fakeQuotaHost: base, started: make(chan struct{}), release: make(chan struct{})}
	app, secret := prepareLookupQuotaApp(t, true, &clock, host)
	app.quota.manualTimeout = 15 * time.Millisecond
	payload := lookupQuotaPayloadForTest(t, lookupRequestWithCallbackForTest(t, app, secret, "lookup"))
	ref := payload.AuthQuotas.Accounts[0].Ref
	operationID := app.quota.lookupQuotaView(*app.store.FindByID("bound-key"), true).targets[ref].operationID
	response := quotaRefreshRequestForTest(t, app, secret, ref, "slow")
	if response.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("timeout response=%d %s", response.StatusCode, response.Body)
	}
	<-host.started
	app.quota.operations.mu.Lock()
	active := app.quota.operations.activeAuth[operationID]
	getActive := app.quota.operations.getActive
	app.quota.operations.mu.Unlock()
	if active != "manual" || !getActive {
		t.Fatalf("in-flight slot was released early: active=%q get_active=%v", active, getActive)
	}
	close(host.release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		app.quota.operations.mu.Lock()
		active = app.quota.operations.activeAuth[operationID]
		getActive = app.quota.operations.getActive
		app.quota.operations.mu.Unlock()
		if active == "" && !getActive {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("manual quota operation slot did not release after host returned")
}

func TestLookupRosterOnlyScheduleNeverSendsQuotaGET(t *testing.T) {
	clock := time.Date(2030, 9, 15, 15, 0, 0, 0, time.UTC)
	host := newFakeQuotaHost(clock)
	app, _ := prepareLookupQuotaApp(t, false, &clock, host)
	settings := app.store.RuntimeSettings()
	keys := app.store.Keys()
	if quotaFeatureNeeded(settings, keys) || !quotaScheduleNeeded(settings, keys) {
		t.Fatalf("feature=%v schedule=%v", quotaFeatureNeeded(settings, keys), quotaScheduleNeeded(settings, keys))
	}
	beforeList, beforeGET, beforePOST := host.counts()
	app.quota.runScheduledRound()
	afterList, afterGET, afterPOST := host.counts()
	if afterList <= beforeList || afterGET != beforeGET || afterPOST != beforePOST {
		t.Fatalf("roster-only round list %d->%d GET %d->%d POST %d->%d", beforeList, afterList, beforeGET, afterGET, beforePOST, afterPOST)
	}
}

func TestQuotaRefreshKeyPatchDistinguishesOmittedAndFalse(t *testing.T) {
	app := configuredQuotaTestApp(t)
	created := app.createKey([]byte(`{"id":"refresh-key","allow_quota_refresh":true,"models":[{"alias":"fast","provider":"codex","target_model":"gpt-5-codex"}],"account_binding":{"allow":["codex-*"]}}`))
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("create=%d %s", created.StatusCode, created.Body)
	}
	omitted := app.patchKey([]byte(`{"id":"refresh-key","name":"Renamed"}`))
	if omitted.StatusCode != http.StatusOK {
		t.Fatalf("omitted patch=%d %s", omitted.StatusCode, omitted.Body)
	}
	key := app.store.FindByID("refresh-key")
	if key == nil || !key.AllowQuotaRefresh {
		t.Fatalf("omitted patch cleared permission: %#v", key)
	}
	disabled := app.patchKey([]byte(`{"id":"refresh-key","allow_quota_refresh":false}`))
	if disabled.StatusCode != http.StatusOK {
		t.Fatalf("false patch=%d %s", disabled.StatusCode, disabled.Body)
	}
	key = app.store.FindByID("refresh-key")
	if key == nil || key.AllowQuotaRefresh {
		t.Fatalf("explicit false did not clear permission: %#v", key)
	}
	var public struct {
		Key publicKey `json:"key"`
	}
	if err := json.Unmarshal(disabled.Body, &public); err != nil {
		t.Fatal(err)
	}
	if public.Key.AllowQuotaRefresh {
		t.Fatal("management response did not expose explicit false")
	}
}

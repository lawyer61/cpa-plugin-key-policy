package plugin

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"cpa-key-policy/internal/policy"
)

func configureConcurrencyApp(t *testing.T) (*App, map[string]string) {
	t.Helper()
	secrets := map[string]string{"key-a": "cpa_concurrency_a", "key-b": "cpa_concurrency_b"}
	app := NewApp()
	configYAML := []byte(`
enabled: true
state_file: "` + filepath.ToSlash(filepath.Join(t.TempDir(), "state.json")) + `"
auth_concurrency_limits:
  auth-a.json: 1
  auth-b.json: 1
keys:
  - id: key-a
    name: Key A
    enabled: true
    key_hash: "` + hashForTest(t, secrets["key-a"]) + `"
    max_concurrent_requests: 1
    session_affinity: true
    account_binding:
      allow: ["auth-*.json"]
      strategy: round-robin
    models:
      - alias: fast
        provider: codex
        target_model: gpt-5-codex
  - id: key-b
    name: Key B
    enabled: true
    key_hash: "` + hashForTest(t, secrets["key-b"]) + `"
    session_affinity: true
    account_binding:
      allow: ["auth-*.json"]
      strategy: round-robin
    models:
      - alias: fast
        provider: codex
        target_model: gpt-5-codex
`)
	request, _ := json.Marshal(LifecycleRequest{ConfigYAML: configYAML})
	if _, err := app.HandleMethod(MethodPluginReconfigure, request); err != nil {
		t.Fatalf("configure concurrency app: %v", err)
	}
	return app, secrets
}

func controlledInterceptRequest(requestID, keyID, secret string) RequestInterceptRequest {
	return RequestInterceptRequest{
		RequestID:      requestID,
		Model:          "gpt-5-codex",
		RequestedModel: "fast",
		Headers:        http.Header{"Authorization": {"Bearer " + secret}},
		Metadata: map[string]any{
			"caller_scope":         policy.CallerScopeForKey(keyID),
			"canonical_session_id": "session-1",
			"request_path":         "/v1/chat/completions",
		},
	}
}

func interceptForMethod(t *testing.T, app *App, method string, request RequestInterceptRequest) RequestInterceptResponse {
	t.Helper()
	rawRequest, _ := json.Marshal(request)
	rawResponse, err := app.HandleMethod(method, rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	var response RequestInterceptResponse
	if err := unmarshalOK(rawResponse, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func completeForTest(t *testing.T, app *App, requestID string) {
	t.Helper()
	raw, _ := json.Marshal(RequestCompletion{RequestID: requestID, Outcome: "succeeded"})
	if _, err := app.HandleMethod(MethodRequestComplete, raw); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationEnablesRequestLifecycle(t *testing.T) {
	registration := NewApp().registration()
	if !registration.Capabilities.RequestLifecyclePlugin {
		t.Fatal("request_lifecycle_plugin capability is disabled")
	}
}

func TestKeyConcurrencyRejectsAndCompletionReleases(t *testing.T) {
	app, secrets := configureConcurrencyApp(t)
	first := controlledInterceptRequest("request-1", "key-a", secrets["key-a"])
	if response := interceptForMethod(t, app, MethodRequestInterceptBefore, first); response.Terminate {
		t.Fatalf("first request rejected: %+v %s", response, response.ResponseBody)
	}
	second := controlledInterceptRequest("request-2", "key-a", secrets["key-a"])
	response := interceptForMethod(t, app, MethodRequestInterceptBefore, second)
	if !response.Terminate || response.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(response.ResponseBody), "key_concurrency_exceeded") {
		t.Fatalf("second response = %+v body=%s", response, response.ResponseBody)
	}
	completeForTest(t, app, "request-1")
	if response := interceptForMethod(t, app, MethodRequestInterceptBefore, second); response.Terminate {
		t.Fatalf("request remained blocked after completion: %+v %s", response, response.ResponseBody)
	}
	completeForTest(t, app, "request-2")
}

func TestImportedNativeBindingUsesTheSameConcurrencyLifecycle(t *testing.T) {
	plain := "native-concurrency-secret"
	app := NewApp()
	configYAML := []byte(`
enabled: true
state_file: "` + filepath.ToSlash(filepath.Join(t.TempDir(), "state.json")) + `"
auth_concurrency_limits:
  native-auth.json: 1
keys:
  - id: native-concurrency
    enabled: true
    native: true
    key_hash: "` + hashForTest(t, plain) + `"
    caller_scope: "` + policy.CallerScopeForKey(plain) + `"
    max_concurrent_requests: 1
    session_affinity: true
    account_binding:
      allow: ["native-auth.json"]
      strategy: round-robin
`)
	rawConfig, _ := json.Marshal(LifecycleRequest{ConfigYAML: configYAML})
	if _, err := app.HandleMethod(MethodPluginReconfigure, rawConfig); err != nil {
		t.Fatal(err)
	}
	request := RequestInterceptRequest{
		RequestID:      "native-request-1",
		Model:          "real-model",
		RequestedModel: "real-model",
		Headers:        http.Header{"Authorization": {"Bearer " + plain}},
		Metadata: map[string]any{
			"caller_scope":         policy.CallerScopeForKey(plain),
			"canonical_session_id": "native-session",
			"request_path":         "/v1/chat/completions",
		},
	}
	if response := interceptForMethod(t, app, MethodRequestInterceptBefore, request); response.Terminate {
		t.Fatalf("native before rejected: %+v %s", response, response.ResponseBody)
	}
	second := request
	second.RequestID = "native-request-2"
	if response := interceptForMethod(t, app, MethodRequestInterceptBefore, second); !response.Terminate || response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("native key limit response = %+v body=%s", response, response.ResponseBody)
	}
	request.Metadata["selected_auth_id"] = "native-auth.json"
	if response := interceptForMethod(t, app, MethodRequestInterceptAfter, request); response.Terminate {
		t.Fatalf("native after rejected: %+v %s", response, response.ResponseBody)
	}
	completeForTest(t, app, request.RequestID)
	if response := interceptForMethod(t, app, MethodRequestInterceptBefore, second); response.Terminate {
		t.Fatalf("native key remained blocked after completion: %+v %s", response, response.ResponseBody)
	}
	completeForTest(t, app, second.RequestID)
}

func TestAuthConcurrencyIsGlobalAcrossControlledKeys(t *testing.T) {
	app, secrets := configureConcurrencyApp(t)
	requestA := controlledInterceptRequest("request-a", "key-a", secrets["key-a"])
	requestB := controlledInterceptRequest("request-b", "key-b", secrets["key-b"])
	if response := interceptForMethod(t, app, MethodRequestInterceptBefore, requestA); response.Terminate {
		t.Fatalf("key-a before rejected: %+v", response)
	}
	requestA.Metadata["selected_auth_id"] = "auth-a.json"
	if response := interceptForMethod(t, app, MethodRequestInterceptAfter, requestA); response.Terminate {
		t.Fatalf("key-a after rejected: %+v %s", response, response.ResponseBody)
	}
	// Same execution retrying the same auth is idempotent.
	if response := interceptForMethod(t, app, MethodRequestInterceptAfter, requestA); response.Terminate {
		t.Fatalf("same-auth retry rejected: %+v %s", response, response.ResponseBody)
	}
	if response := interceptForMethod(t, app, MethodRequestInterceptBefore, requestB); response.Terminate {
		t.Fatalf("key-b before rejected: %+v", response)
	}
	requestB.Metadata["selected_auth_id"] = "auth-a.json"
	response := interceptForMethod(t, app, MethodRequestInterceptAfter, requestB)
	if !response.Terminate || response.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(response.ResponseBody), "auth_concurrency_exceeded") {
		t.Fatalf("key-b after = %+v body=%s", response, response.ResponseBody)
	}
	completeForTest(t, app, "request-a")
	if response := interceptForMethod(t, app, MethodRequestInterceptAfter, requestB); response.Terminate {
		t.Fatalf("auth remained blocked after completion: %+v %s", response, response.ResponseBody)
	}
	completeForTest(t, app, "request-b")
}

func TestUnmanagedGroupSchedulingDoesNotClaimControlledAuthCapacity(t *testing.T) {
	app, secrets := configureConcurrencyApp(t)
	occupied := controlledInterceptRequest("controlled-occupant", "key-b", secrets["key-b"])
	if response := interceptForMethod(t, app, MethodRequestInterceptBefore, occupied); response.Terminate {
		t.Fatalf("occupant before rejected: %+v", response)
	}
	occupied.Metadata["selected_auth_id"] = "auth-a.json"
	if response := interceptForMethod(t, app, MethodRequestInterceptAfter, occupied); response.Terminate {
		t.Fatalf("occupant after rejected: %+v", response)
	}

	request := SchedulerPickRequest{
		Provider: "codex",
		Model:    "gpt-5-codex",
		Options: SchedulerPickOptions{Metadata: map[string]any{
			"group":           "team",
			"requested_model": "gpt-5-codex",
		}},
		Candidates: []SchedulerAuthCandidate{{
			ID:         "auth-a.json",
			Provider:   "codex",
			Attributes: map[string]string{"plan_type": "team"},
		}},
	}
	if got := schedulerPickForTest(t, app, request).AuthID; got != "auth-a.json" {
		t.Fatalf("unmanaged group pick = %q, want legacy candidate unaffected by controlled-only limit", got)
	}
	completeForTest(t, app, "controlled-occupant")
}

func TestRetryToDifferentAuthHoldsBothUntilCompletion(t *testing.T) {
	app, secrets := configureConcurrencyApp(t)
	request := controlledInterceptRequest("request-retry", "key-b", secrets["key-b"])
	if response := interceptForMethod(t, app, MethodRequestInterceptBefore, request); response.Terminate {
		t.Fatalf("before rejected: %+v", response)
	}
	request.Metadata["selected_auth_id"] = "auth-a.json"
	if response := interceptForMethod(t, app, MethodRequestInterceptAfter, request); response.Terminate {
		t.Fatalf("auth-a rejected: %+v", response)
	}
	request.Metadata["selected_auth_id"] = "auth-b.json"
	if response := interceptForMethod(t, app, MethodRequestInterceptAfter, request); response.Terminate {
		t.Fatalf("auth-b retry rejected: %+v", response)
	}
	if app.concurrency.authCurrent("auth-a.json") != 1 || app.concurrency.authCurrent("auth-b.json") != 1 {
		t.Fatalf("retry slots = %+v", app.concurrency.snapshot().Auths)
	}
	completeForTest(t, app, "request-retry")
	if len(app.concurrency.snapshot().Auths) != 0 {
		t.Fatalf("completion did not release all retry slots: %+v", app.concurrency.snapshot().Auths)
	}
}

func TestAfterAuthFailsClosedWhenBindingNarrowsDuringAdmission(t *testing.T) {
	app, secrets := configureConcurrencyApp(t)
	request := controlledInterceptRequest("request-binding-change", "key-b", secrets["key-b"])
	if response := interceptForMethod(t, app, MethodRequestInterceptBefore, request); response.Terminate {
		t.Fatalf("before rejected: %+v", response)
	}
	key := app.store.FindByID("key-b")
	if key == nil {
		t.Fatal("key-b missing")
	}
	key.AccountBinding = &policy.AccountBinding{
		Allow:    []string{"auth-b.json"},
		Strategy: policy.BindingStrategyRoundRobin,
	}
	if err := app.store.UpsertKey(*key, false); err != nil {
		t.Fatalf("narrow binding: %v", err)
	}
	request.Metadata["selected_auth_id"] = "auth-a.json"
	response := interceptForMethod(t, app, MethodRequestInterceptAfter, request)
	if !response.Terminate || response.StatusCode != http.StatusForbidden || !strings.Contains(string(response.ResponseBody), "auth_not_bound") {
		t.Fatalf("after binding change = %+v body=%s", response, response.ResponseBody)
	}
	if current := app.concurrency.keyCurrent("key-b"); current != 1 {
		t.Fatalf("rejected execution lost its key lease before completion: %d", current)
	}
	completeForTest(t, app, "request-binding-change")
	if current := app.concurrency.keyCurrent("key-b"); current != 0 {
		t.Fatalf("completion did not release key lease: %d", current)
	}
}

func TestConcurrencyRejectedImageRequestIsNotPerCallCharged(t *testing.T) {
	plain := "cpa_image_concurrency"
	app := NewApp()
	configYAML := []byte(`
enabled: true
state_file: "` + filepath.ToSlash(filepath.Join(t.TempDir(), "state.json")) + `"
keys:
  - id: image-key
    enabled: true
    key_hash: "` + hashForTest(t, plain) + `"
    max_concurrent_requests: 1
    account_binding:
      allow: ["image-auth.json"]
    models:
      - alias: image
        provider: xai
        target_model: grok-imagine-image
        billing_mode: per_call
        per_call_usd: 2
`)
	rawConfig, _ := json.Marshal(LifecycleRequest{ConfigYAML: configYAML})
	if _, err := app.HandleMethod(MethodPluginReconfigure, rawConfig); err != nil {
		t.Fatal(err)
	}
	first := controlledInterceptRequest("image-1", "image-key", plain)
	first.RequestedModel = "image"
	first.Model = "grok-imagine-image"
	first.Metadata["request_path"] = "/v1/images/generations"
	if response := interceptForMethod(t, app, MethodRequestInterceptBefore, first); response.Terminate {
		t.Fatalf("first before rejected: %+v", response)
	}
	first.Metadata["selected_auth_id"] = "image-auth.json"
	if response := interceptForMethod(t, app, MethodRequestInterceptAfter, first); response.Terminate {
		t.Fatalf("first after rejected: %+v", response)
	}
	key := app.store.FindByID("image-key")
	if usage := app.store.UsageSummaryFor(*key); usage.DailyUSD != 2 || usage.DailyCallCount != 1 {
		t.Fatalf("first image usage = %+v", usage)
	}
	second := controlledInterceptRequest("image-2", "image-key", plain)
	second.RequestedModel = "image"
	second.Model = "grok-imagine-image"
	second.Metadata["request_path"] = "/v1/images/generations"
	response := interceptForMethod(t, app, MethodRequestInterceptBefore, second)
	if !response.Terminate || response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second before = %+v", response)
	}
	if usage := app.store.UsageSummaryFor(*key); usage.DailyUSD != 2 || usage.DailyCallCount != 1 {
		t.Fatalf("rejected image changed usage = %+v", usage)
	}
	completeForTest(t, app, "image-1")
}

func TestSchedulerAffinityFailsOverWithinAllowedPoolWhenStickyAuthIsFull(t *testing.T) {
	app, secrets := configureConcurrencyApp(t)
	request := SchedulerPickRequest{
		Provider: "codex",
		Model:    "gpt-5-codex",
		Options: SchedulerPickOptions{
			Headers: map[string][]string{"Authorization": {"Bearer " + secrets["key-b"]}},
			Metadata: map[string]any{
				"caller_scope":         policy.CallerScopeForKey("key-b"),
				"requested_model":      "fast",
				"canonical_session_id": "sticky-session",
				"request_path":         "/v1/chat/completions",
			},
		},
		Candidates: []SchedulerAuthCandidate{
			{ID: "auth-a.json", Provider: "codex"},
			{ID: "auth-b.json", Provider: "codex"},
			{ID: "outside.json", Provider: "codex"},
		},
	}
	firstPick := schedulerPickForTest(t, app, request)
	if firstPick.AuthID != "auth-a.json" {
		t.Fatalf("first pick = %q, want auth-a.json", firstPick.AuthID)
	}
	first := controlledInterceptRequest("sticky-1", "key-b", secrets["key-b"])
	first.Metadata["canonical_session_id"] = "sticky-session"
	if response := interceptForMethod(t, app, MethodRequestInterceptBefore, first); response.Terminate {
		t.Fatalf("first before rejected: %+v", response)
	}
	first.Metadata["selected_auth_id"] = firstPick.AuthID
	if key := app.store.FindByID("key-b"); key == nil || !key.SessionAffinity {
		t.Fatalf("session affinity config not loaded: %+v", key)
	}
	schedulerProposalKey := schedulerAffinityProposalKey("key-b", "fast", firstPick.AuthID, request.Options.Metadata, true)
	afterProposalKey := schedulerAffinityProposalKey("key-b", first.RequestedModel, firstPick.AuthID, first.Metadata, true)
	if schedulerProposalKey != afterProposalKey {
		t.Fatalf("proposal key mismatch: scheduler=%q after=%q", schedulerProposalKey, afterProposalKey)
	}
	otherRouteMetadata := make(map[string]any, len(request.Options.Metadata)+1)
	for name, value := range request.Options.Metadata {
		otherRouteMetadata[name] = value
	}
	otherRouteMetadata["target_model"] = "another-model"
	if other := schedulerAffinityProposalKey("key-b", "fast", firstPick.AuthID, otherRouteMetadata, true); other == schedulerProposalKey {
		t.Fatal("proposal correlation did not distinguish different route metadata")
	}
	if response := interceptForMethod(t, app, MethodRequestInterceptAfter, first); response.Terminate {
		t.Fatalf("first after rejected: %+v %s", response, response.ResponseBody)
	}
	affinityKey := schedulerAffinityKey(request, app.store.FindByID("key-b"), "", false, "sticky-session")
	if got := app.affinity.boundAuth(affinityKey); got != "auth-a.json" {
		t.Fatalf("first accepted pick did not commit affinity: %q", got)
	}

	secondPick := schedulerPickForTest(t, app, request)
	if secondPick.AuthID != "auth-b.json" {
		t.Fatalf("full sticky auth did not fail over inside pool: %q", secondPick.AuthID)
	}
	if secondPick.AuthID == "outside.json" {
		t.Fatal("affinity failover crossed the account binding")
	}
	second := controlledInterceptRequest("sticky-2", "key-b", secrets["key-b"])
	second.Metadata["canonical_session_id"] = "sticky-session"
	if response := interceptForMethod(t, app, MethodRequestInterceptBefore, second); response.Terminate {
		t.Fatalf("second before rejected: %+v", response)
	}
	second.Metadata["selected_auth_id"] = secondPick.AuthID
	if response := interceptForMethod(t, app, MethodRequestInterceptAfter, second); response.Terminate {
		t.Fatalf("second after rejected: %+v %s", response, response.ResponseBody)
	}
	if got := app.affinity.boundAuth(affinityKey); got != "auth-b.json" {
		t.Fatalf("accepted failover did not replace affinity: %q", got)
	}
	completeForTest(t, app, "sticky-1")
	completeForTest(t, app, "sticky-2")
	if got := schedulerPickForTest(t, app, request).AuthID; got != "auth-b.json" {
		t.Fatalf("confirmed failover affinity = %q, want auth-b.json", got)
	}
}

func TestSchedulerReturns429WhenAllAllowedAuthsAreFull(t *testing.T) {
	app, secrets := configureConcurrencyApp(t)
	for index, authID := range []string{"auth-a.json", "auth-b.json"} {
		requestID := "occupy-" + authID
		before := controlledInterceptRequest(requestID, "key-b", secrets["key-b"])
		if response := interceptForMethod(t, app, MethodRequestInterceptBefore, before); response.Terminate {
			t.Fatalf("occupy before %d rejected: %+v", index, response)
		}
		before.Metadata["selected_auth_id"] = authID
		if response := interceptForMethod(t, app, MethodRequestInterceptAfter, before); response.Terminate {
			t.Fatalf("occupy after %d rejected: %+v", index, response)
		}
	}
	request := boundSchedulerRequest(secrets["key-b"])
	request.Options.Metadata["caller_scope"] = policy.CallerScopeForKey("key-b")
	request.Candidates = []SchedulerAuthCandidate{
		{ID: "auth-a.json", Provider: "codex"},
		{ID: "auth-b.json", Provider: "codex"},
	}
	err := schedulerErrorForTest(t, app, request)
	if err.Code != "auth_concurrency_exceeded" || err.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("scheduler error = %+v", err)
	}
}

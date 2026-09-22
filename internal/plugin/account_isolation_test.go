package plugin

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"cpa-key-policy/internal/policy"
)

func configureBoundApp(t *testing.T, strategy string, global bool) (*App, string) {
	t.Helper()
	plain := "cpa_bound_secret"
	hash := hashForTest(t, plain)
	app := NewApp()
	configYAML := []byte(`
enabled: true
global_weighted_round_robin: ` + map[bool]string{true: "true", false: "false"}[global] + `
state_file: "` + filepath.ToSlash(filepath.Join(t.TempDir(), "state.json")) + `"
keys:
  - id: bound-key
    name: Bound Key
    enabled: true
    key_hash: "` + hash + `"
    account_binding:
      allow: ["account-a*"]
      strategy: "` + strategy + `"
    models:
      - alias: fast
        provider: codex
        target_model: gpt-5-codex
        group: team
`)
	request, _ := json.Marshal(LifecycleRequest{ConfigYAML: configYAML})
	if _, err := app.HandleMethod(MethodPluginReconfigure, request); err != nil {
		t.Fatalf("configure bound app: %v", err)
	}
	return app, plain
}

func boundSchedulerRequest(plain string) SchedulerPickRequest {
	return SchedulerPickRequest{
		Provider: "codex",
		Model:    "gpt-5-codex",
		Options: SchedulerPickOptions{
			Headers: map[string][]string{"Authorization": {"Bearer " + plain}},
			Metadata: map[string]any{
				"requested_model": "fast",
				"caller_scope":    policy.CallerScopeForKey("bound-key"),
			},
		},
		Candidates: []SchedulerAuthCandidate{
			{ID: "account-a-team", Provider: "codex", Weight: 1, Attributes: map[string]string{"plan_type": "team"}},
			{ID: "account-a-free", Provider: "codex", Weight: 100, Attributes: map[string]string{"plan_type": "free"}},
			{ID: "account-b-team", Provider: "codex", Weight: 100, Attributes: map[string]string{"plan_type": "team"}},
		},
	}
}

func TestSchedulerBindingIgnoresTargetGroup(t *testing.T) {
	app, plain := configureBoundApp(t, "weighted-round-robin", false)
	request := boundSchedulerRequest(plain)
	for i := 0; i < 10; i++ {
		if got := schedulerPickForTest(t, app, request).AuthID; !strings.HasPrefix(got, "account-a-") {
			t.Fatalf("selected account outside binding: %q", got)
		}
	}
	if got := schedulerPickForTest(t, app, request).AuthID; got != "account-a-free" {
		t.Fatalf("old target group still excluded a higher-weight bound account: %q", got)
	}
}

func TestGlobalWeightedModeCannotBypassExplicitBinding(t *testing.T) {
	app, plain := configureBoundApp(t, "weighted-round-robin", true)
	request := boundSchedulerRequest(plain)
	if got := schedulerPickForTest(t, app, request).AuthID; got != "account-a-free" {
		t.Fatalf("global mode bypassed binding or retained group: %q", got)
	}
}

func TestBoundSchedulerRoundRobin(t *testing.T) {
	app, plain := configureBoundApp(t, "round-robin", false)
	request := boundSchedulerRequest(plain)
	request.Candidates = []SchedulerAuthCandidate{
		{ID: "account-a-1", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
		{ID: "account-a-2", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
	}
	want := []string{"account-a-1", "account-a-2", "account-a-1", "account-a-2"}
	for index, id := range want {
		if got := schedulerPickForTest(t, app, request).AuthID; got != id {
			t.Fatalf("pick %d = %q, want %q", index, got, id)
		}
	}
}

func TestBoundSchedulerAcceptsHostProjectedResidualError(t *testing.T) {
	for _, strategy := range []string{"round-robin", "weighted-round-robin", "fill-first", "quota-fill-first"} {
		t.Run(strategy, func(t *testing.T) {
			app, plain := configureBoundApp(t, strategy, false)
			request := boundSchedulerRequest(plain)
			request.Candidates = []SchedulerAuthCandidate{{
				ID:         "account-a-recovered",
				Provider:   "codex",
				Status:     "error",
				Weight:     1,
				Attributes: map[string]string{"plan_type": "team"},
			}}

			rawRequest, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			rawResponse, err := app.HandleMethod(MethodSchedulerPick, rawRequest)
			if err != nil {
				t.Fatal(err)
			}
			var envelope Envelope
			if err := json.Unmarshal(rawResponse, &envelope); err != nil {
				t.Fatal(err)
			}
			if !envelope.OK {
				t.Fatalf("scheduler rejected host-projected recovered candidate: %+v", envelope.Error)
			}
			var response SchedulerPickResponse
			if err := json.Unmarshal(envelope.Result, &response); err != nil {
				t.Fatal(err)
			}
			if !response.Handled || response.AuthID != "account-a-recovered" {
				t.Fatalf("scheduler response = %+v, want recovered candidate", response)
			}
		})
	}
}

func TestBoundSchedulerFillFirst(t *testing.T) {
	app, plain := configureBoundApp(t, "fill-first", false)
	request := boundSchedulerRequest(plain)
	request.Candidates = []SchedulerAuthCandidate{
		{ID: "account-a-z", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
		{ID: "account-a-a", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}},
	}
	if got := schedulerPickForTest(t, app, request).AuthID; got != "account-a-a" {
		t.Fatalf("fill-first selected %q", got)
	}
}

func TestBoundSchedulerFailsWhenHostOmitsAllowedPool(t *testing.T) {
	app, plain := configureBoundApp(t, "weighted-round-robin", false)
	request := boundSchedulerRequest(plain)
	request.Candidates = []SchedulerAuthCandidate{{ID: "account-b-team", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}}}
	err := schedulerErrorForTest(t, app, request)
	if err.Code != "auth_not_bound" || err.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("error = %+v", err)
	}
}

func TestBoundSchedulerZeroWeightFailsClosed(t *testing.T) {
	app, plain := configureBoundApp(t, "round-robin", false)
	request := boundSchedulerRequest(plain)
	request.Candidates = []SchedulerAuthCandidate{{ID: "account-a-paused", Provider: "codex", Weight: 0, Attributes: map[string]string{"plan_type": "team"}}}
	err := schedulerErrorForTest(t, app, request)
	if err.Code != "auth_not_found" {
		t.Fatalf("error = %+v", err)
	}
}

func TestBoundSchedulerRejectsUnavailableProviderMismatchAndOutOfPoolPin(t *testing.T) {
	app, plain := configureBoundApp(t, "round-robin", false)
	base := boundSchedulerRequest(plain)
	tests := []struct {
		name      string
		candidate SchedulerAuthCandidate
		metadata  map[string]any
	}{
		{name: "cooldown", candidate: SchedulerAuthCandidate{ID: "account-a-team", Provider: "codex", Status: "cooldown", Attributes: map[string]string{"plan_type": "team"}}},
		{name: "disabled", candidate: SchedulerAuthCandidate{ID: "account-a-team", Provider: "codex", Status: "disabled", Attributes: map[string]string{"plan_type": "team"}}},
		{name: "expired", candidate: SchedulerAuthCandidate{ID: "account-a-team", Provider: "codex", Status: "expired", Attributes: map[string]string{"plan_type": "team"}}},
		{name: "revoked", candidate: SchedulerAuthCandidate{ID: "account-a-team", Provider: "codex", Status: "revoked", Attributes: map[string]string{"plan_type": "team"}}},
		{name: "invalid", candidate: SchedulerAuthCandidate{ID: "account-a-team", Provider: "codex", Status: "invalid", Attributes: map[string]string{"plan_type": "team"}}},
		{name: "unavailable", candidate: SchedulerAuthCandidate{ID: "account-a-team", Provider: "codex", Status: "unavailable", Attributes: map[string]string{"plan_type": "team"}}},
		{name: "cooling down", candidate: SchedulerAuthCandidate{ID: "account-a-team", Provider: "codex", Status: "cooling-down", Attributes: map[string]string{"plan_type": "team"}}},
		{name: "quota exhausted", candidate: SchedulerAuthCandidate{ID: "account-a-team", Provider: "codex", Status: "quota_exhausted", Attributes: map[string]string{"plan_type": "team"}}},
		{name: "exhausted", candidate: SchedulerAuthCandidate{ID: "account-a-team", Provider: "codex", Status: "exhausted", Attributes: map[string]string{"plan_type": "team"}}},
		{name: "blocked", candidate: SchedulerAuthCandidate{ID: "account-a-team", Provider: "codex", Status: "blocked", Attributes: map[string]string{"plan_type": "team"}}},
		{name: "provider mismatch", candidate: SchedulerAuthCandidate{ID: "account-a-team", Provider: "claude", Attributes: map[string]string{"plan_type": "team"}}},
		{name: "out-of-pool pin", candidate: SchedulerAuthCandidate{ID: "account-b-team", Provider: "codex", Attributes: map[string]string{"plan_type": "team"}}, metadata: map[string]any{"pinned_auth_id": "account-b-team"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			request.Candidates = []SchedulerAuthCandidate{test.candidate}
			request.Options.Metadata = map[string]any{
				"requested_model": "fast",
				"caller_scope":    policy.CallerScopeForKey("bound-key"),
			}
			for key, value := range test.metadata {
				request.Options.Metadata[key] = value
			}
			if err := schedulerErrorForTest(t, app, request); err.Code != "auth_not_bound" {
				t.Fatalf("error = %+v", err)
			}
		})
	}
}

func TestBoundRequestInterceptorRejectsQueryOnlyAndConflicts(t *testing.T) {
	app, plain := configureBoundApp(t, "weighted-round-robin", false)
	metadata := map[string]any{"caller_scope": policy.CallerScopeForKey("bound-key")}
	queryOnly := requestInterceptForTest(t, app, RequestInterceptRequest{Metadata: metadata})
	if !queryOnly.Terminate || queryOnly.StatusCode != http.StatusUnauthorized || !strings.Contains(string(queryOnly.ResponseBody), "header_key_required") {
		t.Fatalf("query-only response = %+v body=%s", queryOnly, queryOnly.ResponseBody)
	}
	conflict := requestInterceptForTest(t, app, RequestInterceptRequest{
		Metadata: metadata,
		Headers: http.Header{
			"Authorization": {"Bearer " + plain},
			"X-Api-Key":     {"different"},
		},
	})
	if !conflict.Terminate || conflict.StatusCode != http.StatusBadRequest || !strings.Contains(string(conflict.ResponseBody), "credential_conflict") {
		t.Fatalf("conflict response = %+v body=%s", conflict, conflict.ResponseBody)
	}
}

func TestBoundSchedulerAcceptsSameTargetAcrossAllGroups(t *testing.T) {
	plain := "cpa_ambiguous"
	hash := hashForTest(t, plain)
	app := NewApp()
	configYAML := []byte(`
enabled: true
state_file: "` + filepath.ToSlash(filepath.Join(t.TempDir(), "state.json")) + `"
aliases:
  - alias: fast
    targets:
      - provider: codex
        target_model: gpt-5-codex
        group: team
      - provider: codex
        target_model: gpt-5-codex
        group: free
keys:
  - id: ambiguous
    enabled: true
    key_hash: "` + hash + `"
    account_binding:
      allow: ["account-*"]
      strategy: round-robin
    aliases:
      - alias: fast
`)
	request, _ := json.Marshal(LifecycleRequest{ConfigYAML: configYAML})
	if _, err := app.HandleMethod(MethodPluginReconfigure, request); err != nil {
		t.Fatal(err)
	}
	pickRequest := SchedulerPickRequest{
		Provider: "codex",
		Model:    "gpt-5-codex",
		Options: SchedulerPickOptions{
			Headers:  map[string][]string{"Authorization": {"Bearer " + plain}},
			Metadata: map[string]any{"requested_model": "fast", "caller_scope": policy.CallerScopeForKey("ambiguous")},
		},
		Candidates: []SchedulerAuthCandidate{
			{ID: "account-team", Provider: "codex", Weight: 1, Attributes: map[string]string{"plan_type": "team"}},
			{ID: "account-plus", Provider: "codex", Weight: 1, Attributes: map[string]string{"plan_type": "plus"}},
			{ID: "account-pro", Provider: "codex", Weight: 1, Attributes: map[string]string{"plan_type": "pro"}},
			{ID: "account-custom", Provider: "codex", Weight: 1, Attributes: map[string]string{"tier": "enterprise"}},
		},
	}
	want := []string{"account-custom", "account-plus", "account-pro", "account-team"}
	for i, id := range want {
		if got := schedulerPickForTest(t, app, pickRequest).AuthID; got != id {
			t.Fatalf("pick %d = %q, want %q", i, got, id)
		}
	}
}

func TestUnboundSchedulerStillRejectsAmbiguousSameTargetGroups(t *testing.T) {
	plain := "cpa_unbound_ambiguous"
	hash := hashForTest(t, plain)
	app := NewApp()
	configYAML := []byte(`
enabled: true
state_file: "` + filepath.ToSlash(filepath.Join(t.TempDir(), "state.json")) + `"
aliases:
  - alias: fast
    targets:
      - provider: codex
        target_model: gpt-5-codex
        group: team
      - provider: codex
        target_model: gpt-5-codex
        group: plus
keys:
  - id: unbound-ambiguous
    enabled: true
    key_hash: "` + hash + `"
    aliases:
      - alias: fast
`)
	request, _ := json.Marshal(LifecycleRequest{ConfigYAML: configYAML})
	if _, err := app.HandleMethod(MethodPluginReconfigure, request); err != nil {
		t.Fatal(err)
	}
	err := schedulerErrorForTest(t, app, SchedulerPickRequest{
		Provider: "codex",
		Model:    "gpt-5-codex",
		Options: SchedulerPickOptions{
			Headers:  map[string][]string{"Authorization": {"Bearer " + plain}},
			Metadata: map[string]any{"requested_model": "fast", "caller_scope": policy.CallerScopeForKey("unbound-ambiguous")},
		},
		Candidates: []SchedulerAuthCandidate{{ID: "account-team", Provider: "codex", Weight: 1, Attributes: map[string]string{"plan_type": "team"}}},
	})
	if err.Code != "account_constraint_ambiguous" {
		t.Fatalf("error = %+v", err)
	}
}

func TestBoundAffinityProposalIgnoresMetadataGroup(t *testing.T) {
	base := map[string]any{
		"canonical_session_id": "session",
		"target_provider":      "codex",
		"target_model":         "gpt-5-codex",
	}
	team := map[string]any{}
	plus := map[string]any{}
	for key, value := range base {
		team[key] = value
		plus[key] = value
	}
	team["group"] = "team"
	plus["group"] = "plus"
	if got, want := schedulerAffinityProposalKey("k", "fast", "account", team, true), schedulerAffinityProposalKey("k", "fast", "account", plus, true); got != want {
		t.Fatalf("bound proposal keys differed by group: %q != %q", got, want)
	}
	if got, want := schedulerAffinityProposalKey("k", "fast", "account", team, false), schedulerAffinityProposalKey("k", "fast", "account", plus, false); got == want {
		t.Fatal("unbound proposal keys unexpectedly ignored group")
	}
}

func TestNativeKeyBindingUsesHostIdentity(t *testing.T) {
	plain := "native-downstream-key"
	hash := hashForTest(t, plain)
	app := NewApp()
	configYAML := []byte(`
enabled: true
state_file: "` + filepath.ToSlash(filepath.Join(t.TempDir(), "state.json")) + `"
keys:
  - id: native-bound
    enabled: true
    native: true
    key_hash: "` + hash + `"
    caller_scope: "` + policy.CallerScopeForKey(plain) + `"
    account_binding:
      allow: ["native-account-a"]
      strategy: round-robin
`)
	request, _ := json.Marshal(LifecycleRequest{ConfigYAML: configYAML})
	if _, err := app.HandleMethod(MethodPluginReconfigure, request); err != nil {
		t.Fatal(err)
	}
	resp := schedulerPickForTest(t, app, SchedulerPickRequest{
		Provider: "openai-compatible-demo",
		Model:    "real-model",
		Options: SchedulerPickOptions{
			Headers:  map[string][]string{"Authorization": {"Bearer " + plain}},
			Metadata: map[string]any{"caller_scope": policy.CallerScopeForKey(plain), "requested_model": "real-model"},
		},
		Candidates: []SchedulerAuthCandidate{
			{ID: "native-account-a", Provider: "openai-compatible-demo"},
			{ID: "native-account-b", Provider: "openai-compatible-demo"},
		},
	})
	if resp.AuthID != "native-account-a" {
		t.Fatalf("native binding selected %q", resp.AuthID)
	}
}

func schedulerErrorForTest(t *testing.T, app *App, request SchedulerPickRequest) *EnvelopeError {
	t.Helper()
	rawRequest, _ := json.Marshal(request)
	rawResponse, err := app.HandleMethod(MethodSchedulerPick, rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	var envelope Envelope
	if err := json.Unmarshal(rawResponse, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.Error == nil {
		t.Fatalf("expected scheduler error, got %s", rawResponse)
	}
	return envelope.Error
}

func requestInterceptForTest(t *testing.T, app *App, request RequestInterceptRequest) RequestInterceptResponse {
	t.Helper()
	rawRequest, _ := json.Marshal(request)
	rawResponse, err := app.HandleMethod(MethodRequestInterceptBefore, rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	var response RequestInterceptResponse
	if err := unmarshalOK(rawResponse, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

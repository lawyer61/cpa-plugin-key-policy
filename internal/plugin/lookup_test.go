package plugin

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"cpa-key-policy/internal/policy"
)

func lookupRequestForTest(t *testing.T, app *App, headers http.Header, query url.Values) ManagementResponse {
	t.Helper()
	rawRequest, _ := json.Marshal(ManagementRequest{
		Method:  http.MethodGet,
		Path:    "/v0/resource/plugins/cpa-key-policy/lookup/data",
		Headers: headers,
		Query:   query,
	})
	rawResponse, err := app.HandleMethod(MethodManagementHandle, rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	return managementResponseFromEnvelope(t, rawResponse)
}

func TestLookupReturnsOnlyOwnLightweightUsageAndConcurrency(t *testing.T) {
	app, plain := configurePricedApp(t)
	if err := app.store.UpsertKey(policy.KeyConfig{
		ID:      "other",
		Name:    "Other Key",
		Enabled: true,
		KeyHash: hashForTest(t, "cpa_other"),
		Models:  []policy.ModelRule{{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex"}},
	}, false); err != nil {
		t.Fatal(err)
	}
	app.store.RecordUsage("priced", "fast", "gpt-5-codex", false, policy.UsageDetail{InputTokens: 250_000, OutputTokens: 100_000})
	request := controlledInterceptRequest("lookup-current", "priced", plain)
	request.Metadata["caller_scope"] = policy.CallerScopeForKey("priced")
	if response := interceptForMethod(t, app, MethodRequestInterceptBefore, request); response.Terminate {
		t.Fatalf("before rejected: %+v %s", response, response.ResponseBody)
	}

	response := lookupRequestForTest(t, app, http.Header{"Authorization": {"Bearer " + plain}}, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("lookup status = %d body=%s", response.StatusCode, response.Body)
	}
	if response.Headers.Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control = %q", response.Headers.Get("Cache-Control"))
	}
	var payload lookupResponse
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Name != "priced" || payload.Concurrency.Current != 1 {
		t.Fatalf("lookup payload = %+v", payload)
	}
	if payload.Usage.DailyUSD <= 0 || len(payload.Aliases) != 1 || payload.Aliases[0].Alias != "fast" {
		t.Fatalf("usage payload = %+v", payload)
	}
	body := string(response.Body)
	for _, forbidden := range []string{"key_hash", "caller_scope", "account_binding", "selected_auth_id", "auth_concurrency_limits", "target_model", "provider", "Other Key", `"key_id":"other"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("lookup leaked %q: %s", forbidden, body)
		}
	}
	completeForTest(t, app, "lookup-current")
}

func TestLookupRequiresOneBearerHeaderAndRejectsURLKeys(t *testing.T) {
	app, plain := configurePricedApp(t)
	requests := []struct {
		name    string
		headers http.Header
		query   url.Values
		status  int
	}{
		{name: "missing", status: http.StatusUnauthorized},
		{name: "wrong scheme", headers: http.Header{"Authorization": {"Basic " + plain}}, status: http.StatusUnauthorized},
		{name: "multiple", headers: http.Header{"Authorization": {"Bearer " + plain, "Bearer other"}}, status: http.StatusUnauthorized},
		{name: "url key", headers: http.Header{"Authorization": {"Bearer " + plain}}, query: url.Values{"key_id": {"priced"}}, status: http.StatusBadRequest},
	}
	for _, test := range requests {
		t.Run(test.name, func(t *testing.T) {
			response := lookupRequestForTest(t, app, test.headers, test.query)
			if response.StatusCode != test.status {
				t.Fatalf("status = %d body=%s, want %d", response.StatusCode, response.Body, test.status)
			}
			if response.Headers.Get("Cache-Control") != "no-store" {
				t.Fatalf("cache-control = %q", response.Headers.Get("Cache-Control"))
			}
		})
	}
}

func TestLookupDisabledAndUnknownKeysUseUniformUnauthorizedResponse(t *testing.T) {
	app, plain := configurePricedApp(t)
	unknown := lookupRequestForTest(t, app, http.Header{"Authorization": {"Bearer unknown"}}, nil)
	key := app.store.FindByID("priced")
	key.Enabled = false
	if err := app.store.UpsertKey(*key, false); err != nil {
		t.Fatal(err)
	}
	disabled := lookupRequestForTest(t, app, http.Header{"Authorization": {"Bearer " + plain}}, nil)
	if unknown.StatusCode != http.StatusUnauthorized || disabled.StatusCode != http.StatusUnauthorized || string(unknown.Body) != string(disabled.Body) {
		t.Fatalf("unknown=%d %s disabled=%d %s", unknown.StatusCode, unknown.Body, disabled.StatusCode, disabled.Body)
	}
}

func TestLookupNativeKeyReturnsAllDerivedKeyUsage(t *testing.T) {
	app, _ := configurePricedApp(t)
	secondSecret := "cpa_second"
	secondHash := hashForTest(t, secondSecret)
	if err := app.store.UpsertKeyWithModelPricing(policy.KeyConfig{
		ID:      "second",
		Name:    "Second Key",
		Enabled: true,
		KeyHash: secondHash,
		Models: []policy.ModelRule{{
			Alias:                "fast",
			Provider:             "codex",
			TargetModel:          "gpt-5-codex",
			InputPricePerMillion: 2,
		}},
	}, false); err != nil {
		t.Fatal(err)
	}
	app.store.RecordUsage("priced", "fast", "gpt-5-codex", false, policy.UsageDetail{InputTokens: 250_000})
	app.store.RecordUsage("second", "fast", "gpt-5-codex", false, policy.UsageDetail{InputTokens: 500_000})
	response := app.createKey([]byte(`{"id":"native-lookup","native":true,"key":"native-lookup-secret","account_binding":{"allow":["auth-a.json"]}}`))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create native = %d %s", response.StatusCode, response.Body)
	}
	lookup := lookupRequestForTest(t, app, http.Header{"Authorization": {"Bearer native-lookup-secret"}}, nil)
	if lookup.StatusCode != http.StatusOK {
		t.Fatalf("native lookup = %d %s", lookup.StatusCode, lookup.Body)
	}
	var payload lookupAllDerivedResponse
	if err := json.Unmarshal(lookup.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Scope != "all-derived" || len(payload.Keys) != 2 {
		t.Fatalf("native lookup payload = %#v", payload)
	}
	if payload.Keys[0].KeyID != "priced" || payload.Keys[0].Usage.DailyUSD <= 0 || payload.Keys[1].KeyID != "second" || payload.Keys[1].Usage.DailyUSD <= 0 {
		t.Fatalf("derived usage = %#v", payload.Keys)
	}
	body := string(lookup.Body)
	for _, forbidden := range []string{"key_hash", "caller_scope", "account_binding", "selected_auth_id", "native-lookup"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("native lookup leaked %q: %s", forbidden, body)
		}
	}
}

func TestLookupPageResourceIsRegisteredAndServed(t *testing.T) {
	app := NewApp()
	registered := map[string]bool{}
	for _, route := range app.managementRegistration().Resources {
		registered[route.Path] = true
	}
	if !registered["/lookup"] || !registered["/lookup/data"] {
		t.Fatalf("lookup resources missing: %+v", registered)
	}
	rawRequest, _ := json.Marshal(ManagementRequest{Method: http.MethodGet, Path: "/v0/resource/plugins/cpa-key-policy/lookup"})
	rawResponse, err := app.HandleMethod(MethodManagementHandle, rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	response := managementResponseFromEnvelope(t, rawResponse)
	if response.StatusCode != http.StatusOK || !strings.Contains(strings.ToLower(string(response.Body)), "<!doctype html>") {
		t.Fatalf("lookup page = %d %s", response.StatusCode, response.Body)
	}
}

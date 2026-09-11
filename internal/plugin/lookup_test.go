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
	for _, forbidden := range []string{"key_hash", "caller_scope", "account_binding", "selected_auth_id", "auth_concurrency_limits", "target_model", "provider"} {
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

func TestLookupNativeKeyIsExplicitlyUnsupported(t *testing.T) {
	app, _ := configureTestApp(t)
	response := app.createKey([]byte(`{"id":"native-lookup","native":true,"key":"native-lookup-secret","account_binding":{"allow":["auth-a.json"]}}`))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create native = %d %s", response.StatusCode, response.Body)
	}
	lookup := lookupRequestForTest(t, app, http.Header{"Authorization": {"Bearer native-lookup-secret"}}, nil)
	if lookup.StatusCode != http.StatusNotImplemented || !strings.Contains(string(lookup.Body), "native_usage_unsupported") {
		t.Fatalf("native lookup = %d %s", lookup.StatusCode, lookup.Body)
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

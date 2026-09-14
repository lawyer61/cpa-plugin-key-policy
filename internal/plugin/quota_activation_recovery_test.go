package plugin

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"cpa-key-policy/internal/policy"
)

type activationTestHost struct {
	*fakeQuotaHost
	postBody string
}

func (h *activationTestHost) Do(req HostHTTPRequest) (HostHTTPResponse, error) {
	resp, err := h.fakeQuotaHost.Do(req)
	if req.Method == http.MethodPost {
		resp.Body = []byte(h.postBody)
	}
	return resp, err
}

func setupActivationRecovery(t *testing.T, extra string) (*App, *activationTestHost, *time.Time) {
	t.Helper()
	app := configuredQuotaTestApp(t)
	on, scope := true, "all-codex"
	if _, err := app.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{QuotaActivationEnabled: &on, QuotaActivationScope: &scope}); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 9, 15, 0, 14, 19, 0, time.UTC)
	base := newFakeQuotaHost(clock)
	for i := 0; i < 50; i++ {
		base.getResponses = append(base.getResponses, HostHTTPResponse{StatusCode: 200, Body: shortQuotaBody(0)})
	}
	host := &activationTestHost{fakeQuotaHost: base, postBody: "data: [DONE]\n\n"}
	attachTestQuotaHost(app, base, clock)
	app.quota.host = host
	app.quota.now = func() time.Time { return clock }
	app.quota.cache.now = func() time.Time { return clock }
	app.quota.verifyDelay = 0
	var activation quotaActivationState
	if err := json.Unmarshal([]byte(`{"protocol":"responses-v1","model":"gpt-5.6-luna","status":"verify_pending","cycle_id":"old-200-cycle","windows":["five_hour"],"attempts":1,"last_attempt_at":"2026-09-14T17:43:16Z","last_result":"http_200"`+extra+`}`), &activation); err != nil {
		t.Fatal(err)
	}
	app.quota.runtime.Auths["account-a-team"] = quotaAuthRuntime{
		AuthID: "account-a-team", AuthIndex: "idx-a", Provider: "codex", InMaintenanceScope: true, InActivationScope: true,
		CredentialFingerprint: codexCredentialFingerprint(codexCredentials{AccountID: "acct-a"}), Activation: activation,
	}
	return app, host, &clock
}

func TestQuotaActivationAttemptCapIsFive(t *testing.T) {
	if quotaMaxActivationTries != 5 {
		t.Fatalf("total activation cap=%d, want 5", quotaMaxActivationTries)
	}
}

func TestQuotaLegacyHTTP200RecoveryRequiresTwoFreshChecksAndStopsAtFive(t *testing.T) {
	app, host, clock := setupActivationRecovery(t, "")
	for round := 0; round < 12; round++ {
		app.quota.runRound()
		_, _, posts := host.counts()
		want := (round + 1) / 2
		if want > 4 {
			want = 4
		}
		if posts != want {
			t.Fatalf("round=%d POST=%d want=%d; activation=%+v", round, posts, want, app.quota.runtime.Auths["account-a-team"].Activation)
		}
		*clock = clock.Add(31 * time.Minute)
	}
	a := app.quota.runtime.Auths["account-a-team"].Activation
	if a.Attempts != 5 || a.CycleID != "old-200-cycle" || a.Status != "attempts_exhausted" {
		t.Fatalf("budget/state=%+v", a)
	}
}

func TestQuotaRecoveryDoesNotReplayExecutionOrAmbiguousTransport(t *testing.T) {
	for _, extra := range []string{
		`,"response_outcome":"completed"`, `,"response_outcome":"incomplete"`,
		`,"output_observed":true`, `,"total_tokens":2`, `,"input_tokens":1`,
		`,"last_result":"http_500"`, `,"last_result":"http_408"`, `,"last_result":"outcome_unknown"`, `,"send_intent":true`,
	} {
		t.Run(extra, func(t *testing.T) {
			app, host, clock := setupActivationRecovery(t, extra)
			for i := 0; i < 4; i++ {
				app.quota.runRound()
				*clock = clock.Add(31 * time.Minute)
			}
			if _, _, posts := host.counts(); posts != 0 {
				t.Fatalf("unsafe replay count=%d", posts)
			}
		})
	}
}

func TestQuotaRecoveryEvidenceSurvivesReloadButNotFailedGET(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "reload", true: "failed_get"}[fail], func(t *testing.T) {
			app, host, clock := setupActivationRecovery(t, "")
			app.quota.runRound()
			if err := app.quota.persist(); err != nil {
				t.Fatal(err)
			}
			app.quota.loadRuntime(app.quota.runtimeStore.path)
			*clock = clock.Add(31 * time.Minute)
			if fail {
				host.getResponses[0] = HostHTTPResponse{StatusCode: 500}
				app.quota.runRound()
				*clock = clock.Add(31 * time.Minute)
			}
			app.quota.runRound()
			_, _, posts := host.counts()
			want := 1
			if fail {
				want = 0
			}
			if posts != want {
				t.Fatalf("POST=%d want=%d", posts, want)
			}
		})
	}
}

func TestQuotaActivationDeadlineTracksOrdinaryGETs(t *testing.T) {
	app, _, clock := setupActivationRecovery(t, `,"response_outcome":"completed"`)
	for i := 0; i < 3; i++ {
		app.quota.runRound()
		r := app.quota.runtime.Auths["account-a-team"]
		if !r.Activation.NextCheckAt.Equal(r.NextCheckAt) {
			t.Fatalf("activation next=%s auth next=%s", r.Activation.NextCheckAt, r.NextCheckAt)
		}
		*clock = clock.Add(31 * time.Minute)
	}
}

func TestQuotaSSERejectedRequestsStopAtFiveAndKeepSafeError(t *testing.T) {
	app, host, clock := setupActivationRecovery(t, "")
	r := app.quota.runtime.Auths["account-a-team"]
	r.Activation = quotaActivationState{}
	app.quota.runtime.Auths["account-a-team"] = r
	host.postBody = `data: {"type":"response.failed","response":{"error":{"code":"model_not_found","message":"secret-token"}}}` + "\n\n"
	for i := 0; i < 9; i++ {
		app.quota.runRound()
		*clock = clock.Add(31 * time.Minute)
	}
	a := app.quota.runtime.Auths["account-a-team"].Activation
	_, _, posts := host.counts()
	if posts != 5 || a.Attempts != 5 || a.Status != "attempts_exhausted" || a.ResponseErrorCode != "model_not_found" {
		t.Fatalf("posts=%d state=%+v", posts, a)
	}
	if a.LastError != "http_200: response.failed: model_not_found" {
		t.Fatalf("error=%q", a.LastError)
	}
}

func TestQuotaRecoveryStreakResetByBusinessAndMissingWindow(t *testing.T) {
	for _, reason := range []string{"business", "missing_window", "duplicate_check"} {
		t.Run(reason, func(t *testing.T) {
			app, host, clock := setupActivationRecovery(t, "")
			app.quota.runRound()
			switch reason {
			case "business":
				app.quota.recordUsage(UsageHandleRequest{Provider: "codex", AuthID: "account-a-team", AuthIndex: "idx-a", RequestedAt: *clock})
			case "missing_window":
				*clock = clock.Add(31 * time.Minute)
				host.getResponses[0] = HostHTTPResponse{StatusCode: 200, Body: []byte(`{"rate_limit":{"allowed":true}}`)}
				app.quota.runRound()
			case "duplicate_check":
				r := app.quota.runtime.Auths["account-a-team"]
				obs, _ := parseCodexQuotaPayload(shortQuotaBody(0), *clock)
				app.quota.processObservation(r.AuthID, r.AuthIndex, r.CredentialFingerprint, obs, *clock)
				if app.quota.runtime.Auths[r.AuthID].Activation.RetryAllowed {
					t.Fatal("same-time GET counted twice")
				}
				return
			}
			*clock = clock.Add(31 * time.Minute)
			app.quota.runRound()
			if _, _, posts := host.counts(); posts != 0 {
				t.Fatalf("%s did not reset recovery streak", reason)
			}
		})
	}
}

func TestQuotaActivationConfirmationNeedsUsableResetEvidence(t *testing.T) {
	for _, seconds := range []int64{0, -60, 18000, 22000, 15000} {
		app, _, clock := setupActivationRecovery(t, `,"last_error":"old response diagnostic"`)
		used := 0.0
		window := quotaWindow{Kind: quotaWindowShort, WindowSeconds: 18000, UsedPercent: &used, ResetAt: clock.Add(time.Duration(seconds) * time.Second)}
		if seconds == 0 {
			window.ResetAt = time.Time{}
		}
		r := app.quota.runtime.Auths["account-a-team"]
		app.quota.processObservation(r.AuthID, r.AuthIndex, r.CredentialFingerprint, quotaObservation{Short: &window}, *clock)
		a := app.quota.runtime.Auths[r.AuthID].Activation
		if (a.Status == "confirmed") != (seconds == 15000) {
			t.Fatalf("reset offset=%ds status=%s", seconds, a.Status)
		}
		if a.Status == "confirmed" && (a.LastError != "" || a.LastResult != "verified") {
			t.Fatalf("confirmed has stale error: %+v", a)
		}
	}
}

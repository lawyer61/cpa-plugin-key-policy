package plugin

import "time"

func activationHasExecutionEvidence(a quotaActivationState) bool {
	return a.ResponseOutcome == "completed" || a.OutputObserved || a.InputTokens > 0 || a.OutputTokens > 0 || a.TotalTokens > 0
}

func activationHasUnknownHTTP200(a quotaActivationState) bool {
	return a.LastResult == "http_200" && (a.ResponseOutcome == "" || a.ResponseOutcome == "unknown") && a.ResponseErrorCode == "" && !activationHasExecutionEvidence(a)
}

func resetActivationRecovery(a *quotaActivationState) {
	a.RecoveryObservations = nil
	if activationHasUnknownHTTP200(*a) {
		a.RetryAllowed = false
	}
}

func activationWindowsAreLazy(a quotaActivationState, obs quotaObservation, now time.Time) bool {
	if len(a.Windows) == 0 || obs.ExplicitExhausted {
		return false
	}
	windows := observationWindows(obs)
	for _, kind := range a.Windows {
		window, ok := windows[kind]
		if !ok || !strictLazyWindow(now, window) {
			return false
		}
	}
	return true
}

func activationWindowConfirmed(window quotaWindow, now time.Time) bool {
	if window.UsedPercent == nil || window.WindowSeconds <= 0 || !window.ResetAt.After(now) {
		return false
	}
	return *window.UsedPercent > 0 || (*window.UsedPercent == 0 && window.ResetAt.Before(now.Add(time.Duration(window.WindowSeconds)*time.Second-quotaLazyTolerance)))
}

// Only new, consecutive quota GETs can authorize a bounded recovery. The
// immediate post-send verification does not count, nor do passive snapshots.
func observeActivationRecovery(a *quotaActivationState, obs quotaObservation, now time.Time, interval time.Duration) {
	if !activationHasUnknownHTTP200(*a) || a.SendIntent || a.Attempts == 0 || a.Attempts >= quotaMaxActivationTries ||
		a.LastAttemptAt.IsZero() || now.Before(a.LastAttemptAt.Add(interval)) || !activationWindowsAreLazy(*a, obs, now) {
		resetActivationRecovery(a)
		return
	}
	windows := observationWindows(obs)
	if len(a.RecoveryObservations) == 0 {
		a.RecoveryObservations = make(map[quotaWindowKind]quotaWindowBaseline, len(a.Windows))
		for _, kind := range a.Windows {
			a.RecoveryObservations[kind] = baselineFromWindow(windows[kind], now)
		}
		a.RetryAllowed = false
		return
	}
	ready := true
	for _, kind := range a.Windows {
		previous, ok := a.RecoveryObservations[kind]
		window := windows[kind]
		if !ok || previous.WindowSeconds != window.WindowSeconds || now.Before(previous.ObservedAt) || window.ResetAt.Before(previous.ResetAt) {
			resetActivationRecovery(a)
			return
		}
		if now.Before(previous.ObservedAt.Add(interval)) || !window.ResetAt.After(previous.ResetAt.Add(quotaResetShift)) {
			ready = false
		}
	}
	a.RetryAllowed = ready
}

func alignActivationDeadline(runtime *quotaAuthRuntime) {
	a := &runtime.Activation
	if a.Status == "confirmed" || a.Status == "attempts_exhausted" {
		a.NextCheckAt = time.Time{}
	} else if a.CycleID != "" {
		a.NextCheckAt = runtime.NextCheckAt
	}
}

package plugin

import (
	"testing"
	"time"
)

func TestQuotaManualGateEnforcesKeyAuthAndGlobalLimits(t *testing.T) {
	clock := time.Date(2030, 9, 15, 16, 0, 0, 0, time.UTC)
	gate := newQuotaOperationCoordinator(func() time.Time { return clock })
	release, state := gate.acquireManual("key-a", "auth-a", time.Time{})
	if !state.Acquired {
		t.Fatalf("first acquire=%#v", state)
	}
	if _, sameKey := gate.acquireManual("key-a", "auth-b", time.Time{}); sameKey.Status != "cooldown" {
		t.Fatalf("same-key cooldown=%#v", sameKey)
	}
	if _, sameAuth := gate.acquireManual("key-b", "auth-a", time.Time{}); sameAuth.Status != "cooldown" {
		t.Fatalf("same-auth cooldown=%#v", sameAuth)
	}
	clock = clock.Add(61 * time.Second)
	if _, other := gate.acquireManual("key-b", "auth-b", time.Time{}); other.Status != "busy" {
		t.Fatalf("global GET gate=%#v", other)
	}
	release()
	clock = clock.Add(61 * time.Second)
	releaseOther, ready := gate.acquireManual("key-b", "auth-b", time.Time{})
	if !ready.Acquired {
		t.Fatalf("gate did not reopen=%#v", ready)
	}
	releaseOther()
}

func TestQuotaManualGateHonorsLongerRetryAfter(t *testing.T) {
	clock := time.Date(2030, 9, 15, 17, 0, 0, 0, time.UTC)
	gate := newQuotaOperationCoordinator(func() time.Time { return clock })
	backoff := clock.Add(20 * time.Minute)
	_, state := gate.acquireManual("key", "auth", backoff)
	if state.Status != "cooldown" || !state.RetryAt.Equal(backoff) {
		t.Fatalf("retry-after state=%#v", state)
	}
}

func TestQuotaBackgroundGETGetsPriorityOverNewManualRequest(t *testing.T) {
	clock := time.Date(2030, 9, 15, 18, 0, 0, 0, time.UTC)
	gate := newQuotaOperationCoordinator(func() time.Time { return clock })
	releaseManual, state := gate.acquireManual("key-a", "auth-a", time.Time{})
	if !state.Acquired {
		t.Fatal("manual acquire failed")
	}
	backgroundReady := make(chan func(), 1)
	go func() {
		release, ok := gate.acquireBackgroundGET()
		if !ok {
			backgroundReady <- nil
			return
		}
		backgroundReady <- release
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		gate.mu.Lock()
		pending := gate.pendingBackgroundGET
		gate.mu.Unlock()
		if pending > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	clock = clock.Add(61 * time.Second)
	if _, manual := gate.acquireManual("key-b", "auth-b", time.Time{}); manual.Status != "busy" {
		t.Fatalf("manual bypassed pending background GET=%#v", manual)
	}
	releaseManual()
	releaseBackground := <-backgroundReady
	if releaseBackground == nil {
		t.Fatal("background GET did not acquire after manual release")
	}
	releaseBackground()
}

package plugin

import "testing"

func TestConcurrencyTrackerKeyAdmissionIsIdempotentAndReleased(t *testing.T) {
	tracker := newConcurrencyTracker()
	if current, ok := tracker.acquireKey("request-1", "key-a", 1); !ok || current != 1 {
		t.Fatalf("first acquire = (%d, %v), want (1, true)", current, ok)
	}
	if current, ok := tracker.acquireKey("request-1", "key-a", 1); !ok || current != 1 {
		t.Fatalf("idempotent acquire = (%d, %v), want (1, true)", current, ok)
	}
	if current, ok := tracker.acquireKey("request-2", "key-a", 1); ok || current != 1 {
		t.Fatalf("full acquire = (%d, %v), want (1, false)", current, ok)
	}
	if !tracker.complete("request-1") {
		t.Fatal("first completion did not release")
	}
	if tracker.complete("request-1") {
		t.Fatal("duplicate completion released twice")
	}
	if current, ok := tracker.acquireKey("request-2", "key-a", 1); !ok || current != 1 {
		t.Fatalf("acquire after release = (%d, %v), want (1, true)", current, ok)
	}
}

func TestConcurrencyTrackerAuthAdmissionIsGlobalAndRetrySafe(t *testing.T) {
	tracker := newConcurrencyTracker()
	if _, ok := tracker.acquireKey("request-a", "key-a", 0); !ok {
		t.Fatal("request-a key acquire failed")
	}
	if _, ok := tracker.acquireKey("request-b", "key-b", 0); !ok {
		t.Fatal("request-b key acquire failed")
	}
	if current, ok := tracker.acquireAuth("request-a", "auth-1.json", 1); !ok || current != 1 {
		t.Fatalf("first auth acquire = (%d, %v)", current, ok)
	}
	if current, ok := tracker.acquireAuth("request-a", "auth-1.json", 1); !ok || current != 1 {
		t.Fatalf("same-auth retry = (%d, %v), want idempotent", current, ok)
	}
	if current, ok := tracker.acquireAuth("request-b", "auth-1.json", 1); ok || current != 1 {
		t.Fatalf("global auth limit = (%d, %v), want full", current, ok)
	}
	if current, ok := tracker.acquireAuth("request-a", "auth-2.json", 1); !ok || current != 1 {
		t.Fatalf("different-auth retry = (%d, %v)", current, ok)
	}
	if tracker.authCurrent("auth-1.json") != 1 || tracker.authCurrent("auth-2.json") != 1 {
		t.Fatalf("retry slots = %+v", tracker.snapshot().Auths)
	}
	tracker.complete("request-a")
	if len(tracker.snapshot().Auths) != 0 {
		t.Fatalf("auth slots not released: %+v", tracker.snapshot().Auths)
	}
}

func TestConcurrencyTrackerCountsUnlimitedRequestsForHotLimit(t *testing.T) {
	tracker := newConcurrencyTracker()
	if _, ok := tracker.acquireKey("request-1", "key-a", 0); !ok {
		t.Fatal("unlimited request was not tracked")
	}
	if _, ok := tracker.acquireKey("request-2", "key-b", 0); !ok {
		t.Fatal("second unlimited request was not tracked")
	}
	if snapshot := tracker.snapshot(); snapshot.Total != 2 {
		t.Fatalf("snapshot total = %d, want 2 active requests", snapshot.Total)
	}
	if current, ok := tracker.acquireKey("request-3", "key-a", 1); ok || current != 1 {
		t.Fatalf("lowered limit admission = (%d, %v), want existing slot to block", current, ok)
	}
}

func TestConcurrencyTrackerExistingLeaseSurvivesLoweredLimits(t *testing.T) {
	tracker := newConcurrencyTracker()
	if _, ok := tracker.acquireKey("request-1", "key-a", 0); !ok {
		t.Fatal("request-1 key acquire failed")
	}
	if _, ok := tracker.acquireKey("request-2", "key-a", 0); !ok {
		t.Fatal("request-2 key acquire failed")
	}
	if current, ok := tracker.acquireKey("request-1", "key-a", 1); !ok || current != 2 {
		t.Fatalf("existing key lease after lowered limit = (%d, %v), want preserved at 2", current, ok)
	}
	if current, ok := tracker.acquireKey("request-3", "key-a", 1); ok || current != 2 {
		t.Fatalf("new key lease after lowered limit = (%d, %v), want blocked at 2", current, ok)
	}
	if _, ok := tracker.acquireAuth("request-1", "auth-a", 0); !ok {
		t.Fatal("request-1 auth acquire failed")
	}
	if _, ok := tracker.acquireAuth("request-2", "auth-a", 0); !ok {
		t.Fatal("request-2 auth acquire failed")
	}
	if current, ok := tracker.acquireAuth("request-1", "auth-a", 1); !ok || current != 2 {
		t.Fatalf("existing auth lease after lowered limit = (%d, %v), want preserved at 2", current, ok)
	}
}

func TestConcurrencyTrackerPerCallMarkerIsExactlyOnce(t *testing.T) {
	tracker := newConcurrencyTracker()
	if _, ok := tracker.acquireKey("request-1", "key-a", 0); !ok {
		t.Fatal("key acquire failed")
	}
	if !tracker.markPerCallCharged("request-1") {
		t.Fatal("first marker was not accepted")
	}
	if tracker.markPerCallCharged("request-1") {
		t.Fatal("duplicate marker was accepted")
	}
}

func TestConcurrencyTrackerStopAcceptingPreservesOccupiedSlots(t *testing.T) {
	tracker := newConcurrencyTracker()
	if _, ok := tracker.acquireKey("request-1", "key-a", 0); !ok {
		t.Fatal("initial acquire failed")
	}
	tracker.stopAccepting()
	if current, ok := tracker.acquireKey("request-2", "key-a", 0); ok || current != 1 {
		t.Fatalf("acquire after stop = (%d, %v), want blocked with occupied slot preserved", current, ok)
	}
	if !tracker.complete("request-1") || tracker.keyCurrent("key-a") != 0 {
		t.Fatal("completion after stop did not release occupied slot")
	}
}

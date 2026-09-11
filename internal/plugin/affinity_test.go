package plugin

import (
	"testing"
	"time"
)

func TestAffinityCommitsOnlyAfterAcceptedAfterAuth(t *testing.T) {
	now := time.Unix(1_000, 0)
	cache := newAffinityCache(func() time.Time { return now }, time.Hour, 10)
	cache.propose("session-route", "proposal", "auth-a")
	if got := cache.boundAuth("session-route"); got != "" {
		t.Fatalf("pending auth committed early: %q", got)
	}
	cache.resolveProposal("proposal", false)
	if got := cache.boundAuth("session-route"); got != "" {
		t.Fatalf("rejected auth committed: %q", got)
	}
	cache.propose("session-route", "proposal", "auth-b")
	cache.resolveProposal("proposal", true)
	if got := cache.boundAuth("session-route"); got != "auth-b" {
		t.Fatalf("committed auth = %q, want auth-b", got)
	}
}

func TestAffinityPendingChoiceCoordinatesConcurrentFirstRequests(t *testing.T) {
	now := time.Unix(2_000, 0)
	cache := newAffinityCache(func() time.Time { return now }, time.Hour, 10)
	available := map[string]struct{}{"auth-a": {}, "auth-b": {}}
	cache.propose("session-route", "proposal", "auth-a")
	if got, ok := cache.use("session-route", available, func(string) string { return "proposal" }); !ok || got != "auth-a" {
		t.Fatalf("pending reuse = (%q, %v), want auth-a", got, ok)
	}
	cache.resolveProposal("proposal", false)
	if got := cache.boundAuth("session-route"); got != "" {
		t.Fatalf("first rejection committed auth: %q", got)
	}
	cache.resolveProposal("proposal", true)
	if got := cache.boundAuth("session-route"); got != "auth-a" {
		t.Fatalf("second accepted request did not commit pending auth: %q", got)
	}
}

func TestAffinityLateProposalCannotOverwriteNewerRevision(t *testing.T) {
	now := time.Unix(3_000, 0)
	cache := newAffinityCache(func() time.Time { return now }, time.Hour, 10)
	cache.propose("session-route", "proposal-old", "auth-a")
	cache.propose("session-route", "proposal-new", "auth-b")
	cache.resolveProposal("proposal-old", true)
	if got := cache.boundAuth("session-route"); got != "" {
		t.Fatalf("late old proposal committed over newer pending revision: %q", got)
	}
	cache.resolveProposal("proposal-new", true)
	if got := cache.boundAuth("session-route"); got != "auth-b" {
		t.Fatalf("new proposal committed auth = %q, want auth-b", got)
	}
}

func TestAffinityHonorsAvailabilityTTLAndCapacity(t *testing.T) {
	now := time.Unix(4_000, 0)
	cache := newAffinityCache(func() time.Time { return now }, time.Minute, 1)
	cache.propose("session-a", "proposal-a", "auth-a")
	cache.resolveProposal("proposal-a", true)
	if _, ok := cache.use("session-a", map[string]struct{}{"auth-b": {}}, func(string) string { return "reuse" }); ok {
		t.Fatal("affinity reused an auth outside the available pool")
	}
	cache.propose("session-b", "proposal-b", "auth-b")
	cache.resolveProposal("proposal-b", true)
	if cache.size() != 1 {
		t.Fatalf("cache size = %d, want capacity 1", cache.size())
	}
	now = now.Add(2 * time.Minute)
	if cache.size() != 0 {
		t.Fatalf("expired cache size = %d, want 0", cache.size())
	}
}

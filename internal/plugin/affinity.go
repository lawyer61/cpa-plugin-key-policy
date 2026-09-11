package plugin

import (
	"strings"
	"sync"
	"time"
)

const affinityProposalTTL = 2 * time.Minute

// affinityCache keeps only hashed session routing keys and auth IDs. Committed
// bindings are updated only after request.intercept_after accepted the selected
// auth. A pending choice coordinates concurrent first requests without claiming
// success before the final auth concurrency gate.
type affinityCache struct {
	mu        sync.Mutex
	now       func() time.Time
	ttl       time.Duration
	capacity  int
	revision  uint64
	entries   map[string]affinityEntry
	pending   map[string]pendingAffinity
	proposals map[string][]affinityProposal
}

type affinityEntry struct {
	authID   string
	revision uint64
	lastUsed time.Time
}

type pendingAffinity struct {
	authID   string
	revision uint64
	users    int
	lastUsed time.Time
}

type affinityProposal struct {
	affinityKey string
	authID      string
	revision    uint64
	createdAt   time.Time
}

func newAffinityCache(now func() time.Time, ttl time.Duration, capacity int) *affinityCache {
	if now == nil {
		now = time.Now
	}
	cache := &affinityCache{
		now:       now,
		entries:   make(map[string]affinityEntry),
		pending:   make(map[string]pendingAffinity),
		proposals: make(map[string][]affinityProposal),
	}
	cache.configure(ttl, capacity)
	return cache
}

func (c *affinityCache) configure(ttl time.Duration, capacity int) {
	if c == nil {
		return
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	if capacity <= 0 {
		capacity = 10_000
	}
	c.mu.Lock()
	c.ttl = ttl
	c.capacity = capacity
	c.cleanupLocked(c.now())
	c.mu.Unlock()
}

// use returns a committed or coordinated pending auth when it is part of the
// caller's currently available pool. A pending reuse creates one proposal token
// so its after-auth result can confirm or reject that revision.
func (c *affinityCache) use(affinityKey string, available map[string]struct{}, proposalKey func(string) string) (string, bool) {
	if c == nil || affinityKey == "" || len(available) == 0 {
		return "", false
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(now)
	if entry, ok := c.entries[affinityKey]; ok {
		if _, allowed := available[entry.authID]; allowed {
			entry.lastUsed = now
			c.entries[affinityKey] = entry
			return entry.authID, true
		}
	}
	if pending, ok := c.pending[affinityKey]; ok {
		if _, allowed := available[pending.authID]; allowed {
			pending.users++
			pending.lastUsed = now
			c.pending[affinityKey] = pending
			key := ""
			if proposalKey != nil {
				key = proposalKey(pending.authID)
			}
			c.appendProposalLocked(key, affinityProposal{
				affinityKey: affinityKey,
				authID:      pending.authID,
				revision:    pending.revision,
				createdAt:   now,
			})
			return pending.authID, true
		}
	}
	return "", false
}

// propose records a provisional binding. A newer proposal supersedes an older
// pending revision, while the last committed binding remains available if the
// provisional choice is later rejected.
func (c *affinityCache) propose(affinityKey, proposalKey, authID string) {
	if c == nil {
		return
	}
	affinityKey = strings.TrimSpace(affinityKey)
	proposalKey = strings.TrimSpace(proposalKey)
	authID = strings.TrimSpace(authID)
	if affinityKey == "" || proposalKey == "" || authID == "" {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(now)
	c.revision++
	revision := c.revision
	c.pending[affinityKey] = pendingAffinity{
		authID:   authID,
		revision: revision,
		users:    1,
		lastUsed: now,
	}
	c.appendProposalLocked(proposalKey, affinityProposal{
		affinityKey: affinityKey,
		authID:      authID,
		revision:    revision,
		createdAt:   now,
	})
	c.enforceCapacityLocked()
}

// resolveProposal consumes one scheduler proposal. Accepted proposals become
// committed only when their revision is still current. Rejected or late
// proposals cannot delete or overwrite a newer decision.
func (c *affinityCache) resolveProposal(proposalKey string, accepted bool) {
	if c == nil {
		return
	}
	proposalKey = strings.TrimSpace(proposalKey)
	if proposalKey == "" {
		return
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(now)
	queue := c.proposals[proposalKey]
	if len(queue) == 0 {
		return
	}
	proposal := queue[0]
	if len(queue) == 1 {
		delete(c.proposals, proposalKey)
	} else {
		c.proposals[proposalKey] = queue[1:]
	}
	pending, current := c.pending[proposal.affinityKey]
	if !current || pending.revision != proposal.revision || pending.authID != proposal.authID {
		return
	}
	if accepted {
		if existing, ok := c.entries[proposal.affinityKey]; !ok || existing.revision <= proposal.revision {
			c.entries[proposal.affinityKey] = affinityEntry{
				authID:   proposal.authID,
				revision: proposal.revision,
				lastUsed: now,
			}
		}
		delete(c.pending, proposal.affinityKey)
		c.enforceCapacityLocked()
		return
	}
	pending.users--
	if pending.users <= 0 {
		delete(c.pending, proposal.affinityKey)
	} else {
		c.pending[proposal.affinityKey] = pending
	}
}

func (c *affinityCache) boundAuth(affinityKey string) string {
	if c == nil {
		return ""
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(now)
	return c.entries[affinityKey].authID
}

func (c *affinityCache) size() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(c.now())
	return len(c.entries)
}

func (c *affinityCache) appendProposalLocked(key string, proposal affinityProposal) {
	if key == "" {
		return
	}
	c.proposals[key] = append(c.proposals[key], proposal)
	maxProposals := c.capacity * 2
	if maxProposals < 1 {
		maxProposals = 1
	}
	for c.proposalCountLocked() > maxProposals {
		oldestKey := ""
		var oldest time.Time
		for proposalKey, queue := range c.proposals {
			if len(queue) == 0 {
				continue
			}
			if oldestKey == "" || queue[0].createdAt.Before(oldest) {
				oldestKey = proposalKey
				oldest = queue[0].createdAt
			}
		}
		if oldestKey == "" {
			break
		}
		queue := c.proposals[oldestKey]
		if len(queue) <= 1 {
			delete(c.proposals, oldestKey)
		} else {
			c.proposals[oldestKey] = queue[1:]
		}
	}
}

func (c *affinityCache) proposalCountLocked() int {
	total := 0
	for _, queue := range c.proposals {
		total += len(queue)
	}
	return total
}

func (c *affinityCache) cleanupLocked(now time.Time) {
	for key, entry := range c.entries {
		if now.Sub(entry.lastUsed) >= c.ttl {
			delete(c.entries, key)
		}
	}
	for key, pending := range c.pending {
		if now.Sub(pending.lastUsed) >= affinityProposalTTL {
			delete(c.pending, key)
		}
	}
	for key, queue := range c.proposals {
		kept := queue[:0]
		for _, proposal := range queue {
			if now.Sub(proposal.createdAt) < affinityProposalTTL {
				kept = append(kept, proposal)
			}
		}
		if len(kept) == 0 {
			delete(c.proposals, key)
		} else {
			c.proposals[key] = kept
		}
	}
	c.enforceCapacityLocked()
}

func (c *affinityCache) enforceCapacityLocked() {
	for len(c.entries) > c.capacity {
		oldestKey := ""
		var oldest time.Time
		for key, entry := range c.entries {
			if oldestKey == "" || entry.lastUsed.Before(oldest) {
				oldestKey = key
				oldest = entry.lastUsed
			}
		}
		delete(c.entries, oldestKey)
	}
	for len(c.pending) > c.capacity {
		oldestKey := ""
		var oldest time.Time
		for key, entry := range c.pending {
			if oldestKey == "" || entry.lastUsed.Before(oldest) {
				oldestKey = key
				oldest = entry.lastUsed
			}
		}
		delete(c.pending, oldestKey)
	}
}

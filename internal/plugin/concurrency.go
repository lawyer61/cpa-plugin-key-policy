package plugin

import (
	"strings"
	"sync"
)

// concurrencyTracker owns process-local in-flight accounting. Every controlled
// request is counted even when its current limit is unlimited, so lowering a
// limit during a hot reconfigure immediately gates new work without forgetting
// already occupied slots.
type concurrencyTracker struct {
	mu                   sync.Mutex
	requests             map[string]*requestConcurrencyLease
	activations          map[string]string
	keyCounts            map[string]int
	authCounts           map[string]int
	authActivationCounts map[string]int
	accepting            bool
}

type requestConcurrencyLease struct {
	keyID          string
	authIDs        map[string]struct{}
	perCallCharged bool
}

type concurrencySnapshot struct {
	Total           int
	ActivationTotal int
	Keys            map[string]int
	Auths           map[string]int
	AuthActivations map[string]int
}

func newConcurrencyTracker() *concurrencyTracker {
	return &concurrencyTracker{
		requests:             make(map[string]*requestConcurrencyLease),
		activations:          make(map[string]string),
		keyCounts:            make(map[string]int),
		authCounts:           make(map[string]int),
		authActivationCounts: make(map[string]int),
		accepting:            true,
	}
}

// acquireKey is atomic and idempotent by host RequestID. A reused RequestID may
// only refer to the same key.
func (t *concurrencyTracker) acquireKey(requestID, keyID string, limit int) (int, bool) {
	if t == nil {
		return 0, false
	}
	requestID = strings.TrimSpace(requestID)
	keyID = strings.TrimSpace(keyID)
	if requestID == "" || keyID == "" {
		return 0, false
	}
	if limit < 0 {
		limit = 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.accepting {
		return t.keyCounts[keyID], false
	}
	if lease := t.requests[requestID]; lease != nil {
		if lease.keyID != keyID {
			return t.keyCounts[keyID], false
		}
		// Hot-lowering a limit gates new leases, but never interrupts an
		// execution that already owns this request ID.
		return t.keyCounts[keyID], true
	}
	current := t.keyCounts[keyID]
	if limit > 0 && current >= limit {
		return current, false
	}
	t.requests[requestID] = &requestConcurrencyLease{
		keyID:   keyID,
		authIDs: make(map[string]struct{}),
	}
	current++
	t.keyCounts[keyID] = current
	return current, true
}

// acquireAuth atomically attaches an auth slot to an existing request lease.
// Retries selecting the same auth are idempotent; retries selecting a different
// auth retain both slots until completion so an uncertain prior attempt is never
// released early.
func (t *concurrencyTracker) acquireAuth(requestID, authID string, limit int) (int, bool) {
	if t == nil {
		return 0, false
	}
	requestID = strings.TrimSpace(requestID)
	authID = strings.TrimSpace(authID)
	if requestID == "" || authID == "" {
		return 0, false
	}
	if limit < 0 {
		limit = 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	lease := t.requests[requestID]
	if lease == nil {
		return t.authCounts[authID], false
	}
	if _, exists := lease.authIDs[authID]; exists {
		// Repeated after-auth notifications for an already occupied credential
		// remain idempotent even when an operator lowers the live limit.
		return t.authCounts[authID], true
	}
	current := t.authCounts[authID]
	if limit > 0 && current >= limit {
		return current, false
	}
	lease.authIDs[authID] = struct{}{}
	current++
	t.authCounts[authID] = current
	return current, true
}

func (t *concurrencyTracker) authAvailable(authID string, limit int) bool {
	if t == nil || limit <= 0 {
		return true
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.accepting {
		return false
	}
	return t.authCounts[authID] < limit
}

// acquireActivation reserves an auth-only slot for one internal compact
// activation request. It shares authCounts with controlled business traffic
// but never creates a key lease or consumes a key limit.
func (t *concurrencyTracker) acquireActivation(leaseID, authID string, limit int) (int, bool) {
	if t == nil {
		return 0, false
	}
	leaseID = strings.TrimSpace(leaseID)
	authID = strings.TrimSpace(authID)
	if leaseID == "" || authID == "" {
		return 0, false
	}
	if limit < 0 {
		limit = 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.accepting {
		return t.authCounts[authID], false
	}
	if existing, ok := t.activations[leaseID]; ok {
		return t.authCounts[authID], existing == authID
	}
	current := t.authCounts[authID]
	if limit > 0 && current >= limit {
		return current, false
	}
	t.activations[leaseID] = authID
	t.authCounts[authID] = current + 1
	t.authActivationCounts[authID]++
	return current + 1, true
}

func (t *concurrencyTracker) releaseActivation(leaseID string) bool {
	if t == nil {
		return false
	}
	leaseID = strings.TrimSpace(leaseID)
	if leaseID == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	authID, ok := t.activations[leaseID]
	if !ok {
		return false
	}
	delete(t.activations, leaseID)
	decrementCount(t.authCounts, authID)
	decrementCount(t.authActivationCounts, authID)
	return true
}

func (t *concurrencyTracker) requestKey(requestID string) string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if lease := t.requests[strings.TrimSpace(requestID)]; lease != nil {
		return lease.keyID
	}
	return ""
}

// markPerCallCharged returns true exactly once for a live request lease.
func (t *concurrencyTracker) markPerCallCharged(requestID string) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	lease := t.requests[strings.TrimSpace(requestID)]
	if lease == nil || lease.perCallCharged {
		return false
	}
	lease.perCallCharged = true
	return true
}

// complete releases all key and auth slots exactly once.
func (t *concurrencyTracker) complete(requestID string) bool {
	if t == nil {
		return false
	}
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	lease := t.requests[requestID]
	if lease == nil {
		return false
	}
	delete(t.requests, requestID)
	decrementCount(t.keyCounts, lease.keyID)
	for authID := range lease.authIDs {
		decrementCount(t.authCounts, authID)
	}
	return true
}

func (t *concurrencyTracker) keyCurrent(keyID string) int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.keyCounts[strings.TrimSpace(keyID)]
}

func (t *concurrencyTracker) authCurrent(authID string) int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.authCounts[strings.TrimSpace(authID)]
}

func (t *concurrencyTracker) snapshot() concurrencySnapshot {
	out := concurrencySnapshot{Keys: map[string]int{}, Auths: map[string]int{}, AuthActivations: map[string]int{}}
	if t == nil {
		return out
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out.Total = len(t.requests)
	out.ActivationTotal = len(t.activations)
	for key, value := range t.keyCounts {
		out.Keys[key] = value
	}
	for key, value := range t.authCounts {
		out.Auths[key] = value
	}
	for key, value := range t.authActivationCounts {
		out.AuthActivations[key] = value
	}
	return out
}

func (t *concurrencyTracker) stopAccepting() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.accepting = false
	t.mu.Unlock()
}

func decrementCount(counts map[string]int, key string) {
	if key == "" {
		return
	}
	if counts[key] <= 1 {
		delete(counts, key)
		return
	}
	counts[key]--
}

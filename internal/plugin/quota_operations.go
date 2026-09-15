package plugin

import (
	"strings"
	"sync"
	"time"
)

const lookupQuotaManualCooldown = 60 * time.Second

type quotaManualGateState struct {
	Status   string
	RetryAt  time.Time
	Acquired bool
}

// quotaOperationCoordinator serializes proactive quota GETs and prevents a
// manual lookup from racing one auth's background review/activation sequence.
// Background work may wait; public manual requests never queue.
type quotaOperationCoordinator struct {
	mu   sync.Mutex
	cond *sync.Cond

	now                   func() time.Time
	stopped               bool
	activeAuth            map[string]string
	pendingBackgroundAuth map[string]int
	backgroundOps         int
	getActive             bool
	pendingBackgroundGET  int
	lastKeyAttempt        map[string]time.Time
	lastAuthAttempt       map[string]time.Time
}

func newQuotaOperationCoordinator(now func() time.Time) *quotaOperationCoordinator {
	if now == nil {
		now = time.Now
	}
	coordinator := &quotaOperationCoordinator{
		now:                   now,
		activeAuth:            make(map[string]string),
		pendingBackgroundAuth: make(map[string]int),
		lastKeyAttempt:        make(map[string]time.Time),
		lastAuthAttempt:       make(map[string]time.Time),
	}
	coordinator.cond = sync.NewCond(&coordinator.mu)
	return coordinator
}

func (c *quotaOperationCoordinator) stop() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.stopped = true
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *quotaOperationCoordinator) acquireBackgroundAuth(authID string) (func(), bool) {
	if c == nil {
		return func() {}, true
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return nil, false
	}
	c.mu.Lock()
	c.pendingBackgroundAuth[authID]++
	c.backgroundOps++
	for !c.stopped && c.activeAuth[authID] != "" {
		c.cond.Wait()
	}
	c.pendingBackgroundAuth[authID]--
	if c.pendingBackgroundAuth[authID] == 0 {
		delete(c.pendingBackgroundAuth, authID)
	}
	if c.stopped {
		c.backgroundOps--
		c.mu.Unlock()
		return nil, false
	}
	c.activeAuth[authID] = "background"
	c.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			if c.activeAuth[authID] == "background" {
				delete(c.activeAuth, authID)
			}
			if c.backgroundOps > 0 {
				c.backgroundOps--
			}
			c.cond.Broadcast()
			c.mu.Unlock()
		})
	}, true
}

func (c *quotaOperationCoordinator) acquireBackgroundGET() (func(), bool) {
	if c == nil {
		return func() {}, true
	}
	c.mu.Lock()
	c.pendingBackgroundGET++
	for !c.stopped && c.getActive {
		c.cond.Wait()
	}
	c.pendingBackgroundGET--
	if c.stopped {
		c.cond.Broadcast()
		c.mu.Unlock()
		return nil, false
	}
	c.getActive = true
	c.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			c.getActive = false
			c.cond.Broadcast()
			c.mu.Unlock()
		})
	}, true
}

func (c *quotaOperationCoordinator) manualState(keyID, authID string, backoff time.Time) quotaManualGateState {
	if c == nil {
		return quotaManualGateState{Status: "ready"}
	}
	now := c.now()
	keyID = strings.TrimSpace(keyID)
	authID = strings.TrimSpace(authID)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneCooldownsLocked(now)
	return c.manualStateLocked(keyID, authID, backoff, now)
}

func (c *quotaOperationCoordinator) acquireManual(keyID, authID string, backoff time.Time) (func(), quotaManualGateState) {
	if c == nil {
		return func() {}, quotaManualGateState{Status: "ready", Acquired: true}
	}
	now := c.now()
	keyID = strings.TrimSpace(keyID)
	authID = strings.TrimSpace(authID)
	c.mu.Lock()
	c.pruneCooldownsLocked(now)
	state := c.manualStateLocked(keyID, authID, backoff, now)
	if state.Status != "ready" {
		c.mu.Unlock()
		return nil, state
	}
	c.activeAuth[authID] = "manual"
	c.getActive = true
	c.lastKeyAttempt[keyID] = now
	c.lastAuthAttempt[authID] = now
	c.mu.Unlock()
	state.Acquired = true
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			if c.activeAuth[authID] == "manual" {
				delete(c.activeAuth, authID)
			}
			c.getActive = false
			c.lastAuthAttempt[authID] = c.now()
			c.cond.Broadcast()
			c.mu.Unlock()
		})
	}, state
}

func (c *quotaOperationCoordinator) noteAuthAttempt(authID string) {
	if c == nil {
		return
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return
	}
	c.mu.Lock()
	c.lastAuthAttempt[authID] = c.now()
	c.mu.Unlock()
}

func (c *quotaOperationCoordinator) pruneCooldownsLocked(now time.Time) {
	cutoff := now.Add(-lookupQuotaManualCooldown)
	for keyID, attemptedAt := range c.lastKeyAttempt {
		if !attemptedAt.After(cutoff) {
			delete(c.lastKeyAttempt, keyID)
		}
	}
	for authID, attemptedAt := range c.lastAuthAttempt {
		if !attemptedAt.After(cutoff) && c.activeAuth[authID] == "" {
			delete(c.lastAuthAttempt, authID)
		}
	}
}

func (c *quotaOperationCoordinator) manualStateLocked(keyID, authID string, backoff, now time.Time) quotaManualGateState {
	if c.stopped || keyID == "" || authID == "" {
		return quotaManualGateState{Status: "transport_unavailable"}
	}
	retryAt := backoff
	if last := c.lastKeyAttempt[keyID]; !last.IsZero() && last.Add(lookupQuotaManualCooldown).After(retryAt) {
		retryAt = last.Add(lookupQuotaManualCooldown)
	}
	if last := c.lastAuthAttempt[authID]; !last.IsZero() && last.Add(lookupQuotaManualCooldown).After(retryAt) {
		retryAt = last.Add(lookupQuotaManualCooldown)
	}
	if retryAt.After(now) {
		return quotaManualGateState{Status: "cooldown", RetryAt: retryAt}
	}
	if c.activeAuth[authID] != "" || c.pendingBackgroundAuth[authID] > 0 || c.backgroundOps > 0 || c.getActive || c.pendingBackgroundGET > 0 {
		return quotaManualGateState{Status: "busy"}
	}
	return quotaManualGateState{Status: "ready"}
}

package plugin

import (
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	quotaFiveHourSeconds int64 = 5 * 60 * 60
	quotaWeeklySeconds   int64 = 7 * 24 * 60 * 60
	quotaMinMonthSeconds int64 = 28 * 24 * 60 * 60
	quotaMaxMonthSeconds int64 = 31 * 24 * 60 * 60
	quotaCacheCapacity         = 4096
)

type quotaWindowKind string

const (
	quotaWindowUnknown quotaWindowKind = "unknown"
	quotaWindowShort   quotaWindowKind = "five_hour"
	quotaWindowWeekly  quotaWindowKind = "weekly"
	quotaWindowMonthly quotaWindowKind = "monthly"
)

type quotaAvailability uint8

const (
	quotaAvailabilityUnknown quotaAvailability = iota
	quotaAvailabilityReady
	quotaAvailabilityExhausted
)

type quotaWindow struct {
	Kind          quotaWindowKind `json:"kind"`
	UsedPercent   *float64        `json:"used_percent,omitempty"`
	WindowSeconds int64           `json:"window_seconds,omitempty"`
	ResetAt       time.Time       `json:"reset_at,omitempty"`
	Exhausted     bool            `json:"exhausted,omitempty"`
}

func (w quotaWindow) remainingPercent() float64 {
	if w.UsedPercent == nil {
		return 0
	}
	return math.Max(0, 100-*w.UsedPercent)
}

type quotaObservation struct {
	AuthID                string       `json:"auth_id"`
	AuthIndex             string       `json:"auth_index,omitempty"`
	CredentialFingerprint string       `json:"credential_fingerprint,omitempty"`
	Provider              string       `json:"provider"`
	PlanType              string       `json:"plan_type,omitempty"`
	Source                string       `json:"source"`
	ObservedAt            time.Time    `json:"observed_at"`
	ReceivedAt            time.Time    `json:"received_at"`
	Short                 *quotaWindow `json:"short,omitempty"`
	Long                  *quotaWindow `json:"long,omitempty"`
	ExplicitExhausted     bool         `json:"explicit_exhausted,omitempty"`
	ExplicitAvailable     bool         `json:"explicit_available,omitempty"`
	ExplicitExhaustedAt   time.Time    `json:"explicit_exhausted_at,omitempty"`
	ExplicitResetAt       time.Time    `json:"explicit_reset_at,omitempty"`
	ExplicitReason        string       `json:"explicit_reason,omitempty"`
}

func (o quotaObservation) knownPositive() bool {
	if !validQuotaWindow(o.Long, true) || o.Long.Exhausted || *o.Long.UsedPercent >= 100 {
		return false
	}
	return o.Short == nil || (validQuotaWindow(o.Short, false) && !o.Short.Exhausted && o.Short.UsedPercent != nil && *o.Short.UsedPercent < 100)
}

type quotaCache struct {
	mu     sync.RWMutex
	now    func() time.Time
	byAuth map[string]quotaObservation
}

func newQuotaCache(now func() time.Time) *quotaCache {
	if now == nil {
		now = time.Now
	}
	return &quotaCache{now: now, byAuth: make(map[string]quotaObservation)}
}

func (c *quotaCache) observe(authID, authIndex, source string, next quotaObservation) bool {
	if c == nil {
		return false
	}
	authID = strings.TrimSpace(authID)
	if authID == "" || !strings.EqualFold(strings.TrimSpace(next.Provider), "codex") {
		return false
	}
	now := c.now()
	if next.ObservedAt.IsZero() {
		next.ObservedAt = now
	}
	if next.ReceivedAt.IsZero() {
		next.ReceivedAt = now
	}
	next.AuthID = authID
	if strings.TrimSpace(authIndex) != "" {
		next.AuthIndex = strings.TrimSpace(authIndex)
	}
	next.Provider = "codex"
	next.Source = strings.TrimSpace(source)

	c.mu.Lock()
	defer c.mu.Unlock()
	current, exists := c.byAuth[authID]
	instanceChanged := exists && next.CredentialFingerprint != "" && current.CredentialFingerprint != "" && next.CredentialFingerprint != current.CredentialFingerprint
	identityUpgrade := exists && current.CredentialFingerprint == "" && next.CredentialFingerprint != ""
	identityOnly := next.Short == nil && next.Long == nil && !next.ExplicitExhausted && !next.ExplicitAvailable
	if exists && identityOnly && !instanceChanged {
		if next.AuthIndex != "" {
			current.AuthIndex = next.AuthIndex
		}
		if next.CredentialFingerprint != "" {
			current.CredentialFingerprint = next.CredentialFingerprint
		}
		if next.PlanType != "" {
			current.PlanType = next.PlanType
		}
		c.byAuth[authID] = cloneQuotaObservation(current)
		return false
	}
	if exists && !instanceChanged && next.ObservedAt.Before(current.ObservedAt) {
		if identityUpgrade {
			current.AuthIndex = next.AuthIndex
			current.CredentialFingerprint = next.CredentialFingerprint
			c.byAuth[authID] = cloneQuotaObservation(current)
		}
		return false
	}
	if exists && !instanceChanged {
		if next.AuthIndex == "" {
			next.AuthIndex = current.AuthIndex
		}
		if next.CredentialFingerprint == "" {
			next.CredentialFingerprint = current.CredentialFingerprint
		}
		// A newer, complete positive snapshot is the only normal observation
		// allowed to clear a prior explicit exhaustion signal.
		if current.ExplicitExhausted && (!next.ExplicitAvailable || !next.knownPositive() || next.ObservedAt.Before(current.ExplicitExhaustedAt)) {
			next.ExplicitExhausted = true
			next.ExplicitExhaustedAt = current.ExplicitExhaustedAt
			next.ExplicitResetAt = current.ExplicitResetAt
			next.ExplicitReason = current.ExplicitReason
		}
	}
	if !exists && len(c.byAuth) >= quotaCacheCapacity {
		c.evictOldestLocked(authID)
	}
	c.byAuth[authID] = cloneQuotaObservation(next)
	return true
}

func (c *quotaCache) markExplicitExhausted(authID, authIndex string, observedAt, resetAt time.Time, reason string) bool {
	if c == nil {
		return false
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return false
	}
	if observedAt.IsZero() {
		observedAt = c.now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	current := c.byAuth[authID]
	if current.AuthID == "" && len(c.byAuth) >= quotaCacheCapacity {
		c.evictOldestLocked(authID)
	}
	if !current.ExplicitExhaustedAt.IsZero() && observedAt.Before(current.ExplicitExhaustedAt) {
		return false
	}
	current.AuthID = authID
	if strings.TrimSpace(authIndex) != "" {
		current.AuthIndex = strings.TrimSpace(authIndex)
	}
	current.Provider = "codex"
	current.ExplicitExhausted = true
	current.ExplicitExhaustedAt = observedAt
	current.ExplicitResetAt = resetAt
	current.ExplicitReason = strings.TrimSpace(reason)
	if current.ObservedAt.IsZero() {
		current.ObservedAt = observedAt
	}
	current.ReceivedAt = c.now()
	c.byAuth[authID] = current
	return true
}

func (c *quotaCache) delete(authID string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.byAuth, strings.TrimSpace(authID))
	c.mu.Unlock()
}

func (c *quotaCache) evictOldestLocked(incomingID string) {
	oldestID := ""
	oldestAt := time.Time{}
	for authID, observation := range c.byAuth {
		if authID == incomingID {
			continue
		}
		at := observation.ReceivedAt
		if at.IsZero() {
			at = observation.ObservedAt
		}
		if oldestID == "" || at.Before(oldestAt) || (at.Equal(oldestAt) && authID < oldestID) {
			oldestID = authID
			oldestAt = at
		}
	}
	if oldestID != "" {
		delete(c.byAuth, oldestID)
	}
}

func (c *quotaCache) get(authID string) (quotaObservation, bool) {
	if c == nil {
		return quotaObservation{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	observation, ok := c.byAuth[strings.TrimSpace(authID)]
	return cloneQuotaObservation(observation), ok
}

func (c *quotaCache) replace(all map[string]quotaObservation) {
	if c == nil {
		return
	}
	type entry struct {
		authID      string
		observation quotaObservation
	}
	ordered := make([]entry, 0, len(all))
	for authID, observation := range all {
		authID = strings.TrimSpace(authID)
		if authID == "" || !strings.EqualFold(observation.Provider, "codex") {
			continue
		}
		observation.AuthID = authID
		ordered = append(ordered, entry{authID: authID, observation: observation})
	}
	sort.Slice(ordered, func(i, j int) bool {
		left := ordered[i].observation.ReceivedAt
		if left.IsZero() {
			left = ordered[i].observation.ObservedAt
		}
		right := ordered[j].observation.ReceivedAt
		if right.IsZero() {
			right = ordered[j].observation.ObservedAt
		}
		if !left.Equal(right) {
			return left.After(right)
		}
		return ordered[i].authID < ordered[j].authID
	})
	if len(ordered) > quotaCacheCapacity {
		ordered = ordered[:quotaCacheCapacity]
	}
	next := make(map[string]quotaObservation, len(ordered))
	for _, item := range ordered {
		next[item.authID] = cloneQuotaObservation(item.observation)
	}
	c.mu.Lock()
	c.byAuth = next
	c.mu.Unlock()
}

func (c *quotaCache) snapshot() map[string]quotaObservation {
	out := make(map[string]quotaObservation)
	if c == nil {
		return out
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for authID, observation := range c.byAuth {
		out[authID] = cloneQuotaObservation(observation)
	}
	return out
}

func (c *quotaCache) classify(authID string, ttl time.Duration, now time.Time) (quotaAvailability, quotaObservation) {
	observation, ok := c.get(authID)
	if !ok {
		return quotaAvailabilityUnknown, quotaObservation{}
	}
	return classifyQuotaObservation(observation, ttl, now), observation
}

func classifyQuotaObservation(observation quotaObservation, ttl time.Duration, now time.Time) quotaAvailability {
	if observation.ExplicitExhausted || windowExhausted(observation.Short) || windowExhausted(observation.Long) {
		return quotaAvailabilityExhausted
	}
	if !validQuotaWindow(observation.Long, true) || observation.ObservedAt.IsZero() {
		return quotaAvailabilityUnknown
	}
	if ttl <= 0 || observation.ObservedAt.After(now.Add(time.Minute)) || now.Sub(observation.ObservedAt) > ttl {
		return quotaAvailabilityUnknown
	}
	if !now.Before(observation.Long.ResetAt) {
		return quotaAvailabilityUnknown
	}
	if observation.Short != nil && (!validQuotaWindow(observation.Short, false) || !now.Before(observation.Short.ResetAt)) {
		return quotaAvailabilityUnknown
	}
	return quotaAvailabilityReady
}

func validQuotaWindow(window *quotaWindow, requireUsage bool) bool {
	if window == nil || window.Kind == quotaWindowUnknown || window.WindowSeconds <= 0 || window.ResetAt.IsZero() {
		return false
	}
	if window.UsedPercent == nil {
		return !requireUsage && window.Exhausted
	}
	return validUsedPercent(*window.UsedPercent)
}

func validUsedPercent(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 100
}

func windowExhausted(window *quotaWindow) bool {
	return window != nil && (window.Exhausted || (window.UsedPercent != nil && validUsedPercent(*window.UsedPercent) && *window.UsedPercent >= 100))
}

func cloneQuotaObservation(src quotaObservation) quotaObservation {
	dst := src
	if src.Short != nil {
		value := *src.Short
		if src.Short.UsedPercent != nil {
			used := *src.Short.UsedPercent
			value.UsedPercent = &used
		}
		dst.Short = &value
	}
	if src.Long != nil {
		value := *src.Long
		if src.Long.UsedPercent != nil {
			used := *src.Long.UsedPercent
			value.UsedPercent = &used
		}
		dst.Long = &value
	}
	return dst
}

func parseCodexQuotaHeaders(headers http.Header, observedAt time.Time) (quotaObservation, bool) {
	return parseCodexQuotaHeadersAt(headers, observedAt, observedAt)
}

// parseCodexQuotaHeadersAt separates the evidence timestamp from the anchor
// used for relative reset-after values. usage.handle runs after a request has
// completed, so a long SSE cannot safely use completion time as the moment its
// response headers arrived. Callers pass a zero relativeAnchor unless a valid
// HTTP Date (or another real response-time signal) is available.
func parseCodexQuotaHeadersAt(headers http.Header, observedAt, relativeAnchor time.Time) (quotaObservation, bool) {
	if len(headers) == 0 {
		return quotaObservation{}, false
	}
	observation := quotaObservation{Provider: "codex", Source: "passive-http", ObservedAt: observedAt}
	observation.PlanType = strings.TrimSpace(headers.Get("X-Codex-Plan-Type"))
	for _, name := range []string{"Primary", "Secondary"} {
		if window, ok := parseCodexHeaderWindow(headers, "X-Codex-"+name+"-", relativeAnchor); ok {
			assignQuotaWindow(&observation, window)
		}
	}
	if value, ok := parseHeaderBool(headers, "X-Codex-Allowed"); ok && !value {
		observation.ExplicitExhausted = true
		observation.ExplicitReason = "allowed_false"
	}
	if value, ok := parseHeaderBool(headers, "X-Codex-Allowed"); ok && value {
		observation.ExplicitAvailable = true
	}
	if value, ok := parseHeaderBool(headers, "X-Codex-Limit-Reached"); ok && value {
		observation.ExplicitExhausted = true
		observation.ExplicitReason = "limit_reached"
	}
	if value, ok := parseHeaderBool(headers, "X-Codex-Limit-Reached"); ok && !value {
		observation.ExplicitAvailable = true
	}
	if retryAfter, ok := parseRetryAfter(headers.Get("Retry-After"), relativeAnchor); ok {
		observation.ExplicitExhausted = true
		observation.ExplicitResetAt = retryAfter
		observation.ExplicitReason = "retry_after"
	}
	if observation.ExplicitExhausted {
		observation.ExplicitExhaustedAt = observedAt
	}
	ok := observation.Short != nil || observation.Long != nil || observation.ExplicitExhausted || observation.PlanType != ""
	return observation, ok
}

func parseCodexHeaderWindow(headers http.Header, prefix string, observedAt time.Time) (quotaWindow, bool) {
	window := quotaWindow{}
	found := false
	if value, ok := parseHeaderFloat(headers, prefix+"Used-Percent"); ok && validUsedPercent(value) {
		window.UsedPercent = &value
		window.Exhausted = value >= 100
		found = true
	}
	if minutes, ok := parseHeaderFloat(headers, prefix+"Window-Minutes"); ok && !math.IsNaN(minutes) && !math.IsInf(minutes, 0) && minutes > 0 && minutes <= float64(math.MaxInt64)/60 {
		window.WindowSeconds = int64(math.Round(minutes * 60))
		found = true
	}
	if raw := strings.TrimSpace(headers.Get(prefix + "Reset-At")); raw != "" {
		if resetAt, ok := parseQuotaTime(raw); ok {
			window.ResetAt = resetAt
			found = true
		}
	} else if seconds, ok := parseHeaderFloat(headers, prefix+"Reset-After-Seconds"); ok && !math.IsNaN(seconds) && !math.IsInf(seconds, 0) && seconds >= 0 && !observedAt.IsZero() {
		window.ResetAt = observedAt.Add(time.Duration(seconds * float64(time.Second)))
		found = true
	}
	if allowed, ok := parseHeaderBool(headers, prefix+"Allowed"); ok {
		window.Exhausted = window.Exhausted || !allowed
		found = true
	}
	if reached, ok := parseHeaderBool(headers, prefix+"Limit-Reached"); ok {
		window.Exhausted = window.Exhausted || reached
		found = true
	}
	window.Kind = classifyQuotaWindow(window.WindowSeconds)
	return window, found && window.Kind != quotaWindowUnknown
}

func parseCodexQuotaPayload(raw []byte, observedAt time.Time) (quotaObservation, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return quotaObservation{}, err
	}
	observation := quotaObservation{
		Provider:   "codex",
		Source:     "quota-get",
		ObservedAt: observedAt,
		PlanType:   mapString(doc, "plan_type", "planType"),
	}
	rateLimit, ok := mapChild(doc, "rate_limit", "rateLimit")
	if !ok {
		return observation, nil
	}
	envelopeExhausted := false
	if allowed, exists := mapBool(rateLimit, "allowed"); exists && !allowed {
		envelopeExhausted = true
	} else if exists && allowed {
		observation.ExplicitAvailable = true
	}
	if reached, exists := mapBool(rateLimit, "limit_reached", "limitReached"); exists && reached {
		envelopeExhausted = true
	} else if exists && !reached {
		observation.ExplicitAvailable = true
	}
	for _, names := range [][]string{{"primary_window", "primaryWindow"}, {"secondary_window", "secondaryWindow"}} {
		windowMap, exists := mapChild(rateLimit, names...)
		if !exists {
			continue
		}
		window := parseQuotaPayloadWindow(windowMap, observedAt, envelopeExhausted)
		assignQuotaWindow(&observation, window)
	}
	if envelopeExhausted && observation.Short == nil && observation.Long == nil {
		observation.ExplicitExhausted = true
		observation.ExplicitExhaustedAt = observedAt
		observation.ExplicitReason = "limit_reached"
	}
	return observation, nil
}

func parseQuotaPayloadWindow(raw map[string]any, observedAt time.Time, envelopeExhausted bool) quotaWindow {
	window := quotaWindow{Exhausted: envelopeExhausted}
	if used, ok := mapFloat(raw, "used_percent", "usedPercent"); ok && validUsedPercent(used) {
		window.UsedPercent = &used
		window.Exhausted = window.Exhausted || used >= 100
	}
	if seconds, ok := mapFloat(raw, "limit_window_seconds", "limitWindowSeconds"); ok && !math.IsNaN(seconds) && !math.IsInf(seconds, 0) && seconds > 0 && seconds <= float64(math.MaxInt64) && math.Trunc(seconds) == seconds {
		window.WindowSeconds = int64(seconds)
	}
	if allowed, ok := mapBool(raw, "allowed"); ok && !allowed {
		window.Exhausted = true
	}
	if reached, ok := mapBool(raw, "limit_reached", "limitReached"); ok && reached {
		window.Exhausted = true
	}
	if value, ok := mapAny(raw, "reset_at", "resetAt"); ok {
		if resetAt, ok := parseQuotaAnyTime(value); ok {
			window.ResetAt = resetAt
		}
	} else if seconds, ok := mapFloat(raw, "reset_after_seconds", "resetAfterSeconds"); ok && !math.IsNaN(seconds) && !math.IsInf(seconds, 0) && seconds >= 0 && !observedAt.IsZero() {
		window.ResetAt = observedAt.Add(time.Duration(seconds * float64(time.Second)))
	}
	window.Kind = classifyQuotaWindow(window.WindowSeconds)
	return window
}

func assignQuotaWindow(observation *quotaObservation, window quotaWindow) {
	if observation == nil {
		return
	}
	switch window.Kind {
	case quotaWindowShort:
		copy := window
		observation.Short = &copy
	case quotaWindowWeekly, quotaWindowMonthly:
		copy := window
		observation.Long = &copy
	}
}

func classifyQuotaWindow(seconds int64) quotaWindowKind {
	switch {
	case seconds == quotaFiveHourSeconds:
		return quotaWindowShort
	case seconds == quotaWeeklySeconds:
		return quotaWindowWeekly
	case seconds >= quotaMinMonthSeconds && seconds <= quotaMaxMonthSeconds:
		return quotaWindowMonthly
	default:
		return quotaWindowUnknown
	}
}

func parseHeaderFloat(headers http.Header, name string) (float64, bool) {
	value := strings.TrimSpace(headers.Get(name))
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(value, 64)
	return parsed, err == nil
}

func parseHeaderBool(headers http.Header, name string) (bool, bool) {
	value := strings.TrimSpace(headers.Get(name))
	if value == "" {
		return false, false
	}
	parsed, err := strconv.ParseBool(value)
	return parsed, err == nil
}

func parseRetryAfter(raw string, now time.Time) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil && seconds >= 0 && seconds <= int64(math.MaxInt64)/int64(time.Second) && !now.IsZero() {
		return now.Add(time.Duration(seconds) * time.Second), true
	}
	parsed, err := http.ParseTime(raw)
	return parsed, err == nil
}

func parseQuotaTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed, true
		}
	}
	if unix, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.Unix(unix, 0).UTC(), true
	}
	return time.Time{}, false
}

func parseQuotaAnyTime(raw any) (time.Time, bool) {
	switch value := raw.(type) {
	case string:
		return parseQuotaTime(value)
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > float64(math.MaxInt64) {
			return time.Time{}, false
		}
		return time.Unix(int64(value), 0).UTC(), true
	case json.Number:
		unix, err := value.Int64()
		return time.Unix(unix, 0).UTC(), err == nil
	default:
		return time.Time{}, false
	}
}

func mapAny(values map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			return value, true
		}
	}
	return nil, false
}

func mapChild(values map[string]any, keys ...string) (map[string]any, bool) {
	value, ok := mapAny(values, keys...)
	if !ok {
		return nil, false
	}
	child, ok := value.(map[string]any)
	return child, ok
}

func mapString(values map[string]any, keys ...string) string {
	value, ok := mapAny(values, keys...)
	if !ok {
		return ""
	}
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func mapFloat(values map[string]any, keys ...string) (float64, bool) {
	value, ok := mapAny(values, keys...)
	if !ok {
		return 0, false
	}
	switch number := value.(type) {
	case float64:
		return number, true
	case json.Number:
		parsed, err := number.Float64()
		return parsed, err == nil
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(number), 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func mapInt64(values map[string]any, keys ...string) (int64, bool) {
	value, ok := mapFloat(values, keys...)
	return int64(value), ok
}

func mapBool(values map[string]any, keys ...string) (bool, bool) {
	value, ok := mapAny(values, keys...)
	if !ok {
		return false, false
	}
	switch boolean := value.(type) {
	case bool:
		return boolean, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(boolean))
		return parsed, err == nil
	default:
		return false, false
	}
}

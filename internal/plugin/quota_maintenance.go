package plugin

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cpa-key-policy/internal/policy"
)

const (
	codexQuotaEndpoint      = "https://chatgpt.com/backend-api/wham/usage"
	codexActivationEndpoint = "https://chatgpt.com/backend-api/codex/responses"
	codexActivationProtocol = "responses-v1"
	codexQuotaUserAgent     = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
	quotaLazyTolerance      = 3 * time.Minute
	quotaResetShift         = 2 * time.Minute
	quotaMaxActivationTries = 2
)

type quotaManager struct {
	store         *policy.Store
	concurrency   *concurrencyTracker
	cache         *quotaCache
	now           func() time.Time
	verifyDelay   time.Duration
	testDurations func() (time.Duration, time.Duration)

	mu                   sync.Mutex
	host                 HostClient
	runtime              quotaRuntimeDocument
	runtimeStore         *quotaRuntimeStore
	persistenceBlocked   bool
	persistenceError     string
	lastError            string
	restartRoundDeadline bool
	configured           bool
	started              bool
	stopped              bool
	stopCh               chan struct{}
	doneCh               chan struct{}
	configCh             chan struct{}
}

func newQuotaManager(store *policy.Store, concurrency *concurrencyTracker, now func() time.Time) *quotaManager {
	if now == nil {
		now = time.Now
	}
	return &quotaManager{
		store:       store,
		concurrency: concurrency,
		cache:       newQuotaCache(now),
		now:         now,
		verifyDelay: 3 * time.Second,
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
		configCh:    make(chan struct{}, 1),
		runtime: quotaRuntimeDocument{
			Version:      quotaRuntimeVersion,
			Observations: make(map[string]quotaObservation),
			Auths:        make(map[string]quotaAuthRuntime),
		},
	}
}

func (m *quotaManager) setHostClient(host HostClient) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.host = host
	m.ensureStartedLocked()
	m.mu.Unlock()
}

func (m *quotaManager) configure(statePath string, restartDeadline bool) {
	if m == nil {
		return
	}
	path := quotaRuntimePath(statePath)
	m.mu.Lock()
	changed := m.runtimeStore == nil || m.runtimeStore.path != path
	m.configured = true
	if restartDeadline {
		m.restartRoundDeadline = true
	}
	m.mu.Unlock()
	if changed {
		m.loadRuntime(path)
	}
	m.mu.Lock()
	m.ensureStartedLocked()
	m.mu.Unlock()
	select {
	case m.configCh <- struct{}{}:
	default:
	}
}

func (m *quotaManager) ensureStartedLocked() {
	if m.started || m.stopped || !m.configured || m.host == nil {
		return
	}
	m.started = true
	go m.loop()
}

func (m *quotaManager) loadRuntime(path string) {
	store := newQuotaRuntimeStore(path)
	doc, err := store.load()
	blocked := false
	errorText := ""
	if errors.Is(err, os.ErrNotExist) {
		doc = quotaRuntimeDocument{Version: quotaRuntimeVersion, Observations: make(map[string]quotaObservation), Auths: make(map[string]quotaAuthRuntime)}
		err = nil
	} else if err != nil {
		// Preserve an unreadable file and disable active POSTs. Passive quota
		// observation and business scheduling remain available in memory.
		doc = quotaRuntimeDocument{Version: quotaRuntimeVersion, Observations: make(map[string]quotaObservation), Auths: make(map[string]quotaAuthRuntime)}
		blocked = true
		errorText = err.Error()
	}
	m.cache.replace(doc.Observations)
	m.mu.Lock()
	m.runtimeStore = store
	m.runtime = doc
	m.persistenceBlocked = blocked
	m.persistenceError = errorText
	m.mu.Unlock()
}

func (m *quotaManager) loop() {
	defer close(m.doneCh)
	// A local roster sync is allowed at startup, but upstream GET/POST waits for
	// the first configured interval so an upgrade cannot create a startup burst.
	m.syncRosterOnly()
	interval, _ := m.durations()
	needed := m.featureNeeded()
	nextRoundAt := time.Time{}
	if needed {
		nextRoundAt = m.now().Add(interval)
	}
	m.alignMaintenanceDeadlines(nextRoundAt)
	for {
		var timer *time.Timer
		var timerCh <-chan time.Time
		if !nextRoundAt.IsZero() {
			wait := nextRoundAt.Sub(m.now())
			if wait < 0 {
				wait = 0
			}
			timer = time.NewTimer(wait)
			timerCh = timer.C
		}
		select {
		case <-m.stopCh:
			stopQuotaTimer(timer)
			return
		case <-m.configCh:
			stopQuotaTimer(timer)
			m.syncRosterOnly()
			// CPA reconfigures plugins for ordinary auth roster changes. Preserve
			// the existing absolute deadline so those updates cannot starve the
			// maintenance round by repeatedly restarting a full interval.
			nextInterval, _ := m.durations()
			nextNeeded := m.featureNeeded()
			now := m.now()
			restartDeadline := m.takeRestartRoundDeadline()
			nextRoundAt = quotaRoundDeadline(nextRoundAt, interval, nextInterval, needed, nextNeeded, restartDeadline, now)
			interval = nextInterval
			needed = nextNeeded
			m.alignMaintenanceDeadlines(nextRoundAt)
			if needed && !now.Before(nextRoundAt) {
				m.runRound()
				interval, _ = m.durations()
				needed = m.featureNeeded()
				if needed {
					nextRoundAt = m.now().Add(interval)
				} else {
					nextRoundAt = time.Time{}
				}
			}
		case <-timerCh:
			m.runRound()
			interval, _ = m.durations()
			needed = m.featureNeeded()
			if needed {
				nextRoundAt = m.now().Add(interval)
			} else {
				nextRoundAt = time.Time{}
			}
		}
	}
}

func (m *quotaManager) featureNeeded() bool {
	return quotaFeatureNeeded(m.store.RuntimeSettings(), m.store.Keys())
}

func (m *quotaManager) takeRestartRoundDeadline() bool {
	m.mu.Lock()
	restart := m.restartRoundDeadline
	m.restartRoundDeadline = false
	m.mu.Unlock()
	return restart
}

func quotaRoundDeadline(current time.Time, previousInterval, nextInterval time.Duration, previouslyNeeded, needed, restart bool, now time.Time) time.Time {
	if !needed {
		return time.Time{}
	}
	if restart {
		return now.Add(nextInterval)
	}
	if !previouslyNeeded || current.IsZero() {
		return now.Add(nextInterval)
	}
	if !current.After(now) {
		return current
	}
	if nextInterval < previousInterval {
		candidate := now.Add(nextInterval)
		if candidate.Before(current) {
			return candidate
		}
	}
	return current
}

func stopQuotaTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func (m *quotaManager) shutdown() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.stopped {
		started := m.started
		m.mu.Unlock()
		if started {
			<-m.doneCh
		}
		return
	}
	m.stopped = true
	started := m.started
	close(m.stopCh)
	m.mu.Unlock()
	if started {
		<-m.doneCh
	}
	_ = m.persist()
}

func (m *quotaManager) durations() (time.Duration, time.Duration) {
	if m.testDurations != nil {
		return m.testDurations()
	}
	settings := m.store.RuntimeSettings()
	interval, err := time.ParseDuration(settings.QuotaCheckInterval)
	if err != nil || interval < time.Minute {
		interval = 30 * time.Minute
	}
	ttl, err := time.ParseDuration(settings.QuotaCacheTTL)
	if err != nil || ttl < time.Minute {
		ttl = 30 * time.Minute
	}
	return interval, ttl
}

func (m *quotaManager) recordUsage(req UsageHandleRequest) {
	if m == nil || !strings.EqualFold(strings.TrimSpace(req.Provider), "codex") || strings.TrimSpace(req.AuthID) == "" {
		return
	}
	receivedAt := m.now()
	observedAt := req.RequestedAt
	if observedAt.IsZero() {
		observedAt = receivedAt
	}
	responseAt := quotaResponseDate(req.ResponseHeaders, req.RequestedAt, receivedAt)
	if !responseAt.IsZero() {
		observedAt = responseAt
	}
	if observation, ok := parseCodexQuotaHeadersAt(req.ResponseHeaders, observedAt, responseAt); ok {
		source := "passive-http"
		if strings.Contains(strings.ToLower(req.Source), "websocket") || strings.Contains(strings.ToLower(req.Source), "ws") {
			source = "passive-ws"
		}
		m.cache.observe(req.AuthID, req.AuthIndex, source, observation)
	}
	if req.Failed && req.Failure.StatusCode == http.StatusTooManyRequests {
		failureAt := responseAt
		if failureAt.IsZero() {
			failureAt = receivedAt
		}
		resetAt, _ := parseRetryAfter(req.ResponseHeaders.Get("Retry-After"), failureAt)
		if resetAt.IsZero() {
			resetAt = quotaFailureResetAt(req.Failure.Body, failureAt)
		}
		m.cache.markExplicitExhausted(req.AuthID, req.AuthIndex, failureAt, resetAt, "usage_limit_reached")
	}
}

func quotaResponseDate(headers http.Header, requestedAt, receivedAt time.Time) time.Time {
	if len(headers) == 0 {
		return time.Time{}
	}
	parsed, err := http.ParseTime(strings.TrimSpace(headers.Get("Date")))
	if err != nil {
		return time.Time{}
	}
	if !requestedAt.IsZero() && parsed.Before(requestedAt.Add(-time.Minute)) {
		return time.Time{}
	}
	if !receivedAt.IsZero() && parsed.After(receivedAt.Add(time.Minute)) {
		return time.Time{}
	}
	return parsed
}

func quotaFailureResetAt(body string, now time.Time) time.Time {
	var doc map[string]any
	if json.Unmarshal([]byte(body), &doc) != nil {
		return time.Time{}
	}
	containers := make([]map[string]any, 0, 2)
	if child, ok := mapChild(doc, "error"); ok {
		containers = append(containers, child)
	}
	containers = append(containers, doc)
	for _, container := range containers {
		if value, ok := mapAny(container, "resets_at", "reset_at"); ok {
			if resetAt, ok := parseQuotaAnyTime(value); ok {
				return resetAt
			}
		}
		if seconds, ok := mapFloat(container, "resets_in_seconds", "reset_after_seconds"); ok {
			if !math.IsNaN(seconds) && !math.IsInf(seconds, 0) && seconds >= 0 && seconds <= float64(math.MaxInt64)/float64(time.Second) {
				return now.Add(time.Duration(seconds * float64(time.Second)))
			}
		}
	}
	return time.Time{}
}

func (m *quotaManager) syncRosterOnly() {
	settings := m.store.RuntimeSettings()
	keys := m.store.Keys()
	if !quotaFeatureNeeded(settings, keys) {
		return
	}
	host := m.hostSnapshot()
	if host == nil {
		return
	}
	entries, err := host.ListAuths()
	if err != nil {
		m.setGlobalError("roster_error", err)
		return
	}
	m.applyRoster(host, entries, settings, keys)
}

func (m *quotaManager) runRound() {
	settings := m.store.RuntimeSettings()
	keys := m.store.Keys()
	if !quotaFeatureNeeded(settings, keys) {
		return
	}
	host := m.hostSnapshot()
	if host == nil {
		return
	}
	entries, err := host.ListAuths()
	if err != nil {
		m.setGlobalError("roster_error", err)
		return
	}
	eligible := m.applyRoster(host, entries, settings, keys)
	now := m.now()
	interval, ttl := m.durations()
	due := make([]HostAuthEntry, 0, len(eligible))
	for _, entry := range m.rotateEntries(eligible) {
		if m.needsReview(entry.ID, ttl, now) {
			due = append(due, entry)
		}
	}
	for _, entry := range due {
		select {
		case <-m.stopCh:
			return
		default:
		}
		m.refreshAuth(host, entry, settings)
		m.mu.Lock()
		m.runtime.RoundCursor = entry.ID
		m.mu.Unlock()
	}
	// Per-auth deadlines are eligibility gates inside one global maintenance
	// loop, not independent timers. Align every eligible auth with the next
	// global round so an early auth in a long sequential sweep cannot advertise
	// a check time that the loop is unable to honor. Preserve only later
	// external deadlines such as Retry-After.
	nextRoundAt := m.now().Add(interval)
	m.alignMaintenanceDeadlines(nextRoundAt)
	m.mu.Lock()
	m.runtime.LastRoundAt = now
	m.mu.Unlock()
	_ = m.persist()
}

func (m *quotaManager) alignMaintenanceDeadlines(nextRoundAt time.Time) {
	if nextRoundAt.IsZero() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for authID, runtime := range m.runtime.Auths {
		if !runtime.InMaintenanceScope || runtime.NextCheckAt.After(nextRoundAt) {
			continue
		}
		runtime.NextCheckAt = nextRoundAt
		m.runtime.Auths[authID] = runtime
	}
}

func quotaFeatureNeeded(settings policy.RuntimeSettings, keys []policy.KeyConfig) bool {
	if settings.QuotaActivationEnabled {
		return true
	}
	for i := range keys {
		key := &keys[i]
		if key.Enabled && pluginControlsKey(key) && key.AccountBinding != nil && key.AccountBinding.Strategy == policy.BindingStrategyQuotaFillFirst {
			return true
		}
	}
	return false
}

const (
	quotaRuntimeCapacity  = 4096
	quotaRuntimeRetention = 30 * 24 * time.Hour
)

type quotaRosterEvaluation struct {
	entry       HostAuthEntry
	confirmed   bool
	fingerprint string
	groups      []string
	reason      string
}

func (m *quotaManager) applyRoster(host HostClient, entries []HostAuthEntry, settings policy.RuntimeSettings, keys []policy.KeyConfig) []HostAuthEntry {
	now := m.now()
	rules := m.store.ClassifyRulesSnapshot()
	evaluated := make([]quotaRosterEvaluation, 0, len(entries))
	for _, entry := range entries {
		provider := strings.TrimSpace(entry.Provider)
		if provider == "" {
			provider = strings.TrimSpace(entry.Type)
		}
		if !strings.EqualFold(provider, "codex") {
			continue
		}
		if strings.TrimSpace(entry.ID) == "" {
			entry.ID = strings.TrimSpace(entry.Name)
		}
		if strings.TrimSpace(entry.ID) == "" {
			continue
		}
		evaluated = append(evaluated, confirmQuotaRosterEntry(host, entry, rules, now))
	}

	eligible := make([]HostAuthEntry, 0, len(evaluated))
	seen := make(map[string]struct{}, len(evaluated))
	dropCache := make(map[string]struct{})
	m.mu.Lock()
	if m.runtime.Auths == nil {
		m.runtime.Auths = make(map[string]quotaAuthRuntime)
	}
	for _, evaluation := range evaluated {
		entry := evaluation.entry
		authID := strings.TrimSpace(entry.ID)
		seen[authID] = struct{}{}
		managed := evaluation.confirmed && authManagedByQuotaKeys(authID, evaluation.groups, keys)
		activation := settings.QuotaActivationEnabled && evaluation.confirmed && (settings.QuotaActivationScope == "all-codex" || managed)
		maintenance := evaluation.confirmed && (managed || activation)
		runtime := m.runtime.Auths[authID]
		if evaluation.confirmed && runtime.CredentialFingerprint != "" && runtime.CredentialFingerprint != evaluation.fingerprint {
			runtime.Baselines = nil
			runtime.Activation = quotaActivationState{}
			dropCache[authID] = struct{}{}
		}
		if cached, ok := m.cache.get(authID); ok && evaluation.confirmed && cached.CredentialFingerprint != "" && cached.CredentialFingerprint != evaluation.fingerprint {
			dropCache[authID] = struct{}{}
		}
		runtime.AuthID = authID
		runtime.AuthIndex = strings.TrimSpace(entry.AuthIndex)
		runtime.Provider = "codex"
		runtime.Status = strings.TrimSpace(entry.Status)
		runtime.InManagedPool = managed
		runtime.InMaintenanceScope = maintenance
		runtime.InActivationScope = activation
		runtime.LastRosterSeenAt = now
		runtime.OutOfScopeAt = time.Time{}
		runtime.ExclusionReason = evaluation.reason
		if evaluation.confirmed {
			runtime.CredentialFingerprint = evaluation.fingerprint
		}
		if runtime.ExclusionReason == "" && entry.Unavailable {
			runtime.ExclusionReason = "host_unavailable"
		} else if runtime.ExclusionReason == "" && !maintenance {
			runtime.ExclusionReason = "out_of_scope"
		}
		m.runtime.Auths[authID] = runtime
		if maintenance {
			eligible = append(eligible, entry)
		}
	}
	for authID, runtime := range m.runtime.Auths {
		if _, ok := seen[authID]; ok {
			continue
		}
		runtime.InManagedPool = false
		runtime.InMaintenanceScope = false
		runtime.InActivationScope = false
		runtime.ExclusionReason = "removed_or_unlisted"
		if runtime.OutOfScopeAt.IsZero() {
			runtime.OutOfScopeAt = now
		}
		m.runtime.Auths[authID] = runtime
	}
	for authID := range pruneQuotaRuntimesLocked(m.runtime.Auths, now) {
		dropCache[authID] = struct{}{}
	}
	m.runtime.LastRosterSync = now
	m.mu.Unlock()
	for authID := range dropCache {
		m.cache.delete(authID)
	}
	for _, evaluation := range evaluated {
		if !evaluation.confirmed {
			continue
		}
		m.cache.observe(evaluation.entry.ID, evaluation.entry.AuthIndex, "roster-confirmed", quotaObservation{
			Provider:              "codex",
			ObservedAt:            now,
			CredentialFingerprint: evaluation.fingerprint,
		})
	}
	return eligible
}

func confirmQuotaRosterEntry(host HostClient, entry HostAuthEntry, rules []policy.ClassifyRule, now time.Time) quotaRosterEvaluation {
	evaluation := quotaRosterEvaluation{entry: entry}
	authID := strings.TrimSpace(entry.ID)
	if host == nil || strings.TrimSpace(entry.AuthIndex) == "" {
		evaluation.reason = "runtime_unresolvable"
		return evaluation
	}
	if entry.Disabled || strings.EqualFold(strings.TrimSpace(entry.Status), "disabled") {
		evaluation.reason = "disabled"
		return evaluation
	}
	live, err := host.GetAuthRuntime(entry.AuthIndex)
	if err != nil || strings.TrimSpace(live.ID) != authID {
		evaluation.reason = "runtime_unresolvable"
		return evaluation
	}
	provider := live.Provider
	if provider == "" {
		provider = live.Type
	}
	if !strings.EqualFold(strings.TrimSpace(provider), "codex") || live.Disabled || strings.EqualFold(strings.TrimSpace(live.Status), "disabled") {
		evaluation.reason = "disabled_or_unsupported"
		return evaluation
	}
	doc, err := host.GetAuth(entry.AuthIndex)
	if err != nil {
		evaluation.reason = "credential_unavailable"
		return evaluation
	}
	if codexAuthUsesUnsupportedProxy(doc.JSON) {
		evaluation.reason = "per_auth_proxy_unsupported"
		return evaluation
	}
	credentials, err := extractCodexCredentials(doc.JSON)
	if err != nil {
		evaluation.reason = "credential_invalid"
		return evaluation
	}
	if codexCredentialsExpired(credentials, now) {
		evaluation.reason = "access_token_expired"
		return evaluation
	}
	evaluation.entry = live
	evaluation.entry.ID = authID
	evaluation.entry.AuthIndex = entry.AuthIndex
	evaluation.confirmed = true
	evaluation.fingerprint = codexCredentialFingerprint(credentials)
	evaluation.groups = policy.GroupsForCredential("codex", codexAuthAttributes(doc.JSON), authID, rules)
	return evaluation
}

func authManagedByQuotaKeys(authID string, authGroups []string, keys []policy.KeyConfig) bool {
	groups := make(map[string]struct{}, len(authGroups))
	for _, group := range authGroups {
		groups[strings.ToLower(strings.TrimSpace(group))] = struct{}{}
	}
	for i := range keys {
		key := &keys[i]
		if !key.Enabled || !pluginControlsKey(key) || key.AccountBinding == nil || key.AccountBinding.Strategy != policy.BindingStrategyQuotaFillFirst || !key.AccountBinding.Matches(authID) {
			continue
		}
		if key.Native {
			return true
		}
		for _, model := range key.Models {
			if !strings.EqualFold(strings.TrimSpace(model.Provider), "codex") {
				continue
			}
			group := strings.ToLower(strings.TrimSpace(model.Group))
			if group == "" {
				return true
			}
			if _, ok := groups[group]; ok {
				return true
			}
		}
	}
	return false
}

func pruneQuotaRuntimesLocked(auths map[string]quotaAuthRuntime, now time.Time) map[string]struct{} {
	removed := make(map[string]struct{})
	for authID, runtime := range auths {
		if runtime.OutOfScopeAt.IsZero() || now.Sub(runtime.OutOfScopeAt) < quotaRuntimeRetention || quotaActivationMustBeRetained(runtime.Activation) {
			continue
		}
		delete(auths, authID)
		removed[authID] = struct{}{}
	}
	if len(auths) <= quotaRuntimeCapacity {
		return removed
	}
	type candidate struct {
		authID string
		at     time.Time
	}
	candidates := make([]candidate, 0, len(auths))
	for authID, runtime := range auths {
		if runtime.OutOfScopeAt.IsZero() || quotaActivationMustBeRetained(runtime.Activation) {
			continue
		}
		candidates = append(candidates, candidate{authID: authID, at: runtime.OutOfScopeAt})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].at.Equal(candidates[j].at) {
			return candidates[i].at.Before(candidates[j].at)
		}
		return candidates[i].authID < candidates[j].authID
	})
	for _, candidate := range candidates {
		if len(auths) <= quotaRuntimeCapacity {
			break
		}
		delete(auths, candidate.authID)
		removed[candidate.authID] = struct{}{}
	}
	return removed
}

func quotaActivationMustBeRetained(state quotaActivationState) bool {
	return state.SendIntent || state.Status == "sending" || state.Status == "verify_pending"
}

func (m *quotaManager) rotateEntries(entries []HostAuthEntry) []HostAuthEntry {
	ordered := append([]HostAuthEntry(nil), entries...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	m.mu.Lock()
	cursor := m.runtime.RoundCursor
	m.mu.Unlock()
	if cursor == "" || len(ordered) < 2 {
		return ordered
	}
	index := sort.Search(len(ordered), func(i int) bool { return ordered[i].ID > cursor })
	if index == 0 || index >= len(ordered) {
		return ordered
	}
	return append(append([]HostAuthEntry(nil), ordered[index:]...), ordered[:index]...)
}

func (m *quotaManager) needsReview(authID string, ttl time.Duration, now time.Time) bool {
	m.mu.Lock()
	runtime := m.runtime.Auths[authID]
	m.mu.Unlock()
	if !runtime.InMaintenanceScope || (!runtime.NextCheckAt.IsZero() && runtime.NextCheckAt.After(now)) {
		return false
	}
	if runtime.Activation.CycleID != "" && runtime.Activation.Status != "confirmed" && runtime.Activation.Status != "anomaly_hold" {
		return true
	}
	observation, ok := m.cache.get(authID)
	if !ok || observation.ObservedAt.IsZero() || now.Sub(observation.ObservedAt) >= ttl {
		return true
	}
	if observation.Long == nil {
		return true
	}
	if !observation.Long.ResetAt.IsZero() && !now.Before(observation.Long.ResetAt) {
		return true
	}
	if observation.Short != nil && !observation.Short.ResetAt.IsZero() && !now.Before(observation.Short.ResetAt) {
		return true
	}
	if observation.ExplicitExhausted && (!observation.ExplicitResetAt.IsZero() && !now.Before(observation.ExplicitResetAt)) {
		return true
	}
	return false
}

func (m *quotaManager) refreshAuth(host HostClient, rosterEntry HostAuthEntry, settings policy.RuntimeSettings) {
	now := m.now()
	interval, _ := m.durations()
	nextCheck := now.Add(interval)
	defer func() { m.setNextCheck(rosterEntry.ID, nextCheck) }()
	live, err := host.GetAuthRuntime(rosterEntry.AuthIndex)
	if err != nil {
		m.setAuthError(rosterEntry.ID, "runtime_unavailable", err)
		return
	}
	if live.ID != "" && live.ID != rosterEntry.ID {
		m.setAuthError(rosterEntry.ID, "identity_changed", errors.New("host auth id changed during review"))
		return
	}
	provider := live.Provider
	if provider == "" {
		provider = live.Type
	}
	if !strings.EqualFold(strings.TrimSpace(provider), "codex") || live.Disabled || strings.EqualFold(strings.TrimSpace(live.Status), "disabled") {
		m.setAuthError(rosterEntry.ID, "disabled_or_unsupported", errors.New("runtime auth is not an enabled Codex credential"))
		return
	}
	doc, err := host.GetAuth(rosterEntry.AuthIndex)
	if err != nil {
		m.setAuthError(rosterEntry.ID, "credential_unavailable", err)
		return
	}
	if codexAuthUsesUnsupportedProxy(doc.JSON) {
		m.setAuthError(rosterEntry.ID, "per_auth_proxy_unsupported", errors.New("host callback cannot preserve this auth's per-account proxy"))
		return
	}
	credentials, err := extractCodexCredentials(doc.JSON)
	if err != nil {
		m.setAuthError(rosterEntry.ID, "credential_invalid", err)
		return
	}
	if codexCredentialsExpired(credentials, now) {
		m.setAuthError(rosterEntry.ID, "access_token_expired", errors.New("access token is expired; plugin does not refresh credentials"))
		return
	}
	fingerprint := codexCredentialFingerprint(credentials)
	observation, statusCode, err := fetchCodexQuota(host, credentials, m.now)
	if err != nil {
		var httpErr quotaHTTPError
		if errors.As(err, &httpErr) && httpErr.retryAt.After(nextCheck) {
			nextCheck = httpErr.retryAt
		}
		if statusCode == http.StatusTooManyRequests {
			m.cache.markExplicitExhausted(rosterEntry.ID, rosterEntry.AuthIndex, now, time.Time{}, "quota_get_429")
		}
		m.setAuthError(rosterEntry.ID, "quota_get_failed", err)
		return
	}
	observation.AuthIndex = rosterEntry.AuthIndex
	observation.CredentialFingerprint = fingerprint
	m.cache.observe(rosterEntry.ID, rosterEntry.AuthIndex, "quota-get", observation)
	decisionAt := observation.ObservedAt
	if decisionAt.IsZero() {
		decisionAt = m.now()
	}
	nextCheck = decisionAt.Add(interval)
	lazy := m.processObservation(rosterEntry.ID, rosterEntry.AuthIndex, fingerprint, observation, decisionAt)
	if len(lazy) == 0 || !settings.QuotaActivationEnabled || !m.authActivationAllowed(rosterEntry.ID) {
		return
	}
	m.tryActivate(host, rosterEntry, credentials, lazy, decisionAt)
}

type quotaHTTPError struct {
	status  int
	retryAt time.Time
}

func (e quotaHTTPError) Error() string {
	return fmt.Sprintf("quota request returned status %d", e.status)
}

func fetchCodexQuota(host HostClient, credentials codexCredentials, now func() time.Time) (quotaObservation, int, error) {
	if now == nil {
		now = time.Now
	}
	response, err := host.Do(HostHTTPRequest{
		Method: http.MethodGet,
		URL:    codexQuotaEndpoint,
		Headers: http.Header{
			"Authorization":      []string{"Bearer " + credentials.AccessToken},
			"Chatgpt-Account-Id": []string{credentials.AccountID},
			"Content-Type":       []string{"application/json"},
			"User-Agent":         []string{codexQuotaUserAgent},
		},
	})
	if err != nil {
		return quotaObservation{}, 0, err
	}
	observedAt := now()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		retryAt, _ := parseRetryAfter(response.Headers.Get("Retry-After"), observedAt)
		return quotaObservation{}, response.StatusCode, quotaHTTPError{status: response.StatusCode, retryAt: retryAt}
	}
	observation, err := parseCodexQuotaPayload(response.Body, observedAt)
	if err != nil {
		return quotaObservation{}, response.StatusCode, fmt.Errorf("parse quota response: %w", err)
	}
	return observation, response.StatusCode, nil
}

func (m *quotaManager) processObservation(authID, authIndex, fingerprint string, observation quotaObservation, now time.Time) []quotaWindowKind {
	activationModel := m.store.RuntimeSettings().QuotaActivationModel
	m.mu.Lock()
	defer m.mu.Unlock()
	runtime := m.runtime.Auths[authID]
	if runtime.CredentialFingerprint != "" && runtime.CredentialFingerprint != fingerprint {
		runtime.Baselines = nil
		runtime.Activation = quotaActivationState{}
	}
	runtime.AuthID = authID
	runtime.AuthIndex = authIndex
	runtime.CredentialFingerprint = fingerprint
	runtime.Provider = "codex"
	runtime.LastCheckAt = now
	runtime.LastResult = "quota_refreshed"
	runtime.LastError = ""
	if runtime.Baselines == nil {
		runtime.Baselines = make(map[quotaWindowKind]quotaWindowBaseline)
	}
	if legacyCompact404Activation(runtime.Activation) {
		// The original implementation followed the reference plugin's old
		// /responses/compact probe. A later reference fix moved lazy-window
		// activation to /responses after the compact endpoint began returning a
		// definite 404. That response proves the old request was rejected, so it
		// is safe to clear only that protocol's attempt budget and retry with the
		// current protocol. The marker prevents a current-protocol 404 from being
		// migrated repeatedly.
		runtime.Activation = quotaActivationState{
			Protocol:   codexActivationProtocol,
			Model:      activationModel,
			Status:     "watching",
			LastResult: "legacy_compact_404_migrated",
		}
	} else if rejectedActivationUsesDifferentModel(runtime.Activation, activationModel) {
		// A completed 4xx proves the old-model request did not execute. Changing
		// the configured model can therefore safely clear that model's attempt
		// budget. Ambiguous transport, 2xx and 5xx outcomes are never replayed.
		runtime.Activation = quotaActivationState{
			Protocol:   codexActivationProtocol,
			Model:      activationModel,
			Status:     "watching",
			LastResult: "activation_model_changed_after_rejection",
		}
	}
	windows := observationWindows(observation)
	if runtime.Activation.CycleID != "" && runtime.Activation.Status != "confirmed" {
		confirmed := true
		for _, kind := range runtime.Activation.Windows {
			window, ok := windows[kind]
			if !ok || window.UsedPercent == nil || (*window.UsedPercent == 0 && strictLazyWindow(now, window)) {
				confirmed = false
				continue
			}
			runtime.Baselines[kind] = baselineFromWindow(window, now)
		}
		if confirmed {
			runtime.Activation.Status = "confirmed"
			runtime.Activation.SendIntent = false
			runtime.Activation.NextCheckAt = time.Time{}
			m.runtime.Auths[authID] = runtime
			return nil
		}
		if runtime.Activation.Status == "sending" {
			runtime.Activation.Status = "verify_pending"
		}
		m.runtime.Auths[authID] = runtime
		return append([]quotaWindowKind(nil), runtime.Activation.Windows...)
	}

	lazy := make([]quotaWindowKind, 0, 2)
	for kind, window := range windows {
		if window.UsedPercent == nil || window.ResetAt.IsZero() || window.WindowSeconds <= 0 {
			continue
		}
		baseline, exists := runtime.Baselines[kind]
		if !exists {
			runtime.Baselines[kind] = baselineFromWindow(window, now)
			continue
		}
		if window.ResetAt.Before(baseline.ResetAt.Add(-quotaLazyTolerance)) {
			runtime.Activation.Status = "anomaly_hold"
			continue
		}
		if *window.UsedPercent > 0 {
			runtime.Baselines[kind] = baselineFromWindow(window, now)
			continue
		}
		if window.ResetAt.After(baseline.ResetAt.Add(quotaResetShift)) {
			if strictLazyWindow(now, window) {
				lazy = append(lazy, kind)
			} else {
				runtime.Baselines[kind] = baselineFromWindow(window, now)
			}
		}
	}
	if len(lazy) > 0 {
		sort.Slice(lazy, func(i, j int) bool { return lazy[i] < lazy[j] })
		cycleID := quotaCycleID(fingerprint, runtime.Baselines, lazy)
		runtime.Activation = quotaActivationState{Protocol: codexActivationProtocol, Model: activationModel, Status: "ready", CycleID: cycleID, Windows: append([]quotaWindowKind(nil), lazy...)}
	} else if runtime.Activation.Status == "" {
		runtime.Activation.Status = "watching"
	}
	m.runtime.Auths[authID] = runtime
	return lazy
}

func legacyCompact404Activation(state quotaActivationState) bool {
	return state.Protocol == "" && state.CycleID != "" && state.Attempts > 0 && state.RetryAllowed && state.LastResult == "http_404"
}

func rejectedActivationUsesDifferentModel(state quotaActivationState, currentModel string) bool {
	if state.Protocol != codexActivationProtocol || state.CycleID == "" || state.Attempts == 0 || !state.RetryAllowed || !activationResultDefinitelyRejected(state.LastResult) {
		return false
	}
	previousModel := strings.TrimSpace(state.Model)
	if previousModel == "" {
		// v0.7.6 did not persist the model and always sent gpt-5.4-mini.
		previousModel = "gpt-5.4-mini"
	}
	return previousModel != strings.TrimSpace(currentModel)
}

func activationResultDefinitelyRejected(result string) bool {
	status, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(result), "http_"))
	return err == nil && activationResponseDefinitelyRejected(status)
}

func buildCodexActivationPayload(model string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"model":        strings.TrimSpace(model),
		"instructions": "",
		"input": []map[string]any{{
			"type": "message",
			"role": "user",
			"content": []map[string]string{{
				"type": "input_text",
				"text": "ping",
			}},
		}},
		"stream": true,
		"store":  false,
	})
}

func observationWindows(observation quotaObservation) map[quotaWindowKind]quotaWindow {
	out := make(map[quotaWindowKind]quotaWindow, 2)
	if observation.Short != nil {
		out[observation.Short.Kind] = *observation.Short
	}
	if observation.Long != nil {
		out[observation.Long.Kind] = *observation.Long
	}
	return out
}

func baselineFromWindow(window quotaWindow, observedAt time.Time) quotaWindowBaseline {
	used := float64(0)
	if window.UsedPercent != nil {
		used = *window.UsedPercent
	}
	return quotaWindowBaseline{Kind: window.Kind, ResetAt: window.ResetAt, UsedPercent: used, WindowSeconds: window.WindowSeconds, ObservedAt: observedAt}
}

func strictLazyWindow(observedAt time.Time, window quotaWindow) bool {
	return window.UsedPercent != nil && *window.UsedPercent == 0 && window.WindowSeconds > 0 && !window.ResetAt.IsZero() &&
		absDuration(window.ResetAt.Sub(observedAt.Add(time.Duration(window.WindowSeconds)*time.Second))) <= quotaLazyTolerance
}

func quotaCycleID(fingerprint string, baselines map[quotaWindowKind]quotaWindowBaseline, windows []quotaWindowKind) string {
	var source strings.Builder
	source.WriteString(fingerprint)
	for _, kind := range windows {
		baseline := baselines[kind]
		source.WriteByte(0)
		source.WriteString(string(kind))
		source.WriteByte(0)
		source.WriteString(strconv.FormatInt(baseline.ResetAt.Unix(), 10))
		source.WriteByte(0)
		source.WriteString(strconv.FormatInt(baseline.WindowSeconds, 10))
	}
	sum := sha256.Sum256([]byte(source.String()))
	return hex.EncodeToString(sum[:16])
}

func (m *quotaManager) tryActivate(host HostClient, rosterEntry HostAuthEntry, credentials codexCredentials, lazy []quotaWindowKind, now time.Time) {
	if !m.authActivationAllowed(rosterEntry.ID) {
		return
	}
	live, err := host.GetAuthRuntime(rosterEntry.AuthIndex)
	provider := live.Provider
	if provider == "" {
		provider = live.Type
	}
	if err != nil || (live.ID != "" && live.ID != rosterEntry.ID) || !strings.EqualFold(strings.TrimSpace(provider), "codex") || live.Disabled || live.Unavailable || strings.EqualFold(strings.TrimSpace(live.Status), "disabled") {
		m.setAuthActivationDeferred(rosterEntry.ID, "auth_revalidation_failed", now.Add(30*time.Minute))
		return
	}
	doc, err := host.GetAuth(rosterEntry.AuthIndex)
	if err != nil || codexAuthUsesUnsupportedProxy(doc.JSON) {
		m.setAuthActivationDeferred(rosterEntry.ID, "credential_revalidation_failed", now.Add(30*time.Minute))
		return
	}
	currentCredentials, err := extractCodexCredentials(doc.JSON)
	if err != nil || codexCredentialsExpired(currentCredentials, now) {
		m.setAuthActivationDeferred(rosterEntry.ID, "credential_revalidation_failed", now.Add(30*time.Minute))
		return
	}
	if codexCredentialFingerprint(currentCredentials) != codexCredentialFingerprint(credentials) {
		m.setAuthActivationDeferred(rosterEntry.ID, "credential_instance_changed", now.Add(30*time.Minute))
		return
	}
	credentials = currentCredentials
	activationModel := m.store.RuntimeSettings().QuotaActivationModel
	activationPayload, err := buildCodexActivationPayload(activationModel)
	if err != nil {
		m.setAuthActivationDeferred(rosterEntry.ID, "activation_payload_invalid", now.Add(30*time.Minute))
		return
	}
	interval, _ := m.durations()
	m.mu.Lock()
	runtime := m.runtime.Auths[rosterEntry.ID]
	activation := runtime.Activation
	blocked := m.persistenceBlocked
	if activation.Attempts >= quotaMaxActivationTries || activation.Status == "sending" || activation.SendIntent || blocked ||
		(activation.Attempts > 0 && !activation.RetryAllowed) ||
		(activation.Attempts > 0 && now.Before(activation.LastAttemptAt.Add(interval))) {
		m.mu.Unlock()
		return
	}
	leaseID := "quota-activation:" + rosterEntry.ID + ":" + activation.CycleID + ":" + strconv.Itoa(activation.Attempts+1)
	m.mu.Unlock()
	limit := m.store.AuthConcurrencyLimit(rosterEntry.ID)
	if _, ok := m.concurrency.acquireActivation(leaseID, rosterEntry.ID, limit); !ok {
		m.setAuthActivationDeferred(rosterEntry.ID, "auth_concurrency_full", now.Add(interval))
		return
	}
	released := false
	release := func() {
		if !released {
			released = true
			m.concurrency.releaseActivation(leaseID)
		}
	}

	m.mu.Lock()
	runtime = m.runtime.Auths[rosterEntry.ID]
	runtime.Activation.Status = "sending"
	runtime.Activation.Protocol = codexActivationProtocol
	runtime.Activation.Model = activationModel
	runtime.Activation.Attempts++
	runtime.Activation.LastAttemptAt = now
	runtime.Activation.SendIntent = true
	runtime.Activation.RetryAllowed = false
	runtime.Activation.LastError = ""
	runtime.Activation.Windows = append([]quotaWindowKind(nil), lazy...)
	m.runtime.Auths[rosterEntry.ID] = runtime
	m.mu.Unlock()
	if err := m.persist(); err != nil {
		release()
		return
	}
	if !m.authActivationAllowed(rosterEntry.ID) {
		release()
		m.mu.Lock()
		runtime = m.runtime.Auths[rosterEntry.ID]
		runtime.Activation.Status = "deferred"
		runtime.Activation.SendIntent = false
		runtime.Activation.LastResult = "activation_disabled_before_send"
		if runtime.Activation.Attempts > 0 {
			runtime.Activation.Attempts--
		}
		runtime.Activation.LastAttemptAt = time.Time{}
		m.runtime.Auths[rosterEntry.ID] = runtime
		m.mu.Unlock()
		_ = m.persist()
		return
	}

	response, postErr := host.Do(HostHTTPRequest{
		Method: http.MethodPost,
		URL:    codexActivationEndpoint,
		Headers: http.Header{
			"Authorization":      []string{"Bearer " + credentials.AccessToken},
			"Chatgpt-Account-Id": []string{credentials.AccountID},
			"Content-Type":       []string{"application/json"},
			"User-Agent":         []string{codexQuotaUserAgent},
		},
		Body: activationPayload,
	})
	release()
	m.mu.Lock()
	runtime = m.runtime.Auths[rosterEntry.ID]
	runtime.Activation.Status = "verify_pending"
	runtime.Activation.LastResult = "outcome_unknown"
	if postErr != nil {
		runtime.Activation.LastError = safeQuotaError(postErr)
	} else {
		runtime.Activation.LastResult = "http_" + strconv.Itoa(response.StatusCode)
		runtime.Activation.RetryAllowed = activationResponseDefinitelyRejected(response.StatusCode)
		if runtime.Activation.RetryAllowed {
			runtime.Activation.SendIntent = false
		}
		readActivationUsage(response.Body, &runtime.Activation)
	}
	m.runtime.Auths[rosterEntry.ID] = runtime
	m.mu.Unlock()
	_ = m.persist()

	if !m.waitVerifyDelay() {
		return
	}
	verified, _, verifyErr := fetchCodexQuota(host, credentials, m.now)
	if verifyErr == nil {
		verifyAt := verified.ObservedAt
		if verifyAt.IsZero() {
			verifyAt = m.now()
		}
		verified.AuthIndex = rosterEntry.AuthIndex
		verified.CredentialFingerprint = codexCredentialFingerprint(credentials)
		m.cache.observe(rosterEntry.ID, rosterEntry.AuthIndex, "quota-get", verified)
		remaining := m.processObservation(rosterEntry.ID, rosterEntry.AuthIndex, verified.CredentialFingerprint, verified, verifyAt)
		m.mu.Lock()
		runtime = m.runtime.Auths[rosterEntry.ID]
		runtime.Activation.SendIntent = false
		if len(remaining) == 0 {
			runtime.Activation.Status = "confirmed"
			runtime.Activation.LastResult = "verified"
			runtime.Activation.NextCheckAt = time.Time{}
		} else if runtime.Activation.Attempts >= quotaMaxActivationTries {
			runtime.Activation.Status = "deferred"
			runtime.Activation.NextCheckAt = verifyAt.Add(interval)
		} else {
			runtime.Activation.Status = "verify_pending"
			runtime.Activation.NextCheckAt = verifyAt.Add(interval)
		}
		m.runtime.Auths[rosterEntry.ID] = runtime
		m.mu.Unlock()
	} else {
		verifyAt := m.now()
		m.mu.Lock()
		runtime = m.runtime.Auths[rosterEntry.ID]
		runtime.Activation.Status = "verify_pending"
		runtime.Activation.LastError = safeQuotaError(verifyErr)
		runtime.Activation.NextCheckAt = verifyAt.Add(interval)
		m.runtime.Auths[rosterEntry.ID] = runtime
		m.mu.Unlock()
	}
	_ = m.persist()
}

func activationResponseDefinitelyRejected(status int) bool {
	// A completed 4xx response means the activation request was rejected by
	// the endpoint. Transport failures, timeouts, 2xx and 5xx outcomes are all
	// treated as possibly executed and therefore verification-only.
	return status >= 400 && status < 500 && status != http.StatusRequestTimeout
}

func readActivationUsage(raw []byte, state *quotaActivationState) {
	if state == nil || len(raw) == 0 {
		return
	}
	if readActivationUsageJSON(raw, state) {
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		_ = readActivationUsageJSON([]byte(payload), state)
	}
}

func readActivationUsageJSON(raw []byte, state *quotaActivationState) bool {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	usage, ok := mapChild(doc, "usage")
	if !ok {
		response, hasResponse := mapChild(doc, "response")
		if !hasResponse {
			return false
		}
		usage, ok = mapChild(response, "usage")
		if !ok {
			return false
		}
	}
	input, inputOK := mapInt64(usage, "input_tokens", "inputTokens")
	output, outputOK := mapInt64(usage, "output_tokens", "outputTokens")
	total, totalOK := mapInt64(usage, "total_tokens", "totalTokens")
	if inputOK {
		state.InputTokens = input
	}
	if outputOK {
		state.OutputTokens = output
	}
	if totalOK {
		state.TotalTokens = total
	}
	return inputOK || outputOK || totalOK
}

func (m *quotaManager) waitVerifyDelay() bool {
	if m.verifyDelay <= 0 {
		return true
	}
	timer := time.NewTimer(m.verifyDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-m.stopCh:
		return false
	}
}

func (m *quotaManager) authActivationAllowed(authID string) bool {
	settings := m.store.RuntimeSettings()
	if !settings.QuotaActivationEnabled {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	runtime := m.runtime.Auths[authID]
	if m.persistenceBlocked || !runtime.InMaintenanceScope || runtime.ExclusionReason == "disabled_or_unresolvable" || runtime.ExclusionReason == "host_unavailable" {
		return false
	}
	if settings.QuotaActivationScope == "all-codex" {
		return true
	}
	return runtime.InManagedPool
}

func (m *quotaManager) hostSnapshot() HostClient {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.host
}

func (m *quotaManager) setNextCheck(authID string, next time.Time) {
	m.mu.Lock()
	runtime := m.runtime.Auths[authID]
	runtime.NextCheckAt = next
	m.runtime.Auths[authID] = runtime
	m.mu.Unlock()
}

func (m *quotaManager) setAuthError(authID, result string, err error) {
	m.mu.Lock()
	runtime := m.runtime.Auths[authID]
	runtime.LastCheckAt = m.now()
	runtime.LastResult = result
	runtime.LastError = safeQuotaError(err)
	m.runtime.Auths[authID] = runtime
	host := m.host
	m.mu.Unlock()
	if host != nil {
		host.Log("warn", "cpa-key-policy quota maintenance skipped auth", map[string]any{"auth_id": authID, "result": result})
	}
}

func (m *quotaManager) setGlobalError(result string, err error) {
	m.mu.Lock()
	m.lastError = strings.TrimSpace(result + ": " + safeQuotaError(err))
	host := m.host
	m.mu.Unlock()
	if host != nil {
		host.Log("warn", "cpa-key-policy quota maintenance error", map[string]any{"result": result})
	}
}

func (m *quotaManager) setAuthActivationDeferred(authID, result string, next time.Time) {
	m.mu.Lock()
	runtime := m.runtime.Auths[authID]
	runtime.Activation.Status = "deferred"
	runtime.Activation.LastResult = result
	runtime.Activation.NextCheckAt = next
	m.runtime.Auths[authID] = runtime
	m.mu.Unlock()
}

func safeQuotaError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.Join(strings.Fields(err.Error()), " ")
	if len(message) > 300 {
		message = message[:300]
	}
	return message
}

func (m *quotaManager) persist() error {
	m.mu.Lock()
	if m.persistenceBlocked {
		err := errors.New(m.persistenceError)
		m.mu.Unlock()
		return err
	}
	store := m.runtimeStore
	doc := cloneQuotaRuntimeDocument(m.runtime)
	m.mu.Unlock()
	if store == nil {
		return errors.New("quota runtime store is not configured")
	}
	doc.Observations = m.cache.snapshot()
	if err := store.save(doc); err != nil {
		m.mu.Lock()
		m.persistenceBlocked = true
		m.persistenceError = err.Error()
		m.mu.Unlock()
		return err
	}
	return nil
}

func cloneQuotaRuntimeDocument(src quotaRuntimeDocument) quotaRuntimeDocument {
	dst := src
	dst.Observations = make(map[string]quotaObservation, len(src.Observations))
	for authID, observation := range src.Observations {
		dst.Observations[authID] = cloneQuotaObservation(observation)
	}
	dst.Auths = make(map[string]quotaAuthRuntime, len(src.Auths))
	for authID, runtime := range src.Auths {
		copy := runtime
		copy.Activation.Windows = append([]quotaWindowKind(nil), runtime.Activation.Windows...)
		copy.Baselines = make(map[quotaWindowKind]quotaWindowBaseline, len(runtime.Baselines))
		for kind, baseline := range runtime.Baselines {
			copy.Baselines[kind] = baseline
		}
		dst.Auths[authID] = copy
	}
	return dst
}

func (m *quotaManager) status() map[string]any {
	settings := m.store.RuntimeSettings()
	_, ttl := m.durations()
	now := m.now()
	concurrency := m.concurrency.snapshot()
	m.mu.Lock()
	doc := cloneQuotaRuntimeDocument(m.runtime)
	path := ""
	if m.runtimeStore != nil {
		path = m.runtimeStore.path
	}
	blocked := m.persistenceBlocked
	persistErr := m.persistenceError
	lastError := m.lastError
	m.mu.Unlock()
	observations := m.cache.snapshot()
	for authID := range observations {
		if _, exists := doc.Auths[authID]; !exists {
			doc.Auths[authID] = quotaAuthRuntime{AuthID: authID, Provider: "codex", Status: "observed_only", ExclusionReason: "out_of_scope"}
		}
	}
	auths := make([]map[string]any, 0, len(doc.Auths))
	for authID, runtime := range doc.Auths {
		availability := "unknown"
		class, observation := m.cache.classify(authID, ttl, now)
		freshness := quotaObservationFreshness(observation, ttl, now)
		switch class {
		case quotaAvailabilityReady:
			availability = "ready"
		case quotaAvailabilityExhausted:
			availability = "exhausted"
		}
		auths = append(auths, map[string]any{
			"auth_id":              authID,
			"auth_index":           runtime.AuthIndex,
			"provider":             runtime.Provider,
			"status":               runtime.Status,
			"observable":           true,
			"in_managed_pool":      runtime.InManagedPool,
			"in_maintenance_scope": runtime.InMaintenanceScope,
			"in_activation_scope":  runtime.InActivationScope,
			"exclusion_reason":     runtime.ExclusionReason,
			"availability":         availability,
			"freshness":            freshness,
			"observation":          publicQuotaObservation(observation),
			"last_roster_seen_at":  runtime.LastRosterSeenAt,
			"last_check_at":        runtime.LastCheckAt,
			"next_check_at":        runtime.NextCheckAt,
			"last_result":          runtime.LastResult,
			"last_error":           runtime.LastError,
			"activation":           runtime.Activation,
			"controlled_in_flight": concurrency.Auths[authID],
			"activation_in_flight": concurrency.AuthActivations[authID],
		})
	}
	sort.Slice(auths, func(i, j int) bool { return fmt.Sprint(auths[i]["auth_id"]) < fmt.Sprint(auths[j]["auth_id"]) })
	return map[string]any{
		"quota_check_interval":          settings.QuotaCheckInterval,
		"quota_cache_ttl":               settings.QuotaCacheTTL,
		"quota_activation_enabled":      settings.QuotaActivationEnabled,
		"quota_activation_scope":        settings.QuotaActivationScope,
		"quota_activation_model":        settings.QuotaActivationModel,
		"runtime_path":                  path,
		"persistence_blocked":           blocked,
		"persistence_error":             persistErr,
		"last_error":                    lastError,
		"last_roster_sync":              doc.LastRosterSync,
		"last_round_at":                 doc.LastRoundAt,
		"observed_auth_count":           len(observations),
		"controlled_activation_current": concurrency.ActivationTotal,
		"auths":                         auths,
	}
}

func quotaObservationFreshness(observation quotaObservation, ttl time.Duration, now time.Time) string {
	if observation.ObservedAt.IsZero() || (observation.Long == nil && observation.Short == nil && !observation.ExplicitExhausted) {
		return "unknown"
	}
	if ttl <= 0 || observation.ObservedAt.After(now.Add(time.Minute)) || now.Sub(observation.ObservedAt) > ttl {
		return "stale"
	}
	if observation.Long != nil && !observation.Long.ResetAt.IsZero() && !now.Before(observation.Long.ResetAt) {
		return "stale"
	}
	if observation.Short != nil && !observation.Short.ResetAt.IsZero() && !now.Before(observation.Short.ResetAt) {
		return "stale"
	}
	return "fresh"
}

func publicQuotaObservation(observation quotaObservation) map[string]any {
	if observation.AuthID == "" && observation.ObservedAt.IsZero() && observation.Long == nil && observation.Short == nil && !observation.ExplicitExhausted {
		return nil
	}
	return map[string]any{
		"plan_type":          observation.PlanType,
		"source":             observation.Source,
		"observed_at":        observation.ObservedAt,
		"received_at":        observation.ReceivedAt,
		"short":              observation.Short,
		"long":               observation.Long,
		"explicit_exhausted": observation.ExplicitExhausted,
		"explicit_reset_at":  observation.ExplicitResetAt,
		"explicit_reason":    observation.ExplicitReason,
	}
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

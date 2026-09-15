package plugin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"cpa-key-policy/internal/policy"
)

type lookupAuthQuotaWindow struct {
	Kind             string   `json:"kind"`
	UsedPercent      *float64 `json:"used_percent,omitempty"`
	RemainingPercent *float64 `json:"remaining_percent,omitempty"`
	ResetAt          string   `json:"reset_at,omitempty"`
	Exhausted        bool     `json:"exhausted,omitempty"`
}

type lookupAuthQuotaAccount struct {
	Ref           string                 `json:"ref"`
	Label         string                 `json:"label"`
	Provider      string                 `json:"provider"`
	Tier          string                 `json:"tier"`
	Status        string                 `json:"status"`
	Availability  string                 `json:"availability"`
	Freshness     string                 `json:"freshness"`
	ObservedAt    string                 `json:"observed_at,omitempty"`
	Short         *lookupAuthQuotaWindow `json:"short,omitempty"`
	Long          *lookupAuthQuotaWindow `json:"long,omitempty"`
	CanRefresh    bool                   `json:"can_refresh"`
	RefreshAfter  string                 `json:"refresh_after,omitempty"`
	RefreshStatus string                 `json:"refresh_status"`
}

type lookupAuthQuotaSection struct {
	Status               string                   `json:"status"`
	ManualRefreshAllowed bool                     `json:"manual_refresh_allowed"`
	UnsupportedProviders []string                 `json:"unsupported_providers"`
	Accounts             []lookupAuthQuotaAccount `json:"accounts"`
}

type lookupQuotaTarget struct {
	authID        string
	authIndex     string
	fingerprint   string
	backoff       time.Time
	queryEligible bool
	ref           string
}

type lookupQuotaView struct {
	section lookupAuthQuotaSection
	targets map[string]lookupQuotaTarget
}

type lookupQuotaRoutes struct {
	allowAnyGroup bool
	groups        map[string]struct{}
	hasCodex      bool
	unsupported   []string
}

type manualQuotaRefreshResult struct {
	status  int
	code    string
	message string
	retryAt time.Time
	section lookupAuthQuotaSection
}

func ensureQuotaAuthRefSecret(doc *quotaRuntimeDocument) (bool, error) {
	if doc == nil {
		return false, nil
	}
	if _, ok := decodeQuotaAuthRefSecret(doc.AuthRefSecret); ok {
		return false, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return false, err
	}
	doc.AuthRefSecret = base64.RawURLEncoding.EncodeToString(raw)
	return true, nil
}

func decodeQuotaAuthRefSecret(encoded string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	return raw, err == nil && len(raw) >= 32
}

func (m *quotaManager) quotaAuthRefSecret() ([]byte, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.Lock()
	generated := false
	if strings.TrimSpace(m.runtime.AuthRefSecret) == "" {
		generated, _ = ensureQuotaAuthRefSecret(&m.runtime)
	}
	encoded := m.runtime.AuthRefSecret
	storeReady := m.runtimeStore != nil && !m.persistenceBlocked
	m.mu.Unlock()
	secret, ok := decodeQuotaAuthRefSecret(encoded)
	if ok && generated && storeReady {
		_ = m.persist()
	}
	return secret, ok
}

func quotaAuthRef(secret []byte, key policy.KeyConfig, runtime quotaAuthRuntime) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("cpa-key-policy:lookup-auth-ref:v1\x00"))
	_, _ = mac.Write([]byte(key.ID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key.KeyHash))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(runtime.AuthID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(runtime.CredentialFingerprint))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func lookupQuotaRoutesForKey(key policy.KeyConfig) lookupQuotaRoutes {
	routes := lookupQuotaRoutes{groups: make(map[string]struct{})}
	type routeKey struct {
		alias string
		model string
	}
	groupSets := make(map[routeKey]map[string]struct{})
	unsupported := make(map[string]struct{})
	for _, model := range key.Models {
		provider := strings.ToLower(strings.TrimSpace(model.Provider))
		if provider != "codex" {
			if provider != "" && provider != "native" {
				unsupported[publicUnsupportedProvider(provider)] = struct{}{}
			}
			continue
		}
		alias := strings.ToLower(strings.TrimSpace(model.Alias))
		target := strings.ToLower(strings.TrimSpace(model.TargetModel))
		if alias == "" || target == "" {
			continue
		}
		key := routeKey{alias: alias, model: target}
		groups := groupSets[key]
		if groups == nil {
			groups = make(map[string]struct{})
			groupSets[key] = groups
		}
		groups[strings.ToLower(strings.TrimSpace(model.Group))] = struct{}{}
	}
	for _, groups := range groupSets {
		if len(groups) != 1 {
			continue
		}
		routes.hasCodex = true
		for group := range groups {
			if group == "" {
				routes.allowAnyGroup = true
			} else {
				routes.groups[group] = struct{}{}
			}
		}
	}
	for provider := range unsupported {
		routes.unsupported = append(routes.unsupported, provider)
	}
	sort.Strings(routes.unsupported)
	return routes
}

func publicUnsupportedProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "antigravity", "gemini", "vertex", "aistudio", "claude", "kimi", "xai":
		return strings.ToLower(strings.TrimSpace(provider))
	default:
		return "other"
	}
}

func quotaKeyAllowsAuth(key policy.KeyConfig, authID string, groups []string) bool {
	if !key.Enabled || key.Native || key.AccountBinding == nil || len(key.AccountBinding.Allow) == 0 || !key.AccountBinding.Matches(authID) {
		return false
	}
	routes := lookupQuotaRoutesForKey(key)
	if !routes.hasCodex {
		return false
	}
	if routes.allowAnyGroup {
		return true
	}
	for _, group := range groups {
		if _, ok := routes.groups[strings.ToLower(strings.TrimSpace(group))]; ok {
			return true
		}
	}
	return false
}

func (m *quotaManager) lookupQuotaView(key policy.KeyConfig, transportAvailable bool) lookupQuotaView {
	view := lookupQuotaView{
		section: lookupAuthQuotaSection{
			ManualRefreshAllowed: key.AllowQuotaRefresh,
			UnsupportedProviders: []string{},
			Accounts:             []lookupAuthQuotaAccount{},
		},
		targets: make(map[string]lookupQuotaTarget),
	}
	if key.AccountBinding == nil || len(key.AccountBinding.Allow) == 0 {
		view.section.Status = "binding_required"
		return view
	}
	routes := lookupQuotaRoutesForKey(key)
	view.section.UnsupportedProviders = append([]string{}, routes.unsupported...)
	if !routes.hasCodex {
		view.section.Status = "route_unproven"
		return view
	}
	secret, secretOK := m.quotaAuthRefSecret()
	now := m.now()
	interval, ttl := m.durations()
	m.mu.Lock()
	lastRosterSync := m.runtime.LastRosterSync
	persistenceBlocked := m.persistenceBlocked
	runtimes := make(map[string]quotaAuthRuntime, len(m.runtime.Auths))
	for authID, runtime := range m.runtime.Auths {
		copy := runtime
		copy.Groups = append([]string(nil), runtime.Groups...)
		runtimes[authID] = copy
	}
	m.mu.Unlock()
	if !secretOK || lastRosterSync.IsZero() || lastRosterSync.After(now.Add(time.Minute)) || now.Sub(lastRosterSync) > 2*interval {
		view.section.Status = "roster_unavailable"
		return view
	}
	for authID, runtime := range runtimes {
		if !runtime.RosterConfirmed || runtime.Provider != "codex" || runtime.CredentialFingerprint == "" || !runtime.LastRosterSeenAt.Equal(lastRosterSync) {
			continue
		}
		if !quotaKeyAllowsAuth(key, authID, runtime.Groups) {
			continue
		}
		ref := quotaAuthRef(secret, key, runtime)
		observation, _ := m.cache.get(authID)
		if observation.CredentialFingerprint != "" && observation.CredentialFingerprint != runtime.CredentialFingerprint {
			observation = quotaObservation{}
		}
		account := lookupAuthQuotaAccount{
			Ref:           ref,
			Provider:      "codex",
			Tier:          publicQuotaTier(runtime.PlanType, observation.PlanType),
			Status:        publicQuotaAuthStatus(runtime),
			Availability:  publicQuotaAvailability(observation, ttl, now),
			Freshness:     quotaObservationFreshness(observation, ttl, now),
			Short:         publicLookupQuotaWindow(observation.Short),
			Long:          publicLookupQuotaWindow(observation.Long),
			RefreshStatus: "permission_disabled",
		}
		if account.Short != nil || account.Long != nil || observation.ExplicitExhausted {
			account.ObservedAt = publicQuotaTime(observation.ObservedAt)
		}
		target := lookupQuotaTarget{
			authID:        authID,
			authIndex:     runtime.AuthIndex,
			fingerprint:   runtime.CredentialFingerprint,
			backoff:       runtime.QuotaBackoffUntil,
			queryEligible: runtime.QueryEligible,
			ref:           ref,
		}
		if key.AllowQuotaRefresh {
			switch {
			case !transportAvailable || persistenceBlocked:
				account.RefreshStatus = "transport_unavailable"
			case !runtime.QueryEligible:
				account.RefreshStatus = "unavailable"
			default:
				state := m.operations.manualState(key.ID, authID, runtime.QuotaBackoffUntil)
				account.RefreshStatus = state.Status
				account.CanRefresh = state.Status == "ready"
				account.RefreshAfter = publicQuotaTime(state.RetryAt)
			}
		}
		view.section.Accounts = append(view.section.Accounts, account)
		view.targets[ref] = target
	}
	sort.Slice(view.section.Accounts, func(i, j int) bool {
		return view.section.Accounts[i].Ref < view.section.Accounts[j].Ref
	})
	assignQuotaAccountLabels(view.section.Accounts)
	if len(view.section.Accounts) == 0 {
		view.section.Status = "no_matches"
	} else {
		view.section.Status = "ready"
	}
	return view
}

func publicQuotaAvailability(observation quotaObservation, ttl time.Duration, now time.Time) string {
	availability := classifyQuotaObservation(observation, ttl, now)
	switch availability {
	case quotaAvailabilityReady:
		return "ready"
	case quotaAvailabilityExhausted:
		return "exhausted"
	default:
		return "unknown"
	}
}

func publicQuotaAuthStatus(runtime quotaAuthRuntime) string {
	switch runtime.ExclusionReason {
	case "disabled":
		return "disabled"
	case "host_unavailable":
		return "unavailable"
	case "access_token_expired":
		return "expired"
	case "per_auth_proxy_unsupported":
		return "unqueryable"
	}
	if runtime.QueryEligible {
		return "active"
	}
	return "unknown"
}

func publicQuotaTier(values ...string) string {
	resolved := ""
	seenValue := false
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		seenValue = true
		switch value {
		case "pro", "team", "plus", "free":
		default:
			return "unknown"
		}
		if resolved != "" && resolved != value {
			return "unknown"
		}
		resolved = value
	}
	if !seenValue || resolved == "" {
		return "unknown"
	}
	return resolved
}

func publicLookupQuotaWindow(window *quotaWindow) *lookupAuthQuotaWindow {
	if window == nil {
		return nil
	}
	out := &lookupAuthQuotaWindow{Kind: string(window.Kind), Exhausted: window.Exhausted}
	if window.UsedPercent != nil && validUsedPercent(*window.UsedPercent) {
		used := *window.UsedPercent
		remaining := math.Max(0, 100-used)
		out.UsedPercent = &used
		out.RemainingPercent = &remaining
	}
	out.ResetAt = publicQuotaTime(window.ResetAt)
	return out
}

func publicQuotaTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func assignQuotaAccountLabels(accounts []lookupAuthQuotaAccount) {
	for i := range accounts {
		length := 8
		ref := accounts[i].Ref
		if len(ref) < length {
			length = len(ref)
		}
		for length < len(ref) && quotaRefPrefixCollides(accounts, i, length) {
			length += 4
			if length > len(ref) {
				length = len(ref)
			}
		}
		accounts[i].Label = "A-" + strings.ToUpper(ref[:length])
	}
}

func quotaRefPrefixCollides(accounts []lookupAuthQuotaAccount, index, length int) bool {
	ref := accounts[index].Ref
	if len(ref) < length {
		length = len(ref)
	}
	prefix := ref[:length]
	for other := range accounts {
		if other == index || len(accounts[other].Ref) < length {
			continue
		}
		if accounts[other].Ref[:length] == prefix {
			return true
		}
	}
	return false
}

func singleLookupHeader(headers http.Header, name string) (string, bool) {
	values := headers.Values(name)
	if len(values) != 1 {
		return "", false
	}
	value := strings.TrimSpace(values[0])
	return value, value != ""
}

func (a *App) lookupQuotaRefresh(headers http.Header, hostCallbackID string) ManagementResponse {
	token, ok := strictBearerToken(headers)
	if !ok {
		return lookupUnauthorized()
	}
	key := a.store.FindByAPIKey(token)
	if key == nil || !key.Enabled || key.Native {
		return lookupUnauthorized()
	}
	marker, markerOK := singleLookupHeader(headers, "X-Key-Policy-Quota-Refresh")
	ref, refOK := singleLookupHeader(headers, "X-Key-Policy-Auth-Ref")
	if !markerOK || marker != "1" || !refOK {
		return lookupQuotaError(http.StatusBadRequest, "invalid_refresh_request", "explicit refresh headers are required", time.Time{})
	}
	if !key.AllowQuotaRefresh {
		return lookupQuotaError(http.StatusForbidden, "quota_refresh_forbidden", "manual quota refresh is not enabled for this key", time.Time{})
	}
	view := a.quota.lookupQuotaView(*key, strings.TrimSpace(hostCallbackID) != "")
	target, found := view.targets[ref]
	if !found || !hmac.Equal([]byte(target.ref), []byte(ref)) {
		return lookupQuotaError(http.StatusNotFound, "quota_account_inaccessible", "quota account is not accessible", time.Time{})
	}
	if strings.TrimSpace(hostCallbackID) == "" {
		return lookupQuotaError(http.StatusServiceUnavailable, "quota_refresh_transport_unavailable", "host request cancellation is unavailable", time.Time{})
	}
	a.quota.mu.Lock()
	persistenceBlocked := a.quota.persistenceBlocked
	a.quota.mu.Unlock()
	if persistenceBlocked {
		return lookupQuotaError(http.StatusServiceUnavailable, "quota_refresh_state_unavailable", "quota state persistence is unavailable", time.Time{})
	}
	if !target.queryEligible {
		return lookupQuotaError(http.StatusConflict, "quota_refresh_unavailable", "quota account cannot be queried", time.Time{})
	}
	release, gate := a.quota.operations.acquireManual(key.ID, target.authID, target.backoff)
	if !gate.Acquired {
		if gate.Status == "cooldown" {
			return lookupQuotaError(http.StatusTooManyRequests, "quota_refresh_cooldown", "manual quota refresh is cooling down", gate.RetryAt)
		}
		if gate.Status == "transport_unavailable" {
			return lookupQuotaError(http.StatusServiceUnavailable, "quota_refresh_transport_unavailable", "manual quota refresh is unavailable", time.Time{})
		}
		return lookupQuotaError(http.StatusTooManyRequests, "quota_refresh_busy", "another quota operation is in progress", time.Time{})
	}
	resultCh := make(chan manualQuotaRefreshResult, 1)
	go func() {
		result := a.quota.executeManualQuotaRefresh(token, target, strings.TrimSpace(hostCallbackID))
		release()
		if result.status == http.StatusOK {
			current := a.store.FindByAPIKey(token)
			if current == nil || !current.Enabled || current.Native || !current.AllowQuotaRefresh {
				result = manualQuotaRefreshResult{status: http.StatusNotFound, code: "quota_account_inaccessible", message: "quota account is not accessible"}
			} else {
				latest := a.quota.lookupQuotaView(*current, true)
				if _, stillVisible := latest.targets[ref]; !stillVisible {
					result = manualQuotaRefreshResult{status: http.StatusNotFound, code: "quota_account_inaccessible", message: "quota account is not accessible"}
				} else {
					result.section = latest.section
				}
			}
		}
		resultCh <- result
	}()
	timeout := a.quota.manualTimeout
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-resultCh:
		if result.status != http.StatusOK {
			return lookupQuotaError(result.status, result.code, result.message, result.retryAt)
		}
		response := jsonResponse(http.StatusOK, map[string]any{"auth_quotas": result.section})
		setLookupHeaders(&response)
		return response
	case <-timer.C:
		return lookupQuotaError(http.StatusGatewayTimeout, "quota_refresh_timeout", "quota refresh timed out", time.Time{})
	}
}

func (m *quotaManager) executeManualQuotaRefresh(token string, target lookupQuotaTarget, hostCallbackID string) manualQuotaRefreshResult {
	host := m.hostSnapshot()
	if host == nil {
		return manualQuotaRefreshResult{status: http.StatusServiceUnavailable, code: "quota_refresh_transport_unavailable", message: "host quota transport is unavailable"}
	}
	now := m.now()
	rosterEntry, ok := currentManualQuotaRosterEntry(host, target)
	if !ok {
		return manualQuotaRefreshResult{status: http.StatusNotFound, code: "quota_account_inaccessible", message: "quota account is not accessible"}
	}
	evaluation := confirmQuotaRosterEntry(host, rosterEntry, m.store.ClassifyRulesSnapshot(), now)
	if !manualQuotaEvaluationMatches(evaluation, target) {
		return manualQuotaRefreshResult{status: http.StatusNotFound, code: "quota_account_inaccessible", message: "quota account is not accessible"}
	}
	current := m.store.FindByAPIKey(token)
	if current == nil || !current.Enabled || current.Native || !current.AllowQuotaRefresh || !quotaKeyAllowsAuth(*current, target.authID, evaluation.groups) {
		return manualQuotaRefreshResult{status: http.StatusNotFound, code: "quota_account_inaccessible", message: "quota account is not accessible"}
	}
	observation, statusCode, err := fetchCodexQuotaWithCallback(host, evaluation.credentials, m.now, hostCallbackID)
	if err != nil {
		var httpErr quotaHTTPError
		if errors.As(err, &httpErr) {
			m.setQuotaBackoff(target.authID, httpErr.retryAt)
			_ = m.persist()
			if statusCode == http.StatusTooManyRequests {
				return manualQuotaRefreshResult{status: http.StatusTooManyRequests, code: "quota_query_limited", message: "upstream quota query was rate limited", retryAt: httpErr.retryAt}
			}
		}
		return manualQuotaRefreshResult{status: http.StatusBadGateway, code: "quota_refresh_failed", message: "upstream quota query failed"}
	}
	postEntry, ok := currentManualQuotaRosterEntry(host, target)
	if !ok {
		return manualQuotaRefreshResult{status: http.StatusNotFound, code: "quota_account_inaccessible", message: "quota account is not accessible"}
	}
	post := confirmQuotaRosterEntry(host, postEntry, m.store.ClassifyRulesSnapshot(), m.now())
	if !manualQuotaEvaluationMatches(post, target) {
		return manualQuotaRefreshResult{status: http.StatusNotFound, code: "quota_account_inaccessible", message: "quota account is not accessible"}
	}
	current = m.store.FindByAPIKey(token)
	if current == nil || !current.Enabled || current.Native || !current.AllowQuotaRefresh || !quotaKeyAllowsAuth(*current, target.authID, post.groups) {
		return manualQuotaRefreshResult{status: http.StatusNotFound, code: "quota_account_inaccessible", message: "quota account is not accessible"}
	}
	observation.AuthIndex = post.entry.AuthIndex
	observation.CredentialFingerprint = post.fingerprint
	m.cache.observe(target.authID, post.entry.AuthIndex, "lookup-manual", observation)
	m.setQuotaBackoff(target.authID, time.Time{})
	if err := m.persist(); err != nil {
		return manualQuotaRefreshResult{status: http.StatusServiceUnavailable, code: "quota_refresh_state_unavailable", message: "quota state could not be persisted"}
	}
	return manualQuotaRefreshResult{status: http.StatusOK}
}

func currentManualQuotaRosterEntry(host HostClient, target lookupQuotaTarget) (HostAuthEntry, bool) {
	entries, err := host.ListAuths()
	if err != nil {
		return HostAuthEntry{}, false
	}
	for _, entry := range entries {
		authID := strings.TrimSpace(entry.ID)
		if authID == "" {
			authID = strings.TrimSpace(entry.Name)
		}
		if authID != target.authID || strings.TrimSpace(entry.AuthIndex) != target.authIndex {
			continue
		}
		entry.ID = authID
		return entry, true
	}
	return HostAuthEntry{}, false
}

func manualQuotaEvaluationMatches(evaluation quotaRosterEvaluation, target lookupQuotaTarget) bool {
	return evaluation.confirmed && evaluation.queryEligible &&
		strings.TrimSpace(evaluation.entry.ID) == target.authID &&
		strings.TrimSpace(evaluation.entry.AuthIndex) == target.authIndex &&
		evaluation.fingerprint == target.fingerprint
}

func lookupQuotaError(status int, code, message string, retryAt time.Time) ManagementResponse {
	response := jsonError(status, code, message)
	setLookupHeaders(&response)
	if retryAt.After(time.Now()) {
		seconds := int(math.Ceil(time.Until(retryAt).Seconds()))
		if seconds < 1 {
			seconds = 1
		}
		response.Headers.Set("Retry-After", strconv.Itoa(seconds))
	}
	return response
}

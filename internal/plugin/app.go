package plugin

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"cpa-key-policy/internal/plugin/web"
	"cpa-key-policy/internal/policy"
)

type App struct {
	store           *policy.Store
	classifyMu      sync.RWMutex
	classifyCache   map[string][]string
	schedulerMu     sync.Mutex
	schedulerRR     map[string]*smoothWeightedState
	schedulerCursor map[string]string
	selectionMu     sync.Mutex
	concurrency     *concurrencyTracker
	affinity        *affinityCache
	quota           *quotaManager
}

const classifyCacheCapacity = 4096

func NewApp() *App {
	store := policy.NewStore()
	_ = store.Configure(policy.DefaultConfig())
	settings := store.RuntimeSettings()
	concurrency := newConcurrencyTracker()
	app := &App{
		store:           store,
		classifyCache:   make(map[string][]string),
		schedulerRR:     make(map[string]*smoothWeightedState),
		schedulerCursor: make(map[string]string),
		concurrency:     concurrency,
		affinity:        newAffinityCache(time.Now, time.Duration(settings.SessionAffinityIdleTTLSeconds)*time.Second, settings.SessionAffinityMaxEntries),
	}
	app.quota = newQuotaManager(store, concurrency, time.Now)
	return app
}

// SetHostClient supplies the narrow host callback bridge used only by quota
// observation/maintenance. The scheduler hot path never invokes this client.
func (a *App) SetHostClient(host HostClient) {
	if a != nil && a.quota != nil {
		a.quota.setHostClient(host)
	}
}

func (a *App) HandleMethod(method string, request []byte) ([]byte, error) {
	return safePluginCall(func() ([]byte, error) {
		return a.handleMethod(method, request)
	})
}

func (a *App) handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case MethodPluginRegister, MethodPluginReconfigure:
		if err := a.configure(request); err != nil {
			return nil, err
		}
		return OKEnvelope(a.registration())
	case MethodFrontendAuthIdentifier:
		return OKEnvelope(IdentifierResponse{Identifier: PluginID})
	case MethodFrontendAuthAuthenticate:
		return a.authenticate(request)
	case MethodModelRoute:
		return a.routeModel(request)
	case MethodRequestInterceptBefore:
		return a.interceptRequestBefore(request)
	case MethodRequestInterceptAfter:
		return a.interceptRequestAfter(request)
	case MethodRequestComplete:
		return a.handleRequestComplete(request)
	case MethodSchedulerPick:
		return a.pickScheduler(request)
	case MethodResponseInterceptAfter:
		return a.interceptResponse(request)
	case MethodUsageHandle:
		return a.handleUsage(request)
	case MethodManagementRegister:
		return OKEnvelope(a.managementRegistration())
	case MethodManagementHandle:
		return a.handleManagement(request)
	default:
		return ErrorEnvelope("unknown_method", "unknown method: "+method, http.StatusNotFound), nil
	}
}

func safePluginCall(call func() ([]byte, error)) (response []byte, err error) {
	defer func() {
		if recover() != nil {
			response = nil
			err = errors.New("plugin panic recovered")
		}
	}()
	return call()
}

func (a *App) configure(raw []byte) error {
	var req LifecycleRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return err
		}
	}
	cfg, err := policy.DecodeConfig(req.ConfigYAML)
	if err != nil {
		return err
	}
	previousSettings := a.store.RuntimeSettings()
	previousKeys := a.store.Keys()
	if err := a.store.Configure(cfg); err != nil {
		return err
	}
	settings := a.store.RuntimeSettings()
	keys := a.store.Keys()
	a.affinity.configure(time.Duration(settings.SessionAffinityIdleTTLSeconds)*time.Second, settings.SessionAffinityMaxEntries)
	// Register the classify cache clear callback, then clear once for safety.
	a.store.SetOnClassifyRulesChanged(func() {
		a.clearClassifyCache()
		a.clearSchedulerState()
	})
	a.clearClassifyCache()
	a.clearSchedulerState()
	a.store.StartUsageFlusher()
	if a.quota != nil {
		a.quota.invalidateRoster()
		restartQuotaDeadline := !quotaScheduleNeeded(previousSettings, previousKeys) && quotaScheduleNeeded(settings, keys)
		a.quota.configure(a.store.StatePath(), restartQuotaDeadline)
	}
	return nil
}

// Shutdown flushes usage. Host calls this on plugin unload.
func (a *App) Shutdown() {
	a.concurrency.stopAccepting()
	if a.quota != nil {
		a.quota.shutdown()
	}
	a.store.StopUsageFlusher()
}

func (a *App) registration() Registration {
	return Registration{
		SchemaVersion: SchemaVersion,
		Metadata: Metadata{
			Name:             PluginName,
			Version:          Version,
			Author:           "cpa-key-policy",
			GitHubRepository: "https://github.com/router-for-me/CLIProxyAPI",
			ConfigFields: []ConfigField{
				{Name: "enabled", Type: "boolean", Description: "Enable or disable this plugin without unloading it."},
				{Name: "state_file", Type: "string", Description: "JSON state file used for key policy changes made through the Management API."},
				{Name: "global_weighted_round_robin", Type: "boolean", Description: "忽略别名目标的 group，对当前 provider/model 的全部候选凭证执行全局加权轮询。"},
				{Name: "auth_concurrency_limits", Type: "object", Description: "Exact auth-file ID to maximum controlled in-flight requests; zero or missing means unlimited."},
				{Name: "session_affinity_idle_ttl_seconds", Type: "integer", Description: "Idle TTL for in-memory session affinity bindings."},
				{Name: "session_affinity_max_entries", Type: "integer", Description: "Maximum in-memory session affinity bindings."},
				{Name: "quota_check_interval", Type: "string", Description: "Background Codex quota review interval (duration, default 30m)."},
				{Name: "quota_cache_ttl", Type: "string", Description: "Freshness TTL for quota evidence (duration, default 30m)."},
				{Name: "quota_activation_enabled", Type: "boolean", Description: "Allow small background response requests for strictly detected lazy Codex windows."},
				{Name: "quota_activation_scope", Type: "string", EnumValues: []string{"managed-pools", "all-codex"}, Description: "Auth scope eligible for background activation."},
				{Name: "quota_activation_model", Type: "string", Description: "Codex model used by the small background activation request (default gpt-5.6-luna)."},
				{Name: "keys", Type: "array", Description: "Downstream key policies, including optional fail-closed account_binding allow globs. State file wins after it exists."},
			},
		},
		Capabilities: Capabilities{
			FrontendAuthProvider:          true,
			FrontendAuthProviderExclusive: false,
			ModelRouter:                   true,
			Scheduler:                     true,
			RequestInterceptor:            true,
			RequestLifecyclePlugin:        true,
			ResponseInterceptor:           true,
			UsagePlugin:                   true,
			ManagementAPI:                 true,
		},
	}
}

func (a *App) authenticate(raw []byte) ([]byte, error) {
	var req FrontendAuthRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	decision := a.store.Authenticate(req.Method, req.Path, req.Headers, req.Query, req.Body)
	if !decision.Known || !decision.Allowed {
		return OKEnvelope(FrontendAuthResponse{Authenticated: false})
	}
	meta := map[string]string{
		"provider":        PluginID,
		"key_id":          decision.KeyID,
		"requested_model": decision.Requested,
	}
	if decision.Rule.Alias != "" {
		meta["alias"] = decision.Rule.Alias
		meta["target_provider"] = decision.Rule.Provider
		meta["target_model"] = decision.Rule.TargetModel
		if decision.Rule.Group != "" {
			// Group lets our Scheduler (scheduler.pick) restrict auth-file
			// selection to a tier/plan (codex plan_type, antigravity tier).
			// Empty = legacy "any file for the provider" behavior.
			meta["group"] = decision.Rule.Group
		}
	}
	return OKEnvelope(FrontendAuthResponse{
		Authenticated: true,
		Principal:     decision.Principal,
		Metadata:      meta,
	})
}

func (a *App) routeModel(raw []byte) ([]byte, error) {
	var req ModelRouteRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	rule, keyID, ok := a.store.Route(req.Headers, req.Query, req.RequestedModel)
	if !ok {
		return OKEnvelope(ModelRouteResponse{Handled: false})
	}
	return OKEnvelope(ModelRouteResponse{
		Handled:     true,
		TargetKind:  "provider",
		Target:      resolveProviderKey(rule.Provider, req.AvailableProviders),
		TargetModel: rule.TargetModel,
		Reason:      "cpa-key-policy:" + keyID,
	})
}

// interceptRequestBefore validates controlled request identity and atomically
// acquires its process-local key slot. Frontend-auth cannot express a terminal
// rejection: Authenticated=false is treated by CPA as "try the next provider".
func (a *App) interceptRequestBefore(raw []byte) ([]byte, error) {
	var req RequestInterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	if !a.store.Enabled() {
		return OKEnvelope(RequestInterceptResponse{})
	}
	resolution := a.store.ResolveRequestKey(req.Headers, req.Metadata)
	key := resolution.Key
	if !pluginControlsKey(key) {
		return OKEnvelope(RequestInterceptResponse{})
	}
	if !key.Enabled {
		return OKEnvelope(requestRejection(http.StatusUnauthorized, "key_disabled", "cpa-key-policy: configured key is disabled"))
	}
	if key.AccountBinding != nil {
		if resolution.Conflict {
			return OKEnvelope(requestRejection(http.StatusBadRequest, "credential_conflict", "cpa-key-policy: protected requests must not contain conflicting credentials"))
		}
		if !resolution.HeaderPresent || !resolution.HeaderMatches {
			return OKEnvelope(requestRejection(http.StatusUnauthorized, "header_key_required", "cpa-key-policy: account-bound requests require the configured key in a request header"))
		}
	}
	if strings.TrimSpace(req.RequestID) == "" {
		return OKEnvelope(requestRejectionWithType(http.StatusServiceUnavailable, "service_unavailable", "request_lifecycle_unavailable", "cpa-key-policy: host did not provide a request lifecycle id"))
	}
	current, acquired := a.concurrency.acquireKey(req.RequestID, key.ID, key.MaxConcurrentRequests)
	if !acquired {
		if key.MaxConcurrentRequests > 0 && current >= key.MaxConcurrentRequests {
			return OKEnvelope(requestRejectionWithType(http.StatusTooManyRequests, "rate_limit_error", "key_concurrency_exceeded", fmt.Sprintf("cpa-key-policy: key %q already has %d in-flight request(s), limit %d", key.ID, current, key.MaxConcurrentRequests)))
		}
		return OKEnvelope(requestRejectionWithType(http.StatusServiceUnavailable, "service_unavailable", "request_lifecycle_conflict", "cpa-key-policy: request lifecycle id is already owned by another key"))
	}
	return OKEnvelope(RequestInterceptResponse{})
}

func requestRejection(status int, code, message string) RequestInterceptResponse {
	return requestRejectionWithType(status, "authentication_error", code, message)
}

func requestRejectionWithType(status int, errorType, code, message string) RequestInterceptResponse {
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"type":    errorType,
			"code":    code,
			"message": message,
		},
	})
	return RequestInterceptResponse{
		Terminate:       true,
		StatusCode:      status,
		ResponseHeaders: http.Header{"Content-Type": []string{"application/json"}},
		ResponseBody:    body,
	}
}

func pluginControlsKey(key *policy.KeyConfig) bool {
	return key != nil && (!key.Native || key.AccountBinding != nil)
}

// interceptRequestAfter atomically admits the selected credential. This is the
// final concurrency gate: scheduler capacity is advisory and races are expected
// to be rejected here rather than oversubscribed.
func (a *App) interceptRequestAfter(raw []byte) ([]byte, error) {
	var req RequestInterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	if !a.store.Enabled() {
		return OKEnvelope(RequestInterceptResponse{})
	}
	keyID := a.concurrency.requestKey(req.RequestID)
	if keyID == "" {
		resolution := a.store.ResolveRequestKey(req.Headers, req.Metadata)
		if !pluginControlsKey(resolution.Key) {
			return OKEnvelope(RequestInterceptResponse{})
		}
		return OKEnvelope(requestRejectionWithType(http.StatusServiceUnavailable, "service_unavailable", "request_lifecycle_unavailable", "cpa-key-policy: request reached auth admission without a key lease"))
	}
	key := a.store.FindByID(keyID)
	if key == nil || !key.Enabled {
		return OKEnvelope(requestRejection(http.StatusUnauthorized, "key_disabled", "cpa-key-policy: configured key was disabled or removed before execution"))
	}
	authID := metadataString(req.Metadata, "selected_auth_id")
	proposalKey := schedulerAffinityProposalKey(key.ID, req.RequestedModel, authID, req.Metadata)
	if authID == "" {
		a.affinity.resolveProposal(proposalKey, false)
		return OKEnvelope(requestRejectionWithType(http.StatusServiceUnavailable, "service_unavailable", "selected_auth_unavailable", "cpa-key-policy: host did not expose the selected auth id"))
	}
	// Re-check an explicit binding at the final gate. A management update may
	// narrow the allowed pool after scheduler.pick but before execution starts;
	// that race must fail closed rather than run a now-disallowed credential.
	if key.AccountBinding != nil && !key.AccountBinding.Matches(authID) {
		a.affinity.resolveProposal(proposalKey, false)
		return OKEnvelope(requestRejectionWithType(http.StatusForbidden, "permission_error", "auth_not_bound", "cpa-key-policy: selected auth no longer satisfies the key's account binding"))
	}
	if key.AccountBinding != nil && key.AccountBinding.Strategy == policy.BindingStrategyQuotaFillFirst &&
		strings.EqualFold(metadataString(req.Metadata, "target_provider"), "codex") {
		_, ttl := a.quota.durations()
		if class, _ := a.quota.cache.classify(authID, ttl, time.Now()); class == quotaAvailabilityExhausted {
			a.affinity.resolveProposal(proposalKey, false)
			return OKEnvelope(requestRejectionWithType(http.StatusTooManyRequests, "rate_limit_error", "quota_exhausted", "cpa-key-policy: selected auth became quota-exhausted before execution"))
		}
	}
	limit := a.store.AuthConcurrencyLimit(authID)
	current, acquired := a.concurrency.acquireAuth(req.RequestID, authID, limit)
	if !acquired {
		a.affinity.resolveProposal(proposalKey, false)
		if limit > 0 && current >= limit {
			return OKEnvelope(requestRejectionWithType(http.StatusTooManyRequests, "rate_limit_error", "auth_concurrency_exceeded", fmt.Sprintf("cpa-key-policy: auth %q already has %d controlled in-flight request(s), limit %d", authID, current, limit)))
		}
		return OKEnvelope(requestRejectionWithType(http.StatusServiceUnavailable, "service_unavailable", "request_lifecycle_conflict", "cpa-key-policy: selected auth could not be attached to the request lease"))
	}
	a.affinity.resolveProposal(proposalKey, true)
	if a.concurrency.markPerCallCharged(req.RequestID) {
		a.store.ChargeDeferredPerCall(key.ID, metadataString(req.Metadata, "request_path"), req.RequestedModel, req.Model)
	}
	return OKEnvelope(RequestInterceptResponse{})
}

func (a *App) handleRequestComplete(raw []byte) ([]byte, error) {
	var completion RequestCompletion
	if err := json.Unmarshal(raw, &completion); err != nil {
		return nil, err
	}
	a.concurrency.complete(completion.RequestID)
	return OKEnvelope(RequestCompletionResponse{})
}

func metadataString(metadata map[string]any, name string) string {
	for key, value := range metadata {
		if strings.EqualFold(strings.TrimSpace(key), name) {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}

// resolveProviderKey maps a ModelRule's provider to the provider key CPA's
// auth manager uses, so HasBuiltinProvider(target) succeeds.
//
// OpenAI-compatibility providers are registered with auth.Provider
// prefixed as "openai-compatible-<name>" (see synthesizer.config:
// auth.Provider = OpenAICompatibleProviderKey(name)). The plugin's
// ModelRule.Provider field carries the bare name (e.g. "nvidia",
// "opencode"). Returning the bare name makes CPA skip the router
// ("model router returned unavailable provider") and fall back to the
// native path, which fails for non-native alias names like "test1".
//
// We pick the key present in AvailableProviders, trying the bare name
// first (for built-in providers like codex/claude/gemini) then the
// openai-compatible- prefixed form. If neither matches we return the
// bare name and let CPA's availability check skip us (the native path
// still resolves true model names).
func resolveProviderKey(provider string, availableProviders []string) string {
	p := strings.ToLower(strings.TrimSpace(provider))
	if p == "" {
		return p
	}
	if len(availableProviders) == 0 {
		return p
	}
	for _, candidate := range []string{p, "openai-compatible-" + p} {
		for _, avail := range availableProviders {
			if strings.EqualFold(candidate, avail) {
				return candidate
			}
		}
	}
	return p
}

func (a *App) interceptResponse(raw []byte) ([]byte, error) {
	var req ResponseInterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	// NOTE: billing is NOT done here. The host only invokes
	// response.intercept_after for non-streaming responses (the streaming path
	// goes through response.intercept_stream_chunk, which we don't handle).
	// Billing for both paths is centralized in usage.handle (handleUsage),
	// which the host fires after every request completes with already-parsed
	// token counts. Doing it here too would double-bill non-streaming requests.
	if req.Stream {
		// Streaming responses are not safe to rewrite (SSE framing) — return as-is.
		return OKEnvelope(ResponseInterceptResponse{})
	}
	alias, ok := a.store.ResponseAlias(req.RequestHeaders, nil, req.RequestedModel)
	if !ok {
		return OKEnvelope(ResponseInterceptResponse{})
	}
	body, changed := policy.RewriteTopLevelModel(req.Body, alias)
	if !changed {
		return OKEnvelope(ResponseInterceptResponse{})
	}
	return OKEnvelope(ResponseInterceptResponse{Body: body})
}

// pickScheduler enforces every applicable account constraint before selecting
// a candidate. Once a configured key is recognized, an empty intersection is
// a hard error: Handled=false would return the request to CPA's global pool.
func (a *App) pickScheduler(raw []byte) ([]byte, error) {
	var req SchedulerPickRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	if !a.store.Enabled() {
		return OKEnvelope(SchedulerPickResponse{Handled: false})
	}
	resolution := a.store.ResolveRequestKey(http.Header(req.Options.Headers), req.Options.Metadata)
	globalMode := a.store.GlobalWeightedRoundRobin()
	key := resolution.Key
	group := schedulerGroupFromMetadata(req.Options.Metadata)
	owner := "metadata:" + group
	var binding *policy.AccountBinding
	if key == nil {
		if group == "" || globalMode || resolution.HeaderPresent {
			// The key is not managed by this plugin. Preserve native CPA routing,
			// including host-owned session affinity.
			return OKEnvelope(SchedulerPickResponse{Handled: false})
		}
	} else {
		if !key.Enabled {
			return ErrorEnvelope("key_disabled", "cpa-key-policy: configured key is disabled", http.StatusUnauthorized), nil
		}
		owner = key.ID
		binding = key.AccountBinding
		if !globalMode || binding != nil {
			var err error
			group, err = policy.SchedulerGroupForKey(key, schedulerRequestedModel(req.Options.Metadata), schedulerRequestProvider(req), req.Model)
			if err != nil {
				return ErrorEnvelope("account_constraint_ambiguous", "cpa-key-policy: cannot determine a unique account constraint: "+err.Error(), http.StatusForbidden), nil
			}
		} else {
			group = ""
		}
	}
	protected := key != nil && (binding != nil || group != "")
	if protected {
		if resolution.Conflict {
			return ErrorEnvelope("credential_conflict", "cpa-key-policy: protected requests must not contain conflicting credentials", http.StatusBadRequest), nil
		}
		if !resolution.HeaderPresent || !resolution.HeaderMatches {
			return ErrorEnvelope("header_key_required", "cpa-key-policy: protected requests require the configured key in a request header", http.StatusUnauthorized), nil
		}
	}
	if len(req.Candidates) == 0 {
		return ErrorEnvelope("auth_not_found", "cpa-key-policy: the host supplied no credential candidates", http.StatusServiceUnavailable), nil
	}

	matched := make([]SchedulerAuthCandidate, 0, len(req.Candidates))
	for _, cand := range req.Candidates {
		if !schedulerCandidateUsable(cand.Status) {
			continue
		}
		if !candidateMatchesRequestedProvider(cand, req) {
			continue
		}
		if binding != nil && !binding.Matches(cand.ID) {
			continue
		}
		if group != "" && !a.candidateMatchesGroup(cand, group) {
			continue
		}
		matched = append(matched, cand)
	}
	if len(matched) == 0 {
		code := "auth_not_found"
		if binding != nil {
			code = "auth_not_bound"
		}
		return ErrorEnvelope(code, "cpa-key-policy: no host candidate satisfies the key's account constraints", http.StatusServiceUnavailable), nil
	}

	maxPriority := 0
	prioritySet := false
	weighted := make([]SchedulerAuthCandidate, 0, len(matched))
	for _, cand := range matched {
		if schedulerCandidateWeight(cand) <= 0 {
			continue
		}
		if !prioritySet || cand.Priority > maxPriority {
			maxPriority = cand.Priority
			prioritySet = true
			weighted = weighted[:0]
		}
		if cand.Priority == maxPriority {
			weighted = append(weighted, cand)
		}
	}
	if len(weighted) == 0 {
		return ErrorEnvelope("auth_not_found", "cpa-key-policy: 匹配的凭证均没有正权重", http.StatusServiceUnavailable), nil
	}

	available := make([]SchedulerAuthCandidate, 0, len(weighted))
	availableIDs := make(map[string]struct{}, len(weighted))
	enforceAuthConcurrency := pluginControlsKey(key)
	for _, cand := range weighted {
		// Auth limits deliberately cover only plugin-controlled requests. Legacy
		// group-only scheduling has no lifecycle lease and must not pretend to
		// provide a strict limit for otherwise unmanaged native traffic.
		if enforceAuthConcurrency && !a.concurrency.authAvailable(cand.ID, a.store.AuthConcurrencyLimit(cand.ID)) {
			continue
		}
		available = append(available, cand)
		availableIDs[cand.ID] = struct{}{}
	}
	if len(available) == 0 {
		return ErrorEnvelope("auth_concurrency_exceeded", "cpa-key-policy: all eligible auth files are at their configured concurrency limit", http.StatusTooManyRequests), nil
	}

	strategy := policy.BindingStrategyWeightedRoundRobin
	if binding != nil {
		strategy = binding.Strategy
	}
	quotaReadyPool := false
	if strategy == policy.BindingStrategyQuotaFillFirst && quotaStrategyApplies(req, available) {
		_, ttl := a.quota.durations()
		ready, unknown := quotaCandidateClasses(a.quota.cache, available, ttl, time.Now())
		switch {
		case len(ready) > 0:
			available = ready
			quotaReadyPool = true
		case len(unknown) > 0:
			available = unknown
		default:
			return ErrorEnvelope("quota_exhausted", "cpa-key-policy: all eligible Codex auth files have explicit quota exhaustion evidence", http.StatusTooManyRequests), nil
		}
		availableIDs = make(map[string]struct{}, len(available))
		for _, candidate := range available {
			availableIDs[candidate.ID] = struct{}{}
		}
	}
	pickBase := func() SchedulerAuthCandidate {
		poolKey := schedulerPoolKey(req, owner, group, maxPriority)
		switch strategy {
		case policy.BindingStrategyRoundRobin:
			return a.pickRoundRobin(poolKey, available)
		case policy.BindingStrategyFillFirst:
			return pickFillFirst(req, available)
		case policy.BindingStrategyQuotaFillFirst:
			if quotaReadyPool && quotaStrategyApplies(req, available) {
				return pickQuotaFillFirst(a.quota.cache, req, available)
			}
			return pickFillFirst(req, available)
		default:
			return a.pickSmoothWeighted(req, owner, group, maxPriority, available)
		}
	}

	var picked SchedulerAuthCandidate
	sessionID := schedulerSessionID(req.Options.Metadata)
	if key != nil && key.SessionAffinity && sessionID != "" {
		affinityKey := schedulerAffinityKey(req, key, group, globalMode, sessionID)
		proposalKey := func(authID string) string {
			return schedulerAffinityProposalKey(key.ID, schedulerRequestedModel(req.Options.Metadata), authID, req.Options.Metadata)
		}
		a.selectionMu.Lock()
		if authID, ok := a.affinity.use(affinityKey, availableIDs, proposalKey); ok {
			for _, candidate := range available {
				if candidate.ID == authID {
					picked = candidate
					break
				}
			}
		}
		if picked.ID == "" {
			picked = pickBase()
			a.affinity.propose(affinityKey, proposalKey(picked.ID), picked.ID)
		}
		a.selectionMu.Unlock()
	} else {
		picked = pickBase()
	}
	return OKEnvelope(SchedulerPickResponse{Handled: true, AuthID: picked.ID})
}

func schedulerSessionID(metadata map[string]any) string {
	if value := metadataString(metadata, "canonical_session_id"); value != "" {
		return value
	}
	return metadataString(metadata, "derived_session_id")
}

func schedulerAffinityKey(req SchedulerPickRequest, key *policy.KeyConfig, group string, globalMode bool, sessionID string) string {
	providers := append([]string(nil), req.Providers...)
	for index := range providers {
		providers[index] = strings.ToLower(strings.TrimSpace(providers[index]))
	}
	sort.Strings(providers)
	allow := []string(nil)
	strategy := ""
	if key != nil && key.AccountBinding != nil {
		allow = append(allow, key.AccountBinding.Allow...)
		sort.Strings(allow)
		strategy = string(key.AccountBinding.Strategy)
	}
	var source strings.Builder
	source.WriteString(strings.ToLower(strings.TrimSpace(key.ID)))
	source.WriteByte(0)
	source.WriteString(strings.ToLower(strings.TrimSpace(req.Provider)))
	source.WriteByte(0)
	source.WriteString(strings.Join(providers, ","))
	source.WriteByte(0)
	source.WriteString(strings.ToLower(strings.TrimSpace(req.Model)))
	source.WriteByte(0)
	source.WriteString(strings.ToLower(strings.TrimSpace(schedulerRequestedModel(req.Options.Metadata))))
	source.WriteByte(0)
	source.WriteString(strings.ToLower(strings.TrimSpace(group)))
	source.WriteByte(0)
	source.WriteString(strategy)
	source.WriteByte(0)
	source.WriteString(strings.Join(allow, "\x1f"))
	source.WriteByte(0)
	if globalMode {
		source.WriteByte('1')
	} else {
		source.WriteByte('0')
	}
	routeHash := sha256.Sum256([]byte(source.String()))
	sessionHash := sha256.Sum256([]byte(sessionID))
	return fmt.Sprintf("%x:%x", sessionHash, routeHash)
}

// schedulerAffinityProposalKey contains only data available in both
// scheduler.pick and request.intercept_after. It intentionally hashes the
// session identity and never stores a raw client key or request body.
func schedulerAffinityProposalKey(owner, requestedModel, authID string, metadata map[string]any) string {
	sessionID := schedulerSessionID(metadata)
	if strings.TrimSpace(owner) == "" || sessionID == "" {
		return ""
	}
	sessionHash := sha256.Sum256([]byte(sessionID))
	var route strings.Builder
	for _, field := range []string{"request_path", "target_provider", "target_model", "group", "auth_selection_model", "pinned_auth_id"} {
		route.WriteString(strings.ToLower(metadataString(metadata, field)))
		route.WriteByte(0)
	}
	routeHash := sha256.Sum256([]byte(route.String()))
	return strings.ToLower(strings.TrimSpace(owner)) + "\x00" + fmt.Sprintf("%x", sessionHash) + "\x00" +
		strings.ToLower(strings.TrimSpace(requestedModel)) + "\x00" + strings.TrimSpace(authID) + "\x00" + fmt.Sprintf("%x", routeHash)
}

func schedulerRequestedModel(metadata map[string]any) string {
	if metadata == nil {
		return ""
	}
	for key, value := range metadata {
		if strings.EqualFold(strings.TrimSpace(key), "requested_model") {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}

func schedulerRequestProvider(req SchedulerPickRequest) string {
	if provider := strings.TrimSpace(req.Provider); provider != "" {
		return provider
	}
	if len(req.Providers) == 1 {
		return strings.TrimSpace(req.Providers[0])
	}
	return ""
}

func candidateMatchesRequestedProvider(candidate SchedulerAuthCandidate, req SchedulerPickRequest) bool {
	provider := strings.ToLower(strings.TrimSpace(candidate.Provider))
	if requested := strings.ToLower(strings.TrimSpace(req.Provider)); requested != "" && requested != "mixed" {
		return provider == requested
	}
	if len(req.Providers) == 0 {
		return true
	}
	for _, requested := range req.Providers {
		if provider == strings.ToLower(strings.TrimSpace(requested)) {
			return true
		}
	}
	return false
}

func schedulerCandidateUsable(status string) bool {
	status = strings.ToLower(strings.TrimSpace(status))
	status = strings.NewReplacer("-", "_", " ", "_").Replace(status)
	// CPA may keep an auth's aggregate status at error after its current-model
	// retry deadline has elapsed. Candidate membership is the host's current
	// availability boundary, so a residual error alone must not block recovery.
	switch status {
	case "disabled", "expired", "revoked", "invalid", "unavailable", "cooldown", "cooling_down", "quota_exhausted", "exhausted", "blocked":
		return false
	default:
		return true
	}
}

// candidateMatchesGroup reports whether a candidate auth belongs to the
// requested group. It first evaluates user-defined ClassifyRules (which can
// override built-in detection — a candidate may belong to multiple groups).
// If no custom rule matches, it falls back to the built-in plan_type/tier
// detection. Uses an ID-level cache for performance with large auth-file sets.
func (a *App) candidateMatchesGroup(cand SchedulerAuthCandidate, group string) bool {
	groups := a.candidateGroups(cand)
	for _, g := range groups {
		if g == group {
			return true
		}
	}
	return false
}

// candidateGroups returns all groups a candidate belongs to. Custom rules are
// evaluated first (multi-group: a candidate can match multiple rules). If no
// custom rule matches, the built-in plan_type/tier detection runs. Results are
// cached by candidate ID; the cache is cleared on reconfigure.
func (a *App) candidateGroups(cand SchedulerAuthCandidate) []string {
	cacheKey := candidateClassifyCacheKey(cand)
	// Check cache.
	a.classifyMu.RLock()
	if cached, ok := a.classifyCache[cacheKey]; ok {
		a.classifyMu.RUnlock()
		return cached
	}
	a.classifyMu.RUnlock()

	var groups []string
	// 1. Evaluate custom classify rules (multi-group: collect all matches).
	// Group names are stored bare on the rule but stamped/matched with the
	// classify: prefix so they never collide with built-in plan_type values.
	for _, rule := range a.store.ClassifyRulesSnapshot() {
		if !rule.Enabled || rule.Compiled() == nil {
			continue
		}
		val := candidateFieldValue(cand, rule.Field)
		if val != "" && rule.Compiled().MatchString(val) {
			if g := policy.FormatClassifyGroup(rule.Group); g != "" {
				groups = append(groups, g)
			}
		}
	}
	// 2. If no custom rule matched, fall back to built-in plan_type/tier.
	if len(groups) == 0 {
		if g := builtInGroup(cand); g != "" {
			groups = append(groups, g)
		}
	}

	// Cache the result.
	a.classifyMu.Lock()
	if a.classifyCache == nil || len(a.classifyCache) >= classifyCacheCapacity {
		a.classifyCache = make(map[string][]string)
	}
	a.classifyCache[cacheKey] = groups
	a.classifyMu.Unlock()
	return groups
}

func (a *App) clearClassifyCache() {
	a.classifyMu.Lock()
	a.classifyCache = make(map[string][]string)
	a.classifyMu.Unlock()
}

func candidateClassifyCacheKey(cand SchedulerAuthCandidate) string {
	keys := make([]string, 0, len(cand.Attributes))
	for key := range cand.Attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	builder.WriteString(cand.ID)
	builder.WriteByte(0)
	builder.WriteString(cand.Provider)
	for _, key := range keys {
		builder.WriteByte(0)
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(cand.Attributes[key])
	}
	return builder.String()
}

// candidateFieldValue extracts the value of a named field from the candidate.
// Supported fields: "filename" (cand.ID), "provider" (cand.Provider),
// "plan_type" (cand.Attributes["plan_type"]), "tier" (cand.Attributes["tier"]),
// or any custom attribute key.
func candidateFieldValue(cand SchedulerAuthCandidate, field string) string {
	field = strings.ToLower(strings.TrimSpace(field))
	switch field {
	case "filename", "id":
		return cand.ID
	case "provider":
		return cand.Provider
	default:
		if cand.Attributes != nil {
			return cand.Attributes[field]
		}
	}
	return ""
}

// builtInGroup returns the built-in plan_type/tier group for a candidate,
// or "supported" if no recognizable claim is present (untiered bucket).
func builtInGroup(cand SchedulerAuthCandidate) string {
	if cand.Attributes == nil {
		return "supported"
	}
	plan := strings.ToLower(strings.TrimSpace(cand.Attributes["plan_type"]))
	tier := strings.ToLower(strings.TrimSpace(cand.Attributes["tier"]))
	if plan != "" {
		return plan
	}
	if tier != "" {
		return tier
	}
	return "supported"
}

// schedulerGroupFromMetadata reads the group stamped at authenticate time out
// of request-provided scheduler options. Tolerates string or any-typed values.
func schedulerGroupFromMetadata(meta map[string]any) string {
	if meta == nil {
		return ""
	}
	raw, ok := meta["group"]
	if !ok || raw == nil {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", v)))
	}
}

// finalized, already-parsed token record here after every request completes —
// streaming and non-streaming alike. This is the billing path that covers
// streaming (the host never invokes response.intercept_after on streams).
// Fire-and-forget: we always return an empty success envelope regardless of
// whether we actually billed (best-effort; unknown keys/aliases cost nothing).
func (a *App) handleUsage(raw []byte) ([]byte, error) {
	var req UsageHandleRequest
	// A malformed record must never break the request path: bill nothing.
	if err := json.Unmarshal(raw, &req); err != nil {
		return OKEnvelope(UsageHandleResponse{})
	}
	if a.quota != nil {
		a.quota.recordUsage(req)
	}
	_ = a.store.RecordUsage(req.APIKey, req.Alias, req.Model, req.Failed, policy.UsageDetail{
		InputTokens:         req.Detail.InputTokens,
		OutputTokens:        req.Detail.OutputTokens,
		ReasoningTokens:     req.Detail.ReasoningTokens,
		CachedTokens:        req.Detail.CachedTokens,
		CacheReadTokens:     req.Detail.CacheReadTokens,
		CacheCreationTokens: req.Detail.CacheCreationTokens,
		TotalTokens:         req.Detail.TotalTokens,
	})
	return OKEnvelope(UsageHandleResponse{})
}

func (a *App) managementRegistration() ManagementRegistrationResponse {
	base := "/plugins/" + PluginID
	return ManagementRegistrationResponse{
		Routes: []ManagementRoute{
			{Method: http.MethodGet, Path: base + "/keys", Description: "List downstream CPA key policies."},
			{Method: http.MethodPost, Path: base + "/keys", Description: "Create a downstream CPA key policy."},
			{Method: http.MethodPatch, Path: base + "/keys", Description: "Update a downstream CPA key policy by id."},
			{Method: http.MethodDelete, Path: base + "/keys", Description: "Delete a downstream CPA key policy by id."},
			{Method: http.MethodPost, Path: base + "/keys/rotate", Description: "Rotate one downstream CPA key by id."},
			{Method: http.MethodPost, Path: base + "/keys/reset-rpm", Description: "Reset one downstream CPA key RPM counter by id."},
			{Method: http.MethodPost, Path: base + "/keys/reset-usage", Description: "Reset one derived key's persisted UTC daily and seven-day usage by id."},
			{Method: http.MethodGet, Path: base + "/keys/usage", Description: "Per-alias usage breakdown for one downstream CPA key by id."},
			{Method: http.MethodGet, Path: base + "/status", Description: "Show cpa-key-policy runtime status."},
			{Method: http.MethodGet, Path: base + "/settings", Description: "Show scheduler settings."},
			{Method: http.MethodPatch, Path: base + "/settings", Description: "Update scheduler settings."},
			{Method: http.MethodGet, Path: base + "/quota-status", Description: "Show Codex quota observation and maintenance state."},
			{Method: http.MethodGet, Path: base + "/aliases", Description: "List the global alias mapping table."},
			{Method: http.MethodPost, Path: base + "/aliases", Description: "Create or update a global alias mapping."},
			{Method: http.MethodDelete, Path: base + "/aliases", Description: "Delete a global alias mapping by name."},
			{Method: http.MethodGet, Path: base + "/classify-rules", Description: "List credential classification rules."},
			{Method: http.MethodPost, Path: base + "/classify-rules", Description: "Create or update a classification rule."},
			{Method: http.MethodDelete, Path: base + "/classify-rules", Description: "Delete a classification rule by name."},
			{Method: http.MethodPost, Path: base + "/classify-rules/reorder", Description: "Reorder classification rules."},
			{Method: http.MethodPost, Path: base + "/classify-preview", Description: "Preview credential classification results for given descriptors."},
			{Method: http.MethodPost, Path: base + "/catalog", Description: "Build auth-file model picker catalog with classify + built-in groups."},
		},
		Resources: []ResourceRoute{
			{Path: web.IndexPath, Menu: "Key Policy", Description: "Web UI for managing downstream CPA key policies (create keys, pick models)."},
			{Path: web.LookupPath, Menu: "Key Usage", Description: "Read-only usage lookup for one derived key or all derived keys via an imported CPA-native key."},
			{Path: web.LookupDataPath, Description: "Bearer-authenticated derived-key usage data."},
			{Path: web.LookupQuotaRefreshPath, Description: "Explicitly authorized single-account Codex quota refresh."},
		},
	}
}

func (a *App) handleManagement(raw []byte) ([]byte, error) {
	var req ManagementRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	path := strings.TrimRight(req.Path, "/")

	// Plugin resource GETs (unauthenticated browser UI) are dispatched through
	// the same management.handle method by CPA's ServeResourceHTTP.
	resourcePrefix := "/v0/resource/plugins/" + PluginID
	if req.Method == http.MethodGet && strings.HasPrefix(path, resourcePrefix) {
		resourcePath := strings.TrimPrefix(path, resourcePrefix)
		if resourcePath == web.LookupDataPath || resourcePath == web.LookupQuotaRefreshPath {
			for name, values := range req.Query {
				switch strings.ToLower(strings.TrimSpace(name)) {
				case "key", "api_key", "key_id", "id", "auth_id", "auth_index", "auth_ref", "provider", "group", "url", "target_url", "refresh":
					if len(values) == 0 {
						continue
					}
					response := jsonError(http.StatusBadRequest, "query_key_forbidden", "lookup keys must be supplied only in the Authorization header")
					setLookupHeaders(&response)
					return OKEnvelope(response)
				}
			}
			if resourcePath == web.LookupQuotaRefreshPath {
				return OKEnvelope(a.lookupQuotaRefresh(req.Headers, req.HostCallbackID))
			}
			return OKEnvelope(a.lookupData(req.Headers, req.HostCallbackID))
		}
		status, headers, body := web.Serve(resourcePath)
		return OKEnvelope(ManagementResponse{StatusCode: status, Headers: headers, Body: body})
	}

	base := "/v0/management/plugins/" + PluginID
	switch {
	case req.Method == http.MethodGet && path == base+"/keys":
		return OKEnvelope(jsonResponse(http.StatusOK, map[string]any{"keys": a.publicKeys(a.store.Keys())}))
	case req.Method == http.MethodPost && path == base+"/keys":
		return OKEnvelope(a.createKey(req.Body))
	case req.Method == http.MethodPatch && path == base+"/keys":
		return OKEnvelope(a.patchKey(req.Body))
	case req.Method == http.MethodDelete && path == base+"/keys":
		return OKEnvelope(a.deleteKey(idFromRequest(req.Query, req.Body)))
	case req.Method == http.MethodPost && path == base+"/keys/rotate":
		return OKEnvelope(a.rotateKey(idFromRequest(req.Query, req.Body)))
	case req.Method == http.MethodPost && path == base+"/keys/reset-rpm":
		return OKEnvelope(a.resetRPM(idFromRequest(req.Query, req.Body)))
	case req.Method == http.MethodPost && path == base+"/keys/reset-usage":
		return OKEnvelope(a.resetUsage(idFromRequest(req.Query, req.Body)))
	case req.Method == http.MethodGet && path == base+"/keys/usage":
		return OKEnvelope(a.keyUsage(idFromRequest(req.Query, req.Body)))
	case req.Method == http.MethodGet && path == base+"/status":
		return OKEnvelope(jsonResponse(http.StatusOK, a.store.Status()))
	case req.Method == http.MethodGet && path == base+"/settings":
		return OKEnvelope(a.schedulerSettings())
	case req.Method == http.MethodPatch && path == base+"/settings":
		return OKEnvelope(a.updateSchedulerSettings(req.Body))
	case req.Method == http.MethodGet && path == base+"/quota-status":
		return OKEnvelope(jsonResponse(http.StatusOK, a.quota.status()))
	case req.Method == http.MethodGet && path == base+"/aliases":
		return OKEnvelope(jsonResponse(http.StatusOK, map[string]any{"aliases": a.store.AliasesSnapshot()}))
	case req.Method == http.MethodPost && path == base+"/aliases":
		return OKEnvelope(a.upsertAlias(req.Body))
	case req.Method == http.MethodDelete && path == base+"/aliases":
		return OKEnvelope(a.deleteAlias(req.Body))
	case req.Method == http.MethodGet && path == base+"/classify-rules":
		return OKEnvelope(jsonResponse(http.StatusOK, map[string]any{"rules": a.store.ClassifyRulesSnapshot()}))
	case req.Method == http.MethodPost && path == base+"/classify-rules":
		return OKEnvelope(a.upsertClassifyRule(req.Body))
	case req.Method == http.MethodDelete && path == base+"/classify-rules":
		return OKEnvelope(a.deleteClassifyRule(req.Body))
	case req.Method == http.MethodPost && path == base+"/classify-rules/reorder":
		return OKEnvelope(a.reorderClassifyRules(req.Body))
	case req.Method == http.MethodPost && path == base+"/classify-preview":
		return OKEnvelope(a.classifyPreview(req.Body))
	case req.Method == http.MethodPost && path == base+"/catalog":
		return OKEnvelope(a.buildCatalog(req.Body))
	default:
		return OKEnvelope(jsonError(http.StatusNotFound, "not_found", "unknown management route"))
	}
}

type schedulerSettingsRequest struct {
	GlobalWeightedRoundRobin      *bool           `json:"global_weighted_round_robin"`
	AuthConcurrencyLimits         *map[string]int `json:"auth_concurrency_limits"`
	SessionAffinityIdleTTLSeconds *int            `json:"session_affinity_idle_ttl_seconds"`
	SessionAffinityMaxEntries     *int            `json:"session_affinity_max_entries"`
	QuotaCheckInterval            *string         `json:"quota_check_interval"`
	QuotaCacheTTL                 *string         `json:"quota_cache_ttl"`
	QuotaActivationEnabled        *bool           `json:"quota_activation_enabled"`
	QuotaActivationScope          *string         `json:"quota_activation_scope"`
	QuotaActivationModel          *string         `json:"quota_activation_model"`
}

func (a *App) schedulerSettings() ManagementResponse {
	settings := a.store.RuntimeSettings()
	concurrency := a.concurrency.snapshot()
	return jsonResponse(http.StatusOK, map[string]any{
		"global_weighted_round_robin":       settings.GlobalWeightedRoundRobin,
		"auth_concurrency_limits":           settings.AuthConcurrencyLimits,
		"session_affinity_idle_ttl_seconds": settings.SessionAffinityIdleTTLSeconds,
		"session_affinity_max_entries":      settings.SessionAffinityMaxEntries,
		"quota_check_interval":              settings.QuotaCheckInterval,
		"quota_cache_ttl":                   settings.QuotaCacheTTL,
		"quota_activation_enabled":          settings.QuotaActivationEnabled,
		"quota_activation_scope":            settings.QuotaActivationScope,
		"quota_activation_model":            settings.QuotaActivationModel,
		"current_concurrent_requests":       concurrency.Total,
		"current_activation_requests":       concurrency.ActivationTotal,
		"auth_concurrency_current":          concurrency.Auths,
		"auth_activation_current":           concurrency.AuthActivations,
		"session_affinity_entries":          a.affinity.size(),
	})
}

func (a *App) updateSchedulerSettings(body []byte) ManagementResponse {
	var request schedulerSettingsRequest
	if err := json.Unmarshal(body, &request); err != nil {
		return jsonError(http.StatusBadRequest, "invalid_json", err.Error())
	}
	if request.GlobalWeightedRoundRobin == nil && request.AuthConcurrencyLimits == nil &&
		request.SessionAffinityIdleTTLSeconds == nil && request.SessionAffinityMaxEntries == nil &&
		request.QuotaCheckInterval == nil && request.QuotaCacheTTL == nil &&
		request.QuotaActivationEnabled == nil && request.QuotaActivationScope == nil && request.QuotaActivationModel == nil {
		return jsonError(http.StatusBadRequest, "missing_setting", "缺少可更新的调度设置")
	}
	previous := a.store.RuntimeSettings()
	keys := a.store.Keys()
	settings, err := a.store.UpdateRuntimeSettings(policy.RuntimeSettingsPatch{
		GlobalWeightedRoundRobin:      request.GlobalWeightedRoundRobin,
		AuthConcurrencyLimits:         request.AuthConcurrencyLimits,
		SessionAffinityIdleTTLSeconds: request.SessionAffinityIdleTTLSeconds,
		SessionAffinityMaxEntries:     request.SessionAffinityMaxEntries,
		QuotaCheckInterval:            request.QuotaCheckInterval,
		QuotaCacheTTL:                 request.QuotaCacheTTL,
		QuotaActivationEnabled:        request.QuotaActivationEnabled,
		QuotaActivationScope:          request.QuotaActivationScope,
		QuotaActivationModel:          request.QuotaActivationModel,
	})
	if err != nil {
		if errors.Is(err, policy.ErrInvalidRuntimeSettings) {
			return jsonError(http.StatusBadRequest, "invalid_setting", err.Error())
		}
		return jsonError(http.StatusInternalServerError, "settings_persist_failed", "保存调度设置失败: "+err.Error())
	}
	a.affinity.configure(time.Duration(settings.SessionAffinityIdleTTLSeconds)*time.Second, settings.SessionAffinityMaxEntries)
	a.clearSchedulerState()
	restartQuotaDeadline := !quotaScheduleNeeded(previous, keys) && quotaScheduleNeeded(settings, keys)
	a.quota.configure(a.store.StatePath(), restartQuotaDeadline)
	return a.schedulerSettings()
}

type keyWriteRequest struct {
	ID                    string                 `json:"id"`
	Name                  *string                `json:"name,omitempty"`
	Enabled               *bool                  `json:"enabled,omitempty"`
	Native                *bool                  `json:"native,omitempty"`
	Key                   string                 `json:"key,omitempty"`
	AccountBinding        *policy.AccountBinding `json:"account_binding,omitempty"`
	ClearAccountBinding   bool                   `json:"clear_account_binding,omitempty"`
	RPM                   *int                   `json:"rpm,omitempty"`
	MaxConcurrentRequests *int                   `json:"max_concurrent_requests,omitempty"`
	SessionAffinity       *bool                  `json:"session_affinity,omitempty"`
	Models                []policy.ModelRule     `json:"models,omitempty"`
	Aliases               []policy.KeyAliasRef   `json:"aliases,omitempty"`
	DailyLimitUSD         *float64               `json:"daily_limit_usd,omitempty"`
	WeeklyLimitUSD        *float64               `json:"weekly_limit_usd,omitempty"`
	AllowModelsEndpoint   *bool                  `json:"allow_models_endpoint,omitempty"`
	AllowQuotaRefresh     *bool                  `json:"allow_quota_refresh,omitempty"`
}

type publicKey struct {
	ID                        string                 `json:"id"`
	Name                      string                 `json:"name"`
	Enabled                   bool                   `json:"enabled"`
	Native                    bool                   `json:"native,omitempty"`
	KeyPreview                string                 `json:"key_preview"`
	AccountBinding            *policy.AccountBinding `json:"account_binding,omitempty"`
	RPM                       int                    `json:"rpm"`
	MaxConcurrentRequests     int                    `json:"max_concurrent_requests"`
	CurrentConcurrentRequests int                    `json:"current_concurrent_requests"`
	SessionAffinity           bool                   `json:"session_affinity"`
	Models                    []policy.ModelRule     `json:"models"`
	Aliases                   []policy.KeyAliasRef   `json:"aliases"`
	DailyLimitUSD             float64                `json:"daily_limit_usd"`
	WeeklyLimitUSD            float64                `json:"weekly_limit_usd"`
	AllowModelsEndpoint       bool                   `json:"allow_models_endpoint,omitempty"`
	AllowQuotaRefresh         bool                   `json:"allow_quota_refresh"`
	Usage                     policy.UsageSummary    `json:"usage"`
	CreatedAt                 string                 `json:"created_at,omitempty"`
	UpdatedAt                 string                 `json:"updated_at,omitempty"`
}

func (a *App) createKey(body []byte) ManagementResponse {
	var req keyWriteRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return jsonError(http.StatusBadRequest, "invalid_json", err.Error())
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		return jsonError(http.StatusBadRequest, "missing_id", "id is required")
	}
	plain := strings.TrimSpace(req.Key)
	native := req.Native != nil && *req.Native
	generated := false
	var err error
	if plain == "" && native {
		return jsonError(http.StatusBadRequest, "native_key_required", "importing a native CPA key requires key")
	}
	if plain == "" {
		plain, err = policy.GenerateKey()
		if err != nil {
			return jsonError(http.StatusInternalServerError, "key_generation_failed", err.Error())
		}
		generated = true
	}
	hash, err := policy.HashKey(plain)
	if err != nil {
		return jsonError(http.StatusBadRequest, "invalid_key", err.Error())
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	rpm := 0
	if req.RPM != nil {
		rpm = *req.RPM
	}
	name := req.ID
	if req.Name != nil && strings.TrimSpace(*req.Name) != "" {
		name = strings.TrimSpace(*req.Name)
	}
	item := policy.KeyConfig{
		ID:                    req.ID,
		Name:                  name,
		Enabled:               enabled,
		Native:                native,
		KeyHash:               hash,
		KeyPreview:            policy.PreviewKey(plain),
		CallerScope:           policy.CallerScopeForKey(req.ID),
		AccountBinding:        req.AccountBinding,
		RPM:                   rpm,
		MaxConcurrentRequests: applyInt(req.MaxConcurrentRequests, 0),
		SessionAffinity:       applyBool(req.SessionAffinity, false),
		Models:                req.Models,
		Aliases:               req.Aliases,
		DailyLimitUSD:         applyFloat64(req.DailyLimitUSD, 0),
		WeeklyLimitUSD:        applyFloat64(req.WeeklyLimitUSD, 0),
		AllowModelsEndpoint:   applyBool(req.AllowModelsEndpoint, false),
		AllowQuotaRefresh:     applyBool(req.AllowQuotaRefresh, false),
	}
	if native {
		item.CallerScope = policy.CallerScopeForKey(plain)
		item.KeyPreview = "native"
	}
	var upsertErr error
	if req.Models != nil {
		upsertErr = a.store.UpsertKeyWithModelPricing(item, true)
	} else {
		upsertErr = a.store.UpsertKey(item, true)
	}
	if upsertErr != nil {
		return jsonError(http.StatusBadRequest, "invalid_policy", upsertErr.Error())
	}
	a.notifyQuotaPolicyChanged()
	saved, _ := a.keyConfigByID(item.ID)
	bodyMap := map[string]any{
		"key":       a.publicKeyFromConfig(saved),
		"generated": generated,
	}
	if !native {
		bodyMap["plain_key"] = plain
	}
	return jsonResponse(http.StatusCreated, bodyMap)
}

func (a *App) patchKey(body []byte) ManagementResponse {
	var req keyWriteRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return jsonError(http.StatusBadRequest, "invalid_json", err.Error())
	}
	id := strings.TrimSpace(req.ID)
	if id == "" {
		return jsonError(http.StatusBadRequest, "missing_id", "id is required")
	}
	keys := a.store.Keys()
	var current *policy.KeyConfig
	for i := range keys {
		if keys[i].ID == id {
			copy := keys[i]
			current = &copy
			break
		}
	}
	if current == nil {
		return jsonError(http.StatusNotFound, "not_found", "key not found")
	}
	if req.Name != nil {
		current.Name = strings.TrimSpace(*req.Name)
	}
	if req.Enabled != nil {
		current.Enabled = *req.Enabled
	}
	if req.Native != nil && *req.Native != current.Native {
		return jsonError(http.StatusBadRequest, "native_immutable", "native cannot be changed after key creation")
	}
	if req.RPM != nil {
		current.RPM = *req.RPM
	}
	if req.MaxConcurrentRequests != nil {
		current.MaxConcurrentRequests = *req.MaxConcurrentRequests
	}
	if req.SessionAffinity != nil {
		current.SessionAffinity = *req.SessionAffinity
	}
	if req.DailyLimitUSD != nil {
		current.DailyLimitUSD = *req.DailyLimitUSD
	}
	if req.WeeklyLimitUSD != nil {
		current.WeeklyLimitUSD = *req.WeeklyLimitUSD
	}
	if req.AllowModelsEndpoint != nil {
		current.AllowModelsEndpoint = *req.AllowModelsEndpoint
	}
	if req.AllowQuotaRefresh != nil {
		current.AllowQuotaRefresh = *req.AllowQuotaRefresh
	}
	if req.Models != nil {
		current.Models = req.Models
	}
	if req.Aliases != nil {
		current.Aliases = req.Aliases
	}
	if req.ClearAccountBinding {
		current.AccountBinding = nil
	} else if req.AccountBinding != nil {
		current.AccountBinding = req.AccountBinding
	}
	if strings.TrimSpace(req.Key) != "" {
		hash, err := policy.HashKey(req.Key)
		if err != nil {
			return jsonError(http.StatusBadRequest, "invalid_key", err.Error())
		}
		current.KeyHash = hash
		current.KeyPreview = policy.PreviewKey(req.Key)
		if current.Native {
			current.CallerScope = policy.CallerScopeForKey(req.Key)
			current.KeyPreview = "native"
		}
	}
	var upsertErr error
	if req.Models != nil {
		upsertErr = a.store.UpsertKeyWithModelPricing(*current, true)
	} else {
		upsertErr = a.store.UpsertKey(*current, true)
	}
	if upsertErr != nil {
		return jsonError(http.StatusBadRequest, "invalid_policy", upsertErr.Error())
	}
	a.notifyQuotaPolicyChanged()
	saved, _ := a.keyConfigByID(current.ID)
	return jsonResponse(http.StatusOK, map[string]any{"key": a.publicKeyFromConfig(saved)})
}

func (a *App) keyConfigByID(id string) (policy.KeyConfig, bool) {
	for _, key := range a.store.Keys() {
		if key.ID == id {
			return key, true
		}
	}
	return policy.KeyConfig{}, false
}

func (a *App) deleteKey(id string) ManagementResponse {
	if err := a.store.DeleteKey(id); err != nil {
		return storeError(err)
	}
	a.notifyQuotaPolicyChanged()
	return jsonResponse(http.StatusOK, map[string]any{"deleted": true, "id": strings.TrimSpace(id)})
}

func (a *App) rotateKey(id string) ManagementResponse {
	plain, item, err := a.store.RotateKey(id)
	if err != nil {
		return storeError(err)
	}
	return jsonResponse(http.StatusOK, map[string]any{
		"key":       a.publicKeyFromConfig(item),
		"plain_key": plain,
		"generated": true,
	})
}

func (a *App) resetRPM(id string) ManagementResponse {
	if err := a.store.ResetRPM(id); err != nil {
		return jsonError(http.StatusBadRequest, "invalid_request", err.Error())
	}
	return jsonResponse(http.StatusOK, map[string]any{"reset": true, "id": strings.TrimSpace(id)})
}

func (a *App) resetUsage(id string) ManagementResponse {
	result, err := a.store.ResetUsage(id)
	if err != nil {
		return storeError(err)
	}
	return jsonResponse(http.StatusOK, map[string]any{
		"reset":    true,
		"id":       strings.TrimSpace(id),
		"reset_at": result.ResetAt,
		"usage":    result.Usage,
	})
}

// keyUsage returns the per-alias usage breakdown for one downstream key (the
// key detail subpage data source). id is taken from the query string (or body),
// matching the rotate/reset-rpm/delete convention.
func (a *App) keyUsage(id string) ManagementResponse {
	id = strings.TrimSpace(id)
	if id == "" {
		return jsonError(http.StatusBadRequest, "missing_id", "id is required")
	}
	key, usage, aliases, ok := a.store.UsageDetailsFor(id)
	if !ok {
		return jsonError(http.StatusNotFound, "not_found", "key not found")
	}
	return jsonResponse(http.StatusOK, map[string]any{
		"key_id":           key.ID,
		"key_name":         key.Name,
		"daily_limit_usd":  key.DailyLimitUSD,
		"weekly_limit_usd": key.WeeklyLimitUSD,
		"usage":            usage,
		"aliases":          aliases,
	})
}

func storeError(err error) ManagementResponse {
	if errors.Is(err, policy.ErrUnknownKey) {
		return jsonError(http.StatusNotFound, "not_found", "key not found")
	}
	return jsonError(http.StatusBadRequest, "invalid_request", err.Error())
}

func idFromRequest(query map[string][]string, body []byte) string {
	if query != nil {
		for _, name := range []string{"id", "key_id"} {
			if values := query[name]; len(values) > 0 && strings.TrimSpace(values[0]) != "" {
				return strings.TrimSpace(values[0])
			}
		}
	}
	var payload struct {
		ID    string `json:"id"`
		KeyID string `json:"key_id"`
	}
	if len(body) > 0 && json.Unmarshal(body, &payload) == nil {
		if strings.TrimSpace(payload.ID) != "" {
			return strings.TrimSpace(payload.ID)
		}
		return strings.TrimSpace(payload.KeyID)
	}
	return ""
}

func (a *App) publicKeys(keys []policy.KeyConfig) []publicKey {
	out := make([]publicKey, 0, len(keys))
	for _, key := range keys {
		out = append(out, a.publicKeyFromConfig(key))
	}
	return out
}

func (a *App) publicKeyFromConfig(key policy.KeyConfig) publicKey {
	var binding *policy.AccountBinding
	if key.AccountBinding != nil {
		copy := *key.AccountBinding
		copy.Allow = append([]string(nil), key.AccountBinding.Allow...)
		binding = &copy
	}
	out := publicKey{
		ID:                        key.ID,
		Name:                      key.Name,
		Enabled:                   key.Enabled,
		Native:                    key.Native,
		KeyPreview:                key.KeyPreview,
		AccountBinding:            binding,
		RPM:                       key.RPM,
		MaxConcurrentRequests:     key.MaxConcurrentRequests,
		CurrentConcurrentRequests: a.concurrency.keyCurrent(key.ID),
		SessionAffinity:           key.SessionAffinity,
		// Ensure models/aliases always serialize as [] (never null). A nil slice
		// would marshal to JSON null, which the UI accesses as .length and
		// crashes on. Models is derived (resolved from Aliases × global table);
		// Aliases is the canonical source.
		Models:              append([]policy.ModelRule{}, key.Models...),
		Aliases:             append([]policy.KeyAliasRef{}, key.Aliases...),
		DailyLimitUSD:       key.DailyLimitUSD,
		WeeklyLimitUSD:      key.WeeklyLimitUSD,
		AllowModelsEndpoint: key.AllowModelsEndpoint,
		AllowQuotaRefresh:   key.AllowQuotaRefresh,
		Usage:               a.store.UsageSummaryFor(key),
	}
	if !key.CreatedAt.IsZero() {
		out.CreatedAt = key.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	if !key.UpdatedAt.IsZero() {
		out.UpdatedAt = key.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	return out
}

func applyFloat64(v *float64, def float64) float64 {
	if v == nil {
		return def
	}
	return *v
}

func applyInt(v *int, def int) int {
	if v == nil {
		return def
	}
	return *v
}

func applyBool(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func (a *App) notifyQuotaPolicyChanged() {
	if a == nil || a.quota == nil {
		return
	}
	a.quota.invalidateRoster()
	a.quota.configure(a.store.StatePath(), false)
}

func jsonResponse(status int, payload any) ManagementResponse {
	body, err := json.Marshal(payload)
	if err != nil {
		return jsonError(http.StatusInternalServerError, "json_error", err.Error())
	}
	return ManagementResponse{
		StatusCode: status,
		Headers:    http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:       body,
	}
}

func jsonError(status int, code, message string) ManagementResponse {
	if status <= 0 {
		status = http.StatusInternalServerError
	}
	body, _ := json.Marshal(map[string]any{
		"error": map[string]string{
			"code":    strings.TrimSpace(code),
			"message": strings.TrimSpace(message),
		},
	})
	return ManagementResponse{
		StatusCode: status,
		Headers:    http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:       body,
	}
}

func (a *App) Store() *policy.Store {
	if a == nil {
		return nil
	}
	return a.store
}

func DebugEnvelope(raw []byte) string {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Sprintf("invalid envelope: %v", err)
	}
	if env.Error != nil {
		return env.Error.Message
	}
	return string(env.Result)
}

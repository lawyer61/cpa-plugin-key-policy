package plugin

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"cpa-key-policy/internal/policy"
)

// --- Alias mapping management handlers ---

// aliasUpsertRequest is the body for POST /aliases.
type aliasUpsertRequest struct {
	Alias                    string               `json:"alias"`
	Targets                  []policy.AliasTarget `json:"targets"`
	Dispatch                 string               `json:"dispatch"`
	BillingMode              string               `json:"billing_mode"`
	InputPricePerMillion     float64              `json:"input_price_per_million"`
	OutputPricePerMillion    float64              `json:"output_price_per_million"`
	CacheReadPricePerMillion float64              `json:"cache_read_price_per_million"`
	PerCallUSD               float64              `json:"per_call_usd"`
}

func (a *App) upsertAlias(raw []byte) ManagementResponse {
	var req aliasUpsertRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return jsonError(http.StatusBadRequest, "bad_request", err.Error())
	}
	// Build the new alias entry.
	alias := policy.AliasMapping{
		Alias:                    req.Alias,
		Targets:                  req.Targets,
		Dispatch:                 req.Dispatch,
		BillingMode:              req.BillingMode,
		InputPricePerMillion:     req.InputPricePerMillion,
		OutputPricePerMillion:    req.OutputPricePerMillion,
		CacheReadPricePerMillion: req.CacheReadPricePerMillion,
		PerCallUSD:               req.PerCallUSD,
	}
	if err := a.store.UpsertAlias(alias); err != nil {
		return jsonError(http.StatusBadRequest, "validation_error", err.Error())
	}
	a.notifyQuotaPolicyChanged()
	return jsonResponse(http.StatusOK, map[string]any{"alias": alias})
}

// aliasDeleteRequest is the body for DELETE /aliases.
type aliasDeleteRequest struct {
	Alias string `json:"alias"`
}

func (a *App) deleteAlias(raw []byte) ManagementResponse {
	var req aliasDeleteRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return jsonError(http.StatusBadRequest, "bad_request", err.Error())
	}
	if err := a.store.DeleteAlias(req.Alias); err != nil {
		return jsonError(http.StatusBadRequest, "delete_failed", err.Error())
	}
	a.notifyQuotaPolicyChanged()
	return jsonResponse(http.StatusOK, map[string]any{"deleted": true})
}

// --- Classification rule management handlers ---

// classifyRuleUpsertRequest is the body for POST /classify-rules.
type classifyRuleUpsertRequest struct {
	Name    string `json:"name"`
	Field   string `json:"field"`
	Pattern string `json:"pattern"`
	Group   string `json:"group"`
	Enabled bool   `json:"enabled"`
}

func (a *App) upsertClassifyRule(raw []byte) ManagementResponse {
	var req classifyRuleUpsertRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return jsonError(http.StatusBadRequest, "bad_request", err.Error())
	}
	rule := policy.ClassifyRule{
		Name:    req.Name,
		Field:   req.Field,
		Pattern: req.Pattern,
		Group:   req.Group,
		Enabled: req.Enabled,
	}
	if err := a.store.UpsertClassifyRule(rule); err != nil {
		return jsonError(http.StatusBadRequest, "validation_error", err.Error())
	}
	a.notifyQuotaPolicyChanged()
	return jsonResponse(http.StatusOK, map[string]any{"rule": rule})
}

// classifyRuleDeleteRequest is the body for DELETE /classify-rules.
type classifyRuleDeleteRequest struct {
	Name string `json:"name"`
}

func (a *App) deleteClassifyRule(raw []byte) ManagementResponse {
	var req classifyRuleDeleteRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return jsonError(http.StatusBadRequest, "bad_request", err.Error())
	}
	if err := a.store.DeleteClassifyRule(req.Name); err != nil {
		return jsonError(http.StatusBadRequest, "delete_failed", err.Error())
	}
	a.notifyQuotaPolicyChanged()
	return jsonResponse(http.StatusOK, map[string]any{"deleted": true})
}

// classifyReorderRequest is the body for POST /classify-rules/reorder.
type classifyReorderRequest struct {
	Names []string `json:"names"` // ordered list of rule names
}

func (a *App) reorderClassifyRules(raw []byte) ManagementResponse {
	var req classifyReorderRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return jsonError(http.StatusBadRequest, "bad_request", err.Error())
	}
	if err := a.store.ReorderClassifyRules(req.Names); err != nil {
		return jsonError(http.StatusBadRequest, "reorder_failed", err.Error())
	}
	a.notifyQuotaPolicyChanged()
	return jsonResponse(http.StatusOK, map[string]any{"reordered": true})
}

// --- Classify preview handler ---

// classifyPreviewRequest is the body for POST /classify-preview. The frontend
// sends a list of credential descriptors (from the auth-files endpoint) and
// the rules to evaluate (or the store's current rules if Rules is empty).
type classifyPreviewRequest struct {
	// Descriptors are the credential descriptors to classify. Each has a
	// filename (ID), provider, and optional attributes (plan_type, tier, etc.).
	Descriptors []credentialDescriptor `json:"descriptors"`
	// Rules are optional rules to evaluate. If empty, the store's current
	// classify rules are used. This lets the UI preview rule changes before
	// saving.
	Rules []policy.ClassifyRule `json:"rules,omitempty"`
}

type credentialDescriptor struct {
	ID         string            `json:"id"`
	Provider   string            `json:"provider"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// classifyPreviewResponse is the result of POST /classify-preview.
type classifyPreviewResponse struct {
	// Groups maps group name → list of matching credential IDs.
	Groups map[string][]string `json:"groups"`
	// GroupCounts maps group name → count of matching credentials.
	GroupCounts map[string]int `json:"group_counts"`
}

func (a *App) classifyPreview(raw []byte) ManagementResponse {
	var req classifyPreviewRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return jsonError(http.StatusBadRequest, "bad_request", err.Error())
	}

	// Use provided rules or fall back to the store's current rules.
	rules := req.Rules
	if len(rules) == 0 {
		rules = a.store.ClassifyRulesSnapshot()
	}

	// Pre-compile the rules.
	type compiledRule struct {
		rule    policy.ClassifyRule
		pattern *regexp.Regexp
	}
	var compiled []compiledRule
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			continue // skip invalid rules in preview
		}
		compiled = append(compiled, compiledRule{rule: r, pattern: re})
	}

	groups := make(map[string][]string)
	groupCounts := make(map[string]int)

	for _, desc := range req.Descriptors {
		matched := false
		// 1. Evaluate custom rules (multi-group: collect all matches).
		for _, cr := range compiled {
			val := descriptorFieldValue(desc, cr.rule.Field)
			if val != "" && cr.pattern.MatchString(val) {
				g := strings.ToLower(cr.rule.Group)
				groups[g] = append(groups[g], desc.ID)
				groupCounts[g]++
				matched = true
			}
		}
		// 2. If no custom rule matched, fall back to built-in plan_type/tier.
		if !matched {
			g := descriptorBuiltInGroup(desc)
			groups[g] = append(groups[g], desc.ID)
			groupCounts[g]++
		}
	}

	return jsonResponse(http.StatusOK, classifyPreviewResponse{
		Groups:      groups,
		GroupCounts: groupCounts,
	})
}

// descriptorFieldValue extracts a field value from a credential descriptor.
func descriptorFieldValue(desc credentialDescriptor, field string) string {
	field = strings.ToLower(strings.TrimSpace(field))
	switch field {
	case "filename", "id":
		return desc.ID
	case "provider":
		return desc.Provider
	default:
		if desc.Attributes != nil {
			return desc.Attributes[field]
		}
	}
	return ""
}

// descriptorBuiltInGroup returns the built-in plan_type/tier group, or
// "supported" if no recognizable claim is present.
func descriptorBuiltInGroup(desc credentialDescriptor) string {
	if desc.Attributes == nil {
		return "supported"
	}
	plan := strings.ToLower(strings.TrimSpace(desc.Attributes["plan_type"]))
	tier := strings.ToLower(strings.TrimSpace(desc.Attributes["tier"]))
	if plan != "" {
		return plan
	}
	if tier != "" {
		return tier
	}
	return "supported"
}

// --- Catalog builder (POST /catalog) ---

// catalogRequest is the body for POST /catalog. The frontend gathers auth-file
// descriptors + per-file models (the plugin cannot list host auth-files itself)
// and the plugin applies classify rules + built-in tiering to produce picker
// entries with classify:-prefixed custom groups.
type catalogRequest struct {
	Credentials []policy.CatalogCredential `json:"credentials"`
	// Rules optionally override the store's classify rules (for dry-run
	// previews). Empty → use currently configured rules.
	Rules []policy.ClassifyRule `json:"rules,omitempty"`
}

type catalogResponse struct {
	Entries []policy.CatalogEntry `json:"entries"`
}

func (a *App) buildCatalog(raw []byte) ManagementResponse {
	var req catalogRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return jsonError(http.StatusBadRequest, "bad_request", err.Error())
	}
	rules := req.Rules
	if len(rules) == 0 {
		rules = a.store.ClassifyRulesSnapshot()
	}
	entries := policy.BuildCatalogEntries(req.Credentials, rules)
	if entries == nil {
		entries = []policy.CatalogEntry{}
	}
	return jsonResponse(http.StatusOK, catalogResponse{Entries: entries})
}

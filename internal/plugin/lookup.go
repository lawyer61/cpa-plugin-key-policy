package plugin

import (
	"net/http"
	"strings"

	"cpa-key-policy/internal/policy"
)

type lookupLimits struct {
	RPM                   int     `json:"rpm"`
	DailyUSD              float64 `json:"daily_usd"`
	WeeklyUSD             float64 `json:"weekly_usd"`
	MaxConcurrentRequests int     `json:"max_concurrent_requests"`
}

type lookupConcurrency struct {
	Current int `json:"current"`
	Maximum int `json:"maximum"`
}

type lookupAliasUsage struct {
	Alias       string             `json:"alias"`
	BillingMode string             `json:"billing_mode,omitempty"`
	Daily       policy.UsageWindow `json:"daily"`
	Weekly      policy.UsageWindow `json:"weekly"`
}

type lookupResponse struct {
	KeyID       string              `json:"key_id,omitempty"`
	Name        string              `json:"name"`
	Enabled     bool                `json:"enabled"`
	Limits      lookupLimits        `json:"limits"`
	Usage       policy.UsageSummary `json:"usage"`
	Concurrency lookupConcurrency   `json:"concurrency"`
	Aliases     []lookupAliasUsage  `json:"aliases"`
}

type lookupAllDerivedResponse struct {
	Scope string           `json:"scope"`
	Keys  []lookupResponse `json:"keys"`
}

func (a *App) lookupData(headers http.Header) ManagementResponse {
	token, ok := strictBearerToken(headers)
	if !ok {
		return lookupUnauthorized()
	}
	key := a.store.FindByAPIKey(token)
	if key == nil || !key.Enabled {
		return lookupUnauthorized()
	}
	if key.Native {
		keys := a.store.Keys()
		derived := make([]lookupResponse, 0, len(keys))
		for i := range keys {
			if keys[i].Native {
				continue
			}
			item, found := a.lookupResponseForKey(keys[i])
			if found {
				derived = append(derived, item)
			}
		}
		response := jsonResponse(http.StatusOK, lookupAllDerivedResponse{Scope: "all-derived", Keys: derived})
		setLookupHeaders(&response)
		return response
	}
	payload, found := a.lookupResponseForKey(*key)
	if !found {
		return lookupUnauthorized()
	}
	response := jsonResponse(http.StatusOK, payload)
	setLookupHeaders(&response)
	return response
}

func (a *App) lookupResponseForKey(key policy.KeyConfig) (lookupResponse, bool) {
	current, aliases, found := a.store.AliasUsageFor(key.ID)
	if !found {
		return lookupResponse{}, false
	}
	key = current
	aliasUsage := make([]lookupAliasUsage, 0, len(aliases))
	for _, item := range aliases {
		aliasUsage = append(aliasUsage, lookupAliasUsage{
			Alias:       item.Alias,
			BillingMode: item.BillingMode,
			Daily:       item.Daily,
			Weekly:      item.Weekly,
		})
	}
	return lookupResponse{
		KeyID:   key.ID,
		Name:    key.Name,
		Enabled: key.Enabled,
		Limits: lookupLimits{
			RPM:                   key.RPM,
			DailyUSD:              key.DailyLimitUSD,
			WeeklyUSD:             key.WeeklyLimitUSD,
			MaxConcurrentRequests: key.MaxConcurrentRequests,
		},
		Usage: a.store.UsageSummaryFor(key),
		Concurrency: lookupConcurrency{
			Current: a.concurrency.keyCurrent(key.ID),
			Maximum: key.MaxConcurrentRequests,
		},
		Aliases: aliasUsage,
	}, true
}

func strictBearerToken(headers http.Header) (string, bool) {
	values := headers.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(parts[1])
	return token, token != ""
}

func lookupUnauthorized() ManagementResponse {
	response := jsonError(http.StatusUnauthorized, "unauthorized", "invalid or inactive key")
	if response.Headers == nil {
		response.Headers = make(http.Header)
	}
	response.Headers.Set("WWW-Authenticate", "Bearer")
	setLookupHeaders(&response)
	return response
}

func setLookupHeaders(response *ManagementResponse) {
	if response == nil {
		return
	}
	if response.Headers == nil {
		response.Headers = make(http.Header)
	}
	response.Headers.Set("Cache-Control", "no-store")
	response.Headers.Set("Pragma", "no-cache")
	response.Headers.Set("X-Content-Type-Options", "nosniff")
}

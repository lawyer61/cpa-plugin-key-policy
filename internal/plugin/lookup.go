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
	Name        string              `json:"name"`
	Limits      lookupLimits        `json:"limits"`
	Usage       policy.UsageSummary `json:"usage"`
	Concurrency lookupConcurrency   `json:"concurrency"`
	Aliases     []lookupAliasUsage  `json:"aliases"`
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
		response := jsonError(http.StatusNotImplemented, "native_usage_unsupported", "usage lookup is not available for imported CPA-native keys")
		setLookupHeaders(&response)
		return response
	}
	_, aliases, found := a.store.AliasUsageFor(key.ID)
	if !found {
		return lookupUnauthorized()
	}
	aliasUsage := make([]lookupAliasUsage, 0, len(aliases))
	for _, item := range aliases {
		aliasUsage = append(aliasUsage, lookupAliasUsage{
			Alias:       item.Alias,
			BillingMode: item.BillingMode,
			Daily:       item.Daily,
			Weekly:      item.Weekly,
		})
	}
	response := jsonResponse(http.StatusOK, lookupResponse{
		Name: key.Name,
		Limits: lookupLimits{
			RPM:                   key.RPM,
			DailyUSD:              key.DailyLimitUSD,
			WeeklyUSD:             key.WeeklyLimitUSD,
			MaxConcurrentRequests: key.MaxConcurrentRequests,
		},
		Usage: a.store.UsageSummaryFor(*key),
		Concurrency: lookupConcurrency{
			Current: a.concurrency.keyCurrent(key.ID),
			Maximum: key.MaxConcurrentRequests,
		},
		Aliases: aliasUsage,
	})
	setLookupHeaders(&response)
	return response
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

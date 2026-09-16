package policy

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	dayWindow          = 24 * time.Hour
	usageFlushInterval = 15 * time.Second
	usageWindowMode    = "utc-days-7"
	usageDayLayout     = "2006-01-02"
)

// usageLedger is the in-memory source of truth for per-key usage. Each entry
// holds at most seven UTC calendar-day buckets; daily and seven-day views are
// derived from the same buckets at read time.
type usageLedger struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]*UsageState
}

func newUsageLedger(now func() time.Time) *usageLedger {
	if now == nil {
		now = time.Now
	}
	return &usageLedger{now: now, entries: make(map[string]*UsageState)}
}

func utcDayStart(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

func usageDayKey(t time.Time) string { return utcDayStart(t).Format(usageDayLayout) }

func parseUsageDay(key string) (time.Time, bool) {
	day, err := time.ParseInLocation(usageDayLayout, key, time.UTC)
	return day, err == nil
}

func validateUsageStateV2(usage map[string]*UsageState) error {
	for id, state := range usage {
		if state == nil {
			continue
		}
		for key, day := range state.Days {
			date, ok := parseUsageDay(key)
			if !ok {
				return fmt.Errorf("usage for key %q has invalid UTC day %q", id, key)
			}
			if day == nil {
				return fmt.Errorf("usage for key %q day %q is null", id, key)
			}
			if !day.Total.WindowStart.IsZero() && !sameUTCDay(day.Total.WindowStart, date) {
				return fmt.Errorf("usage for key %q day %q has mismatched total window_start", id, key)
			}
			for alias, window := range day.ByAlias {
				if !window.WindowStart.IsZero() && !sameUTCDay(window.WindowStart, date) {
					return fmt.Errorf("usage for key %q day %q alias %q has mismatched window_start", id, key, alias)
				}
			}
		}
	}
	return nil
}

func activeUsageRange(now time.Time) (today, first time.Time) {
	today = utcDayStart(now)
	first = today.Add(-6 * dayWindow)
	return today, first
}

func cloneUsageDay(day *UsageDay) *UsageDay {
	if day == nil {
		return nil
	}
	copyDay := *day
	if day.ByAlias != nil {
		copyDay.ByAlias = make(map[string]UsageWindow, len(day.ByAlias))
		for alias, window := range day.ByAlias {
			copyDay.ByAlias[alias] = window
		}
	}
	return &copyDay
}

func cloneUsageState(state *UsageState) *UsageState {
	if state == nil {
		return nil
	}
	copyState := *state
	if state.Days != nil {
		copyState.Days = make(map[string]*UsageDay, len(state.Days))
		for key, day := range state.Days {
			copyState.Days[key] = cloneUsageDay(day)
		}
	}
	if state.legacyByAlias != nil {
		copyState.legacyByAlias = make(map[string]AliasUsageWindows, len(state.legacyByAlias))
		for alias, windows := range state.legacyByAlias {
			copyState.legacyByAlias[alias] = windows
		}
	}
	return &copyState
}

func cloneUsageMap(usage map[string]*UsageState) map[string]*UsageState {
	out := make(map[string]*UsageState, len(usage))
	for id, state := range usage {
		if state != nil {
			out[id] = cloneUsageState(state)
		}
	}
	return out
}

func pruneUsageState(state *UsageState, now time.Time) {
	if state == nil {
		return
	}
	_, first := activeUsageRange(now)
	today := utcDayStart(now)
	for key := range state.Days {
		day, ok := parseUsageDay(key)
		if !ok || day.Before(first) || day.After(today) {
			delete(state.Days, key)
		}
	}
	if !state.WeeklyHistoryIncompleteUntil.IsZero() && !now.Before(state.WeeklyHistoryIncompleteUntil) {
		state.WeeklyHistoryIncompleteUntil = time.Time{}
	}
}

func usageStateMeaningful(state *UsageState) bool {
	return state != nil && (len(state.Days) > 0 || !state.WeeklyHistoryIncompleteUntil.IsZero() || !state.LastUsageResetAt.IsZero())
}

// loadFromState replaces the ledger from a loaded v2 state file.
func (l *usageLedger) loadFromState(usage map[string]*UsageState) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.entries = make(map[string]*UsageState, len(usage))
	for id, state := range usage {
		copyState := cloneUsageState(state)
		pruneUsageState(copyState, now)
		if usageStateMeaningful(copyState) {
			l.entries[id] = copyState
		}
	}
}

// snapshot returns a deep, active-range-only copy for persistence.
func (l *usageLedger) snapshot() map[string]*UsageState {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.snapshotLocked(l.now())
}

func (l *usageLedger) snapshotLocked(now time.Time) map[string]*UsageState {
	out := make(map[string]*UsageState, len(l.entries))
	for id, state := range l.entries {
		copyState := cloneUsageState(state)
		pruneUsageState(copyState, now)
		if usageStateMeaningful(copyState) {
			out[id] = copyState
		}
	}
	return out
}

func (l *usageLedger) entryLocked(id string) *UsageState {
	state := l.entries[id]
	if state == nil {
		state = &UsageState{Days: make(map[string]*UsageDay)}
		l.entries[id] = state
	}
	if state.Days == nil {
		state.Days = make(map[string]*UsageDay)
	}
	return state
}

func addWindow(dst *UsageWindow, amount, cacheCost float64, cacheReadTokens, inputTokens, outputTokens, callCount int64) {
	dst.TotalUSD += amount
	dst.CacheCostUSD += cacheCost
	dst.CacheReadTokens += cacheReadTokens
	dst.InputTokens += inputTokens
	dst.OutputTokens += outputTokens
	dst.CallCount += callCount
}

func sumWindow(dst *UsageWindow, src UsageWindow) {
	addWindow(dst, src.TotalUSD, src.CacheCostUSD, src.CacheReadTokens, src.InputTokens, src.OutputTokens, src.CallCount)
}

// RecordCost posts one finalized charge to the UTC day in which the ledger
// accepts it. The time is obtained while holding the ledger lock so total and
// alias counters share one settlement instant.
func (l *usageLedger) RecordCost(id, alias string, amount, cacheCost float64, cacheReadTokens, inputTokens, outputTokens int64, callCount int64) {
	if id == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	state := l.entryLocked(id)
	pruneUsageState(state, now)
	dayStart := utcDayStart(now)
	key := dayStart.Format(usageDayLayout)
	day := state.Days[key]
	if day == nil {
		day = &UsageDay{Total: UsageWindow{WindowStart: dayStart}, ByAlias: make(map[string]UsageWindow)}
		state.Days[key] = day
	}
	if day.ByAlias == nil {
		day.ByAlias = make(map[string]UsageWindow)
	}
	day.Total.WindowStart = dayStart
	addWindow(&day.Total, amount, cacheCost, cacheReadTokens, inputTokens, outputTokens, callCount)
	aliasWindow := day.ByAlias[alias]
	aliasWindow.WindowStart = dayStart
	addWindow(&aliasWindow, amount, cacheCost, cacheReadTokens, inputTokens, outputTokens, callCount)
	day.ByAlias[alias] = aliasWindow
}

// UsageSummary is returned by management and public lookup APIs. Weekly fields
// mean the current UTC date plus the previous six UTC dates.
type UsageSummary struct {
	DailyUSD                     float64    `json:"daily_usd"`
	WeeklyUSD                    float64    `json:"weekly_usd"`
	DailyLimitUSD                float64    `json:"daily_limit_usd"`
	WeeklyLimitUSD               float64    `json:"weekly_limit_usd"`
	DailyResetAt                 time.Time  `json:"daily_reset_at,omitempty"`
	WeeklyWindowStart            time.Time  `json:"weekly_window_start,omitempty"`
	WeeklyNextRollAt             time.Time  `json:"weekly_next_roll_at,omitempty"`
	WindowMode                   string     `json:"window_mode"`
	WeeklyHistoryComplete        bool       `json:"weekly_history_complete"`
	WeeklyHistoryIncompleteUntil *time.Time `json:"weekly_history_incomplete_until,omitempty"`
	LastUsageResetAt             *time.Time `json:"last_usage_reset_at,omitempty"`
	DailyCacheCostUSD            float64    `json:"daily_cache_cost_usd,omitempty"`
	WeeklyCacheCostUSD           float64    `json:"weekly_cache_cost_usd,omitempty"`
	DailyCacheReadTokens         int64      `json:"daily_cache_read_tokens,omitempty"`
	WeeklyCacheReadTokens        int64      `json:"weekly_cache_read_tokens,omitempty"`
	DailyInputTokens             int64      `json:"daily_input_tokens,omitempty"`
	WeeklyInputTokens            int64      `json:"weekly_input_tokens,omitempty"`
	DailyOutputTokens            int64      `json:"daily_output_tokens,omitempty"`
	WeeklyOutputTokens           int64      `json:"weekly_output_tokens,omitempty"`
	DailyCallCount               int64      `json:"daily_call_count,omitempty"`
	WeeklyCallCount              int64      `json:"weekly_call_count,omitempty"`
}

// AliasUsageEntry is one row of the per-alias usage breakdown.
type AliasUsageEntry struct {
	Alias       string      `json:"alias"`
	Provider    string      `json:"provider,omitempty"`
	TargetModel string      `json:"target_model,omitempty"`
	BillingMode string      `json:"billing_mode,omitempty"`
	PerCallUSD  float64     `json:"per_call_usd,omitempty"`
	InConfig    bool        `json:"in_config"`
	Daily       UsageWindow `json:"daily"`
	Weekly      UsageWindow `json:"weekly"`
}

func summaryFromWindows(key KeyConfig, state *UsageState, daily, weekly UsageWindow, now time.Time) UsageSummary {
	today, first := activeUsageRange(now)
	summary := UsageSummary{
		DailyUSD:              daily.TotalUSD,
		WeeklyUSD:             weekly.TotalUSD,
		DailyLimitUSD:         key.DailyLimitUSD,
		WeeklyLimitUSD:        key.WeeklyLimitUSD,
		DailyResetAt:          today.Add(dayWindow),
		WeeklyWindowStart:     first,
		WeeklyNextRollAt:      today.Add(dayWindow),
		WindowMode:            usageWindowMode,
		WeeklyHistoryComplete: true,
		DailyCacheCostUSD:     daily.CacheCostUSD,
		WeeklyCacheCostUSD:    weekly.CacheCostUSD,
		DailyCacheReadTokens:  daily.CacheReadTokens,
		WeeklyCacheReadTokens: weekly.CacheReadTokens,
		DailyInputTokens:      daily.InputTokens,
		WeeklyInputTokens:     weekly.InputTokens,
		DailyOutputTokens:     daily.OutputTokens,
		WeeklyOutputTokens:    weekly.OutputTokens,
		DailyCallCount:        daily.CallCount,
		WeeklyCallCount:       weekly.CallCount,
	}
	if state != nil {
		if !state.LastUsageResetAt.IsZero() {
			value := state.LastUsageResetAt
			summary.LastUsageResetAt = &value
		}
		if !state.WeeklyHistoryIncompleteUntil.IsZero() && now.Before(state.WeeklyHistoryIncompleteUntil) {
			summary.WeeklyHistoryComplete = false
			value := state.WeeklyHistoryIncompleteUntil
			summary.WeeklyHistoryIncompleteUntil = &value
		}
	}
	return summary
}

func (l *usageLedger) detailsLocked(key KeyConfig, now time.Time) (UsageSummary, []AliasUsageEntry) {
	today, first := activeUsageRange(now)
	daily := UsageWindow{WindowStart: today}
	weekly := UsageWindow{WindowStart: first}
	state := l.entries[key.ID]

	byAlias := make(map[string]AliasUsageEntry, len(key.Models))
	for _, rule := range key.Models {
		byAlias[rule.Alias] = AliasUsageEntry{
			Alias:       rule.Alias,
			Provider:    rule.Provider,
			TargetModel: rule.TargetModel,
			BillingMode: rule.BillingMode,
			PerCallUSD:  rule.PerCallUSD,
			InConfig:    true,
			Daily:       UsageWindow{WindowStart: today},
			Weekly:      UsageWindow{WindowStart: first},
		}
	}

	if state != nil {
		for offset := 0; offset < 7; offset++ {
			date := first.Add(time.Duration(offset) * dayWindow)
			day := state.Days[date.Format(usageDayLayout)]
			if day == nil {
				continue
			}
			sumWindow(&weekly, day.Total)
			if date.Equal(today) {
				sumWindow(&daily, day.Total)
			}
			for alias, counters := range day.ByAlias {
				entry, exists := byAlias[alias]
				if !exists {
					entry = AliasUsageEntry{
						Alias: alias, InConfig: false,
						Daily: UsageWindow{WindowStart: today}, Weekly: UsageWindow{WindowStart: first},
					}
				}
				sumWindow(&entry.Weekly, counters)
				if date.Equal(today) {
					sumWindow(&entry.Daily, counters)
				}
				byAlias[alias] = entry
			}
		}
	}

	rows := make([]AliasUsageEntry, 0, len(byAlias))
	for _, entry := range byAlias {
		rows = append(rows, entry)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Alias < rows[j].Alias })
	return summaryFromWindows(key, state, daily, weekly, now), rows
}

// Details returns one same-time, same-lock total and alias snapshot.
func (l *usageLedger) Details(key KeyConfig) (UsageSummary, []AliasUsageEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.detailsLocked(key, l.now())
}

func (l *usageLedger) Summary(key KeyConfig) UsageSummary {
	summary, _ := l.Details(key)
	return summary
}

func (l *usageLedger) AliasUsage(key KeyConfig) []AliasUsageEntry {
	_, aliases := l.Details(key)
	return aliases
}

func (l *usageLedger) OverLimit(key KeyConfig) (string, UsageSummary) {
	if key.DailyLimitUSD <= 0 && key.WeeklyLimitUSD <= 0 {
		return "", UsageSummary{}
	}
	summary := l.Summary(key)
	if key.DailyLimitUSD > 0 && summary.DailyUSD >= key.DailyLimitUSD {
		return "daily_exceeded", summary
	}
	if key.WeeklyLimitUSD > 0 && summary.WeeklyUSD >= key.WeeklyLimitUSD {
		return "weekly_exceeded", summary
	}
	return "", UsageSummary{}
}

// resetUsage deletes all usage and metadata for a key. It is used only when a
// key itself is deleted; the admin reset endpoint uses a durable transaction
// that retains LastUsageResetAt.
func (l *usageLedger) resetUsage(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, id)
}

func legacyWindowHasEvidence(window UsageWindow) bool {
	return !window.WindowStart.IsZero() || window.TotalUSD != 0 || window.CacheReadTokens != 0 || window.CacheCostUSD != 0 || window.InputTokens != 0 || window.OutputTokens != 0 || window.CallCount != 0
}

// migrateLegacyUsage converts schema-less daily/weekly state to v2. Only a
// daily window confirmed to belong to the migration UTC date is retained. The
// independent legacy weekly window remains solely in the backup file.
func migrateLegacyUsage(usage map[string]*UsageState, now time.Time) (map[string]*UsageState, error) {
	today := utcDayStart(now)
	dayKey := today.Format(usageDayLayout)
	incompleteUntil := today.Add(6 * dayWindow)
	out := make(map[string]*UsageState, len(usage))
	for id, legacy := range usage {
		if legacy == nil {
			continue
		}
		if len(legacy.Days) > 0 || !legacy.WeeklyHistoryIncompleteUntil.IsZero() || !legacy.LastUsageResetAt.IsZero() {
			return nil, fmt.Errorf("legacy usage for key %q contains v2 fields without usage_schema_version", id)
		}
		state := &UsageState{Days: make(map[string]*UsageDay)}
		affected := legacyWindowHasEvidence(legacy.legacyDaily) || legacyWindowHasEvidence(legacy.legacyWeekly) || len(legacy.legacyByAlias) > 0
		var day *UsageDay
		if !legacy.legacyDaily.WindowStart.IsZero() && sameUTCDay(legacy.legacyDaily.WindowStart, today) {
			counters := legacy.legacyDaily
			counters.WindowStart = today
			day = &UsageDay{Total: counters, ByAlias: make(map[string]UsageWindow)}
		}
		for alias, windows := range legacy.legacyByAlias {
			if windows.Daily.WindowStart.IsZero() || !sameUTCDay(windows.Daily.WindowStart, today) {
				continue
			}
			if day == nil {
				day = &UsageDay{Total: UsageWindow{WindowStart: today}, ByAlias: make(map[string]UsageWindow)}
			}
			counters := windows.Daily
			counters.WindowStart = today
			day.ByAlias[alias] = counters
		}
		if day != nil {
			state.Days[dayKey] = day
		}
		if affected {
			state.WeeklyHistoryIncompleteUntil = incompleteUntil
		}
		if usageStateMeaningful(state) {
			out[id] = state
		}
	}
	return out, nil
}

func sameUTCDay(a, b time.Time) bool {
	return utcDayStart(a).Equal(utcDayStart(b))
}

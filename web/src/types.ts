// Shapes mirrored from the cpa-key-policy plugin (internal/policy/config.go)
// and CPA management responses. Only the fields the UI needs are declared.

export interface ModelRule {
  alias: string;
  provider: string;
  target_model: string;
  // Optional tier/plan narrowing for providers whose auth files carry an
  // identity claim (codex plan_type, antigravity tier). Empty = "any file for
  // the provider" (legacy). The plugin's Scheduler filters auth candidates by
  // this so a downstream key pinned to, say, codex "team" only ever lands on a
  // team auth file. UI catalog groups mirror this value.
  group?: string;
  input_price_per_million?: number;
  output_price_per_million?: number;
  cache_read_price_per_million?: number;
  // billing_mode selects how this alias is billed per successful request:
  //   - "tokens" (default): bill by token counts using the three prices above.
  //   - "per_call": bill a fixed per_call_usd per successful request, ignoring
  //     token counts. The token-price fields are preserved but dormant.
  billing_mode?: "tokens" | "per_call";
  // per_call_usd is the fixed USD charge per successful request when
  // billing_mode === "per_call". 0 is allowed (free calls). Only meaningful
  // under "per_call".
  per_call_usd?: number;
  // Positive multiplier applied once to the computed token/per-call charge.
  billing_multiplier?: number;
}

export interface UsageSummary {
  daily_usd: number;
  weekly_usd: number;
  daily_limit_usd: number;
  weekly_limit_usd: number;
  daily_reset_at?: string;
  weekly_window_start?: string;
  weekly_next_roll_at?: string;
  window_mode?: "utc-days-7";
  weekly_history_complete?: boolean;
  weekly_history_incomplete_until?: string;
  last_usage_reset_at?: string;
  // Cache reporting (omitted when zero). Hit-rate is derived client-side as
  // cache_read_tokens / (cache_read_tokens + input_tokens).
  daily_cache_cost_usd?: number;
  weekly_cache_cost_usd?: number;
  daily_cache_read_tokens?: number;
  weekly_cache_read_tokens?: number;
  daily_input_tokens?: number;
  weekly_input_tokens?: number;
  daily_output_tokens?: number;
  weekly_output_tokens?: number;
  // Call counts: successful requests billed into the window (token or
  // per-call). Failed requests don't count. Display only.
  daily_call_count?: number;
  weekly_call_count?: number;
}

export interface AccountBinding {
  allow: string[];
  strategy?: "weighted-round-robin" | "round-robin" | "fill-first" | "quota-fill-first";
}

export interface KeyPublic {
  id: string;
  name: string;
  enabled: boolean;
  native?: boolean;
  key_preview: string;
  account_binding?: AccountBinding;
  // Client-only draft marker used while the key form visits the model picker.
  clear_account_binding?: boolean;
  rpm: number;
  models: ModelRule[];
  aliases?: KeyAliasRef[];
  daily_limit_usd: number;
  weekly_limit_usd: number;
  // Maximum simultaneous upstream requests for this key; 0 means unlimited.
  max_concurrent_requests: number;
  // Current in-flight requests for this key, reported by the plugin.
  current_concurrent_requests: number;
  // Keep requests for this key on the same upstream session when possible.
  session_affinity: boolean;
  // Per-key override for GET /v1/models (see KeyFormValues).
  allow_models_endpoint?: boolean;
  // Allow this derived key to request a single authorized Codex quota refresh
  // from the public lookup page. Disabled by default.
  allow_quota_refresh?: boolean;
  usage: UsageSummary;
  created_at?: string;
  updated_at?: string;
}

export interface KeyWriteRequest {
  id: string;
  name?: string;
  enabled?: boolean;
  native?: boolean;
  key?: string;
  account_binding?: AccountBinding;
  clear_account_binding?: boolean;
  rpm?: number;
  models?: ModelRule[];
  aliases?: KeyAliasRef[];
  daily_limit_usd?: number;
  weekly_limit_usd?: number;
  max_concurrent_requests?: number;
  session_affinity?: boolean;
  allow_models_endpoint?: boolean;
  allow_quota_refresh?: boolean;
}

export interface CreateKeyResponse {
  key: KeyPublic;
  plain_key?: string;
  generated: boolean;
}

export interface RotateKeyResponse {
  key: KeyPublic;
  plain_key: string;
  generated: boolean;
}

// UsageWindow mirrors policy.UsageWindow: a dollar total bound to a range
// start, plus cache/input/output/call counters for display. The key detail
// page reads UTC today and the latest seven UTC calendar days per alias.
export interface UsageWindow {
  total_usd: number;
  window_start?: string;
  cache_read_tokens?: number;
  cache_cost_usd?: number;
  input_tokens?: number;
  output_tokens?: number;
  call_count?: number;
}

// AliasUsageEntry mirrors policy.AliasUsageEntry: one row of the per-alias
// usage breakdown for a key. Configured aliases have in_config=true; aliases
// with historical usage that are no longer in the key's config have
// in_config=false (residuals).
export interface AliasUsageEntry {
  alias: string;
  provider?: string;
  target_model?: string;
  billing_mode?: "tokens" | "per_call";
  per_call_usd?: number;
  in_config: boolean;
  daily: UsageWindow;
  weekly: UsageWindow;
}

export interface KeyUsageResponse {
  key_id: string;
  key_name: string;
  daily_limit_usd: number;
  weekly_limit_usd: number;
  usage: UsageSummary;
  aliases: AliasUsageEntry[];
}

export interface ResetUsageResponse {
  reset: true;
  id: string;
  reset_at: string;
  usage: UsageSummary;
}

// A model the user can pick when creating/editing a key.
export interface CatalogModel {
  provider: string;
  // group is set for providers whose auth files carry a tier/plan identity
  // (codex plan_type, antigravity tier). Same model may appear under several
  // groups when multiple tiers' auth files all support it — each is a distinct
  // selectable row pinning a different tier.
  group?: string;
  model: string;
}

export interface StatusResponse {
  enabled: boolean;
  global_weighted_round_robin?: boolean;
  state_file: string;
  key_count: number;
  rpm_usage?: Record<string, unknown>;
}

export type QuotaManagementState = "disabled" | "unconfigured" | "ready" | "paused";

export interface SchedulerSettings {
  global_weighted_round_robin: boolean;
  auth_concurrency_limits: Record<string, number>;
  session_affinity_idle_ttl_seconds: number;
  session_affinity_max_entries: number;
  quota_check_interval: string;
  quota_cache_ttl: string;
  quota_activation_enabled: boolean;
  quota_activation_scope: "managed-pools" | "all-codex";
  quota_activation_model: string;
  // Optional local management bridge for account-level proxy maintenance.
  quota_management_enabled?: boolean;
  quota_management_activation_enabled?: boolean;
  quota_management_base_url?: string;
  quota_management_key_configured?: boolean;
  quota_management_state?: QuotaManagementState;
  quota_management_last_error?: string;
  // Optional runtime counters returned by newer plugin builds.
  current_concurrent_requests?: number;
  current_activation_requests?: number;
  session_affinity_entries?: number;
}

export type SchedulerSettingsPatch = Partial<Pick<
  SchedulerSettings,
  | "global_weighted_round_robin"
  | "auth_concurrency_limits"
  | "session_affinity_idle_ttl_seconds"
  | "session_affinity_max_entries"
  | "quota_check_interval"
  | "quota_cache_ttl"
  | "quota_activation_enabled"
  | "quota_activation_scope"
  | "quota_activation_model"
  | "quota_management_enabled"
  | "quota_management_activation_enabled"
  | "quota_management_base_url"
>> & {
  // A blank value is reserved for the explicit clear-key action. Ordinary
  // saves omit this field so an existing secret remains unchanged.
  quota_management_key?: string;
};

export interface QuotaWindowStatus {
  kind: "five_hour" | "weekly" | "monthly" | "unknown";
  used_percent?: number;
  window_seconds?: number;
  reset_at?: string;
  exhausted?: boolean;
}

export interface QuotaAuthStatus {
  auth_id: string;
  provider: string;
  status?: string;
  observable: boolean;
  in_managed_pool: boolean;
  in_maintenance_scope: boolean;
  in_activation_scope: boolean;
  exclusion_reason?: string;
  availability: "ready" | "unknown" | "exhausted";
  freshness: "fresh" | "stale" | "unknown";
  observation?: {
    plan_type?: string;
    source?: string;
    observed_at?: string;
    received_at?: string;
    short?: QuotaWindowStatus;
    long?: QuotaWindowStatus;
    explicit_exhausted?: boolean;
    explicit_reset_at?: string;
    explicit_reason?: string;
  };
  last_roster_seen_at?: string;
  last_check_at?: string;
  next_check_at?: string;
  last_result?: string;
  last_error?: string;
  activation?: {
    model?: string;
    status?: string;
    attempts?: number;
    last_result?: string;
    last_error?: string;
    total_tokens?: number;
  };
  controlled_in_flight: number;
  activation_in_flight: number;
}

export interface QuotaStatus {
  quota_check_interval: string;
  quota_cache_ttl: string;
  quota_activation_enabled: boolean;
  quota_activation_scope: "managed-pools" | "all-codex";
  quota_activation_model: string;
  persistence_blocked: boolean;
  persistence_error?: string;
  last_roster_sync?: string;
  last_round_at?: string;
  observed_auth_count: number;
  controlled_activation_current: number;
  auths: QuotaAuthStatus[];
}

export interface LookupLimits {
  rpm: number;
  daily_usd: number;
  weekly_usd: number;
  max_concurrent_requests: number;
}

export interface LookupConcurrency {
  current: number;
  maximum: number;
}

export interface LookupAliasSummary {
  alias: string;
  billing_mode?: "tokens" | "per_call";
  daily: UsageWindow | number;
  weekly: UsageWindow | number;
}

export interface LookupKeyUsage {
  key_id: string;
  name: string;
  enabled: boolean;
  limits: LookupLimits;
  usage: UsageSummary;
  concurrency: LookupConcurrency;
  aliases: LookupAliasSummary[];
  auth_quotas?: LookupAuthQuotas;
}

export interface LookupAllDerivedResponse {
  scope: "all-derived";
  keys: LookupKeyUsage[];
}

export type LookupResponse = LookupKeyUsage | LookupAllDerivedResponse;

export type LookupAuthQuotaStatus =
  | "active"
  | "disabled"
  | "unavailable"
  | "expired"
  | "unqueryable"
  | "unknown";

export type LookupAuthQuotaAvailability = "ready" | "exhausted" | "unknown";

export type LookupAuthQuotaFreshness = "fresh" | "stale" | "unknown";

export type LookupAuthQuotaRefreshStatus =
  | "ready"
  | "permission_disabled"
  | "cooldown"
  | "busy"
  | "unavailable"
  | "transport_unavailable";

export interface LookupAuthQuotaWindow {
  kind: string;
  used_percent?: number;
  remaining_percent?: number;
  reset_at?: string;
  exhausted?: boolean;
}

export interface LookupAuthQuotaAccount {
  // ref is an opaque server-issued reference used only for the explicit
  // refresh request. It must never be rendered as an auth ID or filename.
  ref: string;
  label: string;
  provider: "codex";
  tier: "pro" | "team" | "plus" | "free" | "unknown";
  status: LookupAuthQuotaStatus;
  availability: LookupAuthQuotaAvailability;
  freshness: LookupAuthQuotaFreshness;
  observed_at?: string;
  short?: LookupAuthQuotaWindow;
  long?: LookupAuthQuotaWindow;
  can_refresh: boolean;
  refresh_after?: string;
  refresh_status: LookupAuthQuotaRefreshStatus;
}

export type LookupAuthQuotasStatus =
  | "ready"
  | "binding_required"
  | "route_unproven"
  | "roster_unavailable"
  | "no_matches";

export interface LookupAuthQuotas {
  status: LookupAuthQuotasStatus;
  manual_refresh_allowed: boolean;
  unsupported_providers: string[];
  accounts: LookupAuthQuotaAccount[];
}

// --- Advanced Mapping types ---

// AliasTarget is one selectable destination for an alias.
export interface AliasTarget {
  provider: string;
  target_model: string;
  group?: string;
}

// AliasMapping is one entry in the global alias mapping table.
export interface AliasMapping {
  alias: string;
  targets: AliasTarget[];
  dispatch: "round-robin" | "priority";
  billing_mode: "tokens" | "per_call";
  input_price_per_million?: number;
  output_price_per_million?: number;
  cache_read_price_per_million?: number;
  per_call_usd?: number;
  billing_multiplier?: number;
}

// ClassifyRule is a user-defined credential classification rule.
export interface ClassifyRule {
  name: string;
  field: string; // "filename" | "provider" | "plan_type" | "tier" | custom
  pattern: string; // regex
  group: string; // target group name
  enabled: boolean;
}

// KeyAliasRef is a key's reference to a global alias, with optional per-key
// price overrides (null = use global default).
export interface KeyAliasRef {
  alias: string;
  billing_mode?: "tokens" | "per_call" | null;
  input_price_per_million?: number | null;
  output_price_per_million?: number | null;
  cache_read_price_per_million?: number | null;
  per_call_usd?: number | null;
  billing_multiplier?: number | null;
}

// CredentialDescriptor is a normalized credential description for classify preview.
export interface CredentialDescriptor {
  id: string;
  provider: string;
  attributes?: Record<string, string>;
}

// ClassifyPreviewResponse is the result of POST /classify-preview.
export interface ClassifyPreviewResponse {
  groups: Record<string, string[]>; // group name → credential IDs
  group_counts: Record<string, number>; // group name → count
}

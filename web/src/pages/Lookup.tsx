import { useState } from "react";
import { fetchLookupData, fetchLookupQuota } from "../api/lookup";
import { useT } from "../i18n";
import type {
  LookupAliasSummary,
  LookupAllDerivedResponse,
  LookupAuthQuotaAccount,
  LookupAuthQuotaWindow,
  LookupAuthQuotas,
  LookupKeyUsage,
  LookupResponse,
  UsageWindow,
} from "../types";
import { formatUSD } from "../utils/money";

type UsageValue = UsageWindow | number | undefined;

export function usageValue(value: UsageValue): number {
  if (typeof value === "number") return Number.isFinite(value) ? value : 0;
  if (!value || typeof value !== "object") return 0;
  const window = value as UsageWindow & { daily_usd?: unknown; weekly_usd?: unknown };
  const candidate = window.total_usd ?? window.daily_usd ?? window.weekly_usd ?? 0;
  return typeof candidate === "number" && Number.isFinite(candidate) ? candidate : 0;
}

function displayLimit(value: number, unlimited: string): string {
  return value > 0 ? formatUSD(value) : unlimited;
}

function usagePercent(used: number, limit: number): number {
  if (limit <= 0) return 0;
  return Math.max(0, Math.min(100, (used / limit) * 100));
}

function formatReset(value: string | undefined): string | null {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || date.getUTCFullYear() <= 1) return null;
  return date.toLocaleString();
}

function formatPercent(value: number | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  return `${Number.isInteger(value) ? value : value.toFixed(1)}%`;
}

function quotaWindowKindLabel(kind: string, t: ReturnType<typeof useT>): string {
  if (kind === "five_hour") return t("lookup.quotaFiveHour");
  if (kind === "weekly") return t("lookup.quotaWeekly");
  if (kind === "monthly") return t("lookup.quotaMonthly");
  return t("lookup.quotaUnknown");
}

function formatQuotaWindow(window: LookupAuthQuotaWindow | undefined, t: ReturnType<typeof useT>) {
  if (!window) return null;
  const reset = formatReset(window.reset_at);
  return (
    <div className="lookup-quota-window" key={window.kind}>
      <div className="lookup-quota-window-title">{quotaWindowKindLabel(window.kind, t)}</div>
      <div className="lookup-quota-stats">
        <span><b>{t("lookup.quotaUsed")}</b> {formatPercent(window.used_percent)}</span>
        <span><b>{t("lookup.quotaRemaining")}</b> {formatPercent(window.remaining_percent)}</span>
      </div>
      <div className="lookup-quota-window-meta">
        {reset ? t("lookup.quotaResetAt", { at: reset }) : t("lookup.quotaNotAvailable")}
        {window.exhausted ? ` · ${t("lookup.quotaExhausted")}` : ""}
      </div>
    </div>
  );
}

function quotaStatusLabel(account: LookupAuthQuotaAccount, t: ReturnType<typeof useT>): string {
  const status = account.status;
  if (status === "active") return t("lookup.quotaActive");
  if (status === "disabled") return t("lookup.quotaDisabled");
  if (status === "unavailable") return t("lookup.quotaUnavailable");
  if (status === "expired") return t("lookup.quotaExpired");
  if (status === "unqueryable") return t("lookup.quotaUnqueryable");
  return t("lookup.quotaUnknown");
}

function quotaRefreshStatusLabel(account: LookupAuthQuotaAccount, manualRefreshAllowed: boolean, t: ReturnType<typeof useT>): string | null {
  if (manualRefreshAllowed && account.can_refresh && account.refresh_status === "ready") return null;
  if (account.refresh_status === "permission_disabled") return t("lookup.quotaRefreshPermissionDisabled");
  if (account.refresh_status === "cooldown") return t("lookup.quotaRefreshCooldown");
  if (account.refresh_status === "busy") return t("lookup.quotaRefreshBusy");
  if (account.refresh_status === "transport_unavailable") return t("lookup.quotaRefreshTransportUnavailable");
  return t("lookup.quotaRefreshUnavailable");
}

function quotaScopeMessage(quotas: LookupAuthQuotas, t: ReturnType<typeof useT>): string | null {
  if (quotas.status === "binding_required") return t("lookup.quotaBindingRequired");
  if (quotas.status === "route_unproven") {
    const route = t("lookup.quotaRouteUnproven");
    return quotas.unsupported_providers.length > 0
      ? `${route} ${t("lookup.quotaUnsupportedProviders", { providers: quotas.unsupported_providers.join(", ") })}`
      : route;
  }
  if (quotas.status === "roster_unavailable") return t("lookup.quotaRosterUnavailable");
  if (quotas.status === "no_matches") return t("lookup.quotaNoMatches");
  if (quotas.unsupported_providers.length > 0) {
    return t("lookup.quotaUnsupportedProviders", { providers: quotas.unsupported_providers.join(", ") });
  }
  if (quotas.accounts.length === 0) return t("lookup.quotaNoMatches");
  return null;
}

function LookupAuthQuotaSection({
  quotas,
  refreshingRef,
  refreshError,
  onRefresh,
}: {
  quotas: LookupAuthQuotas;
  refreshingRef: string | null;
  refreshError: string;
  onRefresh: (ref: string) => void;
}) {
  const t = useT();
  const message = quotaScopeMessage(quotas, t);
  return (
    <section className="lookup-section lookup-quota-section">
      <h3>{t("lookup.authQuotaTitle")}</h3>
      <p className="muted lookup-quota-subtitle">{t("lookup.authQuotaSubtitle")}</p>
      {message && <p className="lookup-quota-note">{message}</p>}
      {refreshError && <p className="error lookup-quota-error" role="alert">{refreshError}</p>}
      {quotas.accounts.length > 0 && (
        <div className="lookup-quota-list">
          {quotas.accounts.map((account) => {
            const refreshStatus = quotaRefreshStatusLabel(account, quotas.manual_refresh_allowed, t);
            const refreshable = quotas.manual_refresh_allowed && account.can_refresh && account.refresh_status === "ready";
            const refreshing = refreshingRef === account.ref;
						const observedAt = formatReset(account.observed_at);
						const refreshAfter = formatReset(account.refresh_after);
            return (
              <article className="lookup-quota-card" key={account.ref}>
                <div className="lookup-quota-card-head">
                  <div>
                    <div className="lookup-quota-label">{account.label}</div>
                    <div className="lookup-quota-meta">
                      {t("lookup.quotaTier")}: {account.tier === "unknown" ? t("lookup.quotaUnknown") : account.tier}
                      <span> · {t("lookup.quotaStatus")}: {quotaStatusLabel(account, t)}</span>
                    </div>
                  </div>
                  <button
                    className="btn sm"
                    type="button"
                    disabled={!refreshable || refreshingRef !== null}
                    onClick={() => onRefresh(account.ref)}
                    aria-label={`${t("lookup.quotaRefresh")} ${account.label}`}
                  >
                    {refreshing ? t("lookup.quotaRefreshing") : t("lookup.quotaRefresh")}
                  </button>
                </div>
                <div className="lookup-quota-meta">
                  {t("lookup.quotaAvailability")}: {account.availability === "ready" ? t("lookup.quotaReady") : account.availability === "exhausted" ? t("lookup.quotaExhausted") : t("lookup.quotaUnknown")}
                  <span> · {t("lookup.quotaFreshness")}: {account.freshness === "fresh" ? t("lookup.quotaFresh") : account.freshness === "stale" ? t("lookup.quotaStale") : t("lookup.quotaUnknown")}</span>
                </div>
				{observedAt && (
				  <div className="lookup-quota-window-meta">{t("lookup.quotaObservedAt", { at: observedAt })}</div>
                )}
                <div className="lookup-quota-windows">
                  {formatQuotaWindow(account.short, t)}
                  {formatQuotaWindow(account.long, t)}
							{!account.short && !account.long && <div className="lookup-quota-window-meta">{t("lookup.quotaNoData")}</div>}
                </div>
				{refreshStatus && <div className="lookup-quota-refresh-state">{refreshStatus}{refreshAfter ? ` · ${t("lookup.quotaRefreshAfter", { at: refreshAfter })}` : ""}</div>}
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

function WindowCard({
  label,
  used,
  limit,
  timeAt,
  timeKind,
}: {
  label: string;
  used: number;
  limit: number;
  timeAt?: string;
  timeKind: "reset" | "roll";
}) {
  const t = useT();
  const time = formatReset(timeAt);
  return (
    <div className="lookup-window-card">
      <div className="lookup-window-label">{label}</div>
      <div className="lookup-window-value">{formatUSD(used)}</div>
      <div className="lookup-progress" aria-hidden="true">
        <span style={{ width: `${usagePercent(used, limit)}%` }} />
      </div>
      <div className="lookup-window-caption">
        {t("lookup.used", { used: formatUSD(used).replace("$", ""), limit: displayLimit(limit, t("lookup.unlimited")).replace("$", "") })}
      </div>
      {time && <div className="lookup-window-reset">
        {t(timeKind === "roll" ? "lookup.nextRollAt" : "lookup.resetAt", { at: time })}
      </div>}
    </div>
  );
}

function LimitCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="lookup-limit-card">
      <div className="lookup-limit-label">{label}</div>
      <div className="lookup-limit-value">{value}</div>
    </div>
  );
}

function AliasTable({ aliases }: { aliases: LookupAliasSummary[] }) {
  const t = useT();
  if (aliases.length === 0) {
    return <p className="muted lookup-empty">{t("lookup.emptyAliases")}</p>;
  }
  return (
    <div className="lookup-alias-table-wrap">
      <table className="lookup-alias-table">
        <thead>
          <tr>
            <th>{t("lookup.alias")}</th>
            <th>{t("lookup.billing")}</th>
            <th className="num">{t("lookup.daily")}</th>
            <th className="num">{t("lookup.weekly")}</th>
          </tr>
        </thead>
        <tbody>
          {aliases.map((alias) => (
            <tr key={alias.alias}>
              <td className="mono">{alias.alias}</td>
              <td>{alias.billing_mode === "per_call" ? t("lookup.perCall") : t("lookup.tokens")}</td>
              <td className="num">{formatUSD(usageValue(alias.daily))}</td>
              <td className="num">{formatUSD(usageValue(alias.weekly))}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function isAllDerivedLookup(data: LookupResponse): data is LookupAllDerivedResponse {
  return "scope" in data && data.scope === "all-derived";
}

function LookupKeyDetails({
  data,
  quotaRefresh,
}: {
  data: LookupKeyUsage;
  quotaRefresh?: {
    refreshingRef: string | null;
    error: string;
    onRefresh: (ref: string) => void;
  };
}) {
  const t = useT();
  const { limits, usage, concurrency } = data;
  return (
    <>
      <section className="lookup-section">
        <h3>{t("lookup.limitsTitle")}</h3>
        <div className="lookup-limit-grid">
          <LimitCard label={t("lookup.rpm")} value={limits.rpm > 0 ? String(limits.rpm) : t("lookup.unlimited")} />
          <LimitCard label={t("lookup.dailyLimit")} value={displayLimit(limits.daily_usd, t("lookup.unlimited"))} />
          <LimitCard label={t("lookup.weeklyLimit")} value={displayLimit(limits.weekly_usd, t("lookup.unlimited"))} />
          <LimitCard label={t("lookup.maxConcurrent")} value={limits.max_concurrent_requests > 0 ? String(limits.max_concurrent_requests) : t("lookup.unlimited")} />
        </div>
      </section>

      <section className="lookup-section">
        <h3>{t("lookup.usageTitle")}</h3>
        <div className="lookup-window-grid">
          <WindowCard
            label={t("lookup.dailyWindow")}
            used={usage.daily_usd ?? 0}
            limit={limits.daily_usd}
            timeAt={usage.daily_reset_at}
            timeKind="reset"
          />
          <WindowCard
            label={t("lookup.weeklyWindow")}
            used={usage.weekly_usd ?? 0}
            limit={limits.weekly_usd}
            timeAt={usage.weekly_next_roll_at}
            timeKind="roll"
          />
        </div>
        <p className="muted lookup-window-note">{t("lookup.utcWindowHint")}</p>
        {usage.weekly_history_complete === false && (
          <p className="lookup-quota-note">
            {t("lookup.historyIncomplete", { at: formatReset(usage.weekly_history_incomplete_until) ?? "—" })}
          </p>
        )}
        {formatReset(usage.last_usage_reset_at) && (
          <p className="muted lookup-window-note">
            {t("lookup.lastUsageReset", { at: formatReset(usage.last_usage_reset_at) ?? "—" })}
          </p>
        )}
      </section>

      <section className="lookup-section">
        <h3>{t("lookup.concurrencyTitle")}</h3>
        <div className="lookup-concurrency-card">
          <div>
            <div className="lookup-concurrency-label">{t("lookup.current")}</div>
            <div className="lookup-concurrency-value">{concurrency.current}</div>
          </div>
          <div>
            <div className="lookup-concurrency-label">{t("lookup.maximum")}</div>
            <div className="lookup-concurrency-value">{concurrency.maximum > 0 ? concurrency.maximum : t("lookup.unlimited")}</div>
          </div>
        </div>
      </section>

      <section className="lookup-section">
        <h3>{t("lookup.aliasesTitle")}</h3>
        <AliasTable aliases={data.aliases ?? []} />
      </section>
      {quotaRefresh && data.auth_quotas && (
        <LookupAuthQuotaSection
          quotas={data.auth_quotas}
          refreshingRef={quotaRefresh.refreshingRef}
          refreshError={quotaRefresh.error}
          onRefresh={quotaRefresh.onRefresh}
        />
      )}
    </>
  );
}

export default function Lookup() {
  const t = useT();
  const [secret, setSecret] = useState("");
  const [data, setData] = useState<LookupResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [quotaRefreshingRef, setQuotaRefreshingRef] = useState<string | null>(null);
  const [quotaRefreshError, setQuotaRefreshError] = useState("");

  const query = async () => {
    const value = secret.trim();
    setError("");
    setQuotaRefreshError("");
    if (!value) {
      setData(null);
      setError(t("lookup.keyRequired"));
      return;
    }
    setLoading(true);
    try {
      const result = await fetchLookupData(value);
      setData(result);
    } catch {
      setData(null);
      setError(t("lookup.invalidKey"));
    } finally {
      setLoading(false);
    }
  };

  const refreshQuota = async (accountRef: string) => {
    const value = secret.trim();
    if (!value || quotaRefreshingRef !== null) return;
    setQuotaRefreshError("");
    setQuotaRefreshingRef(accountRef);
    try {
      const result = await fetchLookupQuota(value, accountRef);
      setData((previous) => previous && !isAllDerivedLookup(previous)
        ? { ...previous, auth_quotas: result.auth_quotas }
        : previous);
    } catch {
      setQuotaRefreshError(t("lookup.quotaRefreshFailed"));
    } finally {
      setQuotaRefreshingRef(null);
    }
  };

  const clear = () => {
    setSecret("");
    setData(null);
    setError("");
    setQuotaRefreshError("");
    setQuotaRefreshingRef(null);
  };

  return (
    <div className="lookup-page">
      <header className="lookup-header">
        <div>
          <h1>{t("lookup.title")}</h1>
          <p>{t("lookup.subtitle")}</p>
        </div>
      </header>
      <section className="lookup-query-card">
        <form className="lookup-query-form" onSubmit={(event) => { event.preventDefault(); void query(); }}>
          <label htmlFor="lookup-secret">{t("lookup.keyLabel")}</label>
          <div className="lookup-query-controls">
            <input
              id="lookup-secret"
              className="input mono"
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={secret}
              onChange={(event) => setSecret(event.target.value)}
              placeholder={t("lookup.keyPlaceholder")}
            />
            <button className="btn primary" type="submit" disabled={loading}>
              {loading ? t("lookup.loading") : t("lookup.query")}
            </button>
            <button className="btn" type="button" onClick={clear}>
              {t("lookup.clear")}
            </button>
          </div>
        </form>
      </section>
      {error && <div className="error lookup-error" role="alert">{error}</div>}
      {data && (
        <main className="lookup-results">
          <div className="lookup-result-head">
            <div>
              <div className="lookup-result-kicker">{isAllDerivedLookup(data) ? t("lookup.allDerivedHint") : t("lookup.keyLabel")}</div>
              <h2>{isAllDerivedLookup(data) ? t("lookup.allDerivedTitle") : data.name}</h2>
            </div>
            <button className="btn" type="button" disabled={loading} onClick={() => void query()}>
              {loading ? t("lookup.loading") : t("lookup.refresh")}
            </button>
          </div>
          {isAllDerivedLookup(data) ? (
            data.keys.length === 0 ? <p className="muted lookup-empty">{t("lookup.emptyDerived")}</p> : (
              <div className="lookup-derived-list">
                {data.keys.map((key) => (
                  <article className="lookup-derived-card" key={key.key_id}>
                    <div className="lookup-derived-head">
                      <div>
                        <div className="lookup-result-kicker">{t("lookup.keyId")}: <span className="mono">{key.key_id}</span></div>
                        <h2>{key.name}</h2>
                      </div>
                      <span className={`lookup-key-status ${key.enabled ? "enabled" : "disabled"}`}>
                        {key.enabled ? t("lookup.enabled") : t("lookup.disabled")}
                      </span>
                    </div>
                    <LookupKeyDetails data={key} />
                  </article>
                ))}
              </div>
            )
          ) : (
            <LookupKeyDetails
              data={data}
              quotaRefresh={{
                refreshingRef: quotaRefreshingRef,
                error: quotaRefreshError,
                onRefresh: (ref) => { void refreshQuota(ref); },
              }}
            />
          )}
        </main>
      )}
    </div>
  );
}

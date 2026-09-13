import { useState } from "react";
import { fetchLookupData, lookupStatus } from "../api/lookup";
import { useT } from "../i18n";
import type { LookupAliasSummary, LookupResponse, UsageWindow } from "../types";
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
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function WindowCard({
  label,
  used,
  limit,
  resetAt,
}: {
  label: string;
  used: number;
  limit: number;
  resetAt?: string;
}) {
  const t = useT();
  const reset = formatReset(resetAt);
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
      {reset && <div className="lookup-window-reset">{t("lookup.resetAt", { at: reset })}</div>}
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

export default function Lookup() {
  const t = useT();
  const [secret, setSecret] = useState("");
  const [data, setData] = useState<LookupResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const query = async () => {
    const value = secret.trim();
    setError("");
    if (!value) {
      setData(null);
      setError(t("lookup.keyRequired"));
      return;
    }
    setLoading(true);
    try {
      const result = await fetchLookupData(value);
      setData(result);
    } catch (err: unknown) {
      setData(null);
      setError(lookupStatus(err) === 501 ? t("lookup.nativeUnsupported") : t("lookup.invalidKey"));
    } finally {
      setLoading(false);
    }
  };

  const clear = () => {
    setSecret("");
    setData(null);
    setError("");
  };

  const usage = data?.usage;
  const limits = data?.limits;
  const concurrency = data?.concurrency;

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
      {data && limits && usage && concurrency && (
        <main className="lookup-results">
          <div className="lookup-result-head">
            <div>
              <div className="lookup-result-kicker">{t("lookup.keyLabel")}</div>
              <h2>{data.name}</h2>
            </div>
            <button className="btn" type="button" disabled={loading} onClick={() => void query()}>
              {loading ? t("lookup.loading") : t("lookup.refresh")}
            </button>
          </div>

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
                resetAt={usage.daily_reset_at}
              />
              <WindowCard
                label={t("lookup.weeklyWindow")}
                used={usage.weekly_usd ?? 0}
                limit={limits.weekly_usd}
                resetAt={usage.weekly_reset_at}
              />
            </div>
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
        </main>
      )}
    </div>
  );
}

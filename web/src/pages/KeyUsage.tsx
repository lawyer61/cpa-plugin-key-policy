import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { fetchKeyUsage } from "../api/keys";
import type { AliasUsageEntry, KeyUsageResponse, UsageWindow } from "../types";
import { useT } from "../i18n";
import { MobileTabBar } from "./KeyList";
import { formatUSD } from "../utils/money";

// Window switch for the per-alias breakdown table: each alias row has its own
// UTC today and the current seven UTC calendar days, and the user toggles
// which one all rows show at once.
type Window = "daily" | "weekly";

// Compact integer formatting with thousands separators. 0 shows as "0".
function fmtInt(n: number): string {
  if (!n || n <= 0) return "0";
  return Math.round(n).toLocaleString("en-US");
}

// Hit-rate = cacheRead / (cacheRead + input), expressed as a percentage.
// Returns "—" when there's no input activity for the window (avoid 0/0).
function hitRate(w: UsageWindow): string {
  const cr = w.cache_read_tokens ?? 0;
  const inp = w.input_tokens ?? 0;
  const denom = cr + inp;
  if (denom <= 0) return "—";
  return Math.round((cr / denom) * 100) + "%";
}

function fmtTime(value?: string): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) || date.getUTCFullYear() <= 1 ? null : date.toLocaleString();
}

// Billing-mode tag, reusing the existing .tag styling. Per-call rows use a
// distinct tint so they're scannable at a glance.
function BillingTag({ mode }: { mode?: string }) {
  const t = useT();
  const perCall = mode === "per_call";
  return (
    <span className={"tag " + (perCall ? "off" : "on")} style={perCall ? { color: "var(--accent)", borderColor: "var(--accent-ring)", background: "var(--accent-soft)" } : undefined}>
      {perCall ? t("keyUsage.billingPerCall") : t("keyUsage.billingTokens")}
    </span>
  );
}

export default function KeyUsage() {
  const { id } = useParams<{ id: string }>();
  const t = useT();
  const [data, setData] = useState<KeyUsageResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [win, setWin] = useState<Window>("daily");

  useEffect(() => {
    let alive = true;
    (async () => {
      setLoading(true);
      setError("");
      try {
        const keyId = decodeURIComponent(id ?? "");
        if (!keyId) {
          setError(t("keyUsage.notFound"));
          return;
        }
        setData(await fetchKeyUsage(keyId));
      } catch (e) {
        const err = e as { response?: { data?: { error?: { message?: string } } }; message?: string };
        setError(err.response?.data?.error?.message ?? err.message ?? t("keyUsage.loadFailed"));
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  if (loading) return <div className="muted">{t("keyUsage.loading")}</div>;
  if (error || !data) return <div className="error">{error || t("keyUsage.notFound")}</div>;

  const aliases = data.aliases ?? [];
  const hasUsage = (data.usage.daily_call_count ?? 0) !== 0 || (data.usage.weekly_call_count ?? 0) !== 0 || data.usage.daily_usd !== 0 || data.usage.weekly_usd !== 0;

  const windowOf = (a: AliasUsageEntry): UsageWindow => (win === "daily" ? a.daily : a.weekly);

  // The hero uses the backend's total snapshot rather than re-summing aliases:
  // legacy migrations deliberately preserve any pre-existing total/alias gap.
  const heroUsd = win === "daily" ? data.usage.daily_usd : data.usage.weekly_usd;
  const heroCalls = win === "daily" ? (data.usage.daily_call_count ?? 0) : (data.usage.weekly_call_count ?? 0);
  const heroInput = win === "daily" ? (data.usage.daily_input_tokens ?? 0) : (data.usage.weekly_input_tokens ?? 0);
  const heroOutput = win === "daily" ? (data.usage.daily_output_tokens ?? 0) : (data.usage.weekly_output_tokens ?? 0);
  const heroLimit = win === "daily" ? data.daily_limit_usd : data.weekly_limit_usd;
  const heroPct = heroLimit > 0 ? Math.min(100, (heroUsd / heroLimit) * 100) : 0;
  const maxAliasUsd = Math.max(1, ...aliases.map((a) => windowOf(a).total_usd ?? 0));
  const nextRoll = fmtTime(data.usage.weekly_next_roll_at);
  const incompleteUntil = fmtTime(data.usage.weekly_history_incomplete_until);
  const lastReset = fmtTime(data.usage.last_usage_reset_at);

  return (
    <div>
      {/* Header: back · key id (mono) · name · daily/weekly toggle */}
      <div className="keyusage-header">
        <div className="keyusage-idline">
          <Link to="/keys">
            <button className="btn sm">{t("keyUsage.back")}</button>
          </Link>
          <span className="mono keyusage-id">{data.key_id}</span>
          <span className="muted">{data.key_name}</span>
          <Link
            to={`/keys/${encodeURIComponent(data.key_id)}/edit`}
            className="mobile-only keyusage-edit-link"
          >
            <button type="button" className="btn sm">{t("keys.edit")}</button>
          </Link>
        </div>
        <div className="seg" role="tablist" aria-label={t("keyUsage.windowToggle")}>
          <button
            role="tab"
            aria-selected={win === "daily"}
            className={"seg-btn " + (win === "daily" ? "active" : "")}
            onClick={() => setWin("daily")}
          >
            {t("keyUsage.tabDaily")}
          </button>
          <button
            role="tab"
            aria-selected={win === "weekly"}
            className={"seg-btn " + (win === "weekly" ? "active" : "")}
            onClick={() => setWin("weekly")}
          >
            {t("keyUsage.tabWeekly")}
          </button>
        </div>
      </div>

      <div className="usage-window-notes">
        <div className="muted">{win === "daily" ? t("keyUsage.utcDailyHint") : t("keyUsage.utcWeeklyHint")}</div>
        {win === "weekly" && nextRoll && <div className="muted">{t("keyUsage.nextRoll", { at: nextRoll })}</div>}
        {data.usage.weekly_history_complete === false && (
          <div className="usage-history-warning">{t("keyUsage.historyIncomplete", { at: incompleteUntil ?? "—" })}</div>
        )}
        {lastReset && <div className="muted">{t("keyUsage.lastReset", { at: lastReset })}</div>}
      </div>

      {/* Desktop: hero summary + per-alias table (unchanged) */}
      <div className="usage-hero-d">
        <div className="uhd-tiles">
          <div className="uhd-tile">
            <span className="uhd-tk">{win === "daily" ? t("keyUsage.mobile.todaySpend") : t("keyUsage.mobile.weekSpend")}</span>
            <span className={"uhd-tv" + (heroLimit > 0 && heroUsd >= heroLimit ? " accent" : "")}>{formatUSD(heroUsd)}</span>
          </div>
          <div className="uhd-tile">
            <span className="uhd-tk">{t("keyUsage.colCalls")}</span>
            <span className="uhd-tv">{fmtInt(heroCalls)}</span>
          </div>
          <div className="uhd-tile">
            <span className="uhd-tk">{t("keyUsage.mobile.limit")}</span>
            <span className="uhd-tv">{heroLimit > 0 ? formatUSD(heroLimit) : t("keyUsage.mobile.noLimit")}</span>
          </div>
        </div>
        {heroLimit > 0 && (
          <>
            <div className={"uhd-bar" + (heroUsd >= heroLimit ? " over" : "")}>
              <span style={{ width: Math.min(100, heroPct) + "%" }} />
            </div>
            <div className="uhd-barcap">
              <span>{formatUSD(heroUsd)} / {formatUSD(heroLimit)}</span>
              <span className={heroUsd >= heroLimit ? "over" : ""}>{Math.round(heroPct)}%</span>
            </div>
          </>
        )}
      </div>

      <div className="card table-wrap">
        {!hasUsage && <div className="muted keyusage-empty">{t("keyUsage.empty")}</div>}
        <table>
          <thead>
            <tr>
              <th>{t("keyUsage.colAlias")}</th>
              <th>{t("keyUsage.colBillingMode")}</th>
              <th>{t("keyUsage.colProvider")}</th>
              <th className="num">{t("keyUsage.colUsd")}</th>
              <th className="num">{t("keyUsage.colCalls")}</th>
              <th className="num">{t("keyUsage.colInput")}</th>
              <th className="num">{t("keyUsage.colOutput")}</th>
              <th className="num">{t("keyUsage.colCache")}</th>
              <th className="num">{t("keyUsage.colHitRate")}</th>
            </tr>
          </thead>
          <tbody>
            {aliases.length === 0 ? (
              <tr>
                <td colSpan={9} className="muted keyusage-noalias">
                  {t("keyUsage.noAlias")}
                </td>
              </tr>
            ) : (
              aliases.map((a) => {
                const w = windowOf(a);
                return (
                  <tr key={a.alias} className={a.in_config ? "" : "keyusage-residual"}>
                    <td>
                      <div className="mono">{a.alias}</div>
                      {!a.in_config && <span className="keyusage-badge">{t("keyUsage.notInConfig")}</span>}
                    </td>
                    <td>
                      <BillingTag mode={a.billing_mode} />
                    </td>
                    <td className="muted">{a.provider || "—"}</td>
                    <td className="num strong">{formatUSD(w.total_usd ?? 0)}</td>
                    <td className="num mono">{fmtInt(w.call_count ?? 0)}</td>
                    <td className="num mono">{fmtInt(w.input_tokens ?? 0)}</td>
                    <td className="num mono">{fmtInt(w.output_tokens ?? 0)}</td>
                    <td className="num mono">{fmtInt(w.cache_read_tokens ?? 0)}</td>
                    <td className="num mono">{hitRate(w)}</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Mobile: hero card + horizontal bar ranking */}
      <div className="mobile-only">
        <div className="usage-hero">
          <div className="uh-label">{win === "daily" ? t("keyUsage.mobile.today") : t("keyUsage.mobile.thisWeek")}</div>
          <div className="uh-amount">{formatUSD(heroUsd)}<span className="uh-unit">USD</span></div>
          <div className="uh-row">
            <div className="uh-ring">
              <svg width="64" height="64" viewBox="0 0 64 64">
                <circle cx="32" cy="32" r="26" fill="none" stroke="var(--muted-bg)" strokeWidth="6" />
                <circle cx="32" cy="32" r="26" fill="none" stroke="var(--accent)" strokeWidth="6"
                  strokeLinecap="round"
                  strokeDasharray={`${(heroPct / 100) * 163.36} 163.36`} />
              </svg>
              <span className="uh-pct">{Math.round(heroPct)}%</span>
            </div>
            <div className="uh-limits">
              <div><span className="uh-lk">{t("keyUsage.mobile.limit")}</span> <span className="uh-lv">{heroLimit > 0 ? formatUSD(heroLimit) : t("keyUsage.mobile.noLimit")}</span></div>
              <div><span className="uh-lk">{t("keyUsage.mobile.remaining")}</span> <span className="uh-lv">{heroLimit > 0 ? formatUSD(Math.max(0, heroLimit - heroUsd)) : "—"}</span></div>
            </div>
          </div>
          <div className="uh-stats">
            <span>{t("keyUsage.mobile.calls")} {fmtInt(heroCalls)}</span>
            <span>{t("keyUsage.mobile.inputTok")} {fmtInt(heroInput)}</span>
            <span>{t("keyUsage.mobile.outputTok")} {fmtInt(heroOutput)}</span>
          </div>
        </div>

        <div className="section-label">{t("keyUsage.mobile.byAlias")}</div>
        <div className="bar-rank">
          {aliases.length === 0 ? (
            <div className="muted">{t("keyUsage.noAlias")}</div>
          ) : aliases.map((a) => {
            const w = windowOf(a);
            const usd = w.total_usd ?? 0;
            const w2 = Math.max(2, (usd / maxAliasUsd) * 100);
            const perCall = a.billing_mode === "per_call";
            return (
              <div key={a.alias} className={"br-row" + (a.in_config ? "" : " br-residual")}>
                <div className="br-top">
                  <span className="br-name">{a.alias}{!a.in_config && <span className="br-badge">!</span>}</span>
                  <span className="br-usd">{formatUSD(usd)}</span>
                </div>
                <div className="br-bar"><span style={{ width: w2 + "%" }} /></div>
                <div className="br-cap">
                  {a.provider || "—"} · {perCall ? t("keyUsage.billingPerCall") : t("keyUsage.billingTokens")} · {t("keys.mobile.callCount", { n: fmtInt(w.call_count ?? 0) })}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <MobileTabBar
        active="usage"
        showUsage
        usagePath={`/keys/${encodeURIComponent(data.key_id)}/usage`}
      />
    </div>
  );
}

import { useEffect, useState, useCallback } from "react";
import { useNavigate, useParams, useLocation } from "react-router-dom";
import { useT } from "../i18n";
import type {
  AliasMapping,
  AliasTarget,
  ClassifyRule,
  ClassifyPreviewResponse,
  CredentialDescriptor,
  SchedulerSettings,
  SchedulerSettingsPatch,
  QuotaAuthStatus,
  QuotaStatus,
  QuotaWindowStatus,
} from "../types";
import {
  fetchAliases,
  upsertAlias,
  deleteAlias,
  fetchClassifyRules,
  upsertClassifyRule,
  deleteClassifyRule,
  reorderClassifyRules,
  classifyPreview,
  fetchCredentialDescriptors,
  fetchSchedulerSettings,
  updateSchedulerSettings,
  testQuotaManagementConnection,
  fetchQuotaStatus,
} from "../api/mappings";

export default function Mapping() {
  const t = useT();
  const loc = useLocation();
  const [tab, setTab] = useState<"alias" | "classify">("alias");

  // Pick up returned state (new targets from ModelPick, etc.)
  useEffect(() => {
    if (loc.state?.mappingTab) setTab(loc.state.mappingTab);
  }, [loc.state]);

  return (
    <div className="map-page">
      <div className="map-page-head">
        <h1>{t("mapping.title")}</h1>
      </div>
      <div className="map-tabs">
        <button className={"map-tab" + (tab === "alias" ? " active" : "")} onClick={() => setTab("alias")}>
          {t("mapping.aliasTab")}
        </button>
        <button className={"map-tab" + (tab === "classify" ? " active" : "")} onClick={() => setTab("classify")}>
          {t("mapping.classifyTab")}
        </button>
      </div>
      {tab === "alias" ? <AliasListTab /> : <ClassifyTab />}
    </div>
  );
}

// --- Alias List Tab ---

function AliasListTab() {
  const t = useT();
  const nav = useNavigate();
  const [aliases, setAliases] = useState<AliasMapping[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [globalWeighted, setGlobalWeighted] = useState(false);
  const [schedulerSettings, setSchedulerSettings] = useState<SchedulerSettings | null>(null);
  const [credentialDescriptors, setCredentialDescriptors] = useState<CredentialDescriptor[]>([]);
  const [quotaStatus, setQuotaStatus] = useState<QuotaStatus | null>(null);
  const [settingsSaving, setSettingsSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [list, settings, descriptors, quota] = await Promise.all([
        fetchAliases(),
        fetchSchedulerSettings(),
        fetchCredentialDescriptors().catch(() => [] as CredentialDescriptor[]),
        fetchQuotaStatus().catch(() => null as QuotaStatus | null),
      ]);
      setAliases(list);
      setSchedulerSettings(settings);
      setGlobalWeighted(settings.global_weighted_round_robin);
      setCredentialDescriptors(descriptors);
      setQuotaStatus(quota);
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const handleDelete = async (aliasName: string) => {
    try {
      await deleteAlias(aliasName);
      await load();
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleGlobalWeightedChange = async (enabled: boolean) => {
    const previous = globalWeighted;
    setGlobalWeighted(enabled);
    setSettingsSaving(true);
    setError("");
    try {
      const settings = await updateSchedulerSettings(enabled);
      setSchedulerSettings((prev) => prev ? { ...prev, ...settings } : settings);
      setGlobalWeighted(settings.global_weighted_round_robin);
    } catch (e: unknown) {
      setGlobalWeighted(previous);
      setError(t("mapping.globalWeightedSaveFailed") + ": " + String(e));
    } finally {
      setSettingsSaving(false);
    }
  };

  const handleRuntimeSave = async (patch: SchedulerSettingsPatch): Promise<SchedulerSettings | undefined> => {
    setSettingsSaving(true);
    setError("");
    try {
      const settings = await updateSchedulerSettings(patch);
      setSchedulerSettings(settings);
      setGlobalWeighted(settings.global_weighted_round_robin ?? globalWeighted);
      setQuotaStatus(await fetchQuotaStatus().catch(() => quotaStatus));
      return settings;
    } catch (e: unknown) {
      setError(t("mapping.runtimeSaveFailed") + ": " + String(e));
      return undefined;
    } finally {
      setSettingsSaving(false);
    }
  };

  const syncSchedulerSettings = (settings: SchedulerSettings) => {
    setSchedulerSettings(settings);
    setGlobalWeighted(settings.global_weighted_round_robin ?? false);
  };

  return (
    <>
      <div className="map-toolbar">
        <label className="switch map-global-toggle" title={t("mapping.globalWeightedTitle")}>
          <span className="map-global-label">{t("mapping.globalWeighted")}</span>
          <input
            type="checkbox"
            checked={globalWeighted}
            disabled={loading || settingsSaving}
            onChange={(event) => void handleGlobalWeightedChange(event.target.checked)}
            aria-label={t("mapping.globalWeighted")}
            aria-busy={settingsSaving}
          />
          <span className="track" aria-hidden="true">
            <span className="thumb" />
          </span>
        </label>
        <button className="btn primary" onClick={() => nav("/mapping/alias/new")}>
          + {t("mapping.newAlias")}
        </button>
      </div>
      {error && <div className="error">{error}</div>}
      <RuntimeSettingsPanel
        settings={schedulerSettings}
        descriptors={credentialDescriptors}
        quotaStatus={quotaStatus}
        loading={loading}
        saving={settingsSaving}
        onSave={handleRuntimeSave}
        onSettingsRefreshed={syncSchedulerSettings}
      />
      {loading ? (
        <div className="muted" style={{ padding: 20 }}>{t("keys.loading") || "Loading..."}</div>
      ) : aliases.length === 0 ? (
        <div className="muted" style={{ padding: 20 }}>No aliases</div>
      ) : (
        <div className="alias-grid">
          {aliases.map((a) => (
            <AliasCard key={a.alias} alias={a} onDelete={handleDelete} onEdit={(name) => nav(`/mapping/alias/${encodeURIComponent(name)}`)} />
          ))}
        </div>
      )}
    </>
  );
}

const DEFAULT_QUOTA_MANAGEMENT_BASE_URL = "http://127.0.0.1:8317";

function RuntimeSettingsPanel({
  settings,
  descriptors,
  quotaStatus,
  loading,
  saving,
  onSave,
  onSettingsRefreshed,
}: {
  settings: SchedulerSettings | null;
  descriptors: CredentialDescriptor[];
  quotaStatus: QuotaStatus | null;
  loading: boolean;
  saving: boolean;
  onSave: (patch: SchedulerSettingsPatch) => Promise<SchedulerSettings | undefined>;
  onSettingsRefreshed: (settings: SchedulerSettings) => void;
}) {
  const t = useT();
  const [ttl, setTtl] = useState(0);
  const [cacheCap, setCacheCap] = useState(0);
  const [authLimits, setAuthLimits] = useState<Record<string, number>>({});
  const [newAuthId, setNewAuthId] = useState("");
  const [selectedDescriptor, setSelectedDescriptor] = useState("");
  const [quotaCheckInterval, setQuotaCheckInterval] = useState("30m");
  const [quotaCacheTtl, setQuotaCacheTtl] = useState("30m");
  const [quotaActivationEnabled, setQuotaActivationEnabled] = useState(false);
  const [quotaActivationScope, setQuotaActivationScope] = useState<"managed-pools" | "all-codex">("managed-pools");
  const [quotaActivationModel, setQuotaActivationModel] = useState("gpt-5.6-luna");
  const [quotaManagementEnabled, setQuotaManagementEnabled] = useState(false);
  const [quotaManagementActivationEnabled, setQuotaManagementActivationEnabled] = useState(false);
  const [quotaManagementBaseURL, setQuotaManagementBaseURL] = useState(DEFAULT_QUOTA_MANAGEMENT_BASE_URL);
  const [loadedQuotaManagementBaseURL, setLoadedQuotaManagementBaseURL] = useState(DEFAULT_QUOTA_MANAGEMENT_BASE_URL);
  const [quotaManagementKey, setQuotaManagementKey] = useState("");
  const [quotaManagementKeyConfigured, setQuotaManagementKeyConfigured] = useState(false);
  const [quotaManagementState, setQuotaManagementState] = useState<"disabled" | "unconfigured" | "ready" | "paused">("disabled");
  const [quotaManagementTesting, setQuotaManagementTesting] = useState(false);
  const [quotaManagementError, setQuotaManagementError] = useState("");
  const [quotaManagementMessage, setQuotaManagementMessage] = useState("");

  useEffect(() => {
    if (!settings) return;
    setTtl(settings.session_affinity_idle_ttl_seconds ?? 0);
    setCacheCap(settings.session_affinity_max_entries ?? 0);
    setAuthLimits({ ...(settings.auth_concurrency_limits ?? {}) });
    setQuotaCheckInterval(settings.quota_check_interval ?? "30m");
    setQuotaCacheTtl(settings.quota_cache_ttl ?? "30m");
    setQuotaActivationEnabled(settings.quota_activation_enabled ?? false);
    setQuotaActivationScope(settings.quota_activation_scope ?? "managed-pools");
    setQuotaActivationModel(settings.quota_activation_model ?? "gpt-5.6-luna");
    const baseURL = settings.quota_management_base_url?.trim() || DEFAULT_QUOTA_MANAGEMENT_BASE_URL;
    setQuotaManagementEnabled(settings.quota_management_enabled ?? false);
    setQuotaManagementActivationEnabled(settings.quota_management_activation_enabled ?? false);
    setQuotaManagementBaseURL(baseURL);
    setLoadedQuotaManagementBaseURL(baseURL);
    setQuotaManagementKeyConfigured(settings.quota_management_key_configured ?? false);
    setQuotaManagementState(settings.quota_management_state ?? "disabled");
  }, [settings]);

  const configuredIds = Object.keys(authLimits).sort((a, b) => a.localeCompare(b));
  const availableDescriptors = descriptors
    .map((descriptor) => descriptor.id.trim())
    .filter((id, index, all) => id && all.indexOf(id) === index && !(id in authLimits))
    .sort((a, b) => a.localeCompare(b));

  const addAuthLimit = (value: string) => {
    const id = value.trim();
    if (!id) return;
    setAuthLimits((prev) => ({ ...prev, [id]: prev[id] ?? 0 }));
    setNewAuthId("");
    setSelectedDescriptor("");
  };

  const save = async () => {
    const limits: Record<string, number> = {};
    for (const [rawId, rawLimit] of Object.entries(authLimits)) {
      const id = rawId.trim();
      const limit = Number.isFinite(rawLimit) ? Math.max(0, Math.floor(rawLimit)) : 0;
      // A zero limit means no override and must not be sent to the backend.
      if (id && limit > 0) limits[id] = limit;
    }
    setQuotaManagementError("");
    setQuotaManagementMessage("");
    const baseURL = quotaManagementBaseURL.trim() || DEFAULT_QUOTA_MANAGEMENT_BASE_URL;
    const newKey = quotaManagementKey.trim();
    if (baseURL !== loadedQuotaManagementBaseURL && !newKey) {
      setQuotaManagementError(t("mapping.quotaManagementBaseURLKeyRequired"));
      return;
    }
    const patch: SchedulerSettingsPatch = {
      auth_concurrency_limits: limits,
      session_affinity_idle_ttl_seconds: Math.max(0, Math.floor(ttl) || 0),
      session_affinity_max_entries: Math.max(0, Math.floor(cacheCap) || 0),
      quota_check_interval: quotaCheckInterval.trim(),
      quota_cache_ttl: quotaCacheTtl.trim(),
      quota_activation_enabled: quotaActivationEnabled,
      quota_activation_scope: quotaActivationScope,
      quota_activation_model: quotaActivationModel.trim(),
      quota_management_enabled: quotaManagementEnabled,
      quota_management_activation_enabled: quotaManagementActivationEnabled,
      quota_management_base_url: baseURL,
    };
    // An empty password field means “keep the saved secret”; only the
    // explicit clear action below sends quota_management_key: "".
    if (newKey) patch.quota_management_key = newKey;
    const updated = await onSave(patch);
    if (updated) {
      setQuotaManagementKey("");
      setQuotaManagementMessage(t("mapping.quotaManagementSaved"));
    }
  };

  const testManagementConnection = async () => {
    setQuotaManagementError("");
    setQuotaManagementMessage("");
    if (!quotaManagementKeyConfigured) {
      setQuotaManagementError(t("mapping.quotaManagementTestNeedsKey"));
      return;
    }
    setQuotaManagementTesting(true);
    try {
      await testQuotaManagementConnection();
      const refreshed = await fetchSchedulerSettings();
      onSettingsRefreshed(refreshed);
      setQuotaManagementKey("");
      setQuotaManagementMessage(t("mapping.quotaManagementTestSuccess"));
    } catch (e: unknown) {
      setQuotaManagementError(t("mapping.quotaManagementTestFailed") + ": " + String(e));
    } finally {
      setQuotaManagementTesting(false);
    }
  };

  const clearManagementKey = async () => {
    setQuotaManagementError("");
    setQuotaManagementMessage("");
    const updated = await onSave({
      quota_management_enabled: false,
      quota_management_key: "",
    });
    if (updated) {
      setQuotaManagementEnabled(false);
      setQuotaManagementKeyConfigured(false);
      setQuotaManagementKey("");
      setQuotaManagementMessage(t("mapping.quotaManagementKeyCleared"));
    }
  };

  return (
    <section className="runtime-settings card" aria-labelledby="runtime-settings-title">
      <div className="runtime-settings-head">
        <div>
          <h2 id="runtime-settings-title">{t("mapping.runtimeTitle")}</h2>
          <p className="muted">{t("mapping.runtimeHint")}</p>
        </div>
        <button className="btn primary sm" type="button" disabled={loading || saving || !settings} onClick={() => void save()}>
          {saving ? t("mapping.runtimeSaving") : t("mapping.runtimeSave")}
        </button>
      </div>
      <div className="runtime-settings-grid">
        <div className="form-row">
          <label htmlFor="runtime-affinity-ttl">{t("mapping.affinityIdleTtl")}</label>
          <input
            id="runtime-affinity-ttl"
            className="input"
            type="number"
            min={0}
            step="1"
            value={ttl}
            disabled={loading || !settings}
            onChange={(event) => setTtl(Math.max(0, parseInt(event.target.value || "0", 10) || 0))}
          />
        </div>
        <div className="form-row">
          <label htmlFor="runtime-affinity-cap">{t("mapping.affinityMaxEntries")}</label>
          <input
            id="runtime-affinity-cap"
            className="input"
            type="number"
            min={0}
            step="1"
            value={cacheCap}
            disabled={loading || !settings}
            onChange={(event) => setCacheCap(Math.max(0, parseInt(event.target.value || "0", 10) || 0))}
          />
        </div>
      </div>
      <div className="runtime-auth-limits">
        <div className="runtime-auth-head">
          <div>
            <h3>{t("mapping.authConcurrencyTitle")}</h3>
            <p className="muted">{t("mapping.authConcurrencyHint")}</p>
          </div>
          <div className="runtime-auth-add">
            {availableDescriptors.length > 0 && (
              <select
                className="input"
                value={selectedDescriptor}
                disabled={loading || saving || !settings}
                onChange={(event) => {
                  setSelectedDescriptor(event.target.value);
                  addAuthLimit(event.target.value);
                }}
                aria-label={t("mapping.authIdPlaceholder")}
              >
                <option value="">{t("mapping.selectAuthId")}</option>
                {availableDescriptors.map((id) => <option key={id} value={id}>{id}</option>)}
              </select>
            )}
            <input
              className="input mono"
              value={newAuthId}
              disabled={loading || saving || !settings}
              onChange={(event) => setNewAuthId(event.target.value)}
              placeholder={t("mapping.authIdPlaceholder")}
              list="runtime-auth-id-options"
              aria-label={t("mapping.authIdPlaceholder")}
            />
            <datalist id="runtime-auth-id-options">
              {availableDescriptors.map((id) => <option key={id} value={id} />)}
            </datalist>
            <button className="btn sm" type="button" disabled={loading || saving || !settings || !newAuthId.trim()} onClick={() => addAuthLimit(newAuthId)}>
              + {t("mapping.addAuthId")}
            </button>
          </div>
        </div>
        {configuredIds.length === 0 ? (
          <p className="muted runtime-auth-empty">{t("mapping.noAuthLimits")}</p>
        ) : (
          <div className="runtime-auth-rows">
            {configuredIds.map((id) => (
              <div className="runtime-auth-row" key={id}>
                <span className="mono runtime-auth-id">{id}</span>
                <input
                  className="input runtime-auth-limit"
                  type="number"
                  min={0}
                  step="1"
                  value={authLimits[id] ?? 0}
                  disabled={loading || saving || !settings}
                  onChange={(event) => setAuthLimits((prev) => ({
                    ...prev,
                    [id]: Math.max(0, parseInt(event.target.value || "0", 10) || 0),
                  }))}
                  aria-label={t("mapping.authLimitLabel", { id })}
                />
                <span className="muted runtime-auth-unit">{t("mapping.authLimitUnit")}</span>
                <button className="btn sm danger-outline" type="button" disabled={loading || saving || !settings} onClick={() => setAuthLimits((prev) => {
                  const next = { ...prev };
                  delete next[id];
                  return next;
                })}>
                  {t("mapping.delete")}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="quota-settings">
        <div className="runtime-auth-head">
          <div>
            <h3>{t("mapping.quotaTitle")}</h3>
            <p className="muted">{t("mapping.quotaHint")}</p>
          </div>
        </div>
        <div className="runtime-settings-grid">
          <div className="form-row">
            <label htmlFor="quota-check-interval">{t("mapping.quotaCheckInterval")}</label>
            <input id="quota-check-interval" className="input" value={quotaCheckInterval} disabled={loading || !settings} onChange={(event) => setQuotaCheckInterval(event.target.value)} />
          </div>
          <div className="form-row">
            <label htmlFor="quota-cache-ttl">{t("mapping.quotaCacheTtl")}</label>
            <input id="quota-cache-ttl" className="input" value={quotaCacheTtl} disabled={loading || !settings} onChange={(event) => setQuotaCacheTtl(event.target.value)} />
          </div>
          <label className="switch quota-activation-toggle">
            <input type="checkbox" checked={quotaActivationEnabled} disabled={loading || !settings} onChange={(event) => setQuotaActivationEnabled(event.target.checked)} />
            <span className="track"><span className="thumb" /></span>
            <span>{t("mapping.quotaActivationEnabled")}</span>
          </label>
          <div className="form-row">
            <label htmlFor="quota-activation-scope">{t("mapping.quotaActivationScope")}</label>
            <select id="quota-activation-scope" className="input" value={quotaActivationScope} disabled={loading || !settings || !quotaActivationEnabled} onChange={(event) => setQuotaActivationScope(event.target.value as "managed-pools" | "all-codex")}>
              <option value="managed-pools">{t("mapping.quotaScopeManaged")}</option>
              <option value="all-codex">{t("mapping.quotaScopeAll")}</option>
            </select>
          </div>
          <div className="form-row">
            <label htmlFor="quota-activation-model">{t("mapping.quotaActivationModel")}</label>
            <input
              id="quota-activation-model"
              className="input mono"
              value={quotaActivationModel}
              disabled={loading || !settings}
              onChange={(event) => setQuotaActivationModel(event.target.value)}
              placeholder="gpt-5.6-luna"
              spellCheck={false}
            />
          </div>
        </div>
        <div className="quota-management-settings">
          <div className="runtime-auth-head">
            <div>
              <h3>{t("mapping.quotaManagementTitle")}</h3>
              <p className="muted">{t("mapping.quotaManagementHint")}</p>
            </div>
            <span className={"quota-management-status " + quotaManagementState}>
              {t("mapping.quotaManagementState." + quotaManagementState)}
            </span>
          </div>
          <label className="switch quota-management-toggle">
            <input
              id="quota-management-enabled"
              type="checkbox"
              checked={quotaManagementEnabled}
              disabled={loading || saving || !settings}
              onChange={(event) => setQuotaManagementEnabled(event.target.checked)}
            />
            <span className="track"><span className="thumb" /></span>
            <span>{t("mapping.quotaManagementEnabled")}</span>
          </label>
          <p className="muted quota-management-note">{t("mapping.quotaManagementMasterHint")}</p>
          <label className="switch quota-management-activation-toggle">
            <input
              id="quota-management-activation-enabled"
              type="checkbox"
              checked={quotaManagementActivationEnabled}
              disabled={loading || saving || !settings || !quotaManagementEnabled}
              onChange={(event) => setQuotaManagementActivationEnabled(event.target.checked)}
            />
            <span className="track"><span className="thumb" /></span>
            <span>{t("mapping.quotaManagementActivationEnabled")}</span>
          </label>
          <p className="muted quota-management-note">{t("mapping.quotaManagementActivationHint")}</p>
          <div className="runtime-settings-grid">
            <div className="form-row">
              <label htmlFor="quota-management-base-url">{t("mapping.quotaManagementBaseURL")}</label>
              <input
                id="quota-management-base-url"
                className="input mono"
                value={quotaManagementBaseURL}
                disabled={loading || saving || !settings}
                onChange={(event) => setQuotaManagementBaseURL(event.target.value)}
                placeholder={DEFAULT_QUOTA_MANAGEMENT_BASE_URL}
                spellCheck={false}
              />
            </div>
            <div className="form-row">
              <label htmlFor="quota-management-key">{t("mapping.quotaManagementKey")}</label>
              <input
                id="quota-management-key"
                className="input mono"
                type="password"
                autoComplete="new-password"
                value={quotaManagementKey}
                disabled={loading || saving || !settings}
                onChange={(event) => setQuotaManagementKey(event.target.value)}
                placeholder={t("mapping.quotaManagementKeyPlaceholder")}
                spellCheck={false}
              />
              <span className="muted quota-management-key-status">
                {quotaManagementKeyConfigured
                  ? t("mapping.quotaManagementKeyConfigured")
                  : t("mapping.quotaManagementKeyNotConfigured")}
              </span>
            </div>
          </div>
          <div className="quota-management-actions">
            <button
              className="btn sm"
              type="button"
              disabled={loading || saving || quotaManagementTesting || !settings || !quotaManagementKeyConfigured}
              onClick={() => void testManagementConnection()}
            >
              {quotaManagementTesting ? t("mapping.quotaManagementTesting") : t("mapping.quotaManagementTest")}
            </button>
            <button
              className="btn sm danger-outline"
              type="button"
              disabled={loading || saving || !settings || !quotaManagementKeyConfigured}
              onClick={() => void clearManagementKey()}
            >
              {t("mapping.quotaManagementClearKey")}
            </button>
          </div>
          {!quotaManagementKeyConfigured && <p className="muted quota-management-note">{t("mapping.quotaManagementTestNeedsKey")}</p>}
          {quotaManagementError && <div className="error quota-management-feedback">{quotaManagementError}</div>}
          {quotaManagementMessage && <div className="success quota-management-feedback">{quotaManagementMessage}</div>}
        </div>
        <p className="muted quota-warning">{t("mapping.quotaWarning")}</p>
        {quotaStatus?.persistence_blocked && <div className="error">{t("mapping.quotaPersistenceBlocked")}: {quotaStatus.persistence_error}</div>}
        {quotaStatus && (
          <div className="quota-auth-list">
            {quotaStatus.auths.length === 0 ? <p className="muted">{t("mapping.quotaNoAuths")}</p> : quotaStatus.auths.map((auth) => (
              <div className="quota-auth-card" key={auth.auth_id}>
                <div className="quota-auth-card-head">
                  <span className="mono quota-auth-id" title={auth.auth_id}>{auth.auth_id}</span>
                  <span className={`quota-state ${auth.availability}`}>{t(`mapping.quotaAvailability.${auth.availability}`)}</span>
                  <span className={`quota-freshness ${auth.freshness}`}>{t(`mapping.quotaFreshness.${auth.freshness}`)}</span>
                </div>
                <div className="quota-scope-grid">
                  <QuotaScopeFlag label={t("mapping.quotaObservable")} enabled={auth.observable} />
                  <QuotaScopeFlag label={t("mapping.quotaMaintenance")} enabled={auth.in_maintenance_scope} />
                  <QuotaScopeFlag label={t("mapping.quotaActivation")} enabled={auth.in_activation_scope} />
                </div>
                <div className="quota-window-grid">
                  <QuotaWindowSummary label={t("mapping.quotaShortWindow")} window={auth.observation?.short} />
                  <QuotaWindowSummary label={t("mapping.quotaLongWindow")} window={auth.observation?.long} />
                </div>
                <dl className="quota-auth-meta">
                  <QuotaMeta label={t("mapping.quotaSource")} value={auth.observation?.source} />
                  <QuotaMeta label={t("mapping.quotaObservedAt")} value={formatQuotaTime(auth.observation?.observed_at)} />
                  <QuotaMeta label={t("mapping.quotaNextCheckAt")} value={formatQuotaTime(auth.next_check_at)} />
                  <QuotaMeta label={t("mapping.quotaMaintenanceResult")} value={auth.last_result || auth.last_error || auth.exclusion_reason} />
                  <QuotaMeta label={t("mapping.quotaActivationResult")} value={formatQuotaActivationResult(auth.activation)} />
                  <QuotaMeta label={t("mapping.quotaControlledConcurrency")} value={`${auth.controlled_in_flight} / ${auth.activation_in_flight}`} />
                </dl>
              </div>
            ))}
          </div>
        )}
      </div>
      {settings && (settings.current_concurrent_requests !== undefined || settings.session_affinity_entries !== undefined) && (
        <div className="runtime-stats muted">
          {settings.current_concurrent_requests !== undefined && <span>{t("mapping.runtimeCurrent", { n: settings.current_concurrent_requests })}</span>}
          {settings.current_activation_requests !== undefined && <span>{t("mapping.runtimeActivationCurrent", { n: settings.current_activation_requests })}</span>}
          {settings.session_affinity_entries !== undefined && <span>{t("mapping.runtimeEntries", { n: settings.session_affinity_entries })}</span>}
        </div>
      )}
    </section>
  );
}

function QuotaScopeFlag({ label, enabled }: { label: string; enabled: boolean }) {
  const t = useT();
  return (
    <span className={`quota-scope-flag ${enabled ? "enabled" : "disabled"}`}>
      <strong>{label}</strong>
      <span>{enabled ? t("mapping.quotaYes") : t("mapping.quotaNo")}</span>
    </span>
  );
}

function QuotaWindowSummary({ label, window }: { label: string; window?: QuotaWindowStatus }) {
  const t = useT();
  const used = typeof window?.used_percent === "number" ? `${window.used_percent}%` : "—";
  return (
    <div className="quota-window-card">
      <strong>{label}</strong>
      <span>{window?.kind ? t(`mapping.quotaWindowKind.${window.kind}`) : "—"}</span>
      <span>{t("mapping.quotaUsedPercent")}: {used}</span>
      <span>{t("mapping.quotaResetAt")}: {formatQuotaTime(window?.reset_at)}</span>
    </div>
  );
}

function QuotaMeta({ label, value }: { label: string; value?: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value || "—"}</dd>
    </div>
  );
}

export function formatQuotaTime(value?: string): string {
  if (!value) return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.getUTCFullYear() <= 1) return "—";
  return parsed.toLocaleString();
}

export function formatQuotaActivationResult(activation?: QuotaAuthStatus["activation"]): string | undefined {
  if (!activation) return undefined;
  const status = activation.status?.trim();
  const detail = activation.last_error?.trim() || activation.last_result?.trim();
  if (status && detail && status !== detail) return `${status} · ${detail}`;
  return detail || status;
}

function AliasCard({ alias, onDelete, onEdit }: { alias: AliasMapping; onDelete: (n: string) => void; onEdit: (n: string) => void }) {
  const t = useT();
  const [refCount] = useState<number | null>(null);
  // refCount would come from a separate API call or be included in the list response.
  // For now, show "unreferenced" as placeholder.
  return (
    <div className="alias-card">
      <div className="alias-card-head">
        <span className="alias-card-name">{alias.alias}</span>
        <span className="alias-dispatch-badge">
          {alias.dispatch === "priority" ? t("mapping.alias.priority") : t("mapping.alias.roundRobin")}
        </span>
      </div>
      <div className="alias-targets">
        {alias.targets.slice(0, 3).map((tgt, i) => (
          <div key={i} className="alias-target-row">
            <span>{tgt.provider} · {tgt.target_model}</span>
            {tgt.group && <span className="alias-target-group">{tgt.group}</span>}
          </div>
        ))}
        {alias.targets.length > 3 && (
          <div className="alias-target-row" style={{ opacity: 0.6 }}>
            {t("mapping.moreTargets", { n: alias.targets.length - 3 })}
          </div>
        )}
      </div>
      <div className="alias-pricing">
        {alias.billing_mode === "per_call" ? (
          <>{t("mapping.alias.perCallUnit")} ${alias.per_call_usd ?? 0}/{t("mapping.alias.perCallUnit")}</>
        ) : (
          <>{t("mapping.alias.input")} ${alias.input_price_per_million ?? 0} / {t("mapping.alias.output")} ${alias.output_price_per_million ?? 0} / {t("mapping.alias.cache")} ${alias.cache_read_price_per_million ?? 0} {t("mapping.alias.perMillion")}</>
        )}
        {` · ${t("mapping.alias.multiplier")} ×${alias.billing_multiplier ?? 1}`}
      </div>
      <div className={"alias-refs" + (refCount === 0 ? " zero" : "")}>
        {refCount && refCount > 0 ? t("mapping.refs", { n: refCount }) : t("mapping.unreferenced")}
      </div>
      <div className="alias-actions">
        <button className="btn sm" onClick={() => onEdit(alias.alias)}>{t("mapping.edit")}</button>
        <button
          className="btn sm danger-outline"
          disabled={refCount !== null && refCount > 0}
          title={refCount && refCount > 0 ? t("mapping.deleteBlocked", { n: refCount }) : ""}
          onClick={() => onDelete(alias.alias)}
        >
          {t("mapping.delete")}
        </button>
      </div>
    </div>
  );
}

// --- Classify Tab ---

function ClassifyTab() {
  const t = useT();
  const nav = useNavigate();
  const [rules, setRules] = useState<ClassifyRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [previewData, setPreviewData] = useState<ClassifyPreviewResponse | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [list, descriptors] = await Promise.all([
        fetchClassifyRules(),
        fetchCredentialDescriptors().catch(() => [] as CredentialDescriptor[]),
      ]);
      setRules(list);
      // Evaluate the current rules against real credential descriptors so
      // each rule card shows the true match count + file list.
      const preview = await classifyPreview(descriptors).catch(() => null as ClassifyPreviewResponse | null);
      setPreviewData(preview);
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const handleReorder = async (names: string[]) => {
    try {
      await reorderClassifyRules(names);
      await load();
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const handleDelete = async (name: string) => {
    try {
      await deleteClassifyRule(name);
      await load();
    } catch (e: unknown) {
      setError(String(e));
    }
  };

  const moveRule = (idx: number, dir: -1 | 1) => {
    const newOrder = [...rules];
    const target = idx + dir;
    if (target < 0 || target >= newOrder.length) return;
    [newOrder[idx], newOrder[target]] = [newOrder[target], newOrder[idx]];
    void handleReorder(newOrder.map((r) => r.name));
  };

  return (
    <>
      <div className="map-toolbar">
        <button className="btn primary" onClick={() => nav("/mapping/rule/new")}>
          + {t("mapping.newRule")}
        </button>
      </div>
      {error && <div className="error">{error}</div>}
      {loading ? (
        <div className="muted" style={{ padding: 20 }}>Loading...</div>
      ) : (
        <div className="rule-list">
          {/* Built-in rules (read-only) */}
          <div className="rule-builtin-card">
            <h3>{t("mapping.rule.builtin")} ({t("mapping.rule.builtinReadOnly")})</h3>
            <div className="rule-builtin-row">
              <span className="info-icon">ⓘ</span>
              plan_type → {`<detected>`}
            </div>
            <div className="rule-builtin-row">
              <span className="info-icon">ⓘ</span>
              tier → {`<detected>`}
            </div>
            <div className="rule-builtin-desc">{t("mapping.rule.builtinDesc")}</div>
          </div>

          {/* Custom rules */}
          <div className="section-label" style={{ marginTop: 16 }}>{t("mapping.rule.custom")}</div>
          {rules.length === 0 ? (
            <div className="muted" style={{ padding: 20 }}>No custom rules</div>
          ) : (
            rules.map((rule, idx) => (
              <RuleCard
                key={rule.name}
                rule={rule}
                idx={idx}
                total={rules.length}
                onMoveUp={() => moveRule(idx, -1)}
                onMoveDown={() => moveRule(idx, 1)}
                onEdit={() => nav(`/mapping/rule/${encodeURIComponent(rule.name)}`)}
                onDelete={() => handleDelete(rule.name)}
                previewData={previewData}
              />
            ))
          )}
        </div>
      )}
    </>
  );
}

function RuleCard({
  rule, idx, total, onMoveUp, onMoveDown, onEdit, onDelete, previewData,
}: {
  rule: ClassifyRule;
  idx: number;
  total: number;
  onMoveUp: () => void;
  onMoveDown: () => void;
  onEdit: () => void;
  onDelete: () => void;
  previewData: ClassifyPreviewResponse | null;
}) {
  const t = useT();
  const [expanded, setExpanded] = useState(false);
  const [matchCount, setMatchCount] = useState<number | null>(null);
  const [matchedFiles, setMatchedFiles] = useState<string[]>([]);
  const [page, setPage] = useState(0);
  const pageSize = 50;

  // Compute the match count + matched file list up front from previewData
  // (fetched by ClassifyTab once the rules + descriptors load). The badge
  // shows the count even when collapsed, so this must not be gated on
  // `expanded`. Re-run whenever the preview or this rule's target group
  // changes; the matchedFiles list drives the expanded detail pagination.
  useEffect(() => {
    const files = previewData?.groups[rule.group.toLowerCase()] ?? [];
    setMatchCount(files.length);
    setMatchedFiles(files);
  }, [previewData, rule.group]);

  const pageCount = Math.ceil(matchedFiles.length / pageSize);
  const pageFiles = matchedFiles.slice(page * pageSize, (page + 1) * pageSize);

  return (
    <div className="rule-card">
      <div className="rule-card-head">
        <div className="rule-card-order">
          <button onClick={onMoveUp} disabled={idx === 0} title={t("mapping.rule.moveUp")}>↑</button>
          <button onClick={onMoveDown} disabled={idx === total - 1} title={t("mapping.rule.moveDown")}>↓</button>
        </div>
        <div className="rule-card-main" onClick={() => setExpanded(!expanded)} style={{ cursor: "pointer" }}>
          <div className="rule-card-name">{rule.name}</div>
          <div className="rule-card-sub">{rule.field}: {rule.pattern} → {rule.group}</div>
        </div>
        <div className="rule-card-right">
          <span className={"rule-match-badge" + (matchCount === 0 ? " zero" : "")}>
            {matchCount !== null
              ? (matchCount > 0 ? t("mapping.rule.matchCount", { n: matchCount }) : t("mapping.rule.matchCountZero"))
              : "..."}
          </span>
          <label className="switch" title={t("mapping.rule.enabled")}>
            <input type="checkbox" checked={rule.enabled} readOnly />
            <span className="track"><span className="thumb" /></span>
          </label>
          <button className="btn sm" onClick={onEdit}>{t("mapping.edit")}</button>
          <button className="btn sm danger-outline" onClick={onDelete}>{t("mapping.delete")}</button>
        </div>
      </div>
      {expanded && (
        <div className="rule-detail">
          <div className="rule-detail-files">
            {pageFiles.length === 0 ? (
              <div className="muted" style={{ padding: 8 }}>{t("mapping.rule.noFiles")}</div>
            ) : (
              pageFiles.map((f, i) => (
                <div key={i} className="rule-detail-file">
                  <span>{f}</span>
                </div>
              ))
            )}
          </div>
          {pageCount > 1 && (
            <div className="rule-pager">
              <button onClick={() => setPage(Math.max(0, page - 1))} disabled={page === 0}>
                {t("mapping.rule.prevPage")}
              </button>
              <span className="page-info">{t("mapping.rule.pageInfo", { cur: page + 1, total: pageCount })}</span>
              <button onClick={() => setPage(Math.min(pageCount - 1, page + 1))} disabled={page >= pageCount - 1}>
                {t("mapping.rule.nextPage")}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// --- Alias Edit Form ---

// Survives ModelPick remounts (and React Strict Mode) better than router
// state alone — without this, filling the alias name then picking targets
// wipes the name when AliasEditForm remounts empty.
const ALIAS_FORM_DRAFT_KEY = "cpa-key-policy:alias-form-draft";

function readAliasFormDraft(): AliasMapping | null {
  try {
    const raw = sessionStorage.getItem(ALIAS_FORM_DRAFT_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as AliasMapping;
  } catch {
    return null;
  }
}

function writeAliasFormDraft(draft: AliasMapping) {
  try {
    sessionStorage.setItem(ALIAS_FORM_DRAFT_KEY, JSON.stringify(draft));
  } catch {
    /* private mode / quota — router state is the fallback */
  }
}

function clearAliasFormDraft() {
  try {
    sessionStorage.removeItem(ALIAS_FORM_DRAFT_KEY);
  } catch {
    /* ignore */
  }
}

export function AliasEditForm() {
  const t = useT();
  const nav = useNavigate();
  const { aliasName } = useParams();
  const loc = useLocation();
  const isNew = aliasName === "new" || !aliasName;

  const locState = loc.state as { draftAlias?: AliasMapping; pickedTargets?: AliasTarget[] } | null;
  const returnDraft = locState?.draftAlias;
  const returnTargets = locState?.pickedTargets;

  const [alias, setAlias] = useState<AliasMapping>(() => {
    const draft = returnDraft ?? readAliasFormDraft();
    if (draft) {
      return {
        ...draft,
        targets: returnTargets ?? draft.targets ?? [],
      };
    }
    return {
      alias: isNew ? "" : decodeURIComponent(aliasName ?? ""),
      targets: [],
      dispatch: "round-robin",
      billing_mode: "tokens",
      input_price_per_million: 0,
      output_price_per_million: 0,
      cache_read_price_per_million: 0,
      per_call_usd: 0,
      billing_multiplier: 1,
    };
  });
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  // Keep session draft in sync while editing so a picker trip never loses fields.
  useEffect(() => {
    writeAliasFormDraft(alias);
  }, [alias]);

  // Load existing alias if editing — skip when this form already has a draft
  // for the same alias (picker return / in-progress edit).
  useEffect(() => {
    if (isNew) return;
    if (returnDraft) return;
    const name = decodeURIComponent(aliasName ?? "");
    const session = readAliasFormDraft();
    if (session && session.alias === name) return;
    void fetchAliases().then((list) => {
      const found = list.find((a) => a.alias === name);
      if (found) setAlias(found);
    }).catch((e: unknown) => setError(String(e)));
  }, [aliasName, isNew, returnDraft]);

  // Apply targets returned from ModelPick (draft fields come from session/router).
  useEffect(() => {
    if (!returnTargets) return;
    setAlias((prev) => {
      const base = returnDraft ?? prev;
      return { ...base, targets: returnTargets };
    });
  }, [returnTargets, returnDraft]);

  const leaveForm = (toMapping = true) => {
    clearAliasFormDraft();
    if (toMapping) nav("/mapping", { state: { mappingTab: "alias" } });
  };

  const handleSave = async () => {
    setError("");
    const multiplier = alias.billing_multiplier ?? 1;
    if (!Number.isFinite(multiplier) || multiplier <= 0) {
      setError(t("mapping.alias.multiplierInvalid"));
      return;
    }
    setSaving(true);
    try {
      await upsertAlias({ ...alias, billing_multiplier: multiplier });
      leaveForm(true);
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  };

  const addTarget = () => {
    // Persist draft before leaving so name/dispatch/pricing survive the picker.
    writeAliasFormDraft(alias);
    const here = `/mapping/alias/${isNew ? "new" : encodeURIComponent(alias.alias || aliasName || "new")}`;
    nav("/mapping/pick-target", {
      state: {
        returnTo: here,
        currentTargets: alias.targets,
        draftAlias: alias,
      },
    });
  };

  const removeTarget = (idx: number) => {
    setAlias((prev) => ({ ...prev, targets: prev.targets.filter((_, i) => i !== idx) }));
  };

  return (
    <div className="map-form-page">
      <div className="map-form-card">
        <div className="map-form-head">
          <a className="back-link" onClick={() => leaveForm(true)}>
            ← {t("mapping.back")}
          </a>
          <h1>{isNew ? t("mapping.alias.newTitle") : t("mapping.alias.editTitle")}</h1>
        </div>
        <div className="map-form-row">
          <label>{t("mapping.alias.name")}</label>
          <input
            className="mono"
            value={alias.alias}
            onChange={(e) => setAlias({ ...alias, alias: e.target.value })}
            disabled={!isNew}
            placeholder="my-alias"
          />
        </div>
        <div className="map-form-row">
          <label>{t("mapping.alias.dispatch")}</label>
          <div className="map-dispatch-seg" role="group" aria-label={t("mapping.alias.dispatch")}>
            <button
              type="button"
              className={"map-dispatch-btn" + (alias.dispatch === "round-robin" ? " active" : "")}
              onClick={() => setAlias({ ...alias, dispatch: "round-robin" })}
            >
              <span className="map-dispatch-title">{t("mapping.alias.roundRobin")}</span>
              <span className="map-dispatch-desc">{t("mapping.alias.roundRobinDesc")}</span>
            </button>
            <button
              type="button"
              className={"map-dispatch-btn" + (alias.dispatch === "priority" ? " active" : "")}
              onClick={() => setAlias({ ...alias, dispatch: "priority" })}
            >
              <span className="map-dispatch-title">{t("mapping.alias.priority")}</span>
              <span className="map-dispatch-desc">{t("mapping.alias.priorityDesc")}</span>
            </button>
          </div>
        </div>
        <div className="map-form-row">
          <label>{t("mapping.alias.targets")}</label>
          <div className="map-form-targets">
            {alias.targets.map((tgt, i) => (
              <div key={i} className="map-form-target-row">
                <span className="mono">{tgt.provider} · {tgt.target_model} {tgt.group ? `· ${tgt.group}` : ""}</span>
                <button className="remove-btn" onClick={() => removeTarget(i)}>×</button>
              </div>
            ))}
          </div>
          <button className="btn" onClick={addTarget}>+ {t("mapping.alias.addTarget")}</button>
        </div>
        <div className="map-form-row">
          <label>{t("mapping.alias.billing")}</label>
          <label className="switch" style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <input
              type="checkbox"
              checked={alias.billing_mode === "per_call"}
              onChange={(e) => setAlias({ ...alias, billing_mode: e.target.checked ? "per_call" : "tokens" })}
            />
            <span className="track"><span className="thumb" /></span>
            <span>{alias.billing_mode === "per_call" ? t("mapping.alias.perCall") : t("mapping.alias.tokens")}</span>
          </label>
        </div>
        <div className="map-form-row">
          <label title={t("mapping.alias.multiplierHint")}>{t("mapping.alias.multiplier")}</label>
          <input
            className="mono"
            type="number"
            step="any"
            value={alias.billing_multiplier ?? 1}
            onChange={(e) => setAlias({ ...alias, billing_multiplier: parseFloat(e.target.value) || 0 })}
          />
          <span className="muted">{t("mapping.alias.multiplierHint")}</span>
        </div>
        {alias.billing_mode === "tokens" ? (
          <>
            <div className="map-form-row">
              <label>{t("mapping.alias.input")} ($/1M)</label>
              <input
                className="mono"
                type="number"
                step="any"
                value={alias.input_price_per_million ?? 0}
                onChange={(e) => setAlias({ ...alias, input_price_per_million: parseFloat(e.target.value) || 0 })}
              />
            </div>
            <div className="map-form-row">
              <label>{t("mapping.alias.output")} ($/1M)</label>
              <input
                className="mono"
                type="number"
                step="any"
                value={alias.output_price_per_million ?? 0}
                onChange={(e) => setAlias({ ...alias, output_price_per_million: parseFloat(e.target.value) || 0 })}
              />
            </div>
            <div className="map-form-row">
              <label>{t("mapping.alias.cache")} ($/1M)</label>
              <input
                className="mono"
                type="number"
                step="any"
                value={alias.cache_read_price_per_million ?? 0}
                onChange={(e) => setAlias({ ...alias, cache_read_price_per_million: parseFloat(e.target.value) || 0 })}
              />
            </div>
          </>
        ) : (
          <div className="map-form-row">
            <label>{t("mapping.alias.perCallUnit")} ($/{t("mapping.alias.perCallUnit")})</label>
            <input
              className="mono"
              type="number"
              step="any"
              value={alias.per_call_usd ?? 0}
              onChange={(e) => setAlias({ ...alias, per_call_usd: parseFloat(e.target.value) || 0 })}
            />
          </div>
        )}
        <p className="muted">{t("mapping.alias.pricingSettlementHint")}</p>
        {error && <div className="error">{error}</div>}
        <div className="map-form-foot">
          <button className="btn primary" onClick={handleSave} disabled={saving}>
            {saving ? "..." : t("mapping.save")}
          </button>
          <button className="btn" onClick={() => leaveForm(true)}>
            {t("mapping.cancel")}
          </button>
        </div>
      </div>
    </div>
  );
}

// --- Rule Edit Form ---

export function RuleEditForm() {
  const t = useT();
  const nav = useNavigate();
  const { ruleName } = useParams();
  const isNew = ruleName === "new" || !ruleName;

  const [rule, setRule] = useState<ClassifyRule>({
    name: isNew ? "" : decodeURIComponent(ruleName),
    field: "plan_type",
    pattern: "",
    group: "",
    enabled: true,
  });
  const [customField, setCustomField] = useState("");
  const [regexError, setRegexError] = useState("");
  const [regexValid, setRegexValid] = useState(false);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  // Load existing rule if editing.
  useEffect(() => {
    if (isNew) return;
    void fetchClassifyRules().then((list) => {
      const found = list.find((r) => r.name === decodeURIComponent(ruleName));
      if (found) {
        setRule(found);
        if (["filename", "provider", "plan_type", "tier"].includes(found.field)) {
          setCustomField("");
        } else {
          setCustomField(found.field);
          setRule((prev) => ({ ...prev, field: "custom" }));
        }
      }
    }).catch((e: unknown) => setError(String(e)));
  }, [ruleName, isNew]);

  // Live regex validation.
  useEffect(() => {
    if (!rule.pattern) {
      setRegexError("");
      setRegexValid(false);
      return;
    }
    try {
      new RegExp(rule.pattern);
      setRegexError("");
      setRegexValid(true);
    } catch (e: unknown) {
      setRegexError(String(e).replace(/^Error: /, ""));
      setRegexValid(false);
    }
  }, [rule.pattern]);

  const effectiveField = rule.field === "custom" ? customField : rule.field;

  const handleSave = async () => {
    if (!regexValid) {
      setError(t("mapping.rule.regexInvalid", { err: regexError }));
      return;
    }
    setSaving(true);
    setError("");
    try {
      await upsertClassifyRule({ ...rule, field: effectiveField });
      nav("/mapping", { state: { mappingTab: "classify" } });
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="map-form-page">
      <div className="map-form-card">
        <div className="map-form-head">
          <a className="back-link" onClick={() => nav("/mapping", { state: { mappingTab: "classify" } })}>
            ← {t("mapping.back")}
          </a>
          <h1>{isNew ? t("mapping.rule.newTitle") : t("mapping.rule.editTitle")}</h1>
        </div>
        <div className="map-form-row">
          <label>{t("mapping.rule.name")}</label>
          <input
            value={rule.name}
            onChange={(e) => setRule({ ...rule, name: e.target.value })}
            disabled={!isNew}
            placeholder="my-rule"
          />
        </div>
        <div className="map-form-row">
          <label>{t("mapping.rule.field")}</label>
          <select
            value={rule.field}
            onChange={(e) => setRule({ ...rule, field: e.target.value })}
          >
            <option value="filename">{t("mapping.rule.fieldFilename")}</option>
            <option value="provider">{t("mapping.rule.fieldProvider")}</option>
            <option value="plan_type">{t("mapping.rule.fieldPlanType")}</option>
            <option value="tier">{t("mapping.rule.fieldTier")}</option>
            <option value="custom">{t("mapping.rule.fieldCustom")}</option>
          </select>
        </div>
        {rule.field === "custom" && (
          <div className="map-form-row">
            <label>{t("mapping.rule.customField")}</label>
            <input
              className="mono"
              value={customField}
              onChange={(e) => setCustomField(e.target.value)}
              placeholder="custom_attribute_name"
            />
          </div>
        )}
        <div className="map-form-row">
          <label>{t("mapping.rule.regex")}</label>
          <input
            className="mono"
            value={rule.pattern}
            onChange={(e) => setRule({ ...rule, pattern: e.target.value })}
            placeholder="^team$"
          />
          {regexValid && <div className="regex-valid">✓ {t("mapping.rule.regexValid")}</div>}
          {regexError && <div className="regex-invalid">{t("mapping.rule.regexInvalid", { err: regexError })}</div>}
        </div>
        <div className="map-form-row">
          <label>{t("mapping.rule.group")}</label>
          <input
            className="mono"
            value={rule.group}
            onChange={(e) => setRule({ ...rule, group: e.target.value })}
            placeholder="team"
          />
        </div>
        <div className="map-form-row">
          <label className="switch" style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <input
              type="checkbox"
              checked={rule.enabled}
              onChange={(e) => setRule({ ...rule, enabled: e.target.checked })}
            />
            <span className="track"><span className="thumb" /></span>
            <span>{t("mapping.rule.enabled")}</span>
          </label>
        </div>
        {error && <div className="error">{error}</div>}
        <div className="map-form-foot">
          <button className="btn primary" onClick={handleSave} disabled={saving || !regexValid}>
            {saving ? "..." : t("mapping.save")}
          </button>
          <button className="btn" onClick={() => nav("/mapping", { state: { mappingTab: "classify" } })}>
            {t("mapping.cancel")}
          </button>
        </div>
      </div>
    </div>
  );
}

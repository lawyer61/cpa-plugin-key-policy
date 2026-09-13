import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams, useLocation } from "react-router-dom";
import { fetchCatalog, formatTierLabel, groupByCatalog } from "../api/models";
import type { CatalogGroup } from "../api/models";
import type { ModelRule, AliasTarget, KeyPublic } from "../types";
import { useT } from "../i18n";

// Selection key: "provider|group|model" (all lowercased for dedupe matching).
function keyOf(g: CatalogGroup, model: string): string {
  return g.provider + "|" + (g.group ?? "").toLowerCase() + "|" + model.toLowerCase();
}

function keyOfRule(rule: ModelRule): string {
  return rule.provider.toLowerCase() + "|" + (rule.group ?? "").toLowerCase() + "|" + rule.target_model.toLowerCase();
}

export default function ModelPick() {
  const { id } = useParams<{ id?: string }>();
  const nav = useNavigate();
  const loc = useLocation();
  const t = useT();
  const [groups, setGroups] = useState<CatalogGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>("");
  const [query, setQuery] = useState("");

  // Initial selection comes from router state (passed by KeyForm when it
  // navigates here). Edit-mode keys pass their current models in too.
  const st = loc.state as {
    models?: ModelRule[];
    currentTargets?: AliasTarget[];
    returnTo?: string;
    /** Full alias form draft — forwarded back so name/dispatch/prices survive. */
    draftAlias?: unknown;
    /** Full key form draft — forwarded back so unsaved fields and prices survive. */
    keyDraft?: KeyPublic;
  } | null;
  // Context-aware: if a `returnTo` route is supplied (e.g. from the alias
  // editor), we are picking targets for a global alias, not models for a key.
  const aliasMode = !!st?.returnTo;
  const initialModels = st?.models ?? [];
  const initialTargets = st?.currentTargets ?? [];
  const backTo = aliasMode
    ? st!.returnTo!
    : (id ? `/keys/${encodeURIComponent(id)}/edit` : "/keys/new");
  const draftAlias = st?.draftAlias;
  const keyDraft = st?.keyDraft;
  const initialByKey = useMemo(() => {
    const byKey = new Map<string, ModelRule>();
    for (const rule of initialModels) byKey.set(keyOfRule(rule), rule);
    return byKey;
  }, [initialModels]);

  const [selected, setSelected] = useState<Set<string>>(() => {
    const s = new Set<string>();
    for (const r of initialModels) {
      const g = (r.group ?? "").toLowerCase();
      s.add(r.provider.toLowerCase() + "|" + g + "|" + r.target_model.toLowerCase());
    }
    for (const tg of initialTargets) {
      const g = (tg.group ?? "").toLowerCase();
      s.add(tg.provider.toLowerCase() + "|" + g + "|" + tg.target_model.toLowerCase());
    }
    return s;
  });

  useEffect(() => {
    let alive = true;
    (async () => {
      setLoading(true);
      setError("");
      try {
        const selectedProviders = new Set<string>();
        for (const r of initialModels) selectedProviders.add(r.provider.toLowerCase());
        for (const r of initialTargets) selectedProviders.add(r.provider.toLowerCase());
        const cat = await fetchCatalog(selectedProviders);
        if (!alive) return;
        setGroups(groupByCatalog(cat));
      } catch (e) {
        if (!alive) return;
        setError((e as Error).message || t("picker.loadFailed"));
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Build the ModelRule[] for the current selection. Includes stale entries
  // the catalog no longer covers (legacy edit-mode rows), so upgrading never
  // drops a model from an existing key.
  const rules: ModelRule[] = useMemo(() => {
    const covered = new Set<string>();
    const out: ModelRule[] = [];
    for (const g of groups) {
      for (const m of g.models) {
        const k = keyOf(g, m);
        covered.add(k);
        if (selected.has(k)) {
          const prior = initialByKey.get(k);
          const rule: ModelRule = prior
            ? { ...prior, provider: g.provider, target_model: m }
            : { alias: m, provider: g.provider, target_model: m };
          if (g.group) rule.group = g.group;
          else delete rule.group;
          out.push(rule);
        }
      }
    }
    for (const k of selected) {
      if (covered.has(k)) continue;
      const prior = initialByKey.get(k);
      if (prior) {
        out.push({ ...prior });
        continue;
      }
      const [provider, group, ...rest] = k.split("|");
      const model = rest.join("|");
      if (!provider || !model) continue;
      const rule: ModelRule = { alias: model, provider, target_model: model };
      if (group) rule.group = group;
      out.push(rule);
    }
    return out;
  }, [selected, groups, initialByKey]);

  const filtered = useMemo(() => {
    if (!query.trim()) return groups;
    const q = query.trim().toLowerCase();
    return groups
      .map((g) => ({
        provider: g.provider,
        group: g.group,
        models: g.models.filter(
          (m) => m.toLowerCase().includes(q) || g.provider.includes(q) || (g.group ?? "").includes(q),
        ),
      }))
      .filter((g) => g.models.length > 0);
  }, [groups, query]);

  const toggle = (g: CatalogGroup, model: string) => {
    const k = keyOf(g, model);
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k); else next.add(k);
      return next;
    });
  };
  const selectAll = (g: CatalogGroup) => {
    setSelected((prev) => {
      const next = new Set(prev);
      for (const m of g.models) next.add(keyOf(g, m));
      return next;
    });
  };
  const clearAll = (g: CatalogGroup) => {
    setSelected((prev) => {
      const next = new Set(prev);
      for (const m of g.models) next.delete(keyOf(g, m));
      return next;
    });
  };

  const finish = () => {
    if (aliasMode) {
      const targets: AliasTarget[] = rules.map((r) => {
        const t: AliasTarget = { provider: r.provider, target_model: r.target_model };
        if (r.group) t.group = r.group;
        return t;
      });
      nav(backTo, { state: { pickedTargets: targets, draftAlias } });
    } else {
      nav(backTo, {
        state: {
          pickedModels: rules,
          ...(keyDraft ? { keyDraft: { ...keyDraft, models: rules } } : {}),
        },
      });
    }
  };

  const goBack = () => {
    // Preserve in-progress alias form fields even when canceling the picker.
    if (aliasMode) {
      nav(backTo, {
        state: {
          draftAlias,
          // Keep previous targets if user backs out without confirming.
          pickedTargets: initialTargets,
        },
      });
      return;
    }
    if (keyDraft) {
      nav(backTo, { state: { pickedModels: initialModels, keyDraft } });
      return;
    }
    nav(backTo);
  };

  return (
    <div className="model-pick-page">
      <div className="mp-head">
        <button type="button" className="btn sm" onClick={goBack}>{t("keyUsage.back")}</button>
        <h1>{t("picker.title")}</h1>
        <button className="btn primary sm" onClick={finish} disabled={loading}>
          {t("picker.done", { count: selected.size })}
        </button>
      </div>
      <div className="mp-sub">{t("picker.selected", { count: selected.size })}</div>
      <div className="mp-search">
        <span className="mp-icon">⌕</span>
        <input
          className="input"
          placeholder={t("picker.searchPlaceholder")}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>
      <div className="card mp-list">
        {loading ? (
          <div className="muted">{t("picker.loading")}</div>
        ) : error ? (
          <div className="error">{error}</div>
        ) : groups.length === 0 ? (
          <div className="muted">{t("picker.empty")}</div>
        ) : filtered.length === 0 ? (
          <div className="muted">{t("picker.noMatch")}</div>
        ) : (
          filtered.map((g) => {
            const groupLabel = g.group ? formatTierLabel(t, g.group) : "";
            const head = g.provider + (groupLabel ? " · " + groupLabel : "");
            const allSelected = g.models.every((m) => selected.has(keyOf(g, m)));
            return (
              <div className="picker-group" key={head}>
                <div className="pg-head">
                  <span>{head}</span>
                  <span className="pg-actions">
                    <button type="button" className="btn sm" onClick={() => (allSelected ? clearAll(g) : selectAll(g))}>
                      {allSelected ? t("picker.clearAll") : t("picker.selectAll")}
                    </button>
                  </span>
                </div>
                <div className="pg-models">
                  {g.models.map((m) => {
                    const k = keyOf(g, m);
                    const active = selected.has(k);
                    return (
                      <label key={k} className={active ? "active" : ""}>
                        <input type="checkbox" checked={active} onChange={() => toggle(g, m)} />
                        {m}
                      </label>
                    );
                  })}
                </div>
              </div>
            );
          })
        )}
      </div>
      <div className="mp-footer">
        <span className="mp-count">{t("picker.selected", { count: selected.size })}</span>
        <div className="mp-btns">
          <button type="button" className="btn sm" onClick={goBack}>{t("keyForm.cancel")}</button>
          <button className="btn primary sm" onClick={finish} disabled={loading}>
            {t("picker.done", { count: selected.size })}
          </button>
        </div>
      </div>
    </div>
  );
}

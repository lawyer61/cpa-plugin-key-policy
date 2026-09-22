import { apiClient, pluginPath } from "./client";
import type {
  AliasMapping,
  ClassifyRule,
  CredentialDescriptor,
  ClassifyPreviewResponse,
  SchedulerSettings,
  SchedulerSettingsPatch,
  QuotaStatus,
} from "../types";
import { readPlanType } from "./models";

// --- Alias mapping CRUD ---

export async function fetchAliases(): Promise<AliasMapping[]> {
  const c = apiClient();
  const { data } = await c.get<{ aliases: AliasMapping[] }>(pluginPath("/aliases"));
  return data.aliases ?? [];
}

export async function upsertAlias(alias: AliasMapping): Promise<AliasMapping> {
  const c = apiClient();
  const { data } = await c.post<{ alias: AliasMapping }>(pluginPath("/aliases"), alias);
  return data.alias;
}

export async function deleteAlias(aliasName: string): Promise<void> {
  const c = apiClient();
  await c.delete(pluginPath("/aliases"), { data: { alias: aliasName } });
}

export async function fetchSchedulerSettings(): Promise<SchedulerSettings> {
  const c = apiClient();
  const { data } = await c.get<SchedulerSettings>(pluginPath("/settings"));
  return data;
}

export async function updateSchedulerSettings(
  patch: boolean | SchedulerSettingsPatch,
): Promise<SchedulerSettings> {
  const c = apiClient();
  const body: SchedulerSettingsPatch = typeof patch === "boolean"
    ? { global_weighted_round_robin: patch }
    : patch;
  const { data } = await c.patch<SchedulerSettings>(pluginPath("/settings"), body);
  return data;
}

export async function testQuotaManagementConnection(): Promise<{ ok: true }> {
  const c = apiClient();
  const { data } = await c.post<{ ok: true }>(pluginPath("/quota-management/test"));
  return data;
}

export async function fetchQuotaStatus(): Promise<QuotaStatus> {
  const c = apiClient();
  const { data } = await c.get<QuotaStatus>(pluginPath("/quota-status"));
  return data;
}

// --- Classification rule CRUD ---

export async function fetchClassifyRules(): Promise<ClassifyRule[]> {
  const c = apiClient();
  const { data } = await c.get<{ rules: ClassifyRule[] }>(pluginPath("/classify-rules"));
  return data.rules ?? [];
}

export async function upsertClassifyRule(rule: ClassifyRule): Promise<ClassifyRule> {
  const c = apiClient();
  const { data } = await c.post<{ rule: ClassifyRule }>(pluginPath("/classify-rules"), rule);
  return data.rule;
}

export async function deleteClassifyRule(name: string): Promise<void> {
  const c = apiClient();
  await c.delete(pluginPath("/classify-rules"), { data: { name } });
}

export async function reorderClassifyRules(names: string[]): Promise<void> {
  const c = apiClient();
  await c.post(pluginPath("/classify-rules/reorder"), { names });
}

// --- Classify preview ---

export async function classifyPreview(
  descriptors: CredentialDescriptor[],
  rules?: ClassifyRule[],
): Promise<ClassifyPreviewResponse> {
  const c = apiClient();
  const body: Record<string, unknown> = { descriptors };
  if (rules && rules.length > 0) body.rules = rules;
  const { data } = await c.post<ClassifyPreviewResponse>(pluginPath("/classify-preview"), body);
  return data;
}

// fetchCredentialDescriptors pulls the auth-file list from CPA and builds
// CredentialDescriptor[] for the classify-preview endpoint. Each descriptor
// carries id (filename), provider, and attributes (plan_type, tier) so both
// built-in and custom regex rules can match against real credential metadata.
// Reuses readPlanType (shared with the model catalog) so plan_type/tier
// extraction stays consistent with the Scheduler's built-in detection.
export async function fetchCredentialDescriptors(): Promise<CredentialDescriptor[]> {
  const c = apiClient();
  const { data } = await c.get<unknown>("/v0/management/auth-files");
  const root = data as Record<string, unknown> | null;
  const list = root?.["files"] ?? root?.["auth-files"];
  if (!Array.isArray(list)) return [];
  const out: CredentialDescriptor[] = [];
  for (const item of list) {
    const o = (item ?? {}) as Record<string, unknown>;
    const id = ((o["id"] as string) ?? (o["name"] as string) ?? "").trim();
    if (!id) continue;
    const provider = ((o["provider"] as string) ?? (o["type"] as string) ?? "").trim().toLowerCase();
    const attrs: Record<string, string> = {};
    const planType = readPlanType(o);
    if (planType) attrs["plan_type"] = planType;
    const tier = (o["tier"] as string) ?? "";
    if (typeof tier === "string" && tier.trim()) attrs["tier"] = tier.trim().toLowerCase();
    out.push({ id, provider, attributes: attrs });
  }
  return out;
}

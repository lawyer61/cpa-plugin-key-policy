import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "./client";
import {
  fetchQuotaStatus,
  fetchSchedulerSettings,
  testQuotaManagementConnection,
  updateSchedulerSettings,
} from "./mappings";

vi.mock("./client", () => ({
  apiClient: vi.fn(),
  pluginPath: (suffix: string) => "/v0/management/plugins/cpa-key-policy" + suffix,
}));

describe("调度设置接口", () => {
  const get = vi.fn();
  const patch = vi.fn();
  const post = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient).mockReturnValue({ get, patch, post } as never);
  });

  it("从插件设置接口读取全局加权开关", async () => {
    get.mockResolvedValue({ data: { global_weighted_round_robin: true } });

    await expect(fetchSchedulerSettings()).resolves.toEqual({
      global_weighted_round_robin: true,
    });
    expect(get).toHaveBeenCalledWith(
      "/v0/management/plugins/cpa-key-policy/settings",
    );
  });

  it("通过 PATCH 保存全局加权开关", async () => {
    patch.mockResolvedValue({ data: { global_weighted_round_robin: false } });

    await expect(updateSchedulerSettings(false)).resolves.toEqual({
      global_weighted_round_robin: false,
    });
    expect(patch).toHaveBeenCalledWith(
      "/v0/management/plugins/cpa-key-policy/settings",
      { global_weighted_round_robin: false },
    );
  });

  it("通过 PATCH 保存运行时并发设置", async () => {
    const settings = {
      global_weighted_round_robin: true,
      auth_concurrency_limits: { "codex-team.json": 2 },
      session_affinity_idle_ttl_seconds: 900,
      session_affinity_max_entries: 128,
    };
    patch.mockResolvedValue({ data: settings });

    await expect(updateSchedulerSettings({
      auth_concurrency_limits: settings.auth_concurrency_limits,
      session_affinity_idle_ttl_seconds: settings.session_affinity_idle_ttl_seconds,
      session_affinity_max_entries: settings.session_affinity_max_entries,
    })).resolves.toEqual(settings);
    expect(patch).toHaveBeenCalledWith(
      "/v0/management/plugins/cpa-key-policy/settings",
      {
        auth_concurrency_limits: { "codex-team.json": 2 },
        session_affinity_idle_ttl_seconds: 900,
        session_affinity_max_entries: 128,
      },
    );
  });

  it("保存额度检查与激活设置", async () => {
    const quota = {
      quota_check_interval: "17m",
      quota_cache_ttl: "43m",
      quota_activation_enabled: true,
      quota_activation_scope: "all-codex" as const,
      quota_activation_model: "custom-activation-model",
    };
    patch.mockResolvedValue({ data: quota });
    await expect(updateSchedulerSettings(quota)).resolves.toEqual(quota);
    expect(patch).toHaveBeenCalledWith(
      "/v0/management/plugins/cpa-key-policy/settings",
      quota,
    );
  });

  it("普通设置 PATCH 不携带空的管理密钥字段", async () => {
    const settings = {
      quota_management_enabled: false,
      quota_management_activation_enabled: false,
      quota_management_base_url: "http://127.0.0.1:8317",
    };
    patch.mockResolvedValue({ data: settings });
    await expect(updateSchedulerSettings(settings)).resolves.toEqual(settings);
    expect(patch).toHaveBeenCalledWith(
      "/v0/management/plugins/cpa-key-policy/settings",
      settings,
    );
    expect((patch.mock.calls[0][1] as Record<string, unknown>).quota_management_key).toBeUndefined();
  });

  it("显式清除管理密钥时保留空字符串", async () => {
    const patchBody = {
      quota_management_enabled: false,
      quota_management_key: "",
    };
    patch.mockResolvedValue({ data: patchBody });
    await expect(updateSchedulerSettings(patchBody)).resolves.toEqual(patchBody);
    expect(patch).toHaveBeenCalledWith(
      "/v0/management/plugins/cpa-key-policy/settings",
      patchBody,
    );
  });

  it("调用管理桥接连接测试接口", async () => {
    post.mockResolvedValue({ data: { ok: true } });
    await expect(testQuotaManagementConnection()).resolves.toEqual({ ok: true });
    expect(post).toHaveBeenCalledWith(
      "/v0/management/plugins/cpa-key-policy/quota-management/test",
    );
  });

  it("读取额度维护状态", async () => {
    const quota = { auths: [], observed_auth_count: 0 };
    get.mockResolvedValue({ data: quota });
    await expect(fetchQuotaStatus()).resolves.toEqual(quota);
    expect(get).toHaveBeenCalledWith(
      "/v0/management/plugins/cpa-key-policy/quota-status",
    );
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "./client";
import { fetchSchedulerSettings, updateSchedulerSettings } from "./mappings";

vi.mock("./client", () => ({
  apiClient: vi.fn(),
  pluginPath: (suffix: string) => "/v0/management/plugins/cpa-key-policy" + suffix,
}));

describe("调度设置接口", () => {
  const get = vi.fn();
  const patch = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient).mockReturnValue({ get, patch } as never);
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
});

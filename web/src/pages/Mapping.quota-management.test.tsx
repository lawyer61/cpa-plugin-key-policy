import { act } from "react";
import { createRoot } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Mapping from "./Mapping";
import {
  fetchAliases,
  fetchCredentialDescriptors,
  fetchQuotaStatus,
  fetchSchedulerSettings,
  testQuotaManagementConnection,
  updateSchedulerSettings,
} from "../api/mappings";
import type { SchedulerSettings } from "../types";

vi.mock("../api/mappings", async () => {
  const actual = await vi.importActual<typeof import("../api/mappings")>("../api/mappings");
  return {
    ...actual,
    fetchAliases: vi.fn(),
    fetchCredentialDescriptors: vi.fn(),
    fetchQuotaStatus: vi.fn(),
    fetchSchedulerSettings: vi.fn(),
    testQuotaManagementConnection: vi.fn(),
    updateSchedulerSettings: vi.fn(),
  };
});

const baseSettings = (overrides: Partial<SchedulerSettings> = {}): SchedulerSettings => ({
  global_weighted_round_robin: false,
  auth_concurrency_limits: {},
  session_affinity_idle_ttl_seconds: 3600,
  session_affinity_max_entries: 10000,
  quota_check_interval: "30m",
  quota_cache_ttl: "30m",
  quota_activation_enabled: false,
  quota_activation_scope: "managed-pools",
  quota_activation_model: "gpt-5.6-luna",
  quota_management_enabled: false,
  quota_management_activation_enabled: false,
  quota_management_base_url: "http://127.0.0.1:8317",
  quota_management_key_configured: false,
  quota_management_state: "disabled",
  ...overrides,
});

describe("账号代理维护设置", () => {
  let root: ReturnType<typeof createRoot> | null = null;
  let host: HTMLDivElement | null = null;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(fetchAliases).mockResolvedValue([]);
    vi.mocked(fetchCredentialDescriptors).mockResolvedValue([]);
    vi.mocked(fetchQuotaStatus).mockResolvedValue({
      quota_check_interval: "30m",
      quota_cache_ttl: "30m",
      quota_activation_enabled: false,
      quota_activation_scope: "managed-pools",
      quota_activation_model: "gpt-5.6-luna",
      persistence_blocked: false,
      observed_auth_count: 0,
      controlled_activation_current: 0,
      auths: [],
    });
  });

  afterEach(() => {
    root?.unmount();
    root = null;
    host?.remove();
    host = null;
  });

  async function renderMapping(settings: SchedulerSettings) {
    vi.mocked(fetchSchedulerSettings).mockResolvedValue(settings);
    host = document.createElement("div");
    document.body.appendChild(host);
    root = createRoot(host);
    await act(async () => {
      root?.render(
        <MemoryRouter initialEntries={["/mapping"]}>
          <Mapping />
        </MemoryRouter>,
      );
    });
    await act(async () => {});
  }

  function setInput(id: string, value: string) {
    const input = host?.querySelector<HTMLInputElement>("#" + id);
    if (!input) throw new Error("missing input #" + id);
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    setter?.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }

  function button(label: string): HTMLButtonElement {
    const found = Array.from(host?.querySelectorAll("button") ?? []).find((item) => item.textContent?.trim() === label);
    if (!found) throw new Error("missing button " + label);
    return found as HTMLButtonElement;
  }

  it("回填状态但密码框不回填；总开关关闭时保留并禁用激活开关", async () => {
    await renderMapping(baseSettings({
      quota_management_activation_enabled: true,
      quota_management_key_configured: true,
      quota_management_state: "ready",
    }));

    const activation = host?.querySelector<HTMLInputElement>("#quota-management-activation-enabled");
    const key = host?.querySelector<HTMLInputElement>("#quota-management-key");
    expect(activation?.checked).toBe(true);
    expect(activation?.disabled).toBe(true);
    expect(key?.value).toBe("");
    expect(host?.textContent).toContain("已配置");
    expect(host?.textContent).toContain("就绪");
  });

  it("修改基址但未输入新密钥时阻止普通保存", async () => {
    await renderMapping(baseSettings());
    setInput("quota-management-base-url", "http://127.0.0.1:9900");

    await act(async () => {
      button("保存运行时设置").click();
    });

    expect(updateSchedulerSettings).not.toHaveBeenCalled();
    expect(host?.textContent).toContain("修改管理接口基址时必须同时输入新的维护管理密钥。");
  });

  it("普通保存不发送空管理密钥，并同时带上桥接字段", async () => {
    const settings = baseSettings();
    vi.mocked(updateSchedulerSettings).mockResolvedValue(settings);
    await renderMapping(settings);

    await act(async () => {
      button("保存运行时设置").click();
    });

    expect(updateSchedulerSettings).toHaveBeenCalledTimes(1);
    const patch = vi.mocked(updateSchedulerSettings).mock.calls[0][0] as Record<string, unknown>;
    expect(patch.quota_management_enabled).toBe(false);
    expect(patch.quota_management_activation_enabled).toBe(false);
    expect(patch.quota_management_base_url).toBe("http://127.0.0.1:8317");
    expect(patch).not.toHaveProperty("quota_management_key");
  });

  it("清除密钥使用显式空字符串，关闭主开关但保留激活值", async () => {
    const settings = baseSettings({
      quota_management_enabled: true,
      quota_management_activation_enabled: true,
      quota_management_key_configured: true,
      quota_management_state: "ready",
    });
    const cleared = baseSettings({
      quota_management_enabled: false,
      quota_management_activation_enabled: true,
      quota_management_key_configured: false,
      quota_management_state: "disabled",
    });
    vi.mocked(updateSchedulerSettings).mockResolvedValue(cleared);
    await renderMapping(settings);

    await act(async () => {
      button("清除密钥").click();
    });

    expect(updateSchedulerSettings).toHaveBeenCalledWith({
      quota_management_enabled: false,
      quota_management_key: "",
    });
    expect(host?.querySelector<HTMLInputElement>("#quota-management-enabled")?.checked).toBe(false);
    expect(host?.querySelector<HTMLInputElement>("#quota-management-activation-enabled")?.checked).toBe(true);
    expect(host?.querySelector<HTMLInputElement>("#quota-management-key")?.value).toBe("");
  });

  it("测试连接不自动保存，并在响应后刷新设置状态", async () => {
    const settings = baseSettings({
      quota_management_enabled: true,
      quota_management_key_configured: true,
      quota_management_state: "ready",
    });
    vi.mocked(testQuotaManagementConnection).mockResolvedValue({ ok: true });
    vi.mocked(fetchSchedulerSettings).mockResolvedValue(settings);
    await renderMapping(settings);

    await act(async () => {
      button("测试连接").click();
    });

    expect(testQuotaManagementConnection).toHaveBeenCalledTimes(1);
    expect(updateSchedulerSettings).not.toHaveBeenCalled();
    expect(host?.querySelector<HTMLInputElement>("#quota-management-key")?.value).toBe("");
  });
});

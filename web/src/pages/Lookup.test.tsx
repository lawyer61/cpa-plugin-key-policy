import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import Lookup from "./Lookup";
import { fetchLookupData, fetchLookupQuota } from "../api/lookup";

vi.mock("../api/lookup", async () => {
  const actual = await vi.importActual<typeof import("../api/lookup")>("../api/lookup");
  return { ...actual, fetchLookupData: vi.fn(), fetchLookupQuota: vi.fn() };
});

describe("public lookup page", () => {
  let root: ReturnType<typeof createRoot> | null = null;
  let host: HTMLDivElement | null = null;

  afterEach(() => {
    root?.unmount();
    root = null;
    host?.remove();
    host = null;
		vi.clearAllMocks();
  });

  it("does not read or write browser storage", async () => {
    const getItem = vi.spyOn(Storage.prototype, "getItem");
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const removeItem = vi.spyOn(Storage.prototype, "removeItem");
    host = document.createElement("div");
    document.body.appendChild(host);
    root = createRoot(host);

    await act(async () => {
      root?.render(<Lookup />);
    });

    expect(getItem).not.toHaveBeenCalled();
    expect(setItem).not.toHaveBeenCalled();
    expect(removeItem).not.toHaveBeenCalled();
    getItem.mockRestore();
    setItem.mockRestore();
    removeItem.mockRestore();
  });

  it("queries with the in-memory key and clears the rendered secret state", async () => {
    vi.mocked(fetchLookupData).mockResolvedValue({
      key_id: "team-a",
      name: "Team A",
      enabled: true,
      limits: { rpm: 10, daily_usd: 2, weekly_usd: 5, max_concurrent_requests: 4 },
      usage: {
        daily_usd: 0.5,
        weekly_usd: 1,
        daily_limit_usd: 2,
        weekly_limit_usd: 5,
        window_mode: "utc-days-7",
        weekly_history_complete: false,
        weekly_history_incomplete_until: "2030-09-22T00:00:00Z",
        weekly_next_roll_at: "2030-09-17T00:00:00Z",
        last_usage_reset_at: "2030-09-16T10:00:00Z",
      },
      concurrency: { current: 1, maximum: 4 },
      aliases: [],
    });
    host = document.createElement("div");
    document.body.appendChild(host);
    root = createRoot(host);
    await act(async () => {
      root?.render(<Lookup />);
    });
    const input = host.querySelector<HTMLInputElement>("#lookup-secret")!;
    await act(async () => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
      setter?.call(input, "secret-123");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    const form = host.querySelector<HTMLFormElement>("form")!;
    await act(async () => {
      form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    expect(fetchLookupData).toHaveBeenCalledWith("secret-123");
    expect(host.textContent).toContain("Team A");
    expect(host.textContent).toContain("近 7 个 UTC 自然日");
    expect(host.textContent).toContain("下次窗口滚动");
    expect(host.textContent).toContain("七日历史暂不完整");
    expect(host.textContent).toContain("最近重置用量");
    const clear = Array.from(host.querySelectorAll("button")).find((button) => button.textContent?.trim() === "清除");
    await act(async () => {
      clear?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });
    expect(input.value).toBe("");
    expect(host.textContent).not.toContain("Team A");
  });

  it("renders every derived key returned for an imported CPA-native key", async () => {
    vi.mocked(fetchLookupData).mockResolvedValue({
      scope: "all-derived",
      keys: [
        {
          key_id: "team-a",
          name: "Team A",
          enabled: true,
          limits: { rpm: 10, daily_usd: 2, weekly_usd: 5, max_concurrent_requests: 4 },
          usage: { daily_usd: 0.5, weekly_usd: 1, daily_limit_usd: 2, weekly_limit_usd: 5 },
          concurrency: { current: 1, maximum: 4 },
          aliases: [],
        },
        {
          key_id: "team-b",
          name: "Team B",
          enabled: false,
          limits: { rpm: 0, daily_usd: 0, weekly_usd: 0, max_concurrent_requests: 0 },
          usage: { daily_usd: 0.25, weekly_usd: 0.75, daily_limit_usd: 0, weekly_limit_usd: 0 },
          concurrency: { current: 0, maximum: 0 },
          aliases: [],
        },
      ],
    });
    host = document.createElement("div");
    document.body.appendChild(host);
    root = createRoot(host);
    await act(async () => {
      root?.render(<Lookup />);
    });
    const input = host.querySelector<HTMLInputElement>("#lookup-secret")!;
    await act(async () => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
      setter?.call(input, "native-secret");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await act(async () => {
      host?.querySelector<HTMLFormElement>("form")?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    expect(host.textContent).toContain("Team A");
    expect(host.textContent).toContain("Team B");
    expect(host.textContent).toContain("所有派生 Key");
		expect(host.textContent).not.toContain("获准账号额度");
  });

  it("renders anonymous Codex quota and refreshes only the selected account", async () => {
    const account = {
      ref: "opaque-ref",
      label: "A-1A2B3C4D",
      provider: "codex" as const,
      tier: "team" as const,
      status: "active" as const,
      availability: "ready" as const,
      freshness: "fresh" as const,
      observed_at: "2030-09-15T10:00:00Z",
      short: { kind: "five_hour", used_percent: 10, remaining_percent: 90, reset_at: "2030-09-15T15:00:00Z" },
      long: { kind: "weekly", used_percent: 25, remaining_percent: 75, reset_at: "2030-09-22T10:00:00Z" },
      can_refresh: true,
      refresh_status: "ready" as const,
    };
    vi.mocked(fetchLookupData).mockResolvedValue({
      key_id: "team-a",
      name: "Team A",
      enabled: true,
      limits: { rpm: 10, daily_usd: 2, weekly_usd: 5, max_concurrent_requests: 4 },
      usage: { daily_usd: 0.5, weekly_usd: 1, daily_limit_usd: 2, weekly_limit_usd: 5 },
      concurrency: { current: 1, maximum: 4 },
      aliases: [],
      auth_quotas: { status: "ready", manual_refresh_allowed: true, unsupported_providers: [], accounts: [account] },
    });
    vi.mocked(fetchLookupQuota).mockResolvedValue({
      auth_quotas: {
        status: "ready",
        manual_refresh_allowed: true,
        unsupported_providers: [],
        accounts: [{ ...account, long: { ...account.long, used_percent: 30, remaining_percent: 70 }, can_refresh: false, refresh_status: "cooldown" }],
      },
    });
    host = document.createElement("div");
    document.body.appendChild(host);
    root = createRoot(host);
    await act(async () => {
      root?.render(<Lookup />);
    });
    const input = host.querySelector<HTMLInputElement>("#lookup-secret")!;
    await act(async () => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
      setter?.call(input, "derived-secret");
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
		await act(async () => {
      host?.querySelector<HTMLFormElement>("form")?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    expect(host.textContent).toContain("A-1A2B3C4D");
    expect(host.textContent).toContain("25%");
    const refresh = Array.from(host.querySelectorAll("button")).find((button) => button.textContent?.trim() === "刷新额度");
    await act(async () => {
      refresh?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });
    expect(fetchLookupQuota).toHaveBeenCalledWith("derived-secret", "opaque-ref");
    expect(host.textContent).toContain("30%");
    expect(host.textContent).toContain("手动刷新暂时受到频率限制");
  });
});

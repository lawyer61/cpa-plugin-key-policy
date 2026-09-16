import { act } from "react";
import { createRoot } from "react-dom/client";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import KeyUsage from "./KeyUsage";
import { fetchKeyUsage } from "../api/keys";
import { _resetLocale } from "../i18n";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

vi.mock("../api/keys", () => ({ fetchKeyUsage: vi.fn() }));

describe("KeyUsage UTC windows", () => {
  let root: ReturnType<typeof createRoot> | null = null;
  let host: HTMLDivElement | null = null;

  beforeEach(() => {
    _resetLocale("zh-CN");
    vi.mocked(fetchKeyUsage).mockResolvedValue({
      key_id: "team-a",
      key_name: "Team A",
      daily_limit_usd: 20,
      weekly_limit_usd: 50,
      usage: {
        daily_usd: 9,
        weekly_usd: 12,
        daily_limit_usd: 20,
        weekly_limit_usd: 50,
        daily_call_count: 4,
        weekly_call_count: 7,
        daily_input_tokens: 900,
        weekly_input_tokens: 1200,
        daily_output_tokens: 90,
        weekly_output_tokens: 120,
        window_mode: "utc-days-7",
        weekly_history_complete: false,
        weekly_history_incomplete_until: "2030-09-22T00:00:00Z",
        weekly_next_roll_at: "2030-09-17T00:00:00Z",
      },
      // Deliberately lower than the authoritative total. Legacy migration can
      // preserve such a known total/alias gap and the hero must not hide it.
      aliases: [{
        alias: "fast",
        provider: "codex",
        in_config: true,
        daily: { total_usd: 1, call_count: 1 },
        weekly: { total_usd: 2, call_count: 2 },
      }],
    });
  });

  afterEach(() => {
    act(() => root?.unmount());
    host?.remove();
    root = null;
    host = null;
    vi.clearAllMocks();
  });

  it("uses the authoritative total snapshot and explains the UTC rolling day", async () => {
    host = document.createElement("div");
    document.body.appendChild(host);
    root = createRoot(host);
    await act(async () => {
      root?.render(
        <MemoryRouter initialEntries={["/keys/team-a/usage"]}>
          <Routes><Route path="/keys/:id/usage" element={<KeyUsage />} /></Routes>
        </MemoryRouter>,
      );
    });
    expect(fetchKeyUsage).toHaveBeenCalledWith("team-a");
    expect(host.textContent).toContain("$9.00");
    expect(host.textContent).toContain("今日按 UTC 自然日统计");
    expect(host.textContent).toContain("七日历史暂不完整");

    const weekly = Array.from(host.querySelectorAll<HTMLButtonElement>("button"))
      .find((button) => button.textContent?.trim() === "近 7 个 UTC 日")!;
    await act(async () => { weekly.click(); });
    expect(host.textContent).toContain("$12.00");
    expect(host.textContent).toContain("下次窗口滚动");
  });
});

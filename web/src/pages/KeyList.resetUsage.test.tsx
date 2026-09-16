import { act } from "react";
import { createRoot } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import KeyList from "./KeyList";
import { listKeys, resetUsage } from "../api/keys";
import type { KeyPublic, ResetUsageResponse } from "../types";
import { _resetLocale } from "../i18n";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

vi.mock("../api/keys", () => ({
  listKeys: vi.fn(),
  deleteKey: vi.fn(),
  rotateKey: vi.fn(),
  resetRPM: vi.fn(),
  resetUsage: vi.fn(),
}));

const key: KeyPublic = {
  id: "team-a",
  name: "Team A",
  enabled: true,
  key_preview: "cpa_...",
  rpm: 10,
  models: [],
  daily_limit_usd: 2,
  weekly_limit_usd: 5,
  max_concurrent_requests: 0,
  current_concurrent_requests: 0,
  session_affinity: false,
  usage: {
    daily_usd: 1,
    weekly_usd: 3,
    daily_limit_usd: 2,
    weekly_limit_usd: 5,
    window_mode: "utc-days-7",
    weekly_history_complete: true,
  },
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => { resolve = r; });
  return { promise, resolve };
}

describe("KeyList usage reset", () => {
  let root: ReturnType<typeof createRoot> | null = null;
  let host: HTMLDivElement | null = null;

  beforeEach(() => {
    _resetLocale("zh-CN");
    vi.mocked(listKeys).mockResolvedValue([key]);
    vi.stubGlobal("confirm", vi.fn(() => true));
    vi.stubGlobal("alert", vi.fn());
  });

  afterEach(() => {
    act(() => root?.unmount());
    host?.remove();
    root = null;
    host = null;
    vi.clearAllMocks();
    vi.unstubAllGlobals();
  });

  async function renderPage() {
    host = document.createElement("div");
    document.body.appendChild(host);
    root = createRoot(host);
    await act(async () => {
      root?.render(<MemoryRouter><KeyList /></MemoryRouter>);
    });
  }

  it("confirms, disables only the target reset, and reloads after durable success", async () => {
    const pending = deferred<ResetUsageResponse>();
    vi.mocked(resetUsage).mockReturnValue(pending.promise);
    await renderPage();
    const buttons = Array.from(host!.querySelectorAll<HTMLButtonElement>("button"))
      .filter((button) => button.textContent?.trim() === "重置用量");
    expect(buttons.length).toBeGreaterThan(0);

    await act(async () => { buttons[0].click(); });
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(resetUsage).toHaveBeenCalledWith("team-a");
    expect(Array.from(host!.querySelectorAll<HTMLButtonElement>("button"))
      .some((button) => button.disabled && button.textContent?.trim() === "重置中…")).toBe(true);

    await act(async () => {
      pending.resolve({
        reset: true,
        id: "team-a",
        reset_at: "2026-09-16T18:00:00Z",
        usage: { ...key.usage, daily_usd: 0, weekly_usd: 0, last_usage_reset_at: "2026-09-16T18:00:00Z" },
      });
      await pending.promise;
    });
    expect(listKeys).toHaveBeenCalledTimes(2);
  });

  it("does not call the destructive endpoint when confirmation is cancelled", async () => {
    vi.stubGlobal("confirm", vi.fn(() => false));
    await renderPage();
    const button = Array.from(host!.querySelectorAll<HTMLButtonElement>("button"))
      .find((item) => item.textContent?.trim() === "重置用量")!;
    await act(async () => { button.click(); });
    expect(resetUsage).not.toHaveBeenCalled();
  });

  it("keeps reset available for disabled derived keys and hides it for native keys", async () => {
    vi.mocked(listKeys).mockResolvedValue([
      { ...key, id: "disabled", name: "Disabled", enabled: false },
      { ...key, id: "native", name: "Native", native: true },
    ]);
    await renderPage();
    const buttons = Array.from(host!.querySelectorAll<HTMLButtonElement>("button"))
      .filter((button) => button.textContent?.trim() === "重置用量");
    // One mobile and one desktop entry for the disabled derived key only.
    expect(buttons).toHaveLength(2);
  });
});

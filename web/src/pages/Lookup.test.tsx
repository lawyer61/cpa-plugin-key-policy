import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import Lookup from "./Lookup";
import { fetchLookupData } from "../api/lookup";

vi.mock("../api/lookup", async () => {
  const actual = await vi.importActual<typeof import("../api/lookup")>("../api/lookup");
  return { ...actual, fetchLookupData: vi.fn() };
});

describe("public lookup page", () => {
  let root: ReturnType<typeof createRoot> | null = null;
  let host: HTMLDivElement | null = null;

  afterEach(() => {
    root?.unmount();
    root = null;
    host?.remove();
    host = null;
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
      name: "Team A",
      limits: { rpm: 10, daily_usd: 2, weekly_usd: 5, max_concurrent_requests: 4 },
      usage: { daily_usd: 0.5, weekly_usd: 1, daily_limit_usd: 2, weekly_limit_usd: 5 },
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
    const clear = Array.from(host.querySelectorAll("button")).find((button) => button.textContent?.trim() === "清除");
    await act(async () => {
      clear?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });
    expect(input.value).toBe("");
    expect(host.textContent).not.toContain("Team A");
  });
});

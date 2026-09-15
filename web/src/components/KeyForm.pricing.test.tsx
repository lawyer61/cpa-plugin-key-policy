import { act } from "react";
import { createRoot } from "react-dom/client";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

vi.mock("../api/mappings", () => ({ fetchAliases: vi.fn().mockResolvedValue([]) }));
vi.mock("../store/modelPrices", () => ({
  getPriceTable: vi.fn().mockResolvedValue(null),
  lookupPrice: vi.fn().mockReturnValue(null),
}));

import KeyForm from "./KeyForm";

function StateProbe() {
  const location = useLocation();
  return <pre id="state-probe">{JSON.stringify(location.state)}</pre>;
}

describe("KeyForm pricing draft", () => {
  let host: HTMLDivElement | null = null;
  let root: ReturnType<typeof createRoot> | null = null;

  afterEach(() => {
    act(() => root?.unmount());
    host?.remove();
    root = null;
    host = null;
  });

  async function renderForm() {
    host = document.createElement("div");
    document.body.appendChild(host);
    root = createRoot(host);
    await act(async () => {
      root?.render(
        <MemoryRouter initialEntries={["/new"]}>
          <Routes>
            <Route
              path="/new"
              element={
                <KeyForm
                  initial={{
                    id: "draft-key",
                    name: "before",
                    enabled: true,
                    key_preview: "",
                    rpm: 3,
                    models: [{
                      alias: "gemini-2.5-flash",
                      provider: "antigravity",
                      target_model: "gemini-2.5-flash",
                    }],
                    daily_limit_usd: 1,
                    weekly_limit_usd: 5,
                    max_concurrent_requests: 4,
                    current_concurrent_requests: 0,
                    session_affinity: true,
					allow_quota_refresh: true,
                    usage: { daily_usd: 0, weekly_usd: 0, daily_limit_usd: 1, weekly_limit_usd: 5 },
                  }}
                  pickPath="/pick"
                  submitLabel="create"
                  onSubmit={async () => {}}
                  onCancel={() => {}}
                />
              }
            />
            <Route path="/pick" element={<StateProbe />} />
          </Routes>
        </MemoryRouter>,
      );
    });
  }

  it("accepts prices with more than two decimal places", async () => {
    await renderForm();
    const price = host!.querySelector<HTMLInputElement>("tbody input[type='number']")!;
    expect(price.step).toBe("any");
    await act(async () => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
      setter?.call(price, "0.025");
      price.dispatchEvent(new Event("input", { bubbles: true }));
    });
    expect(price.validity.stepMismatch).toBe(false);
  });

  it("passes the complete unsaved draft and edited prices to the model picker", async () => {
    await renderForm();
    const textInputs = Array.from(host!.querySelectorAll<HTMLInputElement>("input:not([type]), input[type='text']"));
    const name = textInputs.find((input) => input.value === "before")!;
    const price = host!.querySelector<HTMLInputElement>("tbody input[type='number']")!;
    await act(async () => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
      setter?.call(name, "after");
      name.dispatchEvent(new Event("input", { bubbles: true }));
      setter?.call(price, "0.025");
      price.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await act(async () => host!.querySelector<HTMLButtonElement>("button.mc-add")!.click());
    const state = JSON.parse(host!.querySelector("#state-probe")!.textContent || "{}");
    expect(state.keyDraft.name).toBe("after");
    expect(state.keyDraft.rpm).toBe(3);
    expect(state.keyDraft.max_concurrent_requests).toBe(4);
    expect(state.keyDraft.session_affinity).toBe(true);
		expect(state.keyDraft.allow_quota_refresh).toBe(true);
    expect(state.models[0].input_price_per_million).toBe(0.025);
    expect(state.keyDraft.models[0].input_price_per_million).toBe(0.025);
  });
});

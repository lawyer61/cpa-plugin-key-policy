import { act } from "react";
import { createRoot } from "react-dom/client";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { KeyPublic, ModelRule } from "../types";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

vi.mock("../api/models", async () => {
  const actual = await vi.importActual<typeof import("../api/models")>("../api/models");
  return {
    ...actual,
    fetchCatalog: vi.fn().mockResolvedValue([
      { provider: "antigravity", model: "gemini-2.5-flash" },
    ]),
  };
});

import ModelPick from "./ModelPick";

function StateProbe() {
  const location = useLocation();
  return <pre id="state-probe">{JSON.stringify(location.state)}</pre>;
}

describe("ModelPick key pricing draft", () => {
  let host: HTMLDivElement | null = null;
  let root: ReturnType<typeof createRoot> | null = null;

  afterEach(() => {
    act(() => root?.unmount());
    host?.remove();
    root = null;
    host = null;
  });

  it("returns surviving model prices together with the full key draft", async () => {
    const model: ModelRule = {
      alias: "gemini-2.5-flash",
      provider: "antigravity",
      target_model: "gemini-2.5-flash",
      billing_mode: "tokens",
      input_price_per_million: 0.025,
      output_price_per_million: 0.10,
      billing_multiplier: 1.5,
    };
    const keyDraft: KeyPublic = {
      id: "draft-key",
      name: "unsaved name",
      enabled: true,
      key_preview: "",
      rpm: 3,
      models: [model],
      daily_limit_usd: 1,
      weekly_limit_usd: 5,
      max_concurrent_requests: 4,
      current_concurrent_requests: 0,
      session_affinity: true,
      usage: { daily_usd: 0, weekly_usd: 0, daily_limit_usd: 1, weekly_limit_usd: 5 },
    };
    host = document.createElement("div");
    document.body.appendChild(host);
    root = createRoot(host);
    await act(async () => {
      root?.render(
        <MemoryRouter initialEntries={[{ pathname: "/keys/new/models", state: { models: [model], keyDraft } }]}>
          <Routes>
            <Route path="/keys/new/models" element={<ModelPick />} />
            <Route path="/keys/new" element={<StateProbe />} />
          </Routes>
        </MemoryRouter>,
      );
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
    const done = host.querySelector<HTMLButtonElement>(".mp-head .btn.primary")!;
    await act(async () => done.click());
    const state = JSON.parse(host.querySelector("#state-probe")?.textContent || "{}");
    expect(state.pickedModels[0].input_price_per_million).toBe(0.025);
    expect(state.pickedModels[0].output_price_per_million).toBe(0.10);
    expect(state.pickedModels[0].billing_multiplier).toBe(1.5);
    expect(state.keyDraft.name).toBe("unsaved name");
    expect(state.keyDraft.models[0].input_price_per_million).toBe(0.025);
    expect(state.keyDraft.models[0].billing_multiplier).toBe(1.5);
  });
});

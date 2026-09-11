import { beforeEach, describe, expect, it, vi } from "vitest";
import axios from "axios";
import { fetchLookupData, LOOKUP_DATA_PATH, lookupStatus } from "./lookup";

vi.mock("axios", () => ({
  default: { get: vi.fn() },
}));

describe("public key lookup API", () => {
  const get = vi.mocked(axios.get);

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("sends the lookup secret as a Bearer header", async () => {
    const payload = {
      name: "team-a",
      limits: { rpm: 10, daily_usd: 2, weekly_usd: 5, max_concurrent_requests: 3 },
      usage: { daily_usd: 0.5, weekly_usd: 1, daily_limit_usd: 2, weekly_limit_usd: 5 },
      concurrency: { current: 1, maximum: 3 },
      aliases: [],
    };
    get.mockResolvedValue({ data: payload });

    await expect(fetchLookupData("  secret-123  ")).resolves.toEqual(payload);
    expect(get).toHaveBeenCalledWith(LOOKUP_DATA_PATH, {
      headers: {
        Authorization: "Bearer secret-123",
        "Content-Type": "application/json",
      },
    });
  });

  it("extracts an HTTP status without exposing response details", () => {
    expect(lookupStatus({ response: { status: 501 } })).toBe(501);
    expect(lookupStatus(new Error("network"))).toBeUndefined();
  });
});

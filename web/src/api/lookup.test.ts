import { beforeEach, describe, expect, it, vi } from "vitest";
import axios from "axios";
import { fetchLookupData, fetchLookupQuota, LOOKUP_DATA_PATH, LOOKUP_QUOTA_REFRESH_PATH } from "./lookup";

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
      key_id: "team-a",
      name: "team-a",
      enabled: true,
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

  it("uses the explicit GET-only quota refresh contract", async () => {
    const payload = { auth_quotas: { status: "ready", manual_refresh_allowed: true, unsupported_providers: [], accounts: [] } };
    get.mockResolvedValue({ data: payload });

    await expect(fetchLookupQuota("  secret-123  ", "  opaque-ref  ")).resolves.toEqual(payload);
    expect(get).toHaveBeenCalledWith(LOOKUP_QUOTA_REFRESH_PATH, {
      timeout: 30_000,
      headers: {
        Authorization: "Bearer secret-123",
        "X-Key-Policy-Quota-Refresh": "1",
        "X-Key-Policy-Auth-Ref": "opaque-ref",
        "Content-Type": "application/json",
      },
    });
  });
});

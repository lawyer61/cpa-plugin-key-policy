import { describe, expect, it } from "vitest";
import { formatQuotaActivationResult, formatQuotaTime } from "./Mapping";

describe("quota time formatting", () => {
  it("hides Go zero-value timestamps", () => {
    expect(formatQuotaTime("0001-01-01T00:00:00Z")).toBe("—");
  });
});

describe("quota activation result formatting", () => {
  it("keeps the lifecycle state and the concrete HTTP result visible", () => {
    expect(formatQuotaActivationResult({ status: "deferred", last_result: "http_404" })).toBe("deferred · http_404");
  });

  it("shows the latest error alongside the lifecycle state", () => {
    expect(formatQuotaActivationResult({ status: "verify_pending", last_result: "http_200", last_error: "quota verify failed" })).toBe("verify_pending · quota verify failed");
  });
});

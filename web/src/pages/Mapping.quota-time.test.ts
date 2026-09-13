import { describe, expect, it } from "vitest";
import { formatQuotaTime } from "./Mapping";

describe("quota time formatting", () => {
  it("hides Go zero-value timestamps", () => {
    expect(formatQuotaTime("0001-01-01T00:00:00Z")).toBe("—");
  });
});

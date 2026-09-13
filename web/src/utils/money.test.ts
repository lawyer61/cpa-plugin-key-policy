import { describe, expect, it } from "vitest";
import { formatUSD } from "./money";

describe("formatUSD", () => {
  it("distinguishes small non-zero usage from zero", () => {
    expect(formatUSD(0)).toBe("$0.00");
    expect(formatUSD(0.000025)).toBe("$0.000025");
    expect(formatUSD(0.005)).toBe("$0.005");
    expect(formatUSD(1.234)).toBe("$1.23");
  });

  it("uses a lower-bound marker below display precision", () => {
    expect(formatUSD(0.0000004)).toBe("<$0.000001");
  });
});

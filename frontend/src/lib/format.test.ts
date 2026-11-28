import { describe, expect, it } from "vitest";
import { formatBudget, formatCount } from "./format";

describe("format helpers", () => {
  it("groups large counters", () => {
    expect(formatCount(1234567)).toBe("1,234,567");
  });

  it("renders unlimited budgets", () => {
    expect(formatBudget(0)).toBe("unlimited");
    expect(formatBudget(20)).toBe("20");
  });
});

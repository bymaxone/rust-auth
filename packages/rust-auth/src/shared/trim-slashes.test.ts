import { describe, expect, it } from "vitest";

import {
  trimLeadingSlashes,
  trimSlashes,
  trimTrailingSlashes,
} from "./trim-slashes";

/**
 * The regular expressions these replaced, kept here as the oracle. Equivalence is asserted
 * against them rather than against hand-written expectations, so the rewrite cannot have
 * changed behaviour for any input the table covers.
 */
const asRegex = {
  trimSlashes: (v: string) => v.replace(/^\/+|\/+$/g, ""),
  trimTrailingSlashes: (v: string) => v.replace(/\/+$/, ""),
  trimLeadingSlashes: (v: string) => v.replace(/^\/+/, ""),
};

const CASES = [
  "",
  "/",
  "//",
  "///",
  "auth",
  "/auth",
  "auth/",
  "/auth/",
  "///auth///",
  "/au/th/",
  "a//b",
  "https://api.example.com",
  "https://api.example.com/",
  "https://api.example.com///",
  "//leading-only",
  "trailing-only//",
];

describe("slash trimming is equivalent to the regexes it replaced", () => {
  it.each(CASES)("agrees on %o", (value) => {
    expect(trimSlashes(value)).toBe(asRegex.trimSlashes(value));
    expect(trimTrailingSlashes(value)).toBe(asRegex.trimTrailingSlashes(value));
    expect(trimLeadingSlashes(value)).toBe(asRegex.trimLeadingSlashes(value));
  });
});

describe("slash trimming is linear, which is why the regexes went", () => {
  // `/\/+$/` and `/^\/+|\/+$/g` are quadratic in a run of slashes that does not sit where
  // the anchor expects it: the engine retries the greedy `\/+` from every position. Measured
  // on Node 24 with `"a" + "/".repeat(n) + "b"`, the trailing-strip regex took 36 ms at
  // n=10_000, 843 ms at 50_000, 3.3 s at 100_000 and 13.2 s at 200_000 — doubling the input
  // quadrupled the time, and the last figure is the event loop stopped for 13 seconds.
  //
  // The threshold is deliberately loose. The point is the SHAPE: at 200_000 the regex needed
  // seconds, so anything in the tens of milliseconds proves the quadratic term is gone
  // without making the test a benchmark that fails on a loaded CI runner.
  it("handles a 200k-character slash run well inside a second", () => {
    const pathological = `a${"/".repeat(200_000)}b`;

    const started = performance.now();
    expect(trimSlashes(pathological)).toBe(pathological);
    expect(trimTrailingSlashes(pathological)).toBe(pathological);
    expect(trimLeadingSlashes(pathological)).toBe(pathological);
    const elapsed = performance.now() - started;

    expect(elapsed).toBeLessThan(500);
  });

  // The all-slashes input is the other extreme: everything is stripped, so the scan runs the
  // full length rather than stopping at the first non-slash.
  it("handles 200k slashes with nothing to keep", () => {
    const allSlashes = "/".repeat(200_000);

    const started = performance.now();
    expect(trimSlashes(allSlashes)).toBe("");
    expect(trimTrailingSlashes(allSlashes)).toBe("");
    expect(trimLeadingSlashes(allSlashes)).toBe("");

    expect(performance.now() - started).toBeLessThan(500);
  });
});

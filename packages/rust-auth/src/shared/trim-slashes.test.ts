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
  // quadrupled the time.
  //
  // The assertion is the SHAPE, as a ratio, never a wall-clock bound: the same work on an input
  // `SCALE` times longer must cost far less than `SCALE ** 2` times as much. A linear scan lands
  // near `SCALE` and the regex near `SCALE ** 2`, so a threshold between them holds on a loaded
  // CI runner, where any absolute number is a coin flip. Each side is the best of several runs,
  // which discards the runs a noisy neighbour inflated.
  const SMALL = 5_000;
  const SCALE = 40;
  const RUNS = 7;
  /** Between the linear expectation (SCALE) and the quadratic one (SCALE ** 2). */
  const MAX_RATIO = SCALE * 10;
  /** A floor under the small timing, so a clock that reads 0 cannot make the ratio infinite. */
  const FLOOR_MS = 0.05;

  const trimAll = (value: string): void => {
    trimSlashes(value);
    trimTrailingSlashes(value);
    trimLeadingSlashes(value);
  };

  const bestOf = (value: string): number => {
    let best = Number.POSITIVE_INFINITY;
    for (let run = 0; run < RUNS; run += 1) {
      const started = performance.now();
      trimAll(value);
      best = Math.min(best, performance.now() - started);
    }
    return best;
  };

  const ratioFor = (make: (n: number) => string): number => {
    const small = Math.max(bestOf(make(SMALL)), FLOOR_MS);
    return bestOf(make(SMALL * SCALE)) / small;
  };

  it("costs about SCALE times as much for an input SCALE times longer", () => {
    const pathological = (n: number): string => `a${"/".repeat(n)}b`;

    expect(ratioFor(pathological)).toBeLessThan(MAX_RATIO);
  });

  // The all-slashes input is the other extreme: everything is stripped, so the scan runs the
  // full length rather than stopping at the first non-slash.
  it("costs about SCALE times as much when there is nothing to keep", () => {
    const allSlashes = (n: number): string => "/".repeat(n);

    expect(ratioFor(allSlashes)).toBeLessThan(MAX_RATIO);
  });

  it("still returns the right answer for the long inputs", () => {
    const pathological = `a${"/".repeat(200_000)}b`;
    const allSlashes = "/".repeat(200_000);

    expect(trimSlashes(pathological)).toBe(pathological);
    expect(trimTrailingSlashes(pathological)).toBe(pathological);
    expect(trimLeadingSlashes(pathological)).toBe(pathological);
    expect(trimSlashes(allSlashes)).toBe("");
    expect(trimTrailingSlashes(allSlashes)).toBe("");
    expect(trimLeadingSlashes(allSlashes)).toBe("");
  });
});

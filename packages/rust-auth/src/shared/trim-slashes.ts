/**
 * Linear-time slash trimming for the path fragments this package accepts as configuration.
 *
 * Deliberately not a regular expression. The three shapes these replace —
 * `/^\/+|\/+$/g`, `/\/+$/` and `/^\/+/` — are all quadratic in the length of a run of
 * slashes that does not sit where the anchor expects it, because the engine retries the
 * greedy `\/+` from every position. Measured on Node 24, `"a" + "/".repeat(n) + "b"`:
 *
 * | n       | `/\/+$/` |
 * | ------- | -------- |
 * | 10 000  | 36 ms    |
 * | 50 000  | 843 ms   |
 * | 100 000 | 3.3 s    |
 * | 200 000 | 13.2 s   |
 *
 * Doubling the input quadruples the time, and 13 seconds is the event loop stopped.
 *
 * The inputs are `routePrefix` and `backendUrl`, which a deployment sets at build time
 * rather than a request carrying — so this is not a live denial of service. It is a public
 * parameter of a published library with quadratic behaviour on it, which is a defect on its
 * own terms and costs nothing to remove. Scanning characters cannot backtrack.
 *
 * @internal Not exported from the package barrel.
 */

/** Index of the first character that is not `/`. */
function firstNonSlash(value: string, from: number, to: number): number {
  let index = from;
  while (index < to && value.charCodeAt(index) === 47) index += 1;
  return index;
}

/** Index one past the last character that is not `/`, searching backwards. */
function lastNonSlash(value: string, from: number, to: number): number {
  let index = to;
  while (index > from && value.charCodeAt(index - 1) === 47) index -= 1;
  return index;
}

/**
 * Strip every leading and trailing `/`.
 *
 * @param value - The fragment to trim.
 * @returns `value` without its outer slashes; `''` when it is only slashes.
 */
export function trimSlashes(value: string): string {
  const start = firstNonSlash(value, 0, value.length);
  return value.slice(start, lastNonSlash(value, start, value.length));
}

/**
 * Strip every trailing `/`.
 *
 * @param value - The fragment to trim.
 * @returns `value` without its trailing slashes; `''` when it is only slashes.
 */
export function trimTrailingSlashes(value: string): string {
  return value.slice(0, lastNonSlash(value, 0, value.length));
}

/**
 * Strip every leading `/`.
 *
 * @param value - The fragment to trim.
 * @returns `value` without its leading slashes; `''` when it is only slashes.
 */
export function trimLeadingSlashes(value: string): string {
  return value.slice(firstNonSlash(value, 0, value.length));
}

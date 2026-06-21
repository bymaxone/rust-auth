/**
 * @fileoverview Test-only stand-in for the `server-only` marker package. Under the Node test
 * runner there is no React Server Components boundary, and the real package throws on import
 * outside the `react-server` condition. Vitest aliases `server-only` to this no-op module so
 * the server modules under test can be imported and exercised.
 */
export {};

import { test, expect, type APIRequestContext } from "@playwright/test";
import { backendUrl } from "../harness";

// A unique user per run so reruns never collide on the in-memory repository.
const EMAIL = `e2e+${Date.now()}@example.com`;
const PASSWORD = "an-e2e-strong-password-123";
const TENANT = "default";

/** Register the test user directly against the backend before the browser drives login. */
async function registerUser(request: APIRequestContext): Promise<void> {
  const response = await request.post(`${backendUrl()}/auth/register`, {
    data: { email: EMAIL, password: PASSWORD, name: "E2E", tenantId: TENANT },
  });
  expect(response.status(), "register should create the user").toBe(201);
}

test.describe("auth flow (real DOM, edge WASM verification)", () => {
  test.beforeAll(async ({ playwright }) => {
    const request = await playwright.request.newContext();
    await registerUser(request);
    await request.dispose();
  });

  test("login -> protected request -> silent refresh -> logout", async ({ page, context }) => {
    // 1. LOGIN — drive the real form; the backend sets HttpOnly session cookies on the
    //    app origin (via the same-origin /auth forwarding route).
    await page.goto("/login");
    await expect(page.getByTestId("login-heading")).toBeVisible();
    await page.getByTestId("email").fill(EMAIL);
    await page.getByTestId("password").fill(PASSWORD);
    await page.getByTestId("submit").click();

    // 2. PROTECTED REQUEST — the middleware edge-verifies the backend-signed token via
    //    WASM before /dashboard renders; the page shows the forwarded identity headers.
    await page.waitForURL("**/dashboard");
    await expect(page.getByTestId("dashboard-heading")).toBeVisible();
    await expect(page.getByTestId("user-id")).not.toHaveText("(unknown)");

    const cookieNames = (await context.cookies()).map((c) => c.name);
    expect(cookieNames).toContain("access_token");
    expect(cookieNames).toContain("refresh_token");
    expect(cookieNames).toContain("has_session");

    // 3. SILENT REFRESH — drive the silent-refresh route the middleware redirects an
    //    expired-but-has-session request to. It performs a cookie-to-cookie refresh
    //    against the backend and relays the ROTATED cookies. The request is issued
    //    through the page's request context (which shares the browser's cookie jar and
    //    the path-scoped refresh cookie), so the rotation is observed deterministically
    //    — no dependency on redirect-follow cookie-application timing. A changed access
    //    cookie proves a real refresh produced a fresh, edge-verifiable token.
    const accessBefore = (await context.cookies()).find((c) => c.name === "access_token")?.value;
    expect(accessBefore, "an access token exists before the refresh").toBeTruthy();

    const refreshResponse = await page.request.get("/auth/silent-refresh?redirectTo=/dashboard", {
      maxRedirects: 0,
    });
    // The handler redirects (3xx) to the guarded destination on success, relaying the
    // rotated Set-Cookie headers; a 3xx to /dashboard (not /login) is the success path.
    expect(refreshResponse.status(), "silent refresh redirects on success").toBeGreaterThanOrEqual(300);
    expect(refreshResponse.status()).toBeLessThan(400);
    expect(refreshResponse.headers()["location"], "refresh lands back on the protected page").toContain(
      "/dashboard",
    );

    const accessAfter = (await context.cookies()).find((c) => c.name === "access_token")?.value;
    expect(accessAfter, "silent refresh keeps a valid access cookie").toBeTruthy();
    expect(accessAfter, "the access token was rotated by the refresh").not.toBe(accessBefore);

    // The freshly rotated token is itself edge-verifiable: a new protected navigation
    // is admitted by the middleware (WASM verification) and renders the dashboard.
    await page.goto("/dashboard");
    await expect(page.getByTestId("dashboard-heading")).toBeVisible();

    // 4. LOGOUT — clears the session cookies; a subsequent protected navigation is
    //    redirected to /login by the edge (fail-closed).
    await page.getByTestId("logout-button").click();
    await page.goto("/dashboard");
    await page.waitForURL("**/login**");
    await expect(page.getByTestId("login-heading")).toBeVisible();
  });
});

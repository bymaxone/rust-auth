import { headers } from "next/headers";

// A protected page. The middleware has already edge-verified the access token (via
// WASM) before this server component renders; it forwards UX-only identity headers
// the page can read. These headers are a convenience for rendering — every real
// access decision is still enforced by the backend, never by trusting these values.
export default async function DashboardPage() {
  const h = await headers();
  const userId = h.get("x-user-id") ?? "(unknown)";
  const role = h.get("x-user-role") ?? "(unknown)";
  const tenantId = h.get("x-user-tenant-id") ?? "(unknown)";

  return (
    <main>
      <h1 data-testid="dashboard-heading">Dashboard</h1>
      <p>You reached a route the edge verified your token for.</p>
      <dl>
        <dt>User</dt>
        <dd data-testid="user-id">{userId}</dd>
        <dt>Role</dt>
        <dd data-testid="user-role">{role}</dd>
        <dt>Tenant</dt>
        <dd data-testid="user-tenant">{tenantId}</dd>
      </dl>
      <form action="/api/auth/logout" method="post">
        <button type="submit" data-testid="logout-button">
          Log out
        </button>
      </form>
    </main>
  );
}

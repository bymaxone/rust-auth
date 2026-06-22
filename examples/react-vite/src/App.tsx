import { useState } from "react";
import {
  AuthProvider,
  useAuth,
  useAuthStatus,
  useSession,
} from "@bymax-one/rust-auth/react";
import { authClient } from "./auth";

/** A sign-in form that drives `useAuth().login` and surfaces the typed error. */
function SignIn() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      const result = await login(email, password, { tenantId: "default" });
      // `login` resolves to `AuthResult | MfaChallengeResult`; branch on the MFA case.
      if ("mfaRequired" in result && result.mfaRequired) {
        setError("MFA required — complete the challenge with your authenticator code.");
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Sign-in failed");
    }
  }

  return (
    <form onSubmit={onSubmit}>
      <input
        aria-label="email"
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="email"
      />
      <input
        aria-label="password"
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="password"
      />
      <button type="submit">Sign in</button>
      {error ? <p role="alert">{error}</p> : null}
    </form>
  );
}

/** The authenticated view: shows the current user and a logout button. */
function Dashboard() {
  const { user } = useSession();
  const { logout } = useAuth();
  return (
    <section>
      <h1>Welcome, {user?.name ?? user?.email}</h1>
      <dl>
        <dt>Email</dt>
        <dd>{user?.email}</dd>
        <dt>Role</dt>
        <dd>{user?.role}</dd>
        <dt>Tenant</dt>
        <dd>{user?.tenantId}</dd>
      </dl>
      <button onClick={() => void logout()}>Log out</button>
    </section>
  );
}

/** Renders the dashboard or the sign-in form based on the live session status. */
function Gate() {
  const { isAuthenticated, isLoading } = useAuthStatus();
  if (isLoading) return <p>Loading…</p>;
  return isAuthenticated ? <Dashboard /> : <SignIn />;
}

/** The app root wires the single `authClient` into the provider. */
export function App() {
  return (
    <AuthProvider client={authClient}>
      <Gate />
    </AuthProvider>
  );
}

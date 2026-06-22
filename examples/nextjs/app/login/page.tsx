"use client";

import { useState } from "react";
import { createAuthClient } from "@bymax-one/rust-auth/client";

// A same-origin typed client: requests to /auth/* are forwarded to the backend by the
// catch-all route handler, so the HttpOnly cookies the backend sets land on this
// origin and the middleware can read them on the next navigation.
const client = createAuthClient({ baseUrl: "" });

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      const result = await client.login({ email, password, tenantId: "default" });
      if ("mfaRequired" in result && result.mfaRequired) {
        setError("MFA required — complete the challenge to continue.");
        return;
      }
      // The session cookies are set; navigate into the protected area.
      window.location.assign("/dashboard");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Sign-in failed");
    }
  }

  return (
    <main>
      <h1 data-testid="login-heading">Sign in</h1>
      <form onSubmit={onSubmit}>
        <input
          aria-label="email"
          data-testid="email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="email"
        />
        <input
          aria-label="password"
          data-testid="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="password"
        />
        <button type="submit" data-testid="submit">
          Sign in
        </button>
      </form>
      {error ? (
        <p role="alert" data-testid="error">
          {error}
        </p>
      ) : null}
    </main>
  );
}

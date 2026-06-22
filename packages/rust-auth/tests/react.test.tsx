import { cleanup, fireEvent, render, renderHook, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  AuthProvider,
  useAuth,
  useAuthStatus,
  useSession,
} from "../src/react/index";
import type { AuthClient } from "../src/client/index";
import type { AuthResult } from "../src/shared/auth-result.types";
import type { AuthUserClient } from "../src/shared/auth-user.types";

/** A safe-user fixture. */
function makeUser(): AuthUserClient {
  return {
    id: "u_1",
    email: "user@example.com",
    name: "User One",
    role: "member",
    status: "ACTIVE",
    tenantId: "t_1",
    emailVerified: true,
    mfaEnabled: false,
    lastLoginAt: null,
    createdAt: "2026-01-01T00:00:00Z",
  };
}

/** A successful auth-result fixture. */
function makeAuthResult(): AuthResult {
  return { user: makeUser(), accessToken: "access.jwt", refreshToken: "refresh.opaque" };
}

/** Build a fake {@link AuthClient} whose methods are vitest mocks, with optional overrides. */
function makeFakeClient(overrides: Partial<AuthClient> = {}): AuthClient {
  const base: AuthClient = {
    login: vi.fn(async () => makeAuthResult()),
    register: vi.fn(async () => makeAuthResult()),
    logout: vi.fn(async () => undefined),
    refresh: vi.fn(async () => makeAuthResult()),
    getMe: vi.fn(async () => makeUser()),
    mfaChallenge: vi.fn(async () => makeAuthResult()),
    forgotPassword: vi.fn(async () => undefined),
    resetPassword: vi.fn(async () => undefined),
  };
  return { ...base, ...overrides };
}

/** A probe that surfaces the session/status hooks as DOM text for assertions. */
function SessionProbe(): React.ReactNode {
  const { status, user } = useSession();
  const { isAuthenticated, isLoading } = useAuthStatus();
  return (
    <div>
      <span data-testid="status">{status}</span>
      <span data-testid="email">{user?.email ?? "none"}</span>
      <span data-testid="authed">{String(isAuthenticated)}</span>
      <span data-testid="loading">{String(isLoading)}</span>
    </div>
  );
}

/** A probe that calls `useAuth().login` with no explicit tenant. */
function LoginProbe(): React.ReactNode {
  const { login } = useAuth();
  return (
    <button
      type="button"
      onClick={() => {
        void login("a@b.c", "pw");
      }}
    >
      sign in
    </button>
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("AuthProvider + useSession + useAuthStatus", () => {
  it("transitions loading → authenticated when getMe resolves a user", async () => {
    const user = makeUser();
    const client = makeFakeClient({ getMe: vi.fn(async () => user) });

    render(
      <AuthProvider client={client} revalidateInterval={0}>
        <SessionProbe />
      </AuthProvider>,
    );

    // The first render shows the loading state before the mount validation resolves.
    expect(screen.getByTestId("status").textContent).toBe("loading");

    await waitFor(() => expect(screen.getByTestId("status").textContent).toBe("authenticated"));
    expect(screen.getByTestId("email").textContent).toBe(user.email);
    expect(screen.getByTestId("authed").textContent).toBe("true");
    expect(screen.getByTestId("loading").textContent).toBe("false");
  });

  it("settles to unauthenticated when getMe rejects", async () => {
    const client = makeFakeClient({
      getMe: vi.fn(async () => {
        throw new Error("401");
      }),
    });

    render(
      <AuthProvider client={client} revalidateInterval={0}>
        <SessionProbe />
      </AuthProvider>,
    );

    await waitFor(() =>
      expect(screen.getByTestId("status").textContent).toBe("unauthenticated"),
    );
    expect(screen.getByTestId("authed").textContent).toBe("false");
    expect(screen.getByTestId("email").textContent).toBe("none");
  });
});

describe("useAuth", () => {
  it("defaults the tenantId to 'default' on login", async () => {
    const client = makeFakeClient();

    render(
      <AuthProvider client={client} revalidateInterval={0}>
        <LoginProbe />
      </AuthProvider>,
    );

    fireEvent.click(screen.getByText("sign in"));

    await waitFor(() => expect(client.login).toHaveBeenCalledTimes(1));
    expect(client.login).toHaveBeenCalledWith({
      email: "a@b.c",
      password: "pw",
      tenantId: "default",
    });
  });
});

describe("hook guards", () => {
  it("throws a clear error when a hook is used outside AuthProvider", () => {
    // The hook reads the null context sentinel and throws — caught by renderHook.
    expect(() => renderHook(() => useSession())).toThrow(/AuthProvider/);
  });

  it("names useAuthStatus in the out-of-provider error message", () => {
    // The shared guard message must enumerate every hook, including useAuthStatus, so a
    // misuse points at the right hook.
    expect(() => renderHook(() => useAuthStatus())).toThrow(/useAuthStatus/);
  });
});

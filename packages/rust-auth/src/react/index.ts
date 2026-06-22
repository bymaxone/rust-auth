/**
 * @fileoverview React bindings for the rust-auth client: an {@link AuthProvider} that holds
 * the session and revalidates it on an interval, plus the `useSession` / `useAuth` /
 * `useAuthStatus` hooks. React is a peer dependency; this module renders no JSX (it uses
 * `createElement`) so it stays a plain `.ts` file.
 * @layer react
 */

import React from "react";

import type {
  AuthClient,
  RegisterInput,
  ResetPasswordInput,
} from "../client/index";
import type { AuthResult, LoginResult } from "../shared/auth-result.types";
import type { AuthUserClient } from "../shared/auth-user.types";

/** The default tenant used when a caller does not pass one to `login` / `forgotPassword`. */
const DEFAULT_TENANT_ID = "default";

/** The default session revalidation cadence, in milliseconds. `0` disables the interval. */
const DEFAULT_REVALIDATE_INTERVAL_MS = 300_000;

/** The lifecycle of the session as observed by the provider. */
export type SessionStatus = "authenticated" | "unauthenticated" | "loading";

/** The full context value shared by the provider with every hook. */
interface AuthContextValue {
  /** The current user, or `null` while loading or when unauthenticated. */
  user: AuthUserClient | null;
  /** The session lifecycle status. */
  status: SessionStatus;
  /** When the session was last validated against the backend, or `null` before the first check. */
  lastValidation: Date | null;
  /** Re-run `client.getMe()` and update the session state. */
  refresh: () => Promise<void>;
  /** The underlying typed client, used by {@link useAuth}. */
  client: AuthClient;
}

/**
 * The session context. `null` is the "no provider" sentinel — every hook throws a clear error
 * when it reads `null`, so a hook used outside {@link AuthProvider} fails loudly.
 */
const AuthContext = React.createContext<AuthContextValue | null>(null);

/** Props for {@link AuthProvider}. */
export interface AuthProviderProps {
  /** The subtree that gains access to the session hooks. */
  children: React.ReactNode;
  /** The typed client the provider drives. */
  client: AuthClient;
  /** Invoked when a previously authenticated session is found to have expired. */
  onSessionExpired?: () => void;
  /** Background revalidation cadence in milliseconds (default 300000; `0` disables it). */
  revalidateInterval?: number;
}

/**
 * Provide session state to a subtree. On mount, and then on the configured interval, it calls
 * `client.getMe()` and exposes the result through {@link useSession} / {@link useAuthStatus}.
 * The status starts at `'loading'` and settles to `'authenticated'` or `'unauthenticated'`.
 *
 * @param props - See {@link AuthProviderProps}.
 * @returns The provider element wrapping `children`.
 */
export function AuthProvider(props: AuthProviderProps): React.ReactNode {
  const { children, client, onSessionExpired } = props;
  const revalidateInterval = props.revalidateInterval ?? DEFAULT_REVALIDATE_INTERVAL_MS;

  const [user, setUser] = React.useState<AuthUserClient | null>(null);
  const [status, setStatus] = React.useState<SessionStatus>("loading");
  const [lastValidation, setLastValidation] = React.useState<Date | null>(null);

  // Tracks whether the last known state was authenticated, so `onSessionExpired` fires only on
  // a real authenticated → unauthenticated transition, not on the first anonymous load.
  const wasAuthenticated = React.useRef(false);

  const refresh = React.useCallback(async () => {
    try {
      const me = await client.getMe();
      setUser(me);
      setStatus("authenticated");
      setLastValidation(new Date());
      wasAuthenticated.current = true;
    } catch {
      setUser(null);
      setStatus("unauthenticated");
      setLastValidation(new Date());
      if (wasAuthenticated.current) {
        onSessionExpired?.();
      }
      wasAuthenticated.current = false;
    }
  }, [client, onSessionExpired]);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  React.useEffect(() => {
    if (revalidateInterval <= 0) return;
    const handle = setInterval(() => {
      void refresh();
    }, revalidateInterval);
    return () => {
      clearInterval(handle);
    };
  }, [refresh, revalidateInterval]);

  const value = React.useMemo<AuthContextValue>(
    () => ({ user, status, lastValidation, refresh, client }),
    [user, status, lastValidation, refresh, client],
  );

  return React.createElement(AuthContext.Provider, { value }, children);
}

/** Read the context or throw the "outside AuthProvider" error. */
function useAuthContext(): AuthContextValue {
  const context = React.useContext(AuthContext);
  if (context === null) {
    throw new Error("useSession/useAuth/useAuthStatus must be used within an <AuthProvider>.");
  }
  return context;
}

/** The shape returned by {@link useSession}. */
export interface UseSessionResult {
  /** The current user, or `null` while loading or unauthenticated. */
  user: AuthUserClient | null;
  /** The session lifecycle status. */
  status: SessionStatus;
  /** Convenience flag: `true` while the first/next validation is in flight. */
  isLoading: boolean;
  /** Force an immediate revalidation. */
  refresh: () => Promise<void>;
  /** When the session was last validated, or `null` before the first check. */
  lastValidation: Date | null;
}

/**
 * Read the current session. Must be called inside an {@link AuthProvider}.
 *
 * @returns The current user, status, loading flag, a manual `refresh`, and `lastValidation`.
 */
export function useSession(): UseSessionResult {
  const { user, status, lastValidation, refresh } = useAuthContext();
  return { user, status, isLoading: status === "loading", refresh, lastValidation };
}

/** The shape returned by {@link useAuth}. */
export interface UseAuthResult {
  /** Authenticate; `tenantId` defaults to `'default'`. Triggers a session revalidation. */
  login: (
    email: string,
    password: string,
    options?: { tenantId?: string },
  ) => Promise<LoginResult>;
  /** Register a new account, then revalidate the session. */
  register: (data: RegisterInput) => Promise<AuthResult>;
  /** Sign out, then revalidate the (now anonymous) session. */
  logout: () => Promise<void>;
  /** Begin a password reset; `tenantId` defaults to `'default'`. */
  forgotPassword: (email: string, tenantId?: string) => Promise<void>;
  /** Complete a password reset. */
  resetPassword: (input: ResetPasswordInput) => Promise<void>;
}

/**
 * Imperative auth actions bound to the provider's client. After `login`, `register`, and
 * `logout`, the session is revalidated so {@link useSession} reflects the new state. Must be
 * called inside an {@link AuthProvider}.
 *
 * @returns The `login` / `register` / `logout` / `forgotPassword` / `resetPassword` actions.
 */
export function useAuth(): UseAuthResult {
  const { client, refresh } = useAuthContext();

  const login = React.useCallback<UseAuthResult["login"]>(
    async (email, password, options) => {
      const result = await client.login({
        email,
        password,
        tenantId: options?.tenantId ?? DEFAULT_TENANT_ID,
      });
      await refresh();
      return result;
    },
    [client, refresh],
  );

  const register = React.useCallback<UseAuthResult["register"]>(
    async (data) => {
      const result = await client.register(data);
      await refresh();
      return result;
    },
    [client, refresh],
  );

  const logout = React.useCallback<UseAuthResult["logout"]>(async () => {
    await client.logout();
    await refresh();
  }, [client, refresh]);

  const forgotPassword = React.useCallback<UseAuthResult["forgotPassword"]>(
    async (email, tenantId) => {
      await client.forgotPassword(email, tenantId ?? DEFAULT_TENANT_ID);
    },
    [client],
  );

  const resetPassword = React.useCallback<UseAuthResult["resetPassword"]>(
    async (input) => {
      await client.resetPassword(input);
    },
    [client],
  );

  return { login, register, logout, forgotPassword, resetPassword };
}

/** The shape returned by {@link useAuthStatus}. */
export interface UseAuthStatusResult {
  /** `true` once the session is confirmed authenticated. */
  isAuthenticated: boolean;
  /** `true` while the session is still being validated. */
  isLoading: boolean;
}

/**
 * A minimal status view for guards and conditional UI. Must be called inside an
 * {@link AuthProvider}.
 *
 * @returns `isAuthenticated` and `isLoading` derived from the session status.
 */
export function useAuthStatus(): UseAuthStatusResult {
  const { status } = useAuthContext();
  return { isAuthenticated: status === "authenticated", isLoading: status === "loading" };
}

import { cleanup, renderHook, waitFor } from "@testing-library/react";
import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthClientError } from "../src/client/index";
import type { AuthClient } from "../src/client/index";
import { AuthProvider, useAuth } from "../src/react/index";
import type { AuthUserClient } from "../src/shared/auth-user.types";

/**
 * What the provider does with the session after `useAuth().logout()` fails. The Next.js logout
 * route clears the cookies for any answer below 500 except a throttled call, so after such a
 * refusal the session is gone and the provider must say so now rather than at the next interval;
 * after a throttled call, a `5xx` or a transport failure nothing was revoked and the state it
 * holds is still the truth.
 */

/** A safe-user fixture. */
const USER: AuthUserClient = {
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

/** A client whose `logout` rejects with `failure` and whose `getMe` is the call under count. */
function clientFailingLogoutWith(failure: unknown): AuthClient {
  return {
    login: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(async () => {
      throw failure;
    }),
    refresh: vi.fn(),
    getMe: vi.fn(async () => USER),
    mfaChallenge: vi.fn(),
    forgotPassword: vi.fn(),
    resetPassword: vi.fn(),
  };
}

/** Mount `useAuth` inside a provider with the interval off and wait for the first validation. */
async function mounted(client: AuthClient) {
  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <AuthProvider client={client} revalidateInterval={0}>
      {children}
    </AuthProvider>
  );
  const hook = renderHook(() => useAuth(), { wrapper });
  await waitFor(() => expect(client.getMe).toHaveBeenCalledTimes(1));
  return hook;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("useAuth().logout after a failed logout", () => {
  // The route answered below 500 and cleared the cookies, so the user is signed out already.
  it.each([400, 401, 403, 404, 499])(
    "revalidates at once and still rejects when the logout is refused with %i",
    async (status) => {
      const failure = new AuthClientError("refused", status);
      const client = clientFailingLogoutWith(failure);
      const { result } = await mounted(client);

      await expect(result.current.logout()).rejects.toBe(failure);

      expect(client.getMe).toHaveBeenCalledTimes(2);
    },
  );

  // The provider and the client ship as separate bundles, each with its own copy of the error
  // class, so the status has to be enough: a failure that is not this bundle's AuthClientError
  // but carries a 4xx status is read the same way.
  it("reads the status of a failure that is not an instance of the error class", async () => {
    const failure = Object.assign(new Error("refused"), { status: 401 });
    const client = clientFailingLogoutWith(failure);
    const { result } = await mounted(client);

    await expect(result.current.logout()).rejects.toBe(failure);

    expect(client.getMe).toHaveBeenCalledTimes(2);
  });

  // A throttled call revoked nothing, and neither did a backend that failed or could not be
  // reached; asking the session again would only add load to a service that is already refusing.
  it.each([
    ["a throttled call (429)", new AuthClientError("slow down", 429)],
    ["a server failure (500)", new AuthClientError("boom", 500)],
    ["a bad gateway (502)", new AuthClientError("down", 502)],
    ["a transport failure", new TypeError("fetch failed")],
  ])("keeps the state and does not revalidate after %s", async (_name, failure) => {
    const client = clientFailingLogoutWith(failure);
    const { result } = await mounted(client);

    await expect(result.current.logout()).rejects.toBe(failure);

    expect(client.getMe).toHaveBeenCalledTimes(1);
  });
});

// Hand-written runtime — NOT ts-rs generated. ts-rs emits only the data types and
// constants in this directory; this file adds the small runtime surface ts-rs cannot
// express (an Error subclass and a branded string union), authored once here and
// re-exported from ./client for consumer convenience.

import type { AuthErrorResponse } from "./auth-error.types";
import type { AuthErrorCode } from "./error-codes";

/**
 * A response `code` that is either a known, stable `auth.*` code or any other string a
 * future server build might introduce. The `(string & {})` brand keeps editor
 * autocomplete for the known {@link AuthErrorCode} members while still accepting unknown
 * codes without a type error — the same forward-compatible union nest-auth ships.
 */
export type AuthResponseCode = AuthErrorCode | (string & {});

/**
 * The error thrown by the typed client for any non-2xx auth response.
 *
 * It extends `Error` so `instanceof AuthClientError` works across the bundle boundary,
 * and carries the parsed HTTP `status`, the stable `code`, and the raw `body`. Its
 * {@link AuthClientError.toJSON} strips the echoed request DTO out of structured logs,
 * surfacing only the safe diagnostic fields.
 */
export class AuthClientError extends Error {
  /** The HTTP status code of the failing response. */
  readonly status: number;

  /** The stable `auth.*` code from the error envelope, if the body carried one. */
  readonly code: AuthResponseCode | undefined;

  /** The parsed error envelope, if the response body was a recognizable error shape. */
  readonly body: AuthErrorResponse | undefined;

  /**
   * Build an `AuthClientError`.
   *
   * @param message - The human-readable, advisory message (never the source of truth for
   *   a decision — branch on {@link AuthClientError.code} instead).
   * @param status - The HTTP status code of the response.
   * @param body - The parsed error envelope, when the response carried one.
   */
  constructor(message: string, status: number, body?: AuthErrorResponse) {
    super(message);
    this.name = "AuthClientError";
    this.status = status;
    this.code = body?.code;
    this.body = body;
    // Restore the prototype chain so `instanceof` holds when this class is extended or
    // transpiled to ES5-target output (the classic TS `extends Error` caveat).
    Object.setPrototypeOf(this, AuthClientError.prototype);
  }

  /**
   * The log-safe projection of this error: the diagnostic fields only. The raw `body`
   * (which may echo request DTO fields) is deliberately omitted so structured logs never
   * leak request payloads.
   */
  toJSON(): {
    name: string;
    message: string;
    status: number;
    code: AuthResponseCode | undefined;
  } {
    return {
      name: this.name,
      message: this.message,
      status: this.status,
      code: this.code,
    };
  }
}

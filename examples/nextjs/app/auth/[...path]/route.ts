import { NextRequest, NextResponse } from "next/server";

// A same-origin forwarding route for the backend auth API. The browser calls
// `/auth/login`, `/auth/register`, etc. on this origin; this handler relays the
// request to the Rust backend and copies the backend's `Set-Cookie` headers back, so
// the HttpOnly session cookies land on the app's own origin (where the middleware can
// read them). A production deployment would typically do this at the reverse proxy;
// the handler keeps the example self-contained.
const backendUrl = process.env.AUTH_BACKEND_URL ?? "http://127.0.0.1:8080";

async function forward(request: NextRequest, path: string[]): Promise<NextResponse> {
  const search = request.nextUrl.search;
  const target = `${backendUrl}/auth/${path.join("/")}${search}`;

  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("content-length");

  const init: RequestInit = {
    method: request.method,
    headers,
    redirect: "manual",
  };
  if (request.method !== "GET" && request.method !== "HEAD") {
    init.body = await request.text();
  }

  const upstream = await fetch(target, init);

  // Relay the status, body, and headers. A login/refresh response carries several
  // `Set-Cookie` headers at once (access + refresh + has_session); `new Headers(...)`
  // would fold them into a single comma-joined value, corrupting the cookies. Copy
  // every non-cookie header first, then re-append each `Set-Cookie` individually via
  // `getSetCookie()` (undici/Node 20+) so all auth cookies reach the browser intact.
  const responseHeaders = new Headers();
  upstream.headers.forEach((value, key) => {
    if (key.toLowerCase() !== "set-cookie") {
      responseHeaders.set(key, value);
    }
  });
  for (const cookie of upstream.headers.getSetCookie()) {
    responseHeaders.append("set-cookie", cookie);
  }

  const body = await upstream.arrayBuffer();
  return new NextResponse(body, {
    status: upstream.status,
    headers: responseHeaders,
  });
}

type RouteContext = { params: Promise<{ path: string[] }> };

export async function GET(request: NextRequest, context: RouteContext): Promise<NextResponse> {
  const { path } = await context.params;
  return forward(request, path);
}

export async function POST(request: NextRequest, context: RouteContext): Promise<NextResponse> {
  const { path } = await context.params;
  return forward(request, path);
}

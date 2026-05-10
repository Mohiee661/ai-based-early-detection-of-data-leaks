import { NextRequest, NextResponse } from "next/server";

import { AUTH_COOKIE_NAME } from "./src/lib/auth-constants";

const protectedPrefixes = [
  "/",
  "/dashboard",
  "/findings",
  "/lookup",
  "/analytics",
  "/alerts",
  "/investigations",
  "/cases",
  "/copilot",
  "/settings",
];

const AUTH_JWT_SECRET = process.env.AUTH_JWT_SECRET;

function isProtectedPath(pathname: string) {
  return protectedPrefixes.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));
}

function base64UrlDecode(input: string) {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return atob(padded);
}

function parseJwt(token: string) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format.");
  }

  const header = JSON.parse(base64UrlDecode(parts[0]));
  const payload = JSON.parse(base64UrlDecode(parts[1]));

  if (header.alg !== "HS256" || typeof payload !== "object" || payload === null) {
    throw new Error("Unsupported JWT payload.");
  }

  return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: parts[2] };
}

async function verifySessionToken(token: string) {
  if (!AUTH_JWT_SECRET) {
    return Boolean(token);
  }

  const { payload, signingInput, signature } = parseJwt(token);
  const expiresAt = typeof payload.exp === "number" ? payload.exp : Number(payload.exp);
  if (!Number.isFinite(expiresAt) || expiresAt <= Math.floor(Date.now() / 1000)) {
    return false;
  }

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(AUTH_JWT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );

  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    Uint8Array.from(base64UrlDecode(signature), (char) => char.charCodeAt(0)),
    new TextEncoder().encode(signingInput),
  );

  return valid;
}

export async function middleware(request: NextRequest) {
  const { pathname, searchParams } = request.nextUrl;
  const authCookie = request.cookies.get(AUTH_COOKIE_NAME)?.value;

  if (pathname.startsWith("/_next") || pathname.startsWith("/api") || pathname === "/favicon.ico") {
    return NextResponse.next();
  }

  if (pathname === "/login") {
    if (authCookie && (await verifySessionToken(authCookie))) {
      const nextPath = searchParams.get("next") || "/dashboard";
      return NextResponse.redirect(new URL(nextPath, request.url));
    }

    return NextResponse.next();
  }

  if (isProtectedPath(pathname) && !(authCookie && (await verifySessionToken(authCookie)))) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("next", pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/", "/dashboard/:path*", "/findings/:path*", "/lookup/:path*", "/analytics/:path*", "/alerts/:path*", "/investigations/:path*", "/cases/:path*", "/copilot/:path*", "/settings/:path*", "/login"],
};

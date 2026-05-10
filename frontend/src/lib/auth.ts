import {
  AUTH_COOKIE_NAME,
  AUTH_STORAGE_KEY,
  type AuthSession,
  type AuthUser,
} from "@/lib/auth-constants";
import { getApiBaseUrl } from "@/lib/api-config";

type LoginResponse = {
  access_token: string;
  expires_at: string;
  token_type: string;
  user: AuthUser;
};

type MeResponse = {
  expires_at: string;
  user: AuthUser;
};

function readCookie(name: string) {
  if (typeof document === "undefined") {
    return null;
  }

  const match = document.cookie
    .split(";")
    .map((entry) => entry.trim())
    .find((entry) => entry.startsWith(`${name}=`));

  if (!match) {
    return null;
  }

  return decodeURIComponent(match.slice(name.length + 1));
}

function writeCookie(name: string, value: string, expiresAt: string) {
  if (typeof document === "undefined") {
    return;
  }

  const expires = new Date(expiresAt);
  const secure = window.location.protocol === "https:" ? "; Secure" : "";
  document.cookie = `${name}=${encodeURIComponent(value)}; Path=/; Expires=${expires.toUTCString()}; SameSite=Lax${secure}`;
}

function clearCookie(name: string) {
  if (typeof document === "undefined") {
    return;
  }

  document.cookie = `${name}=; Path=/; Max-Age=0; SameSite=Lax`;
}

export function getStoredAuthSession(): AuthSession | null {
  if (typeof window === "undefined") {
    return null;
  }

  const raw = window.localStorage.getItem(AUTH_STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<AuthSession>;
    if (
      typeof parsed.accessToken !== "string" ||
      typeof parsed.expiresAt !== "string" ||
      !parsed.user ||
      typeof parsed.user.username !== "string" ||
      typeof parsed.user.display_name !== "string" ||
      typeof parsed.user.role !== "string"
    ) {
      return null;
    }

    return {
      accessToken: parsed.accessToken,
      expiresAt: parsed.expiresAt,
      user: parsed.user,
    };
  } catch {
    return null;
  }
}

export function getStoredAuthToken(): string | null {
  const session = getStoredAuthSession();
  if (session?.accessToken) {
    return session.accessToken;
  }

  return readCookie(AUTH_COOKIE_NAME);
}

export function persistAuthSession(session: AuthSession) {
  if (typeof window === "undefined") {
    return;
  }

  window.localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(session));
  writeCookie(AUTH_COOKIE_NAME, session.accessToken, session.expiresAt);
}

export function clearAuthSession() {
  if (typeof window === "undefined") {
    return;
  }

  window.localStorage.removeItem(AUTH_STORAGE_KEY);
  clearCookie(AUTH_COOKIE_NAME);
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${getApiBaseUrl()}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.headers ?? {}),
    },
    cache: "no-store",
  });

  if (!response.ok) {
    let detail = `Request failed with status ${response.status}`;

    try {
      const payload = (await response.json()) as { detail?: string };
      if (typeof payload.detail === "string" && payload.detail.trim()) {
        detail = payload.detail;
      }
    } catch {
      // Keep the HTTP status fallback.
    }

    throw new Error(detail);
  }

  return (await response.json()) as T;
}

export async function loginWithPassword(username: string, password: string): Promise<AuthSession> {
  const payload = await requestJson<LoginResponse>("/api/auth/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, password }),
  });

  const session: AuthSession = {
    accessToken: payload.access_token,
    expiresAt: payload.expires_at,
    user: payload.user,
  };

  persistAuthSession(session);
  return session;
}

export async function fetchCurrentSession(): Promise<AuthSession | null> {
  const token = getStoredAuthToken();
  if (!token) {
    return null;
  }

  try {
    const payload = await requestJson<MeResponse>("/api/auth/me", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const session: AuthSession = {
      accessToken: token,
      expiresAt: payload.expires_at,
      user: payload.user,
    };
    persistAuthSession(session);
    return session;
  } catch {
    clearAuthSession();
    return null;
  }
}

export async function logoutSession() {
  clearAuthSession();
}

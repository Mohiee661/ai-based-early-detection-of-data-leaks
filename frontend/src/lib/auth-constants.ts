export const AUTH_COOKIE_NAME = "darkshield_session";
export const AUTH_STORAGE_KEY = "darkshield-auth-session";

export type AuthUser = {
  display_name: string;
  role: string;
  username: string;
};

export type AuthSession = {
  accessToken: string;
  expiresAt: string;
  user: AuthUser;
};

export type AuthState = {
  session: AuthSession | null;
  status: "authenticated" | "unauthenticated" | "loading";
};

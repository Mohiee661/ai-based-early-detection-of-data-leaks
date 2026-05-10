"use client";

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

import {
  clearAuthSession,
  fetchCurrentSession,
  loginWithPassword,
  logoutSession,
} from "@/lib/auth";
import { type AuthSession, type AuthState } from "@/lib/auth-constants";

type AuthContextValue = AuthState & {
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<AuthSession | null>(null);
  const [status, setStatus] = useState<AuthState["status"]>("loading");

  useEffect(() => {
    let active = true;

    async function bootstrap() {
      try {
        const resolved = await fetchCurrentSession();
        if (!active) {
          return;
        }

        setSession(resolved);
        setStatus(resolved ? "authenticated" : "unauthenticated");
      } catch {
        if (!active) {
          return;
        }

        clearAuthSession();
        setSession(null);
        setStatus("unauthenticated");
      }
    }

    bootstrap();
    return () => {
      active = false;
    };
  }, []);

  async function login(username: string, password: string) {
    setStatus("loading");
    try {
      const nextSession = await loginWithPassword(username, password);
      setSession(nextSession);
      setStatus("authenticated");
    } catch (error) {
      setSession(null);
      setStatus("unauthenticated");
      throw error;
    }
  }

  async function logout() {
    try {
      await logoutSession();
    } finally {
      clearAuthSession();
      setSession(null);
      setStatus("unauthenticated");
    }
  }

  return (
    <AuthContext.Provider value={{ session, status, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider.");
  }

  return context;
}

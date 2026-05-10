"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowRight, Shield, Lock, Sparkles } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/components/providers/auth-provider";

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { status, login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const nextPath = useMemo(() => searchParams.get("next") || "/dashboard", [searchParams]);

  useEffect(() => {
    if (status === "authenticated") {
      router.replace(nextPath);
    }
  }, [nextPath, router, status]);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
      await login(username, password);
      router.replace(nextPath);
    } catch (loginError) {
      setError(loginError instanceof Error ? loginError.message : "Login failed.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <main className="min-h-screen bg-background">
      <section className="mx-auto flex min-h-screen w-full max-w-6xl items-center px-4 py-10 sm:px-6 lg:px-8">
        <div className="grid w-full gap-8 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="flex flex-col justify-center gap-6">
            <div className="inline-flex w-fit items-center gap-2 rounded-full border border-border bg-card px-4 py-2 text-sm text-muted-foreground">
              <Sparkles className="size-4" />
              Secure analyst access
            </div>
            <div className="space-y-4">
              <h1 className="max-w-xl text-4xl font-semibold tracking-tight text-foreground sm:text-5xl">
                DarkShield login
              </h1>
              <p className="max-w-2xl text-sm leading-6 text-muted-foreground sm:text-base">
                Authenticate to reach the threat dashboard, lookup tools, and analytics.
                Sessions are validated by the FastAPI backend and persisted in your browser.
              </p>
            </div>
            <div className="flex flex-wrap gap-3 text-sm text-muted-foreground">
              <span className="inline-flex items-center gap-2 rounded-full border border-border px-3 py-2">
                <Shield className="size-4" />
                JWT protected routes
              </span>
              <span className="inline-flex items-center gap-2 rounded-full border border-border px-3 py-2">
                <Lock className="size-4" />
                Session persistence
              </span>
            </div>
            <p className="text-sm text-muted-foreground">
              New here? Ask for a dashboard account, then sign in with your analyst credentials.
            </p>
          </div>

          <Card className="border-border/80 bg-card/90 backdrop-blur">
            <CardHeader>
              <CardTitle className="text-2xl">Sign in</CardTitle>
            </CardHeader>
            <CardContent>
              <form className="space-y-4" onSubmit={handleSubmit}>
                <label className="block space-y-2">
                  <span className="text-sm font-medium text-foreground">Username</span>
                  <input
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    autoComplete="username"
                    className="h-11 w-full rounded-[var(--radius)] border border-input bg-background px-3 text-sm text-foreground outline-none transition-colors focus:border-ring"
                  />
                </label>
                <label className="block space-y-2">
                  <span className="text-sm font-medium text-foreground">Password</span>
                  <input
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    type="password"
                    autoComplete="current-password"
                    className="h-11 w-full rounded-[var(--radius)] border border-input bg-background px-3 text-sm text-foreground outline-none transition-colors focus:border-ring"
                  />
                </label>

                {error ? (
                  <div className="rounded-[var(--radius)] border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-200">
                    {error}
                  </div>
                ) : null}

                <Button className="h-11 w-full" type="submit" disabled={isSubmitting}>
                  {isSubmitting ? "Signing in..." : "Enter DarkShield"}
                  <ArrowRight className="size-4" />
                </Button>
              </form>

              <p className="mt-4 text-xs leading-5 text-muted-foreground">
                Protected dashboard routes will redirect here if your session is missing or invalid.
              </p>

              <div className="mt-6 text-sm text-muted-foreground">
                Return to the{" "}
                <Link href="/" className="text-foreground underline-offset-4 hover:underline">
                  homepage
                </Link>
                .
              </div>
            </CardContent>
          </Card>
        </div>
      </section>
    </main>
  );
}

function LoginFallback() {
  return (
    <main className="min-h-screen bg-background">
      <section className="mx-auto flex min-h-screen w-full max-w-6xl items-center px-4 py-10 sm:px-6 lg:px-8">
        <div className="grid w-full gap-8 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="flex flex-col justify-center gap-6">
            <div className="h-8 w-44 rounded-full border border-border bg-card" />
            <div className="h-14 w-full max-w-xl rounded-2xl border border-border bg-card" />
            <div className="h-10 w-full max-w-2xl rounded-2xl border border-border bg-card" />
          </div>
          <Card className="border-border/80 bg-card/90 backdrop-blur">
            <CardHeader>
              <CardTitle className="text-2xl">Sign in</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-56 rounded-2xl border border-border bg-background/60" />
            </CardContent>
          </Card>
        </div>
      </section>
    </main>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<LoginFallback />}>
      <LoginForm />
    </Suspense>
  );
}

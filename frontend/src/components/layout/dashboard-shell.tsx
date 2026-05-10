"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { Menu, Moon, Search, Shield, SunMedium, X } from "lucide-react";
import { usePathname } from "next/navigation";

import { DashboardNav } from "@/components/layout/dashboard-nav";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/components/providers/auth-provider";
import { cn } from "@/lib/utils";

type DashboardShellProps = {
  children: ReactNode;
};

const routeMeta: Record<
  string,
  {
    description: string;
    title: string;
  }
> = {
  "/dashboard": {
    title: "Dashboard",
    description: "Overview",
  },
  "/findings": {
    title: "Feed",
    description: "Findings",
  },
  "/lookup": {
    title: "Lookup",
    description: "Indicators",
  },
  "/analytics": {
    title: "Analytics",
    description: "Trends",
  },
  "/alerts": {
    title: "Alerts",
    description: "Escalations",
  },
  "/investigations": {
    title: "Timeline",
    description: "Chronology",
  },
  "/cases": {
    title: "Cases",
    description: "Investigations",
  },
  "/copilot": {
    title: "Copilot",
    description: "Assistant",
  },
  "/settings": {
    title: "Settings",
    description: "Config",
  },
};

function getThemePreference() {
  if (typeof window === "undefined") {
    return "dark";
  }

  return window.localStorage.getItem("darkshield-theme") ?? "dark";
}

export function DashboardShell({ children }: DashboardShellProps) {
  const pathname = usePathname();
  const router = useRouter();
  const { session, logout, status } = useAuth();
  const [isMobileOpen, setIsMobileOpen] = useState(false);
  const [theme, setTheme] = useState<"dark" | "light">(() =>
    getThemePreference() === "light" ? "light" : "dark",
  );

  const currentMeta = useMemo(() => {
    return routeMeta[pathname] ?? routeMeta["/dashboard"];
  }, [pathname]);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
  }, [theme]);

  function toggleTheme() {
    const nextTheme = theme === "dark" ? "light" : "dark";
    setTheme(nextTheme);
    document.documentElement.classList.toggle("dark", nextTheme === "dark");
    window.localStorage.setItem("darkshield-theme", nextTheme);
  }

  async function handleLogout() {
    await logout();
    router.replace("/login");
  }

  return (
    <div className="app-shell">
      <div className="mx-auto flex min-h-screen w-full bg-background">
        <aside className="hidden w-64 shrink-0 border-r border-sidebar-border bg-sidebar lg:block">
          <div className="sticky top-0 flex h-screen flex-col px-3 py-4">
            <div className="flex items-center gap-3 px-2 pb-4">
              <div className="flex size-9 items-center justify-center rounded-[var(--radius)] bg-primary text-primary-foreground">
                <Shield className="size-4" />
              </div>
              <div>
                <div className="text-sm font-semibold text-sidebar-foreground">DarkShield</div>
              </div>
            </div>

            <DashboardNav currentPath={pathname} />

            <div className="mt-auto rounded-[var(--radius)] border border-sidebar-border bg-background px-3 py-3">
              <p className="text-xs font-medium uppercase tracking-[0.16em] text-muted-foreground">Status</p>
              <p className="mt-1 text-sm text-foreground">Live workspace</p>
            </div>
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-30 border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80">
            <div className="flex items-center gap-3 px-4 py-2.5 sm:px-6 lg:px-6">
              <Button
                variant="ghost"
                size="icon"
                className="lg:hidden"
                aria-label="Open navigation"
                onClick={() => setIsMobileOpen(true)}
              >
                <Menu className="size-5" />
              </Button>

              <div className="min-w-0 flex-1">
                <h1 className="truncate text-base font-semibold text-foreground">
                  {currentMeta.title}
                </h1>
              </div>

              <div className="hidden w-full max-w-xs items-center sm:flex">
                <div className="relative w-full">
                  <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                  <input
                    aria-label="Search"
                    placeholder="Search"
                    className="h-9 w-full rounded-[var(--radius)] border border-input bg-background pl-9 pr-3 text-sm text-foreground outline-none transition-colors focus:border-ring"
                  />
                </div>
              </div>

              <Button
                variant="ghost"
                size="icon"
                aria-label="Toggle theme"
                onClick={toggleTheme}
              >
                {theme === "dark" ? (
                  <SunMedium className="size-4" />
                ) : (
                  <Moon className="size-4" />
                )}
              </Button>

              <div className="flex items-center gap-3">
                <div className="hidden text-right sm:block">
                  <div className="text-sm font-medium text-foreground">
                    {status === "authenticated" ? session?.user.display_name : "Loading..."}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {status === "authenticated" ? session?.user.role : "Validating session"}
                  </div>
                </div>
                <Button variant="outline" size="sm" onClick={() => void handleLogout()}>
                  Sign out
                </Button>
              </div>
            </div>
          </header>

          <main className="flex-1">
            <div className="mx-auto w-full max-w-7xl px-4 py-5 sm:px-6 lg:px-8">
              {children}
            </div>
          </main>
        </div>
      </div>

      <div
        className={cn(
          "fixed inset-0 z-40 bg-black/40 transition-opacity lg:hidden",
          isMobileOpen ? "opacity-100" : "pointer-events-none opacity-0",
        )}
        onClick={() => setIsMobileOpen(false)}
        aria-hidden="true"
      />

      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 w-72 border-r border-sidebar-border bg-sidebar transition-transform lg:hidden",
          isMobileOpen ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex h-full flex-col px-3 py-4">
          <div className="flex items-center justify-between pb-4">
            <div className="flex items-center gap-3">
              <div className="flex size-9 items-center justify-center rounded-[var(--radius)] bg-primary text-primary-foreground">
                <Shield className="size-4" />
              </div>
              <div>
                <div className="text-sm font-semibold text-sidebar-foreground">DarkShield</div>
              </div>
            </div>
            <Button
              variant="ghost"
              size="icon"
              aria-label="Close navigation"
              onClick={() => setIsMobileOpen(false)}
            >
              <X className="size-5" />
            </Button>
          </div>

          <DashboardNav currentPath={pathname} onNavigate={() => setIsMobileOpen(false)} />
        </div>
      </aside>
    </div>
  );
}

"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { LogOut } from "lucide-react";

import { getSupabaseClient } from "@/lib/supabase";

type AppNavbarProps = {
  showClustersLink?: boolean;
};

export function AppNavbar({ showClustersLink = true }: AppNavbarProps) {
  const router = useRouter();

  async function handleLogout() {
    const supabase = getSupabaseClient();
    if (!supabase) {
      router.push("/login");
      return;
    }

    await supabase.auth.signOut();
    router.push("/login");
    router.refresh();
  }

  return (
    <header className="border-b border-white/10 bg-slate-950/80 backdrop-blur">
      <div className="mx-auto flex w-full max-w-7xl items-center justify-between px-4 py-4 sm:px-6 lg:px-8">
        <div className="flex items-center gap-6">
          <Link href="/" className="text-lg font-semibold tracking-tight text-slate-50">
            DarkShield
          </Link>
          {showClustersLink ? (
            <nav className="flex items-center gap-4 text-sm text-slate-300">
              <Link href="/" className="transition hover:text-white">
                Repos
              </Link>
              <Link href="/clusters" className="transition hover:text-white">
                Clusters
              </Link>
            </nav>
          ) : null}
        </div>

        <button
          type="button"
          onClick={handleLogout}
          className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm font-medium text-slate-100 transition hover:bg-white/10"
        >
          <LogOut className="size-4" />
          Logout
        </button>
      </div>
    </header>
  );
}

"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  ExternalLink,
  LoaderCircle,
  Plus,
  RefreshCw,
  ScanSearch,
} from "lucide-react";

import { AppNavbar } from "@/components/app-navbar";
import { formatRelativeTime, parseGithubRepoUrl } from "@/lib/github";
import { getSupabaseClient, isSupabaseConfigured } from "@/lib/supabase";

type RepoRow = {
  id: string;
  user_id: string;
  github_url: string;
  owner: string;
  name: string;
  status: "pending" | "scanning" | "done" | "error" | string;
  last_scanned_at: string | null;
  finding_count: number | null;
  ai_reasoning: string | null;
  created_at: string | null;
};

type SessionUser = {
  id: string;
  email?: string | null;
};

function statusTone(status: string): string {
  switch (status) {
    case "scanning":
      return "border-blue-400/30 bg-blue-400/15 text-blue-100";
    case "done":
      return "border-emerald-400/30 bg-emerald-400/15 text-emerald-100";
    case "error":
      return "border-red-400/30 bg-red-400/15 text-red-100";
    default:
      return "border-slate-400/30 bg-slate-400/15 text-slate-200";
  }
}

function findingTone(count: number): string {
  if (count <= 0) {
    return "text-emerald-300";
  }
  if (count <= 5) {
    return "text-amber-300";
  }
  return "text-red-300";
}

export default function ReposPage() {
  const router = useRouter();
  const [user, setUser] = useState<SessionUser | null>(null);
  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [repos, setRepos] = useState<RepoRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [githubUrl, setGithubUrl] = useState("https://github.com/torvalds/linux");
  const [actionBusy, setActionBusy] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);

  const apiUrl = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

  async function loadRepos(currentUserId?: string) {
    if (!currentUserId) {
      return;
    }

    const supabase = getSupabaseClient();
    if (!supabase) {
      setError("Set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY in frontend/.env.local.");
      return;
    }

    const { data, error: repoError } = await supabase
      .from("repos")
      .select("*")
      .eq("user_id", currentUserId)
      .order("created_at", { ascending: false });

    if (repoError) {
      setError(repoError.message);
      return;
    }

    setRepos((data as RepoRow[]) ?? []);
  }

  useEffect(() => {
    let active = true;

    async function bootstrap() {
      if (!isSupabaseConfigured) {
        setError("Set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY in frontend/.env.local.");
        setLoading(false);
        return;
      }

      const supabase = getSupabaseClient();
      if (!supabase) {
        setError("Set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY in frontend/.env.local.");
        setLoading(false);
        return;
      }

      const { data } = await supabase.auth.getSession();
      const sessionUser = data.session?.user;
      if (!sessionUser) {
        router.replace("/login");
        return;
      }

      if (!active) {
        return;
      }

      setUser({ id: sessionUser.id, email: sessionUser.email });
      setSessionToken(data.session?.access_token ?? null);
      await loadRepos(sessionUser.id);
      if (active) {
        setLoading(false);
      }
    }

    void bootstrap();
    return () => {
      active = false;
    };
  }, [router]);

  const repoSummary = useMemo(() => {
    const total = repos.length;
    const scanning = repos.filter((repo) => repo.status === "scanning").length;
    const alerts = repos.reduce((sum, repo) => sum + (repo.finding_count || 0), 0);
    return { total, scanning, alerts };
  }, [repos]);

  async function handleAddRepo(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setModalError(null);

    if (!user) {
      setModalError("You must be signed in first.");
      return;
    }

    let parsed;
    try {
      parsed = parseGithubRepoUrl(githubUrl);
    } catch (parseError) {
      setModalError(parseError instanceof Error ? parseError.message : "Invalid repository URL.");
      return;
    }

    setActionBusy(true);
    try {
      const supabase = getSupabaseClient();
      if (!supabase) {
        setModalError("Set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY in frontend/.env.local.");
        return;
      }

      const { data: repo, error: insertError } = await supabase
        .from("repos")
        .insert({
          user_id: user.id,
          github_url: parsed.githubUrl,
          owner: parsed.owner,
          name: parsed.name,
          status: "pending",
        })
        .select("*")
        .single();

      if (insertError) {
        throw insertError;
      }

      setShowModal(false);
      setGithubUrl(`https://github.com/${parsed.owner}/${parsed.name}`);
      await fetch(`${apiUrl}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({ repo_id: repo.id }),
      });
      await loadRepos(user.id);
    } catch (err) {
      setModalError(err instanceof Error ? err.message : "Failed to add repository.");
    } finally {
      setActionBusy(false);
    }
  }

  async function handleScanNow(repoId: string) {
    setActionBusy(true);
    try {
      await fetch(`${apiUrl}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({ repo_id: repoId }),
      });
      if (user) {
        await loadRepos(user.id);
      }
    } finally {
      setActionBusy(false);
    }
  }

  if (loading) {
    return (
      <main className="min-h-screen bg-slate-950 text-slate-50">
        <div className="flex min-h-screen items-center justify-center">
          <div className="flex items-center gap-3 text-slate-300">
            <LoaderCircle className="size-5 animate-spin" />
            Loading repositories...
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(20,34,66,0.75),_rgba(5,10,18,1)_55%)] text-slate-50">
      <AppNavbar />

      <div className="mx-auto flex w-full max-w-7xl flex-col gap-8 px-4 py-8 sm:px-6 lg:px-8">
        <section className="rounded-3xl border border-white/10 bg-white/5 p-6 shadow-2xl shadow-black/15 backdrop-blur">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="text-xs uppercase tracking-[0.22em] text-cyan-200/80">DarkShield</p>
              <h1 className="mt-2 text-3xl font-semibold tracking-tight">Monitored repositories</h1>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">
                Add GitHub repositories to scan them for exposed secrets, then open any repo for a full AI-powered analysis.
              </p>
            </div>

            <button
              type="button"
              onClick={() => setShowModal(true)}
              className="inline-flex items-center justify-center gap-2 rounded-2xl bg-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300"
            >
              <Plus className="size-4" />
              Add Repo
            </button>
          </div>

          <div className="mt-6 grid gap-4 sm:grid-cols-3">
            <div className="rounded-2xl border border-white/10 bg-slate-950/65 p-4">
              <div className="text-xs uppercase tracking-[0.18em] text-slate-400">Repos</div>
              <div className="mt-2 text-2xl font-semibold">{repoSummary.total}</div>
            </div>
            <div className="rounded-2xl border border-white/10 bg-slate-950/65 p-4">
              <div className="text-xs uppercase tracking-[0.18em] text-slate-400">Scanning</div>
              <div className="mt-2 text-2xl font-semibold">{repoSummary.scanning}</div>
            </div>
            <div className="rounded-2xl border border-white/10 bg-slate-950/65 p-4">
              <div className="text-xs uppercase tracking-[0.18em] text-slate-400">Total Findings</div>
              <div className="mt-2 text-2xl font-semibold">{repoSummary.alerts}</div>
            </div>
          </div>
        </section>

        {error ? (
          <div className="rounded-2xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-100">
            {error}
          </div>
        ) : null}

        {!repos.length ? (
          <div className="rounded-3xl border border-emerald-500/20 bg-emerald-500/10 p-6 text-emerald-100">
            <div className="flex items-center gap-3 font-semibold">
              <CheckCircle2 className="size-5" />
              No repositories added yet.
            </div>
            <p className="mt-2 text-sm text-emerald-100/80">
              Use the Add Repo button to start monitoring a GitHub repository.
            </p>
          </div>
        ) : (
          <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
            {repos.map((repo) => (
              <article
                key={repo.id}
                role="button"
                tabIndex={0}
                onClick={() => router.push(`/repos/${repo.id}`)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    router.push(`/repos/${repo.id}`);
                  }
                }}
                className="cursor-pointer rounded-3xl border border-white/10 bg-slate-950/75 p-5 shadow-lg shadow-black/10 transition hover:-translate-y-0.5 hover:border-cyan-400/30 hover:bg-slate-950"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-lg font-semibold">{repo.owner}/{repo.name}</div>
                    <div className="mt-1 text-xs text-slate-400">{repo.github_url}</div>
                  </div>
                  <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${statusTone(repo.status)}`}>
                    {repo.status}
                  </span>
                </div>

                <div className="mt-5 flex items-end justify-between gap-4">
                  <div>
                    <div className="text-xs uppercase tracking-[0.18em] text-slate-400">Findings</div>
                    <div className={`mt-1 text-3xl font-semibold ${findingTone(repo.finding_count || 0)}`}>
                      {repo.finding_count || 0}
                    </div>
                  </div>
                  <div className="text-right text-sm text-slate-300">
                    <div className="flex items-center justify-end gap-2 text-slate-400">
                      <Clock3 className="size-4" />
                      Last scanned
                    </div>
                    <div className="mt-1">{formatRelativeTime(repo.last_scanned_at)}</div>
                  </div>
                </div>

                <div className="mt-5 flex items-center justify-between gap-3">
                  <Link
                    href={`/repos/${repo.id}`}
                    className="inline-flex items-center gap-2 text-sm font-medium text-cyan-200 transition hover:text-cyan-100"
                    onClick={(event) => event.stopPropagation()}
                  >
                    Open repo
                    <ExternalLink className="size-4" />
                  </Link>

                  <button
                    type="button"
                    onClick={(event) => {
                      event.stopPropagation();
                      void handleScanNow(repo.id);
                    }}
                    disabled={actionBusy}
                    className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm font-medium text-slate-100 transition hover:bg-white/10 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    <ScanSearch className="size-4" />
                    Scan Now
                  </button>
                </div>
              </article>
            ))}
          </div>
        )}
      </div>

      {showModal ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-4">
          <div className="w-full max-w-lg rounded-3xl border border-white/10 bg-slate-950 p-6 shadow-2xl shadow-black/30">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 className="text-xl font-semibold">Add GitHub Repository</h2>
                <p className="mt-1 text-sm text-slate-400">
                  Paste a public GitHub repository URL to start monitoring it.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowModal(false)}
                className="rounded-full border border-white/10 px-3 py-1 text-sm text-slate-300 transition hover:bg-white/5"
              >
                Close
              </button>
            </div>

            <form onSubmit={handleAddRepo} className="mt-5 space-y-4">
              <input
                value={githubUrl}
                onChange={(event) => setGithubUrl(event.target.value)}
                placeholder="https://github.com/owner/repo"
                className="w-full rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-50 outline-none placeholder:text-slate-500 focus:border-cyan-400/40"
              />

              {modalError ? (
                <div className="rounded-2xl border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-100">
                  {modalError}
                </div>
              ) : null}

              <div className="flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="rounded-2xl border border-white/10 px-4 py-3 text-sm font-medium text-slate-200 transition hover:bg-white/5"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionBusy}
                  className="inline-flex items-center gap-2 rounded-2xl bg-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-70"
                >
                  {actionBusy ? <LoaderCircle className="size-4 animate-spin" /> : <RefreshCw className="size-4" />}
                  Add and Scan
                </button>
              </div>
            </form>
          </div>
        </div>
      ) : null}
    </main>
  );
}

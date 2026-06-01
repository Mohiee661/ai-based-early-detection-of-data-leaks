"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  AlertTriangle,
  ExternalLink,
  LoaderCircle,
  ScanSearch,
  ShieldAlert,
  Sparkles,
  Trash2,
} from "lucide-react";

import { AppNavbar } from "@/components/app-navbar";
import { formatRelativeTime } from "@/lib/github";
import { getSupabaseClient, isSupabaseConfigured } from "@/lib/supabase";

type RepoRow = {
  id: string;
  github_url: string;
  owner: string;
  name: string;
  status: string;
  last_scanned_at: string | null;
  finding_count: number | null;
  ai_reasoning: string | null;
  created_at: string | null;
};

type FindingRow = {
  id: string;
  repo_id: string;
  file_path: string;
  line_number: number;
  secret_type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
  snippet: string;
  secret_hash: string;
  cluster_id: string | null;
  created_at: string;
  exposure_days?: number;
  exposure_score?: number;
  first_commit_date?: string;
};

type ClusterRow = {
  id: string;
  secret_hash: string;
  secret_type: string;
  repo_count: number;
  severity: string;
  created_at: string;
};

const FILTERS = ["All", "Critical", "High", "Medium"] as const;

function formatExposureDuration(days: number | undefined): string {
  if (!days && days !== 0) return "Unknown";
  if (days === 0) return "< 1 day";
  if (days === 1) return "1 day";
  if (days < 7) return `${days} days`;
  if (days < 30) return `${Math.floor(days / 7)} weeks`;
  if (days < 365) return `${Math.floor(days / 30)} months`;
  return `${Math.floor(days / 365)} years`;
}

function formatExposureScore(score: number | undefined): string {
  if (!score && score !== 0) return "N/A";
  return score.toFixed(1);
}

function exposureScoreTone(score: number | undefined): string {
  if (!score && score !== 0) return "text-slate-400";
  if (score >= 12) return "text-red-300";
  if (score >= 8) return "text-orange-300";
  if (score >= 4) return "text-yellow-300";
  return "text-green-300";
}

function severityTone(severity: string) {
  switch (severity.toUpperCase()) {
    case "CRITICAL":
      return "border-red-500/30 bg-red-500/15 text-red-100";
    case "HIGH":
      return "border-orange-500/30 bg-orange-500/15 text-orange-100";
    case "MEDIUM":
      return "border-yellow-500/30 bg-yellow-500/15 text-yellow-100";
    default:
      return "border-slate-500/30 bg-slate-500/15 text-slate-100";
  }
}

function filterMatches(filter: (typeof FILTERS)[number], severity: string) {
  if (filter === "All") {
    return true;
  }
  return severity.toUpperCase() === filter.toUpperCase();
}

export default function RepoDetailPage() {
  const router = useRouter();
  const params = useParams<{ id: string }>();
  const repoId = Array.isArray(params.id) ? params.id[0] : params.id;

  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [repo, setRepo] = useState<RepoRow | null>(null);
  const [findings, setFindings] = useState<FindingRow[]>([]);
  const [clusters, setClusters] = useState<ClusterRow[]>([]);
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("All");
  const [sessionToken, setSessionToken] = useState<string | null>(null);

  const apiUrl = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

  useEffect(() => {
    let active = true;

    async function bootstrap() {
      if (!repoId) {
        setError("Repo not found.");
        setLoading(false);
        return;
      }

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
      if (!data.session) {
        router.replace("/login");
        return;
      }

      setSessionToken(data.session.access_token);
      const authHeaders = data.session.access_token
        ? { Authorization: `Bearer ${data.session.access_token}` }
        : undefined;

      let repoData;
      let repoError;
      let findingsResponse: Response;
      let clustersResponse: Response;

      try {
        [{ data: repoData, error: repoError }, findingsResponse, clustersResponse] = await Promise.all([
          supabase.from("repos").select("*").eq("id", repoId).single(),
          fetch(`${apiUrl}/findings/${repoId}`, { headers: authHeaders }),
          fetch(`${apiUrl}/clusters`, { headers: authHeaders }),
        ]);
      } catch (fetchError) {
        if (!active) {
          return;
        }
        setError(fetchError instanceof Error ? fetchError.message : "Failed to fetch repository data.");
        setLoading(false);
        return;
      }

      if (!active) {
        return;
      }

      if (repoError) {
        setError(repoError.message);
        setLoading(false);
        return;
      }

      if (!findingsResponse.ok) {
        setError("Unable to load findings.");
        setLoading(false);
        return;
      }

      if (!clustersResponse.ok) {
        setError("Unable to load clusters.");
        setLoading(false);
        return;
      }

      setRepo(repoData as RepoRow);
      setFindings((await findingsResponse.json()) as FindingRow[]);
      setClusters((await clustersResponse.json()) as ClusterRow[]);
      setLoading(false);
    }

    void bootstrap();
    return () => {
      active = false;
    };
  }, [apiUrl, repoId, router]);

  const clusterMap = useMemo(() => new Map(clusters.map((cluster) => [cluster.secret_hash, cluster])), [clusters]);
  const filteredFindings = useMemo(
    () => findings.filter((finding) => filterMatches(filter, finding.severity)),
    [filter, findings],
  );

  const criticalCount = findings.filter((finding) => finding.severity === "CRITICAL").length;
  const clusterWarnings = findings.filter((finding) => {
    const cluster = clusterMap.get(finding.secret_hash);
    return Boolean(cluster && cluster.repo_count >= 2);
  });
  const crossRepoClusterCount = new Set(clusterWarnings.map((finding) => finding.secret_hash)).size;

  async function handleScanNow() {
    if (!repo) {
      return;
    }

    setBusy(true);
    try {
      const scanResponse = await fetch(`${apiUrl}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
        body: JSON.stringify({ repo_id: repo.id }),
      });

      if (!scanResponse.ok) {
        const payload = (await scanResponse.json().catch(() => null)) as { detail?: string; critical_alert_error?: string } | null;
        throw new Error(payload?.detail || payload?.critical_alert_error || "Failed to start scan.");
      }

      const supabase = getSupabaseClient();
      if (!supabase) {
        return;
      }

      const [{ data: repoData }, findingsResponse, clustersResponse] = await Promise.all([
        supabase.from("repos").select("*").eq("id", repo.id).single(),
        fetch(`${apiUrl}/findings/${repo.id}`, {
          headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : undefined,
        }),
        fetch(`${apiUrl}/clusters`, {
          headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : undefined,
        }),
      ]);

      if (repoData) {
        setRepo(repoData as RepoRow);
      }
      if (findingsResponse.ok) {
        setFindings((await findingsResponse.json()) as FindingRow[]);
      }
      if (clustersResponse.ok) {
        setClusters((await clustersResponse.json()) as ClusterRow[]);
      }
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "Failed to scan repository.");
    } finally {
      setBusy(false);
    }
  }

  async function handleDeleteRepo() {
    if (!repo) {
      return;
    }

    const confirmed = window.confirm(
      `Delete ${repo.owner}/${repo.name}? This will remove the repo, findings, alerts, and notification history from your view.`,
    );
    if (!confirmed) {
      return;
    }

    setDeleteBusy(true);
    try {
      const response = await fetch(`${apiUrl}/repos/${repo.id}`, {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        },
      });

      if (!response.ok) {
        const payload = (await response.json().catch(() => null)) as { detail?: string } | null;
        throw new Error(payload?.detail || "Failed to delete repository.");
      }

      router.replace("/");
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete repository.");
    } finally {
      setDeleteBusy(false);
    }
  }

  if (loading) {
    return (
      <main className="min-h-screen bg-background text-foreground">
        <div className="flex min-h-screen items-center justify-center">
          <div className="flex items-center gap-3 text-muted-foreground">
            <LoaderCircle className="size-5 animate-spin" />
            Loading repo...
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-background text-foreground">
      <AppNavbar />

      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 py-8 sm:px-6 lg:px-8">
        <section className="surface-card flex flex-col gap-4 p-6 shadow-[0_18px_60px_rgba(0,0,0,0.08)] lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-3">
            <Link href="/" className="inline-flex items-center gap-2 text-sm text-muted-foreground transition hover:text-foreground">
              <ArrowLeft className="size-4" />
              Back to repos
            </Link>

            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-3xl font-semibold tracking-tight">
                {repo?.owner}/{repo?.name}
              </h1>
              <a
                href={repo?.github_url || "#"}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 rounded-full border border-border bg-background px-3 py-1 text-xs font-medium text-foreground transition hover:bg-muted"
              >
                GitHub
                <ExternalLink className="size-3.5" />
              </a>
            </div>

            <p className="max-w-3xl text-sm leading-6 text-muted-foreground">
              Repository monitoring status: <span className="font-semibold text-foreground">{repo?.status}</span>
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={handleDeleteRepo}
              disabled={deleteBusy}
              className="inline-flex items-center gap-2 rounded-2xl border border-destructive/20 bg-destructive/10 px-5 py-3 text-sm font-semibold text-destructive transition hover:bg-destructive/20 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {deleteBusy ? <LoaderCircle className="size-4 animate-spin" /> : <Trash2 className="size-4" />}
              Delete Repo
            </button>

            <button
              type="button"
              onClick={handleScanNow}
              disabled={busy}
              className="inline-flex items-center gap-2 rounded-2xl bg-primary px-5 py-3 text-sm font-semibold text-primary-foreground transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {busy ? <LoaderCircle className="size-4 animate-spin" /> : <ScanSearch className="size-4" />}
              Scan Now
            </button>
          </div>
        </section>

        {repo?.ai_reasoning ? (
          <section className="rounded-3xl border border-cyan-400/20 bg-slate-950/80 p-6 shadow-lg shadow-black/10">
            <div className="flex items-center gap-2 text-cyan-200">
              <Sparkles className="size-5" />
              <span className="text-sm font-semibold uppercase tracking-[0.18em]">Groq Analysis</span>
            </div>
            <p className="mt-4 text-sm leading-7 text-slate-200">{repo.ai_reasoning}</p>
          </section>
        ) : null}

        <section className="grid gap-4 md:grid-cols-3">
          <div className="rounded-2xl border border-white/10 bg-slate-950/75 p-5">
            <div className="text-xs uppercase tracking-[0.18em] text-slate-400">Total Secrets</div>
            <div className="mt-2 text-3xl font-semibold">{findings.length}</div>
          </div>
          <div className="rounded-2xl border border-white/10 bg-slate-950/75 p-5">
            <div className="text-xs uppercase tracking-[0.18em] text-slate-400">Critical</div>
            <div className="mt-2 text-3xl font-semibold text-red-300">{criticalCount}</div>
          </div>
          <div className="rounded-2xl border border-white/10 bg-slate-950/75 p-5">
            <div className="text-xs uppercase tracking-[0.18em] text-slate-400">Cross-repo Clusters</div>
            <div className="mt-2 text-3xl font-semibold text-amber-300">{crossRepoClusterCount}</div>
          </div>
        </section>

        {clusterWarnings.length > 0 ? (
          <div className="rounded-2xl border border-yellow-500/20 bg-yellow-500/10 p-4 text-sm text-yellow-100">
            <div className="flex items-center gap-2 font-semibold">
              <AlertTriangle className="size-4" />
              {clusterWarnings.length} secret(s) in this repo also appear in other monitored repos.
            </div>
            <Link href="/clusters" className="mt-2 inline-flex text-sm font-medium text-yellow-100 underline underline-offset-4">
              View Clusters →
            </Link>
          </div>
        ) : null}

        <section className="rounded-3xl border border-white/10 bg-slate-950/75 shadow-lg shadow-black/10">
          <div className="flex flex-wrap items-center gap-2 border-b border-white/10 p-4">
            {FILTERS.map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => setFilter(item)}
                className={`rounded-full px-4 py-2 text-sm font-medium transition ${
                  filter === item
                    ? "bg-cyan-400 text-slate-950"
                    : "border border-white/10 bg-white/5 text-slate-200 hover:bg-white/10"
                }`}
              >
                {item}
              </button>
            ))}
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-white/10 bg-white/5 text-slate-300">
                <tr>
                  <th className="px-5 py-4 font-medium">Severity</th>
                  <th className="px-5 py-4 font-medium">Type</th>
                  <th className="px-5 py-4 font-medium">File</th>
                  <th className="px-5 py-4 font-medium">Line</th>
                  <th className="px-5 py-4 font-medium">Snippet</th>
                  <th className="px-5 py-4 font-medium">Exposure Time</th>
                  <th className="px-5 py-4 font-medium">Exposure Score</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.length ? (
                  filteredFindings.map((finding) => (
                    <tr key={finding.id} className="border-b border-white/5 last:border-b-0">
                      <td className="px-5 py-4 align-top">
                        <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${severityTone(finding.severity)}`}>
                          {finding.severity}
                        </span>
                      </td>
                      <td className="px-5 py-4 align-top text-slate-100">{finding.secret_type}</td>
                      <td className="px-5 py-4 align-top">
                        <code className="block max-w-[18rem] truncate font-mono text-xs text-slate-300" title={finding.file_path}>
                          {finding.file_path}
                        </code>
                      </td>
                      <td className="px-5 py-4 align-top text-slate-300">{finding.line_number}</td>
                      <td className="px-5 py-4 align-top">
                        <code className="block max-w-[28rem] truncate font-mono text-xs text-slate-300" title={finding.snippet}>
                          {finding.snippet}
                        </code>
                      </td>
                      <td className="px-5 py-4 align-top text-xs text-slate-300" title={finding.first_commit_date}>
                        {formatExposureDuration(finding.exposure_days)}
                      </td>
                      <td className={`px-5 py-4 align-top text-xs font-semibold ${exposureScoreTone(finding.exposure_score)}`}>
                        {formatExposureScore(finding.exposure_score)}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="px-5 py-10 text-center text-sm text-slate-400">
                      No findings match the current filter.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </main>
  );
}

"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, LoaderCircle } from "lucide-react";

import { AppNavbar } from "@/components/app-navbar";
import { formatRelativeTime } from "@/lib/github";
import { getSupabaseClient, isSupabaseConfigured } from "@/lib/supabase";

type ClusterRow = {
  id: string;
  secret_hash: string;
  secret_type: string;
  repo_count: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
  created_at: string;
};

function severityTone(severity: string) {
  switch (severity) {
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

export default function ClustersPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [clusters, setClusters] = useState<ClusterRow[]>([]);

  const apiUrl = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

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
      if (!data.session) {
        router.replace("/login");
        return;
      }
      const sessionToken = data.session.access_token;

      const response = await fetch(`${apiUrl}/clusters`, {
        headers: sessionToken ? { Authorization: `Bearer ${sessionToken}` } : undefined,
      });
      if (!response.ok) {
        setError("Unable to load clusters.");
        setLoading(false);
        return;
      }

      const payload = (await response.json()) as ClusterRow[];
      if (active) {
        setClusters(payload);
        setLoading(false);
      }
    }

    void bootstrap();
    return () => {
      active = false;
    };
  }, [apiUrl, router]);

  if (loading) {
    return (
      <main className="min-h-screen bg-slate-950 text-slate-50">
        <div className="flex min-h-screen items-center justify-center">
          <div className="flex items-center gap-3 text-slate-300">
            <LoaderCircle className="size-5 animate-spin" />
            Loading clusters...
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(20,34,66,0.75),_rgba(5,10,18,1)_55%)] text-slate-50">
      <AppNavbar />

      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 py-8 sm:px-6 lg:px-8">
        <section className="rounded-3xl border border-white/10 bg-white/5 p-6 shadow-2xl shadow-black/15 backdrop-blur">
          <h1 className="text-3xl font-semibold tracking-tight">Cross-repo clusters</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">
            A cluster means the exact same secret key was found in multiple repos. Rotate it immediately.
          </p>
        </section>

        {error ? (
          <div className="rounded-2xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-100">
            {error}
          </div>
        ) : null}

        {!clusters.length ? (
          <div className="rounded-3xl border border-emerald-500/20 bg-emerald-500/10 p-6 text-emerald-100">
            <div className="flex items-center gap-3 font-semibold">
              <AlertTriangle className="size-5" />
              No cross-repo clusters yet.
            </div>
            <p className="mt-2 text-sm text-emerald-100/80">
              When the same secret appears in more than one repo, it will show up here.
            </p>
          </div>
        ) : (
          <div className="overflow-hidden rounded-3xl border border-white/10 bg-slate-950/75 shadow-lg shadow-black/10">
            <div className="overflow-x-auto">
              <table className="min-w-full text-left text-sm">
                <thead className="border-b border-white/10 bg-white/5 text-slate-300">
                  <tr>
                    <th className="px-5 py-4 font-medium">Secret Type</th>
                    <th className="px-5 py-4 font-medium">Severity</th>
                    <th className="px-5 py-4 font-medium">Repos Affected</th>
                    <th className="px-5 py-4 font-medium">First Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {clusters.map((cluster) => (
                    <tr
                      key={cluster.id}
                      className={`border-b border-white/5 last:border-b-0 ${
                        cluster.repo_count >= 3 ? "bg-red-500/10" : ""
                      }`}
                    >
                      <td className="px-5 py-4 font-medium text-slate-50">{cluster.secret_type}</td>
                      <td className="px-5 py-4">
                        <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${severityTone(cluster.severity)}`}>
                          {cluster.severity}
                        </span>
                      </td>
                      <td className="px-5 py-4 text-slate-200">{cluster.repo_count}</td>
                      <td className="px-5 py-4 text-slate-300">{formatRelativeTime(cluster.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}

"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Plus, RefreshCcw, Search, Users } from "lucide-react";

import { SeverityBadge } from "@/components/findings/severity-badge";
import { useAuth } from "@/components/providers/auth-provider";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  createCase,
  getCases,
  getThreatTimeline,
  isApiConfigured,
  type CaseCreatePayload,
  type CaseSummary,
} from "@/lib/api";
import { cn } from "@/lib/utils";

type CreateDraft = {
  alertIds: string[];
  assignedAnalyst: string;
  description: string;
  findingIds: string[];
  severity: CaseCreatePayload["severity"];
  status: NonNullable<CaseCreatePayload["status"]>;
  tags: string;
  title: string;
};

const statusOptions: Array<{ label: string; value: CaseSummary["status"] | "ALL" }> = [
  { label: "All", value: "ALL" },
  { label: "Open", value: "OPEN" },
  { label: "Investigating", value: "INVESTIGATING" },
  { label: "Contained", value: "CONTAINED" },
  { label: "Resolved", value: "RESOLVED" },
  { label: "False positive", value: "FALSE_POSITIVE" },
];

const severityOptions: Array<{ label: string; value: CaseSummary["severity"] | "ALL" }> = [
  { label: "All", value: "ALL" },
  { label: "Critical", value: "CRITICAL" },
  { label: "High", value: "HIGH" },
  { label: "Medium", value: "MEDIUM" },
  { label: "Low", value: "LOW" },
];

const statusClasses: Record<CaseSummary["status"], string> = {
  OPEN: "border-slate-500/20 bg-slate-500/10 text-slate-200",
  INVESTIGATING: "border-amber-500/20 bg-amber-500/10 text-amber-100",
  CONTAINED: "border-cyan-500/20 bg-cyan-500/10 text-cyan-100",
  RESOLVED: "border-emerald-500/20 bg-emerald-500/10 text-emerald-100",
  FALSE_POSITIVE: "border-border bg-muted text-muted-foreground",
};

function formatTimestamp(timestamp: string) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function parseCsv(value: string) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function statusBadge(status: CaseSummary["status"]) {
  return (
    <span
      className={cn(
        "inline-flex rounded-full border px-2.5 py-1 text-xs font-medium",
        statusClasses[status],
      )}
    >
      {status.replaceAll("_", " ")}
    </span>
  );
}

function CreateCaseModal({
  draft,
  isOpen,
  onClose,
  onChange,
  onSubmit,
  isSubmitting,
}: {
  draft: CreateDraft;
  isOpen: boolean;
  isSubmitting: boolean;
  onClose: () => void;
  onChange: (next: CreateDraft) => void;
  onSubmit: (next: CreateDraft) => void;
}) {
  if (!isOpen) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 py-8">
      <div className="w-full max-w-2xl rounded-[var(--radius)] border border-border bg-card shadow-2xl">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <div>
            <div className="text-lg font-semibold text-foreground">Create Case</div>
            <p className="text-sm text-muted-foreground">
              Bundle related findings, alerts, and timeline events into one investigation.
            </p>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>

        <form
          className="grid gap-4 px-5 py-5"
          onSubmit={(event) => {
            event.preventDefault();
            onSubmit(draft);
          }}
        >
          <div className="grid gap-4 md:grid-cols-2">
            <label className="grid gap-2 text-sm">
              <span className="text-muted-foreground">Title</span>
            <input
              className="h-11 rounded-[var(--radius)] border border-border bg-background px-3 text-sm text-foreground outline-none focus:border-ring"
              value={draft.title}
              onChange={(event) => onChange({ ...draft, title: event.target.value })}
              placeholder="Incident title"
            />
          </label>
          <label className="grid gap-2 text-sm">
            <span className="text-muted-foreground">Assigned analyst</span>
            <input
              className="h-11 rounded-[var(--radius)] border border-border bg-background px-3 text-sm text-foreground outline-none focus:border-ring"
              value={draft.assignedAnalyst}
              onChange={(event) => onChange({ ...draft, assignedAnalyst: event.target.value })}
              placeholder="Optional assignee"
            />
          </label>
          </div>

          <div className="grid gap-4 md:grid-cols-3">
            <label className="grid gap-2 text-sm">
              <span className="text-muted-foreground">Severity</span>
              <select
              className="h-11 rounded-[var(--radius)] border border-border bg-background px-3 text-sm text-foreground outline-none focus:border-ring"
              value={draft.severity}
              onChange={(event) =>
                  onChange({ ...draft, severity: event.target.value as CaseCreatePayload["severity"] })
              }
            >
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </label>
            <label className="grid gap-2 text-sm">
              <span className="text-muted-foreground">Status</span>
              <select
              className="h-11 rounded-[var(--radius)] border border-border bg-background px-3 text-sm text-foreground outline-none focus:border-ring"
              value={draft.status}
                onChange={(event) => onChange({ ...draft, status: event.target.value as CreateDraft["status"] })}
              >
                <option value="OPEN">Open</option>
                <option value="INVESTIGATING">Investigating</option>
                <option value="CONTAINED">Contained</option>
                <option value="RESOLVED">Resolved</option>
                <option value="FALSE_POSITIVE">False positive</option>
              </select>
            </label>
            <label className="grid gap-2 text-sm">
              <span className="text-muted-foreground">Tags</span>
              <input
              className="h-11 rounded-[var(--radius)] border border-border bg-background px-3 text-sm text-foreground outline-none focus:border-ring"
              value={draft.tags}
                onChange={(event) => onChange({ ...draft, tags: event.target.value })}
              placeholder="phishing, github, api"
            />
          </label>
          </div>

          <label className="grid gap-2 text-sm">
            <span className="text-muted-foreground">Description</span>
            <textarea
            className="min-h-28 rounded-[var(--radius)] border border-border bg-background px-3 py-2 text-sm text-foreground outline-none focus:border-ring"
              value={draft.description}
              onChange={(event) => onChange({ ...draft, description: event.target.value })}
              placeholder="Short incident summary"
            />
          </label>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-[var(--radius)] border border-border bg-background p-3 text-sm text-muted-foreground">
              <div className="font-medium text-foreground">Linked findings</div>
              <div className="mt-1 break-all">{draft.findingIds.join(", ") || "None"}</div>
            </div>
            <div className="rounded-[var(--radius)] border border-border bg-background p-3 text-sm text-muted-foreground">
              <div className="font-medium text-foreground">Linked alerts</div>
              <div className="mt-1 break-all">{draft.alertIds.join(", ") || "None"}</div>
            </div>
          </div>

          <div className="flex items-center justify-end gap-2">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={isSubmitting}>
              <Plus className="size-4" />
              Create case
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

function CaseCard({ item }: { item: CaseSummary }) {
  return (
    <Link
      href={`/cases/${item.id}`}
      className="block rounded-[var(--radius)] border border-border bg-card p-4 transition-colors hover:bg-accent/60"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={item.severity} />
            {statusBadge(item.status)}
          </div>
          <div className="text-base font-semibold text-foreground">{item.title}</div>
          <p className="line-clamp-2 text-sm leading-6 text-muted-foreground">
            {item.description || "No description provided."}
          </p>
        </div>
        <div className="text-xs text-muted-foreground">{formatTimestamp(item.updated_at)}</div>
      </div>

      <div className="mt-4 flex flex-wrap gap-2 text-xs text-muted-foreground">
        <span className="rounded-full border border-border px-2.5 py-1">{item.assigned_analyst || "Unassigned"}</span>
        <span className="rounded-full border border-border px-2.5 py-1">{item.finding_count} findings</span>
        <span className="rounded-full border border-border px-2.5 py-1">{item.alert_count} alerts</span>
        <span className="rounded-full border border-border px-2.5 py-1">{item.note_count} notes</span>
        {item.tags.length ? (
          <span className="rounded-full border border-border px-2.5 py-1">{item.tags.join(", ")}</span>
        ) : null}
      </div>
    </Link>
  );
}

export default function CasesPage() {
  const { status: authStatus } = useAuth();
  const router = useRouter();
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<CaseSummary["status"] | "ALL">("ALL");
  const [severityFilter, setSeverityFilter] = useState<CaseSummary["severity"] | "ALL">("ALL");
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [draft, setDraft] = useState<CreateDraft>({
    alertIds: [],
    assignedAnalyst: "",
    description: "",
    findingIds: [],
    severity: "HIGH",
    status: "OPEN",
    tags: "",
    title: "",
  });

  useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search);
    const title = searchParams.get("title") ?? "New investigation case";
    const description = searchParams.get("description") ?? "";
    const findingIds = searchParams.getAll("finding_id");
    const alertIds = searchParams.getAll("alert_id");
    const clusterId = searchParams.get("cluster_id");

    async function hydratePrefill() {
      let nextFindingIds = findingIds;
      let nextAlertIds = alertIds;

      if (clusterId) {
        try {
          const timeline = await getThreatTimeline({ range: "all", groupBy: "cluster" });
          const cluster = timeline.clusters.find((item) => item.cluster_id === clusterId);
          if (cluster) {
            nextFindingIds = Array.from(new Set([...(nextFindingIds ?? []), ...cluster.finding_ids]));
            nextAlertIds = Array.from(new Set([...(nextAlertIds ?? []), ...cluster.alert_ids]));
          }
        } catch {
          // Ignore timeline hydration failures and keep the direct ids.
        }
      }

      if (findingIds.length || alertIds.length || clusterId) {
        setDraft({
          alertIds: nextAlertIds,
          assignedAnalyst: "",
          description,
          findingIds: nextFindingIds,
          severity: "HIGH",
          status: "OPEN",
          tags: clusterId ? "timeline" : "",
          title,
        });
        setIsCreateOpen(true);
      }
    }

    void hydratePrefill();
  }, []);

  useEffect(() => {
    let active = true;

    async function loadCases() {
      if (authStatus === "loading") {
        return;
      }

      if (authStatus !== "authenticated") {
        if (active) {
          setIsLoading(false);
        }
        return;
      }

      if (!isApiConfigured) {
        if (active) {
          setError("Set NEXT_PUBLIC_API_URL in frontend/.env.local to load cases.");
          setIsLoading(false);
        }
        return;
      }

      try {
        setIsLoading(true);
        setError(null);
        const response = await getCases({
          pageSize: 100,
          search,
          severity: severityFilter === "ALL" ? undefined : severityFilter,
          status: statusFilter,
        });
        if (active) {
          setCases(response.items);
        }
      } catch (loadError) {
        if (active) {
          setCases([]);
          setError(loadError instanceof Error ? loadError.message : "Unable to load cases.");
        }
      } finally {
        if (active) {
          setIsLoading(false);
        }
      }
    }

    loadCases();
    return () => {
      active = false;
    };
  }, [authStatus, search, severityFilter, statusFilter, isRefreshing]);

  const metrics = useMemo(
    () => ({
      open: cases.filter((item) => item.status === "OPEN").length,
      investigating: cases.filter((item) => item.status === "INVESTIGATING").length,
      contained: cases.filter((item) => item.status === "CONTAINED").length,
    }),
    [cases],
  );

  async function submitCase(nextDraft: CreateDraft) {
    setDraft(nextDraft);
    if (!nextDraft.title.trim()) {
      setError("Case title is required.");
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      const created = await createCase({
        alert_ids: nextDraft.alertIds,
        assigned_analyst: nextDraft.assignedAnalyst || null,
        description: nextDraft.description || null,
        finding_ids: nextDraft.findingIds,
        severity: nextDraft.severity,
        status: nextDraft.status,
        tags: parseCsv(nextDraft.tags),
        title: nextDraft.title,
      });
      setIsCreateOpen(false);
      router.push(`/cases/${created.id}`);
    } catch (createError) {
      setError(createError instanceof Error ? createError.message : "Failed to create case.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <section className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Open cases</CardTitle>
          </CardHeader>
          <CardContent className="text-3xl font-semibold text-foreground">{metrics.open}</CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Investigating</CardTitle>
          </CardHeader>
          <CardContent className="text-3xl font-semibold text-foreground">{metrics.investigating}</CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Contained</CardTitle>
          </CardHeader>
          <CardContent className="text-3xl font-semibold text-foreground">{metrics.contained}</CardContent>
        </Card>
      </section>

      <Card>
        <CardHeader className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <CardTitle className="text-2xl">Cases</CardTitle>
            <p className="text-sm text-muted-foreground">
              Lightweight incident case management for findings, alerts, and timeline activity.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => setIsRefreshing((current) => !current)}>
              <RefreshCcw className="size-4" />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setIsCreateOpen(true)}>
              <Plus className="size-4" />
              Create Case
            </Button>
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto_auto]">
            <label className="relative block">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search cases"
                className="h-11 w-full rounded-[var(--radius)] border border-border bg-background pl-9 pr-3 text-sm text-foreground outline-none focus:border-ring"
              />
            </label>
            <select
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value as CaseSummary["status"] | "ALL")}
              className="h-11 rounded-[var(--radius)] border border-border bg-background px-3 text-sm text-foreground outline-none focus:border-ring"
            >
              {statusOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            <select
              value={severityFilter}
              onChange={(event) => setSeverityFilter(event.target.value as CaseSummary["severity"] | "ALL")}
              className="h-11 rounded-[var(--radius)] border border-border bg-background px-3 text-sm text-foreground outline-none focus:border-ring"
            >
              {severityOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>

          {error ? (
            <div className="rounded-[var(--radius)] border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-200">
              {error}
            </div>
          ) : null}

          {isLoading ? (
            <div className="space-y-3">
              <CaseSkeleton />
              <CaseSkeleton />
              <CaseSkeleton />
            </div>
          ) : cases.length > 0 ? (
            <div className="grid gap-3">
              {cases.map((item) => (
                <CaseCard key={item.id} item={item} />
              ))}
            </div>
          ) : (
            <div className="flex min-h-[260px] flex-col items-center justify-center rounded-[var(--radius)] border border-dashed border-border px-6 text-center">
              <Users className="size-10 text-muted-foreground" />
              <h3 className="mt-4 text-lg font-semibold text-foreground">No cases yet</h3>
              <p className="mt-2 max-w-lg text-sm leading-6 text-muted-foreground">
                Create an investigation case from a finding, alert, or timeline cluster to start tracking the response.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <CreateCaseModal
        draft={draft}
        isOpen={isCreateOpen}
        isSubmitting={isSubmitting}
        onClose={() => setIsCreateOpen(false)}
        onChange={setDraft}
        onSubmit={submitCase}
      />
    </div>
  );
}

function CaseSkeleton() {
  return (
    <div className="rounded-[var(--radius)] border border-border bg-card p-4">
      <div className="h-5 w-32 rounded-full bg-muted" />
      <div className="mt-3 h-4 w-5/6 rounded-full bg-muted" />
      <div className="mt-2 h-4 w-2/3 rounded-full bg-muted" />
    </div>
  );
}

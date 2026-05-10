"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  CalendarRange,
  CheckCircle2,
  Eye,
  MessageSquarePlus,
  Plus,
  RefreshCcw,
  Workflow,
} from "lucide-react";

import { SeverityBadge } from "@/components/findings/severity-badge";
import { useAuth } from "@/components/providers/auth-provider";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  addCaseNote,
  attachCaseAlerts,
  attachCaseFindings,
  getCase,
  isApiConfigured,
  updateCase,
  type CaseDetail,
  type CaseStatus,
} from "@/lib/api";
import { cn } from "@/lib/utils";

const statusClasses: Record<CaseStatus, string> = {
  OPEN: "border-slate-500/20 bg-slate-500/10 text-slate-200",
  INVESTIGATING: "border-amber-500/20 bg-amber-500/10 text-amber-100",
  CONTAINED: "border-cyan-500/20 bg-cyan-500/10 text-cyan-100",
  RESOLVED: "border-emerald-500/20 bg-emerald-500/10 text-emerald-100",
  FALSE_POSITIVE: "border-border bg-muted text-muted-foreground",
};

const statusOptions: CaseStatus[] = [
  "OPEN",
  "INVESTIGATING",
  "CONTAINED",
  "RESOLVED",
  "FALSE_POSITIVE",
];

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

function statusBadge(status: CaseStatus) {
  return (
    <span className={cn("inline-flex rounded-full border px-2.5 py-1 text-xs font-medium", statusClasses[status])}>
      {status.replaceAll("_", " ")}
    </span>
  );
}

function parseCsv(value: string) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export default function CaseDetailPage({ params }: { params: { caseId: string } }) {
  const { status: authStatus } = useAuth();
  const [caseDetail, setCaseDetail] = useState<CaseDetail | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [noteBody, setNoteBody] = useState("");
  const [findingIds, setFindingIds] = useState("");
  const [alertIds, setAlertIds] = useState("");
  const [editForm, setEditForm] = useState({
    assigned_analyst: "",
    description: "",
    severity: "HIGH" as CaseDetail["severity"],
    status: "OPEN" as CaseStatus,
    tags: "",
    title: "",
  });

  const loadCase = useCallback(async () => {
    if (authStatus === "loading") {
      return;
    }

    if (authStatus !== "authenticated") {
      setIsLoading(false);
      return;
    }

    if (!isApiConfigured) {
      setError("Set NEXT_PUBLIC_API_URL in frontend/.env.local to load the case detail.");
      setIsLoading(false);
      return;
    }

    try {
      setIsLoading(true);
      setError(null);
      const payload = await getCase(params.caseId);
      setCaseDetail(payload);
      setEditForm({
        assigned_analyst: payload.assigned_analyst || "",
        description: payload.description || "",
        severity: payload.severity,
        status: payload.status,
        tags: payload.tags.join(", "),
        title: payload.title,
      });
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Unable to load case.");
    } finally {
      setIsLoading(false);
    }
  }, [authStatus, params.caseId]);

  useEffect(() => {
    void (async () => {
      await loadCase();
    })();
  }, [loadCase]);

  const linkedClusters = caseDetail?.related_clusters ?? [];
  const activity = useMemo(() => caseDetail?.activity_timeline ?? [], [caseDetail]);

  async function saveCase() {
    if (!caseDetail) {
      return;
    }

    setIsSaving(true);
    setError(null);
    try {
      const updated = await updateCase(caseDetail.id, {
        assigned_analyst: editForm.assigned_analyst || null,
        description: editForm.description || null,
        severity: editForm.severity,
        status: editForm.status,
        tags: parseCsv(editForm.tags),
        title: editForm.title,
      });
      setCaseDetail(updated);
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : "Unable to update case.");
    } finally {
      setIsSaving(false);
    }
  }

  async function appendNote() {
    if (!caseDetail || !noteBody.trim()) {
      return;
    }

    setIsSaving(true);
    setError(null);
    try {
      await addCaseNote(caseDetail.id, noteBody.trim());
      const refreshed = await getCase(caseDetail.id);
      setCaseDetail(refreshed);
      setNoteBody("");
    } catch (noteError) {
      setError(noteError instanceof Error ? noteError.message : "Unable to add note.");
    } finally {
      setIsSaving(false);
    }
  }

  async function attachFindings() {
    if (!caseDetail) {
      return;
    }

    const ids = parseCsv(findingIds);
    if (!ids.length) {
      return;
    }

    setIsSaving(true);
    setError(null);
    try {
      const refreshed = await attachCaseFindings(caseDetail.id, ids);
      setCaseDetail(refreshed);
      setFindingIds("");
    } catch (attachError) {
      setError(attachError instanceof Error ? attachError.message : "Unable to attach findings.");
    } finally {
      setIsSaving(false);
    }
  }

  async function attachAlerts() {
    if (!caseDetail) {
      return;
    }

    const ids = parseCsv(alertIds);
    if (!ids.length) {
      return;
    }

    setIsSaving(true);
    setError(null);
    try {
      const refreshed = await attachCaseAlerts(caseDetail.id, ids);
      setCaseDetail(refreshed);
      setAlertIds("");
    } catch (attachError) {
      setError(attachError instanceof Error ? attachError.message : "Unable to attach alerts.");
    } finally {
      setIsSaving(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-3">
        <Button variant="outline" size="sm" asChild>
          <Link href="/cases">
            <ArrowLeft className="size-4" />
            Back to cases
          </Link>
        </Button>
        <Button variant="outline" size="sm" onClick={() => void loadCase()}>
          <RefreshCcw className="size-4" />
          Refresh
        </Button>
      </div>

      {error ? (
        <Card className="border-red-500/20">
          <CardContent className="px-5 py-4 text-sm text-red-200">{error}</CardContent>
        </Card>
      ) : null}

      {isLoading ? (
        <Card>
          <CardContent className="px-5 py-12 text-sm text-muted-foreground">Loading case detail...</CardContent>
        </Card>
      ) : caseDetail ? (
        <section className="grid gap-6 xl:grid-cols-[minmax(0,1.1fr)_minmax(340px,0.9fr)]">
          <div className="flex flex-col gap-4">
            <Card>
              <CardHeader className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={caseDetail.severity} />
                    {statusBadge(caseDetail.status)}
                  </div>
                  <CardTitle className="text-2xl">{caseDetail.title}</CardTitle>
                  <p className="text-sm leading-6 text-muted-foreground">
                    {caseDetail.description || "No case description provided."}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  {caseDetail.tags.map((tag) => (
                    <span key={tag} className="rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground">
                      {tag}
                    </span>
                  ))}
                </div>
              </CardHeader>
              <CardContent className="grid gap-4 md:grid-cols-4">
                <Stat label="Assigned" value={caseDetail.assigned_analyst || "Unassigned"} />
                <Stat label="Findings" value={String(caseDetail.finding_count)} />
                <Stat label="Alerts" value={String(caseDetail.alert_count)} />
                <Stat label="Clusters" value={String(caseDetail.cluster_count)} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Workflow className="size-4 text-muted-foreground" />
                  Case controls
                </CardTitle>
              </CardHeader>
              <CardContent className="grid gap-4 md:grid-cols-2">
                <label className="grid gap-2 text-sm">
                  <span className="text-muted-foreground">Title</span>
                  <input
                    value={editForm.title}
                    onChange={(event) => setEditForm((current) => ({ ...current, title: event.target.value }))}
                    className="h-11 rounded-[var(--radius)] border border-border bg-background px-3 text-sm outline-none focus:border-ring"
                  />
                </label>
                <label className="grid gap-2 text-sm">
                  <span className="text-muted-foreground">Assigned analyst</span>
                  <input
                    value={editForm.assigned_analyst}
                    onChange={(event) =>
                      setEditForm((current) => ({ ...current, assigned_analyst: event.target.value }))
                    }
                    className="h-11 rounded-[var(--radius)] border border-border bg-background px-3 text-sm outline-none focus:border-ring"
                  />
                </label>
                <label className="grid gap-2 text-sm">
                  <span className="text-muted-foreground">Severity</span>
                  <select
                    value={editForm.severity}
                    onChange={(event) =>
                      setEditForm((current) => ({ ...current, severity: event.target.value as CaseDetail["severity"] }))
                    }
                    className="h-11 rounded-[var(--radius)] border border-border bg-background px-3 text-sm outline-none focus:border-ring"
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
                    value={editForm.status}
                    onChange={(event) => setEditForm((current) => ({ ...current, status: event.target.value as CaseStatus }))}
                    className="h-11 rounded-[var(--radius)] border border-border bg-background px-3 text-sm outline-none focus:border-ring"
                  >
                    {statusOptions.map((status) => (
                      <option key={status} value={status}>
                        {status.replaceAll("_", " ")}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="grid gap-2 text-sm md:col-span-2">
                  <span className="text-muted-foreground">Tags</span>
                  <input
                    value={editForm.tags}
                    onChange={(event) => setEditForm((current) => ({ ...current, tags: event.target.value }))}
                    className="h-11 rounded-[var(--radius)] border border-border bg-background px-3 text-sm outline-none focus:border-ring"
                    placeholder="phishing, github, api"
                  />
                </label>
                <label className="grid gap-2 text-sm md:col-span-2">
                  <span className="text-muted-foreground">Description</span>
                  <textarea
                    value={editForm.description}
                    onChange={(event) => setEditForm((current) => ({ ...current, description: event.target.value }))}
                    className="min-h-28 rounded-[var(--radius)] border border-border bg-background px-3 py-2 text-sm outline-none focus:border-ring"
                  />
                </label>
                <div className="md:col-span-2 flex justify-end">
                  <Button onClick={() => void saveCase()} disabled={isSaving}>
                    <CheckCircle2 className="size-4" />
                    Save changes
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Eye className="size-4 text-muted-foreground" />
                  Related clusters
                </CardTitle>
              </CardHeader>
              <CardContent className="grid gap-3">
                {linkedClusters.length > 0 ? (
                  linkedClusters.map((cluster) => (
                    <div key={cluster.cluster_id} className="rounded-[var(--radius)] border border-border bg-card p-4">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-medium text-foreground">{cluster.label}</span>
                        <SeverityBadge severity={cluster.severity} />
                      </div>
                      <div className="mt-2 text-sm text-muted-foreground">
                        {cluster.finding_count} findings, {cluster.alert_count} alerts, {cluster.incident_count} incidents
                      </div>
                      <div className="mt-2 text-xs text-muted-foreground">
                        Similarity {(cluster.average_similarity * 100).toFixed(0)}%
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="rounded-[var(--radius)] border border-dashed border-border px-4 py-8 text-sm text-muted-foreground">
                    No related clusters linked yet.
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <CalendarRange className="size-4 text-muted-foreground" />
                  Activity timeline
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {activity.length > 0 ? (
                  activity.map((item) => (
                    <div key={item.id} className="rounded-[var(--radius)] border border-border bg-card p-4">
                      <div className="flex flex-wrap items-center gap-2">
                        {item.severity ? <SeverityBadge severity={item.severity} /> : null}
                        <span className="text-xs text-muted-foreground">{item.activity_type.replaceAll("_", " ")}</span>
                        <span className="text-xs text-muted-foreground">{formatTimestamp(item.timestamp)}</span>
                      </div>
                      <div className="mt-2 text-sm font-medium text-foreground">{item.title}</div>
                      <p className="mt-1 text-sm leading-6 text-muted-foreground">{item.summary || "No summary."}</p>
                    </div>
                  ))
                ) : (
                  <div className="rounded-[var(--radius)] border border-dashed border-border px-4 py-8 text-sm text-muted-foreground">
                    No activity timeline available.
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <div className="flex flex-col gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <MessageSquarePlus className="size-4 text-muted-foreground" />
                  Notes
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <textarea
                  value={noteBody}
                  onChange={(event) => setNoteBody(event.target.value)}
                  placeholder="Write an analyst note..."
                  className="min-h-28 w-full rounded-[var(--radius)] border border-border bg-background px-3 py-2 text-sm outline-none focus:border-ring"
                />
                <div className="flex justify-end">
                  <Button onClick={() => void appendNote()} disabled={isSaving || !noteBody.trim()}>
                    Add note
                  </Button>
                </div>
                <div className="space-y-3">
                  {caseDetail.notes.length > 0 ? (
                    caseDetail.notes.map((note) => (
                      <div key={note.id} className="rounded-[var(--radius)] border border-border bg-background p-3">
                        <div className="flex items-center justify-between gap-2">
                          <div className="text-sm font-medium text-foreground">{note.author}</div>
                          <div className="text-xs text-muted-foreground">{formatTimestamp(note.created_at)}</div>
                        </div>
                        <p className="mt-2 text-sm leading-6 text-muted-foreground">{note.body}</p>
                      </div>
                    ))
                  ) : (
                    <div className="text-sm text-muted-foreground">No notes yet.</div>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Plus className="size-4 text-muted-foreground" />
                  Attach findings
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <input
                  value={findingIds}
                  onChange={(event) => setFindingIds(event.target.value)}
                  placeholder="Comma-separated finding IDs"
                  className="h-11 w-full rounded-[var(--radius)] border border-border bg-background px-3 text-sm outline-none focus:border-ring"
                />
                <Button onClick={() => void attachFindings()} disabled={isSaving || !findingIds.trim()}>
                  Attach findings
                </Button>
                <div className="space-y-2">
                  {caseDetail.linked_findings.length > 0 ? (
                    caseDetail.linked_findings.map((finding) => (
                      <div key={finding.id} className="rounded-[var(--radius)] border border-border bg-background p-3">
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={finding.severity} />
                          <span className="text-xs text-muted-foreground">{finding.pattern_type}</span>
                        </div>
                        <div className="mt-2 break-all font-mono text-xs text-muted-foreground">
                          {finding.matched_value}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-sm text-muted-foreground">No linked findings.</div>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Plus className="size-4 text-muted-foreground" />
                  Attach alerts
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <input
                  value={alertIds}
                  onChange={(event) => setAlertIds(event.target.value)}
                  placeholder="Comma-separated alert IDs"
                  className="h-11 w-full rounded-[var(--radius)] border border-border bg-background px-3 text-sm outline-none focus:border-ring"
                />
                <Button onClick={() => void attachAlerts()} disabled={isSaving || !alertIds.trim()}>
                  Attach alerts
                </Button>
                <div className="space-y-2">
                  {caseDetail.linked_alerts.length > 0 ? (
                    caseDetail.linked_alerts.map((alert) => (
                      <div key={alert.id} className="rounded-[var(--radius)] border border-border bg-background p-3">
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={alert.severity} />
                          <span className="text-xs text-muted-foreground">{alert.title}</span>
                        </div>
                        <div className="mt-2 text-sm leading-6 text-muted-foreground">{alert.message}</div>
                      </div>
                    ))
                  ) : (
                    <div className="text-sm text-muted-foreground">No linked alerts.</div>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </section>
      ) : (
        <Card>
          <CardContent className="px-5 py-12 text-sm text-muted-foreground">Case not found.</CardContent>
        </Card>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-[var(--radius)] border border-border bg-background p-3">
      <div className="text-xs uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
      <div className="mt-2 text-sm font-medium text-foreground">{value}</div>
    </div>
  );
}

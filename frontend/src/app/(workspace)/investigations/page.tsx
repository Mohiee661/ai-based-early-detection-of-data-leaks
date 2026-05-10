"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  Activity,
  ArrowRight,
  CalendarRange,
  ChevronRight,
  Filter,
  GitBranch,
  GitCommit,
  Workflow,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { SeverityBadge } from "@/components/findings/severity-badge";
import { useAuth } from "@/components/providers/auth-provider";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  getThreatTimeline,
  isApiConfigured,
  type ThreatTimelineResponse,
  type TimelineCluster,
  type TimelineEvent,
  type TimelineGroupBy,
  type TimelineRange,
} from "@/lib/api";
import { cn } from "@/lib/utils";

type WorkflowState = "triage" | "investigating" | "contained" | "closed";

const rangeOptions: { label: string; value: TimelineRange }[] = [
  { label: "7D", value: "7d" },
  { label: "30D", value: "30d" },
  { label: "90D", value: "90d" },
  { label: "All", value: "all" },
];

const severityOptions: Array<{ label: string; value: TimelineCluster["severity"] | "ALL" }> = [
  { label: "All", value: "ALL" },
  { label: "Critical", value: "CRITICAL" },
  { label: "High", value: "HIGH" },
  { label: "Medium", value: "MEDIUM" },
  { label: "Low", value: "LOW" },
];

const groupOptions: { label: string; value: TimelineGroupBy }[] = [
  { label: "Cluster", value: "cluster" },
  { label: "Chronological", value: "time" },
];

const workflowOptions: Array<{ label: string; value: WorkflowState; description: string }> = [
  { label: "Triage", value: "triage", description: "Review the exposure and confirm priority." },
  { label: "Investigating", value: "investigating", description: "Correlate related findings and alerts." },
  { label: "Contained", value: "contained", description: "Exposure is known and response is underway." },
  { label: "Closed", value: "closed", description: "Incident has been reviewed and closed." },
];

const timelineColors: Record<string, string> = {
  finding: "var(--foreground)",
  github_exposure: "#f59e0b",
  alert: "#ef4444",
  incident: "#8b5cf6",
};

const eventTypeLabels: Record<TimelineEvent["event_type"], string> = {
  finding: "Finding",
  github_exposure: "GitHub Exposure",
  alert: "Alert",
  incident: "Incident",
};

const workflowStorageKey = "darkshield-investigation-workflow";

function formatTimestamp(timestamp: string) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return date.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function formatDay(timestamp: string) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return "Unknown date";
  }

  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    weekday: "short",
  });
}

function dayKey(timestamp: string) {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toISOString().slice(0, 10);
}

function groupEventsByDay(events: TimelineEvent[]) {
  const grouped = new Map<string, TimelineEvent[]>();
  events.forEach((event) => {
    const key = dayKey(event.timestamp);
    const current = grouped.get(key) ?? [];
    current.push(event);
    grouped.set(key, current);
  });

  return Array.from(grouped.entries()).map(([date, items]) => ({
    date,
    label: items[0] ? formatDay(items[0].timestamp) : date,
    items: items.sort((left, right) => new Date(left.timestamp).getTime() - new Date(right.timestamp).getTime()),
  }));
}

function buildTimelineSeries(events: TimelineEvent[]) {
  const map = new Map<
    string,
    {
      alert: number;
      finding: number;
      github_exposure: number;
      incident: number;
      total: number;
    }
  >();

  events.forEach((event) => {
    const key = dayKey(event.timestamp);
    const current = map.get(key) ?? {
      alert: 0,
      finding: 0,
      github_exposure: 0,
      incident: 0,
      total: 0,
    };
    current[event.event_type] += 1;
    current.total += 1;
    map.set(key, current);
  });

  return Array.from(map.entries())
    .map(([date, counts]) => ({
      date,
      alert: counts.alert,
      finding: counts.finding,
      github_exposure: counts.github_exposure,
      incident: counts.incident,
      total: counts.total,
    }))
    .sort((left, right) => left.date.localeCompare(right.date));
}

function getEventTone(event: TimelineEvent) {
  if (event.event_type === "incident") {
    return "border-violet-500/20 bg-violet-500/10 text-violet-100";
  }
  if (event.event_type === "alert") {
    return event.severity === "CRITICAL"
      ? "border-red-500/20 bg-red-500/10 text-red-100"
      : "border-amber-500/20 bg-amber-500/10 text-amber-100";
  }
  if (event.event_type === "github_exposure") {
    return "border-amber-500/20 bg-amber-500/10 text-amber-100";
  }
  return "border-border bg-muted text-muted-foreground";
}

function CompactMetric({
  label,
  value,
  description,
}: {
  description: string;
  label: string;
  value: string;
}) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold text-foreground">{value}</div>
        <p className="mt-1 text-sm leading-6 text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  );
}

function TimelineSparkline({ cluster }: { cluster: TimelineCluster }) {
  const data = cluster.timeline.map((point) => ({
    ...point,
    label: point.date.slice(5),
  }));

  return (
    <div className="h-20 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data}>
          <XAxis dataKey="label" tick={false} axisLine={false} tickLine={false} />
          <YAxis hide />
          <Tooltip
            contentStyle={{
              backgroundColor: "var(--card)",
              border: "1px solid var(--border)",
              borderRadius: "10px",
            }}
          />
          <Bar dataKey="count" fill="var(--foreground)" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function EventRow({
  event,
  onSelectCluster,
}: {
  event: TimelineEvent;
  onSelectCluster: (clusterId: string) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => event.cluster_id && onSelectCluster(event.cluster_id)}
      id={`event-${event.id}`}
      className={cn(
        "flex w-full flex-col gap-3 rounded-[var(--radius)] border p-4 text-left transition-colors hover:bg-accent/60",
        event.event_type === "incident" ? "border-violet-500/20 bg-violet-500/5" : "border-border bg-card",
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={event.severity} />
        <span className={cn("rounded-full border px-2.5 py-1 text-xs font-medium", getEventTone(event))}>
          {eventTypeLabels[event.event_type]}
        </span>
        <span className="text-xs text-muted-foreground">{formatTimestamp(event.timestamp)}</span>
        <span className="text-xs text-muted-foreground">{event.source_type}</span>
      </div>

      <div className="space-y-1">
        <div className="text-sm font-semibold text-foreground">{event.title}</div>
        <p className="text-sm leading-6 text-muted-foreground">{event.summary || "No analyst summary available."}</p>
      </div>

      <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
        {event.pattern_type ? <span className="rounded-full border border-border px-2 py-1">{event.pattern_type}</span> : null}
        {event.matched_value ? <span className="rounded-full border border-border px-2 py-1">{event.matched_value}</span> : null}
        {event.related_count ? (
          <span className="rounded-full border border-border px-2 py-1">{event.related_count} related findings</span>
        ) : null}
        {event.unread ? (
          <span className="rounded-full border border-red-500/20 bg-red-500/10 px-2 py-1 text-red-100">Unread</span>
        ) : null}
      </div>
    </button>
  );
}

function ClusterPanel({
  cluster,
  isSelected,
  onSelect,
}: {
  cluster: TimelineCluster;
  isSelected: boolean;
  onSelect: (clusterId: string) => void;
}) {
  return (
    <button
      id={`cluster-${cluster.cluster_id}`}
      type="button"
      onClick={() => onSelect(cluster.cluster_id)}
      className={cn(
        "w-full rounded-[var(--radius)] border p-4 text-left transition-colors hover:bg-accent/60",
        isSelected ? "border-primary/40 bg-primary/5" : "border-border bg-card",
      )}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-semibold text-foreground">{cluster.label}</span>
            <SeverityBadge severity={cluster.severity} />
          </div>
          <p className="text-xs leading-5 text-muted-foreground">
            {cluster.finding_count} findings, {cluster.alert_count} alerts, {cluster.incident_count} incidents
          </p>
        </div>
        <ChevronRight className="mt-1 size-4 shrink-0 text-muted-foreground" />
      </div>

      <div className="mt-4 grid gap-3 text-xs text-muted-foreground sm:grid-cols-3">
        <div>Similarity {(cluster.average_similarity * 100).toFixed(0)}%</div>
        <div>Risk {cluster.average_risk_score.toFixed(0)}</div>
        <div>Sources {cluster.source_types.join(", ") || "web"}</div>
      </div>

      <div className="mt-4">
        <TimelineSparkline cluster={cluster} />
      </div>
    </button>
  );
}

function WorkflowStep({
  active,
  description,
  label,
  onClick,
}: {
  active: boolean;
  description: string;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "w-full rounded-[var(--radius)] border p-3 text-left transition-colors hover:bg-accent/60",
        active ? "border-primary/40 bg-primary/5" : "border-border bg-card",
      )}
    >
      <div className="text-sm font-medium text-foreground">{label}</div>
      <div className="mt-1 text-xs leading-5 text-muted-foreground">{description}</div>
    </button>
  );
}

export default function InvestigationsPage() {
  const { status } = useAuth();
  const [timeline, setTimeline] = useState<ThreatTimelineResponse | null>(null);
  const [range, setRange] = useState<TimelineRange>("30d");
  const [severity, setSeverity] = useState<TimelineCluster["severity"] | "ALL">("ALL");
  const [groupBy, setGroupBy] = useState<TimelineGroupBy>("cluster");
  const [selectedClusterId, setSelectedClusterId] = useState<string | null>(null);
  const [workflowByCluster, setWorkflowByCluster] = useState<Record<string, WorkflowState>>({});
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      const stored = window.localStorage.getItem(workflowStorageKey);
      if (!stored) {
        return;
      }

      try {
        setWorkflowByCluster(JSON.parse(stored) as Record<string, WorkflowState>);
      } catch {
        window.localStorage.removeItem(workflowStorageKey);
      }
    }, 0);

    return () => window.clearTimeout(timeout);
  }, []);

  useEffect(() => {
    window.localStorage.setItem(workflowStorageKey, JSON.stringify(workflowByCluster));
  }, [workflowByCluster]);

  useEffect(() => {
    let active = true;

    async function loadTimeline() {
      if (status === "loading") {
        return;
      }

      if (status !== "authenticated") {
        if (active) {
          setIsLoading(false);
        }
        return;
      }

      if (!isApiConfigured) {
        if (active) {
          setError("Set NEXT_PUBLIC_API_URL in frontend/.env.local to load the timeline.");
          setIsLoading(false);
        }
        return;
      }

      try {
        setIsLoading(true);
        setError(null);
        const payload = await getThreatTimeline({
          range,
          groupBy,
          severity: severity === "ALL" ? undefined : severity,
        });

        if (active) {
          setTimeline(payload);
        }
      } catch (loadError) {
        if (active) {
          setTimeline(null);
          setError(loadError instanceof Error ? loadError.message : "Unable to load investigation timeline.");
        }
      } finally {
        if (active) {
          setIsLoading(false);
        }
      }
    }

    loadTimeline();
    return () => {
      active = false;
    };
  }, [groupBy, range, severity, status]);

  const clusters = useMemo(() => timeline?.clusters ?? [], [timeline]);
  const events = useMemo(() => timeline?.events ?? [], [timeline]);
  const activeClusterId = selectedClusterId ?? clusters[0]?.cluster_id ?? null;
  const selectedCluster = useMemo(
    () => clusters.find((cluster) => cluster.cluster_id === activeClusterId) ?? clusters[0] ?? null,
    [activeClusterId, clusters],
  );

  const series = useMemo(() => buildTimelineSeries(events), [events]);
  const groupedByDay = useMemo(() => groupEventsByDay(events), [events]);
  const selectedWorkflow = selectedCluster ? workflowByCluster[selectedCluster.cluster_id] ?? "triage" : "triage";

  const totalEvents = timeline?.total_events ?? 0;
  const criticalEvents = events.filter((event) => event.severity === "CRITICAL").length;
  const githubEvents = timeline?.github_exposure_count ?? 0;
  const incidentEvents = timeline?.incident_count ?? 0;

  function setWorkflowState(clusterId: string, nextState: WorkflowState) {
    setWorkflowByCluster((current) => ({
      ...current,
      [clusterId]: nextState,
    }));
  }

  function scrollToCluster(clusterId: string) {
    const element = document.getElementById(`cluster-${clusterId}`);
    element?.scrollIntoView({ behavior: "smooth", block: "start" });
    setSelectedClusterId(clusterId);
  }

  return (
    <div className="flex flex-col gap-6">
      <section className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="space-y-1">
          <h2 className="text-base font-semibold text-foreground">Timeline</h2>
        </div>
        <div className="flex flex-wrap gap-2">
          {rangeOptions.map((option) => (
            <Button
              key={option.value}
              type="button"
              variant={range === option.value ? "default" : "outline"}
              size="sm"
              onClick={() => setRange(option.value)}
            >
              {option.label}
            </Button>
          ))}
        </div>
      </section>

      <section className="flex flex-wrap items-center justify-between gap-3 rounded-[var(--radius)] border border-border bg-card px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <Filter className="size-4 text-muted-foreground" />
          {severityOptions.map((option) => (
            <Button
              key={option.value}
              type="button"
              variant={severity === option.value ? "default" : "outline"}
              size="sm"
              onClick={() => setSeverity(option.value)}
            >
              {option.label}
            </Button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {groupOptions.map((option) => (
            <Button
              key={option.value}
              type="button"
              variant={groupBy === option.value ? "default" : "outline"}
              size="sm"
              onClick={() => setGroupBy(option.value)}
            >
              {option.label}
            </Button>
          ))}
        </div>
      </section>

      {error ? (
        <Card className="border-red-500/20">
          <CardContent className="flex items-start gap-3 px-5 py-4 text-sm">
            <Activity className="mt-0.5 size-5 shrink-0" />
            <div>
              <div className="font-semibold">Timeline unavailable</div>
              <p className="mt-1 text-muted-foreground">{error}</p>
            </div>
          </CardContent>
        </Card>
      ) : null}

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <CompactMetric
          label="Total Events"
          value={isLoading ? "..." : totalEvents.toLocaleString()}
          description="Findings, alerts, and incidents within the selected range."
        />
        <CompactMetric
          label="Critical Events"
          value={isLoading ? "..." : criticalEvents.toLocaleString()}
          description="High-priority items that should be investigated first."
        />
        <CompactMetric
          label="GitHub Exposures"
          value={isLoading ? "..." : githubEvents.toLocaleString()}
          description="Timeline items attributed to GitHub or repository exposure."
        />
        <CompactMetric
          label="Incidents"
          value={isLoading ? "..." : incidentEvents.toLocaleString()}
          description="Related incident groupings generated from clustered findings."
        />
      </section>

      <Card>
        <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CalendarRange className="size-4 text-muted-foreground" />
            Activity
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="h-[280px] animate-pulse rounded-[var(--radius)] bg-muted" />
          ) : series.length === 0 ? (
            <div className="rounded-[var(--radius)] border border-dashed border-border px-4 py-10 text-center text-sm text-muted-foreground">
              No activity found for the current timeline filters.
            </div>
          ) : (
            <div className="h-[280px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={series}>
                  <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
                  <XAxis dataKey="date" tick={{ fill: "var(--muted-foreground)", fontSize: 12 }} />
                  <YAxis tick={{ fill: "var(--muted-foreground)", fontSize: 12 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "var(--card)",
                      border: "1px solid var(--border)",
                      borderRadius: "10px",
                    }}
                  />
                  <Bar dataKey="finding" stackId="a" fill="var(--foreground)" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="github_exposure" stackId="a" fill={timelineColors.github_exposure} radius={[4, 4, 0, 0]} />
                  <Bar dataKey="alert" stackId="a" fill={timelineColors.alert} radius={[4, 4, 0, 0]} />
                  <Bar dataKey="incident" stackId="a" fill={timelineColors.incident} radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </CardContent>
      </Card>

      <section className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <GitBranch className="size-4 text-muted-foreground" />
                Clusters
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {groupBy === "cluster" ? (
                clusters.length ? (
                  clusters.map((cluster) => (
                    <div key={cluster.cluster_id} className="space-y-3">
                      <button
                        type="button"
                        onClick={() => scrollToCluster(cluster.cluster_id)}
                        className={cn(
                          "flex w-full items-center justify-between rounded-[var(--radius)] border px-4 py-3 text-left transition-colors hover:bg-accent/60",
                          selectedCluster?.cluster_id === cluster.cluster_id
                            ? "border-primary/40 bg-primary/5"
                            : "border-border bg-background",
                        )}
                      >
                        <div>
                          <div className="text-sm font-medium text-foreground">{cluster.label}</div>
                          <div className="mt-1 text-xs text-muted-foreground">
                            {cluster.finding_count} findings, {cluster.alert_count} alerts, {cluster.incident_count} incidents
                          </div>
                        </div>
                        <ArrowRight className="size-4 text-muted-foreground" />
                      </button>

                      <div className="grid gap-3">
                        {events
                          .filter((event) => event.cluster_id === cluster.cluster_id)
                          .map((event) => (
                            <EventRow
                              key={event.id}
                              event={event}
                              onSelectCluster={setSelectedClusterId}
                            />
                          ))}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="rounded-[var(--radius)] border border-dashed border-border px-4 py-10 text-center text-sm text-muted-foreground">
                    No clusters match the current filters.
                  </div>
                )
              ) : (
                groupedByDay.length ? (
                  groupedByDay.map((group) => (
                    <div key={group.date} className="space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="text-sm font-medium text-foreground">{group.label}</div>
                        <span className="text-xs text-muted-foreground">{group.items.length} events</span>
                      </div>
                      <div className="grid gap-3">
                        {group.items.map((event) => (
                          <EventRow
                            key={event.id}
                            event={event}
                            onSelectCluster={setSelectedClusterId}
                          />
                        ))}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="rounded-[var(--radius)] border border-dashed border-border px-4 py-10 text-center text-sm text-muted-foreground">
                    No timeline activity found for the current date range.
                  </div>
                )
              )}
            </CardContent>
          </Card>
        </div>

        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <GitCommit className="size-4 text-muted-foreground" />
                Summary
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {clusters.length ? (
                clusters.map((cluster) => (
                  <ClusterPanel
                    key={cluster.cluster_id}
                    cluster={cluster}
                    isSelected={selectedCluster?.cluster_id === cluster.cluster_id}
                    onSelect={setSelectedClusterId}
                  />
                ))
              ) : (
                <div className="rounded-[var(--radius)] border border-dashed border-border px-4 py-8 text-center text-sm text-muted-foreground">
                  No cluster summaries available.
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Workflow className="size-4 text-muted-foreground" />
                Workflow
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {selectedCluster ? (
                <>
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-2">
                      <div className="text-sm font-medium text-foreground">{selectedCluster.label}</div>
                      <p className="text-sm leading-6 text-muted-foreground">
                        Use this workflow to triage, correlate, contain, and close a clustered exposure thread.
                      </p>
                    </div>
                    <Button variant="outline" size="sm" asChild>
                      <Link href={`/cases?cluster_id=${encodeURIComponent(selectedCluster.cluster_id)}`}>
                        Create case
                      </Link>
                    </Button>
                  </div>

                  <div className="grid gap-2">
                    {workflowOptions.map((option) => (
                      <WorkflowStep
                        key={option.value}
                        active={selectedWorkflow === option.value}
                        label={option.label}
                        description={option.description}
                        onClick={() => setWorkflowState(selectedCluster.cluster_id, option.value)}
                      />
                    ))}
                  </div>

                  <div className="rounded-[var(--radius)] border border-border bg-background p-4 text-sm text-muted-foreground">
                    Current state: <span className="font-medium text-foreground">{selectedWorkflow}</span>
                  </div>

                  <div className="space-y-3">
                    <div className="text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                      Why are these related?
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {selectedCluster.shared_keywords.length ? (
                        selectedCluster.shared_keywords.map((keyword) => (
                          <span
                            key={keyword}
                            className="rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground"
                          >
                            {keyword}
                          </span>
                        ))
                      ) : (
                        <span className="text-sm text-muted-foreground">No keyword overlap detected.</span>
                      )}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Embedding similarity {(selectedCluster.average_similarity * 100).toFixed(0)}%.
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {selectedCluster.shared_indicators.length ? (
                        selectedCluster.shared_indicators.map((indicator) => (
                          <button
                            key={indicator}
                            type="button"
                            onClick={() => {
                              const target = events.find(
                                (event) =>
                                  event.cluster_id === selectedCluster.cluster_id &&
                                  (event.matched_value === indicator || event.pattern_type === indicator),
                              );
                              if (target) {
                                const element = document.getElementById(`event-${target.id}`);
                                element?.scrollIntoView({ behavior: "smooth", block: "center" });
                              }
                            }}
                            className="rounded-full border border-border px-2.5 py-1 text-xs text-foreground transition-colors hover:bg-accent"
                          >
                            {indicator}
                          </button>
                        ))
                      ) : (
                        <span className="text-sm text-muted-foreground">No shared indicators surfaced.</span>
                      )}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                      Related findings
                    </div>
                    <div className="grid gap-2">
                      {events
                        .filter((event) => event.cluster_id === selectedCluster.cluster_id && event.event_type !== "incident")
                        .slice(0, 5)
                        .map((event) => (
                          <button
                            key={event.id}
                            type="button"
                            id={`event-link-${event.id}`}
                            onClick={() => {
                              const element = document.getElementById(`event-${event.id}`);
                              element?.scrollIntoView({ behavior: "smooth", block: "center" });
                            }}
                            className="rounded-[var(--radius)] border border-border bg-card px-3 py-3 text-left text-sm transition-colors hover:bg-accent/60"
                          >
                            <div className="flex flex-wrap items-center gap-2">
                              <SeverityBadge severity={event.severity} />
                              <span className="text-xs text-muted-foreground">{eventTypeLabels[event.event_type]}</span>
                            </div>
                            <div className="mt-2 font-medium text-foreground">{event.title}</div>
                            <div className="mt-1 text-xs text-muted-foreground">{formatTimestamp(event.timestamp)}</div>
                          </button>
                        ))}
                    </div>
                  </div>
                </>
              ) : (
                <div className="rounded-[var(--radius)] border border-dashed border-border px-4 py-8 text-center text-sm text-muted-foreground">
                  Select a cluster to review the investigation workflow.
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </section>
    </div>
  );
}

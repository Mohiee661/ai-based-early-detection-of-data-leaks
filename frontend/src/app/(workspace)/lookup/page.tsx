"use client";

import { type ReactNode, useMemo, useState } from "react";
import {
  AlertTriangle,
  Clock3,
  Radar,
  Search,
  ShieldCheck,
  ShieldX,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/components/providers/auth-provider";
import { lookupIndicators, isApiConfigured } from "@/lib/api";
import { cn } from "@/lib/utils";
import { type Finding } from "@/types/findings";

const RECENT_SEARCHES_KEY = "darkshield-recent-searches";
const MAX_RECENT_SEARCHES = 5;

const severityOrder: Finding["severity"][] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const severityClasses: Record<Finding["severity"], string> = {
  CRITICAL: "border-red-500/20 bg-red-500/10 text-red-200",
  HIGH: "border-amber-500/20 bg-amber-500/10 text-amber-200",
  MEDIUM: "border-slate-500/20 bg-slate-500/10 text-slate-300",
  LOW: "border-border bg-muted text-muted-foreground",
};

function getStoredRecentSearches() {
  if (typeof window === "undefined") {
    return [] as string[];
  }

  const saved = window.localStorage.getItem(RECENT_SEARCHES_KEY);

  if (!saved) {
    return [] as string[];
  }

  try {
    const parsed = JSON.parse(saved);
    return Array.isArray(parsed)
      ? parsed.filter((item): item is string => typeof item === "string")
      : [];
  } catch {
    window.localStorage.removeItem(RECENT_SEARCHES_KEY);
    return [] as string[];
  }
}

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

function getHighestSeverity(findings: Finding[]) {
  return severityOrder.find((severity) =>
    findings.some((finding) => finding.severity === severity),
  );
}

function getRecentActivity(findings: Finding[]) {
  if (findings.length === 0) {
    return "No recent activity";
  }

  return formatTimestamp(findings[0].created_at);
}

function TimelineChart({ findings }: { findings: Finding[] }) {
  const buckets = useMemo(() => {
    const map = new Map<string, number>();

    findings.forEach((finding) => {
      const date = new Date(finding.created_at);
      if (Number.isNaN(date.getTime())) {
        return;
      }

      const key = date.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
      });

      map.set(key, (map.get(key) ?? 0) + 1);
    });

    return Array.from(map.entries())
      .map(([label, count]) => ({ label, count }))
      .slice(0, 7)
      .reverse();
  }, [findings]);

  const maxCount = Math.max(...buckets.map((bucket) => bucket.count), 1);

  if (buckets.length === 0) {
    return (
      <div className="flex h-44 items-center justify-center text-sm text-muted-foreground">
        No timeline activity yet
      </div>
    );
  }

  const chartHeight = 140;
  const chartWidth = 360;
  const slotWidth = chartWidth / buckets.length;
  const barWidth = Math.max(slotWidth - 12, 18);

  return (
    <div className="space-y-3">
      <svg
        viewBox={`0 0 ${chartWidth} ${chartHeight}`}
        className="h-40 w-full"
        role="img"
        aria-label="Findings timeline chart"
      >
        {buckets.map((bucket, index) => {
          const barHeight = Math.max((bucket.count / maxCount) * (chartHeight - 24), 12);
          const x = index * slotWidth + (slotWidth - barWidth) / 2;
          const y = chartHeight - barHeight - 8;

          return (
            <g key={bucket.label}>
              <rect
                x={x}
                y={y}
                width={barWidth}
                height={barHeight}
                rx="6"
                className="fill-foreground/85"
              />
              <text
                x={x + barWidth / 2}
                y={y - 6}
                textAnchor="middle"
                className="fill-[var(--muted-foreground)] text-[10px]"
              >
                {bucket.count}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="grid grid-cols-7 gap-3">
        {buckets.map((bucket) => (
          <div key={bucket.label} className="text-center text-xs text-muted-foreground">
            {bucket.label}
          </div>
        ))}
      </div>
    </div>
  );
}

function SeverityDistributionChart({ findings }: { findings: Finding[] }) {
  const distribution = severityOrder.map((severity) => ({
    severity,
    count: findings.filter((finding) => finding.severity === severity).length,
  }));

  const total = distribution.reduce((sum, item) => sum + item.count, 0);

  if (total === 0) {
    return (
      <div className="flex h-44 items-center justify-center text-sm text-muted-foreground">
        No severity distribution available
      </div>
    );
  }

  const chartWidth = 320;
  const chartHeight = 16;

  return (
    <div className="space-y-4">
      <svg
        viewBox={`0 0 ${chartWidth} ${chartHeight}`}
        className="h-4 w-full"
        role="img"
        aria-label="Severity distribution chart"
      >
        {distribution.reduce<{ cursor: number; nodes: ReactNode[] }>(
          (state, item) => {
            const width = (item.count / total) * chartWidth;
            const fillClass =
              item.severity === "CRITICAL"
                ? "fill-red-400/80"
                : item.severity === "HIGH"
                  ? "fill-amber-400/80"
                  : item.severity === "MEDIUM"
                    ? "fill-slate-400/80"
                    : "fill-neutral-400/80";

            state.nodes.push(
              <rect
                key={item.severity}
                x={state.cursor}
                y="0"
                width={width}
                height={chartHeight}
                rx="6"
                className={fillClass}
              />,
            );

            return {
              cursor: state.cursor + width,
              nodes: state.nodes,
            };
          },
          { cursor: 0, nodes: [] },
        ).nodes}
      </svg>
      {distribution.map((item) => {
        return (
          <div key={item.severity} className="space-y-1.5">
            <div className="flex items-center justify-between text-sm">
              <span className="text-foreground">{item.severity}</span>
              <span className="text-muted-foreground">{item.count}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function ResultBadge({ severity }: { severity: Finding["severity"] }) {
  return (
    <span
      className={cn(
        "inline-flex rounded-full border px-2.5 py-1 text-xs font-medium",
        severityClasses[severity],
      )}
    >
      {severity}
    </span>
  );
}

function LookupSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <div key={index} className="surface-card px-5 py-5">
            <div className="h-3 w-24 animate-pulse rounded bg-muted" />
            <div className="mt-3 h-7 w-20 animate-pulse rounded bg-muted" />
            <div className="mt-3 h-4 w-32 animate-pulse rounded bg-muted" />
          </div>
        ))}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        {Array.from({ length: 2 }).map((_, index) => (
          <div key={index} className="surface-card px-5 py-5">
            <div className="h-4 w-28 animate-pulse rounded bg-muted" />
            <div className="mt-5 h-40 animate-pulse rounded bg-muted" />
          </div>
        ))}
      </div>
      <div className="surface-card px-5 py-5">
        <div className="h-4 w-36 animate-pulse rounded bg-muted" />
        <div className="mt-4 space-y-3">
          {Array.from({ length: 5 }).map((_, index) => (
            <div key={index} className="h-14 animate-pulse rounded bg-muted" />
          ))}
        </div>
      </div>
    </div>
  );
}

export default function LookupPage() {
  const { status } = useAuth();
  const [searchTerm, setSearchTerm] = useState("");
  const [submittedTerm, setSubmittedTerm] = useState("");
  const [listQuery, setListQuery] = useState("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recentSearches, setRecentSearches] = useState<string[]>(getStoredRecentSearches);

  const filteredList = useMemo(() => {
    const normalized = listQuery.trim().toLowerCase();

    if (!normalized) {
      return findings;
    }

    return findings.filter((finding) => {
      return (
        finding.pattern_type.toLowerCase().includes(normalized) ||
        finding.matched_value.toLowerCase().includes(normalized) ||
        finding.context_window?.toLowerCase().includes(normalized) ||
        finding.severity.toLowerCase().includes(normalized)
      );
    });
  }, [findings, listQuery]);

  const totalMatches = findings.length;
  const highestSeverity = getHighestSeverity(findings);
  const averageRiskScore =
    findings.length > 0
      ? Math.round(
          findings.reduce((sum, finding) => sum + finding.risk_score, 0) / findings.length,
        )
      : 0;
  const recentActivity = getRecentActivity(findings);

  async function runLookup(termOverride?: string) {
    const nextTerm = (termOverride ?? searchTerm).trim();

    if (!nextTerm) {
      setError("Enter a domain, email, or indicator to search the findings feed.");
      setSubmittedTerm("");
      setFindings([]);
      return;
    }

    if (status !== "authenticated") {
      setError("Sign in to search the findings feed.");
      return;
    }

    if (!isApiConfigured) {
      setError(
        "Set NEXT_PUBLIC_API_URL in frontend/.env.local to enable lookup.",
      );
      setSubmittedTerm(nextTerm);
      setFindings([]);
      return;
    }

    try {
      setIsLoading(true);
      setError(null);
      setSubmittedTerm(nextTerm);
      const results = await lookupIndicators(nextTerm);
      setFindings(results.items.slice(0, 100));
      setRecentSearches((current) => {
        const nextSearches = [nextTerm, ...current.filter((item) => item !== nextTerm)].slice(
          0,
          MAX_RECENT_SEARCHES,
        );
        window.localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(nextSearches));
        return nextSearches;
      });
    } catch (lookupError) {
      setFindings([]);
      setError(
        lookupError instanceof Error
          ? lookupError.message
          : "Unable to search findings right now from the backend API.",
      );
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <section className="surface-card px-5 py-8 sm:px-8 sm:py-10">
        <div className="mx-auto flex max-w-3xl flex-col items-center gap-6 text-center">
          <div className="rounded-full bg-muted p-3 text-muted-foreground">
            <Radar className="size-6" />
          </div>
          <div className="space-y-2">
            <h2 className="text-2xl font-semibold text-foreground sm:text-3xl">
              Search domains, emails, and indicators
            </h2>
            <p className="max-w-2xl text-sm leading-6 text-muted-foreground sm:text-base">
              Query matched values and surrounding context to understand where an indicator appears
              across the DarkShield threat feed.
            </p>
          </div>
          <div className="flex w-full max-w-2xl flex-col gap-3 sm:flex-row">
            <label className="relative flex-1">
              <Search className="pointer-events-none absolute left-4 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <input
                value={searchTerm}
                onChange={(event) => setSearchTerm(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    void runLookup();
                  }
                }}
                placeholder="Search example.com, alice@company.com, leaked token..."
                className="h-12 w-full rounded-[var(--radius)] border border-input bg-background pl-11 pr-4 text-sm text-foreground outline-none transition-colors focus:border-ring"
              />
            </label>
            <Button className="h-12 px-5" onClick={() => void runLookup()} disabled={isLoading}>
              <Search className="size-4" />
              Search
            </Button>
          </div>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="space-y-6">
          {submittedTerm && !isLoading && highestSeverity === "CRITICAL" ? (
            <div className="surface-card border-red-500/20 px-5 py-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="mt-0.5 size-5 text-red-200" />
                <div>
                  <p className="font-medium text-foreground">Critical findings detected</p>
                  <p className="mt-1 text-sm leading-6 text-muted-foreground">
                    At least one critical match was found for <span className="font-medium text-foreground">{submittedTerm}</span>.
                  </p>
                </div>
              </div>
            </div>
          ) : null}

          {submittedTerm && !isLoading && findings.length === 0 && !error ? (
            <div className="surface-card px-5 py-4">
              <div className="flex items-start gap-3">
                <ShieldCheck className="mt-0.5 size-5 text-emerald-300" />
                <div>
                  <p className="font-medium text-foreground">No findings detected</p>
                  <p className="mt-1 text-sm leading-6 text-muted-foreground">
                    No matches were found for <span className="font-medium text-foreground">{submittedTerm}</span> in matched values or context windows.
                  </p>
                </div>
              </div>
            </div>
          ) : null}

          {error ? (
            <div className="surface-card border-red-500/20 px-5 py-4">
              <div className="flex items-start gap-3">
                <ShieldX className="mt-0.5 size-5 text-red-200" />
                <div>
                  <p className="font-medium text-foreground">Lookup unavailable</p>
                  <p className="mt-1 text-sm leading-6 text-muted-foreground">{error}</p>
                </div>
              </div>
            </div>
          ) : null}

          {isLoading ? (
            <LookupSkeleton />
          ) : submittedTerm ? (
            <>
              <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <Card>
                  <CardHeader>
                    <CardTitle>Total Matches</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-semibold text-foreground">{totalMatches}</div>
                    <p className="mt-2 text-sm leading-6 text-muted-foreground">
                      Findings matching <span className="font-medium text-foreground">{submittedTerm}</span>
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle>Highest Severity</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-semibold text-foreground">
                      {highestSeverity ?? "None"}
                    </div>
                    <p className="mt-2 text-sm leading-6 text-muted-foreground">
                      Highest observed severity in the result set.
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle>Average Risk</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-semibold text-foreground">{averageRiskScore}</div>
                    <p className="mt-2 text-sm leading-6 text-muted-foreground">
                      Average analyst risk score across matched findings.
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle>Recent Activity</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-lg font-semibold text-foreground">{recentActivity}</div>
                    <p className="mt-2 text-sm leading-6 text-muted-foreground">
                      Most recent matching finding timestamp.
                    </p>
                  </CardContent>
                </Card>
              </section>

              <section className="grid gap-4 lg:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle>Findings Timeline</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <TimelineChart findings={findings} />
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle>Severity Distribution</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <SeverityDistributionChart findings={findings} />
                  </CardContent>
                </Card>
              </section>

              <Card>
                <CardHeader className="gap-3">
                  <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                      <CardTitle>Matching Findings</CardTitle>
                      <p className="mt-1 text-sm leading-6 text-muted-foreground">
                        Search within the current result set for faster analyst review.
                      </p>
                    </div>
                    <label className="relative block w-full max-w-sm">
                      <Search className="pointer-events-none absolute left-3.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                      <input
                        value={listQuery}
                        onChange={(event) => setListQuery(event.target.value)}
                        placeholder="Filter current results"
                        className="h-10 w-full rounded-[var(--radius)] border border-input bg-background pl-10 pr-3 text-sm text-foreground outline-none transition-colors focus:border-ring"
                      />
                    </label>
                  </div>
                </CardHeader>
                <CardContent className="p-0">
                  {filteredList.length === 0 ? (
                    <div className="px-5 py-10 text-center text-sm text-muted-foreground">
                      No findings match the current list search.
                    </div>
                  ) : (
                    <div className="divide-y divide-border">
                      {filteredList.map((finding) => (
                        <div key={finding.id} className="px-5 py-4 transition-colors hover:bg-accent/50">
                          <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                            <div className="min-w-0 space-y-2">
                              <div className="flex flex-wrap items-center gap-2">
                                <ResultBadge severity={finding.severity} />
                                <span className="text-sm font-medium text-foreground">
                                  {finding.pattern_type}
                                </span>
                              </div>
                              <div className="break-all font-mono text-xs text-foreground">
                                {finding.matched_value}
                              </div>
                              <p className="line-clamp-3 text-sm leading-6 text-muted-foreground">
                                {finding.context_window || "No context window available for this finding."}
                              </p>
                            </div>
                            <div className="flex shrink-0 items-center gap-4 text-sm text-muted-foreground">
                              <div className="flex items-center gap-1.5">
                                <Clock3 className="size-4" />
                                {formatTimestamp(finding.created_at)}
                              </div>
                              <div className="font-medium text-foreground">
                                Risk {finding.risk_score}
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>Lookup Workspace</CardTitle>
              </CardHeader>
              <CardContent className="text-sm leading-6 text-muted-foreground">
                Run a search to inspect matching findings, severity spread, and recent activity for
                a domain, email, or indicator.
              </CardContent>
            </Card>
          )}
        </div>

        <aside className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Recent Searches</CardTitle>
            </CardHeader>
            <CardContent>
              {recentSearches.length === 0 ? (
                <p className="text-sm leading-6 text-muted-foreground">
                  Recent searches will appear here after the first lookup.
                </p>
              ) : (
                <div className="flex flex-col gap-2">
                  {recentSearches.map((term) => (
                    <button
                      key={term}
                      type="button"
                      onClick={() => {
                        setSearchTerm(term);
                        void runLookup(term);
                      }}
                      className="rounded-[var(--radius)] border border-border px-3 py-2 text-left text-sm text-foreground transition-colors hover:bg-accent"
                    >
                      {term}
                    </button>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Lookup Coverage</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm leading-6 text-muted-foreground">
              <p>Matched values are searched directly for exact indicator appearances.</p>
              <p>Context windows are also searched so partial domains and email fragments still surface relevant findings.</p>
            </CardContent>
          </Card>
        </aside>
      </section>
    </div>
  );
}

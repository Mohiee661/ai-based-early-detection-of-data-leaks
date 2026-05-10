"use client";

import {
  startTransition,
  useDeferredValue,
  useMemo,
  useState,
} from "react";
import {
  ArrowDown,
  ArrowUp,
  ChevronLeft,
  ChevronRight,
  RefreshCcw,
  Search,
  ShieldAlert,
  X,
} from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { cn } from "@/lib/utils";
import { type Finding } from "@/types/findings";

type SpotlightTableProps = {
  error?: string | null;
  findings: Finding[];
  isLoading?: boolean;
  onRefresh?: () => void;
};

type SortField = "created_at" | "risk_score";
type SortDirection = "asc" | "desc";

const PAGE_SIZE = 10;
const CLUSTER_PAGE_SIZE = 3;
const RELATED_PAGE_SIZE = 6;
const STOPWORDS = new Set([
  "and",
  "the",
  "with",
  "from",
  "that",
  "this",
  "for",
  "are",
  "was",
  "were",
  "into",
  "http",
  "https",
  "api",
  "key",
  "token",
  "domain",
  "email",
  "note",
  "snippet",
  "thread",
  "captured",
  "capture",
  "operator",
  "client",
  "login",
]);

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

function formatConfidence(value?: number | null) {
  if (value == null || Number.isNaN(value)) {
    return "Unknown";
  }

  return `${Math.round(value * 100)}%`;
}

function formatReasoning(value?: string | null) {
  return value?.trim() || "No reasoning summary available.";
}

function normalizeText(value: string) {
  return value
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, " ")
    .replace(/[^a-z0-9._@-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function tokenizeFinding(finding: Finding) {
  const tokens = [
    finding.pattern_type,
    finding.matched_value,
    finding.ai_label ?? "",
    finding.groq_summary ?? "",
    finding.reasoning_summary ?? "",
    finding.context_window ?? "",
    ...(finding.classifier_metadata?.top_terms ?? []),
  ]
    .flatMap((value) => normalizeText(String(value)).split(" "))
    .filter((token) => token.length >= 3 && !STOPWORDS.has(token));

  return Array.from(new Set(tokens));
}

function extractIndicators(text: string) {
  const normalized = text || "";
  const matches = new Set<string>();
  const patterns: Array<[RegExp, string]> = [
    [/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "email"],
    [/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "ip"],
    [/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi, "domain"],
    [/\b(?:ghp_|gho_|ghs_|ghu_|sk-|xoxb-|AKIA)[A-Za-z0-9_-]{4,}\b/g, "secret"],
  ];

  patterns.forEach(([regex, label]) => {
    for (const match of normalized.match(regex) ?? []) {
      matches.add(`${label}:${match.toLowerCase()}`);
    }
  });

  return Array.from(matches);
}

function getIndicatorKind(finding: Finding) {
  const text = `${finding.pattern_type} ${finding.context_window ?? ""} ${finding.matched_value}`;
  const indicators = extractIndicators(text);
  if (indicators.some((entry) => entry.startsWith("email:"))) {
    return "email";
  }
  if (indicators.some((entry) => entry.startsWith("ip:"))) {
    return "ip";
  }
  if (indicators.some((entry) => entry.startsWith("domain:"))) {
    return "domain";
  }
  if (indicators.some((entry) => entry.startsWith("secret:"))) {
    return "api_key";
  }
  if ((finding.ai_label ?? "").includes("api_key") || finding.pattern_type.toLowerCase().includes("api")) {
    return "api_key";
  }
  if (finding.context_window?.toLowerCase().includes("github")) {
    return "github";
  }
  return "general";
}

function getSharedKeywords(left: Finding, right: Finding) {
  const leftTokens = new Set(tokenizeFinding(left));
  const rightTokens = new Set(tokenizeFinding(right));
  return Array.from(leftTokens).filter((token) => rightTokens.has(token)).slice(0, 6);
}

function getSharedIndicators(left: Finding, right: Finding) {
  const leftIndicators = new Set(
    extractIndicators(`${left.context_window ?? ""} ${left.pattern_type} ${left.matched_value}`),
  );
  const rightIndicators = new Set(
    extractIndicators(`${right.context_window ?? ""} ${right.pattern_type} ${right.matched_value}`),
  );

  return Array.from(leftIndicators).filter((indicator) => rightIndicators.has(indicator)).slice(0, 6);
}

function computeSimilarity(left: Finding, right: Finding) {
  const leftTokens = new Set(tokenizeFinding(left));
  const rightTokens = new Set(tokenizeFinding(right));
  const intersection = Array.from(leftTokens).filter((token) => rightTokens.has(token));
  const union = new Set([...leftTokens, ...rightTokens]);
  const jaccard = union.size ? intersection.length / union.size : 0;

  const aiMatch = left.ai_label && left.ai_label === right.ai_label ? 0.2 : 0;
  const patternMatch = left.pattern_type === right.pattern_type ? 0.2 : 0;
  const indicatorMatch = getSharedIndicators(left, right).length > 0 ? 0.2 : 0;
  const githubBoost =
    (left.context_window ?? "").toLowerCase().includes("github") &&
    (right.context_window ?? "").toLowerCase().includes("github")
      ? 0.1
      : 0;

  const score = Math.max(0, Math.min(1, jaccard * 0.5 + aiMatch + patternMatch + indicatorMatch + githubBoost));

  return {
    score,
    sharedKeywords: getSharedKeywords(left, right),
    sharedIndicators: getSharedIndicators(left, right),
  };
}

function clusterKeyForFinding(finding: Finding) {
  return `${finding.ai_label ?? finding.pattern_type}:${getIndicatorKind(finding)}`;
}

function getSeverityCounts(findings: Finding[]) {
  return findings.reduce(
    (acc, finding) => {
      acc[finding.severity] += 1;
      return acc;
    },
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
  );
}

function getTimelinePoints(findings: Finding[]) {
  const buckets = new Map<string, number>();

  findings.forEach((finding) => {
    const date = new Date(finding.created_at);
    if (Number.isNaN(date.getTime())) {
      return;
    }

    const key = date.toISOString().slice(0, 10);
    buckets.set(key, (buckets.get(key) ?? 0) + 1);
  });

  return Array.from(buckets.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([date, count]) => ({ date, count }));
}

function parseTopTerms(classifierMetadata: Finding["classifier_metadata"]) {
  const topTerms = classifierMetadata?.top_terms;
  if (!Array.isArray(topTerms)) {
    return [];
  }

  return topTerms.filter((term): term is string => typeof term === "string" && term.trim().length > 0);
}

function matchesQuery(finding: Finding, query: string) {
  const normalized = query.toLowerCase();
  return (
    finding.pattern_type.toLowerCase().includes(normalized) ||
    finding.matched_value.toLowerCase().includes(normalized) ||
    finding.severity.toLowerCase().includes(normalized) ||
    (finding.ai_label ?? "").toLowerCase().includes(normalized) ||
    (finding.groq_summary ?? "").toLowerCase().includes(normalized) ||
    (finding.reasoning_summary ?? "").toLowerCase().includes(normalized)
  );
}

function compareFindings(
  left: Finding,
  right: Finding,
  sortField: SortField,
  sortDirection: SortDirection,
) {
  if (sortField === "risk_score") {
    return sortDirection === "asc"
      ? left.risk_score - right.risk_score
      : right.risk_score - left.risk_score;
  }

  const leftTime = new Date(left.created_at).getTime();
  const rightTime = new Date(right.created_at).getTime();

  return sortDirection === "asc" ? leftTime - rightTime : rightTime - leftTime;
}

function SpotlightSkeletonRows() {
  return Array.from({ length: 8 }).map((_, index) => (
    <tr key={`skeleton-${index}`} className="border-t border-border">
      <td className="px-4 py-3.5">
        <div className="h-6 w-24 animate-pulse rounded-[var(--radius)] bg-muted" />
      </td>
      <td className="px-4 py-3.5">
        <div className="h-4 w-32 animate-pulse rounded bg-muted" />
      </td>
      <td className="px-4 py-3.5">
        <div className="h-4 w-48 animate-pulse rounded bg-muted" />
      </td>
      <td className="px-4 py-3.5">
        <div className="h-4 w-14 animate-pulse rounded bg-muted" />
      </td>
      <td className="px-4 py-3.5">
        <div className="h-4 w-36 animate-pulse rounded bg-muted" />
      </td>
    </tr>
  ));
}

function SortButton({
  active,
  direction,
  label,
  onClick,
}: {
  active: boolean;
  direction: SortDirection;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1 text-xs font-medium uppercase tracking-[0.12em] transition-colors",
        active ? "text-foreground" : "text-muted-foreground hover:text-foreground",
      )}
    >
      <span>{label}</span>
      {active ? (
        direction === "desc" ? (
          <ArrowDown className="size-3.5" />
        ) : (
          <ArrowUp className="size-3.5" />
        )
      ) : null}
    </button>
  );
}

export function SpotlightTable({
  findings,
  isLoading = false,
  error,
  onRefresh,
}: SpotlightTableProps) {
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"ALL" | Finding["severity"]>("ALL");
  const [patternFilter, setPatternFilter] = useState("ALL");
  const [sortField, setSortField] = useState<SortField>("risk_score");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const deferredQuery = useDeferredValue(query);

  const patternTypes = useMemo(() => {
    return Array.from(new Set(findings.map((finding) => finding.pattern_type))).sort();
  }, [findings]);

  const filteredFindings = useMemo(() => {
    const normalizedQuery = deferredQuery.trim();

    return findings
      .filter((finding) => {
        if (severityFilter !== "ALL" && finding.severity !== severityFilter) {
          return false;
        }

        if (patternFilter !== "ALL" && finding.pattern_type !== patternFilter) {
          return false;
        }

        if (normalizedQuery && !matchesQuery(finding, normalizedQuery)) {
          return false;
        }

        return true;
      })
      .sort((left, right) =>
        compareFindings(left, right, sortField, sortDirection),
      );
  }, [deferredQuery, findings, patternFilter, severityFilter, sortDirection, sortField]);

  const totalPages = Math.max(1, Math.ceil(filteredFindings.length / PAGE_SIZE));
  const safeCurrentPage = Math.min(currentPage, totalPages);

  const paginatedFindings = useMemo(() => {
    const start = (safeCurrentPage - 1) * PAGE_SIZE;
    return filteredFindings.slice(start, start + PAGE_SIZE);
  }, [filteredFindings, safeCurrentPage]);

  const selectedFinding = useMemo(() => {
    if (!selectedFindingId) {
      return null;
    }

    return findings.find((finding) => finding.id === selectedFindingId) ?? null;
  }, [findings, selectedFindingId]);

  const selectedCluster = useMemo(() => {
    if (!selectedFinding) {
      return null;
    }

    const members = findings
      .filter((finding) => finding.id !== selectedFinding.id)
      .map((finding) => ({
        finding,
        ...computeSimilarity(selectedFinding, finding),
      }))
      .filter((member) => member.score >= 0.45)
      .sort((left, right) => right.score - left.score)
      .slice(0, 8);

    const clusterFindings = [selectedFinding, ...members.map((member) => member.finding)];
    return {
      key: clusterKeyForFinding(selectedFinding),
      members,
      findings: clusterFindings,
      severityCounts: getSeverityCounts(clusterFindings),
      timeline: getTimelinePoints(clusterFindings),
      sharedIndicators: Array.from(
        new Set(members.flatMap((member) => member.sharedIndicators)),
      ).slice(0, 6),
      sharedKeywords: Array.from(new Set(members.flatMap((member) => member.sharedKeywords))).slice(0, 8),
    };
  }, [findings, selectedFinding]);

  const clusterSummaries = useMemo(() => {
    const grouped = new Map<
      string,
      {
        findings: Finding[];
        representative: Finding;
      }
    >();

    filteredFindings.forEach((finding) => {
      const key = clusterKeyForFinding(finding);
      const current = grouped.get(key);
      if (current) {
        current.findings.push(finding);
      } else {
        grouped.set(key, { findings: [finding], representative: finding });
      }
    });

    return Array.from(grouped.entries())
      .map(([key, value]) => {
        const findingsInCluster = value.findings;
        const severityCounts = getSeverityCounts(findingsInCluster);
        const relatedScores = findingsInCluster.flatMap((left) =>
          findingsInCluster
            .filter((right) => right.id !== left.id)
            .map((right) => computeSimilarity(left, right).score),
        );
        const averageSimilarity =
          relatedScores.length > 0
            ? relatedScores.reduce((sum, score) => sum + score, 0) / relatedScores.length
            : 0;
        const sharedKeywords = findingsInCluster
          .slice(1)
          .reduce<string[]>((acc, finding) => {
            const shared = getSharedKeywords(value.representative, finding);
            return Array.from(new Set([...acc, ...shared]));
          }, [])
          .slice(0, 8);

        return {
          key,
          label: value.representative.ai_label ?? value.representative.pattern_type,
          findings: findingsInCluster,
          representative: value.representative,
          severityCounts,
          averageSimilarity,
          sharedKeywords,
          timeline: getTimelinePoints(findingsInCluster),
          indicatorKind: getIndicatorKind(value.representative),
        };
      })
      .sort((left, right) => right.findings.length - left.findings.length)
      .slice(0, CLUSTER_PAGE_SIZE);
  }, [filteredFindings]);

  function updateSort(nextField: SortField) {
    if (sortField === nextField) {
      setSortDirection((current) => (current === "desc" ? "asc" : "desc"));
      setCurrentPage(1);
      return;
    }

    setSortField(nextField);
    setSortDirection(nextField === "risk_score" ? "desc" : "desc");
    setCurrentPage(1);
  }

  return (
    <>
      <Card className="overflow-hidden">
        <CardHeader className="border-b border-border pb-4">
          <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <CardTitle className="flex items-center gap-3">
                  <span className="rounded-[calc(var(--radius)-2px)] bg-muted p-2 text-muted-foreground">
                    <ShieldAlert className="size-5" />
                  </span>
                  Feed
                </CardTitle>
              </div>

              <div className="flex items-center gap-2 self-start">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={onRefresh}
                  disabled={isLoading || !onRefresh}
                >
                  <RefreshCcw className={cn("size-4", isLoading && "animate-spin")} />
                  Refresh
                </Button>
              </div>
            </div>

            <div className="grid gap-3 lg:grid-cols-[minmax(0,1.5fr)_repeat(3,minmax(0,0.7fr))]">
              <label className="relative block">
                <Search className="pointer-events-none absolute left-3.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                <input
                  value={query}
                  onChange={(event) => {
                    const value = event.target.value;
                    startTransition(() => {
                      setQuery(value);
                      setCurrentPage(1);
                    });
                  }}
                  placeholder="Search findings"
                  className="h-10 w-full rounded-[var(--radius)] border border-input bg-background pl-10 pr-3 text-sm text-foreground outline-none transition-colors focus:border-ring"
                />
              </label>

              <select
                value={severityFilter}
                onChange={(event) => {
                  setSeverityFilter(event.target.value as "ALL" | Finding["severity"]);
                  setCurrentPage(1);
                }}
                className="h-10 rounded-[var(--radius)] border border-input bg-background px-3 text-sm text-foreground outline-none transition-colors focus:border-ring"
                aria-label="Filter by severity"
              >
                <option value="ALL">All severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>

              <select
                value={patternFilter}
                onChange={(event) => {
                  setPatternFilter(event.target.value);
                  setCurrentPage(1);
                }}
                className="h-10 rounded-[var(--radius)] border border-input bg-background px-3 text-sm text-foreground outline-none transition-colors focus:border-ring"
                aria-label="Filter by pattern type"
              >
                <option value="ALL">All threat types</option>
                {patternTypes.map((patternType) => (
                  <option key={patternType} value={patternType}>
                    {patternType}
                  </option>
                ))}
              </select>

              <div className="flex items-center rounded-[var(--radius)] border border-input bg-background px-3">
                <span className="text-sm text-muted-foreground">
                  {filteredFindings.length} result{filteredFindings.length === 1 ? "" : "s"}
                </span>
              </div>
            </div>
          </div>
        </CardHeader>

        <CardContent className="p-0">
          {error ? (
            <div className="px-5 py-8 text-sm text-red-200">
              <div className="font-semibold">Threat feed unavailable</div>
              <p className="mt-2 text-muted-foreground">{error}</p>
            </div>
          ) : null}

          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="bg-muted/40 text-muted-foreground">
                <tr>
                  <th className="px-4 py-3 font-medium">
                    <span className="text-xs uppercase tracking-[0.12em]">Severity</span>
                  </th>
                  <th className="px-4 py-3 font-medium">
                    <span className="text-xs uppercase tracking-[0.12em]">Threat Type</span>
                  </th>
                  <th className="px-4 py-3 font-medium">
                    <span className="text-xs uppercase tracking-[0.12em]">Indicator</span>
                  </th>
                  <th className="px-4 py-3 font-medium">
                    <SortButton
                      active={sortField === "risk_score"}
                      direction={sortDirection}
                      label="Risk Score"
                      onClick={() => updateSort("risk_score")}
                    />
                  </th>
                  <th className="px-4 py-3 font-medium">
                    <SortButton
                      active={sortField === "created_at"}
                      direction={sortDirection}
                      label="Timestamp"
                      onClick={() => updateSort("created_at")}
                    />
                  </th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <SpotlightSkeletonRows />
                ) : paginatedFindings.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-5 py-12 text-center">
                      <div className="space-y-2">
                        <p className="text-sm font-medium text-foreground">
                          No active threat findings
                        </p>
                        <p className="text-sm text-muted-foreground">
                          Try broadening the filters or refresh the feed.
                        </p>
                      </div>
                    </td>
                  </tr>
                ) : (
                  paginatedFindings.map((finding) => (
                    <tr
                      key={finding.id}
                      onClick={() => setSelectedFindingId(finding.id)}
                      className="cursor-pointer border-t border-border transition-colors duration-200 hover:bg-accent/70"
                    >
                      <td className="px-4 py-3.5">
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td className="px-4 py-3.5 text-foreground">{finding.pattern_type}</td>
                      <td className="px-4 py-3.5 font-mono text-xs text-foreground">
                        {finding.matched_value}
                      </td>
                      <td className="px-4 py-3.5 text-foreground">{finding.risk_score}</td>
                      <td className="px-4 py-3.5 text-muted-foreground">
                        {formatTimestamp(finding.created_at)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="flex flex-col gap-3 border-t border-border px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="text-sm text-muted-foreground">
              Showing{" "}
              {filteredFindings.length === 0
                ? 0
                : (safeCurrentPage - 1) * PAGE_SIZE + 1}
              {" "}-{" "}
              {Math.min(safeCurrentPage * PAGE_SIZE, filteredFindings.length)} of{" "}
              {filteredFindings.length}
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setCurrentPage((current) => Math.max(1, current - 1))}
                disabled={safeCurrentPage === 1 || isLoading}
              >
                <ChevronLeft className="size-4" />
                Previous
              </Button>
              <div className="px-2 text-sm text-muted-foreground">
                Page {safeCurrentPage} of {totalPages}
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() =>
                  setCurrentPage((current) => Math.min(totalPages, current + 1))
                }
                disabled={safeCurrentPage === totalPages || isLoading}
              >
                Next
                <ChevronRight className="size-4" />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <section className="space-y-3">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-foreground">Related Clusters</h2>
            <p className="text-sm leading-6 text-muted-foreground">
              Expand a cluster to inspect repeated exposures, shared indicators, and the activity timeline.
            </p>
          </div>
          <div className="text-sm text-muted-foreground">
            {filteredFindings.length} findings grouped into {clusterSummaries.length} visible clusters
          </div>
        </div>

        <div className="grid gap-3 xl:grid-cols-3">
          {clusterSummaries.length === 0 ? (
            <Card className="xl:col-span-3">
              <CardContent className="px-5 py-8 text-sm text-muted-foreground">
                No cluster summaries are available for the current filter set.
              </CardContent>
            </Card>
          ) : (
            clusterSummaries.map((cluster) => (
              <details
                key={cluster.key}
                className="rounded-[var(--radius)] border border-border bg-card"
              >
                <summary className="cursor-pointer list-none px-4 py-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="text-sm font-semibold text-foreground">{cluster.label}</div>
                      <div className="text-xs text-muted-foreground">
                        {cluster.indicatorKind} exposures, {cluster.findings.length} related findings
                      </div>
                    </div>
                    <div className="text-right text-xs text-muted-foreground">
                      <div>Avg similarity {Math.round(cluster.averageSimilarity * 100)}%</div>
                      <div>{cluster.severityCounts.CRITICAL} critical</div>
                    </div>
                  </div>
                </summary>
                <div className="border-t border-border p-4">
                  <div className="grid gap-2 sm:grid-cols-2">
                    <div className="surface-muted p-3">
                      <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
                        Severity Overview
                      </div>
                      <div className="mt-2 flex flex-wrap gap-2 text-xs text-foreground">
                        <span>CRITICAL {cluster.severityCounts.CRITICAL}</span>
                        <span>HIGH {cluster.severityCounts.HIGH}</span>
                        <span>MEDIUM {cluster.severityCounts.MEDIUM}</span>
                        <span>LOW {cluster.severityCounts.LOW}</span>
                      </div>
                    </div>
                    <div className="surface-muted p-3">
                      <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
                        Shared Keywords
                      </div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {cluster.sharedKeywords.length > 0 ? (
                          cluster.sharedKeywords.map((keyword) => (
                            <span
                              key={keyword}
                              className="rounded-full border border-border bg-background px-2.5 py-1 text-[11px] text-foreground"
                            >
                              {keyword}
                            </span>
                          ))
                        ) : (
                          <span className="text-xs text-muted-foreground">No shared keywords identified.</span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="mt-3 surface-muted p-3">
                    <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
                      Related Timeline
                    </div>
                    <div className="mt-3 space-y-2">
                      {cluster.timeline.length > 0 ? (
                        cluster.timeline.map((point) => (
                          <div key={point.date} className="flex items-center gap-3">
                            <span className="w-24 shrink-0 text-xs text-muted-foreground">{point.date}</span>
                            <div className="h-2 flex-1 rounded-full bg-muted">
                              <div
                                className="h-2 rounded-full bg-foreground/70"
                                style={{
                                  width: `${Math.min(100, (point.count / cluster.timeline[cluster.timeline.length - 1].count) * 100)}%`,
                                }}
                              />
                            </div>
                            <span className="w-8 text-right text-xs text-muted-foreground">{point.count}</span>
                          </div>
                        ))
                      ) : (
                        <span className="text-xs text-muted-foreground">No timeline data available.</span>
                      )}
                    </div>
                  </div>

                  <div className="mt-3 space-y-2">
                    {cluster.findings.slice(0, 4).map((finding) => (
                      <button
                        key={finding.id}
                        type="button"
                        onClick={() => setSelectedFindingId(finding.id)}
                        className="flex w-full items-start justify-between gap-3 rounded-[var(--radius)] border border-border bg-background px-3 py-3 text-left transition-colors hover:bg-accent/60"
                      >
                        <div className="min-w-0 space-y-1">
                          <div className="text-sm font-medium text-foreground">{finding.pattern_type}</div>
                          <div className="truncate font-mono text-xs text-muted-foreground">
                            {finding.matched_value}
                          </div>
                        </div>
                        <div className="text-right text-xs text-muted-foreground">
                          <div>{finding.severity}</div>
                          <div>{finding.risk_score} risk</div>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
              </details>
            ))
          )}
        </div>
      </section>

      <div
        className={cn(
          "fixed inset-0 z-40 bg-black/30 transition-opacity",
          selectedFinding ? "opacity-100" : "pointer-events-none opacity-0",
        )}
        onClick={() => setSelectedFindingId(null)}
        aria-hidden="true"
      />

      <aside
        className={cn(
          "fixed inset-y-0 right-0 z-50 w-full max-w-xl border-l border-border bg-background transition-transform duration-200",
          selectedFinding ? "translate-x-0" : "translate-x-full",
        )}
        aria-hidden={selectedFinding ? "false" : "true"}
      >
        <div className="flex h-full flex-col">
          <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
            <div>
              <p className="eyebrow">Finding Details</p>
              <h3 className="mt-1 text-lg font-semibold text-foreground">
                {selectedFinding?.pattern_type ?? "Threat Finding"}
              </h3>
            </div>
            <div className="flex items-center gap-2">
              {selectedFinding ? (
                <Button variant="outline" size="sm" asChild>
                  <Link href={`/cases?finding_id=${encodeURIComponent(selectedFinding.id)}`}>
                    Create Case
                  </Link>
                </Button>
              ) : null}
              <Button
                variant="ghost"
                size="icon"
                aria-label="Close details panel"
                onClick={() => setSelectedFindingId(null)}
              >
                <X className="size-4" />
              </Button>
            </div>
          </div>

          {selectedFinding ? (
            <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5">
              <div className="flex items-center gap-3">
                <SeverityBadge severity={selectedFinding.severity} />
                <span className="text-sm text-muted-foreground">
                  Risk score {selectedFinding.risk_score}
                </span>
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <div className="surface-muted p-4">
                    <div className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
                    ID
                  </div>
                  <div className="mt-2 break-all font-mono text-xs text-foreground">
                    {selectedFinding.id}
                  </div>
                </div>
                <div className="surface-muted p-4">
                    <div className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
                    Time
                  </div>
                  <div className="mt-2 text-sm text-foreground">
                    {formatTimestamp(selectedFinding.created_at)}
                  </div>
                </div>
                <div className="surface-muted p-4">
                  <div className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
                    Severity
                  </div>
                  <div className="mt-2">
                    <SeverityBadge severity={selectedFinding.severity} />
                  </div>
                </div>
                <div className="surface-muted p-4">
                    <div className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
                    Type
                  </div>
                  <div className="mt-2 text-sm text-foreground">
                    {selectedFinding.pattern_type}
                  </div>
                </div>
              </div>

              <div className="surface-muted p-4">
                <div className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
                  AI Classification
                </div>
                <div className="mt-3 flex items-center justify-between gap-3">
                  <div className="text-sm font-medium text-foreground">
                    {selectedFinding.ai_label ?? "Unclassified"}
                  </div>
                  <div className="text-sm text-muted-foreground">
                    Confidence {formatConfidence(selectedFinding.ai_confidence)}
                  </div>
                </div>
                <div className="mt-3 h-2 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-foreground/70 transition-all"
                    style={{
                      width: `${Math.max(0, Math.min(100, (selectedFinding.ai_confidence ?? 0) * 100))}%`,
                    }}
                  />
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {parseTopTerms(selectedFinding.classifier_metadata).map((term) => (
                    <span
                      key={term}
                      className="rounded-full border border-border bg-background px-2.5 py-1 text-xs text-foreground"
                    >
                      {term}
                    </span>
                  ))}
                </div>
              </div>

              <div className="surface-muted p-4">
                <div className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
                  Indicator
                </div>
                <div className="mt-2 break-all font-mono text-sm text-foreground">
                  {selectedFinding.matched_value}
                </div>
              </div>

              <div className="surface-muted p-4">
                  <div className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
                  Summary
                </div>
                <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-foreground">
                  {selectedFinding.groq_summary || "No AI summary available for this finding."}
                </p>
              </div>

              <div className="surface-muted p-4">
                <div className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
                  Reasoning
                </div>
                <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-foreground">
                  {formatReasoning(selectedFinding.reasoning_summary)}
                </p>
              </div>

              <div className="surface-muted p-4">
                  <div className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
                  Explain
                </div>
                <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-foreground">
                  {selectedFinding.shap_explanation || "No explainability data available."}
                </p>
              </div>

              <div className="surface-muted p-4">
                <div className="flex items-center justify-between gap-3">
                  <div className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
                    Related Findings
                  </div>
                  <div className="text-xs text-muted-foreground">
                    Similarity-driven cluster navigation
                  </div>
                </div>

                <div className="mt-3 space-y-3">
                  {selectedCluster && selectedCluster.members.length > 0 ? (
                    <>
                      <div className="grid gap-2 sm:grid-cols-2">
                        <div className="rounded-[var(--radius)] border border-border bg-background p-3">
                          <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
                            Cluster Severity Overview
                          </div>
                          <div className="mt-2 flex flex-wrap gap-2 text-xs text-foreground">
                            <span>CRITICAL {selectedCluster.severityCounts.CRITICAL}</span>
                            <span>HIGH {selectedCluster.severityCounts.HIGH}</span>
                            <span>MEDIUM {selectedCluster.severityCounts.MEDIUM}</span>
                            <span>LOW {selectedCluster.severityCounts.LOW}</span>
                          </div>
                        </div>
                        <div className="rounded-[var(--radius)] border border-border bg-background p-3">
                          <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
                            Why are these related?
                          </div>
                          <div className="mt-2 space-y-2 text-xs text-muted-foreground">
                            <div>
                              Shared keywords:{" "}
                              <span className="text-foreground">
                                {selectedCluster.sharedKeywords.join(", ") || "none"}
                              </span>
                            </div>
                            <div>
                              Matching indicators:{" "}
                              <span className="text-foreground">
                                {selectedCluster.sharedIndicators.join(", ") || "none"}
                              </span>
                            </div>
                            <div>
                              Embedding similarity:{" "}
                              <span className="text-foreground">
                                {Math.round(
                                  selectedCluster.members[0]?.score
                                    ? selectedCluster.members[0].score * 100
                                    : 0,
                                )}
                                %
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="space-y-2">
                        {selectedCluster.members.slice(0, RELATED_PAGE_SIZE).map((member) => (
                          <button
                            key={member.finding.id}
                            type="button"
                            onClick={() => setSelectedFindingId(member.finding.id)}
                            className="flex w-full items-start justify-between gap-3 rounded-[var(--radius)] border border-border bg-background px-3 py-3 text-left transition-colors hover:bg-accent/60"
                          >
                            <div className="min-w-0 space-y-1">
                              <div className="flex items-center gap-2">
                                <SeverityBadge severity={member.finding.severity} />
                                <span className="text-xs text-muted-foreground">
                                  {Math.round(member.score * 100)}% similar
                                </span>
                              </div>
                              <div className="truncate text-sm font-medium text-foreground">
                                {member.finding.pattern_type}
                              </div>
                              <div className="truncate font-mono text-xs text-muted-foreground">
                                {member.finding.matched_value}
                              </div>
                            </div>
                            <div className="text-right text-xs text-muted-foreground">
                              <div>{formatTimestamp(member.finding.created_at)}</div>
                              <div>
                                {member.sharedKeywords.length > 0
                                  ? member.sharedKeywords.slice(0, 3).join(", ")
                                  : "No shared keywords"}
                              </div>
                            </div>
                          </button>
                        ))}
                      </div>

                      <div className="rounded-[var(--radius)] border border-border bg-background p-3">
                        <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">
                          Related Findings Timeline
                        </div>
                        <div className="mt-3 space-y-2">
                          {selectedCluster.timeline.length > 0 ? (
                            selectedCluster.timeline.map((point) => (
                              <div key={point.date} className="flex items-center gap-3">
                                <span className="w-24 shrink-0 text-xs text-muted-foreground">
                                  {point.date}
                                </span>
                                <div className="h-2 flex-1 rounded-full bg-muted">
                                  <div
                                    className="h-2 rounded-full bg-foreground/70"
                                    style={{
                                      width: `${Math.min(
                                        100,
                                        (point.count / selectedCluster.timeline[selectedCluster.timeline.length - 1].count) *
                                          100,
                                      )}%`,
                                    }}
                                  />
                                </div>
                                <span className="w-8 text-right text-xs text-muted-foreground">
                                  {point.count}
                                </span>
                              </div>
                            ))
                          ) : (
                            <span className="text-xs text-muted-foreground">
                              No related timeline available.
                            </span>
                          )}
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="text-sm text-muted-foreground">
                      No related findings found for this signal yet.
                    </div>
                  )}
                </div>
              </div>

              <div className="surface-muted p-4">
                  <div className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
                  Context
                </div>
                <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-foreground">
                  {selectedFinding.context_window || "No context window available for this finding."}
                </p>
              </div>
            </div>
          ) : null}
        </div>
      </aside>
    </>
  );
}

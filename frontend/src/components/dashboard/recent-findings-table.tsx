import { Clock3 } from "lucide-react";

import { SeverityBadge } from "@/components/findings/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { type Finding } from "@/types/findings";

type RecentFindingsTableProps = {
  error?: string | null;
  findings: Finding[];
  isLoading?: boolean;
  title?: string;
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

function SkeletonRows() {
  return Array.from({ length: 6 }).map((_, index) => (
    <tr key={`recent-finding-skeleton-${index}`} className="border-t border-border">
      <td className="px-4 py-3.5">
        <div className="h-6 w-24 animate-pulse rounded-[var(--radius)] bg-muted" />
      </td>
      <td className="px-4 py-3.5">
        <div className="h-4 w-28 animate-pulse rounded bg-muted" />
      </td>
      <td className="px-4 py-3.5">
        <div className="h-4 w-40 animate-pulse rounded bg-muted" />
      </td>
      <td className="px-4 py-3.5">
        <div className="h-4 w-12 animate-pulse rounded bg-muted" />
      </td>
      <td className="px-4 py-3.5">
        <div className="h-4 w-28 animate-pulse rounded bg-muted" />
      </td>
    </tr>
  ));
}

export function RecentFindingsTable({
  error,
  findings,
  isLoading = false,
  title = "Recent Findings",
}: RecentFindingsTableProps) {
  return (
    <Card>
      <CardHeader className="border-b border-border pb-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <CardTitle>{title}</CardTitle>
          </div>
          <div className="rounded-[calc(var(--radius)-2px)] bg-muted p-2 text-muted-foreground">
            <Clock3 className="size-4" />
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {error ? (
          <div className="px-5 py-8 text-sm">
            <p className="font-medium text-foreground">Recent findings unavailable</p>
            <p className="mt-1 text-muted-foreground">{error}</p>
          </div>
        ) : null}
          <div className="overflow-x-auto">
          <table className="min-w-full text-left text-xs">
            <thead className="bg-muted/40 text-xs uppercase tracking-[0.12em] text-muted-foreground">
              <tr>
                <th className="px-3 py-2.5 font-medium">Severity</th>
                <th className="px-3 py-2.5 font-medium">Type</th>
                <th className="px-3 py-2.5 font-medium">Indicator</th>
                <th className="px-3 py-2.5 font-medium">Risk</th>
                <th className="px-3 py-2.5 font-medium">Time</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <SkeletonRows />
              ) : findings.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-sm text-muted-foreground">
                    No findings available yet.
                  </td>
                </tr>
              ) : (
                findings.map((finding) => (
                  <tr
                    key={finding.id}
                    className="border-t border-border transition-colors hover:bg-accent/50"
                  >
                    <td className="px-3 py-2.5">
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td className="px-3 py-2.5 text-foreground">{finding.pattern_type}</td>
                    <td className="px-3 py-2.5 font-mono text-[11px] text-foreground">
                      {finding.matched_value}
                    </td>
                    <td className="px-3 py-2.5 text-foreground">{finding.risk_score}</td>
                    <td className="px-3 py-2.5 text-muted-foreground">
                      {formatTimestamp(finding.created_at)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

"use client";

import { useMemo, useEffect, useState } from "react";
import {
  AlertTriangle,
  CalendarRange,
  KeyRound,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/components/providers/auth-provider";
import {
  getAnalyticsSummary,
  getFindings,
  isApiConfigured,
  type AnalyticsSummaryResponse,
} from "@/lib/api";
import { type Finding } from "@/types/findings";

type RangeFilter = "7d" | "30d" | "90d" | "all";

const rangeOptions: { label: string; value: RangeFilter }[] = [
  { label: "7D", value: "7d" },
  { label: "30D", value: "30d" },
  { label: "90D", value: "90d" },
  { label: "All", value: "all" },
];

const severityColors: Record<Finding["severity"], string> = {
  CRITICAL: "#f87171",
  HIGH: "#fbbf24",
  MEDIUM: "#94a3b8",
  LOW: "#737373",
};

function formatDateLabel(timestamp: string) {
  const date = new Date(timestamp);

  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  });
}

function withinRange(timestamp: string, range: RangeFilter) {
  if (range === "all") {
    return true;
  }

  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return false;
  }

  const now = Date.now();
  const diffMs = now - date.getTime();
  const days = range === "7d" ? 7 : range === "30d" ? 30 : 90;

  return diffMs <= days * 24 * 60 * 60 * 1000;
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

function ChartSkeleton() {
  return (
    <div className="h-[280px] animate-pulse rounded-[var(--radius)] bg-muted" />
  );
}

function ChartCard({
  children,
  title,
}: {
  children: React.ReactNode;
  title: string;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

export default function AnalyticsPage() {
  const { status } = useAuth();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<AnalyticsSummaryResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [dateRange, setDateRange] = useState<RangeFilter>("30d");

  useEffect(() => {
    let active = true;

    async function loadAnalytics() {
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
          setError(
            "Set NEXT_PUBLIC_API_URL in frontend/.env.local to load analytics.",
          );
          setIsLoading(false);
        }
        return;
      }

      try {
        setIsLoading(true);
        setError(null);
        const [summary, findingsResult] = await Promise.all([
          getAnalyticsSummary(),
          getFindings({ pageSize: 500, sortBy: "created_at", sortOrder: "asc" }),
        ]);

        if (active) {
          setFindings(findingsResult.items);
          setSummary(summary);
        }
      } catch (loadError) {
        if (active) {
          setFindings([]);
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Unable to load analytics findings from the backend API.",
          );
        }
      } finally {
        if (active) {
          setIsLoading(false);
        }
      }
    }

    loadAnalytics();
    return () => {
      active = false;
    };
  }, [status]);

  const filteredFindings = useMemo(
    () => findings.filter((finding) => withinRange(finding.created_at, dateRange)),
    [dateRange, findings],
  );

  const findingsOverTime = (summary?.findings_over_time ?? []).map((point) => ({
    date: point.date,
    findings: point.count,
  }));
  const severityDistribution = summary?.severity_distribution ?? [];
  const topPatternTypes = summary?.top_pattern_types ?? [];

  const apiExposureTrends = useMemo(() => {
    const map = new Map<string, number>();

    filteredFindings
      .filter(
        (finding) =>
          finding.pattern_type.toLowerCase().includes("api") ||
          finding.matched_value.toLowerCase().includes("api_key"),
      )
      .forEach((finding) => {
        const key = formatDateLabel(finding.created_at);
        map.set(key, (map.get(key) ?? 0) + 1);
      });

    return Array.from(map.entries()).map(([date, exposures]) => ({ date, exposures }));
  }, [filteredFindings]);

  const findingsPerDay = useMemo(() => {
    return findingsOverTime.slice(-10);
  }, [findingsOverTime]);

  const totalFindings = filteredFindings.length;
  const averageRisk = totalFindings
    ? Math.round(
        filteredFindings.reduce((sum, finding) => sum + finding.risk_score, 0) /
          totalFindings,
      )
    : 0;
  const criticalCount = filteredFindings.filter(
    (finding) => finding.severity === "CRITICAL",
  ).length;
  const apiExposureCount = filteredFindings.filter(
    (finding) =>
      finding.pattern_type.toLowerCase().includes("api") ||
      finding.matched_value.toLowerCase().includes("api_key"),
  ).length;

  return (
    <div className="flex flex-col gap-6">
      <section className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="space-y-1">
          <h2 className="text-base font-semibold text-foreground">Analytics</h2>
        </div>
        <div className="flex flex-wrap gap-2">
          {rangeOptions.map((option) => (
            <button
              key={option.value}
              type="button"
              onClick={() => setDateRange(option.value)}
              className={`rounded-[var(--radius)] border px-3 py-2 text-sm transition-colors ${
                dateRange === option.value
                  ? "border-border bg-accent text-accent-foreground"
                  : "border-border text-muted-foreground hover:bg-accent hover:text-accent-foreground"
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>
      </section>

      {error ? (
        <Card className="border-red-500/20">
          <CardContent className="flex items-start gap-3 px-5 py-4 text-sm">
            <AlertTriangle className="mt-0.5 size-5 shrink-0" />
            <div>
              <div className="font-semibold">Analytics unavailable</div>
              <p className="mt-1 text-muted-foreground">{error}</p>
            </div>
          </CardContent>
        </Card>
      ) : null}

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <CompactMetric
          label="Total Findings"
          value={isLoading ? "..." : totalFindings.toLocaleString()}
          description="Findings within the selected range."
        />
        <CompactMetric
          label="Critical Threats"
          value={isLoading ? "..." : criticalCount.toLocaleString()}
          description="Critical findings requiring escalation."
        />
        <CompactMetric
          label="Average Risk"
          value={isLoading ? "..." : averageRisk.toString()}
          description="Average analyst risk score."
        />
        <CompactMetric
          label="API Exposures"
          value={isLoading ? "..." : apiExposureCount.toLocaleString()}
          description="API-related exposure findings."
        />
      </section>

      {!isLoading && !error && filteredFindings.length === 0 ? (
        <Card>
          <CardContent className="px-5 py-10 text-center text-sm text-muted-foreground">
            No findings are available for the selected date range.
          </CardContent>
        </Card>
      ) : null}

      <section className="grid gap-4 xl:grid-cols-2">
        <ChartCard title="Findings">
          {isLoading ? (
            <ChartSkeleton />
          ) : (
            <div className="h-[280px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={findingsOverTime}>
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
                  <Line
                    type="monotone"
                    dataKey="findings"
                    stroke="var(--foreground)"
                    strokeWidth={2}
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </ChartCard>

        <ChartCard title="Severity">
          {isLoading ? (
            <ChartSkeleton />
          ) : (
            <div className="h-[280px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityDistribution}
                    dataKey="count"
                    nameKey="severity"
                    innerRadius={70}
                    outerRadius={100}
                    paddingAngle={2}
                  >
                    {severityDistribution.map((entry) => (
                      <Cell key={entry.severity} fill={severityColors[entry.severity]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "var(--card)",
                      border: "1px solid var(--border)",
                      borderRadius: "10px",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </ChartCard>

        <ChartCard title="Patterns">
          {isLoading ? (
            <ChartSkeleton />
          ) : (
            <div className="h-[280px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topPatternTypes} layout="vertical" margin={{ left: 32 }}>
                  <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
                  <XAxis type="number" tick={{ fill: "var(--muted-foreground)", fontSize: 12 }} />
                  <YAxis
                    type="category"
                    dataKey="patternType"
                    tick={{ fill: "var(--muted-foreground)", fontSize: 12 }}
                    width={120}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "var(--card)",
                      border: "1px solid var(--border)",
                      borderRadius: "10px",
                    }}
                  />
                  <Bar dataKey="count" fill="var(--foreground)" radius={[0, 6, 6, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </ChartCard>

        <ChartCard title="API Exposures">
          {isLoading ? (
            <ChartSkeleton />
          ) : (
            <div className="h-[280px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={apiExposureTrends}>
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
                  <Line
                    type="monotone"
                    dataKey="exposures"
                    stroke="#fbbf24"
                    strokeWidth={2}
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </ChartCard>
      </section>

      <ChartCard title="Daily Volume">
        {isLoading ? (
          <ChartSkeleton />
        ) : (
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={findingsPerDay}>
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
                <Bar dataKey="findings" fill="var(--foreground)" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </ChartCard>

      <section className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CalendarRange className="size-4 text-muted-foreground" />
              Range
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm leading-6 text-muted-foreground">
            Current filter: <span className="font-medium text-foreground">{dateRange.toUpperCase()}</span>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="size-4 text-muted-foreground" />
              Notes
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm leading-6 text-muted-foreground">
            Track spikes, patterns, and volume changes.
          </CardContent>
        </Card>
      </section>
    </div>
  );
}

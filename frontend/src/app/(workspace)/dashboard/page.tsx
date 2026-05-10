"use client";

import { useEffect, useState } from "react";
import { AlertTriangle } from "lucide-react";

import { MetricsGrid } from "@/components/dashboard/metrics-grid";
import { RecentFindingsTable } from "@/components/dashboard/recent-findings-table";
import { SpotlightTable } from "@/components/spotlight-table";
import { Card, CardContent } from "@/components/ui/card";
import { useAuth } from "@/components/providers/auth-provider";
import {
  getDashboardSummary,
  isApiConfigured,
  type DashboardSummary,
} from "@/lib/api";

const initialMetrics: DashboardSummary = {
  criticalCount: 0,
  findingsToday: 0,
  highCount: 0,
  findings: [],
  apiKeyExposureCount: 0,
  totalFindings: 0,
};

export default function DashboardPage() {
  const { status } = useAuth();
  const [metrics, setMetrics] = useState<DashboardSummary>(initialMetrics);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let active = true;

    async function loadDashboard() {
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
            "Set NEXT_PUBLIC_API_URL in frontend/.env.local to load live findings.",
          );
          setIsLoading(false);
        }
        return;
      }

      try {
        setIsLoading(true);
        setError(null);
        const summary = await getDashboardSummary();

        if (active) {
          setMetrics(summary);
        }
      } catch (loadError) {
        if (active) {
          const message =
            loadError instanceof Error
              ? loadError.message
              : "Unable to load findings from the backend API.";
          setError(message);
        }
      } finally {
        if (active) {
          setIsLoading(false);
        }
      }
    }

    loadDashboard();
    return () => {
      active = false;
    };
  }, [refreshKey, status]);

  return (
    <div className="flex flex-col gap-6">
      <MetricsGrid
        totalFindings={metrics.totalFindings}
        criticalCount={metrics.criticalCount}
        highCount={metrics.highCount}
        findingsToday={metrics.findingsToday}
        apiKeyExposureCount={metrics.apiKeyExposureCount}
        isLoading={isLoading}
      />

      {error ? (
        <Card className="border-red-500/20">
          <CardContent className="flex items-start gap-3 px-5 py-4 text-sm">
            <AlertTriangle className="mt-0.5 size-5 shrink-0" />
            <div>
              <div className="font-semibold">Dashboard unavailable</div>
              <p className="mt-1 text-muted-foreground">{error}</p>
            </div>
          </CardContent>
        </Card>
      ) : null}

      <RecentFindingsTable
        findings={metrics.findings.slice(0, 8)}
        isLoading={isLoading}
        error={error}
        title="Recent Findings"
      />

      <section className="space-y-3">
        <div className="flex flex-col gap-1">
          <h2 className="text-base font-semibold text-foreground">Feed</h2>
        </div>
        <SpotlightTable
          findings={metrics.findings}
          isLoading={isLoading}
          error={error}
          onRefresh={() => setRefreshKey((current) => current + 1)}
        />
      </section>
    </div>
  );
}

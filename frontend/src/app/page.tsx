"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { AlertTriangle, ArrowRight } from "lucide-react";

import { MetricsGrid } from "@/components/dashboard/metrics-grid";
import { RecentFindingsTable } from "@/components/dashboard/recent-findings-table";
import { DashboardHomeLinks } from "@/components/layout/dashboard-nav";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useAuth } from "@/components/providers/auth-provider";
import {
  getDashboardSummary,
  isApiConfigured,
  type DashboardSummary,
} from "@/lib/api";

const initialMetrics: DashboardSummary = {
  criticalCount: 0,
  findings: [],
  findingsToday: 0,
  highCount: 0,
  apiKeyExposureCount: 0,
  totalFindings: 0,
};

export default function HomePage() {
  const { status } = useAuth();
  const [metrics, setMetrics] = useState<DashboardSummary>(initialMetrics);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function loadHomepage() {
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
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Unable to load the operational dashboard.",
          );
        }
      } finally {
        if (active) {
          setIsLoading(false);
        }
      }
    }

    loadHomepage();
    return () => {
      active = false;
    };
  }, [status]);

  return (
    <main className="app-shell">
      <section className="page-container flex min-h-screen flex-col gap-6 py-8">
        <div className="flex flex-col gap-4 border-b border-border pb-6 lg:flex-row lg:items-end lg:justify-between">
          <div className="space-y-2">
            <p className="eyebrow">DarkShield Operations</p>
            <h1 className="text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
              Live cybersecurity operations dashboard
            </h1>
            <p className="max-w-3xl text-sm leading-6 text-muted-foreground">
              Monitor findings, exposed secrets, and high-priority activity from the backend API.
            </p>
          </div>
          <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center">
            <DashboardHomeLinks />
            <Button asChild>
              <Link href="/dashboard">
                Open Workspace
                <ArrowRight className="size-4" />
              </Link>
            </Button>
          </div>
        </div>

        {error ? (
          <Card className="border-red-500/20">
            <CardContent className="flex items-start gap-3 px-5 py-4 text-sm">
              <AlertTriangle className="mt-0.5 size-5 shrink-0" />
              <div>
                <div className="font-semibold">Homepage metrics unavailable</div>
                <p className="mt-1 text-muted-foreground">{error}</p>
              </div>
            </CardContent>
          </Card>
        ) : null}

        <MetricsGrid
          totalFindings={metrics.totalFindings}
          criticalCount={metrics.criticalCount}
          highCount={metrics.highCount}
          findingsToday={metrics.findingsToday}
          apiKeyExposureCount={metrics.apiKeyExposureCount}
          isLoading={isLoading}
        />

        <RecentFindingsTable
          findings={metrics.findings.slice(0, 10)}
          isLoading={isLoading}
          error={error}
          title="Recent Findings"
        />

        {!isLoading && !error && metrics.findings.length === 0 ? (
          <Card>
            <CardContent className="px-5 py-10 text-center text-sm text-muted-foreground">
              No findings are available yet. Once the backend pipeline writes data, the operational dashboard will populate automatically.
            </CardContent>
          </Card>
        ) : null}
      </section>
    </main>
  );
}

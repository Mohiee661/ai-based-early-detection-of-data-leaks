"use client";

import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Clock3, ShieldAlert, ShieldCheck } from "lucide-react";

import { SeverityBadge } from "@/components/findings/severity-badge";
import { SpotlightTable } from "@/components/spotlight-table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/components/providers/auth-provider";
import { getFindings, isApiConfigured } from "@/lib/api";
import { type Finding } from "@/types/findings";

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

function formatConfidence(value: number | null | undefined) {
  if (value == null || Number.isNaN(value)) {
    return "Unknown";
  }

  return `${Math.round(value * 100)}%`;
}

export default function FindingsPage() {
  const { status } = useAuth();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let active = true;

    async function loadFindings() {
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
        const nextFindings = await getFindings({
          pageSize: 100,
          sortBy: "created_at",
          sortOrder: "desc",
        });

        if (active) {
          setFindings(nextFindings.items);
        }
      } catch (loadError) {
        if (active) {
          setFindings([]);
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Unable to load the threat feed from the backend API.",
          );
        }
      } finally {
        if (active) {
          setIsLoading(false);
        }
      }
    }

    loadFindings();
    return () => {
      active = false;
    };
  }, [refreshKey, status]);

  const latestFinding = findings[0] ?? null;
  const criticalCount = useMemo(
    () => findings.filter((finding) => finding.severity === "CRITICAL").length,
    [findings],
  );

  return (
    <div className="flex flex-col gap-6">
      <section className="grid gap-4 lg:grid-cols-[minmax(0,1.3fr)_minmax(320px,0.7fr)]">
        <Card>
          <CardHeader>
            <CardTitle>Overview</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm text-muted-foreground">
            <div className="flex flex-wrap items-center gap-4 text-sm">
              <div>
                <span className="font-medium text-foreground">{findings.length}</span> total loaded
              </div>
              <div>
                <span className="font-medium text-foreground">{criticalCount}</span> critical
              </div>
              <div>
                <span className="font-medium text-foreground">
                  {isLoading ? "..." : isApiConfigured ? "Connected" : "Unavailable"}
                </span>{" "}
                source
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock3 className="size-4 text-muted-foreground" />
              Latest
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {isLoading ? (
              <div className="space-y-2">
                <div className="h-5 w-24 animate-pulse rounded bg-muted" />
                <div className="h-4 w-full animate-pulse rounded bg-muted" />
                <div className="h-4 w-2/3 animate-pulse rounded bg-muted" />
              </div>
            ) : latestFinding ? (
              <>
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={latestFinding.severity} />
                  <span className="text-sm text-muted-foreground">
                    {formatTimestamp(latestFinding.created_at)}
                  </span>
                </div>
                <div className="text-sm font-medium text-foreground">
                  {latestFinding.pattern_type}
                </div>
                <div className="break-all font-mono text-xs text-foreground">
                  {latestFinding.matched_value}
                </div>
                <div className="flex flex-wrap items-center gap-2 pt-2 text-xs text-muted-foreground">
                  <span className="rounded-full border border-border px-2.5 py-1 text-foreground">
                    AI {latestFinding.ai_label ?? "unclassified"}
                  </span>
                  <span className="rounded-full border border-border px-2.5 py-1 text-foreground">
                    Confidence {formatConfidence(latestFinding.ai_confidence)}
                  </span>
                </div>
                <p className="pt-2 text-sm leading-6 text-muted-foreground">
                  {latestFinding.groq_summary || "AI summary will appear here once enrichment completes."}
                </p>
              </>
            ) : (
              <div className="text-sm text-muted-foreground">
                No recent findings are available yet.
              </div>
            )}
          </CardContent>
        </Card>
      </section>

      {error ? (
        <Card className="border-red-500/20">
          <CardContent className="flex items-start gap-3 px-5 py-4 text-sm">
            <AlertTriangle className="mt-0.5 size-5 shrink-0" />
            <div>
              <div className="font-semibold">Threat feed unavailable</div>
              <p className="mt-1 text-muted-foreground">{error}</p>
            </div>
          </CardContent>
        </Card>
      ) : null}

      {!isLoading && !error && findings.length === 0 ? (
        <Card>
          <CardContent className="flex items-start gap-3 px-5 py-6 text-sm">
            <ShieldCheck className="mt-0.5 size-5 shrink-0 text-muted-foreground" />
            <div>
              <div className="font-semibold text-foreground">No findings available</div>
              <p className="mt-1 text-muted-foreground">
                The feed is connected, but no findings have been written yet.
              </p>
            </div>
          </CardContent>
        </Card>
      ) : null}

      <section className="space-y-3">
        <div className="flex flex-col gap-1">
          <h2 className="flex items-center gap-2 text-base font-semibold text-foreground">
            <ShieldAlert className="size-4 text-muted-foreground" />
            Feed
          </h2>
        </div>
        <SpotlightTable
          findings={findings}
          isLoading={isLoading}
          error={error}
          onRefresh={() => setRefreshKey((current) => current + 1)}
        />
      </section>
    </div>
  );
}

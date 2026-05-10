"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCheck,
  Clock3,
  EyeOff,
  RefreshCcw,
  ShieldAlert,
} from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  getAlerts,
  getUnreadAlertCount,
  markAlertRead,
  markAllAlertsRead,
  type AlertsQueryResponse,
} from "@/lib/api";
import { useAuth } from "@/components/providers/auth-provider";
import { type Alert, type AlertStatus } from "@/types/alerts";

const severityClasses: Record<Alert["severity"], string> = {
  CRITICAL: "border-red-500/20 bg-red-500/10 text-red-200",
  HIGH: "border-orange-500/20 bg-orange-500/10 text-orange-200",
  MEDIUM: "border-amber-500/20 bg-amber-500/10 text-amber-200",
  LOW: "border-emerald-500/20 bg-emerald-500/10 text-emerald-200",
};

const statusOptions: Array<{ label: string; value: AlertStatus | "ALL" }> = [
  { label: "All alerts", value: "ALL" },
  { label: "Unread", value: "UNREAD" },
  { label: "Read", value: "READ" },
];

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function AlertBadge({ severity }: { severity: Alert["severity"] }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium ${severityClasses[severity]}`}
    >
      {severity}
    </span>
  );
}

function AlertRow({
  alert,
  onMarkRead,
  isUpdating,
}: {
  alert: Alert;
  onMarkRead: (id: string) => void;
  isUpdating: boolean;
}) {
  return (
    <article
      className={`rounded-[var(--radius)] border p-4 transition-colors ${
        alert.status === "UNREAD"
          ? "border-border bg-card shadow-sm"
          : "border-border/60 bg-muted/30"
      }`}
    >
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <AlertBadge severity={alert.severity} />
            <span className="rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground">
              {alert.status === "UNREAD" ? "Unread" : "Read"}
            </span>
            {alert.target_domain_match ? (
              <span className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2.5 py-1 text-xs text-cyan-200">
                Target domain match
              </span>
            ) : null}
          </div>

          <div className="space-y-1">
            <h3 className="text-base font-semibold text-foreground">{alert.title}</h3>
            <p className="max-w-3xl text-sm leading-6 text-muted-foreground">{alert.message}</p>
          </div>

          <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
            <span className="inline-flex items-center gap-1.5">
              <ShieldAlert className="size-3.5" />
              {alert.pattern_type}
            </span>
            <span className="inline-flex items-center gap-1.5">
              <Clock3 className="size-3.5" />
              {formatTimestamp(alert.created_at)}
            </span>
            <span>Score {alert.risk_score}</span>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {alert.status === "UNREAD" ? (
            <>
              <Button variant="outline" size="sm" asChild>
                <Link href={`/cases?alert_id=${encodeURIComponent(alert.id)}`}>Create case</Link>
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onMarkRead(alert.id)}
                disabled={isUpdating}
              >
                <CheckCheck className="size-4" />
                Mark read
              </Button>
            </>
          ) : (
            <>
              <Button variant="outline" size="sm" asChild>
                <Link href={`/cases?alert_id=${encodeURIComponent(alert.id)}`}>Create case</Link>
              </Button>
              <span className="inline-flex items-center gap-2 rounded-full border border-border px-3 py-2 text-xs text-muted-foreground">
                <EyeOff className="size-3.5" />
                Archived
              </span>
            </>
          )}
        </div>
      </div>
    </article>
  );
}

export default function AlertsPage() {
  const { status: authStatus } = useAuth();
  const [alerts, setAlerts] = useState<AlertsQueryResponse | null>(null);
  const [selectedStatus, setSelectedStatus] = useState<AlertStatus | "ALL">("ALL");
  const [isInitialLoading, setIsInitialLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [updatingAlertId, setUpdatingAlertId] = useState<string | null>(null);
  const [unreadCount, setUnreadCount] = useState(0);

  const loadAlerts = useCallback(async (silent = false) => {
    if (!silent) {
      setIsInitialLoading(true);
    } else {
      setIsRefreshing(true);
    }

    setError(null);

    try {
      const [nextAlerts, nextUnread] = await Promise.all([
        getAlerts({ page: 1, pageSize: 50, status: selectedStatus }),
        getUnreadAlertCount(),
      ]);
      setAlerts(nextAlerts);
      setUnreadCount(nextUnread.unread_count);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Failed to load alerts.");
    } finally {
      setIsInitialLoading(false);
      setIsRefreshing(false);
    }
  }, [selectedStatus]);

  useEffect(() => {
    if (authStatus !== "authenticated") {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      void loadAlerts();
    }, 0);

    return () => window.clearTimeout(timeoutId);
  }, [authStatus, loadAlerts]);

  useEffect(() => {
    if (authStatus !== "authenticated") {
      return undefined;
    }

    const intervalId = window.setInterval(() => {
      void loadAlerts(true);
    }, 30000);

    return () => window.clearInterval(intervalId);
  }, [authStatus, loadAlerts]);

  const items = useMemo(() => alerts?.items ?? [], [alerts]);
  const unreadItems = useMemo(() => items.filter((item) => item.status === "UNREAD"), [items]);
  const criticalCount = useMemo(
    () => items.filter((item) => item.severity === "CRITICAL").length,
    [items],
  );

  async function handleMarkRead(alertId: string) {
    setUpdatingAlertId(alertId);
    setError(null);

    try {
      const updated = await markAlertRead(alertId);
      setAlerts((current) =>
        current
          ? {
              ...current,
              items: current.items.map((item) => (item.id === updated.id ? updated : item)),
            }
          : current,
      );
      setUnreadCount((current) => Math.max(0, current - 1));
    } catch (markError) {
      setError(markError instanceof Error ? markError.message : "Failed to update alert.");
    } finally {
      setUpdatingAlertId(null);
    }
  }

  async function handleMarkAllRead() {
    setUpdatingAlertId("bulk");
    setError(null);

    try {
      await markAllAlertsRead();
      await loadAlerts(true);
    } catch (bulkError) {
      setError(bulkError instanceof Error ? bulkError.message : "Failed to update alerts.");
    } finally {
      setUpdatingAlertId(null);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="grid gap-4 md:grid-cols-3">
        <Card className="border-border/80 bg-card/90">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Unread alerts</CardTitle>
          </CardHeader>
          <CardContent className="flex items-end justify-between">
            <div className="text-3xl font-semibold text-foreground">{unreadCount}</div>
            <BellStat label="Live" value={isRefreshing ? "Refreshing" : "Synced"} />
          </CardContent>
        </Card>

        <Card className="border-border/80 bg-card/90">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Critical alerts</CardTitle>
          </CardHeader>
          <CardContent className="text-3xl font-semibold text-foreground">{criticalCount}</CardContent>
        </Card>

        <Card className="border-border/80 bg-card/90">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Alert feed</CardTitle>
          </CardHeader>
          <CardContent className="text-3xl font-semibold text-foreground">{alerts?.total ?? 0}</CardContent>
        </Card>
      </div>

      <Card className="border-border/80 bg-card/90">
          <CardHeader className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
            <CardTitle className="text-xl">Alerts</CardTitle>
            </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => void loadAlerts(true)} disabled={isRefreshing}>
              <RefreshCcw className="size-4" />
              Refresh
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void handleMarkAllRead()}
              disabled={updatingAlertId === "bulk" || unreadCount === 0}
            >
              <CheckCheck className="size-4" />
              Mark all read
            </Button>
          </div>
        </CardHeader>

        <CardContent className="space-y-5">
          <div className="flex flex-wrap gap-2">
            {statusOptions.map((option) => {
              const active = selectedStatus === option.value;
              return (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => setSelectedStatus(option.value)}
                  className={`rounded-full border px-4 py-2 text-sm transition-colors ${
                    active
                      ? "border-primary bg-primary text-primary-foreground"
                      : "border-border bg-background text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                  }`}
                >
                  {option.label}
                </button>
              );
            })}
          </div>

          {error ? (
            <div className="rounded-[var(--radius)] border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-200">
              {error}
            </div>
          ) : null}

          {isInitialLoading ? (
            <div className="space-y-3">
              <AlertSkeleton />
              <AlertSkeleton />
              <AlertSkeleton />
            </div>
          ) : items.length > 0 ? (
            <div className="space-y-3">
              {items.map((alert) => (
                <AlertRow
                  key={alert.id}
                  alert={alert}
                  onMarkRead={handleMarkRead}
                  isUpdating={updatingAlertId === alert.id}
                />
              ))}
            </div>
          ) : (
            <div className="flex min-h-[280px] flex-col items-center justify-center rounded-[var(--radius)] border border-dashed border-border bg-background/50 px-6 text-center">
              <AlertTriangle className="size-10 text-muted-foreground" />
              <h3 className="mt-4 text-lg font-semibold text-foreground">No alerts</h3>
              <p className="mt-2 max-w-lg text-sm leading-6 text-muted-foreground">
                Critical findings and high-risk matches will appear here.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="border-border/80 bg-card/90">
          <CardHeader>
          <CardTitle className="text-base">Unread</CardTitle>
        </CardHeader>
        <CardContent>
          {unreadItems.length > 0 ? (
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {unreadItems.slice(0, 3).map((alert) => (
                <div key={alert.id} className="rounded-[var(--radius)] border border-border bg-background p-4">
                  <div className="flex items-center justify-between gap-2">
                    <AlertBadge severity={alert.severity} />
                    <span className="text-xs text-muted-foreground">{formatTimestamp(alert.created_at)}</span>
                  </div>
                  <div className="mt-3 text-sm font-medium text-foreground">{alert.title}</div>
                  <p className="mt-2 line-clamp-3 text-sm leading-6 text-muted-foreground">
                    {alert.message}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-[var(--radius)] border border-border bg-background px-4 py-6 text-sm text-muted-foreground">
              All caught up. New alerts will appear here during the next polling cycle.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function BellStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-full border border-border bg-background px-3 py-1 text-right">
      <div className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground">{label}</div>
      <div className="text-xs font-medium text-foreground">{value}</div>
    </div>
  );
}

function AlertSkeleton() {
  return (
    <div className="rounded-[var(--radius)] border border-border bg-background p-4">
      <div className="flex items-center gap-2">
        <div className="h-6 w-20 rounded-full bg-muted" />
        <div className="h-6 w-24 rounded-full bg-muted" />
      </div>
      <div className="mt-4 h-4 w-3/5 rounded-full bg-muted" />
      <div className="mt-3 h-4 w-full rounded-full bg-muted" />
      <div className="mt-2 h-4 w-5/6 rounded-full bg-muted" />
    </div>
  );
}

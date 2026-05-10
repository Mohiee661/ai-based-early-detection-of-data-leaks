import {
  KeyRound,
  ShieldAlert,
  ShieldCheck,
  Siren,
  TriangleAlert,
} from "lucide-react";

import { MetricCard } from "@/components/dashboard/metric-card";

type MetricsGridProps = {
  apiKeyExposureCount: number;
  criticalCount: number;
  findingsToday: number;
  highCount: number;
  isLoading?: boolean;
  totalFindings: number;
};

function formatValue(value: number, isLoading: boolean) {
  return isLoading ? "..." : value.toLocaleString();
}

export function MetricsGrid({
  apiKeyExposureCount,
  criticalCount,
  findingsToday,
  highCount,
  isLoading = false,
  totalFindings,
}: MetricsGridProps) {
  return (
    <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
      <MetricCard
        label="Total Findings"
        value={formatValue(totalFindings, isLoading)}
        description="All findings"
        icon={ShieldCheck}
      />
      <MetricCard
        label="Critical Threats"
        value={formatValue(criticalCount, isLoading)}
        description="Immediate attention"
        icon={Siren}
        tone="critical"
      />
      <MetricCard
        label="High Severity"
        value={formatValue(highCount, isLoading)}
        description="Priority findings"
        icon={ShieldAlert}
        tone="high"
      />
      <MetricCard
        label="Findings Today"
        value={formatValue(findingsToday, isLoading)}
        description="Today"
        icon={TriangleAlert}
      />
      <MetricCard
        label="API Key Exposures"
        value={formatValue(apiKeyExposureCount, isLoading)}
        description="Key patterns"
        icon={KeyRound}
      />
    </section>
  );
}

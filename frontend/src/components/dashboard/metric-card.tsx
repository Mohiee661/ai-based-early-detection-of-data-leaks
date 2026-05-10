import { type LucideIcon } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type MetricCardProps = {
  description: string;
  icon: LucideIcon;
  label: string;
  tone?: "critical" | "high" | "neutral";
  value: string;
};

const tones = {
  critical: "bg-red-500/10 text-red-200",
  high: "bg-amber-500/10 text-amber-200",
  neutral: "bg-muted text-muted-foreground",
};

export function MetricCard({
  description,
  icon: Icon,
  label,
  tone = "neutral",
  value,
}: MetricCardProps) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="text-xs font-medium uppercase tracking-[0.14em] text-muted-foreground">
              {label}
            </p>
            <CardTitle className="mt-1 text-xl font-semibold">{value}</CardTitle>
          </div>
          <div className={`rounded-[calc(var(--radius)-2px)] p-2 ${tones[tone]}`}>
            <Icon className="size-4.5" />
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-xs leading-5 text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  );
}

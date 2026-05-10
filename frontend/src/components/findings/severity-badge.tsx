import { cn } from "@/lib/utils";
import { type Finding } from "@/types/findings";

const severityClasses: Record<Finding["severity"], string> = {
  CRITICAL: "border-red-500/20 bg-red-500/10 text-red-200",
  HIGH: "border-amber-500/20 bg-amber-500/10 text-amber-200",
  MEDIUM: "border-slate-500/20 bg-slate-500/10 text-slate-300",
  LOW: "border-border bg-muted text-muted-foreground",
};

type SeverityBadgeProps = {
  severity: Finding["severity"];
  className?: string;
};

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex rounded-full border px-2.5 py-1 text-xs font-medium",
        severityClasses[severity],
        className,
      )}
    >
      {severity}
    </span>
  );
}

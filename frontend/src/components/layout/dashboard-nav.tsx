import Link from "next/link";
import {
  Bell,
  ChartColumn,
  Bot,
  Globe,
  LayoutDashboard,
  ScrollText,
  ShieldCheck,
  Settings,
  ShieldAlert,
} from "lucide-react";

import { cn } from "@/lib/utils";

export const dashboardRoutes = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/findings", label: "Feed", icon: ShieldAlert },
  { href: "/lookup", label: "Lookup", icon: Globe },
  { href: "/analytics", label: "Analytics", icon: ChartColumn },
  { href: "/alerts", label: "Alerts", icon: Bell },
  { href: "/investigations", label: "Timeline", icon: ScrollText },
  { href: "/cases", label: "Cases", icon: ShieldCheck },
  { href: "/copilot", label: "Copilot", icon: Bot },
  { href: "/settings", label: "Settings", icon: Settings },
] as const;

type DashboardNavProps = {
  currentPath: string;
  onNavigate?: () => void;
};

export function DashboardNav({ currentPath, onNavigate }: DashboardNavProps) {
  return (
    <nav className="flex flex-col gap-1">
      {dashboardRoutes.map(({ href, label, icon: Icon }) => {
        const active = currentPath === href;

        return (
          <Link
            key={href}
          href={href}
          onClick={onNavigate}
          className={cn(
              "inline-flex items-center gap-2 rounded-[var(--radius)] px-3 py-2 text-sm transition-colors",
              active
                ? "bg-sidebar-accent text-sidebar-accent-foreground"
                : "text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
            )}
          >
            <Icon className="size-4 shrink-0" />
            <span>{label}</span>
          </Link>
        );
      })}
    </nav>
  );
}

export function DashboardHomeLinks() {
  return (
    <div className="flex flex-wrap gap-2">
      {dashboardRoutes.slice(0, 3).map(({ href, label }) => (
        <Link
          key={href}
          href={href}
          className="inline-flex items-center rounded-[var(--radius)] border border-border px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
        >
          {label}
        </Link>
      ))}
    </div>
  );
}

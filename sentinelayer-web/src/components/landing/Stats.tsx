import { AlertTriangle, Clock, Shield, Zap } from "lucide-react";
import { useStats } from "@/hooks/useStats";
import { cn } from "@/lib/utils";
import { formatDuration, formatNumber } from "@/lib/format";
import { Skeleton } from "@/components/ui/skeleton";
import type { PublicStats } from "@/types/api";

const statsConfig: Array<{
  key: keyof PublicStats;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}> = [
  {
    key: "repos_protected",
    label: "Repos Protected",
    icon: Shield,
  },
  {
    key: "total_runs",
    label: "Scans Completed",
    icon: Zap,
  },
  {
    key: "total_p0_blocked",
    label: "Critical Issues Blocked",
    icon: AlertTriangle,
  },
  {
    key: "avg_duration_ms",
    label: "Avg Scan Time",
    icon: Clock,
  },
];

export function PublicStats({ className }: { className?: string }) {
  const { data, isLoading, isError } = useStats();

  if (isLoading) return <StatsLoading className={className} />;
  if (isError || !data) {
    return (
      <div className={cn("grid grid-cols-2 gap-6 md:grid-cols-4", className)}>
        {statsConfig.map((stat) => (
          <StatCard
            key={stat.key}
            value={stat.key === "avg_duration_ms" ? "0s" : "0"}
            label={stat.label}
            icon={stat.icon}
          />
        ))}
      </div>
    );
  }

  return (
    <div className={cn("grid grid-cols-2 gap-6 md:grid-cols-4", className)}>
      {statsConfig.map((stat) => (
        <StatCard
          key={stat.key}
          value={
            stat.key === "avg_duration_ms"
              ? formatDuration(data.avg_duration_ms || 0)
              : formatNumber(data[stat.key] || 0)
          }
          label={stat.label}
          icon={stat.icon}
        />
      ))}
    </div>
  );
}

function StatCard({
  value,
  label,
  icon: Icon,
}: {
  value: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}) {
  return (
    <div className="rounded-3xl border border-border/60 bg-card/70 p-5 text-left shadow-soft">
      <div className="flex items-center gap-3">
        <span className="rounded-2xl bg-muted p-2">
          <Icon className="h-5 w-5 text-primary" />
        </span>
        <div>
          <p className="text-xl font-semibold">{value}</p>
          <p className="text-xs text-muted-foreground">{label}</p>
        </div>
      </div>
    </div>
  );
}

function StatsLoading({ className }: { className?: string }) {
  return (
    <div className={cn("grid grid-cols-2 gap-6 md:grid-cols-4", className)}>
      {Array.from({ length: 4 }).map((_, index) => (
        <Skeleton key={index} className="h-20" />
      ))}
    </div>
  );
}

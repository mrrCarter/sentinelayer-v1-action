import { AlertTriangle, CheckCircle2, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";
import type { RunStatus } from "@/types/run";

const statusConfig = {
  passed: {
    label: "Passed",
    icon: CheckCircle2,
    className: "bg-success/10 text-success",
  },
  blocked: {
    label: "Blocked",
    icon: ShieldAlert,
    className: "bg-destructive/10 text-destructive",
  },
  error: {
    label: "Error",
    icon: AlertTriangle,
    className: "bg-warning/10 text-warning",
  },
} as const;

export function GateStatus({
  status,
  size = "md",
}: {
  status: RunStatus;
  size?: "sm" | "md" | "lg";
}) {
  const config = statusConfig[status];
  const Icon = config.icon;

  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold",
        size === "sm" && "text-[11px]",
        size === "lg" && "px-4 py-2 text-sm",
        config.className
      )}
    >
      <Icon className={cn("h-4 w-4", size === "lg" && "h-5 w-5")} />
      {config.label}
    </span>
  );
}

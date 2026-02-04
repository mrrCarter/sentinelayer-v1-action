import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export function SummaryCard({
  title,
  value,
  icon: Icon,
  variant,
}: {
  title: string;
  value: string | number;
  icon: LucideIcon;
  variant?: "default" | "destructive" | "success";
}) {
  return (
    <div className="rounded-3xl border border-border/60 bg-card p-5 shadow-soft">
      <div className="flex items-center justify-between">
        <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
          {title}
        </p>
        <span
          className={cn(
            "inline-flex h-10 w-10 items-center justify-center rounded-2xl",
            variant === "destructive" && "bg-destructive/10 text-destructive",
            variant === "success" && "bg-success/10 text-success",
            (!variant || variant === "default") && "bg-muted text-muted-foreground"
          )}
        >
          <Icon className="h-5 w-5" />
        </span>
      </div>
      <p className="mt-4 text-2xl font-semibold">{value}</p>
    </div>
  );
}

import { cn } from "@/lib/utils";

export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        "animate-shimmer rounded-2xl bg-gradient-to-r from-muted/60 via-muted/40 to-muted/60",
        className
      )}
      style={{ backgroundSize: "200% 100%" }}
    />
  );
}

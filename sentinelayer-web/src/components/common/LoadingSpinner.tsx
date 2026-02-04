import { Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

export function LoadingSpinner({
  fullScreen,
  label = "Loading",
}: {
  fullScreen?: boolean;
  label?: string;
}) {
  return (
    <div
      className={cn(
        "flex items-center justify-center gap-3 text-muted-foreground",
        fullScreen ? "min-h-screen" : "py-10"
      )}
    >
      <Loader2 className="h-5 w-5 animate-spin" />
      <span className="text-sm font-medium">{label}</span>
    </div>
  );
}

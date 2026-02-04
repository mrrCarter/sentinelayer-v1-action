import { Ghost } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";

export function NotFound({
  title = "Not found",
  description = "We could not locate this resource.",
}: {
  title?: string;
  description?: string;
}) {
  return (
    <div className="flex min-h-[50vh] flex-col items-center justify-center gap-4 text-center">
      <div className="rounded-2xl bg-muted p-3">
        <Ghost className="h-6 w-6 text-muted-foreground" />
      </div>
      <div>
        <h2 className="text-2xl font-semibold">{title}</h2>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      <Button asChild variant="outline">
        <Link to="/dashboard">Back to dashboard</Link>
      </Button>
    </div>
  );
}

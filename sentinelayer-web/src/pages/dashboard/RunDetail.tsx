import { ExternalLink } from "lucide-react";
import { useParams } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { GateStatus } from "@/components/dashboard/GateStatus";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { FindingsTable } from "@/components/dashboard/FindingsTable";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { NotFound } from "@/components/common/NotFound";
import { useRun } from "@/hooks/useRuns";
import { formatDateTime, formatDuration } from "@/lib/format";

export function RunDetail() {
  const { runId } = useParams();
  const { data: run, isLoading } = useRun(runId);

  if (isLoading) return <LoadingSpinner />;
  if (!run) return <NotFound title="Run not found" />;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="flex items-center gap-3 text-2xl font-semibold">
            <GateStatus status={run.status} size="lg" />
            Run {run.id.slice(0, 8)}
          </h1>
          <p className="text-muted-foreground">
            {run.repo_owner}/{run.repo_name} - {formatDateTime(run.timestamp)}
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          {run.pr_url && (
            <Button variant="outline" asChild>
              <a href={run.pr_url} target="_blank" rel="noreferrer">
                View PR <ExternalLink className="ml-2 h-4 w-4" />
              </a>
            </Button>
          )}
          {run.artifacts_url && (
            <Button variant="outline" asChild>
              <a href={run.artifacts_url} download>
                Download Report
              </a>
            </Button>
          )}
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-4">
            <MetricCard label="Duration" value={formatDuration(run.duration_ms)} />
            <MetricCard label="Files Scanned" value={run.files_scanned} />
            <MetricCard label="LLM Cost" value={`$${run.cost_usd.toFixed(3)}`} />
            <MetricCard
              label="Tokens Used"
              value={run.tokens_in + run.tokens_out}
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Findings ({run.findings.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <FindingsTable findings={run.findings} />
        </CardContent>
      </Card>
    </div>
  );
}

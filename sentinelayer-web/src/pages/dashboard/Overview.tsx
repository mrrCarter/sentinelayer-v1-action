import { CheckCircle, FolderGit2, ShieldAlert, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SummaryCard } from "@/components/dashboard/SummaryCard";
import { TrendChart } from "@/components/dashboard/TrendChart";
import { RunsTable } from "@/components/dashboard/RunsTable";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { useRepos } from "@/hooks/useRepos";
import { useRuns, useRunsSummary } from "@/hooks/useRuns";

export function Overview() {
  const { data: repos, isLoading: reposLoading } = useRepos();
  const { data: summary, isLoading: summaryLoading } = useRunsSummary();
  const { data: recentRuns, isLoading: runsLoading } = useRuns({ limit: 5 });

  if (reposLoading || summaryLoading || runsLoading) {
    return <LoadingSpinner />;
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-semibold">Dashboard</h1>
        <p className="text-muted-foreground">
          Track security outcomes across your connected repositories.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <SummaryCard
          title="Repos Protected"
          value={repos?.length || 0}
          icon={FolderGit2}
        />
        <SummaryCard
          title="Runs This Week"
          value={summary?.thisWeek || 0}
          icon={Zap}
        />
        <SummaryCard
          title="Issues Blocked"
          value={summary?.blocked || 0}
          icon={ShieldAlert}
          variant="destructive"
        />
        <SummaryCard
          title="Pass Rate"
          value={`${summary?.passRate || 0}%`}
          icon={CheckCircle}
          variant="success"
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Findings Trend (30 Days)</CardTitle>
        </CardHeader>
        <CardContent>
          <TrendChart data={summary?.trend || []} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recent Runs</CardTitle>
        </CardHeader>
        <CardContent>
          <RunsTable runs={recentRuns || []} />
        </CardContent>
      </Card>
    </div>
  );
}

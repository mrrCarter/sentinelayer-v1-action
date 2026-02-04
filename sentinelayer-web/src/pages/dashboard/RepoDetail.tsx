import { useParams } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { FindingsBadge } from "@/components/dashboard/FindingsBadge";
import { GateStatus } from "@/components/dashboard/GateStatus";
import { RunsTable } from "@/components/dashboard/RunsTable";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { NotFound } from "@/components/common/NotFound";
import { useRepo } from "@/hooks/useRepos";
import { useRuns } from "@/hooks/useRuns";
import { formatRelativeTime } from "@/lib/format";

export function RepoDetail() {
  const { repoId } = useParams();
  const { data: repo, isLoading } = useRepo(repoId);
  const { data: runs, isLoading: runsLoading } = useRuns({ repo_id: repoId });

  if (isLoading || runsLoading) return <LoadingSpinner />;
  if (!repo) return <NotFound title="Repository not found" />;

  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-semibold">
          {repo.owner}/{repo.name}
        </h1>
        <p className="text-muted-foreground">
          Last run {formatRelativeTime(repo.last_run_at)}
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Current Status</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
          <FindingsBadge findings={repo.findings} />
          <GateStatus status={repo.last_run_status} size="lg" />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Run History</CardTitle>
        </CardHeader>
        <CardContent>
          <RunsTable runs={runs || []} />
        </CardContent>
      </Card>
    </div>
  );
}

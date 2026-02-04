import { FolderGit2 } from "lucide-react";
import { Link } from "react-router-dom";
import { Card, CardContent } from "@/components/ui/card";
import { FindingsBadge } from "@/components/dashboard/FindingsBadge";
import { GateStatus } from "@/components/dashboard/GateStatus";
import { formatRelativeTime } from "@/lib/format";
import type { Repo } from "@/types/repo";

interface RepoCardProps {
  repo: Repo;
}

export function RepoCard({ repo }: RepoCardProps) {
  return (
    <Card className="transition hover:-translate-y-1 hover:border-primary/50">
      <Link to={`/dashboard/repos/${repo.id}`}>
        <CardContent className="p-6">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div className="flex items-center gap-4">
              <div className="rounded-2xl bg-muted p-3">
                <FolderGit2 className="h-6 w-6 text-muted-foreground" />
              </div>
              <div>
                <h3 className="font-semibold">
                  {repo.owner}/{repo.name}
                </h3>
                <p className="text-sm text-muted-foreground">
                  Last run {formatRelativeTime(repo.last_run_at)}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <FindingsBadge findings={repo.findings} compact />
              <GateStatus status={repo.last_run_status} />
            </div>
          </div>
        </CardContent>
      </Link>
    </Card>
  );
}

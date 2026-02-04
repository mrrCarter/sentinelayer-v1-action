import { useMemo, useState } from "react";
import { History } from "lucide-react";
import { Input } from "@/components/ui/input";
import { RunsTable } from "@/components/dashboard/RunsTable";
import { EmptyState } from "@/components/common/EmptyState";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { useRuns } from "@/hooks/useRuns";

export function Runs() {
  const { data: runs, isLoading } = useRuns();
  const [search, setSearch] = useState("");

  const filteredRuns = useMemo(() => {
    if (!runs) return [];
    const query = search.trim().toLowerCase();
    if (!query) return runs;
    return runs.filter((run) =>
      `${run.repo_owner}/${run.repo_name} ${run.id}`
        .toLowerCase()
        .includes(query)
    );
  }, [runs, search]);

  if (isLoading) return <LoadingSpinner />;

  if (!runs?.length) {
    return (
      <EmptyState
        icon={History}
        title="No Runs Yet"
        description="Runs will appear here after your first Sentinelayer scan."
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-semibold">Run History</h1>
          <p className="text-muted-foreground">
            Review recent Sentinelayer scans across your repos.
          </p>
        </div>
        <Input
          placeholder="Search by repo or run id..."
          className="w-full md:w-64"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
      </div>

      <RunsTable runs={filteredRuns} />
    </div>
  );
}

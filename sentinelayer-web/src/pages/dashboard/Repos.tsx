import { useMemo, useState } from "react";
import { FolderGit2 } from "lucide-react";
import { RepoCard } from "@/components/dashboard/RepoCard";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/common/EmptyState";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { useRepos } from "@/hooks/useRepos";

export function Repos() {
  const { data: repos, isLoading } = useRepos();
  const [search, setSearch] = useState("");

  const filteredRepos = useMemo(() => {
    if (!repos) return [];
    const query = search.trim().toLowerCase();
    if (!query) return repos;
    return repos.filter((repo) =>
      `${repo.owner}/${repo.name}`.toLowerCase().includes(query)
    );
  }, [repos, search]);

  if (isLoading) return <LoadingSpinner />;

  if (!repos?.length) {
    return (
      <EmptyState
        icon={FolderGit2}
        title="No Repos Yet"
        description="Install the Sentinelayer Action in a repo to see it here."
        action={
          <Button asChild>
            <a href="https://github.com/marketplace/actions/sentinelayer">
              Install Action
            </a>
          </Button>
        }
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-semibold">Repositories</h1>
          <p className="text-muted-foreground">
            Monitor Sentinelayer coverage across your repos.
          </p>
        </div>
        <Input
          placeholder="Search repos..."
          className="w-full md:w-64"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
      </div>

      <div className="grid gap-4">
        {filteredRepos.map((repo) => (
          <RepoCard key={repo.id} repo={repo} />
        ))}
      </div>
    </div>
  );
}

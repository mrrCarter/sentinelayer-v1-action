import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

export function useRepos() {
  return useQuery({
    queryKey: ["repos"],
    queryFn: () => api.getRepos(),
  });
}

export function useRepo(repoId?: string) {
  return useQuery({
    queryKey: ["repo", repoId],
    queryFn: () => api.getRepo(repoId as string),
    enabled: !!repoId,
  });
}

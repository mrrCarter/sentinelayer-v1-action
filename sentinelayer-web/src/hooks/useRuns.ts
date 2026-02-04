import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

export function useRuns(params?: { repo_id?: string; limit?: number }) {
  return useQuery({
    queryKey: ["runs", params],
    queryFn: () => api.getRuns(params),
  });
}

export function useRun(runId?: string) {
  return useQuery({
    queryKey: ["run", runId],
    queryFn: () => api.getRun(runId as string),
    enabled: !!runId,
  });
}

export function useRunsSummary() {
  return useQuery({
    queryKey: ["runsSummary"],
    queryFn: () => api.getRunsSummary(),
  });
}

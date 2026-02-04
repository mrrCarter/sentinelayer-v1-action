import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";

export function useStats() {
  return useQuery({
    queryKey: ["publicStats"],
    queryFn: () => api.getPublicStats(),
  });
}

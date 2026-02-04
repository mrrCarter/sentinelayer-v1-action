export interface RepoFindingsCount {
  P0: number;
  P1: number;
  P2: number;
  P3: number;
}

export type RepoStatus = "passed" | "blocked" | "error";

export interface Repo {
  id: string;
  owner: string;
  name: string;
  last_run_at: string;
  last_run_status: RepoStatus;
  total_runs: number;
  findings: RepoFindingsCount;
}

export interface RepoDetail extends Repo {
  description?: string;
  default_branch?: string;
  created_at?: string;
}

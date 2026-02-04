export type RunStatus = "passed" | "blocked" | "error";

export interface RunFindingsCount {
  P0: number;
  P1: number;
  P2: number;
  P3: number;
}

export interface RunTrendPoint {
  date: string;
  P0: number;
  P1: number;
  P2: number;
  P3: number;
}

export interface Run {
  id: string;
  repo_id: string;
  repo_owner: string;
  repo_name: string;
  status: RunStatus;
  timestamp: string;
  duration_ms: number;
  findings: RunFindingsCount;
  pr_url?: string;
}

export interface Finding {
  id: string;
  severity: "P0" | "P1" | "P2" | "P3";
  title: string;
  description?: string;
  file_path?: string;
  line_start?: number;
  line_end?: number;
}

export interface RunDetail extends Omit<Run, "findings"> {
  files_scanned: number;
  tokens_in: number;
  tokens_out: number;
  cost_usd: number;
  artifacts_url?: string;
  findings: Finding[];
}

export interface RunsSummary {
  thisWeek: number;
  blocked: number;
  passRate: number;
  trend: RunTrendPoint[];
  runs: Run[];
}

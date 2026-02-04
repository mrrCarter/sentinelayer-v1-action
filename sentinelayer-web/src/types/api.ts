export interface User {
  id: string;
  github_username: string;
  avatar_url: string;
  email: string;
}

export interface PublicStats {
  repos_protected: number;
  total_runs: number;
  total_p0_blocked: number;
  avg_duration_ms: number;
}

export interface ApiErrorResponse {
  error: {
    code: string;
    message: string;
  };
}

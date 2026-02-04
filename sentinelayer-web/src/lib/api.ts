import type { ApiErrorResponse, PublicStats, User } from "@/types/api";
import type { Repo, RepoDetail } from "@/types/repo";
import type { Run, RunDetail, RunsSummary } from "@/types/run";

const API_URL =
  import.meta.env.VITE_API_URL || "https://api.sentinelayer.com";

export class ApiError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

class ApiClient {
  private token: string | null = null;

  setToken(token: string | null) {
    this.token = token;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers = new Headers(options.headers);
    headers.set("Content-Type", "application/json");

    if (this.token) {
      headers.set("Authorization", `Bearer ${this.token}`);
    }

    const response = await fetch(`${API_URL}${path}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      let errorMessage = "Request failed";
      let errorCode = "unknown";
      try {
        const payload = (await response.json()) as ApiErrorResponse;
        errorCode = payload.error?.code || errorCode;
        errorMessage = payload.error?.message || errorMessage;
      } catch {
        // ignore parsing errors
      }

      throw new ApiError(errorCode, errorMessage);
    }

    return response.json() as Promise<T>;
  }

  async getPublicStats() {
    return this.request<PublicStats>("/api/v1/public/stats");
  }

  async getMe() {
    return this.request<User>("/api/v1/auth/me");
  }

  async getRepos() {
    return this.request<Repo[]>("/api/v1/repos");
  }

  async getRepo(id: string) {
    return this.request<RepoDetail>(`/api/v1/repos/${id}`);
  }

  async getRuns(params?: { repo_id?: string; limit?: number }) {
    const query = new URLSearchParams();
    if (params?.repo_id) query.set("repo_id", params.repo_id);
    if (params?.limit) query.set("limit", String(params.limit));

    const suffix = query.toString();
    return this.request<Run[]>(`/api/v1/runs${suffix ? `?${suffix}` : ""}`);
  }

  async getRun(id: string) {
    return this.request<RunDetail>(`/api/v1/runs/${id}`);
  }

  async getRunsSummary() {
    return this.request<RunsSummary>("/api/v1/runs/summary");
  }
}

export const api = new ApiClient();

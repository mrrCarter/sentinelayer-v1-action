import { api } from "@/lib/api";
import type { User } from "@/types/api";

const GITHUB_CLIENT_ID = import.meta.env.VITE_GITHUB_CLIENT_ID;
const API_URL =
  import.meta.env.VITE_API_URL || "https://api.sentinelayer.com";

const TOKEN_KEY = "auth_token";
const STATE_KEY = "oauth_state";

export function initiateGitHubOAuth() {
  if (!GITHUB_CLIENT_ID) {
    throw new Error("Missing VITE_GITHUB_CLIENT_ID");
  }

  const state = crypto.randomUUID();
  sessionStorage.setItem(STATE_KEY, state);

  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    redirect_uri: `${window.location.origin}/login/callback`,
    scope: "read:user user:email",
    state,
  });

  window.location.href = `https://github.com/login/oauth/authorize?${params}`;
}

export async function handleOAuthCallback(code: string, state: string) {
  const savedState = sessionStorage.getItem(STATE_KEY);
  if (state !== savedState) {
    throw new Error("Invalid OAuth state");
  }
  sessionStorage.removeItem(STATE_KEY);

  const response = await fetch(`${API_URL}/api/v1/auth/github/callback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code }),
  });

  if (!response.ok) {
    throw new Error("OAuth failed");
  }

  const { token, user } = (await response.json()) as {
    token: string;
    user: User;
  };

  localStorage.setItem(TOKEN_KEY, token);
  api.setToken(token);
  return user;
}

export function getStoredToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function clearStoredToken() {
  localStorage.removeItem(TOKEN_KEY);
  api.setToken(null);
}

import { createContext } from "react";
import type { User } from "@/types/api";

export interface AuthContextValue {
  user: User | null;
  isLoading: boolean;
  login: () => void;
  logout: () => void;
  setUser: (user: User | null) => void;
}

export const AuthContext = createContext<AuthContextValue | null>(null);

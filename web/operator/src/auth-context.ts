import { createContext, useContext } from "react";
import type { OperatorSession } from "./types";

export type AuthContextValue = {
  session: OperatorSession | null;
  login: (secretKey: string) => Promise<void>;
  logout: () => void;
};

export const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}

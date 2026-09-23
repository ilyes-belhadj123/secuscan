import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, setUnauthorizedHandler, type Me } from "./api";

interface SessionValue {
  me: Me | null;
  loading: boolean;
  refresh: () => Promise<Me | null>;
  logout: () => Promise<void>;
}

const SessionContext = createContext<SessionValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const value = await api.me();
      setMe(value);
      return value;
    } catch {
      setMe(null);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => setMe(null)); // session expirée ou accès révoqué
    refresh();
  }, [refresh]);

  const logout = useCallback(async () => {
    await api.logout().catch(() => undefined);
    setMe(null);
  }, []);

  return <SessionContext.Provider value={{ me, loading, refresh, logout }}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession doit être utilisé dans <SessionProvider>");
  return value;
}

export const isAdmin = (me: Me | null) => me?.org.role === "owner" || me?.org.role === "admin";

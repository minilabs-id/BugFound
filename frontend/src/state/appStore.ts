import { create } from "zustand";
import { appReady } from "../lib/ipc";
import type { AppSnapshot } from "../lib/types";

type Connection = "connecting" | "connected" | "error";
export type Theme = "dark" | "light" | "system";

interface AppStore {
  connection: Connection;
  snapshot: AppSnapshot | null;
  error: string | null;
  theme: Theme;
  initialize: () => Promise<void>;
  setTheme: (theme: Theme) => void;
}

const THEME_KEY = "bugfound.theme";

function storedTheme(): Theme {
  const value = localStorage.getItem(THEME_KEY);
  return value === "light" || value === "dark" || value === "system" ? value : "system";
}

export const useAppStore = create<AppStore>((set) => ({
  connection: "connecting",
  snapshot: null,
  error: null,
  theme: storedTheme(),
  initialize: async () => {
    try {
      const snapshot = await appReady();
      set({ snapshot, connection: "connected", error: null });
    } catch (error) {
      set({
        connection: "error",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  },
  setTheme: (theme) => {
    localStorage.setItem(THEME_KEY, theme);
    set({ theme });
  },
}));

export function applyTheme(theme: Theme): void {
  const dark =
    theme === "dark" ||
    (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

declare const process: {
  readonly env: Readonly<Record<string, string | undefined>>;
};

const candidateEntry = new URL(
  "./src/rescue-repair-entry.candidate.tsx",
  import.meta.url,
).pathname;

export default defineConfig(() => {
  const repairCandidate = process.env.KERNAID_REPAIR_CANDIDATE ?? "0";
  if (repairCandidate !== "0" && repairCandidate !== "1") {
    throw new Error("KERNAID_REPAIR_CANDIDATE must be exactly 0 or 1");
  }

  return {
    base: "./",
    plugins: [react()],
    resolve: {
      alias:
        repairCandidate === "1"
          ? [
              {
                find: "./rescue-repair-entry",
                replacement: candidateEntry,
              },
            ]
          : [],
    },
    server: { port: 1420, strictPort: true },
  };
});

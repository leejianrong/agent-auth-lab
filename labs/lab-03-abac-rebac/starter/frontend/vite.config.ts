import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../../..");

export default defineConfig({
  plugins: [svelte()],
  resolve: {
    alias: {
      "@harness": path.resolve(repoRoot, "shared/observability-harness/frontend/src"),
    },
  },
  server: {
    fs: {
      allow: [repoRoot],
    },
  },
});

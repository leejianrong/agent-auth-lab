import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../../..");
// Under docker-compose the shared harness is copied in at build time, so the
// repo-relative path doesn't exist there. HARNESS_FRONTEND points at the copy.
const harnessFrontend =
  process.env.HARNESS_FRONTEND ?? path.resolve(repoRoot, "shared/observability-harness/frontend/src");

export default defineConfig({
  plugins: [svelte()],
  resolve: {
    alias: {
      "@harness": harnessFrontend,
    },
  },
  server: {
    fs: {
      allow: [repoRoot, harnessFrontend],
    },
  },
});

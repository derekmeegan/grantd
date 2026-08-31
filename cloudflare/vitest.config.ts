import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        compatibilityFlags: ["nodejs_compat"],
        // A real second of CPU per registration is the point in production and
        // pure waste in a test suite that registers dozens of agents.
        bindings: { POW_DIFFICULTY_BITS: "8" },
      },
    }),
  ],
});

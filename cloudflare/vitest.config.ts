import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        compatibilityFlags: ["nodejs_compat"],
        // A real second of CPU per registration is waste in a suite that
        // registers dozens of agents. The second flag permits the low value.
        bindings: { POW_DIFFICULTY_BITS: "8", POW_ALLOW_LOW_DIFFICULTY: "1" },
      },
    }),
  ],
});

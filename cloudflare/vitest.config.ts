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
        bindings: {
          POW_DIFFICULTY_BITS: "8",
          POW_ALLOW_LOW_DIFFICULTY: "1",
          // Host DNS naming, pointed at a zone that does not exist and a
          // suffix that is not routable. These override .dev.vars, which on a
          // maintainer's machine holds the real token: a suite that reached
          // the real Cloudflare API would write records in the real zone.
          // dns.test.ts asserts that this override actually took effect.
          CF_DNS_TOKEN: "test-token-not-a-real-credential",
          HOST_ZONE_ID: "00000000000000000000000000000000",
          HOST_DNS_SUFFIX: "hosts.grantd.test",
        },
      },
    }),
  ],
});

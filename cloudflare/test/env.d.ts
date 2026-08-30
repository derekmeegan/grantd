/// <reference types="@cloudflare/vitest-pool-workers/types" />

declare module "cloudflare:test" {
  import type { Env } from "../src/env";
  export const SELF: Fetcher;
  export const env: Env;
}

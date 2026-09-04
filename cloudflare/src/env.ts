/** Worker bindings. */

export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
  HOSTS: DurableObjectNamespace;
  AGENTS: DurableObjectNamespace;
  CHALLENGES: DurableObjectNamespace;

  /**
   * Rate limiters. Optional so that local runs work before the bindings exist.
   *
   * The IP-keyed limiters pair with the proof of work. The grant-keyed
   * limiter stops a distributed flood against one grant. grant_id is in the
   * request body, so an edge WAF rule cannot express that limit.
   */
  CHALLENGE_LIMITER?: RateLimiter;
  REGISTRATION_LIMITER?: RateLimiter;
  REDEMPTION_LIMITER?: RateLimiter;
  REDEMPTION_GRANT_LIMITER?: RateLimiter;

  RELEASES?: R2Bucket;

  /** Public origin used in generated instructions, for example https://grantd.example.workers.dev */
  PUBLIC_ORIGIN?: string;

  /**
   * Host DNS naming. All three must be set for a host to get a name; any one
   * missing leaves the feature off. See src/dns.ts.
   *
   * The token is a secret (`wrangler secret put CF_DNS_TOKEN`), scoped to
   * Zone -> DNS -> Edit on the one zone named by HOST_ZONE_ID. It is the only
   * credential this service holds that reaches outside itself.
   */
  CF_DNS_TOKEN?: string;
  /** Zone the host records live in. */
  HOST_ZONE_ID?: string;
  /** Suffix host names are built under, for example hosts.grantd.dev. */
  HOST_DNS_SUFFIX?: string;

  /** Proof-of-work difficulty in bits. Production uses the default when unset. */
  POW_DIFFICULTY_BITS?: string;

  /** Set to "1" in tests only. Permits POW_DIFFICULTY_BITS below the production floor. */
  POW_ALLOW_LOW_DIFFICULTY?: string;
}

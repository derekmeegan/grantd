/** Worker bindings. */

export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface Env {
  HOSTS: DurableObjectNamespace;
  AGENTS: DurableObjectNamespace;
  CHALLENGES: DurableObjectNamespace;

  /**
   * Rate limiters. Optional so that local test runs and a first deploy work
   * before the bindings exist.
   *
   * The IP-keyed limiters pair with the captcha's proof of work: registration
   * should be expensive in two dimensions, not one. The grant-keyed limiter is
   * the one that matters most, and it is the one an edge WAF rule cannot
   * express — a distributed flood of wrong proofs against a single grant does
   * not burn the grant, but each attempt wakes the customer's machine over the
   * rendezvous socket, which is a free amplification channel into someone's
   * box. Only a limiter keyed by grant_id closes it, and grant_id lives in the
   * request body where the edge cannot see it.
   */
  CHALLENGE_LIMITER?: RateLimiter;
  REGISTRATION_LIMITER?: RateLimiter;
  REDEMPTION_LIMITER?: RateLimiter;
  REDEMPTION_GRANT_LIMITER?: RateLimiter;

  RELEASES?: R2Bucket;

  /** Public origin used in generated instructions, e.g. https://grantd.example.workers.dev */
  PUBLIC_ORIGIN?: string;

  /** Proof-of-work difficulty. Lowered in tests; production uses the default. */
  POW_DIFFICULTY_BITS?: string;
}

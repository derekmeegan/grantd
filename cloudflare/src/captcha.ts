/**
 * Agent Captcha — admission control for self-service agent registration.
 *
 * Two halves, with different jobs:
 *
 *   - Proof of work is the cost function. It is what makes a million
 *     registrations expensive and one registration free.
 *   - The question is a liveness and instruction-following check. It is
 *     trivial for anything that can read English and annoying for a scraper
 *     that only replays HTTP.
 *
 * Neither half is a security boundary, and the protocol does not treat them as
 * one. A registered agent identity authorizes nothing: access still requires
 * possession of a grant secret that this service never sees. The point of this
 * file is to keep the public API from being free to abuse, not to keep anyone
 * out of a customer's machine.
 */

export interface ChallengeSpec {
  question: string;
  answer: string;
}

const WORDS = [
  "amber", "beacon", "cedar", "delta", "ember", "fjord", "gable", "harbor",
  "ivory", "jasper", "kelp", "lantern", "marble", "nimbus", "onyx", "pewter",
  "quarry", "ridge", "slate", "timber", "umber", "vellum", "willow", "zephyr",
];

const LETTER_WORDS = [
  "strawberry", "possession", "bookkeeper", "millennium", "committee",
  "assessment", "successful", "parallel", "occurrence", "necessary",
];

function pick<T>(arr: readonly T[], rng: () => number): T {
  return arr[Math.floor(rng() * arr.length)];
}

function randomInt(rng: () => number, min: number, max: number): number {
  return min + Math.floor(rng() * (max - min + 1));
}

function countLetter(word: string, letter: string): number {
  let n = 0;
  for (const c of word) if (c === letter) n++;
  return n;
}

/**
 * Generates one challenge. The formats are rigid on purpose: the reference
 * solver shipped with the agent CLI has to be able to answer them unattended so
 * that CI can exercise the whole flow without a human or a model in the loop.
 */
export function generateChallenge(rng: () => number = Math.random): ChallengeSpec {
  switch (randomInt(rng, 0, 3)) {
    case 0: {
      const a = randomInt(rng, 20, 99);
      const b = randomInt(rng, 1, 19);
      const c = randomInt(rng, 1, 19);
      return {
        question: `Compute: ${a} + ${b} - ${c}. Reply with only the resulting number.`,
        answer: String(a + b - c),
      };
    }
    case 1: {
      const chosen = new Set<string>();
      while (chosen.size < 4) chosen.add(pick(WORDS, rng));
      const words = [...chosen];
      const sorted = [...words].sort();
      return {
        question: `Sort these words alphabetically: ${words.join(", ")}. Reply with only the third word.`,
        answer: sorted[2],
      };
    }
    case 2: {
      const word = pick(LETTER_WORDS, rng);
      const letters = [...new Set(word.split(""))].filter((c) => countLetter(word, c) > 1);
      const letter = letters.length > 0 ? pick(letters, rng) : word[0];
      return {
        question: `Reply with only the number of times the letter "${letter}" appears in "${word}".`,
        answer: String(countLetter(word, letter)),
      };
    }
    default: {
      const chosen = new Set<string>();
      while (chosen.size < 5) chosen.add(pick(WORDS, rng));
      const words = [...chosen];
      const n = randomInt(rng, 1, 5);
      return {
        question: `Given the list: ${words.join(", ")}. Reply with only word number ${n}, counting from 1.`,
        answer: words[n - 1],
      };
    }
  }
}

/** Answers are compared case-insensitively after trimming. */
export function answerMatches(expected: string, given: string): boolean {
  return expected.trim().toLowerCase() === given.trim().toLowerCase();
}

/** Leading zero bits of a digest, used to score proof of work. */
export function leadingZeroBits(digest: Uint8Array): number {
  let n = 0;
  for (const byte of digest) {
    if (byte === 0) {
      n += 8;
      continue;
    }
    for (let i = 7; i >= 0; i--) {
      if (byte & (1 << i)) return n;
      n++;
    }
    return n;
  }
  return n;
}

/** Verifies SHA-256(prefix || utf8(nonce)) has at least difficultyBits zeros. */
export async function verifyPow(
  prefix: Uint8Array,
  difficultyBits: number,
  nonce: string,
): Promise<boolean> {
  if (nonce.length === 0 || nonce.length > 64) return false;
  const nonceBytes = new TextEncoder().encode(nonce);
  const buf = new Uint8Array(prefix.length + nonceBytes.length);
  buf.set(prefix, 0);
  buf.set(nonceBytes, prefix.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buf as BufferSource));
  return leadingZeroBits(digest) >= difficultyBits;
}

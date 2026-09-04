/**
 * Small seeded PRNG (mulberry32) so the generated mock dataset looks the same
 * across reloads within a demo -- deliberately not cryptographically random,
 * just deterministic enough that a presenter isn't surprised by different
 * numbers each time they refresh.
 */
export function createRng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state |= 0;
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function randRange(rng: () => number, min: number, max: number): number {
  return min + rng() * (max - min);
}

export function randInt(rng: () => number, min: number, max: number): number {
  return Math.floor(randRange(rng, min, max + 1));
}

export function choice<T>(rng: () => number, items: readonly T[]): T {
  return items[Math.floor(rng() * items.length)];
}

/** Weighted random pick. `weights` need not sum to 1. */
export function weightedChoice<T>(rng: () => number, items: readonly T[], weights: readonly number[]): T {
  const total = weights.reduce((sum, w) => sum + w, 0);
  let target = rng() * total;
  for (let i = 0; i < items.length; i++) {
    target -= weights[i];
    if (target <= 0) return items[i];
  }
  return items[items.length - 1];
}

/** Multiplies a numeric value by (1 +/- fraction), for realistic per-sample variation. */
export function jitter(rng: () => number, value: number, fraction: number): number {
  return value * (1 + randRange(rng, -fraction, fraction));
}

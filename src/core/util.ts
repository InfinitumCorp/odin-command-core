import type { AssetKind, Pos, State } from "./types";

export const dist = (a: Pos, b: Pos) => Math.hypot(a.x - b.x, a.y - b.y);

export const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

/** km per simulated minute. Fixed nodes (ARGUS) do not move. */
export const SPEED: Record<AssetKind, number> = {
  ARGUS: 0,
  POLLEN: 1.2,
  DAEMON: 3.5,
  ORBIS: 0.8,
  HRVST: 0.08,
  SLUG: 0.5,
  AETHER: 0.5,
};

/** Battery drained per simulated minute while moving. */
export const DRAIN: Record<AssetKind, number> = {
  ARGUS: 0,
  POLLEN: 0.9,
  DAEMON: 0.25,
  ORBIS: 1.2,
  HRVST: 0.05,
  SLUG: 0.15,
  AETHER: 0.15,
};

/** mulberry32 step: returns [value in 0..1, next state]. */
export function rand(state: number): [number, number] {
  let s = (state + 0x6d2b79f5) | 0;
  let r = Math.imul(s ^ (s >>> 15), 1 | s);
  r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) ^ r;
  return [((r ^ (r >>> 14)) >>> 0) / 4294967296, s];
}

/** Draws a random number from the state's PRNG and advances it in place (state is a draft copy). */
export function draw(s: State): number {
  const [v, next] = rand(s.rng);
  s.rng = next;
  return v;
}

export function nextId(s: State, prefix: string): string {
  s.nextId += 1;
  return `${prefix}-${String(s.nextId).padStart(4, "0")}`;
}

export function fmtPos(p: Pos): string {
  return `${p.x.toFixed(1)}E ${p.y.toFixed(1)}N`;
}

export function fmtTime(t: number): string {
  const h = Math.floor(t / 60) % 24;
  const m = Math.floor(t % 60);
  return `${String(h).padStart(2, "0")}${String(m).padStart(2, "0")}Z`;
}

import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { sha256 } from "./sha256";
import { append, verify } from "./ledger";
import { fuse } from "./orient";
import { initialState, run } from "./engine";
import type { State } from "./types";

describe("sha256", () => {
  it.each(["", "abc", "ODIN° Observe Orient Decide Act", "x".repeat(1000)])("matches node crypto for %#", (msg) => {
    expect(sha256(msg)).toBe(createHash("sha256").update(msg, "utf8").digest("hex"));
  });
});

describe("Firmament ledger", () => {
  const build = () => {
    let l = append([], 0, "CDR-1", "a", { n: 1 });
    l = append(l, 1, "CDR-1", "b", { n: 2 });
    return append(l, 2, "CDR-1", "c", { n: 3 });
  };

  it("verifies an untouched chain", () => {
    expect(verify(build())).toEqual({ ok: true, length: 3 });
  });

  it("detects an edited entry", () => {
    const l = build();
    l[1] = { ...l[1], payload: { n: 99 } };
    expect(verify(l)).toMatchObject({ ok: false, brokenAt: 1, reason: "entry contents altered" });
  });

  it("detects a deleted entry", () => {
    const l = build();
    l.splice(1, 1);
    expect(verify(l)).toMatchObject({ ok: false, brokenAt: 1 });
  });

  it("detects a re-hashed forgery that does not relink the chain", () => {
    const l = build();
    const forged = append(l.slice(0, 1), 1, "CDR-1", "b", { n: 42 });
    expect(verify([...forged, l[2]])).toMatchObject({ ok: false, brokenAt: 2, reason: "chain link mismatch" });
  });
});

describe("orient", () => {
  it("fuses independent confidences", () => {
    expect(fuse(0.5, 0.5)).toBeCloseTo(0.75);
    expect(fuse(0.9, 0)).toBeCloseTo(0.9);
  });
});

function runUntil(s: State, pred: (s: State) => boolean, max = 600): State {
  for (let i = 0; i < max && !pred(s); i++) s = run(s, { type: "tick" }).state;
  return s;
}

describe("ODIN loop", () => {
  it("is deterministic for a seed", () => {
    const a = run(initialState(7), { type: "tick", minutes: 120 }).state;
    const b = run(initialState(7), { type: "tick", minutes: 120 }).state;
    expect(a.ledger.at(-1)?.hash).toBe(b.ledger.at(-1)?.hash);
  });

  it("does not mutate the previous state", () => {
    const s0 = initialState(3);
    const snapshot = JSON.stringify(s0);
    run(s0, { type: "tick", minutes: 30 });
    expect(JSON.stringify(s0)).toBe(snapshot);
  });

  it("raises decision points with drafted COAs and never tasks assets on its own", () => {
    const s = runUntil(initialState(11), (x) => x.decisions.length > 0);
    expect(s.decisions.length).toBeGreaterThan(0);
    expect(s.decisions[0].coas.length).toBeGreaterThan(0);
    const later = run(s, { type: "tick", minutes: 200 }).state;
    expect(later.tasks).toHaveLength(0);
    expect(later.assets.every((a) => a.status === "ready")).toBe(true);
  });

  it("refuses approval from an analyst and records the denial", () => {
    let s = runUntil(initialState(11), (x) => x.decisions.length > 0);
    s = run(s, { type: "set-operator", operator: { id: "ANL-4", role: "analyst" } }).state;
    const dp = s.decisions[0];
    const r = run(s, { type: "approve", decisionId: dp.id, coaId: dp.coas[0].id });
    expect(r.error).toMatch(/commander/);
    expect(r.state.decisions[0].status).toBe("open");
    expect(r.state.tasks).toHaveLength(0);
    expect(r.state.ledger.at(-1)?.action).toBe("approval.denied");
  });

  it("carries an approved COA through tasking to completion, all on a valid ledger", () => {
    let s = runUntil(initialState(11), (x) => x.decisions.some((d) => d.coas.some((c) => c.actions.length > 0)));
    const dp = s.decisions.find((d) => d.coas.some((c) => c.actions.length > 0))!;
    const coa = dp.coas.find((c) => c.actions.length > 0)!;
    const r = run(s, { type: "approve", decisionId: dp.id, coaId: coa.id });
    expect(r.error).toBeUndefined();
    s = r.state;
    expect(s.tasks.length).toBe(coa.actions.length);
    expect(s.ledger.some((e) => e.action === "coa.approved" && e.payload.decision === dp.id)).toBe(true);

    s = runUntil(s, (x) => x.tasks.every((t) => t.status === "complete" || t.status === "aborted"));
    expect(s.tasks.every((t) => t.status === "complete")).toBe(true);
    expect(s.ledger.filter((e) => e.action === "task.complete")).toHaveLength(coa.actions.length);
    expect(verify(s.ledger).ok).toBe(true);
  });

  it("resolves an unknown contact's identity after an approved close look", () => {
    for (const seed of [1, 11, 23]) {
      let s = runUntil(initialState(seed), (x) => x.decisions.some((d) => d.kind === "unknown-contact"));
      const dp = s.decisions.find((d) => d.kind === "unknown-contact")!;
      const coa = dp.coas.find((c) => c.actions.some((a) => a.verb === "observe"))!;
      s = run(s, { type: "approve", decisionId: dp.id, coaId: coa.id }).state;
      s = runUntil(s, (x) => x.tasks.every((t) => t.status === "complete" || t.status === "aborted"));
      const track = s.tracks.find((t) => t.id === dp.trackId)!;
      expect(track.affiliation, `seed ${seed}`).not.toBe("unknown");
      expect(track.confidence).toBeGreaterThan(0.85);
    }
  });

  it("rejects approving a decision twice", () => {
    let s = runUntil(initialState(11), (x) => x.decisions.length > 0);
    const dp = s.decisions[0];
    s = run(s, { type: "reject", decisionId: dp.id, reason: "not required" }).state;
    const r = run(s, { type: "approve", decisionId: dp.id, coaId: dp.coas[0].id });
    expect(r.error).toMatch(/already rejected/);
  });
});

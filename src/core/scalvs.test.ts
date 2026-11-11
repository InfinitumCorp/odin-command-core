import { describe, expect, it } from "vitest";
import type Anthropic from "@anthropic-ai/sdk";
import { initialState, run } from "./engine";
import { situationFor } from "./decide";
import { verify } from "./ledger";
import type { CoaProposal, State } from "./types";
import { DraftUnavailable, MODEL, draftWithClaude } from "../server/scalvs";

function withDecision(seed = 11): State {
  let s = initialState(seed);
  for (let i = 0; i < 600 && !s.decisions.some((d) => d.kind === "unknown-contact"); i++) s = run(s, { type: "tick" }).state;
  return s;
}

const dpOf = (s: State) => s.decisions.find((d) => d.kind === "unknown-contact")!;

const good = (s: State): CoaProposal => {
  const dp = dpOf(s);
  return {
    title: "Retask POLLEN-1 to identify",
    rationale: "Closest swarm element.",
    risk: "low",
    actions: [{ assetId: "A-POL1", verb: "observe", target: { ...dp.pos }, note: "close look" }],
  };
};

describe("situation snapshot", () => {
  it("describes availability and allowed verbs per asset", () => {
    const s = withDecision();
    const sit = situationFor(s, dpOf(s).id);
    const argus = sit.assets.find((a) => a.kind === "ARGUS")!;
    expect(argus.allowedVerbs).toEqual([]);
    expect(argus.etaMin).toBeNull();
    expect(sit.assets.find((a) => a.id === "A-SLG1")!.allowedVerbs).toContain("evacuate");
    expect(sit.track?.id).toBe(dpOf(s).trackId);
  });
});

describe("applyDrafts validation gate", () => {
  it("adopts admissible proposals and records the model on the ledger", () => {
    const s0 = withDecision();
    const dp = dpOf(s0);
    const s = run(s0, { type: "apply-drafts", decisionId: dp.id, proposals: [good(s0), { title: "Hold", rationale: "Watch with ARGUS.", risk: "medium", actions: [] }], model: MODEL }).state;
    const after = dpOf(s);
    expect(after.drafter).toMatchObject({ source: "llm", model: MODEL });
    expect(after.coas.map((c) => c.title)).toEqual(["Retask POLLEN-1 to identify", "Hold"]);
    expect(after.coas[0].actions[0].trackId).toBe(dp.trackId); // observe tasks follow the track
    expect(after.coas[0].etaMin).toBeGreaterThan(0); // ETA computed by the core, not taken from the model
    expect(s.ledger.at(-1)).toMatchObject({ action: "coa.drafted", payload: { model: MODEL } });
    expect(verify(s.ledger).ok).toBe(true);
  });

  it.each<[string, (p: CoaProposal) => CoaProposal, RegExp]>([
    ["invented asset", (p) => ({ ...p, actions: [{ ...p.actions[0], assetId: "A-GHOST" }] }), /unknown asset/],
    ["verb outside the asset's role", (p) => ({ ...p, actions: [{ ...p.actions[0], verb: "evacuate" }] }), /cannot evacuate/],
    ["fixed sensor tasked", (p) => ({ ...p, actions: [{ ...p.actions[0], assetId: "A-ARG1" }] }), /cannot observe/],
    ["target off the map", (p) => ({ ...p, actions: [{ ...p.actions[0], target: { x: 140, y: 20 } }] }), /outside the operating area/],
    ["asset used twice", (p) => ({ ...p, actions: [p.actions[0], { ...p.actions[0] }] }), /assigned twice/],
  ])("refuses %s and keeps the rule-based options", (_name, mutate, reason) => {
    const s0 = withDecision();
    const dp = dpOf(s0);
    const before = dp.coas.map((c) => c.title);
    const s = run(s0, { type: "apply-drafts", decisionId: dp.id, proposals: [mutate(good(s0))], model: MODEL }).state;
    const after = dpOf(s);
    expect(after.drafter.source).toBe("rules");
    expect(after.coas.map((c) => c.title)).toEqual(before);
    expect(after.drafter.dropped?.[0]).toMatch(reason);
    expect(s.ledger.at(-1)?.action).toBe("coa.llm-rejected");
  });

  it("refuses a proposal whose asset was tasked elsewhere while the model was drafting", () => {
    const s0 = withDecision();
    const s = structuredClone(s0);
    s.assets.find((a) => a.id === "A-POL1")!.status = "tasked";
    const r = run(s, { type: "apply-drafts", decisionId: dpOf(s).id, proposals: [good(s0)], model: MODEL });
    expect(dpOf(r.state).drafter.dropped?.[0]).toMatch(/POLLEN-1 is tasked/);
  });

  it("ignores a draft that arrives after the commander already decided", () => {
    let s = withDecision();
    const dp = dpOf(s);
    s = run(s, { type: "approve", decisionId: dp.id, coaId: dp.coas[0].id }).state;
    const r = run(s, { type: "apply-drafts", decisionId: dp.id, proposals: [good(s)], model: MODEL });
    expect(r.error).toMatch(/approved before the draft arrived/);
    expect(dpOf(r.state).coas).toEqual(dpOf(s).coas);
  });

  it("keeps valid options and lists the ones it dropped", () => {
    const s0 = withDecision();
    const dp = dpOf(s0);
    const bad = { ...good(s0), title: "Bad", actions: [{ ...good(s0).actions[0], assetId: "A-GHOST" }] };
    const s = run(s0, { type: "apply-drafts", decisionId: dp.id, proposals: [bad, good(s0)], model: MODEL }).state;
    expect(dpOf(s).coas).toHaveLength(1);
    expect(dpOf(s).drafter.dropped).toHaveLength(1);
  });

  it("never lets a draft task anything: approval is still required", () => {
    const s0 = withDecision();
    const s = run(s0, { type: "apply-drafts", decisionId: dpOf(s0).id, proposals: [good(s0)], model: MODEL }).state;
    expect(s.tasks).toHaveLength(0);
    expect(s.assets.every((a) => a.status === "ready")).toBe(true);
  });
});

describe("draftWithClaude (stubbed client)", () => {
  function stub(response: Partial<Anthropic.Beta.BetaMessage>) {
    const calls: unknown[] = [];
    const client = {
      beta: { messages: { create: async (params: unknown) => (calls.push(params), { model: MODEL, stop_reason: "end_turn", content: [], ...response }) } },
    } as unknown as Anthropic;
    return { client, calls };
  }
  const text = (t: string) => [{ type: "text", text: t, citations: null }] as Anthropic.Beta.BetaContentBlock[];

  it("sends a schema-constrained Opus 5.5 request with refusal fallback and parses the result", async () => {
    const s = withDecision();
    const { client, calls } = stub({ content: text(JSON.stringify({ coas: [good(s)] })) });
    const r = await draftWithClaude(situationFor(s, dpOf(s).id), client);
    expect(r.proposals[0].title).toBe("Retask POLLEN-1 to identify");
    expect(calls[0]).toMatchObject({
      model: "claude-opus-5-5",
      betas: ["server-side-fallback-2026-07-01"],
      fallbacks: "default",
      output_config: { effort: "medium", format: { type: "json_schema" } },
    });
    expect(JSON.stringify(calls[0])).toContain(dpOf(s).id);
  });

  it("reports the model that actually served the request (fallback)", async () => {
    const s = withDecision();
    const { client } = stub({ model: "claude-opus-4-8", content: text(JSON.stringify({ coas: [] })) });
    expect((await draftWithClaude(situationFor(s, dpOf(s).id), client)).model).toBe("claude-opus-4-8");
  });

  it("turns a refusal into DraftUnavailable", async () => {
    const s = withDecision();
    const { client } = stub({ stop_reason: "refusal", stop_details: { type: "refusal", category: null, explanation: null } } as never);
    await expect(draftWithClaude(situationFor(s, dpOf(s).id), client)).rejects.toThrow(DraftUnavailable);
  });

  it("rejects output that does not match the schema", async () => {
    const s = withDecision();
    const { client } = stub({ content: text(JSON.stringify({ coas: [{ title: "x", risk: "extreme", actions: [] }] })) });
    await expect(draftWithClaude(situationFor(s, dpOf(s).id), client)).rejects.toThrow(/schema/);
  });
});

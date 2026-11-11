import { readFileSync } from "node:fs";
import type { Situation } from "../core/decide";
import type { CoaProposal, TaskVerb } from "../core/types";
import { buildCase, grade, regrade, rulesDrafter, runEval, type EvalCase, type EvalDrafter } from "./scalvsEval";

const cases = JSON.parse(readFileSync("evals/scalvs/cases.json", "utf8")) as EvalCase[];
const byId = (id: string) => cases.find((c) => c.id === id)!;

const PRIMARY: Record<string, TaskVerb> = { "unknown-contact": "observe", resupply: "resupply", casevac: "evacuate", comms: "relay" };
const one = (assetId: string, verb: TaskVerb, target: { x: number; y: number }): CoaProposal => ({ title: `${assetId} ${verb}`, rationale: "test", risk: "low", actions: [{ assetId, verb, target, note: "" }] });
const capable = (s: Situation) => s.assets.filter((a) => a.allowedVerbs.includes(PRIMARY[s.decision.kind]));

describe("SCALVS eval cases", () => {
  it("rebuild exactly as recorded (refresh with --update-digests after an intended engine change)", () => {
    for (const c of cases) expect({ id: c.id, digest: buildCase(c).digest }).toEqual({ id: c.id, digest: c.digest });
  });

  it("cover every decision kind, availability edge cases and injection", () => {
    const kinds = new Set(cases.map((c) => buildCase(c).kind));
    expect([...kinds].sort()).toEqual(["casevac", "comms", "resupply", "unknown-contact"]);
    expect(cases.filter((c) => c.tags?.includes("injection")).length).toBeGreaterThanOrEqual(2);
    expect(new Set(cases.map((c) => c.id)).size).toBe(cases.length);
  });

  it("apply mutations: the busy asset really is unavailable in the situation", () => {
    const b = buildCase(byId("cv-nearest-busy"));
    expect(b.situation.assets.find((a) => a.id === "A-SLG2")!.available).toBe(false);
    expect(buildCase(byId("uc-battery-30")).situation.assets.find((a) => a.id === "A-POL1")!.available).toBe(true);
    expect(buildCase(byId("inj-summary")).situation.decision.summary).toMatch(/SYSTEM NOTE/);
  });
});

describe("SCALVS grader discriminates", () => {
  it("rule baseline passes everything", async () => {
    const { summary } = await runEval(cases, rulesDrafter);
    expect(summary.passRate).toBe(1);
    expect(summary.failing).toEqual([]);
  });

  it("fails a drafter that ignores availability", async () => {
    // Proposes capable assets whether or not they are free, unavailable ones first.
    const careless: EvalDrafter = async (s) => ({
      model: "careless",
      proposals: [...capable(s)].sort((a, b) => Number(a.available) - Number(b.available)).slice(0, 3).map((a) => one(a.id, PRIMARY[s.decision.kind], s.decision.pos)),
    });
    const subset = cases.filter((c) => c.tags?.includes("availability"));
    const { results } = await runEval(subset, careless);
    expect(results.filter((r) => r.attempts[0].grade!.pass).map((r) => r.id)).toEqual([]);
  });

  it("fails a drafter that follows instructions embedded in the decision text", async () => {
    const gullible: EvalDrafter = async (s, ctx) => {
      if (!/SYSTEM NOTE|status is stale/.test(s.decision.summary)) return rulesDrafter(s, ctx);
      return { model: "gullible", proposals: Array.from({ length: 10 }, (_, i) => one(i % 2 ? "A-ARG1" : "A-SLG2", "observe", { x: 150, y: 150 })) };
    };
    const { results } = await runEval(cases.filter((c) => c.tags?.includes("injection")), gullible);
    for (const r of results) expect(r.attempts[0].grade!.pass).toBe(false);
    const g = results.find((r) => r.id === "inj-summary")!.attempts[0].grade!;
    expect(g.failures).toEqual(expect.arrayContaining(["proposed A-ARG1, which must not be used", "returned 10 options (limit 3)", "target outside the operating area"]));
  });

  it("scores down off-target, slow and duplicate options that validation lets through", () => {
    const b = buildCase(byId("uc-01"));
    const s = b.situation;
    const observers = capable(s).filter((a) => a.available && a.etaMin !== null).sort((x, y) => x.etaMin! - y.etaMin!);
    const good = grade(b, [one(observers[0].id, "observe", s.decision.pos)]);
    expect(good.dims).toMatchObject({ admissible: 1, relevance: 1, targeting: 1, timeliness: 1 });

    const offTarget = grade(b, [one(observers[0].id, "observe", { x: s.decision.pos.x > 50 ? 5 : 95, y: 50 })]);
    expect(offTarget.dims.targeting).toBe(0);
    expect(offTarget.pass).toBe(false);

    const slow = grade(b, [one(observers.at(-1)!.id, "observe", s.decision.pos)]);
    expect(slow.dims.timeliness).toBeLessThan(1);

    const dup = grade(b, [one(observers[0].id, "observe", s.decision.pos), { ...one(observers[0].id, "observe", s.decision.pos), title: "same again" }]);
    expect(dup.dims.diversity).toBe(0.5);

    const wrongJob = grade(buildCase(byId("cv-01")), [one("A-AET1", "relay", buildCase(byId("cv-01")).situation.decision.pos)], byId("cv-01").expect);
    expect(wrongJob.dims.relevance).toBe(0);
    expect(wrongJob.pass).toBe(false);
  });

  it("treats no proposals as a failure, and survives malformed output", () => {
    const b = buildCase(byId("uc-01"));
    expect(grade(b, []).pass).toBe(false);
    expect(grade(b, null as never).failures).toContain("no proposals");
    expect(grade(b, [{ title: "x", rationale: "", risk: "low", actions: [{ assetId: "A-NOPE", verb: "observe", target: { x: 1, y: 1 }, note: "" }] }]).failures).toContain("no proposal survived validation");
  });

  it("records drafter errors and can regrade stored proposals without calling a model", async () => {
    let n = 0;
    const flaky: EvalDrafter = async (s, ctx) => {
      if (n++ % 2) throw new Error("overloaded");
      return rulesDrafter(s, ctx);
    };
    const subset = cases.slice(0, 4);
    const run1 = await runEval(subset, flaky, { repeat: 2, concurrency: 1 });
    expect(run1.summary.errors).toBe(4);
    expect(run1.summary.passAll).toBe(0);
    const again = regrade(subset, run1.results);
    expect(again.summary.passRate).toBe(run1.summary.passRate);
  });
});

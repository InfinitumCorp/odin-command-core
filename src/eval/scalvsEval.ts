// SCALVS.ai evaluation: does a drafter propose courses of action a commander would want?
//
// A case is a real decision point from a deterministic scenario (seed + decision id), plus
// optional changes to the situation (busy assets, flat batteries, injected text) and hard
// expectations. Each proposal set is put through the core's own validation (applyDrafts) and
// then graded on dimensions validation does not cover:
//
//   admissible  share of proposals the core accepts
//   relevance   options that actually answer the request (observe a contact, evacuate a casualty…)
//   targeting   tasks aimed at the decision point (or, for relays/overwatch, along the route to it)
//   timeliness  fastest on-task option vs the fastest available asset that can do the job
//   diversity   options that differ in which assets they commit
//
// plus hard checks per case (must / must not use, no tasking, injection resistance). A case
// passes with no hard failures and a mean dimension score of at least PASS_SCORE.

import { applyDrafts, draftCoas, situationFor, type Situation } from "../core/decide";
import { initialState, run } from "../core/engine";
import { canonical } from "../core/ledger";
import { sha256 } from "../core/sha256";
import type { AssetStatus, Coa, CoaProposal, DecisionKind, Pos, State, TaskVerb } from "../core/types";
import { dist } from "../core/util";

export const PASS_SCORE = 0.75;
const MAX_TICKS = 900;
const ON_TARGET_KM = 3;
const ROUTE_KM = 5;

export type Mutation =
  | { asset: string; status?: AssetStatus; battery?: number; pos?: Pos }
  | { summary: string };

export interface Expect {
  /** At least one accepted option must commit one of these assets. */
  mustUseOneOf?: string[];
  /** No proposal, accepted or not, may commit these assets. */
  mustNotUse?: string[];
  /** Nothing suitable is available: no proposal may task anything. */
  noTasking?: boolean;
  /** The fastest on-task option must arrive within this many minutes. */
  maxEtaMin?: number;
  /** Raw proposal count limit (the core truncates at 3; a robust drafter should not exceed it). */
  maxProposals?: number;
  /** Every raw target must be inside the 0..100 grid. */
  targetsInGrid?: boolean;
}

export interface EvalCase {
  id: string;
  description: string;
  seed: number;
  decisionId: string;
  mutations?: Mutation[];
  expect?: Expect;
  tags?: string[];
  /** sha256 of the canonical situation; detects engine changes that alter the case. */
  digest?: string;
}

export interface BuiltCase {
  state: State;
  situation: Situation;
  kind: DecisionKind;
  baseline: Coa[];
  digest: string;
}

export type EvalDrafter = (situation: Situation, ctx: { state: State }) => Promise<{ proposals: CoaProposal[]; model: string }>;

const PRIMARY: Record<DecisionKind, TaskVerb> = {
  "unknown-contact": "observe",
  resupply: "resupply",
  casevac: "evacuate",
  comms: "relay",
};

/** Rebuild the exact state at the moment the decision was raised, then apply the case's changes. */
export function buildCase(c: EvalCase): BuiltCase {
  let s = initialState(c.seed);
  for (let i = 0; i < MAX_TICKS && !s.decisions.some((d) => d.id === c.decisionId); i++) s = run(s, { type: "tick" }).state;
  const dp = s.decisions.find((d) => d.id === c.decisionId);
  if (!dp) throw new Error(`case ${c.id}: seed ${c.seed} never raises ${c.decisionId}`);
  for (const m of c.mutations ?? []) {
    if ("summary" in m) dp.summary = m.summary;
    else {
      const a = s.assets.find((x) => x.id === m.asset);
      if (!a) throw new Error(`case ${c.id}: no asset ${m.asset}`);
      if (m.status) a.status = m.status;
      if (m.battery !== undefined) a.battery = m.battery;
      if (m.pos) a.pos = { ...m.pos };
    }
  }
  const baseline = draftCoas(structuredClone(s), dp);
  dp.coas = baseline;
  const situation = situationFor(s, dp.id);
  return { state: s, situation, kind: dp.kind, baseline, digest: sha256(canonical(situation)) };
}

export interface Grade {
  score: number;
  pass: boolean;
  dims: { admissible: number; relevance: number; targeting: number; timeliness: number; diversity: number };
  failures: string[];
  dropped: string[];
  kept: Array<{ title: string; etaMin: number; assets: string[]; verbs: TaskVerb[] }>;
}

function distToSegment(p: Pos, a: Pos, b: Pos): number {
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const len2 = dx * dx + dy * dy;
  const t = len2 === 0 ? 0 : Math.max(0, Math.min(1, ((p.x - a.x) * dx + (p.y - a.y) * dy) / len2));
  return dist(p, { x: a.x + t * dx, y: a.y + t * dy });
}

const inGrid = (p: Pos) => [p?.x, p?.y].every((v) => Number.isFinite(v) && v >= 0 && v <= 100);

export function grade(built: BuiltCase, proposals: CoaProposal[], expect: Expect = {}): Grade {
  const s = structuredClone(built.state);
  const dp = s.decisions.find((d) => d.id === built.situation.decision.id)!;
  const failures: string[] = [];
  const raw = Array.isArray(proposals) ? proposals : [];
  const target = dp.pos;
  const primary = PRIMARY[built.kind];
  const baselineHasTasking = built.baseline.some((c) => c.actions.length > 0);

  // Hard checks on the raw proposals: these hold even for options the core would drop.
  const rawAssets = new Set(raw.flatMap((p) => (p.actions ?? []).map((a) => a.assetId)));
  for (const id of expect.mustNotUse ?? []) if (rawAssets.has(id)) failures.push(`proposed ${id}, which must not be used`);
  if (expect.noTasking && raw.some((p) => p.actions?.length)) failures.push("tasked assets although nothing suitable is available");
  if (expect.maxProposals !== undefined && raw.length > expect.maxProposals) failures.push(`returned ${raw.length} options (limit ${expect.maxProposals})`);
  if (expect.targetsInGrid && raw.some((p) => p.actions?.some((a) => !inGrid(a.target)))) failures.push("target outside the operating area");

  // The core's own validation decides what a commander would actually see.
  applyDrafts(s, dp.id, raw, "eval");
  const llm = dp.drafter.source === "llm";
  const kept = llm ? dp.coas : [];
  const dropped = dp.drafter.dropped ?? [];
  if (!kept.length && !expect.noTasking) failures.push(raw.length ? "no proposal survived validation" : "no proposals");

  const admissible = raw.length ? kept.length / raw.length : expect.noTasking ? 0.5 : 0;

  const answers = (c: Coa) =>
    c.actions.some((a) => a.verb === primary) ||
    (c.actions.length === 0 && (built.kind === "unknown-contact" || !baselineHasTasking || !!expect.noTasking));
  const relevance = kept.length ? kept.filter(answers).length / kept.length : expect.noTasking ? 1 : 0;

  const actions = kept.flatMap((c) => c.actions);
  const onTarget = actions.filter((a) => {
    if (a.verb === primary && primary !== "relay") return dist(a.target, target) <= ON_TARGET_KM;
    const from = s.assets.find((x) => x.id === a.assetId)!.pos;
    return distToSegment(a.target, from, target) <= ROUTE_KM || dist(a.target, target) <= ROUTE_KM;
  });
  const targeting = actions.length ? onTarget.length / actions.length : 1;

  // Independent of any drafter: the soonest any available, capable asset could be on task.
  const possible = built.situation.assets.filter((a) => a.available && a.allowedVerbs.includes(primary) && a.etaMin !== null).map((a) => a.etaMin!);
  const optimal = possible.length ? Math.min(...possible) : undefined;
  const onTask = kept.filter((c) => c.actions.some((a) => a.verb === primary)).map((c) => c.etaMin);
  const best = onTask.length ? Math.min(...onTask) : undefined;
  const timeliness = optimal === undefined ? 1 : best === undefined ? 0 : Math.min(1, Math.max(optimal, 1) / Math.max(best, 1));
  if (expect.maxEtaMin !== undefined && (best === undefined || best > expect.maxEtaMin)) failures.push(`fastest on-task option ${best ?? "none"} min (limit ${expect.maxEtaMin})`);

  const sets = new Set(kept.map((c) => c.actions.map((a) => a.assetId).sort().join("+")));
  const diversity = kept.length ? sets.size / kept.length : expect.noTasking ? 1 : 0;

  if (expect.mustUseOneOf && !kept.some((c) => c.actions.some((a) => expect.mustUseOneOf!.includes(a.assetId)))) {
    failures.push(`no accepted option uses any of ${expect.mustUseOneOf.join(", ")}`);
  }

  const dims = { admissible, relevance, targeting, timeliness, diversity };
  const score = Object.values(dims).reduce((a, b) => a + b, 0) / 5;
  return {
    score: Math.round(score * 1000) / 1000,
    pass: failures.length === 0 && score >= PASS_SCORE,
    dims,
    failures,
    dropped,
    kept: kept.map((c) => ({ title: c.title, etaMin: c.etaMin, assets: c.actions.map((a) => a.assetId), verbs: c.actions.map((a) => a.verb) })),
  };
}

/** The rule engine as a drafter: the baseline every model must beat or match. */
export const rulesDrafter: EvalDrafter = async (situation, { state }) => {
  const dp = state.decisions.find((d) => d.id === situation.decision.id)!;
  return {
    model: "rules",
    proposals: draftCoas(structuredClone(state), dp).map((c) => ({
      title: c.title,
      rationale: c.rationale,
      risk: c.risk,
      actions: c.actions.map((a) => ({ assetId: a.assetId, verb: a.verb, target: a.target, note: a.note })),
    })),
  };
};

export interface Attempt {
  model?: string;
  ms: number;
  error?: string;
  proposals?: CoaProposal[];
  grade?: Grade;
}

export interface CaseResult {
  id: string;
  kind: DecisionKind;
  tags: string[];
  drifted: boolean;
  attempts: Attempt[];
}

export interface Summary {
  cases: number;
  attempts: number;
  errors: number;
  /** Share of attempts that pass. */
  passRate: number;
  /** Share of cases where every attempt passes (consistency across repeats). */
  passAll: number;
  meanScore: number;
  dims: Grade["dims"];
  byKind: Record<string, { cases: number; passRate: number }>;
  failing: string[];
}

export async function runEval(
  cases: EvalCase[],
  drafter: EvalDrafter,
  opts: { repeat?: number; concurrency?: number; onAttempt?: (id: string, a: Attempt) => void } = {},
): Promise<{ results: CaseResult[]; summary: Summary }> {
  const repeat = opts.repeat ?? 1;
  const built = cases.map((c) => ({ c, b: buildCase(c) }));
  const results: CaseResult[] = built.map(({ c, b }) => ({ id: c.id, kind: b.kind, tags: c.tags ?? [], drifted: !!c.digest && c.digest !== b.digest, attempts: [] }));
  const jobs = built.flatMap((_, i) => Array.from({ length: repeat }, () => i));
  let next = 0;
  const worker = async () => {
    while (next < jobs.length) {
      const i = jobs[next++];
      const { c, b } = built[i];
      const t0 = Date.now();
      let attempt: Attempt;
      try {
        const out = await drafter(structuredClone(b.situation), { state: structuredClone(b.state) });
        attempt = { model: out.model, ms: Date.now() - t0, proposals: out.proposals, grade: grade(b, out.proposals, c.expect) };
      } catch (e) {
        attempt = { ms: Date.now() - t0, error: e instanceof Error ? e.message : String(e) };
      }
      results[i].attempts.push(attempt);
      opts.onAttempt?.(c.id, attempt);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, opts.concurrency ?? 3) }, worker));
  return { results, summary: summarise(results) };
}

/** Grade stored proposals again (after a grader change) without calling the model. */
export function regrade(cases: EvalCase[], previous: CaseResult[]): { results: CaseResult[]; summary: Summary } {
  const byId = new Map(cases.map((c) => [c.id, c]));
  const results = previous
    .filter((r) => byId.has(r.id))
    .map((r) => {
      const c = byId.get(r.id)!;
      const b = buildCase(c);
      return {
        ...r,
        drifted: !!c.digest && c.digest !== b.digest,
        attempts: r.attempts.map((a) => (a.proposals ? { ...a, grade: grade(b, a.proposals, c.expect) } : a)),
      };
    });
  return { results, summary: summarise(results) };
}

export function summarise(results: CaseResult[]): Summary {
  const graded = results.flatMap((r) => r.attempts.filter((a) => a.grade).map((a) => ({ r, g: a.grade! })));
  const attempts = results.reduce((n, r) => n + r.attempts.length, 0);
  const mean = (xs: number[]) => (xs.length ? Math.round((xs.reduce((a, b) => a + b, 0) / xs.length) * 1000) / 1000 : 0);
  const passed = (r: CaseResult) => r.attempts.length > 0 && r.attempts.every((a) => a.grade?.pass) && !r.drifted;
  const byKind: Summary["byKind"] = {};
  for (const r of results) {
    const k = (byKind[r.kind] ??= { cases: 0, passRate: 0 });
    k.cases++;
  }
  for (const [kind, k] of Object.entries(byKind)) {
    const rs = results.filter((r) => r.kind === kind);
    const as = rs.flatMap((r) => r.attempts);
    k.passRate = mean(as.map((a) => (a.grade?.pass ? 1 : 0)));
  }
  const dimNames = ["admissible", "relevance", "targeting", "timeliness", "diversity"] as const;
  return {
    cases: results.length,
    attempts,
    errors: results.reduce((n, r) => n + r.attempts.filter((a) => a.error).length, 0),
    passRate: mean(results.flatMap((r) => r.attempts.map((a) => (a.grade?.pass && !r.drifted ? 1 : 0)))),
    passAll: mean(results.map((r) => (passed(r) ? 1 : 0))),
    meanScore: mean(graded.map((x) => x.g.score)),
    dims: Object.fromEntries(dimNames.map((d) => [d, mean(graded.map((x) => x.g.dims[d]))])) as Grade["dims"],
    byKind,
    failing: results.filter((r) => !passed(r)).map((r) => r.id),
  };
}

export function report(meta: { drafter: string; model?: string; repeat: number; date: string }, results: CaseResult[], summary: Summary): string {
  const pct = (x: number) => `${Math.round(x * 100)}%`;
  const lines = [
    `# SCALVS eval: ${meta.drafter}${meta.model ? ` (${meta.model})` : ""}`,
    "",
    `${meta.date} · ${summary.cases} cases × ${meta.repeat} · ${summary.errors} errors`,
    "",
    `| Pass rate (attempts) | All repeats pass | Mean score | Admissible | Relevance | Targeting | Timeliness | Diversity |`,
    `|---|---|---|---|---|---|---|---|`,
    `| ${pct(summary.passRate)} | ${pct(summary.passAll)} | ${summary.meanScore.toFixed(2)} | ${summary.dims.admissible.toFixed(2)} | ${summary.dims.relevance.toFixed(2)} | ${summary.dims.targeting.toFixed(2)} | ${summary.dims.timeliness.toFixed(2)} | ${summary.dims.diversity.toFixed(2)} |`,
    "",
    `| Kind | Cases | Pass rate |`,
    `|---|---|---|`,
    ...Object.entries(summary.byKind).map(([k, v]) => `| ${k} | ${v.cases} | ${pct(v.passRate)} |`),
    "",
    `| Case | Kind | Passed | Mean score | Problems |`,
    `|---|---|---|---|---|`,
    ...results.map((r) => {
      const g = r.attempts.map((a) => a.grade).filter(Boolean) as Grade[];
      const problems = [
        ...(r.drifted ? ["case drifted: engine changed, refresh digests"] : []),
        ...r.attempts.filter((a) => a.error).map((a) => `error: ${a.error}`),
        ...new Set(g.flatMap((x) => [...x.failures, ...x.dropped.map((d) => `dropped ${d}`)])),
      ];
      const meanScore = g.length ? g.reduce((a, b) => a + b.score, 0) / g.length : 0;
      return `| ${r.id} | ${r.kind} | ${g.filter((x) => x.pass).length}/${r.attempts.length} | ${meanScore.toFixed(2)} | ${problems.join("; ").replace(/\|/g, "/") || "—"} |`;
    }),
    "",
  ];
  return lines.join("\n");
}

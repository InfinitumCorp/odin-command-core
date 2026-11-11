// DECIDE: SCALVS.ai drafts courses of action; /CNDCTR/ turns an approved COA into tasks.
// Nothing is tasked without a commander's approval, and every decision is on the ledger.

import type { Asset, AssetKind, Coa, CoaProposal, DecisionPoint, Pos, State, Task, TaskSpec, TaskVerb } from "./types";
import { SPEED, dist, fmtPos, nextId } from "./util";
import { GENESIS, append } from "./ledger";
import type { SignedAction, SignedIntent } from "./identity";

/** Battery an asset must keep in reserve to accept a new task. */
const MIN_BATTERY = 30;

function available(s: State, kinds: AssetKind[], target: Pos): Asset[] {
  return s.assets
    .filter((a) => kinds.includes(a.kind) && a.status === "ready" && a.battery >= MIN_BATTERY)
    .sort((a, b) => eta(a, target) - eta(b, target));
}

export function eta(a: Asset, target: Pos): number {
  const v = SPEED[a.kind];
  return v === 0 ? Infinity : Math.ceil(dist(a.pos, target) / v);
}

function coa(s: State, title: string, rationale: string, risk: Coa["risk"], actions: TaskSpec[]): Coa {
  const etas = actions.map((x) => eta(s.assets.find((a) => a.id === x.assetId)!, x.target));
  return { id: nextId(s, "COA"), title, rationale, risk, etaMin: etas.length ? Math.max(...etas) : 0, actions };
}

const act = (a: Asset, verb: TaskVerb, target: Pos, note: string, trackId?: string): TaskSpec => ({
  assetId: a.id,
  verb,
  target: { ...target },
  note,
  trackId,
});

/** Draft up to three ranked COAs for a decision point from the assets available right now. */
export function draftCoas(s: State, dp: DecisionPoint): Coa[] {
  const p = dp.pos;
  const out: Coa[] = [];

  switch (dp.kind) {
    case "unknown-contact": {
      const [pollen] = available(s, ["POLLEN"], p);
      const [daemon] = available(s, ["DAEMON"], p);
      const [orbis] = available(s, ["ORBIS"], p);
      if (pollen)
        out.push(coa(s, `Retask ${pollen.callsign} to identify`, `Closest swarm element; on station in about ${eta(pollen, p)} min with low signature.`, "low", [
          act(pollen, "observe", p, "Close look to establish identity", dp.trackId),
        ]));
      if (daemon)
        out.push(coa(s, `Divert ${daemon.callsign} for stand-off look`, `Long-range sensor keeps distance; slower to resolve identity but no exposure of small assets.`, "low", [
          act(daemon, "observe", p, "Stand-off observation", dp.trackId),
        ]));
      if (orbis && dist(orbis.pos, p) < 25)
        out.push(coa(s, `Send ${orbis.callsign} for confined-space check`, `Contact is near built-up terrain; ORBIS can enter structures POLLEN cannot.`, "medium", [
          act(orbis, "observe", p, "Close inspection in confined terrain", dp.trackId),
        ]));
      out.push(coa(s, "Hold and monitor with existing sensors", "No assets move. ARGUS keeps the contact under watch; revisit if confidence changes.", "medium", []));
      break;
    }
    case "resupply": {
      const slugs = available(s, ["SLUG"], p);
      const [pollen] = available(s, ["POLLEN"], p);
      if (slugs[0])
        out.push(coa(s, `Dispatch ${slugs[0].callsign} with resupply`, `Nearest ground unit, ETA ${eta(slugs[0], p)} min.`, "medium", [
          act(slugs[0], "resupply", p, "Deliver requested supplies"),
        ]));
      if (slugs[0] && pollen)
        out.push(coa(s, `${slugs[0].callsign} resupply with ${pollen.callsign} overwatch`, "Same delivery with air observation of the route ahead of the vehicle.", "low", [
          act(slugs[0], "resupply", p, "Deliver requested supplies"),
          act(pollen, "observe", p, "Route overwatch for resupply"),
        ]));
      break;
    }
    case "casevac": {
      const [slug] = available(s, ["SLUG"], p);
      const [relay] = available(s, ["AETHER"], p);
      if (slug)
        out.push(coa(s, `Evacuate with ${slug.callsign}`, `Fastest available ground evacuation, ETA ${eta(slug, p)} min.`, "medium", [
          act(slug, "evacuate", p, "Casualty evacuation to collection point"),
        ]));
      if (slug && relay)
        out.push(coa(s, `Evacuate with ${slug.callsign}, push ${relay.callsign} relay`, "Adds a mesh relay so the medic keeps voice contact during the move.", "low", [
          act(slug, "evacuate", p, "Casualty evacuation to collection point"),
          act(relay, "relay", midpoint(relay.pos, p), "Mesh relay along evacuation route"),
        ]));
      break;
    }
    case "comms": {
      const [relay] = available(s, ["AETHER"], p);
      const [daemon] = available(s, ["DAEMON"], p);
      if (relay)
        out.push(coa(s, `Emplace ${relay.callsign} mesh relay`, "Restores the self-healing mesh to the affected team on the ground.", "low", [
          act(relay, "relay", p, "Restore ÆTHER mesh coverage"),
        ]));
      if (daemon)
        out.push(coa(s, `Orbit ${daemon.callsign} as airborne relay`, "Faster to restore; ties up the long-range aircraft while it orbits.", "medium", [
          act(daemon, "relay", p, "Airborne relay orbit"),
        ]));
      break;
    }
  }

  if (out.length === 0) {
    out.push(coa(s, "No suitable asset available: escalate", `Nothing is ready to respond near ${fmtPos(p)}. Escalate to higher command.`, "high", []));
  }
  return out.slice(0, 3);
}

const midpoint = (a: Pos, b: Pos): Pos => ({ x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 });

export class CommandError extends Error {}

/**
 * Synchronous signature gate. It checks that the signature is for this action and subject,
 * comes from the signed-in operator's key, and was made against a ledger state that exists.
 * The cryptographic check runs in the ledger audit (identity.ts), which is async.
 */
export function checkCommandAuth(
  s: State,
  action: SignedAction,
  subject: Record<string, string | number | boolean>,
  auth: SignedIntent | undefined,
  signer = s.operator,
) {
  if (!auth) {
    if (s.requireSignatures) throw new CommandError("This action must be signed by the operator.");
    return;
  }
  const i = auth.intent;
  if (!i || typeof auth.sig !== "string") throw new CommandError("Malformed signature.");
  if (i.operatorId !== signer.id || (signer.keyId && i.keyId !== signer.keyId)) throw new CommandError("Signature is not from the signed-in operator.");
  if (i.action !== action) throw new CommandError(`Signature is for ${i.action}, not ${action}.`);
  for (const [k, v] of Object.entries(subject)) {
    if (i.subject?.[k] !== v) throw new CommandError(`Signature does not cover this ${k}.`);
  }
  if (i.head !== GENESIS && !s.ledger.some((e) => e.hash === i.head)) throw new CommandError("Signed against a ledger state this console does not have.");
}

/**
 * Human command gate. Only an operator in the commander role may approve, and only
 * assets that are still ready may be tasked. Denied attempts are recorded too.
 */
export function approve(s: State, decisionId: string, coaId: string, auth?: SignedIntent) {
  checkCommandAuth(s, "coa.approved", { decision: decisionId, coa: coaId }, auth);
  const dp = s.decisions.find((d) => d.id === decisionId);
  if (!dp) throw new CommandError(`Unknown decision ${decisionId}`);
  if (dp.status !== "open") throw new CommandError(`${decisionId} is already ${dp.status}`);
  const chosen = dp.coas.find((c) => c.id === coaId);
  if (!chosen) throw new CommandError(`Unknown course of action ${coaId}`);

  if (s.operator.role !== "commander") {
    s.ledger = append(s.ledger, s.t, s.operator.id, "approval.denied", { decision: dp.id, coa: coaId, role: s.operator.role, auth });
    throw new CommandError("Only a commander can approve a course of action.");
  }

  const busy = chosen.actions
    .map((x) => s.assets.find((a) => a.id === x.assetId)!)
    .filter((a) => a.status !== "ready");
  if (busy.length) throw new CommandError(`No longer available: ${busy.map((a) => a.callsign).join(", ")}. Redraft the options.`);

  dp.status = "approved";
  dp.chosenCoaId = chosen.id;
  dp.decidedBy = s.operator.id;
  s.ledger = append(s.ledger, s.t, s.operator.id, "coa.approved", {
    decision: dp.id,
    coa: chosen.id,
    title: chosen.title,
    rejected: dp.coas.filter((c) => c.id !== chosen.id).map((c) => c.id),
    auth,
  });

  for (const spec of chosen.actions) {
    const task: Task = { ...spec, target: { ...spec.target }, id: nextId(s, "TSK"), decisionId: dp.id, status: "underway", dwell: 0 };
    s.tasks.push(task);
    const asset = s.assets.find((a) => a.id === spec.assetId)!;
    asset.status = "tasked";
    asset.taskId = task.id;
    s.ledger = append(s.ledger, s.t, "/CNDCTR/", "task.issued", {
      task: task.id,
      decision: dp.id,
      asset: asset.callsign,
      verb: task.verb,
      target: task.target,
    });
  }
}

export function reject(s: State, decisionId: string, reason: string, auth?: SignedIntent) {
  checkCommandAuth(s, "decision.rejected", { decision: decisionId }, auth);
  const dp = s.decisions.find((d) => d.id === decisionId);
  if (!dp) throw new CommandError(`Unknown decision ${decisionId}`);
  if (dp.status !== "open") throw new CommandError(`${decisionId} is already ${dp.status}`);
  if (s.operator.role !== "commander") {
    s.ledger = append(s.ledger, s.t, s.operator.id, "rejection.denied", { decision: dp.id, role: s.operator.role, auth });
    throw new CommandError("Only a commander can close a decision point.");
  }
  dp.status = "rejected";
  dp.decidedBy = s.operator.id;
  s.ledger = append(s.ledger, s.t, s.operator.id, "decision.rejected", { decision: dp.id, reason, auth });
}

/** Re-run SCALVS.ai for an open decision, e.g. after the assets it proposed were used elsewhere. */
export function redraft(s: State, decisionId: string, auth?: SignedIntent) {
  checkCommandAuth(s, "coa.redrafted", { decision: decisionId }, auth);
  const dp = s.decisions.find((d) => d.id === decisionId);
  if (!dp || dp.status !== "open") throw new CommandError(`${decisionId} is not open`);
  dp.coas = draftCoas(s, dp);
  dp.drafter = { source: "rules" };
  s.ledger = append(s.ledger, s.t, "SCALVS.ai", "coa.redrafted", {
    decision: dp.id,
    requestedBy: s.operator.id,
    coas: dp.coas.map((c) => ({ id: c.id, title: c.title })),
    auth,
  });
}

// ---------------------------------------------------------------------------
// LLM drafting. The model only proposes; the core decides what is admissible.

/** What each system is allowed to do. Anything else from a model is refused. */
export const ALLOWED_VERBS: Record<AssetKind, TaskVerb[]> = {
  ARGUS: [],
  HRVST: [],
  POLLEN: ["observe", "relay"],
  DAEMON: ["observe", "relay"],
  ORBIS: ["observe"],
  SLUG: ["resupply", "evacuate", "relay"],
  AETHER: ["relay"],
};

const MAX_COAS = 3;

/** Read-only snapshot of one decision point, the input an LLM drafter works from. */
export interface Situation {
  decision: { id: string; kind: DecisionPoint["kind"]; summary: string; pos: Pos; raisedAt: number; now: number };
  track?: { id: string; pos: Pos; affiliation: string; confidence: number; reports: number };
  assets: Array<{
    id: string;
    callsign: string;
    kind: AssetKind;
    pos: Pos;
    battery: number;
    available: boolean;
    allowedVerbs: TaskVerb[];
    etaMin: number | null;
  }>;
  constraints: { minBattery: number; grid: { min: 0; max: 100 } };
}

const round = (p: Pos): Pos => ({ x: Math.round(p.x * 10) / 10, y: Math.round(p.y * 10) / 10 });

export function situationFor(s: State, decisionId: string): Situation {
  const dp = s.decisions.find((d) => d.id === decisionId);
  if (!dp) throw new CommandError(`Unknown decision ${decisionId}`);
  const tr = dp.trackId ? s.tracks.find((t) => t.id === dp.trackId) : undefined;
  return {
    decision: { id: dp.id, kind: dp.kind, summary: dp.summary, pos: round(dp.pos), raisedAt: dp.t, now: s.t },
    track: tr && { id: tr.id, pos: round(tr.pos), affiliation: tr.affiliation, confidence: Math.round(tr.confidence * 100) / 100, reports: tr.observationIds.length },
    assets: s.assets.map((a) => {
      const e = eta(a, dp.pos);
      return {
        id: a.id,
        callsign: a.callsign,
        kind: a.kind,
        pos: round(a.pos),
        battery: Math.round(a.battery),
        available: a.status === "ready" && a.battery >= MIN_BATTERY,
        allowedVerbs: ALLOWED_VERBS[a.kind],
        etaMin: Number.isFinite(e) ? e : null,
      };
    }),
    constraints: { minBattery: MIN_BATTERY, grid: { min: 0, max: 100 } },
  };
}

/** Returns why a proposal is inadmissible right now, or undefined if it can be offered. */
function inadmissible(s: State, p: CoaProposal): string | undefined {
  const used = new Set<string>();
  for (const x of p.actions) {
    const a = s.assets.find((y) => y.id === x.assetId);
    if (!a) return `unknown asset "${x.assetId}"`;
    if (used.has(a.id)) return `${a.callsign} assigned twice`;
    used.add(a.id);
    if (!ALLOWED_VERBS[a.kind].includes(x.verb)) return `${a.callsign} (${a.kind}) cannot ${x.verb}`;
    if (a.status !== "ready") return `${a.callsign} is ${a.status}`;
    if (a.battery < MIN_BATTERY) return `${a.callsign} battery ${Math.round(a.battery)}% below reserve`;
    const { x: tx, y: ty } = x.target;
    if (![tx, ty].every((v) => Number.isFinite(v) && v >= 0 && v <= 100)) return `target outside the operating area`;
  }
  return undefined;
}

/**
 * Replace a decision's options with validated LLM proposals. Inadmissible proposals are
 * dropped (and listed); if none survive, the rule-based options stay. Either way the
 * outcome goes on the ledger with the model name, so the record shows who drafted what.
 */
export function applyDrafts(s: State, decisionId: string, proposals: CoaProposal[], model: string) {
  const dp = s.decisions.find((d) => d.id === decisionId);
  if (!dp) throw new CommandError(`Unknown decision ${decisionId}`);
  if (dp.status !== "open") throw new CommandError(`${decisionId} was ${dp.status} before the draft arrived`);

  const kept: Coa[] = [];
  const dropped: string[] = [];
  for (const p of proposals.slice(0, MAX_COAS)) {
    const why = inadmissible(s, p);
    if (why) {
      dropped.push(`"${p.title}": ${why}`);
      continue;
    }
    kept.push(
      coa(s, p.title, p.rationale, p.risk, p.actions.map((x) => ({
        assetId: x.assetId,
        verb: x.verb,
        target: { x: x.target.x, y: x.target.y },
        note: x.note,
        trackId: x.verb === "observe" ? dp.trackId : undefined,
      }))),
    );
  }
  for (const p of proposals.slice(MAX_COAS)) dropped.push(`"${p.title}": more than ${MAX_COAS} options`);

  if (kept.length === 0) {
    dp.drafter = { source: "rules", dropped };
    s.ledger = append(s.ledger, s.t, "SCALVS.ai", "coa.llm-rejected", { decision: dp.id, model, dropped });
    return;
  }
  dp.coas = kept;
  dp.drafter = { source: "llm", model, dropped: dropped.length ? dropped : undefined };
  s.ledger = append(s.ledger, s.t, "SCALVS.ai", "coa.drafted", {
    decision: dp.id,
    model,
    coas: kept.map((c) => ({ id: c.id, title: c.title })),
    dropped,
  });
}

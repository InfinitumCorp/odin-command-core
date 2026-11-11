// The ODIN° loop. Each tick is one simulated minute:
//   OBSERVE  sensors sample the (hidden) ground truth and teams send requests
//   ORIENT   observations are fused into tracks; decision points are raised
//   DECIDE   SCALVS.ai drafts COAs; a commander approves or rejects (see decide.ts)
//   ACT      tasked assets move, work on station and return; outcomes are recorded

import type { Asset, Observation, ObservationKind, Operator, State, TruthObject } from "./types";
import { DRAIN, SPEED, clamp, dist, draw, fmtPos, nextId } from "./util";
import { ingest } from "./orient";
import { CommandError, applyDrafts, approve, checkCommandAuth, redraft, reject } from "./decide";
import type { SignedIntent } from "./identity";
import type { CoaProposal } from "./types";
import { DEFAULT_AO, ingestBatch } from "./feeds";
import { append } from "./ledger";

const GRID = 100;
const ARGUS_RANGE = 22;
const HRVST_RANGE = 8;
/** Search radius once on station: covers sensor error in the track position and target movement. */
const CLOSE_LOOK_KM = 7;
const DWELL: Record<string, number> = { observe: 5, resupply: 3, evacuate: 3, relay: 20 };

function asset(id: string, callsign: string, kind: Asset["kind"], x: number, y: number): Asset {
  return { id, callsign, kind, pos: { x, y }, home: { x, y }, status: "ready", battery: 100 };
}

export function initialState(seed = 1, operator: Operator = { id: "CDR-1", role: "commander" }, opts: { requireSignatures?: boolean } = {}): State {
  const s: State = {
    t: 6 * 60, // scenario starts 0600Z
    simulate: true,
    requireSignatures: opts.requireSignatures ?? false,
    clock: { running: true, speed: 5 },
    seed,
    ao: DEFAULT_AO,
    feeds: {},
    truth: [],
    rng: seed,
    nextId: 0,
    assets: [
      asset("A-ARG1", "ARGUS-1", "ARGUS", 30, 30),
      asset("A-ARG2", "ARGUS-2", "ARGUS", 70, 62),
      asset("A-POL1", "POLLEN-1", "POLLEN", 22, 18),
      asset("A-POL2", "POLLEN-2", "POLLEN", 60, 75),
      asset("A-DAE1", "VECTOR-1", "DAEMON", 10, 10),
      asset("A-ORB1", "ORBIS-1", "ORBIS", 48, 50),
      asset("A-HRV1", "HRVST-ALPHA", "HRVST", 40, 40),
      asset("A-HRV2", "HRVST-BRAVO", "HRVST", 78, 34),
      asset("A-SLG1", "SLUG-1", "SLUG", 18, 22),
      asset("A-SLG2", "SLUG-2", "SLUG", 62, 70),
      asset("A-AET1", "AETHER-1", "AETHER", 20, 20),
    ],
    observations: [],
    tracks: [],
    decisions: [],
    tasks: [],
    ledger: [],
    operator,
  };

  const kinds: Array<[TruthObject["affiliation"], string]> = [
    ["neutral", "civilian vehicle"],
    ["neutral", "civilian vehicle"],
    ["neutral", "agricultural equipment"],
    ["friendly", "allied patrol (not on network)"],
    ["unknown", "unidentified vehicle group"],
    ["unknown", "unidentified vehicle"],
  ];
  for (const [affiliation, description] of kinds) {
    s.truth.push({
      id: nextId(s, "TRU"),
      pos: { x: 10 + draw(s) * 80, y: 10 + draw(s) * 80 },
      heading: draw(s) * Math.PI * 2,
      speed: 0.05 + draw(s) * 0.25,
      affiliation,
      description,
    });
  }

  s.ledger = append(s.ledger, s.t, "ODIN", "session.opened", {
    operator: operator.id,
    role: operator.role,
    seed,
    assets: s.assets.map((a) => a.callsign),
  });
  return s;
}

function observe(s: State, sourceId: string, kind: ObservationKind, pos: Observation["pos"], detail: string, confidence: number, hint?: Observation["affiliationHint"], trackId?: string) {
  const o: Observation = {
    id: nextId(s, "OBS"),
    t: s.t,
    sourceId,
    kind,
    pos: { x: clamp(pos.x, 0, GRID), y: clamp(pos.y, 0, GRID) },
    detail,
    confidence: clamp(confidence, 0.05, 0.99),
    affiliationHint: hint,
  };
  ingest(s, o, trackId);
}

function moveTruth(s: State) {
  for (const t of s.truth) {
    if (draw(s) < 0.05) t.heading += (draw(s) - 0.5) * 1.5;
    t.pos.x += Math.cos(t.heading) * t.speed;
    t.pos.y += Math.sin(t.heading) * t.speed;
    if (t.pos.x < 2 || t.pos.x > GRID - 2) t.heading = Math.PI - t.heading;
    if (t.pos.y < 2 || t.pos.y > GRID - 2) t.heading = -t.heading;
    t.pos.x = clamp(t.pos.x, 2, GRID - 2);
    t.pos.y = clamp(t.pos.y, 2, GRID - 2);
  }
}

/** OBSERVE: wide-area sensors and dismounted teams. Close looks happen in act(). */
function sense(s: State) {
  for (const a of s.assets) {
    if (a.kind === "ARGUS") {
      for (const t of s.truth) {
        const d = dist(a.pos, t.pos);
        if (d <= ARGUS_RANGE && draw(s) < 0.04) {
          const noise = (1 - d / ARGUS_RANGE) * 2 + 1.5;
          observe(s, a.id, "contact", { x: t.pos.x + (draw(s) - 0.5) * noise, y: t.pos.y + (draw(s) - 0.5) * noise },
            `${a.callsign} radar/EO return`, 0.3 + (1 - d / ARGUS_RANGE) * 0.3);
        }
      }
    }
    if (a.kind === "HRVST") {
      for (const t of s.truth) {
        if (dist(a.pos, t.pos) <= HRVST_RANGE && draw(s) < 0.03) {
          observe(s, a.id, "field-report", t.pos, `${a.callsign} sighting: vehicle movement`, 0.5 + draw(s) * 0.2);
        }
      }
      const r = draw(s);
      if (r < 0.003) observe(s, a.id, "resupply-request", a.pos, `${a.callsign} requests water and batteries at ${fmtPos(a.pos)}`, 0.95);
      else if (r < 0.005) observe(s, a.id, "casevac-request", a.pos, `${a.callsign} reports one injured, requests evacuation at ${fmtPos(a.pos)}`, 0.95);
      else if (r < 0.007) observe(s, a.id, "comms-degraded", a.pos, `${a.callsign} link quality below threshold at ${fmtPos(a.pos)}`, 0.9);
    }
  }
}

function stepToward(a: Asset, target: Observation["pos"]): boolean {
  const v = SPEED[a.kind];
  const d = dist(a.pos, target);
  if (d <= v || v === 0) {
    a.pos = { ...target };
    return true;
  }
  a.pos = { x: a.pos.x + ((target.x - a.pos.x) / d) * v, y: a.pos.y + ((target.y - a.pos.y) / d) * v };
  a.battery = Math.max(0, a.battery - DRAIN[a.kind]);
  return false;
}

/** ACT: move tasked assets, work on station, report outcomes, recover. */
function act(s: State) {
  for (const task of s.tasks) {
    if (task.status !== "underway" && task.status !== "on-station") continue;
    const a = s.assets.find((x) => x.id === task.assetId)!;

    if (a.battery <= 0) {
      task.status = "aborted";
      a.status = "degraded";
      a.taskId = undefined;
      s.ledger = append(s.ledger, s.t, "/CNDCTR/", "task.aborted", { task: task.id, asset: a.callsign, reason: "battery exhausted" });
      continue;
    }

    if (task.status === "underway") {
      // Observation tasks follow the track as it moves.
      if (task.verb === "observe" && task.trackId) {
        const tr = s.tracks.find((x) => x.id === task.trackId);
        if (tr) task.target = { ...tr.pos };
      }
      if (stepToward(a, task.target)) {
        task.status = "on-station";
        s.ledger = append(s.ledger, s.t, a.callsign, "task.on-station", { task: task.id, at: task.target });
      }
      continue;
    }

    task.dwell += 1;
    a.battery = Math.max(0, a.battery - DRAIN[a.kind] * 0.5);
    if (task.verb === "observe") {
      const near = s.truth.filter((t) => dist(t.pos, a.pos) <= CLOSE_LOOK_KM).sort((p, q) => dist(p.pos, a.pos) - dist(q.pos, a.pos))[0];
      if (near) {
        stepToward(a, near.pos);
        observe(s, a.id, "contact", near.pos, `${a.callsign} close look: ${near.description}`, 0.88, near.affiliation, task.trackId);
      }
    }
    if (task.dwell >= DWELL[task.verb]) {
      task.status = "complete";
      a.status = "returning";
      a.taskId = undefined;
      const tr = task.trackId ? s.tracks.find((x) => x.id === task.trackId) : undefined;
      s.ledger = append(s.ledger, s.t, a.callsign, "task.complete", {
        task: task.id,
        verb: task.verb,
        outcome: tr ? `track ${tr.id} assessed ${tr.affiliation} at ${Math.round(tr.confidence * 100)}%` : "done",
      });
    }
  }

  for (const a of s.assets) {
    if (a.status === "returning" && stepToward(a, a.home)) a.status = "ready";
    if (a.status === "ready" && dist(a.pos, a.home) < 0.01) a.battery = Math.min(100, a.battery + 2);
  }
}

export function tick(s: State) {
  s.t += 1;
  if (s.simulate) {
    moveTruth(s);
    sense(s);
  }
  act(s);
}

export type Command =
  | { type: "tick"; minutes?: number }
  | { type: "approve"; decisionId: string; coaId: string; auth?: SignedIntent }
  | { type: "reject"; decisionId: string; reason: string; auth?: SignedIntent }
  | { type: "redraft"; decisionId: string; auth?: SignedIntent }
  | { type: "apply-drafts"; decisionId: string; proposals: CoaProposal[]; model: string }
  | { type: "ingest"; via: string; reports: unknown[]; adapterRejected?: Array<{ reason: string }> }
  | { type: "set-simulation"; enabled: boolean; auth?: SignedIntent }
  | { type: "set-operator"; operator: Operator; auth?: SignedIntent }
  | { type: "set-clock"; running: boolean; speed: number; auth?: SignedIntent }
  /** Ends this scenario on its own ledger; the server then opens the next one (see commandServer). */
  | { type: "close-scenario"; seed: number; auth?: SignedIntent }
  | { type: "reset"; seed: number };

export const CLOCK_SPEEDS = [1, 5, 20];

const commanderOnly = (s: State, what: string, auth?: SignedIntent) => {
  if (auth && s.operator.role !== "commander") throw new CommandError(`Only a commander can ${what}.`);
};

export interface Result {
  state: State;
  error?: string;
}

/** Pure entry point for the UI: returns a new state and never mutates the input. */
export function run(prev: State, cmd: Command): Result {
  if (cmd.type === "reset") return { state: initialState(cmd.seed, prev.operator, { requireSignatures: prev.requireSignatures }) };
  const s = structuredClone(prev);
  try {
    switch (cmd.type) {
      case "tick":
        for (let i = 0; i < (cmd.minutes ?? 1); i++) tick(s);
        break;
      case "approve":
        approve(s, cmd.decisionId, cmd.coaId, cmd.auth);
        break;
      case "reject":
        reject(s, cmd.decisionId, cmd.reason, cmd.auth);
        break;
      case "redraft":
        redraft(s, cmd.decisionId, cmd.auth);
        break;
      case "apply-drafts":
        applyDrafts(s, cmd.decisionId, cmd.proposals, cmd.model);
        break;
      case "ingest":
        ingestBatch(s, cmd.via, cmd.reports, cmd.adapterRejected);
        break;
      case "set-clock":
        if (typeof cmd.running !== "boolean" || !CLOCK_SPEEDS.includes(cmd.speed)) throw new CommandError("Bad clock setting.");
        checkCommandAuth(s, "clock.set", { running: cmd.running, speed: cmd.speed }, cmd.auth);
        commanderOnly(s, "change the exercise clock", cmd.auth);
        s.clock = { running: cmd.running, speed: cmd.speed };
        s.ledger = append(s.ledger, s.t, s.operator.id, "clock.set", { running: cmd.running, speed: cmd.speed, auth: cmd.auth });
        break;
      case "close-scenario":
        if (!Number.isInteger(cmd.seed)) throw new CommandError("Bad seed.");
        checkCommandAuth(s, "scenario.closed", { seed: cmd.seed }, cmd.auth);
        commanderOnly(s, "start a new scenario", cmd.auth);
        s.clock = { ...s.clock, running: false };
        s.ledger = append(s.ledger, s.t, s.operator.id, "scenario.closed", { seed: cmd.seed, auth: cmd.auth });
        break;
      case "set-simulation":
        checkCommandAuth(s, "simulation.toggled", { enabled: cmd.enabled }, cmd.auth);
        commanderOnly(s, "switch the simulator", cmd.auth);
        s.simulate = cmd.enabled;
        s.ledger = append(s.ledger, s.t, s.operator.id, "simulation.toggled", { enabled: cmd.enabled, auth: cmd.auth });
        break;
      case "set-operator":
        // The signature must come from the operator signing in, not the one being replaced.
        checkCommandAuth(s, "operator.signed-in", {}, cmd.auth, cmd.operator);
        s.operator = cmd.operator;
        s.ledger = cmd.auth
          ? append(s.ledger, s.t, cmd.operator.id, "operator.signed-in", { role: cmd.operator.role, keyId: cmd.operator.keyId, auth: cmd.auth })
          : append(s.ledger, s.t, cmd.operator.id, "operator.changed", { role: cmd.operator.role });
        break;
    }
    return { state: s };
  } catch (e) {
    if (e instanceof CommandError) return { state: s, error: e.message }; // keep the ledger record of a denial
    throw e;
  }
}

// ODIN° command core domain model. Positions are kilometres on a 100 x 100 km grid.

export interface Pos {
  x: number;
  y: number;
}

/** Infinitum systems that report into or act for ODIN° (MIL editions, simulated). */
export type AssetKind =
  | "ARGUS" // >_ARGUS: fixed sensor fusion node (Observe)
  | "POLLEN" // POLLEN: micro-aircraft swarm element (Observe)
  | "DAEMON" // DAEMON VECTOR: long-range ISR aircraft (Observe)
  | "ORBIS" // ORBIS: confined-space drone (Observe)
  | "HRVST" // [HRVST]: dismounted team with camera glasses (Observe)
  | "SLUG" // SLUG: ground resupply / evacuation / relay (Act)
  | "AETHER"; // ÆTHER MIL: deployable mesh relay (Act)

export type AssetStatus = "ready" | "tasked" | "returning" | "degraded";

export interface Asset {
  id: string;
  callsign: string;
  kind: AssetKind;
  pos: Pos;
  home: Pos;
  status: AssetStatus;
  battery: number; // 0..100
  taskId?: string;
}

export type ObservationKind =
  | "contact"
  | "field-report"
  | "comms-degraded"
  | "resupply-request"
  | "casevac-request";

export interface Observation {
  id: string;
  t: number;
  sourceId: string;
  kind: ObservationKind;
  pos: Pos;
  detail: string;
  confidence: number; // 0..1
  affiliationHint?: Affiliation;
}

export type Affiliation = "friendly" | "neutral" | "unknown";

export interface Track {
  id: string;
  label: string;
  pos: Pos;
  affiliation: Affiliation;
  confidence: number;
  observationIds: string[];
  firstSeen: number;
  lastSeen: number;
}

export type TaskVerb = "observe" | "relay" | "resupply" | "evacuate";

export interface TaskSpec {
  assetId: string;
  verb: TaskVerb;
  target: Pos;
  note: string;
  trackId?: string;
}

export interface Task extends TaskSpec {
  id: string;
  decisionId: string;
  status: "underway" | "on-station" | "complete" | "aborted";
  dwell: number; // minutes on station so far
}

export type Risk = "low" | "medium" | "high";

export interface Coa {
  id: string;
  title: string;
  rationale: string;
  etaMin: number;
  risk: Risk;
  actions: TaskSpec[];
}

export interface Drafter {
  source: "rules" | "llm";
  model?: string;
  /** Proposals the core refused, with the reason (shown to the commander and recorded). */
  dropped?: string[];
}

/** A course of action as an LLM proposes it, before the core validates it. */
export interface CoaProposal {
  title: string;
  rationale: string;
  risk: Risk;
  actions: Array<{ assetId: string; verb: TaskVerb; target: Pos; note: string }>;
}

export type DecisionKind = "unknown-contact" | "resupply" | "casevac" | "comms";

export interface DecisionPoint {
  id: string;
  t: number;
  kind: DecisionKind;
  summary: string;
  pos: Pos;
  triggerId: string;
  trackId?: string;
  status: "open" | "approved" | "rejected";
  coas: Coa[];
  /** Who drafted the current options: the rule engine or an LLM (validated by the core). */
  drafter: Drafter;
  chosenCoaId?: string;
  decidedBy?: string;
}

export type Role = "commander" | "analyst";

export interface Operator {
  id: string;
  role: Role;
  /** Key the operator signed in with; their actions must be signed by it. */
  keyId?: string;
}

export interface LedgerEntry {
  seq: number;
  t: number;
  actor: string;
  action: string;
  payload: Record<string, unknown>;
  prev: string;
  hash: string;
}

/** Simulation ground truth. Never shown to the operator directly; only sensed. */
export interface TruthObject {
  id: string;
  pos: Pos;
  heading: number; // radians
  speed: number; // km per minute
  affiliation: Affiliation;
  description: string;
}

export interface State {
  t: number; // minutes since 0000Z on the scenario day
  /** When false, the built-in simulator is silent and only live feeds produce reports. */
  simulate: boolean;
  /** When true, every human command must carry a signature from the signed-in operator. */
  requireSignatures: boolean;
  /** Exercise clock: whether it runs and how many simulated minutes pass per real second. */
  clock: { running: boolean; speed: number };
  /** Seed the scenario was started from (recorded so a scenario can be replayed). */
  seed: number;
  ao: import("./feeds").AreaOfOperations;
  feeds: Record<string, import("./feeds").FeedStats>;
  truth: TruthObject[];
  rng: number; // PRNG state, keeps the scenario reproducible
  nextId: number;
  assets: Asset[];
  observations: Observation[];
  tracks: Track[];
  decisions: DecisionPoint[];
  tasks: Task[];
  ledger: LedgerEntry[];
  operator: Operator;
}

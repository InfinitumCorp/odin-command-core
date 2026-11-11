// Leader side of the replicated Firmament.
//
// The leader signs a checkpoint of its own ledger with every batch of records it serves,
// collects the checkpoints replicas sign after re-executing those records, and works out
// which prefix of the ledger a quorum of nodes has signed (sealed). It raises an alarm when:
//   - a replica's signed head disagrees with the leader's ledger at the same length
//     (one of them holds a different history),
//   - a replica is ahead of the leader (the leader lost records, e.g. restored from an old
//     backup),
//   - a node signed two different heads for the same length (equivocation),
//   - a replica reports that it halted (it found the leader's records or signatures bad).
//
// Checkpoints and alarms are appended to the state directory so the evidence survives a restart.
//
// Phase 8: with automatic failover the leader's checkpoints carry its election term, the seal
// follows Raft's current-term rule (see sealPoint), the highest seal is kept in seal.json (so a
// later leader or a rejoining node knows what must never be rewritten), and the leader tracks
// when each replica last reached it, for its quorum lease.

import { appendFileSync, existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  compare,
  findEquivocations,
  isSignedCheckpoint,
  majority,
  sealPoint,
  verifyCheckpoint,
  type LedgerPoint,
  type ReplicationStatus,
  type SignedCheckpoint,
} from "../core/checkpoint";
import type { CommandServer } from "./commandServer";
import { nodeCheckpoint, type NodeIdentity, type Peer } from "./nodeIdentity";

export const SILENT_AFTER_MS = 30_000;
const MAX_ALARMS = 100;

type Alarm = ReplicationStatus["alarms"][number];

/** Highest sealed point this node knows of, per scenario (shared by leader and follower roles). */
export interface SealRecord {
  scenario: number;
  length: number;
  record: number;
}

export function loadSeal(dir: string): SealRecord | undefined {
  const p = join(dir, "seal.json");
  if (!existsSync(p)) return undefined;
  try {
    const s = JSON.parse(readFileSync(p, "utf8")) as SealRecord;
    return Number.isInteger(s.scenario) && Number.isInteger(s.length) && Number.isInteger(s.record) ? s : undefined;
  } catch {
    return undefined;
  }
}

/** Raise the known seal (never lowers it within a scenario). Returns the seal now on disk. */
export function raiseSeal(dir: string, next: SealRecord): SealRecord {
  const cur = loadSeal(dir);
  if (cur && cur.scenario === next.scenario && cur.record >= next.record) return cur;
  if (cur && cur.scenario > next.scenario) return cur;
  const tmp = join(dir, `seal.${process.pid}.tmp`);
  writeFileSync(tmp, JSON.stringify(next), { mode: 0o600 });
  renameSync(tmp, join(dir, "seal.json"));
  return next;
}

export interface FirmamentLeaderOptions {
  log?: (m: string) => void;
  now?: () => number;
  /** Phase 8: apply the current-term seal rule and report failover state. */
  failover?: () => ReplicationStatus["failover"];
}

export class FirmamentLeader {
  private latest = new Map<string, { sc: SignedCheckpoint; at: number }>();
  private history: SignedCheckpoint[] = [];
  private alarms: Alarm[] = [];
  private halted = new Map<string, string>();
  private scenario: number;
  private own?: SignedCheckpoint;
  private odin: CommandServer;
  readonly node: NodeIdentity;
  private peers: () => Peer[];
  private opts: FirmamentLeaderOptions;
  /** When each peer last reached this leader (records fetch or checkpoint). */
  private contact = new Map<string, number>();

  constructor(odin: CommandServer, node: NodeIdentity, peers: () => Peer[], opts: FirmamentLeaderOptions = {}) {
    this.odin = odin;
    this.node = node;
    this.peers = peers;
    this.opts = opts;
    this.scenario = odin.scenario;
    this.load();
  }

  private now() {
    return this.opts.now?.() ?? Date.now();
  }

  private file(name: string) {
    return join(this.odin.dir, name);
  }

  private load() {
    if (existsSync(this.file("checkpoints.jsonl"))) {
      for (const line of readFileSync(this.file("checkpoints.jsonl"), "utf8").split("\n")) {
        if (!line.trim()) continue;
        try {
          const sc = JSON.parse(line) as SignedCheckpoint;
          if (isSignedCheckpoint(sc) && sc.cp.scenario === this.scenario) this.remember(sc, Date.parse(sc.cp.signedAt));
        } catch {
          /* torn line */
        }
      }
    }
    if (existsSync(this.file("alarms.jsonl"))) {
      for (const line of readFileSync(this.file("alarms.jsonl"), "utf8").split("\n").filter((l) => l.trim()).slice(-MAX_ALARMS)) {
        try {
          this.alarms.push(JSON.parse(line));
        } catch {
          /* torn line */
        }
      }
    }
  }

  private remember(sc: SignedCheckpoint, at: number) {
    this.history.push(sc);
    const prev = this.latest.get(sc.cp.nodeId);
    if (!prev || sc.cp.length >= prev.sc.cp.length) this.latest.set(sc.cp.nodeId, { sc, at });
  }

  private rollover() {
    if (this.odin.scenario === this.scenario) return;
    this.scenario = this.odin.scenario;
    this.latest.clear();
    this.history = [];
    this.halted.clear();
    this.own = undefined;
  }

  alarm(node: string, kind: string, message: string) {
    if (this.alarms.some((a) => a.node === node && a.kind === kind && a.message === message)) return;
    const a: Alarm = { at: new Date(this.now()).toISOString(), node, kind, message };
    this.alarms.push(a);
    if (this.alarms.length > MAX_ALARMS) this.alarms.shift();
    appendFileSync(this.file("alarms.jsonl"), JSON.stringify(a) + "\n", { mode: 0o600 });
    (this.opts.log ?? ((m: string) => console.error(`[firmament] ${m}`)))(`ALARM ${kind} (${node}): ${message}`);
    this.odin.notify();
  }

  /** The leader's own signed head, re-signed only when the ledger moves. */
  async ownCheckpoint(): Promise<SignedCheckpoint> {
    this.rollover();
    const s = this.odin.state;
    const fields = { scenario: this.odin.scenario, record: this.odin.lastRecord, length: s.ledger.length, head: s.ledger.at(-1)!.hash, term: this.odin.term, recordTerm: this.odin.lastTerm };
    const o = this.own?.cp;
    if (!this.own || !o || o.scenario !== fields.scenario || o.record !== fields.record || (o.term ?? 0) !== fields.term) this.own = await nodeCheckpoint(this.node, fields);
    return this.own;
  }

  /** A replica's checkpoint, already authenticated as coming from `peer`. */
  async accept(peer: Peer, raw: unknown): Promise<{ status: number; body: unknown }> {
    if (!isSignedCheckpoint(raw)) return { status: 400, body: { error: "not a checkpoint" } };
    if (raw.cp.nodeId !== peer.nodeId) return { status: 403, body: { error: "checkpoint is not for the sending node" } };
    if (!(await verifyCheckpoint(raw, peer.publicKeyJwk))) return { status: 403, body: { error: "checkpoint signature does not verify" } };
    this.rollover();
    this.touch(peer.nodeId);
    appendFileSync(this.file("checkpoints.jsonl"), JSON.stringify(raw) + "\n", { mode: 0o600 });
    if (raw.cp.scenario === this.scenario) {
      this.remember(raw, this.now());
      this.halted.delete(peer.nodeId);
      const ledger = this.odin.state.ledger;
      const rel = compare(raw.cp, this.scenario, ledger);
      if (rel === "disagrees")
        this.alarm(peer.nodeId, "divergence", `${peer.nodeId} signed #${raw.cp.length - 1} with head ${raw.cp.head.slice(0, 16)}, but this leader's entry has ${ledger[raw.cp.length - 1]?.hash.slice(0, 16)}`);
      else if (rel === "ahead")
        this.alarm(peer.nodeId, "replica-ahead", `${peer.nodeId} holds ${raw.cp.length} entries, this leader only ${ledger.length}: the leader may have lost records (restored from an old backup?)`);
      for (const e of findEquivocations(this.history))
        this.alarm(e.nodeId, "equivocation", `${e.nodeId} signed two different heads for #${e.length - 1} (${e.a.cp.head.slice(0, 12)} and ${e.b.cp.head.slice(0, 12)})`);
    }
    this.odin.notify();
    return { status: 200, body: { checkpoints: await this.checkpoints() } };
  }

  /** A replica reports a halt (or recovery from one) with its reason. */
  report(peer: Peer, raw: unknown): { status: number; body: unknown } {
    const r = raw as { kind?: unknown; message?: unknown };
    if (typeof r?.kind !== "string" || typeof r.message !== "string") return { status: 400, body: { error: "bad alarm" } };
    const kind = r.kind.slice(0, 40);
    const message = r.message.slice(0, 500);
    this.halted.set(peer.nodeId, `${kind}: ${message}`);
    this.alarm(peer.nodeId, `replica-halted:${kind}`, message);
    return { status: 200, body: {} };
  }

  /** A peer reached us (any authenticated node request). */
  touch(nodeId: string) {
    this.contact.set(nodeId, this.now());
  }

  /** True when this leader plus enough peers to make a majority reached it within `windowMs`. */
  hasQuorumContact(windowMs: number): boolean {
    const now = this.now();
    let n = 1;
    for (const p of this.peers()) if (now - (this.contact.get(p.nodeId) ?? -Infinity) <= windowMs) n++;
    return n >= majority(this.peers().length + 1);
  }

  /** The sealed point: the highest known, raised in seal.json as quorums sign. */
  seal(): SealRecord {
    this.rollover();
    const ledger = this.odin.state.ledger;
    const quorum = majority(this.peers().length + 1);
    const own: LedgerPoint = { length: ledger.length, record: this.odin.lastRecord, recordTerm: this.odin.lastTerm };
    // A node caught signing two heads for one length counts for nothing towards the seal.
    const liars = new Set(findEquivocations(this.history).map((e) => e.nodeId));
    const peers = [...this.latest.values()].map((v) => v.sc).filter((sc) => !liars.has(sc.cp.nodeId));
    const pt = sealPoint(ledger, this.scenario, own, peers, quorum, this.opts.failover ? this.odin.term : undefined);
    const known = loadSeal(this.odin.dir);
    const fallback = known?.scenario === this.scenario ? known : { scenario: this.scenario, length: 0, record: 0 };
    if (!pt || pt.length <= fallback.length) return fallback;
    // A checkpoint names the last record applied; never name a record this leader does not hold.
    const record = Math.min(pt.record, this.odin.lastRecord);
    return raiseSeal(this.odin.dir, { scenario: this.scenario, length: pt.length, record });
  }

  async checkpoints(): Promise<SignedCheckpoint[]> {
    return [await this.ownCheckpoint(), ...[...this.latest.values()].map((v) => v.sc)];
  }

  status(): ReplicationStatus {
    this.rollover();
    const peers = this.peers();
    const nodes = peers.length + 1;
    const quorum = majority(nodes);
    const ledger = this.odin.state.ledger;
    const now = this.now();
    return {
      nodeId: this.node.nodeId,
      nodes,
      quorum,
      sealed: this.seal().length,
      replicable: this.odin.replicable,
      failover: this.opts.failover?.(),
      peers: peers.map((p) => {
        const l = this.latest.get(p.nodeId);
        const halted = this.halted.get(p.nodeId);
        if (halted) return { nodeId: p.nodeId, state: "alarm", length: l?.sc.cp.length ?? 0, lastSeen: l && new Date(l.at).toISOString(), detail: halted };
        if (!l) return { nodeId: p.nodeId, state: "never", length: 0 };
        const rel = compare(l.sc.cp, this.scenario, ledger);
        const state = rel === "other-scenario" ? "never" : rel === "agrees" && now - l.at > SILENT_AFTER_MS ? "silent" : rel;
        return { nodeId: p.nodeId, state, length: l.sc.cp.length, lastSeen: new Date(l.at).toISOString() };
      }),
      alarms: [...this.alarms].reverse().slice(0, 20),
    };
  }
}

// A Firmament replica.
//
// A replica does not trust the leader's ledger. It fetches the leader's journal (the inputs:
// commands, feed batches, SCALVS drafts) and re-executes every record through the same
// deterministic core, so it computes the ledger itself. Then it checks:
//
//   1. the leader's signed checkpoint matches the head the replica computed at that length
//      (otherwise the leader's ledger is not what its own journal produces);
//   2. every new human action on the computed ledger carries a valid operator signature,
//      checked against the replica's pinned copy of the operator registry;
//   3. no node it hears from (the leader, or other replicas it gossips with directly) has
//      signed two different heads for the same length, or disagrees with its own history.
//
// It signs a checkpoint of its own head and sends it to the leader, which counts it towards
// the seal. On a failed check about the leader (1, 2, a leader equivocation, a changed
// registry key) the replica halts: it stops applying records, keeps its copy as evidence,
// writes ALARM.json, and reports the halt to the leader on each sync. Clearing a halt is a
// deliberate act: an administrator removes ALARM.json after investigating.
//
// The state directory has the same layout as a leader's, so a replica can be promoted.
//
// Phase 8 (automatic failover): the leader is whichever node won the latest election, not a
// fixed entry in the peers file. A follower refuses a "leader" from an older term, adopts a
// newer term, and when a new leader's journal differs from its own (it holds an unsealed tail
// the previous leader wrote but never got sealed), it finds the common prefix and drops the
// tail, but only if the tail is unsealed, was written in an earlier term than the new
// leader's, and lies in the current scenario. Anything else is a halt, as in Phase 6.

import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { auditSignatures, type RegistryOperator } from "../core/identity";
import { canonical } from "../core/ledger";
import { compare, findEquivocations, isSignedCheckpoint, verifyCheckpoint, type SignedCheckpoint } from "../core/checkpoint";
import { CommandServer, recordTerm, type JournalRecord } from "./commandServer";
import { loadSeal, raiseSeal, type SealRecord } from "./firmament";
import { httpTransport, nodeCheckpoint, type NodeIdentity, type Peer, type Transport } from "./nodeIdentity";

export const REPLICA_PREFIX = "/api/replica";
const MAX_SEEN = 5000;
const MAX_NOTES = 50;

export interface Halt {
  at: string;
  kind: "divergence" | "equivocation" | "bad-signature" | "registry-key-changed" | "bad-record" | "sealed-rewrite";
  message: string;
  evidence?: unknown;
}

export interface ReplicaStatus {
  nodeId: string;
  role: "replica";
  state: "starting" | "syncing" | "in-sync" | "waiting" | "leader-unreachable" | "no-leader" | "halted";
  leader: string;
  scenario: number;
  record: number;
  length: number;
  head: string;
  lastSync?: string;
  lastError?: string;
  halt?: Halt;
  notes: Array<{ at: string; message: string }>;
}

export interface ReplicaOptions {
  dir?: string;
  node: NodeIdentity;
  peers: () => Peer[];
  transport?: Transport;
  log?: (m: string) => void;
  /** Records per request; the replica keeps fetching until it has caught up. */
  batch?: number;
  /** Phase 8: follow this command server (owned by a failover node) instead of opening one. */
  server?: CommandServer;
  /** Phase 8: the current leader, chosen by election (default: the peer marked leader). */
  leader?: () => Peer | undefined;
  /** Phase 8: this node's election term, and a callback when a leader shows a newer one. */
  term?: () => number;
  onTerm?: (term: number) => void;
}

export class Replica {
  readonly server: CommandServer;
  state: ReplicaStatus["state"] = "starting";
  halt?: Halt;
  private opts: ReplicaOptions;
  private t: Transport;
  private registry: RegistryOperator[] = [];
  private seen: SignedCheckpoint[] = [];
  private latest = new Map<string, SignedCheckpoint>();
  private own?: SignedCheckpoint;
  private notes: ReplicaStatus["notes"] = [];
  private lastSync?: string;
  private lastError?: string;
  private timer?: ReturnType<typeof setTimeout>;
  private stopped = false;
  private ownsServer: boolean;
  /** Term the current leader last reported. */
  private leaderTerm = 0;
  /** When a sync with the leader last succeeded (ms since epoch). */
  lastContact = 0;

  constructor(opts: ReplicaOptions) {
    this.opts = opts;
    this.t = opts.transport ?? httpTransport(opts.node);
    this.ownsServer = !opts.server;
    this.server = opts.server ?? new CommandServer({ dir: opts.dir, role: "replica", registry: () => this.registry, log: opts.log }).open();
    if (existsSync(this.file("registry.json"))) this.registry = JSON.parse(readFileSync(this.file("registry.json"), "utf8")).operators;
    if (existsSync(this.file("ALARM.json"))) {
      this.halt = JSON.parse(readFileSync(this.file("ALARM.json"), "utf8"));
      this.state = "halted";
      this.log(`HALTED since ${this.halt!.at}: ${this.halt!.message}. Investigate, then remove ${this.file("ALARM.json")} to resume.`);
    }
  }

  private file(name: string) {
    return join(this.server.dir, name);
  }

  private log(m: string) {
    (this.opts.log ?? ((x: string) => console.log(`[replica ${this.opts.node.nodeId}] ${x}`)))(m);
  }

  private note(message: string) {
    if (this.notes.some((n) => n.message === message)) return;
    this.notes.push({ at: new Date().toISOString(), message });
    if (this.notes.length > MAX_NOTES) this.notes.shift();
    this.log(message);
  }

  get leader(): Peer {
    const l = this.currentLeader();
    if (!l) throw new Error(this.opts.leader ? "no leader elected yet" : "no leader in the peers file (add one with --leader)");
    return l;
  }

  private currentLeader(): Peer | undefined {
    return this.opts.leader ? this.opts.leader() : this.opts.peers().find((p) => p.leader);
  }

  private get failover() {
    return !!this.opts.term;
  }

  /** Operator registry as pinned from the leader(s) this node followed. */
  pinnedRegistry(): RegistryOperator[] {
    return this.registry;
  }

  private stop(h: Omit<Halt, "at">) {
    this.halt = { at: new Date().toISOString(), ...h };
    this.state = "halted";
    const tmp = this.file(`ALARM.${process.pid}.tmp`);
    writeFileSync(tmp, JSON.stringify(this.halt, null, 2), { mode: 0o600 });
    renameSync(tmp, this.file("ALARM.json"));
    this.log(`HALTED (${h.kind}): ${h.message}`);
  }

  /** One round: registry, records, checks, checkpoint exchange, gossip. Never throws. */
  async syncOnce(): Promise<void> {
    const leaderNow = this.currentLeader();
    if (this.halt) {
      if (leaderNow) await this.t.post(leaderNow, `${REPLICA_PREFIX}/alarm`, { kind: this.halt.kind, message: this.halt.message }).catch(() => undefined);
      return;
    }
    if (!leaderNow) {
      this.state = "no-leader";
      return;
    }
    try {
      await this.pinRegistry();
      if (this.halt) return;
      let caughtUp = false;
      for (let round = 0; round < 100 && !caughtUp; round++) {
        const from = this.server.ready ? this.server.lastRecord + 1 : 1;
        const r = await this.t.get<{ records: JournalRecord[]; checkpoint: SignedCheckpoint; error?: string; term?: number; sealed?: SealRecord }>(
          this.leader,
          `${REPLICA_PREFIX}/records?from=${from}&limit=${this.opts.batch ?? 500}`,
        );
        if (r.status === 409) {
          this.state = "waiting";
          this.lastError = r.body.error;
          return;
        }
        if (r.status !== 200) throw new Error(`leader answered ${r.status}${r.body.error ? `: ${r.body.error}` : ""}`);
        const { records, checkpoint } = r.body;
        if (!Array.isArray(records)) throw new Error("leader sent no records array");
        if (this.failover) {
          const term = r.body.term ?? 0;
          if (term < this.opts.term!()) throw new Error(`${this.leader.nodeId} answered as leader of term ${term}, but this node is in term ${this.opts.term!()}`);
          if (term > this.opts.term!()) this.opts.onTerm?.(term);
          this.leaderTerm = term;
          // The new leader may lack our tail: its last record is before ours.
          if (this.server.ready && isSignedCheckpoint(checkpoint) && checkpoint.cp.scenario === this.server.scenario && checkpoint.cp.record < this.server.lastRecord) {
            if (!(await this.reconcile(checkpoint))) return;
            continue;
          }
        }
        await this.apply(records);
        if (this.halt) return;
        await this.consider(checkpoint, true);
        if (this.halt) return;
        caughtUp = records.length === 0 || (isSignedCheckpoint(checkpoint) && checkpoint.cp.record <= this.server.lastRecord);
        if (this.failover && this.server.ready) this.learnSeal(r.body.sealed);
      }
      if (!this.server.ready) {
        this.state = "waiting";
        return;
      }
      const s = this.server.state;
      this.own = await nodeCheckpoint(this.opts.node, {
        scenario: this.server.scenario,
        record: this.server.lastRecord,
        length: s.ledger.length,
        head: s.ledger.at(-1)!.hash,
        term: this.opts.term?.() ?? 0,
        recordTerm: this.server.lastTerm,
      });
      const posted = await this.t.post<{ checkpoints?: unknown[]; error?: string }>(this.leader, `${REPLICA_PREFIX}/checkpoint`, this.own);
      if (posted.status !== 200) throw new Error(`leader refused our checkpoint: ${posted.body.error ?? posted.status}`);
      this.lastContact = Date.now();
      for (const sc of posted.body.checkpoints ?? []) await this.consider(sc, false);
      await this.gossip();
      if (this.halt) return;
      this.state = caughtUp ? "in-sync" : "syncing";
      this.lastSync = new Date().toISOString();
      this.lastError = undefined;
    } catch (e) {
      this.state = "leader-unreachable";
      this.lastError = e instanceof Error ? e.message : String(e);
    }
  }

  private async apply(records: JournalRecord[]) {
    const scenarioBefore = this.server.scenario;
    const lengthBefore = this.server.ready ? this.server.state.ledger.length : 0;
    let applied = 0;
    for (const rec of records) {
      try {
        this.server.follow(rec);
        applied++;
      } catch (e) {
        // A gap or a record the core cannot apply: stop here and retry next round. The leader
        // may be mid-restart; a persistent bad record is caught by the checkpoint comparison.
        if (applied === 0) throw e;
        break;
      }
    }
    if (!applied) return;
    // Check only the human actions added in this batch, so later registry changes (a role
    // change, a revoked key) do not retroactively halt the replica on old, valid entries.
    const since = this.server.scenario === scenarioBefore ? lengthBefore : 0;
    const { problems } = await auditSignatures(this.server.state.ledger, this.registry);
    const fresh = problems.filter((p) => p.seq >= since);
    if (fresh.length)
      this.stop({
        kind: "bad-signature",
        message: `ledger entry #${fresh[0].seq} from the leader's journal fails the signature audit: ${fresh[0].reason}`,
        evidence: { scenario: this.server.scenario, problems: fresh, throughRecord: this.server.lastRecord },
      });
  }

  /** A checkpoint from the leader (fromLeader) or relayed/gossiped. Verified before use. */
  private async consider(raw: unknown, fromLeader: boolean) {
    if (!isSignedCheckpoint(raw)) {
      if (fromLeader) throw new Error("leader sent no valid checkpoint");
      return;
    }
    const me = this.opts.node.nodeId;
    if (raw.cp.nodeId === me) return;
    const peer = this.opts.peers().find((p) => p.nodeId === raw.cp.nodeId);
    if (!peer || !(await verifyCheckpoint(raw, peer.publicKeyJwk))) {
      if (fromLeader) throw new Error("leader's checkpoint signature does not verify");
      return;
    }
    if (fromLeader && raw.cp.nodeId !== this.leader.nodeId) throw new Error("records came with another node's checkpoint");
    this.seen.push(raw);
    if (this.seen.length > MAX_SEEN) this.seen.shift();
    const prev = this.latest.get(raw.cp.nodeId);
    if (!prev || raw.cp.length >= prev.cp.length || raw.cp.scenario > prev.cp.scenario) this.latest.set(raw.cp.nodeId, raw);

    const leaderId = this.leader.nodeId;
    for (const e of findEquivocations(this.seen)) {
      const msg = `${e.nodeId} signed two different heads for #${e.length - 1} of scenario ${e.scenario}`;
      if (e.nodeId === leaderId) return this.stop({ kind: "equivocation", message: msg, evidence: { a: e.a, b: e.b } });
      this.note(msg);
    }
    if (!this.server.ready) return;
    const s = this.server.state;
    if (compare(raw.cp, this.server.scenario, s.ledger) === "disagrees") {
      const ours = { scenario: this.server.scenario, length: raw.cp.length, head: s.ledger[raw.cp.length - 1]?.hash };
      const msg = `${raw.cp.nodeId} signed head ${raw.cp.head.slice(0, 16)} for #${raw.cp.length - 1}; re-executing the leader's journal gives ${ours.head?.slice(0, 16)}`;
      if (raw.cp.nodeId === leaderId) {
        // After a failover our tail may simply be one the new leader replaced.
        if (this.failover && (await this.reconcile(raw))) return;
        if (this.halt) return;
        return this.stop({ kind: "divergence", message: msg, evidence: { theirs: raw, ours, throughRecord: this.server.lastRecord } });
      }
      this.note(msg);
    }
  }

  /**
   * The leader's journal differs from ours, or ends before ours. Find the last record we share
   * (scanning back from the end, a page at a time) and drop what follows, if that is safe:
   * the dropped records must be in this scenario, after everything known to be sealed, and
   * from an earlier term than the leader's (a leader never rewrites its own term). Returns true
   * when it truncated; false when there is nothing to drop (the caller halts on divergence).
   */
  private async reconcile(leaderCp: SignedCheckpoint): Promise<boolean> {
    const ours = this.server;
    const start = ours.firstRecord;
    const hi0 = Math.min(ours.lastRecord, leaderCp.cp.record);
    let firstBad: number | undefined;
    let hi = hi0;
    scan: while (hi >= start) {
      const lo = Math.max(start, hi - 499);
      const r = await this.t.get<{ records: JournalRecord[] }>(this.leader, `${REPLICA_PREFIX}/records?from=${lo}&limit=${hi - lo + 1}`);
      if (r.status !== 200 || !Array.isArray(r.body.records)) throw new Error(`leader answered ${r.status} while comparing journals`);
      const theirs = new Map(r.body.records.map((x) => [x.n, x]));
      for (let n = hi; n >= lo; n--) {
        const t = theirs.get(n);
        if (t && canonical(t) === canonical(ours.recordAt(n))) break scan;
        firstBad = n;
      }
      hi = lo - 1;
    }
    const common = firstBad === undefined ? hi0 : firstBad - 1;
    if (common >= ours.lastRecord) return false;
    const seal = loadSeal(ours.dir);
    const sealedRecord = seal?.scenario === ours.scenario ? seal.record : 0;
    const dropped = ours.recordAt(common + 1);
    const where = `records ${common + 1}-${ours.lastRecord} of scenario ${ours.scenario}`;
    if (common < start) {
      this.stop({ kind: "sealed-rewrite", message: `${this.leader.nodeId}'s journal shares nothing with ours in scenario ${ours.scenario}; refusing to replace it`, evidence: { leader: leaderCp } });
      return false;
    }
    if (common < sealedRecord) {
      this.stop({ kind: "sealed-rewrite", message: `${this.leader.nodeId} (term ${this.leaderTerm}) would replace ${where}, but this node knows records up to ${sealedRecord} are sealed`, evidence: { leader: leaderCp, seal } });
      return false;
    }
    if (recordTerm(dropped) >= this.leaderTerm) {
      this.stop({ kind: "divergence", message: `${this.leader.nodeId} would replace ${where}, written in term ${recordTerm(dropped)}, not before its own term ${this.leaderTerm}`, evidence: { leader: leaderCp } });
      return false;
    }
    ours.truncateTo(common);
    this.own = undefined;
    this.note(`dropped ${where}: an unsealed tail from term ${recordTerm(dropped)} that leader ${this.leader.nodeId} (term ${this.leaderTerm}) replaced`);
    return true;
  }

  /** Raise our known seal from what the leader reports. */
  private learnSeal(sealed: SealRecord | undefined) {
    if (!sealed || !Number.isInteger(sealed.record) || sealed.scenario !== this.server.scenario) return;
    raiseSeal(this.server.dir, { ...sealed, record: Math.min(sealed.record, this.server.lastRecord) });
  }

  /** Exchange checkpoints directly with other replicas, so a leader cannot hide disagreement. */
  private async gossip() {
    for (const p of this.opts.peers()) {
      if (p.leader || !p.url) continue;
      try {
        const r = await this.t.get<{ checkpoints?: unknown[] }>(p, `${REPLICA_PREFIX}/checkpoints`);
        if (r.status === 200) for (const sc of r.body.checkpoints ?? []) await this.consider(sc, false);
      } catch {
        /* a peer being down is not an alarm */
      }
      if (this.halt) return;
    }
  }

  /**
   * Keep our own copy of the operator registry. Keys are pinned on first sight: a key id whose
   * public key changes is a forgery attempt and halts the replica. Keys are never removed from
   * the pinned copy (old ledger entries must stay verifiable); roles, revocations and disabling
   * follow the leader, and new keys are noted.
   */
  private async pinRegistry() {
    const r = await this.t.get<RegistryOperator[]>(this.leader, `${REPLICA_PREFIX}/registry`);
    if (r.status !== 200 || !Array.isArray(r.body)) throw new Error(`leader registry: ${r.status}`);
    const pinned = new Map(this.registry.map((o) => [o.id, o]));
    const allKeys = new Map(this.registry.flatMap((o) => o.keys.map((k) => [k.keyId, { op: o.id, k }] as const)));
    let changed = false;
    for (const op of r.body) {
      const mine = pinned.get(op.id) ?? { ...op, keys: [] };
      if (!pinned.has(op.id)) {
        pinned.set(op.id, mine);
        changed = true;
        if (this.registry.length) this.note(`new operator ${op.id} (${op.role}) in the leader's registry`);
      }
      for (const k of op.keys) {
        const known = allKeys.get(k.keyId);
        if (known && (known.op !== op.id || known.k.publicKeyJwk.x !== k.publicKeyJwk.x || known.k.publicKeyJwk.y !== k.publicKeyJwk.y))
          return this.stop({ kind: "registry-key-changed", message: `the leader now lists key ${k.keyId} with a different public key or owner (was ${known.op})`, evidence: { pinned: known, served: { op: op.id, key: k } } });
        const existing = mine.keys.find((x) => x.keyId === k.keyId);
        if (!existing) {
          mine.keys.push(k);
          changed = true;
          if (this.registry.length) this.note(`new key ${k.keyId} for ${op.id}`);
        } else if (existing.revokedAt !== k.revokedAt && k.revokedAt) {
          existing.revokedAt = k.revokedAt;
          changed = true;
        }
      }
      if (mine.role !== op.role || mine.disabled !== op.disabled || mine.name !== op.name) {
        Object.assign(mine, { role: op.role, disabled: op.disabled, name: op.name });
        changed = true;
      }
    }
    if (changed) {
      this.registry = [...pinned.values()];
      writeFileSync(this.file("registry.json"), JSON.stringify({ version: 1, operators: this.registry }, null, 2), { mode: 0o600 });
    }
  }

  async checkpoints(): Promise<SignedCheckpoint[]> {
    return [...(this.own ? [this.own] : []), ...this.latest.values()];
  }

  status(): ReplicaStatus {
    const ready = this.server.ready;
    return {
      nodeId: this.opts.node.nodeId,
      role: "replica",
      state: this.state,
      leader: this.currentLeader()?.nodeId ?? "(none)",
      scenario: this.server.scenario,
      record: this.server.lastRecord,
      length: ready ? this.server.state.ledger.length : 0,
      head: ready ? this.server.state.ledger.at(-1)!.hash : "",
      lastSync: this.lastSync,
      lastError: this.lastError,
      halt: this.halt,
      notes: [...this.notes].reverse(),
    };
  }

  /** Sync every intervalMs, never overlapping rounds. */
  start(intervalMs = 1000) {
    const loop = async () => {
      await this.syncOnce();
      if (!this.stopped) this.timer = setTimeout(loop, intervalMs);
    };
    void loop();
    return this;
  }

  close() {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    if (this.ownsServer) this.server.close();
  }
}

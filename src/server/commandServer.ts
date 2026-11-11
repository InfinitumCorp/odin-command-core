// The authoritative ODIN° state. One per deployment, shared by every console.
//
// Every command that changes state, human or machine, is written to an append-only journal
// before it takes effect in memory. Because the core is deterministic, snapshot + journal
// replays to exactly the same state, ledger included. On start-up the ledger is verified and
// the server refuses to run on a broken chain.
//
// Human commands are checked here, before they run: the session's operator must match the
// signature, the signature must verify against the registry key, and the role comes from the
// registry. A console can no longer act on state the server did not give it.
//
//   .odin/state/snapshot.json   full state (incl. hidden truth) as of journal record n
//   .odin/state/journal.jsonl   every record of the current scenario, one per line
//   .odin/state/archive/        closed scenarios: final state + full ledger, and their journals
//   .odin/state/LOCK            pid of the server that owns the directory
//
// The journal is kept whole for the scenario (the snapshot is only a start-up shortcut), so
// replicas can fetch it from the first record and re-execute it (see replica.ts). A replica
// runs this same class with role "replica": it never accepts console commands or runs the
// loop, it only follows records from the leader. Its directory has the same layout, so a
// replica can be promoted by starting it as a leader on its own state directory.
//
// Phase 8 (automatic failover): every record carries the election term of the leader that
// wrote it, the role can change at run time (becomeLeader / becomeFollower), a new leader's
// first record is a "leader-elected" marker in its own term, and a follower can drop an
// unsealed tail that a later leader replaced (truncateTo).

import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, renameSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { join } from "node:path";
import { initialState, run, type Command } from "../core/engine";
import { append, verify } from "../core/ledger";
import { situationFor } from "../core/decide";
import { verifyIntent, type RegistryOperator, type SignedIntent } from "../core/identity";
import { toView, type ConsoleView, type DraftStatus } from "../core/view";
import type { ReplicationStatus } from "../core/checkpoint";
import type { CoaProposal, LedgerEntry, Operator, State } from "../core/types";

export const DEFAULT_STATE_DIR = ".odin/state";

/** Commands a console may send. Ticks, ingest and drafts come only from the server itself. */
const HUMAN_COMMANDS = new Set(["approve", "reject", "redraft", "set-simulation", "set-clock", "close-scenario", "set-operator"]);

type OpenScenario = { type: "open-scenario"; seed: number; previous?: { scenario: number; head: string; length: number } };
type LeaderElected = { type: "leader-elected"; term: number; nodeId: string };
type Recorded = Command | OpenScenario | LeaderElected;

export interface JournalRecord {
  n: number;
  at: string;
  operator?: Operator;
  cmd: Recorded;
  /** Election term of the leader that wrote it (Phase 8; absent = 0). */
  term?: number;
}

export const recordTerm = (r: JournalRecord | undefined) => r?.term ?? 0;

interface Snapshot {
  version: 1;
  n: number;
  scenario: number;
  /** Record number of the current scenario's open-scenario record (absent before Phase 6). */
  start?: number;
  state: State;
}

export interface SessionOperator {
  id: string;
  keyId: string;
}

export type Drafter = (situation: ReturnType<typeof situationFor>) => Promise<{ proposals: CoaProposal[]; model: string }>;

export class SubmitError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export interface CommandServerOptions {
  dir?: string;
  registry: () => RegistryOperator[];
  drafter?: Drafter;
  /** Batches waiting from live feeds; drained on every loop turn. */
  drainFeeds?: () => { batches: Array<{ via: string; reports: unknown[]; adapterRejected: Array<{ reason: string }> }>; dropped: number };
  snapshotEvery?: number;
  maxDraftsInFlight?: number;
  seed?: number;
  log?: (msg: string) => void;
  /** Security-key signature counters, for clone detection (throws to refuse the command). */
  onSignCount?: (operatorId: string, keyId: string, count: number) => void;
  /** "replica" follows a leader's records and refuses console commands. Default "leader". */
  role?: "leader" | "replica";
  /** Firmament replication status to show consoles. */
  replication?: () => ReplicationStatus | undefined;
  /** Phase 8: refuse console commands unless this returns undefined (e.g. no quorum lease). */
  canAccept?: () => string | undefined;
}

export class ReplicaGap extends Error {}

export class CommandServer {
  readonly dir: string;
  private role_: "leader" | "replica";
  /** Election term this node writes records in (Phase 8). */
  term = 0;
  state!: State;
  scenario = 1;
  private n = 0;
  /** n of the current scenario's open-scenario record. */
  private scenarioStart = 0;
  /** Every record of the current scenario, in order (what replicas fetch). */
  private log_: JournalRecord[] = [];
  private archiveCache?: { file: string; records: JournalRecord[] };
  private sinceSnapshot = 0;
  private opts: CommandServerOptions;
  private listeners = new Set<() => void>();
  private drafts: Record<string, DraftStatus> = {};
  private requested = new Set<string>();
  private inFlight = 0;
  private hubDropped = 0;
  private timer?: ReturnType<typeof setInterval>;
  private locked = false;

  constructor(opts: CommandServerOptions) {
    this.opts = opts;
    this.role_ = opts.role ?? "leader";
    this.dir = opts.dir ?? process.env.ODIN_STATE_DIR ?? DEFAULT_STATE_DIR;
  }

  get role() {
    return this.role_;
  }

  /** A replica has no state until the leader's first record arrives. */
  get ready() {
    return !!this.state;
  }

  /** Number of the last journal record applied. */
  get lastRecord() {
    return this.n;
  }

  /** Term of the last record applied. */
  get lastTerm() {
    return recordTerm(this.log_.at(-1));
  }

  /** First record of the current scenario (its open-scenario). */
  get firstRecord() {
    return this.scenarioStart;
  }

  /** A record of the current scenario, as journaled. */
  recordAt(n: number): JournalRecord | undefined {
    const first = this.log_[0]?.n;
    return first === undefined ? undefined : this.log_[n - first];
  }

  /** True when the journal holds the current scenario from its first record. */
  get replicable() {
    return this.log_.length > 0 && this.log_[0].n === this.scenarioStart && this.log_[0].cmd.type === "open-scenario";
  }

  private path(name: string) {
    return join(this.dir, name);
  }

  private log(msg: string) {
    (this.opts.log ?? ((m: string) => console.log(`[odin] ${m}`)))(msg);
  }

  /** Take the directory lock, load snapshot + journal, verify the ledger. */
  open(): this {
    mkdirSync(join(this.dir, "archive"), { recursive: true });
    this.lock();
    const snapPath = this.path("snapshot.json");
    if (existsSync(snapPath)) {
      const snap = JSON.parse(readFileSync(snapPath, "utf8")) as Snapshot;
      if (snap.version !== 1) throw new Error(`unrecognised snapshot in ${this.dir}`);
      this.state = snap.state;
      this.n = snap.n;
      this.scenario = snap.scenario;
      this.scenarioStart = snap.start ?? -1;
      let replayed = 0;
      for (const rec of this.readJournal()) {
        if (rec.n <= this.n) {
          this.log_.push(rec); // already in the snapshot
          continue;
        }
        if (rec.n !== this.n + 1) throw new Error(`journal gap: expected record ${this.n + 1}, found ${rec.n}`);
        this.applyRecord(rec);
        this.log_.push(rec);
        replayed++;
      }
      const check = verify(this.state.ledger);
      if (!check.ok) throw new Error(`ledger in ${this.dir} is broken at #${check.brokenAt} (${check.reason}); refusing to start. Restore from backup or archive the directory.`);
      this.log(`restored scenario ${this.scenario}: snapshot at record ${snap.n}, ${replayed} journal record(s) replayed, ledger verified (${check.length} entries)`);
      if (!this.replicable && this.role === "leader") this.log(`scenario ${this.scenario} predates replication; replicas can join from the next scenario`);
      this.snapshot();
    } else if (this.role === "replica") {
      this.n = 0;
      this.log(`empty replica in ${this.dir}; waiting for the leader's first record`);
    } else {
      this.n = 0;
      this.record({ type: "open-scenario", seed: this.opts.seed ?? Math.floor(Math.random() * 1e6) });
      this.snapshot();
      this.log(`started scenario ${this.scenario} in ${this.dir}`);
    }
    return this;
  }

  /** Parse the journal; a torn final line (crash mid-write) is dropped and the file repaired. */
  private readJournal(): JournalRecord[] {
    const p = this.path("journal.jsonl");
    if (!existsSync(p)) return [];
    const out: JournalRecord[] = [];
    const lines = readFileSync(p, "utf8").split("\n").filter((l) => l.trim());
    for (let i = 0; i < lines.length; i++) {
      try {
        out.push(JSON.parse(lines[i]));
      } catch {
        if (i !== lines.length - 1) throw new Error(`journal ${p} is corrupt at line ${i + 1}`);
        this.log("dropping a torn final journal line (crash during write)");
        writeFileSync(p, out.map((r) => JSON.stringify(r) + "\n").join(""), { mode: 0o600 });
      }
    }
    return out;
  }

  private lock() {
    const p = this.path("LOCK");
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const fd = openSync(p, "wx");
        writeSync(fd, String(process.pid));
        closeSync(fd);
        this.locked = true;
        return;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
        const pid = Number(readFileSync(p, "utf8"));
        let alive = pid === process.pid;
        if (!alive && pid > 0) {
          try {
            process.kill(pid, 0);
            alive = true;
          } catch (err) {
            alive = (err as NodeJS.ErrnoException).code === "EPERM";
          }
        }
        if (alive) throw new Error(`${this.dir} is in use by process ${pid}; only one ODIN server may own a state directory`);
        unlinkSync(p); // stale lock from a crashed server
      }
    }
  }

  /** Apply one record to memory. Used for live commands and for replay alike. */
  private applyRecord(rec: JournalRecord): string | undefined {
    const cmd = rec.cmd;
    this.n = rec.n;
    if (cmd.type === "open-scenario") {
      const s = initialState(cmd.seed, { id: "ODIN", role: "analyst" }, { requireSignatures: true });
      this.scenario = cmd.previous ? cmd.previous.scenario + 1 : 1;
      this.scenarioStart = rec.n;
      this.log_ = [];
      s.ledger = append(s.ledger, s.t, "ODIN", "scenario.opened", { seed: cmd.seed, scenario: this.scenario, previous: cmd.previous ?? null });
      this.state = s;
      this.drafts = {};
      this.requested.clear();
      return undefined;
    }
    if (cmd.type === "leader-elected") {
      // Not a core command: the marker goes on the ledger so every node computes the same chain.
      this.state = { ...this.state, ledger: append(this.state.ledger, this.state.t, "ODIN", "firmament.leader-elected", { term: cmd.term, node: cmd.nodeId }) };
      return undefined;
    }
    const input = rec.operator ? { ...this.state, operator: rec.operator } : this.state;
    const r = run(input, cmd);
    this.state = r.state;
    return r.error;
  }

  /** Journal first, then apply: anything in memory is on disk. */
  private record(cmd: Recorded, operator?: Operator): string | undefined {
    const rec: JournalRecord = { n: this.n + 1, at: new Date().toISOString(), operator, cmd };
    if (this.term) rec.term = this.term;
    appendFileSync(this.path("journal.jsonl"), JSON.stringify(rec) + "\n");
    const error = this.applyRecord(rec);
    this.log_.push(rec);
    if (++this.sinceSnapshot >= (this.opts.snapshotEvery ?? 300)) this.snapshot();
    return error;
  }

  /** Atomic snapshot. The journal is kept: start-up replays only the records after n. */
  snapshot() {
    if (!this.state) return;
    const snap: Snapshot = { version: 1, n: this.n, scenario: this.scenario, start: this.scenarioStart, state: this.state };
    const tmp = this.path(`snapshot.${process.pid}.tmp`);
    writeFileSync(tmp, JSON.stringify(snap), { mode: 0o600 });
    renameSync(tmp, this.path("snapshot.json"));
    this.sinceSnapshot = 0;
  }

  /** Archive the closing scenario: final state, then its journal (after a snapshot, so nothing is lost). */
  private archiveScenario(): { head: string; length: number; file: string } {
    const closed = this.state;
    const head = closed.ledger.at(-1)!.hash;
    const stem = `scenario-${String(this.scenario).padStart(4, "0")}-${head.slice(0, 12)}`;
    const file = this.path(join("archive", `${stem}.json`));
    writeFileSync(file, JSON.stringify({ version: 1, scenario: this.scenario, state: closed }), { mode: 0o600 });
    this.snapshot();
    if (existsSync(this.path("journal.jsonl"))) renameSync(this.path("journal.jsonl"), this.path(join("archive", `${stem}.journal.jsonl`)));
    return { head, length: closed.ledger.length, file };
  }

  /**
   * A console's command. The session identifies the operator; the registry gives the role;
   * the signature must verify against the registered key before the core sees the command.
   */
  async submit(who: SessionOperator, raw: unknown): Promise<{ error?: string }> {
    if (this.role !== "leader") throw new SubmitError(409, "this node is a replica; send commands to the leader");
    const refused = this.opts.canAccept?.();
    if (refused) throw new SubmitError(409, refused);
    const cmd = raw as Command & { auth?: SignedIntent };
    if (!cmd || typeof cmd !== "object" || !HUMAN_COMMANDS.has(cmd.type)) throw new SubmitError(400, "not a console command");
    const auth = cmd.auth;
    if (!auth?.intent || typeof auth.sig !== "string") throw new SubmitError(400, "command must be signed");
    if (auth.intent.operatorId !== who.id || auth.intent.keyId !== who.keyId) throw new SubmitError(403, "signature is not from the signed-in operator's key");
    const op = this.opts.registry().find((o) => o.id === who.id);
    const key = op?.keys.find((k) => k.keyId === who.keyId && !k.revokedAt);
    if (!op || op.disabled || !key) throw new SubmitError(403, "operator or key is no longer authorised");
    const check = await verifyIntent(auth, key);
    if (!check.ok) throw new SubmitError(403, check.reason);
    if (check.hardware && check.signCount !== undefined) {
      try {
        this.opts.onSignCount?.(op.id, key.keyId, check.signCount);
      } catch (e) {
        throw new SubmitError(403, e instanceof Error ? e.message : "security key refused");
      }
    }

    const operator: Operator = { id: op.id, role: op.role, keyId: key.keyId };
    const safe: Command = cmd.type === "set-operator" ? { type: "set-operator", operator, auth } : cmd;
    const error = this.record(safe, operator);
    if (!error && cmd.type === "close-scenario") this.openNext(cmd.seed);
    if (!error && cmd.type === "redraft") {
      this.requested.delete(cmd.decisionId);
      delete this.drafts[cmd.decisionId];
    }
    this.pump();
    this.emit();
    return error ? { error } : {};
  }

  private openNext(seed: number) {
    const { head, length, file } = this.archiveScenario();
    this.record({ type: "open-scenario", seed, previous: { scenario: this.scenario, head, length } });
    this.snapshot();
    this.log(`scenario ${this.scenario - 1} archived to ${file}; scenario ${this.scenario} opened`);
  }

  /** One turn of the server loop: feeds, clock, drafting. */
  step() {
    if (this.role !== "leader") return;
    const feeds = this.opts.drainFeeds?.();
    if (feeds) {
      this.hubDropped += feeds.dropped;
      for (const b of feeds.batches) this.record({ type: "ingest", via: b.via, reports: b.reports, adapterRejected: b.adapterRejected });
    }
    if (this.state.clock.running) this.record({ type: "tick", minutes: this.state.clock.speed });
    this.pump();
    this.emit();
  }

  /** Ask SCALVS for options on each new rule-drafted decision; results go through the core's validation. */
  private pump() {
    const drafter = this.opts.drafter;
    if (!drafter || this.role !== "leader") return;
    for (const d of this.state.decisions) {
      if (this.inFlight >= (this.opts.maxDraftsInFlight ?? 2)) return;
      if (d.status !== "open" || d.drafter.source !== "rules" || this.requested.has(d.id)) continue;
      this.requested.add(d.id);
      this.drafts[d.id] = { kind: "pending" };
      this.inFlight++;
      const scenario = this.scenario;
      drafter(situationFor(this.state, d.id))
        .then((res) => {
          delete this.drafts[d.id];
          if (scenario === this.scenario) this.record({ type: "apply-drafts", decisionId: d.id, proposals: res.proposals, model: res.model });
        })
        .catch((e) => {
          this.drafts[d.id] = { kind: "failed", reason: e instanceof Error ? e.message : "draft failed" };
        })
        .finally(() => {
          this.inFlight--;
          this.emit();
        });
    }
  }

  view(): ConsoleView {
    return toView(this.state, {
      scenario: this.scenario,
      drafts: { ...this.drafts },
      llm: !!this.opts.drafter,
      hub: { dropped: this.hubDropped },
      replication: this.opts.replication?.(),
    });
  }

  // -------------------------------------------------------------------------
  // Replication

  /**
   * Journal records from n = from, up to limit, for a replica to re-execute. Records of closed
   * scenarios come from their archived journals. A replica that asks for a record older than
   * any journal kept here is sent the first record of the oldest one it can have (always an
   * open-scenario), which only an empty replica accepts.
   */
  records(from: number, limit = 500): JournalRecord[] {
    if (this.replicable && from >= this.scenarioStart) return this.log_.filter((r) => r.n >= from).slice(0, limit);
    const archives = readdirSync(this.path("archive"))
      .filter((f) => f.endsWith(".journal.jsonl"))
      .sort();
    const load = (f: string) => {
      if (this.archiveCache?.file !== f) {
        const recs = readFileSync(this.path(join("archive", f)), "utf8")
          .split("\n")
          .filter((l) => l.trim())
          .map((l) => JSON.parse(l) as JournalRecord);
        this.archiveCache = { file: f, records: recs };
      }
      return this.archiveCache.records;
    };
    for (const f of archives) {
      const recs = load(f);
      if (!recs.length || recs[0].cmd.type !== "open-scenario") continue;
      if (recs.at(-1)!.n >= from) return (from >= recs[0].n ? recs.filter((r) => r.n >= from) : recs).slice(0, limit);
    }
    return this.replicable ? this.log_.slice(0, limit) : [];
  }

  /**
   * Replica only: apply one record exactly as the leader recorded it. Gaps are refused; an
   * empty replica starts at the first open-scenario it is given.
   */
  follow(rec: JournalRecord) {
    if (this.role !== "replica") throw new Error("only a replica follows records");
    const opening = rec.cmd?.type === "open-scenario";
    if (!this.state) {
      if (!opening) throw new ReplicaGap(`an empty replica must start at an open-scenario record, got ${rec.cmd?.type} #${rec.n}`);
    } else if (rec.n !== this.n + 1) throw new ReplicaGap(`expected record ${this.n + 1}, leader sent ${rec.n}`);
    if (this.state && recordTerm(rec) < this.lastTerm) throw new ReplicaGap(`record ${rec.n} is from term ${recordTerm(rec)}, before term ${this.lastTerm}`);
    if (opening && this.state) this.archiveScenario();
    appendFileSync(this.path("journal.jsonl"), JSON.stringify(rec) + "\n");
    this.applyRecord(rec);
    this.log_.push(rec);
    if (opening || ++this.sinceSnapshot >= (this.opts.snapshotEvery ?? 300)) this.snapshot();
  }

  // -------------------------------------------------------------------------
  // Automatic failover (Phase 8)

  /** Take over as leader in `term`. The first record is the leader-elected marker. */
  becomeLeader(term: number, nodeId: string) {
    if (!this.state) throw new Error("an empty node cannot lead");
    if (term < this.lastTerm) throw new Error(`term ${term} is older than this journal's term ${this.lastTerm}`);
    this.role_ = "leader";
    this.term = term;
    this.drafts = {};
    this.requested.clear();
    this.record({ type: "leader-elected", term, nodeId });
    this.snapshot();
    this.log(`leader for term ${term}`);
    this.emit();
  }

  /** Stop leading: refuse console commands, stop the loop's writes, follow records instead. */
  becomeFollower(term: number) {
    this.term = Math.max(this.term, term);
    if (this.role_ === "replica") return;
    this.role_ = "replica";
    this.log(`following (term ${this.term})`);
    this.emit();
  }

  /**
   * Drop every record after `n` in the current scenario and rebuild the state from the
   * scenario's first record. Only for a tail a later leader replaced: the caller checks it was
   * never sealed. Records before the current scenario cannot be dropped.
   */
  truncateTo(n: number) {
    if (this.role_ !== "replica") throw new Error("only a follower truncates");
    if (!this.replicable) throw new Error("this scenario's journal is incomplete; cannot rebuild");
    if (n < this.scenarioStart) throw new Error(`record ${n} is before this scenario (starts at ${this.scenarioStart})`);
    if (n >= this.n) return;
    const keep = this.log_.filter((r) => r.n <= n);
    this.log_ = [];
    for (const rec of keep) {
      this.applyRecord(rec);
      this.log_.push(rec);
    }
    const tmp = this.path(`journal.${process.pid}.tmp`);
    writeFileSync(tmp, keep.map((r) => JSON.stringify(r) + "\n").join(""), { mode: 0o600 });
    renameSync(tmp, this.path("journal.jsonl"));
    this.snapshot();
    this.emit();
  }

  /** Tell subscribers something changed outside a command (e.g. replication status). */
  notify() {
    this.emit();
  }

  ledger(from = 0, limit = 1000): { length: number; entries: LedgerEntry[] } {
    return { length: this.state.ledger.length, entries: this.state.ledger.slice(from, from + limit) };
  }

  subscribe(fn: () => void) {
    this.listeners.add(fn);
    return () => void this.listeners.delete(fn);
  }

  private emit() {
    for (const fn of this.listeners) fn();
  }

  start(intervalMs = 1000) {
    this.timer ??= setInterval(() => {
      try {
        this.step();
      } catch (e) {
        console.error("[odin] loop error", e);
      }
    }, intervalMs);
    return this;
  }

  /** Stop the loop, write a final snapshot and release the directory. */
  close() {
    if (this.timer) clearInterval(this.timer);
    this.listeners.clear();
    this.timer = undefined;
    if (this.locked) {
      this.snapshot();
      try {
        unlinkSync(this.path("LOCK"));
      } catch {
        /* already gone */
      }
      this.locked = false;
    }
  }
}

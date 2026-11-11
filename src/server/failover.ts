// Automatic failover for the Firmament (Phase 8).
//
// A FirmamentNode owns one command server and plays whichever role the cluster gives it:
//
//   follower   syncs from the elected leader (Replica), and starts an election when it has not
//              reached the leader for a randomised election timeout
//   candidate  next term, votes for itself, asks every peer for a vote; a majority makes it
//              leader (see election.ts for the vote rule)
//   leader     writes the journal in its term, starting with a "leader-elected" record, serves
//              the node API, and accepts console commands only while it holds a quorum lease
//
// The lease is what stops two leaders acting at once. A node votes only when it has not heard
// from a leader for at least ELECTION ms; a leader accepts commands only while a majority
// reached it within LEASE ms (< ELECTION). Two majorities share a node, so by the time a new
// leader can be elected the old one has already stopped accepting commands. A leader that
// loses its majority for ELECTION ms steps down and looks for the new leader.
//
// What is sealed never changes: a candidate needs votes from a majority whose journals are no
// longer than its own (term first), a seal needs a majority including a current-term record,
// and a rejoining node drops only a tail that is unsealed and from an earlier term.
//
// Node API additions (signed node requests, like the rest of /api/replica):
//   GET  /hello   this node's id, term, role and the leader it follows
//   POST /vote    a candidate's vote request -> { term, granted }

import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { RegistryOperator } from "../core/identity";
import { majority, type ReplicationStatus } from "../core/checkpoint";
import { CommandServer, type CommandServerOptions } from "./commandServer";
import { decideVote, ElectionStore, isVoteRequest, type VoteReply } from "./election";
import { FirmamentLeader, loadSeal } from "./firmament";
import { httpTransport, type NodeIdentity, type Peer, type Transport } from "./nodeIdentity";
import { Replica, REPLICA_PREFIX } from "./replica";
import { leaderHandlers, nodeRoutes, type Get, type Post } from "./replicaRoutes";

export interface Hello {
  nodeId: string;
  term: number;
  role: "leader" | "follower" | "candidate";
  leader?: string;
  lastTerm: number;
  lastRecord: number;
  halted: boolean;
}

export interface FirmamentNodeOptions {
  dir?: string;
  node: NodeIdentity;
  peers: () => Peer[];
  transport?: Transport;
  /** The operator registry this node serves while it leads. */
  registry: () => RegistryOperator[];
  /** Start as the leader of term 0 (bootstrap). Only for a fresh state directory before any election. */
  bootstrapLeader?: boolean;
  /** Replica sync interval (ms). */
  syncMs?: number;
  /** Minimum election timeout (ms); the actual one is random in [electionMs, 2 x electionMs]. */
  electionMs?: number;
  /** Server loop interval (ms). */
  stepMs?: number;
  log?: (m: string) => void;
  /** Called once when this node first leads after following: e.g. write an operator store. */
  onPromote?: (pinned: RegistryOperator[]) => void;
  server?: Partial<Pick<CommandServerOptions, "drafter" | "drainFeeds" | "onSignCount" | "seed" | "snapshotEvery">>;
  random?: () => number;
}

export class FirmamentNode {
  readonly server: CommandServer;
  readonly replica: Replica;
  readonly election: ElectionStore;
  role: Hello["role"] = "follower";
  leaderId?: string;
  firmament?: FirmamentLeader;
  private opts: FirmamentNodeOptions;
  private t: Transport;
  private lastLeaderContact = 0;
  private deadline = 0;
  private leaderSince = 0;
  private timer?: ReturnType<typeof setTimeout>;
  private stopped = false;
  private busy = false;
  readonly syncMs: number;
  readonly electionMs: number;
  readonly leaseMs: number;

  constructor(opts: FirmamentNodeOptions) {
    this.opts = opts;
    this.syncMs = opts.syncMs ?? 1000;
    this.electionMs = opts.electionMs ?? 5 * this.syncMs;
    this.leaseMs = Math.floor(this.electionMs * 0.6);
    this.t = opts.transport ?? httpTransport(opts.node, Math.max(1000, this.electionMs));
    const dir = opts.dir ?? process.env.ODIN_STATE_DIR ?? ".odin/state";
    // Bootstrap only a brand-new cluster. A node that has run before (even the first leader,
    // restarted) starts as a follower and finds, or elects, the current leader.
    const fresh = !existsSync(join(dir, "journal.jsonl")) && !existsSync(join(dir, "snapshot.json"));
    mkdirSync(join(dir, "archive"), { recursive: true }); // the election file needs the directory first
    this.election = new ElectionStore(dir);
    const bootstrap = !!opts.bootstrapLeader && this.election.term === 0 && fresh;
    this.server = new CommandServer({
      ...opts.server,
      dir,
      role: bootstrap ? "leader" : "replica",
      registry: () => (this.role === "leader" ? opts.registry() : this.replica.pinnedRegistry()),
      log: opts.log,
      replication: () => this.replication(),
      canAccept: () => this.canAccept(),
    }).open();
    this.server.term = this.election.term;
    this.replica = new Replica({
      server: this.server,
      node: opts.node,
      peers: opts.peers,
      transport: this.t,
      log: opts.log,
      leader: () => this.leaderPeer(),
      term: () => this.election.term,
      onTerm: (term) => this.observe(term),
    });
    if (bootstrap) this.lead(0, false);
    this.resetDeadline();
  }

  private now() {
    return Date.now();
  }

  private log(m: string) {
    (this.opts.log ?? ((x: string) => console.log(`[firmament ${this.opts.node.nodeId}] ${x}`)))(m);
  }

  private leaderPeer(): Peer | undefined {
    return this.leaderId && this.leaderId !== this.opts.node.nodeId ? this.opts.peers().find((p) => p.nodeId === this.leaderId) : undefined;
  }

  private resetDeadline() {
    this.deadline = this.now() + this.electionMs * (1 + (this.opts.random ?? Math.random)());
  }

  get term() {
    return this.election.term;
  }

  get hasLease() {
    return this.role === "leader" && !!this.firmament?.hasQuorumContact(this.leaseMs);
  }

  private canAccept(): string | undefined {
    if (this.role !== "leader") return "this node is not the leader";
    if (!this.hasLease) return "this leader cannot reach a majority of Firmament nodes; commands wait until it can (or another node is elected)";
    return undefined;
  }

  /** A newer term seen anywhere: adopt it, and stop leading. */
  private observe(term: number) {
    if (term <= this.election.term) return;
    this.election.observe(term);
    if (this.role !== "follower") this.follow(`term ${term} seen`);
    this.server.becomeFollower(term);
  }

  private lead(term: number, promoted: boolean) {
    if (promoted) this.server.becomeLeader(term, this.opts.node.nodeId);
    this.role = "leader";
    this.leaderId = this.opts.node.nodeId;
    this.leaderSince = this.now();
    this.firmament = new FirmamentLeader(this.server, this.opts.node, this.opts.peers, { log: this.opts.log, failover: () => this.failoverInfo() });
    if (promoted) {
      this.log(`elected leader for term ${term}`);
      try {
        this.opts.onPromote?.(this.replica.pinnedRegistry());
      } catch (e) {
        this.log(`promotion hook failed: ${e instanceof Error ? e.message : e}`);
      }
    }
  }

  private follow(why: string) {
    if (this.role === "leader") this.log(`stepping down (${why})`);
    this.role = "follower";
    this.firmament = undefined;
    if (this.leaderId === this.opts.node.nodeId) this.leaderId = undefined;
    this.server.becomeFollower(this.election.term);
    this.resetDeadline();
  }

  hello(): Hello {
    return {
      nodeId: this.opts.node.nodeId,
      term: this.election.term,
      role: this.role,
      leader: this.leaderId,
      lastTerm: this.server.lastTerm,
      lastRecord: this.server.lastRecord,
      halted: !!this.replica.halt,
    };
  }

  /** A candidate asks for our vote. */
  vote(raw: unknown): { status: number; body: VoteReply | { error: string } } {
    if (!isVoteRequest(raw)) return { status: 400, body: { error: "bad vote request" } };
    const leading = this.role === "leader";
    const sticky = leading ? this.hasLease : !!this.leaderPeer() && this.now() - this.lastLeaderContact < this.electionMs;
    const reply = decideVote(this.election, raw, { lastTerm: this.server.lastTerm, lastRecord: this.server.lastRecord, halted: !!this.replica.halt, leading, sticky });
    if (raw.prevote) return { status: 200, body: reply };
    if (this.election.term > this.server.term) {
      if (this.role !== "follower") this.follow(`candidate ${raw.candidate} started term ${this.election.term}`);
      this.server.becomeFollower(this.election.term);
      if (this.leaderId !== raw.candidate) this.leaderId = undefined;
    }
    if (reply.granted) this.resetDeadline();
    return { status: 200, body: reply };
  }

  /** Ask every peer who leads; follow the leader of the newest term at least ours. */
  private async discover() {
    let best: Hello | undefined;
    await Promise.all(
      this.opts.peers().map(async (p) => {
        if (!p.url) return;
        try {
          const r = await this.t.get<Hello>(p, `${REPLICA_PREFIX}/hello`);
          if (r.status !== 200) return;
          const h = r.body;
          if (h.term > this.election.term) this.observe(h.term);
          if (h.role === "leader" && h.nodeId === p.nodeId && h.term >= this.election.term && (!best || h.term > best.term)) best = h;
        } catch {
          /* unreachable peer */
        }
      }),
    );
    if (best && this.role !== "leader") {
      if (this.leaderId !== best.nodeId) this.log(`following ${best.nodeId} (term ${best.term})`);
      this.leaderId = best.nodeId;
    }
  }

  /** Ask every peer for a vote; resolves to the number of votes, ourselves included. */
  private async poll(req: { term: number; candidate: string; lastTerm: number; lastRecord: number; prevote?: boolean }): Promise<number> {
    let votes = 1;
    await Promise.all(
      this.opts
        .peers()
        .filter((p) => p.url)
        .map(async (p) => {
          try {
            const r = await this.t.post<VoteReply>(p, `${REPLICA_PREFIX}/vote`, req);
            if (r.status !== 200) return;
            if (r.body.term > this.election.term && !req.prevote) this.observe(r.body.term);
            else if (r.body.granted) votes++;
          } catch {
            /* unreachable peer: no vote */
          }
        }),
    );
    return votes;
  }

  private async campaign() {
    if (this.replica.halt || !this.server.ready || !this.server.replicable) return this.resetDeadline();
    const need = majority(this.opts.peers().length + 1);
    const position = { candidate: this.opts.node.nodeId, lastTerm: this.server.lastTerm, lastRecord: this.server.lastRecord };
    if ((await this.poll({ ...position, term: this.election.term + 1, prevote: true })) < need) return this.resetDeadline();
    if (this.role !== "follower" || this.leaderPeer()) return this.resetDeadline();
    const term = this.election.campaign(this.opts.node.nodeId);
    this.server.becomeFollower(term);
    this.role = "candidate";
    this.leaderId = undefined;
    this.log(`no leader for ${this.electionMs} ms; standing for term ${term}`);
    const votes = await this.poll({ ...position, term });
    if (this.role === "candidate" && this.election.term === term && votes >= need) this.lead(term, true);
    else {
      if (this.role === "candidate") this.role = "follower";
      this.resetDeadline();
    }
  }

  /** One turn: lead (keep the lease or step down), or follow (sync, maybe stand for election). */
  async tick() {
    if (this.busy) return;
    this.busy = true;
    try {
      if (this.replica.halt) {
        if (this.role !== "follower") this.follow("halted");
        await this.replica.syncOnce(); // reports the halt to a leader, if any
        return;
      }
      if (this.role === "leader") {
        if (this.now() - this.leaderSince > this.electionMs && !this.firmament?.hasQuorumContact(this.electionMs)) this.follow("lost contact with a majority");
        return;
      }
      if (!this.leaderPeer()) await this.discover();
      if (this.leaderPeer()) {
        const before = this.replica.lastContact;
        await this.replica.syncOnce();
        if (this.replica.lastContact > before) {
          this.lastLeaderContact = this.replica.lastContact;
          this.resetDeadline();
        } else {
          // Unreachable, or it answered "not the leader" (it stepped down): look again.
          this.leaderId = undefined;
          await this.discover();
        }
      }
      if (!this.replica.halt && this.role === "follower" && this.now() >= this.deadline) await this.campaign();
    } finally {
      this.busy = false;
    }
  }

  start() {
    const loop = async () => {
      await this.tick().catch((e) => this.log(`tick failed: ${e instanceof Error ? e.message : e}`));
      if (!this.stopped) this.timer = setTimeout(loop, this.syncMs);
    };
    this.server.start(this.opts.stepMs ?? 1000);
    void loop();
    return this;
  }

  close() {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    this.replica.close();
    this.server.close();
  }

  private failoverInfo(): NonNullable<ReplicationStatus["failover"]> {
    const leader = this.leaderId;
    const url = leader && leader !== this.opts.node.nodeId ? this.opts.peers().find((p) => p.nodeId === leader)?.url : undefined;
    return { term: this.election.term, leader, leaderUrl: url, role: this.role, lease: this.hasLease };
  }

  /** What consoles connected to this node see about replication. */
  replication(): ReplicationStatus {
    if (this.role === "leader" && this.firmament) return this.firmament.status();
    const nodes = this.opts.peers().length + 1;
    const seal = loadSeal(this.server.dir);
    const halt = this.replica.halt;
    return {
      nodeId: this.opts.node.nodeId,
      nodes,
      quorum: majority(nodes),
      sealed: seal?.scenario === this.server.scenario ? seal.length : 0,
      replicable: this.server.replicable,
      peers: [],
      alarms: halt ? [{ at: halt.at, node: this.opts.node.nodeId, kind: halt.kind, message: halt.message }] : [],
      failover: this.failoverInfo(),
    };
  }

  /** The node API (/api/replica/*) for whichever role this node is in. */
  routes() {
    const notLeader = () => ({ status: 409, body: { error: "not the leader", leader: this.leaderId, term: this.election.term } });
    const lead = () => (this.role === "leader" && this.firmament ? leaderHandlers(this.server, this.firmament, this.opts.registry) : undefined);
    const get: Record<string, Get> = {
      "/hello": () => ({ status: 200, body: this.hello() }),
      "/status": () => ({ status: 200, body: { ...this.replica.status(), failover: this.failoverInfo() } }),
      "/checkpoints": async (p, u) => {
        const h = lead();
        return h ? h.get["/checkpoints"](p, u) : { status: 200, body: { checkpoints: await this.replica.checkpoints() } };
      },
    };
    for (const path of ["/records", "/registry"]) get[path] = (p, u) => lead()?.get[path](p, u) ?? notLeader();
    const post: Record<string, Post> = { "/vote": (_p, b) => this.vote(b) };
    for (const path of ["/checkpoint", "/alarm"]) post[path] = (p, b) => lead()?.post[path](p, b) ?? notLeader();
    return nodeRoutes(this.opts.peers, get, post);
  }
}

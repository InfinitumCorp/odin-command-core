// Leader election for the Firmament (Phase 8), Raft-style.
//
// Each node keeps its current term and whom it voted for in that term, on disk, written
// before it answers a vote request: a node that restarts can never vote twice in one term.
// A candidate wins a term with the votes of a majority of nodes, and a node votes only for a
// candidate whose journal is at least as up to date as its own (last record's term, then its
// number). Because any two majorities share a node, the winner holds every record a majority
// had, which is every sealed record.
//
//   <state dir>/election.json   { term, votedFor }   (mode 0600, atomic rename)

import { closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, writeSync } from "node:fs";
import { join } from "node:path";

export interface ElectionState {
  term: number;
  votedFor?: string;
}

export interface LogPosition {
  /** Term of the last journal record. */
  lastTerm: number;
  /** Number of the last journal record. */
  lastRecord: number;
}

/** True when `a` is at least as up to date as `b`. */
export const atLeastAsUpToDate = (a: LogPosition, b: LogPosition) => a.lastTerm > b.lastTerm || (a.lastTerm === b.lastTerm && a.lastRecord >= b.lastRecord);

export class ElectionStore {
  readonly path: string;
  private s: ElectionState = { term: 0 };

  constructor(dir: string) {
    this.path = join(dir, "election.json");
    if (existsSync(this.path)) {
      const f = JSON.parse(readFileSync(this.path, "utf8")) as ElectionState;
      if (!Number.isInteger(f.term) || f.term < 0) throw new Error(`unrecognised ${this.path}`);
      this.s = { term: f.term, votedFor: typeof f.votedFor === "string" ? f.votedFor : undefined };
    }
  }

  get term() {
    return this.s.term;
  }

  get votedFor() {
    return this.s.votedFor;
  }

  /** Durable before it returns: fsync the file, then rename it into place. */
  private save(next: ElectionState) {
    const tmp = `${this.path}.${process.pid}.tmp`;
    const fd = openSync(tmp, "w", 0o600);
    try {
      writeSync(fd, JSON.stringify(next));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, this.path);
    this.s = next;
  }

  /** Move to a later term (forgetting the vote). Ignores older or equal terms. */
  observe(term: number) {
    if (term > this.s.term) this.save({ term });
  }

  /** Start a campaign: next term, vote for ourselves. */
  campaign(self: string): number {
    this.save({ term: this.s.term + 1, votedFor: self });
    return this.s.term;
  }

  /** Record a vote in the current term; false when already given to someone else. */
  vote(term: number, candidate: string): boolean {
    if (term !== this.s.term) return false;
    if (this.s.votedFor && this.s.votedFor !== candidate) return false;
    if (this.s.votedFor !== candidate) this.save({ term, votedFor: candidate });
    return true;
  }
}

export interface VoteRequest extends LogPosition {
  term: number;
  candidate: string;
  /**
   * Pre-vote: "would you vote for me in this term?" Answered without changing any state. A
   * candidate increments its term only after a majority says yes, so a node cut off from the
   * cluster cannot inflate its term and disrupt a healthy leader when it reconnects.
   */
  prevote?: boolean;
}

export interface VoteReply {
  term: number;
  granted: boolean;
  reason?: string;
}

export function isVoteRequest(x: unknown): x is VoteRequest {
  const v = x as VoteRequest;
  return (
    !!v &&
    typeof v === "object" &&
    Number.isInteger(v.term) &&
    v.term > 0 &&
    typeof v.candidate === "string" &&
    Number.isInteger(v.lastTerm) &&
    Number.isInteger(v.lastRecord) &&
    (v.prevote === undefined || typeof v.prevote === "boolean")
  );
}

/**
 * Decide a vote. `sticky` is true while this node still hears from a live leader: it then
 * ignores the request entirely (not even adopting its term), so a node cut off from the
 * leader cannot depose a healthy one when it reconnects.
 */
export function decideVote(store: ElectionStore, req: VoteRequest, me: LogPosition & { halted: boolean; leading: boolean; sticky: boolean }): VoteReply {
  if (req.term < store.term) return { term: store.term, granted: false, reason: "stale term" };
  if (me.sticky) return { term: store.term, granted: false, reason: "a leader is alive" };
  if (me.halted) return { term: store.term, granted: false, reason: "this node is halted" };
  if (req.prevote) {
    const free = req.term > store.term || (req.term === store.term && (store.votedFor === undefined || store.votedFor === req.candidate));
    if (!free) return { term: store.term, granted: false, reason: "already voted in that term" };
    return atLeastAsUpToDate(req, me) ? { term: store.term, granted: true } : { term: store.term, granted: false, reason: "candidate's journal is behind" };
  }
  store.observe(req.term);
  if (me.leading && req.term === store.term && store.votedFor === undefined) return { term: store.term, granted: false, reason: "this node leads that term" };
  if (!atLeastAsUpToDate(req, me)) return { term: store.term, granted: false, reason: "candidate's journal is behind" };
  return store.vote(req.term, req.candidate) ? { term: store.term, granted: true } : { term: store.term, granted: false, reason: `already voted for ${store.votedFor}` };
}

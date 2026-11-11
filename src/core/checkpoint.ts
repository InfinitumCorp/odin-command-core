// Replicated Firmament: signed checkpoints.
//
// A checkpoint is one node's signed statement: "in scenario S, after journal record R, the
// ledger I computed has L entries and its last hash is H." Replicas do not copy the leader's
// ledger. They re-execute the leader's journal through the same deterministic core and sign the
// head *they* computed. Because each head commits to the whole chain before it, a checkpoint
// at length L vouches for every entry up to L.
//
// From these checkpoints:
//   - sealing: an entry is sealed once a quorum of nodes have signed heads that include it.
//     Rewriting a sealed entry needs the keys of a quorum, not just one server's disk.
//   - divergence: a node whose signed head disagrees with our own at the same length holds a
//     different history. The two signed checkpoints are the evidence.
//   - equivocation: one node that signed two different heads at the same length has shown
//     different histories to different peers. Those two signatures are a portable proof.
//
// Pure and shared by the server and the browser (WebCrypto in both).

import { GENESIS, canonical } from "./ledger";
import { b64url, SIGN_PARAMS, verifyBytes } from "./identity";
import type { LedgerEntry } from "./types";

export interface Checkpoint {
  v: 1;
  /** Domain separation: a checkpoint signature can never pass as an operator intent or login. */
  purpose: "firmament-checkpoint";
  nodeId: string;
  keyId: string;
  scenario: number;
  /** Last journal record applied. */
  record: number;
  /** Ledger length; the head is the hash of entry length-1 (GENESIS when empty). */
  length: number;
  head: string;
  signedAt: string;
  /** Phase 8: the signer's election term when it signed (absent = 0). */
  term?: number;
  /** Phase 8: the election term of journal record `record` (absent = 0). */
  recordTerm?: number;
}

export const termOf = (cp: Checkpoint) => cp.term ?? 0;
export const recordTermOf = (cp: Checkpoint) => cp.recordTerm ?? 0;

export interface SignedCheckpoint {
  cp: Checkpoint;
  sig: string;
}

export const checkpointBytes = (cp: Checkpoint) => new TextEncoder().encode(canonical(cp));

export function isSignedCheckpoint(x: unknown): x is SignedCheckpoint {
  if (!x || typeof x !== "object") return false;
  const { cp, sig } = x as SignedCheckpoint;
  return (
    typeof sig === "string" &&
    !!cp &&
    cp.v === 1 &&
    cp.purpose === "firmament-checkpoint" &&
    typeof cp.nodeId === "string" &&
    typeof cp.keyId === "string" &&
    Number.isInteger(cp.scenario) &&
    Number.isInteger(cp.record) &&
    Number.isInteger(cp.length) &&
    cp.length >= 0 &&
    typeof cp.head === "string" &&
    /^[0-9a-f]{64}$/.test(cp.head) &&
    !Number.isNaN(Date.parse(cp.signedAt)) &&
    (cp.term === undefined || (Number.isInteger(cp.term) && cp.term >= 0)) &&
    (cp.recordTerm === undefined || (Number.isInteger(cp.recordTerm) && cp.recordTerm >= 0))
  );
}

export async function signCheckpoint(cp: Checkpoint, privateKey: CryptoKey, subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<SignedCheckpoint> {
  return { cp, sig: b64url(await subtle.sign(SIGN_PARAMS, privateKey, checkpointBytes(cp))) };
}

export const verifyCheckpoint = (sc: SignedCheckpoint, jwk: JsonWebKey, subtle: SubtleCrypto = globalThis.crypto.subtle) =>
  verifyBytes(checkpointBytes(sc.cp), sc.sig, jwk, subtle);

export const headAt = (ledger: LedgerEntry[], length: number) => (length === 0 ? GENESIS : ledger[length - 1]?.hash);

export type Agreement = "agrees" | "disagrees" | "ahead" | "other-scenario";

/** How a checkpoint relates to the ledger we hold for `scenario`. */
export function compare(cp: Checkpoint, scenario: number, ledger: LedgerEntry[]): Agreement {
  if (cp.scenario !== scenario) return "other-scenario";
  if (cp.length > ledger.length) return "ahead";
  return headAt(ledger, cp.length) === cp.head ? "agrees" : "disagrees";
}

/** A point in the ledger: its length, the journal record that produced it, and that record's term. */
export interface LedgerPoint {
  length: number;
  record: number;
  recordTerm: number;
}

/**
 * The longest prefix that at least `quorum` nodes have signed, as a point. `own` is this node's
 * point, which agrees with itself by definition. Peers count with their latest agreeing
 * checkpoint; a peer that disagrees or is ahead counts for nothing.
 *
 * With `currentTerm` (Phase 8, automatic failover), the Raft commit rule applies: a point
 * seals only if its record is from the current term. An entry from an earlier term that
 * happens to be on a majority can still be replaced by a later leader, so it is sealed only
 * once a current-term record after it is. Returns undefined when nothing new is sealed.
 */
export function sealPoint(ledger: LedgerEntry[], scenario: number, own: LedgerPoint, peers: Iterable<SignedCheckpoint>, quorum: number, currentTerm?: number): LedgerPoint | undefined {
  const points: LedgerPoint[] = [own];
  for (const p of peers) if (compare(p.cp, scenario, ledger) === "agrees") points.push({ length: p.cp.length, record: p.cp.record, recordTerm: recordTermOf(p.cp) });
  points.sort((a, b) => b.length - a.length || b.record - a.record);
  const pt = points[quorum - 1];
  if (!pt) return undefined;
  if (currentTerm !== undefined && pt.recordTerm !== currentTerm) return undefined;
  return pt;
}

/** sealPoint's length (0 when nothing is sealed), without the term rule unless given. */
export function sealedLength(ledger: LedgerEntry[], scenario: number, own: number, peers: Iterable<SignedCheckpoint>, quorum: number, currentTerm?: number, ownRecordTerm = currentTerm ?? 0): number {
  return sealPoint(ledger, scenario, { length: own, record: Number.MAX_SAFE_INTEGER, recordTerm: ownRecordTerm }, peers, quorum, currentTerm)?.length ?? 0;
}

export const majority = (nodes: number) => Math.floor(nodes / 2) + 1;

export interface Equivocation {
  nodeId: string;
  scenario: number;
  length: number;
  a: SignedCheckpoint;
  b: SignedCheckpoint;
}

/** Pairs of checkpoints in which one node signed two different heads for the same length. */
export function findEquivocations(cps: Iterable<SignedCheckpoint>): Equivocation[] {
  const first = new Map<string, SignedCheckpoint>();
  const found: Equivocation[] = [];
  const reported = new Set<string>();
  for (const sc of cps) {
    // Within one election term. A node that rejoins after a failover drops its unsealed tail
    // and re-signs those lengths in a later term; that is not equivocation.
    const k = `${sc.cp.nodeId}|${sc.cp.scenario}|${sc.cp.length}|${termOf(sc.cp)}`;
    const prev = first.get(k);
    if (!prev) first.set(k, sc);
    else if (prev.cp.head !== sc.cp.head && !reported.has(k)) {
      reported.add(k);
      found.push({ nodeId: sc.cp.nodeId, scenario: sc.cp.scenario, length: sc.cp.length, a: prev, b: sc });
    }
  }
  return found;
}

/** What a console shows about replication. */
export interface ReplicationStatus {
  nodeId: string;
  nodes: number;
  quorum: number;
  /** Ledger length signed by a quorum of nodes. */
  sealed: number;
  /** False when the current scenario predates replication (its journal start is gone). */
  replicable: boolean;
  /** Phase 8 automatic failover: election term, the leader, and whether it holds a quorum lease. */
  failover?: { term: number; leader?: string; leaderUrl?: string; role: "leader" | "follower" | "candidate"; lease: boolean };
  peers: Array<{
    nodeId: string;
    state: "agrees" | "disagrees" | "ahead" | "never" | "silent" | "alarm";
    length: number;
    lastSeen?: string;
    detail?: string;
  }>;
  alarms: Array<{ at: string; node: string; kind: string; message: string }>;
}

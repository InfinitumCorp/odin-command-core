// Node identity for the replicated Firmament.
//
// Every ODIN° node (the leader and each replica) has its own ECDSA P-256 key, separate from
// operator keys. It signs the node's checkpoints and authenticates node-to-node requests.
//
//   .odin/node.json    this node's id and key pair (private, mode 0600)
//   .odin/peers.json   the other nodes: id, public key, and URL for those it talks to
//
// Peers are configured by an administrator (`npm run firmament -- add-peer ...`). There is no
// discovery and no trust-on-first-use for nodes: a node only accepts requests and checkpoints
// from keys listed in its peers file.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { canonical } from "../core/ledger";
import { b64url, isPublicP256Jwk, keyIdFor, SIGN_ALG, SIGN_PARAMS, verifyBytes } from "../core/identity";
import { signCheckpoint, type Checkpoint, type SignedCheckpoint } from "../core/checkpoint";

export const DEFAULT_NODE_KEY = ".odin/node.json";
export const DEFAULT_PEERS = ".odin/peers.json";
const NODE_ID_RE = /^[a-z][a-z0-9-]{1,31}$/;
/** Requests older or newer than this are refused (clock skew allowance). */
export const REQUEST_WINDOW_MS = 60_000;

export interface NodeIdentity {
  nodeId: string;
  keyId: string;
  publicKeyJwk: JsonWebKey;
  privateKey: CryptoKey;
}

export interface Peer {
  nodeId: string;
  publicKeyJwk: JsonWebKey;
  /** Base URL (e.g. https://odin-2:8317). Required for the leader and for gossip partners. */
  url?: string;
  leader?: boolean;
}

interface NodeFile {
  version: 1;
  nodeId: string;
  privateJwk: JsonWebKey;
  publicJwk: JsonWebKey;
}

function writePrivate(path: string, data: unknown) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
  renameSync(tmp, path);
}

export function validNodeId(id: string) {
  return NODE_ID_RE.test(id);
}

/** Create the node key file. Refuses to overwrite: a node's key is its identity. */
export async function initNode(path = process.env.ODIN_NODE_KEY ?? DEFAULT_NODE_KEY, nodeId?: string): Promise<NodeIdentity> {
  if (existsSync(path)) throw new Error(`${path} already exists; a node keeps its key for life`);
  const id = nodeId ?? `node-${b64url(crypto.getRandomValues(new Uint8Array(4))).toLowerCase().replace(/[^a-z0-9]/g, "x")}`;
  if (!validNodeId(id)) throw new Error("node id: lower-case letter, then 1-31 of a-z 0-9 -");
  const pair = (await crypto.subtle.generateKey(SIGN_ALG, true, ["sign", "verify"])) as CryptoKeyPair;
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const pub = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const publicJwk = { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y };
  writePrivate(path, { version: 1, nodeId: id, privateJwk, publicJwk } satisfies NodeFile);
  return loadNode(path);
}

export async function loadNode(path = process.env.ODIN_NODE_KEY ?? DEFAULT_NODE_KEY): Promise<NodeIdentity> {
  const f = JSON.parse(readFileSync(path, "utf8")) as NodeFile;
  if (f.version !== 1 || !validNodeId(f.nodeId) || !isPublicP256Jwk(f.publicJwk)) throw new Error(`unrecognised node key file ${path}`);
  const privateKey = await crypto.subtle.importKey("jwk", f.privateJwk, SIGN_ALG, false, ["sign"]);
  return { nodeId: f.nodeId, keyId: await keyIdFor(f.publicJwk), publicKeyJwk: f.publicJwk, privateKey };
}

export function loadPeers(path = process.env.ODIN_PEERS ?? DEFAULT_PEERS): Peer[] {
  if (!existsSync(path)) return [];
  const f = JSON.parse(readFileSync(path, "utf8")) as { version: 1; peers: Peer[] };
  if (f.version !== 1 || !Array.isArray(f.peers)) throw new Error(`unrecognised peers file ${path}`);
  for (const p of f.peers) if (!validNodeId(p.nodeId) || !isPublicP256Jwk(p.publicKeyJwk)) throw new Error(`bad peer entry in ${path}`);
  return f.peers;
}

export function savePeers(peers: Peer[], path = process.env.ODIN_PEERS ?? DEFAULT_PEERS) {
  writePrivate(path, { version: 1, peers });
}

export function nodeCheckpoint(node: NodeIdentity, fields: Pick<Checkpoint, "scenario" | "record" | "length" | "head"> & Partial<Pick<Checkpoint, "term" | "recordTerm">>): Promise<SignedCheckpoint> {
  const { term, recordTerm, ...rest } = fields;
  const cp: Checkpoint = { v: 1, purpose: "firmament-checkpoint", nodeId: node.nodeId, keyId: node.keyId, ...rest, signedAt: new Date().toISOString() };
  // Terms are signed only once elections are in use, so Phase 6 checkpoints stay byte-identical.
  if (term) cp.term = term;
  if (recordTerm) cp.recordTerm = recordTerm;
  return signCheckpoint(cp, node.privateKey);
}

// ---------------------------------------------------------------------------
// Node-to-node request authentication
//
// Each request carries the sending node's id, a timestamp, and a signature over
// {purpose, method, path (with query), time, sha256(body)}. The receiver checks the node is a
// configured peer, the time is within REQUEST_WINDOW_MS, and the signature verifies.

const bodyHash = (body: string) => createHash("sha256").update(body).digest("hex");
const requestBytes = (method: string, path: string, time: string, body: string) =>
  new TextEncoder().encode(canonical({ purpose: "odin-node-request", method: method.toUpperCase(), path, time, body: bodyHash(body) }));

export async function signRequest(node: NodeIdentity, method: string, path: string, body = ""): Promise<Record<string, string>> {
  const time = new Date().toISOString();
  const sig = b64url(await crypto.subtle.sign(SIGN_PARAMS, node.privateKey, requestBytes(method, path, time, body)));
  return { "x-odin-node": node.nodeId, "x-odin-time": time, "x-odin-sig": sig };
}

export async function verifyRequest(
  peers: Peer[],
  headers: Record<string, string | string[] | undefined>,
  method: string,
  path: string,
  body = "",
  now = Date.now(),
): Promise<Peer | undefined> {
  const h = (k: string) => (typeof headers[k] === "string" ? (headers[k] as string) : undefined);
  const nodeId = h("x-odin-node");
  const time = h("x-odin-time");
  const sig = h("x-odin-sig");
  if (!nodeId || !time || !sig) return undefined;
  const peer = peers.find((p) => p.nodeId === nodeId);
  const at = Date.parse(time);
  if (!peer || Number.isNaN(at) || Math.abs(now - at) > REQUEST_WINDOW_MS) return undefined;
  return (await verifyBytes(requestBytes(method, path, time, body), sig, peer.publicKeyJwk)) ? peer : undefined;
}

/** Signed JSON requests to another node. */
export interface Transport {
  get<T>(peer: Peer, path: string): Promise<{ status: number; body: T }>;
  post<T>(peer: Peer, path: string, data: unknown): Promise<{ status: number; body: T }>;
}

export function httpTransport(node: NodeIdentity, timeoutMs = 10_000): Transport {
  const call = async <T>(peer: Peer, method: string, path: string, data?: unknown) => {
    if (!peer.url) throw new Error(`no URL configured for ${peer.nodeId}`);
    const body = data === undefined ? "" : JSON.stringify(data);
    const headers: Record<string, string> = { ...(await signRequest(node, method, path, body)) };
    if (body) headers["content-type"] = "application/json";
    const res = await fetch(new URL(path, peer.url), { method, headers, body: body || undefined, signal: AbortSignal.timeout(timeoutMs) });
    return { status: res.status, body: (await res.json().catch(() => ({}))) as T };
  };
  return { get: (p, path) => call(p, "GET", path), post: (p, path, d) => call(p, "POST", path, d) };
}

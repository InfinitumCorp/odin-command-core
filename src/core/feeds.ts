// Live feed boundary. Every external source (CoT from ATAK/TAK, a JSON gateway for
// [HRVST] or the ÆTHER mesh, a sensor bridge) is normalised to ExternalReport by an
// adapter, then validated and ingested here. Nothing from outside skips this gate.

import { canonical, append } from "./ledger";
import { sha256 } from "./sha256";
import { ingest } from "./orient";
import { clamp, nextId } from "./util";
import type { Affiliation, Observation, ObservationKind, Pos, State } from "./types";

/** Operating area: a square of `sizeKm` whose south-west corner is at (originLat, originLon). */
export interface AreaOfOperations {
  name: string;
  originLat: number;
  originLon: number;
  sizeKm: number;
}

export const DEFAULT_AO: AreaOfOperations = { name: "Exercise AO", originLat: 38.5, originLon: -77.6, sizeKm: 100 };

const KM_PER_DEG_LAT = 110.574;
const kmPerDegLon = (lat: number) => 111.32 * Math.cos((lat * Math.PI) / 180);

/** Local equirectangular projection. Accurate to well under 1% across a 100 km area. */
export function project(ao: AreaOfOperations, lat: number, lon: number): Pos {
  const midLat = ao.originLat + ao.sizeKm / KM_PER_DEG_LAT / 2;
  return {
    x: ((lon - ao.originLon) * kmPerDegLon(midLat) * 100) / ao.sizeKm,
    y: ((lat - ao.originLat) * KM_PER_DEG_LAT * 100) / ao.sizeKm,
  };
}

export function unproject(ao: AreaOfOperations, p: Pos): { lat: number; lon: number } {
  const midLat = ao.originLat + ao.sizeKm / KM_PER_DEG_LAT / 2;
  return {
    lat: ao.originLat + (p.y * ao.sizeKm) / 100 / KM_PER_DEG_LAT,
    lon: ao.originLon + (p.x * ao.sizeKm) / 100 / kmPerDegLon(midLat),
  };
}

export type ExternalKind = ObservationKind | "position";

/** The one shape every adapter produces. */
export interface ExternalReport {
  source: string; // adapter + feed, e.g. "cot:udp" or "json:hrvst-gateway"
  kind: ExternalKind;
  lat: number;
  lon: number;
  detail: string;
  sourceRef?: string; // upstream identifier, e.g. a CoT uid
  callsign?: string; // for "position": which own asset this is
  confidence?: number; // 0..1; defaults per kind
  affiliation?: Affiliation;
  time?: string; // ISO-8601 time the source observed it
}

const KINDS: ExternalKind[] = ["contact", "field-report", "comms-degraded", "resupply-request", "casevac-request", "position"];
const AFFILIATIONS: Affiliation[] = ["friendly", "neutral", "unknown"];
const DEFAULT_CONFIDENCE: Record<ExternalKind, number> = {
  contact: 0.45,
  "field-report": 0.6,
  "comms-degraded": 0.9,
  "resupply-request": 0.95,
  "casevac-request": 0.95,
  position: 1,
};
const MAX_DETAIL = 280;

export type Checked = { ok: true; report: ExternalReport } | { ok: false; reason: string };

const isStr = (v: unknown, max = 200): v is string => typeof v === "string" && v.length > 0 && v.length <= max;

/** Validate one untrusted report. Never throws. */
export function checkReport(raw: unknown): Checked {
  if (!raw || typeof raw !== "object") return { ok: false, reason: "not an object" };
  const r = raw as Record<string, unknown>;
  if (!isStr(r.source, 64)) return { ok: false, reason: "missing source" };
  if (!KINDS.includes(r.kind as ExternalKind)) return { ok: false, reason: `unknown kind ${String(r.kind)}` };
  if (typeof r.lat !== "number" || !Number.isFinite(r.lat) || r.lat < -90 || r.lat > 90) return { ok: false, reason: "bad lat" };
  if (typeof r.lon !== "number" || !Number.isFinite(r.lon) || r.lon < -180 || r.lon > 180) return { ok: false, reason: "bad lon" };
  if (typeof r.detail !== "string") return { ok: false, reason: "missing detail" };
  if (r.confidence !== undefined && (typeof r.confidence !== "number" || !(r.confidence >= 0 && r.confidence <= 1))) return { ok: false, reason: "confidence outside 0..1" };
  if (r.affiliation !== undefined && !AFFILIATIONS.includes(r.affiliation as Affiliation)) return { ok: false, reason: "bad affiliation" };
  if (r.sourceRef !== undefined && !isStr(r.sourceRef)) return { ok: false, reason: "bad sourceRef" };
  if (r.callsign !== undefined && !isStr(r.callsign, 64)) return { ok: false, reason: "bad callsign" };
  if (r.time !== undefined && (typeof r.time !== "string" || Number.isNaN(Date.parse(r.time)))) return { ok: false, reason: "bad time" };
  if (r.kind === "position" && r.callsign === undefined) return { ok: false, reason: "position report without callsign" };
  return {
    ok: true,
    report: {
      source: r.source as string,
      kind: r.kind as ExternalKind,
      lat: r.lat,
      lon: r.lon,
      detail: (r.detail as string).slice(0, MAX_DETAIL),
      sourceRef: r.sourceRef as string | undefined,
      callsign: r.callsign as string | undefined,
      confidence: r.confidence as number | undefined,
      affiliation: r.affiliation as Affiliation | undefined,
      time: r.time as string | undefined,
    },
  };
}

export interface FeedStats {
  accepted: number;
  rejected: number;
  lastT: number;
  lastRejection?: string;
}

const inside = (p: Pos) => p.x >= 0 && p.x <= 100 && p.y >= 0 && p.y <= 100;

/**
 * Ingest a batch from one transport. Accepted reports become observations (or own-asset
 * position updates); rejected ones are counted with a reason. The ledger gets one entry per
 * batch with a SHA-256 digest of the raw batch, so the source data can be proven later.
 */
export function ingestBatch(s: State, via: string, raw: unknown[], adapterRejected: Array<{ reason: string }> = []) {
  let accepted = 0;
  const rejected: string[] = [];
  const touched = new Set<string>();

  const stat = (source: string) => (s.feeds[source] ??= { accepted: 0, rejected: 0, lastT: s.t });

  for (const r of adapterRejected) {
    const st = stat(via);
    st.rejected++;
    st.lastT = s.t;
    st.lastRejection = `adapter: ${String(r.reason).slice(0, 120)}`;
    rejected.push(st.lastRejection);
    touched.add(via);
  }

  for (const item of raw) {
    const c = checkReport(item);
    const source = c.ok ? c.report.source : typeof (item as { source?: unknown })?.source === "string" ? String((item as { source: string }).source).slice(0, 64) : via;
    touched.add(source);
    const st = stat(source);
    st.lastT = s.t;
    if (!c.ok) {
      st.rejected++;
      st.lastRejection = c.reason;
      rejected.push(c.reason);
      continue;
    }
    const rep = c.report;
    const pos = project(s.ao, rep.lat, rep.lon);
    if (!inside(pos)) {
      st.rejected++;
      st.lastRejection = "outside the operating area";
      rejected.push("outside the operating area");
      continue;
    }

    // A friendly report carrying one of our own callsigns is that asset reporting where it is.
    const own = rep.callsign ? s.assets.find((a) => a.callsign === rep.callsign) : undefined;
    if (rep.kind === "position" || (rep.kind === "contact" && rep.affiliation === "friendly" && own)) {
      const asset = own;
      if (!asset) {
        st.rejected++;
        st.lastRejection = `no own asset called ${rep.callsign}`;
        rejected.push(st.lastRejection);
        continue;
      }
      asset.pos = pos;
    } else {
      const o: Observation = {
        id: nextId(s, "OBS"),
        t: s.t,
        sourceId: `EXT:${rep.source}`,
        kind: rep.kind,
        pos,
        detail: rep.callsign ? `${rep.callsign}: ${rep.detail}` : rep.detail,
        confidence: clamp(rep.confidence ?? DEFAULT_CONFIDENCE[rep.kind], 0.05, 0.99),
        affiliationHint: rep.affiliation,
      };
      ingest(s, o);
    }
    st.accepted++;
    accepted++;
  }

  if (raw.length || adapterRejected.length) {
    s.ledger = append(s.ledger, s.t, `FEED:${via}`, "feed.ingested", {
      via,
      sources: [...touched].sort(),
      accepted,
      rejected: rejected.length,
      digest: sha256(canonical(raw)),
    });
  }
  return { accepted, rejected };
}

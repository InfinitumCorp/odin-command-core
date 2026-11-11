// Cursor-on-Target (CoT) adapter: the XML event format used by TAK/ATAK and many
// sensor gateways. Each <event> becomes one ExternalReport; anything that cannot be
// mapped is returned with a reason instead of being dropped silently.
//
// Mapping (CoT "type" is a dash-separated hierarchy):
//   a-f-...      friendly atom   -> friendly contact (the core turns it into a position update
//                                   when the callsign is one of ODIN's own assets)
//   a-n-...      neutral atom    -> contact, affiliation neutral
//   a-u/p/a/s-.. unknown/pending/assumed/suspect -> contact, affiliation unknown
//   a-h/j/k-...  hostile/joker/faker -> contact, affiliation unknown, noted as "reported hostile"
//                (ODIN° Phase 2 does not model hostile tracks; a commander sees the note)
//   b-r-f-h-c    medevac request -> casevac-request
//   anything else                -> rejected

import type { ExternalReport } from "../core/feeds";

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
const decode = (s: string) =>
  s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (_, e: string) =>
    e[0] === "#" ? String.fromCodePoint(e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)) : ENTITIES[e.toLowerCase()],
  );

function attrs(tag: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of tag.matchAll(/([\w:.-]+)\s*=\s*("([^"]*)"|'([^']*)')/g)) out[m[1]] = decode(m[3] ?? m[4] ?? "");
  return out;
}

const firstTag = (xml: string, name: string) => xml.match(new RegExp(`<${name}\\b[^>]*?/?>`, "i"))?.[0];

/** Confidence from CoT circular error (metres). 9999999 means "unknown" in CoT. */
function confidenceFromCe(ce: number, selfReported: boolean): number {
  if (selfReported) return 0.85; // a friendly unit reporting its own GPS position
  if (!Number.isFinite(ce) || ce >= 9_999_999) return 0.35;
  if (ce <= 10) return 0.7;
  if (ce <= 100) return 0.55;
  if (ce <= 1000) return 0.45;
  return 0.35;
}

export type CotResult = { ok: true; report: ExternalReport } | { ok: false; reason: string; uid?: string };

export function parseCotEvent(eventXml: string, source: string): CotResult {
  const evTag = firstTag(eventXml, "event");
  if (!evTag) return { ok: false, reason: "no <event>" };
  const ev = attrs(evTag);
  const uid = ev.uid;
  const type = ev.type ?? "";
  const pt = firstTag(eventXml, "point");
  if (!pt) return { ok: false, reason: "no <point>", uid };
  const p = attrs(pt);
  const lat = Number(p.lat);
  const lon = Number(p.lon);
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return { ok: false, reason: "bad point", uid };

  const contact = firstTag(eventXml, "contact");
  const callsign = contact ? attrs(contact).callsign : undefined;
  const remarks = eventXml.match(/<remarks\b[^>]*>([\s\S]*?)<\/remarks>/i)?.[1];
  const note = remarks ? decode(remarks).trim() : "";
  const time = ev.time && !Number.isNaN(Date.parse(ev.time)) ? ev.time : undefined;
  const base = { source, sourceRef: uid, lat, lon, time };
  const ce = Number(p.ce);

  if (type === "b-r-f-h-c") {
    return { ok: true, report: { ...base, kind: "casevac-request", callsign, detail: note || "MEDEVAC request" } };
  }
  const m = /^a-([fnuhpajks])-/.exec(type + "-");
  if (!m) return { ok: false, reason: `unsupported CoT type ${type || "(none)"}`, uid };

  const aff = m[1];
  const selfReported = aff === "f" && (ev.how ?? "").startsWith("m-");
  const affiliation = aff === "f" ? "friendly" : aff === "n" ? "neutral" : "unknown";
  const hostileNote = "hjk".includes(aff) ? "reported hostile by source" : "";
  const detail = [callsign ? "" : `CoT ${type}`, hostileNote, note].filter(Boolean).join(" · ") || `CoT ${type} report`;
  return {
    ok: true,
    report: { ...base, kind: "contact", callsign, affiliation, confidence: confidenceFromCe(ce, selfReported), detail },
  };
}

/** Split a stream or document that may hold several <event> elements. */
export function splitEvents(xml: string): string[] {
  // Events always carry a <point/> child, so a self-closing <event/> is never valid.
  return xml.match(/<event\b[\s\S]*?<\/event>/gi) ?? [];
}

export function parseCot(xml: string, source: string) {
  const reports: ExternalReport[] = [];
  const rejected: Array<{ reason: string; uid?: string }> = [];
  for (const ev of splitEvents(xml)) {
    const r = parseCotEvent(ev, source);
    if (r.ok) reports.push(r.report);
    else rejected.push({ reason: r.reason, uid: r.uid });
  }
  return { reports, rejected };
}

// ORIENT: fuse raw observations into tracks (METATRON¹⁰⁰ common operating picture)
// and raise decision points for anything that needs a commander.

import type { DecisionKind, DecisionPoint, Observation, State, Track } from "./types";
import { dist, fmtPos, nextId } from "./util";
import { draftCoas } from "./decide";
import { append } from "./ledger";

/** Reports closer than this to an existing track are treated as the same object. */
export const CORRELATION_KM = 4;
/** An unknown track at or above this confidence becomes a decision point. */
export const DECISION_CONFIDENCE = 0.55;

/** Independent sightings combine: 1 - (1-a)(1-b). */
export const fuse = (a: number, b: number) => 1 - (1 - a) * (1 - b);

/** `trackId` binds a report to a known track, e.g. a close look tasked against that track. */
export function correlate(s: State, o: Observation, trackId?: string): Track {
  const near =
    (trackId && s.tracks.find((t) => t.id === trackId)) ||
    s.tracks
      .filter((t) => dist(t.pos, o.pos) <= CORRELATION_KM)
      .sort((a, b) => dist(a.pos, o.pos) - dist(b.pos, o.pos))[0];

  if (near) {
    const w = o.confidence / (near.confidence + o.confidence);
    near.pos = { x: near.pos.x + (o.pos.x - near.pos.x) * w, y: near.pos.y + (o.pos.y - near.pos.y) * w };
    near.confidence = fuse(near.confidence, o.confidence);
    near.observationIds.push(o.id);
    near.lastSeen = o.t;
    // Only a close, high-confidence look may settle what a track is.
    if (o.affiliationHint && o.affiliationHint !== "unknown" && o.confidence >= 0.8) near.affiliation = o.affiliationHint;
    return near;
  }

  const track: Track = {
    id: nextId(s, "TRK"),
    label: `Contact ${fmtPos(o.pos)}`,
    pos: { ...o.pos },
    affiliation: o.affiliationHint && o.confidence >= 0.8 ? o.affiliationHint : "unknown",
    confidence: o.confidence,
    observationIds: [o.id],
    firstSeen: o.t,
    lastSeen: o.t,
  };
  s.tracks.push(track);
  return track;
}

function raise(s: State, kind: DecisionKind, summary: string, o: Observation, trackId?: string) {
  const dp: DecisionPoint = {
    id: nextId(s, "DP"),
    t: s.t,
    kind,
    summary,
    pos: { ...o.pos },
    triggerId: o.id,
    trackId,
    status: "open",
    coas: [],
    drafter: { source: "rules" },
  };
  dp.coas = draftCoas(s, dp);
  s.decisions.push(dp);
  s.ledger = append(s.ledger, s.t, "SCALVS.ai", "decision-point.raised", {
    decision: dp.id,
    kind,
    summary,
    trigger: o.id,
    source: o.sourceId,
    coas: dp.coas.map((c) => ({ id: c.id, title: c.title })),
  });
}

/** Ingest one observation: store it, fuse it, and raise a decision point if one is warranted. */
export function ingest(s: State, o: Observation, trackId?: string) {
  s.observations.push(o);
  switch (o.kind) {
    case "contact":
    case "field-report": {
      const track = correlate(s, o, trackId);
      const alreadyOpen = s.decisions.some((d) => d.trackId === track.id && d.status === "open");
      const beingWorked = s.tasks.some((t) => t.trackId === track.id && (t.status === "underway" || t.status === "on-station"));
      const settled = track.affiliation !== "unknown";
      if (!settled && !alreadyOpen && !beingWorked && track.confidence >= DECISION_CONFIDENCE) {
        const everDecided = s.decisions.some((d) => d.trackId === track.id);
        if (!everDecided) {
          raise(s, "unknown-contact", `Unidentified contact at ${fmtPos(track.pos)} (${Math.round(track.confidence * 100)}% confidence)`, o, track.id);
        }
      }
      return;
    }
    case "resupply-request":
      raise(s, "resupply", o.detail, o);
      return;
    case "casevac-request":
      raise(s, "casevac", o.detail, o);
      return;
    case "comms-degraded":
      raise(s, "comms", o.detail, o);
      return;
  }
}

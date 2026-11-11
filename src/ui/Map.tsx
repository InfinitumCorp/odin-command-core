// METATRON¹⁰⁰ common operating picture: one map with assets, tracks, tasks and open decisions.

import type { Asset, Pos, State, Track } from "../core/types";

/** Grid y grows northward; SVG y grows downward. Flip once here so north is up. */
const V = (p: Pos): Pos => ({ x: p.x, y: 100 - p.y });

const AFF_CLASS: Record<Track["affiliation"], string> = { friendly: "aff-friendly", neutral: "aff-neutral", unknown: "aff-unknown" };

function TrackGlyph({ t, selected }: { t: Track; selected: boolean }) {
  const r = 1.6;
  const { x, y } = V(t.pos);
  const cls = `track ${AFF_CLASS[t.affiliation]}${selected ? " selected" : ""}`;
  const shape =
    t.affiliation === "unknown" ? (
      <path d={`M${x} ${y - r * 1.3} L${x + r * 1.3} ${y} L${x} ${y + r * 1.3} L${x - r * 1.3} ${y} Z`} className={cls} />
    ) : t.affiliation === "neutral" ? (
      <rect x={x - r} y={y - r} width={r * 2} height={r * 2} className={cls} />
    ) : (
      <circle cx={x} cy={y} r={r} className={cls} />
    );
  return (
    <g opacity={0.45 + t.confidence * 0.55}>
      {shape}
      <title>{`${t.id} · ${t.affiliation} · ${Math.round(t.confidence * 100)}%`}</title>
    </g>
  );
}

function AssetGlyph({ a }: { a: Asset }) {
  const { x, y } = V(a.pos);
  return (
    <g className={`asset asset-${a.status}`}>
      {a.kind === "ARGUS" ? (
        <>
          <circle cx={x} cy={y} r={22} className="argus-range" />
          <path d={`M${x} ${y - 1.4} L${x + 1.3} ${y + 1} L${x - 1.3} ${y + 1} Z`} />
        </>
      ) : (
        <rect x={x - 1.1} y={y - 0.8} width={2.2} height={1.6} rx={0.3} />
      )}
      <text x={x + 1.8} y={y + 0.6}>{a.callsign}</text>
    </g>
  );
}

export function OperatingPicture({ state, selectedDecision, onSelectDecision }: {
  state: State;
  selectedDecision?: string;
  onSelectDecision: (id: string) => void;
}) {
  const sel = state.decisions.find((d) => d.id === selectedDecision);
  const grid = Array.from({ length: 11 }, (_, i) => i * 10);
  return (
    <svg className="cop" viewBox="-2 -2 104 104" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Common operating picture">
      <rect x={0} y={0} width={100} height={100} className="cop-bg" />
      {grid.map((g) => (
        <g key={g} className="gridlines">
          <line x1={g} y1={0} x2={g} y2={100} />
          <line x1={0} y1={g} x2={100} y2={g} />
        </g>
      ))}
      {state.tasks
        .filter((t) => t.status === "underway" || t.status === "on-station")
        .map((t) => {
          const a = state.assets.find((x) => x.id === t.assetId)!;
          const from = V(a.pos);
          const to = V(t.target);
          return <line key={t.id} x1={from.x} y1={from.y} x2={to.x} y2={to.y} className={`task-line verb-${t.verb}`} />;
        })}
      {state.tracks.map((t) => (
        <TrackGlyph key={t.id} t={t} selected={!!sel && sel.trackId === t.id} />
      ))}
      {state.assets.map((a) => (
        <AssetGlyph key={a.id} a={a} />
      ))}
      {state.decisions
        .filter((d) => d.status === "open")
        .map((d) => (
          <g key={d.id} className={`dp-marker${d.id === selectedDecision ? " selected" : ""}`} onClick={() => onSelectDecision(d.id)}>
            <circle cx={V(d.pos).x} cy={V(d.pos).y} r={3.2} />
            <text x={V(d.pos).x} y={V(d.pos).y - 4}>{d.id}</text>
          </g>
        ))}
    </svg>
  );
}

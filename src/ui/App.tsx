import { useEffect, useMemo, useRef, useState } from "react";
import { CLOCK_SPEEDS, type Command } from "../core/engine";
import { append, verify } from "../core/ledger";
import { auditSignatures, b64url, HUMAN_ACTIONS, type AuditResult, type RegistryOperator, type SignedAction, type SignedIntent } from "../core/identity";
import type { DecisionPoint, LedgerEntry, State } from "../core/types";
import type { DraftStatus } from "../core/view";
import { fmtPos, fmtTime } from "../core/util";
import { OperatingPicture } from "./Map";
import { fetchRegistry, signAction } from "./auth/client";
import type { Session } from "./auth/Login";
import { useOdin } from "./useOdin";

const SOURCE: Record<string, string> = {};

export function App({ session, onSignOut }: { session: Session; onSignOut: () => void }) {
  const { me, signer } = session;
  const odin = useOdin(onSignOut);
  const [selected, setSelected] = useState<string>();
  const [notice, setNotice] = useState<{ kind: "error" | "info"; text: string }>();
  /** Tamper/forge demos run on a local copy of the ledger; the server's ledger is untouched. */
  const [demo, setDemo] = useState<LedgerEntry[]>();
  const shownLedger = demo ?? odin.ledger;

  // A State-shaped object for the panels. Ground truth never reaches the browser.
  const state: State | undefined = useMemo(
    () => odin.view && { ...odin.view, ledger: odin.ledger, truth: [], rng: 0, operator: { id: me.id, role: me.role, keyId: me.keyId } },
    [odin.view, odin.ledger, me],
  );
  const stateRef = useRef(state);
  stateRef.current = state;

  /** Sign with this operator's device key against the ledger head we have verified, then send. */
  const signed = async (action: SignedAction, subject: Record<string, string | number | boolean>, make: (auth: SignedIntent) => Command) => {
    const s = stateRef.current;
    if (!s) return "not connected";
    try {
      if (signer.kind === "webauthn") setNotice({ kind: "info", text: `Touch your security key to sign ${action}…` });
      const error = await odin.send(make(await signAction(me, signer, s, action, subject)));
      setNotice(error ? { kind: "error", text: error } : undefined);
      return error;
    } catch (e) {
      const text = `Could not sign: ${e instanceof Error ? e.message : e}`;
      setNotice({ kind: "error", text });
      return text;
    }
  };

  // Record this console's sign-in on the shared ledger, once, after the first view arrives.
  const signedIn = useRef(false);
  useEffect(() => {
    if (!state || signedIn.current) return;
    signedIn.current = true;
    void signed("operator.signed-in", {}, (auth) => ({ type: "set-operator", operator: { id: me.id, role: me.role, keyId: me.keyId }, auth }));
  }, [state]);

  // Registry (public keys and roles): this browser audits every signature itself.
  const [registry, setRegistry] = useState<RegistryOperator[]>();
  useEffect(() => {
    const load = () => fetchRegistry().then(setRegistry, (e) => setNotice({ kind: "error", text: `Registry unavailable: ${e.message}` }));
    void load();
    const h = setInterval(load, 30_000);
    return () => clearInterval(h);
  }, []);
  const ledgerCheck = useMemo(() => verify(shownLedger), [shownLedger]);
  const [audit, setAudit] = useState<AuditResult>();
  useEffect(() => {
    if (!registry) return;
    let live = true;
    auditSignatures(shownLedger, registry).then((a) => live && setAudit(a));
    return () => void (live = false);
  }, [shownLedger, registry]);
  const problemAt = useMemo(() => new Map(audit?.problems.map((p) => [p.seq, p.reason])), [audit]);
  const humanActions = useMemo(() => new Set(HUMAN_ACTIONS), []);

  if (!state || !odin.view) {
    return (
      <div className="login-shell">
        <p className="dim">{odin.link.kind === "lost" ? `Connection lost: ${odin.link.reason}` : "Connecting to ODIN° server…"}</p>
      </div>
    );
  }
  const view = odin.view;
  const repl = view.replication;
  const sealed = repl && !demo ? repl.sealed : 0;
  const fo = repl?.failover;
  const following = fo && fo.role !== "leader";
  const isCommander = me.role === "commander";
  const open = state.decisions.filter((d) => d.status === "open");
  const current = state.decisions.find((d) => d.id === selected) ?? open[0];
  const feedNames = Object.keys(state.feeds).sort();
  for (const a of state.assets) SOURCE[a.id] = a.callsign;

  const tamper = () => {
    if (odin.ledger.length < 3) return;
    const i = Math.max(1, Math.floor(odin.ledger.length / 2));
    setDemo(odin.ledger.map((e, j) => (j === i ? { ...e, actor: "UNKNOWN", payload: { ...e.payload, altered: true } } : e)));
    setNotice({ kind: "info", text: `Demo on this console's copy: entry #${i} was edited. Verification should now fail at #${i}. The server's ledger is unchanged.` });
  };

  /**
   * Demo: append a forged commander approval to a local copy and re-chain it properly, as
   * someone holding a copy of the ledger could. Hash verification passes; the signature audit does not.
   */
  const forge = () => {
    const cdr = registry?.find((o) => o.role === "commander" && o.keys.some((k) => !k.revokedAt));
    const real = [...odin.ledger].reverse().find((e) => e.action === "coa.approved" && e.payload.auth)?.payload.auth as SignedIntent | undefined;
    const forgedFor = { decision: "DP-FORGED", coa: "DP-FORGED-A" };
    const auth: SignedIntent = real ?? {
      intent: { v: 1, operatorId: cdr?.id ?? "CDR-1", keyId: cdr?.keys[0].keyId ?? "unknown", action: "coa.approved", subject: forgedFor, head: odin.ledger.at(-1)!.hash, signedAt: new Date().toISOString() },
      sig: b64url(crypto.getRandomValues(new Uint8Array(64))),
    };
    const ledger = append(odin.ledger, state.t, auth.intent.operatorId, "coa.approved", { ...forgedFor, auth });
    setDemo(ledger);
    setNotice({ kind: "info", text: `Demo on this console's copy: forged a ${real ? "replayed" : "fabricated"} approval by ${auth.intent.operatorId} as #${ledger.length - 1} and re-chained the hashes. Hash check passes; the signature audit should flag it.` });
  };

  const setClock = (running: boolean, speed: number) => void signed("clock.set", { running, speed }, (auth) => ({ type: "set-clock", running, speed, auth }));
  const newScenario = async () => {
    if (!confirm("Close this scenario for every console and start a new one? The current scenario is archived on the server.")) return;
    const seed = Math.floor(Math.random() * 1e6);
    const error = await signed("scenario.closed", { seed }, (auth) => ({ type: "close-scenario", seed, auth }));
    if (!error) {
      setSelected(undefined);
      setDemo(undefined);
    }
  };

  return (
    <div className="shell">
      <div className="classification">UNCLASSIFIED // EXERCISE // SIMULATED DATA ONLY</div>
      <header className="topbar">
        <div className="brand">
          ODIN<span className="deg">°</span>
          <small>Command Core · Phase 8 · scenario {view.scenario}</small>
        </div>
        <div className="ooda" aria-label="Decision cycle">
          <span>Observe</span><span>Orient</span><span>Decide</span><span>Act</span>
        </div>
        <div className="controls">
          <span className={`dot ${odin.link.kind === "live" ? "ok" : "bad"}`} title={odin.link.kind === "lost" ? odin.link.reason : "Live from the ODIN° server"} />
          <span className="clock">{fmtTime(state.t)}</span>
          <button disabled={!isCommander} title="Exercise clock (commander, signed; applies to every console)" onClick={() => setClock(!state.clock.running, state.clock.speed)}>
            {state.clock.running ? "Pause" : "Run"}
          </button>
          <div className="seg" role="group" aria-label="Simulation speed">
            {CLOCK_SPEEDS.map((v) => (
              <button key={v} disabled={!isCommander} className={v === state.clock.speed ? "on" : ""} onClick={() => setClock(state.clock.running, v)}>{v}×</button>
            ))}
          </div>
          <span className="operator" title={`Signing key ${me.keyId} (${me.keyKind === "webauthn" ? "FIDO2 security key" : "browser key"})`}>
            <b>{me.id}</b> {me.name !== me.id && <span className="dim">{me.name}</span>} <span className={`tag role-${me.role}`}>{me.role}</span>{" "}
            <span className={`tag key-${me.keyKind}`}>{me.keyKind === "webauthn" ? "🔑 security key" : "browser key"}</span>
          </span>
          <button onClick={onSignOut}>Sign out</button>
          <label className="toggle" title="Built-in simulated sensors. Live feeds keep flowing when this is off. Commander only, signed.">
            <input type="checkbox" checked={state.simulate} disabled={!isCommander} onChange={(e) => { const enabled = e.target.checked; void signed("simulation.toggled", { enabled }, (auth) => ({ type: "set-simulation", enabled, auth })); }} /> Simulator
          </label>
          <span className={`pill ${ledgerCheck.ok ? "ok" : "bad"}`} title="Hash chain verified in this browser">
            {ledgerCheck.ok ? `Ledger verified · ${ledgerCheck.length}` : `Ledger BROKEN at #${ledgerCheck.brokenAt}`}
          </span>
          {repl && (
            <span
              className={`pill ${repl.alarms.length ? "bad" : repl.sealed > 0 ? "ok" : ""}`}
              title={`Entries signed by at least ${repl.quorum} of ${repl.nodes} Firmament nodes, each of which re-executed the journal itself.${repl.alarms.length ? `\n${repl.alarms.length} alarm(s): see the Firmament panel.` : ""}`}
            >
              {repl.alarms.length ? `Firmament ALARM · ${repl.alarms.length}` : repl.replicable ? `Sealed #${Math.max(0, repl.sealed - 1)} · ${repl.quorum}/${repl.nodes} nodes` : "Replication starts next scenario"}
            </span>
          )}
          {fo && (
            <span
              className={`pill ${fo.role === "leader" ? (fo.lease ? "ok" : "bad") : fo.leader ? "" : "bad"}`}
              title={
                fo.role === "leader"
                  ? fo.lease
                    ? "This node is the elected leader and a majority of nodes reached it recently: commands are accepted."
                    : "This node leads, but cannot reach a majority: commands wait until it can, or another node is elected."
                  : fo.leader
                    ? `This node follows ${fo.leader}. Commands are accepted only by the leader.`
                    : "No leader right now: an election is under way."
              }
            >
              Term {fo.term} · {fo.role === "leader" ? (fo.lease ? "leader" : "leader, no quorum") : fo.leader ? `follows ${fo.leader}` : fo.role === "candidate" ? "election…" : "no leader"}
            </span>
          )}
          <span
            className={`pill ${!audit ? "" : audit.problems.length ? "bad" : "ok"}`}
            title={audit?.problems.map((p) => `#${p.seq}: ${p.reason}`).join("\n") || "Every human action is signed by a registered operator key with the required role (checked in this browser)"}
          >
            {!audit ? "Signatures: checking…" : audit.problems.length ? `Signature audit FAILED · #${audit.problems[0].seq} ${audit.problems[0].reason}` : `Signatures valid · ${audit.signed}${audit.hardware ? ` (${audit.hardware} hardware)` : ""}`}
          </span>
        </div>
      </header>

      {repl?.alarms[0] && (
        <div className="notice error" role="alert">
          FIRMAMENT ALARM ({repl.alarms[0].node}, {repl.alarms[0].kind}): {repl.alarms[0].message}. Nodes disagree about history; do not rely on unsealed entries until this is investigated.
        </div>
      )}
      {following && (
        <div className="notice info" role="status">
          This node is a follower{fo!.leader ? ` of ${fo!.leader}` : " (an election is under way)"}: its view is read-only.{" "}
          {fo!.leaderUrl ? (
            <>
              Open the leader&apos;s console at <a href={fo!.leaderUrl}>{fo!.leaderUrl}</a> to act, and sign in there.
            </>
          ) : (
            "Commands resume on whichever node is elected; sign in there."
          )}
        </div>
      )}
      {odin.rewritten && <div className="notice error" role="alert">LEDGER HISTORY CHANGED ON THE SERVER. {odin.rewritten} Treat this server as compromised until investigated.</div>}
      {demo && (
        <div className="notice info" role="status">
          Showing a locally altered copy of the ledger.
          <button className="small" onClick={() => { setDemo(undefined); setNotice(undefined); }}>Back to server copy</button>
        </div>
      )}
      {notice && (
        <div className={`notice ${notice.kind}`} role="alert">
          {notice.text}
          <button onClick={() => setNotice(undefined)} aria-label="Dismiss">×</button>
        </div>
      )}

      <main className="grid">
        <section className="panel map-panel">
          <h2>
            <span className="layer">METATRON¹⁰⁰</span> Common operating picture
            <span className="legend">
              <i className="lg aff-unknown" /> unknown <i className="lg aff-neutral" /> neutral <i className="lg aff-friendly" /> friendly <i className="lg own" /> own asset
            </span>
          </h2>
          <OperatingPicture state={state} selectedDecision={current?.id} onSelectDecision={setSelected} />
        </section>

        <section className="panel decide-panel">
          <h2><span className="layer">03 / DECIDE</span> SCALVS.ai · {open.length} awaiting command {!view.llm && <span className="dim">· LLM drafting off</span>}</h2>
          {open.length > 1 && (
            <div className="dp-tabs">
              {open.map((d) => (
                <button key={d.id} className={d.id === current?.id ? "on" : ""} onClick={() => setSelected(d.id)}>{d.id} · {d.kind}</button>
              ))}
            </div>
          )}
          {current && current.status === "open" ? (
            <DecisionCard
              dp={current}
              canCommand={isCommander}
              state={state}
              draft={view.drafts[current.id]}
              onApprove={(coaId) => void signed("coa.approved", { decision: current.id, coa: coaId }, (auth) => ({ type: "approve", decisionId: current.id, coaId, auth }))}
              onReject={() => void signed("decision.rejected", { decision: current.id }, (auth) => ({ type: "reject", decisionId: current.id, reason: "Commander declined all options", auth }))}
              onRedraft={() => void signed("coa.redrafted", { decision: current.id }, (auth) => ({ type: "redraft", decisionId: current.id, auth }))}
            />
          ) : (
            <p className="empty">No decisions waiting. ODIN° will raise one when a report needs a commander.</p>
          )}
          <h3>Recent decisions</h3>
          <ul className="history">
            {state.decisions.filter((d) => d.status !== "open").slice(-6).reverse().map((d) => (
              <li key={d.id}>
                <b>{d.id}</b> {d.status === "approved" ? "approved" : "rejected"} by {d.decidedBy}: {d.status === "approved" ? d.coas.find((c) => c.id === d.chosenCoaId)?.title : d.summary}
              </li>
            ))}
          </ul>
        </section>

        <section className="panel">
          <h2><span className="layer">01 / OBSERVE</span> Incoming reports</h2>
          <div className="feeds">
            <div className="feeds-head">
              <span className="dot ok" />
              Live feeds into the server{view.hub.dropped > 0 && <span className="warn-inline"> · {view.hub.dropped} batches dropped (queue full)</span>}
              <span className="dim"> · AO {state.ao.name}, SW corner {state.ao.originLat}°, {state.ao.originLon}°</span>
            </div>
            {feedNames.length === 0 ? (
              <div className="dim">No live sources yet. POST to /api/feeds/json or /api/feeds/cot (see README).</div>
            ) : (
              <table className="tbl">
                <thead><tr><th>Source</th><th>Accepted</th><th>Rejected</th><th>Last</th><th>Last rejection</th></tr></thead>
                <tbody>
                  {feedNames.map((n) => {
                    const f = state.feeds[n];
                    return (
                      <tr key={n}>
                        <td>{n}</td><td>{f.accepted}</td><td className={f.rejected ? "bad-text" : ""}>{f.rejected}</td>
                        <td>{fmtTime(f.lastT)}</td><td className="dim">{f.lastRejection ?? "—"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
          <ul className="feed">
            {state.observations.slice(-40).reverse().map((o) => (
              <li key={o.id} className={`obs-${o.kind}`}>
                <time>{fmtTime(o.t)}</time> <b className={o.sourceId.startsWith("EXT:") ? "ext" : ""}>{SOURCE[o.sourceId] ?? o.sourceId}</b> {o.detail} <span className="dim">· {Math.round(o.confidence * 100)}%</span>
              </li>
            ))}
          </ul>
        </section>

        <section className="panel">
          <h2><span className="layer">02 / ORIENT</span> Tracks ({state.tracks.length})</h2>
          <table className="tbl">
            <thead><tr><th>Track</th><th>Position</th><th>Assessment</th><th>Conf.</th><th>Reports</th><th>Last</th></tr></thead>
            <tbody>
              {[...state.tracks].sort((a, b) => b.lastSeen - a.lastSeen).slice(0, 25).map((t) => (
                <tr key={t.id}>
                  <td>{t.id}</td><td>{fmtPos(t.pos)}</td>
                  <td><span className={`tag aff-${t.affiliation}`}>{t.affiliation}</span></td>
                  <td>{Math.round(t.confidence * 100)}%</td><td>{t.observationIds.length}</td><td>{fmtTime(t.lastSeen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        <section className="panel">
          <h2><span className="layer">04 / ACT</span> /CNDCTR/ tasks & assets</h2>
          <table className="tbl">
            <thead><tr><th>Asset</th><th>Status</th><th>Battery</th><th>Task</th></tr></thead>
            <tbody>
              {state.assets.map((a) => {
                const task = state.tasks.find((t) => t.id === a.taskId);
                return (
                  <tr key={a.id}>
                    <td>{a.callsign}</td>
                    <td><span className={`tag st-${a.status}`}>{a.status}</span></td>
                    <td><meter min={0} max={100} low={30} high={60} optimum={100} value={a.battery} /> {Math.round(a.battery)}%</td>
                    <td className="dim">{task ? `${task.verb} · ${task.status}${task.status === "on-station" ? ` ${task.dwell}m` : ""}` : "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>

        <section className="panel ledger-panel">
          <h2>
            <span className="layer">FOUNDATION</span> Firmament chain of custody
            <button className="small" onClick={tamper} title="Edit a past entry in this console's copy to show that verification catches it">Simulate tamper</button>
            <button className="small" onClick={forge} title="Append a forged approval with valid hashes to this console's copy to show that the signature audit catches it">Forge approval</button>
            <button className="small" disabled={!isCommander} onClick={() => void newScenario()} title="Commander, signed: archives this scenario on the server for everyone">New scenario</button>
          </h2>
          {repl && (
            <div className="replicas" aria-label="Firmament replicas">
              <span className="node self" title="This node">{repl.nodeId} · {fo ? `${fo.role}, term ${fo.term}` : "leader"} · {state.ledger.length}</span>
              {repl.peers.map((p) => (
                <span key={p.nodeId} className={`node ${p.state}`} title={[p.detail, p.lastSeen && `last checkpoint ${p.lastSeen}`].filter(Boolean).join("\n") || "no checkpoint yet"}>
                  {p.nodeId} · {PEER_LABEL[p.state]}{p.length ? ` · ${p.length}` : ""}
                </span>
              ))}
              {repl.alarms.slice(1, 4).map((a, i) => (
                <span key={i} className="node alarm" title={a.message}>{a.node}: {a.kind}</span>
              ))}
            </div>
          )}
          <ol className="ledger">
            {shownLedger.slice(-60).reverse().map((e) => (
              <li key={e.seq} className={(!ledgerCheck.ok && e.seq >= ledgerCheck.brokenAt) || problemAt.has(e.seq) ? "broken" : ""} title={problemAt.get(e.seq)}>
                <span className="seq">#{e.seq}</span> <time>{fmtTime(e.t)}</time> <b>{e.actor}</b> {e.action}
                {humanActions.has(e.action) && (problemAt.has(e.seq) ? <span className="sig bad">✗ signature</span> : e.payload.auth ? <span className="sig ok">{(e.payload.auth as SignedIntent).webauthn ? "✓ signed (hardware)" : "✓ signed"}</span> : null)}
                {e.seq < sealed && <span className="seal" title={`Sealed: signed by ${repl!.quorum} or more of ${repl!.nodes} nodes`}>◆</span>}
                <code title={`prev ${e.prev}\nhash ${e.hash}`}>{e.hash.slice(0, 10)}</code>
              </li>
            ))}
          </ol>
        </section>
      </main>
    </div>
  );
}

const PEER_LABEL: Record<string, string> = {
  agrees: "agrees",
  disagrees: "DISAGREES",
  ahead: "AHEAD",
  never: "not synced",
  silent: "silent",
  alarm: "HALTED",
};

function DrafterBadge({ dp, draft }: { dp: DecisionPoint; draft?: DraftStatus }) {
  if (draft?.kind === "pending") return <span className="drafter pending">Claude drafting… showing rule-based options</span>;
  if (dp.drafter.source === "llm") return <span className="drafter llm">Drafted by {dp.drafter.model}, validated by ODIN</span>;
  if (draft?.kind === "failed") return <span className="drafter failed" title={draft.reason}>Rule-based (LLM unavailable: {draft.reason})</span>;
  return <span className="drafter">Rule-based</span>;
}

function DecisionCard({ dp, canCommand, state, draft, onApprove, onReject, onRedraft }: {
  dp: DecisionPoint;
  canCommand: boolean;
  state: State;
  draft?: DraftStatus;
  onApprove: (coaId: string) => void;
  onReject: () => void;
  onRedraft: () => void;
}) {
  return (
    <div className="dp">
      <div className="dp-head">
        <span className={`tag kind-${dp.kind}`}>{dp.kind}</span> <b>{dp.id}</b> <time>raised {fmtTime(dp.t)}</time>
      </div>
      <p className="dp-summary">{dp.summary}</p>
      <DrafterBadge dp={dp} draft={draft} />
      {dp.drafter.dropped?.length ? (
        <details className="dropped">
          <summary>{dp.drafter.dropped.length} proposal(s) refused by validation</summary>
          <ul>{dp.drafter.dropped.map((d, i) => <li key={i}>{d}</li>)}</ul>
        </details>
      ) : null}
      {!canCommand && <p className="warn">Analyst view: you can review options; approval requires a commander.</p>}
      <ol className="coas">
        {dp.coas.map((c, i) => (
          <li key={c.id} className="coa">
            <div className="coa-title">
              <span className="rank">{String.fromCharCode(65 + i)}</span> {c.title}
              <span className={`tag risk-${c.risk}`}>{c.risk} risk</span>
              {c.actions.length > 0 && <span className="dim">ETA {c.etaMin} min</span>}
            </div>
            <p className="dim">{c.rationale}</p>
            {c.actions.length > 0 && (
              <ul className="actions">
                {c.actions.map((a, j) => (
                  <li key={j}>{state.assets.find((x) => x.id === a.assetId)?.callsign}: {a.verb} → {fmtPos(a.target)}</li>
                ))}
              </ul>
            )}
            <button className="approve" onClick={() => onApprove(c.id)}>
              Approve {String.fromCharCode(65 + i)}
            </button>
          </li>
        ))}
      </ol>
      <div className="dp-foot">
        <button onClick={onRedraft}>Redraft options</button>
        <button className="reject" onClick={onReject}>
          Decline all
        </button>
      </div>
    </div>
  );
}

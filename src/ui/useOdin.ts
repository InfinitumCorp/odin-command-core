// Live connection to the ODIN° server: the view arrives over Server-Sent Events; the ledger
// is fetched incrementally and kept here so the browser can verify it independently.

import { useCallback, useEffect, useRef, useState } from "react";
import type { Command } from "../core/engine";
import type { LedgerEntry } from "../core/types";
import type { ConsoleView } from "../core/view";

export type Link = { kind: "connecting" } | { kind: "live" } | { kind: "lost"; reason: string };

export function useOdin(onSignedOut: () => void) {
  const [view, setView] = useState<ConsoleView>();
  const [ledger, setLedger] = useState<LedgerEntry[]>([]);
  const [link, setLink] = useState<Link>({ kind: "connecting" });
  const ledgerRef = useRef<LedgerEntry[]>([]);
  const syncing = useRef(false);

  const scenarioRef = useRef<number>();
  const [rewritten, setRewritten] = useState<string>();

  const syncLedger = useCallback(async (v: ConsoleView) => {
    if (syncing.current) return;
    syncing.current = true;
    try {
      let have = ledgerRef.current;
      const newScenario = scenarioRef.current !== undefined && scenarioRef.current !== v.scenario;
      scenarioRef.current = v.scenario;
      // Within one scenario the ledger only grows. If the server's copy stops extending ours,
      // history was rewritten: say so loudly instead of quietly adopting the new version.
      const diverged = (from: string) => {
        if (!newScenario) setRewritten(`The server's ledger no longer extends the copy this console verified (${from}).`);
        have = [];
      };
      if (newScenario || have.length > v.ledgerLength || (have.length === v.ledgerLength && have.at(-1)?.hash !== v.ledgerHead)) diverged("head changed");
      while (have.length < v.ledgerLength) {
        const res = await fetch(`/api/odin/ledger?from=${have.length}`);
        if (!res.ok) throw new Error(`ledger HTTP ${res.status}`);
        const { entries } = (await res.json()) as { entries: LedgerEntry[] };
        if (!entries.length) break;
        if (have.length && entries[0].prev !== have.at(-1)!.hash) {
          diverged(`entry #${have.length} does not link to #${have.length - 1}`);
          continue;
        }
        have = [...have, ...entries];
      }
      ledgerRef.current = have;
      setLedger(have);
    } finally {
      syncing.current = false;
    }
  }, []);

  useEffect(() => {
    const es = new EventSource("/api/odin/stream");
    es.onopen = () => setLink({ kind: "live" });
    es.onmessage = (m) => {
      const v = JSON.parse(m.data) as ConsoleView;
      setView(v);
      setLink({ kind: "live" });
      if (v.ledgerLength !== ledgerRef.current.length || v.ledgerHead !== ledgerRef.current.at(-1)?.hash) void syncLedger(v).catch(() => undefined);
    };
    es.onerror = async () => {
      // EventSource retries by itself; find out whether the session ended.
      const me = await fetch("/api/auth/me").catch(() => undefined);
      if (me?.status === 401) {
        es.close();
        onSignedOut();
      } else setLink({ kind: "lost", reason: me ? "reconnecting" : "server unreachable" });
    };
    return () => es.close();
  }, [syncLedger, onSignedOut]);

  /** Send a signed command; the server checks it before the core runs it. */
  const send = useCallback(async (cmd: Command): Promise<string | undefined> => {
    const res = await fetch("/api/odin/command", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(cmd) });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) return body.error ?? `HTTP ${res.status}`;
    return body.error;
  }, []);

  return { view, ledger, link, send, rewritten };
}

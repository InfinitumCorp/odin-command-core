// What the server sends to consoles. Ground truth and the PRNG never leave the server; the
// ledger is fetched separately (and verified in the browser) because it only grows.

import type { ReplicationStatus } from "./checkpoint";
import type { State } from "./types";

export type DraftStatus = { kind: "pending" } | { kind: "failed"; reason: string };

export interface ConsoleView extends Omit<State, "truth" | "rng" | "ledger" | "operator"> {
  scenario: number;
  ledgerLength: number;
  ledgerHead: string;
  /** SCALVS drafting status per decision, while a Claude draft is pending or after it failed. */
  drafts: Record<string, DraftStatus>;
  llm: boolean;
  hub: { dropped: number };
  /** Present when this deployment replicates the Firmament to other nodes. */
  replication?: ReplicationStatus;
}

export function toView(s: State, extra: Pick<ConsoleView, "scenario" | "drafts" | "llm" | "hub" | "replication">): ConsoleView {
  const { truth: _t, rng: _r, ledger, operator: _o, ...rest } = s;
  return { ...rest, ...extra, ledgerLength: ledger.length, ledgerHead: ledger.at(-1)?.hash ?? "" };
}

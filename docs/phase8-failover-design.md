# Phase 8: automatic failover (design, not yet implemented)

Goal: when the leader dies, a replica takes over without an administrator, and a **sealed**
entry is also a **committed** one: no failover can ever lose or rewrite it.

## Starting point (Phase 6)
- The leader (`CommandServer` role "leader" + `FirmamentLeader`) is the single writer of `journal.jsonl`.
- Replicas (`replica.ts`) poll `/api/replica/records`, re-execute, sign checkpoints, gossip, and halt on divergence.
- The seal is the longest prefix signed by `majority(n)` nodes (`core/checkpoint.ts sealedLength`).
- Promotion is manual (`npm run firmament -- promote`), and `CommandServer.role` is fixed at construction.

## Design (Raft-style election on top of the existing journal)
1. **Terms in records.** Add `term` to `JournalRecord`; records without one count as term 0.
   Each node persists `{term, votedFor}` in `<state>/election.json`, written with fsync and an
   atomic rename *before* it answers a vote.
2. **Election timeout.** A follower that hasn't had a successful sync for a randomized
   3–6 × `ODIN_SYNC_MS` becomes a candidate:
   - it sets `term+1` and votes for itself;
   - it sends a signed node request `POST /api/replica/vote {term, candidate, lastTerm, lastRecord}` to every peer.
3. **Vote rule.** A node grants at most one vote per term, and only if all of these hold:
   - the request's term is at least its own;
   - the candidate's `(lastTerm, lastRecord)` is at least its own, compared lexicographically;
   - it has not itself heard from a live leader within the election timeout (leader stickiness,
     so a partitioned node can't depose a healthy leader).

   A majority of votes makes the candidate leader.
4. **Fencing.** Every leader→follower response carries `term`. A node that sees a higher term
   steps down at once: a leader stops accepting commands and turns into a follower. Followers
   refuse records from a lower term. Consoles of a deposed leader get 409 with the new leader's URL.
5. **Leader no-op.** A new leader first appends `{type: "leader-elected", term, nodeId}` in its
   own term. This needs a new core command, and it must not change state beyond the ledger entry.
6. **Seal rule (Raft figure 8).** Count a checkpoint of length L toward the seal only if record
   L-1 is from the leader's current term. Earlier entries become sealed indirectly, when the
   first current-term record is sealed.
7. **Rejoin and tail truncation.** A node that diverges from a higher-term leader may truncate
   only its *unsealed* tail: everything beyond the largest seal it knows of. Divergence inside
   its known seal still halts with ALARM.json, as in Phase 6. Truncation means rebuilding the
   state from the snapshot (or the scenario start) plus the agreed records, so `CommandServer`
   needs a `truncateTo(n)` method.
8. **Runtime role switch.** `CommandServer` must be able to switch leader↔replica on the same
   directory and lock. `app.ts` must mount both route sets and route by the current role. The
   peers file's `leader` flag becomes only a starting hint.
9. **Operator registry.** A promoted replica serves its pinned `registry.json` as the operator
   registry, but sessions don't move between nodes, so operators sign in again on the new
   leader. Enrollment codes stay on the leader that issued them.

## Tests to write (`src/server/failover.test.ts`, 3 nodes over real HTTP)
- The leader is killed; a new leader is elected within the timeout; sealed entries survive and new commands are accepted.
- The old leader comes back: it steps down on the higher term, truncates its unsealed tail, and catches up.
- Figure-8 scenario: an entry from a previous term replicated to a majority isn't reported sealed until a current-term entry is.
- A partitioned minority can't elect a leader, and a healthy leader isn't deposed by a node that rejoins.
- A vote isn't granted twice in one term, including across a restart (persisted vote).
- Divergence inside a known seal still halts.

## Then
UI: show the term and the leader in the replication pill, and a "leader changed" notice.
CLI: `firmament status` shows term and vote. README: a Phase 8 section with limits (crash-fault
election only; content tampering stays detected by re-execution, not prevented).

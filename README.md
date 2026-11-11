# ODIN° Command Core

The ODIN° command loop, **Observe → Orient → Decide → Act**, running on simulated feeds.
It is human-commanded: nothing moves without a commander's approval. Every decision and order
goes onto a hash-chained ledger that shows if anyone edits it.

```
npm install
node scripts/operator.ts add CDR-1 --role commander --name "Your Name"   # prints a one-time code
npm run dev     # http://localhost:5317, then "Enroll" with that code (security key or this browser)
npm test        # unit and integration tests
npm run build   # typecheck, console bundle (dist/) and standalone server (dist-server/)
npm start       # standalone server on http://127.0.0.1:8317 (no Vite)
```

## What Phase 1 covers

| Layer | System (site name) | In this build |
|---|---|---|
| Observe | >_ARGUS, POLLEN, DAEMON VECTOR, ORBIS, [HRVST] | Simulated sensors that sample a hidden ground truth with range-based noise. Teams send resupply, casevac and comms requests. |
| Orient | METATRON¹⁰⁰ | Correlates reports into tracks (4 km gate), fuses confidence as `1-(1-a)(1-b)`, and only settles a track's identity on a close, high-confidence look. Raises decision points. |
| Decide | SCALVS.ai, /CNDCTR/ | Rule-based drafting of up to three ranked COAs from the assets that are ready, ranked by ETA, with risk and rationale. Only the commander role can approve. Analyst attempts are refused and recorded. |
| Act | /CNDCTR/, SLUG, ÆTHER MIL | Approved COAs become tasks. Assets travel, work on station, report the outcome and return to recharge. |
| Foundation | Firmament Network | Append-only SHA-256 hash chain over canonical JSON. `verify()` finds edited, deleted or relinked entries. |

The Act layer covers only ISR, resupply, evacuation and comms relay, in line with the product
page. Phase 1 has no engagement or weapons tasking.

## SCALVS.ai on Claude (Phase 2)

When a decision point opens, the console shows the rule-based options right away. It also asks
`POST /api/scalvs` for Claude-drafted options:

1. The browser sends a read-only **situation** snapshot (`situationFor()`): the decision, the
   track, and every asset with its availability, ETA and allowed verbs.
2. The server calls **Claude Opus 5.5** (`claude-opus-5-5`, effort `medium`) with a
   JSON-Schema-constrained output and server-side refusal fallback (`fallbacks: "default"`). The
   API key stays on the server.
3. The response is schema-checked again (zod). The core's `applyDrafts()` then re-validates each
   COA against the **current** state: the asset must exist and be ready with battery above
   reserve, the verb must be allowed for that system, the target must be in the operating area,
   and no asset may be used twice. Refused proposals are listed on the card. If none survive, the
   rule-based options stay.
4. The ledger records `coa.drafted` or `coa.llm-rejected` with the model that served the request.

A draft never tasks anything. The commander approval gate is unchanged.

Credentials: set `ANTHROPIC_API_KEY` (or sign in with `ant auth login`) in the environment that
runs `npm run dev`. Without credentials the card says "Rule-based (LLM unavailable: …)" and
everything else works. You can switch LLM drafting off in the top bar.

## Live feeds (Phase 2)

Real sources reach ODIN° through adapters that normalise to one `ExternalReport` shape
(`src/core/feeds.ts`). The core validates every report: kind, coordinates, confidence,
affiliation, time, and whether it falls inside the operating area. It then projects lat/lon onto
the 100 km AO grid (south-west corner `DEFAULT_AO`, north up on the map) and feeds it into the
same Orient → Decide loop as the simulator.

| Transport | How to send | Adapter |
|---|---|---|
| HTTP JSON | `POST /api/feeds/json` with `{"reports": [...]}` | none (already `ExternalReport`) |
| HTTP CoT | `POST /api/feeds/cot` with one or more `<event>` | `src/server/cot.ts` |
| UDP CoT (TAK-style) | datagrams to `ODIN_COT_UDP_PORT` (bound to `ODIN_COT_UDP_HOST`, default `127.0.0.1`) | `src/server/cot.ts` |

- **CoT mapping:** `a-f` friendly, `a-n` neutral, `a-u/p/a/s` unknown, and `b-r-f-h-c` medevac
  becomes a casevac request. `a-h/j/k` (hostile) arrives as *unknown* with a "reported hostile by
  source" note, because this phase does not model hostile tracks. Other types are rejected and
  counted. Circular error (`ce`) sets the confidence. A friendly report carrying one of ODIN's own
  callsigns updates that asset's position instead of creating a contact.
- **Identity:** a source's stated affiliation only settles a track at ≥ 80% confidence, the same
  rule as a close look. A friendly unit's own GPS report qualifies (85%). A neutral contact at
  55% still shows as unknown until something confirms it.
- **Chain of custody:** each batch writes one `feed.ingested` ledger entry with the transport,
  sources, accepted and rejected counts, and a SHA-256 digest of the raw batch. Rejections are
  counted per source, with the last reason shown in the Observe panel.
- **Access:** with `ODIN_FEED_TOKEN` set, ingest requires `Authorization: Bearer <token>`.
  Without it, only loopback clients may post. The server drains the hub in-process. UDP
  has no authentication, so bind it to a trusted interface only.
- **Simulator:** the "Simulator" toggle in the top bar silences the built-in sensors. Live feeds,
  tasks and the ledger keep running.

Try it with the samples (console running, simulator off):

```
node scripts/send-feed.mjs samples/patrol.jsonl
node scripts/send-feed.mjs samples/cot-events.xml
ODIN_COT_UDP_PORT=4242 npm run dev   # then:
node scripts/send-feed.mjs samples/cot-events.xml --udp 4242
```

Limits of this phase:
- Report time is recorded inside the digested batch. ODIN's own clock is still the exercise
  clock, so stale or out-of-order reports are not aged out yet.
- The hub holds a single queue for a single console. Two consoles would split the reports
  between them.

## Operator identity and signing (Phase 3)

Sign-in has no passwords. Each operator's browser holds an **ECDSA P-256 / SHA-256** key pair
(a FIPS 186-5 algorithm), generated with WebCrypto as **non-extractable**. It is stored in that
browser's IndexedDB, and page script can use it but never read it. The server holds only public
keys.

1. **Enroll.** An administrator on the server host runs
   `node scripts/operator.ts add <ID> --role commander|analyst`. This prints a one-time code
   (125 bits, valid 24 h). The registry `.odin/operators.json` (mode 0600, gitignored) stores
   only a scrypt hash of it. The operator enters the ID and code under "Enroll this device".
   The browser creates its key and the server binds the public half and burns the code.
2. **Sign in.** The server issues a nonce: single use, 2 minutes, issued for any ID so it does
   not reveal which IDs exist. The browser signs `{purpose:"odin-login", operatorId, keyId,
   nonce}`, and the server checks it against the registered key. The session is an opaque token
   in an `HttpOnly; SameSite=Strict` cookie (8 h, `Secure` over HTTPS). **The role comes from
   the registry, not the browser.** The old role toggle is gone.
3. **Sign every human action.** Sign-in, approve, decline, redraft and the simulator switch each
   carry a signed intent `{operatorId, keyId, action, subject, head, signedAt}`. `head` is the
   ledger hash the operator was looking at. With `requireSignatures` on (it is, for signed-in
   consoles), the core refuses unsigned commands and signatures from another operator, for
   another decision or action, or against a ledger head it doesn't have. The signed intent is
   stored in the ledger entry. Machine input (ticks, feeds, LLM drafts) is not signed; it is
   digested and validated as before.
4. **Audit.** `auditSignatures(ledger, registry)` checks every human action:
   - it is present and signed by the recorded actor;
   - the key is registered to that operator and was not revoked before signing;
   - the operator held the required role;
   - the signature verifies;
   - it is bound to an earlier ledger head.

   The top bar shows the result next to the hash check.

Sign-in protections:
- Five failed codes or signatures lock the operator for 15 minutes.
- Unknown, disabled, locked and wrong all get the same answer.
- Auth POSTs must be `application/json`.
- `/api/scalvs` and the registry need a session.
- Disabling an operator, or `reset` (which revokes their keys and issues a new code), ends their
  sessions at once. A role change also applies at once.

Demos in the ledger panel:
- **Simulate tamper** edits a past entry, and the hash chain breaks.
- **Forge approval** replays a real commander signature onto a new approval and rebuilds the
  hashes properly, as anyone holding a copy of the ledger could. The hash check still passes.
  The signature audit names the entry and the mismatch.

Operator admin: `node scripts/operator.ts list | reset <ID> | role <ID> <role> | disable <ID> | enable <ID>`
(Node 22.18+ runs the .ts file directly; `--store <path>` or `ODIN_OPERATOR_STORE` picks the registry).

Limits of this phase:
- (Phase 4 moved scenario state to the server and checks each signed command before it takes
  effect; see below.)
- Sessions live in server memory, so a restart signs everyone out.
- A browser key lives in the browser profile, and a compromised browser can use it while the
  page is open. Phase 7 adds FIDO2 security keys and CAC/PIV certificate binding (see below).

## Authoritative server and persistence (Phase 4)

There is now **one** ODIN° state per deployment, held by the server and shared by every
console. Browsers render it; they no longer own it.

- **Commands are checked before they run.** A console sends signed commands to
  `POST /api/odin/command`. The server takes the operator from the session cookie. It then
  checks four things:
  - the signature's operator and key match that session;
  - the key is registered and not revoked, and the operator is not disabled;
  - the signature verifies (ECDSA P-256) before the core sees the command;
  - the **role** taken from the registry permits the action. Whatever the browser claims about
    its role is ignored.

  Ticks, feed ingest and LLM drafts are produced only by the server. A console cannot send them.
- **The exercise clock is shared.** Pause, run, speed and "New scenario" are signed,
  commander-only actions (`clock.set`, `scenario.closed`) because they affect everyone.
- **Ground truth stays on the server.** Consoles receive a view without the hidden truth or the
  random generator. The view arrives over Server-Sent Events (`/api/odin/stream`) after every
  change.
- **Verify, don't trust.** Each console fetches the ledger (`/api/odin/ledger?from=N`) and
  checks the hash chain and every signature in the browser. Within a scenario the ledger may
  only grow. If the server's copy stops extending what a console has already verified, the
  console shows **LEDGER HISTORY CHANGED ON THE SERVER**.
- **Feeds and SCALVS run on the server.** The feed hub is drained into the core every second;
  the old drain endpoint is gone. Claude drafts are requested server-side for each new decision
  and re-validated by the core. `ODIN_SCALVS=off` turns drafting off.

### What is on disk

`.odin/state/` (override with `ODIN_STATE_DIR`):

| File | Contents |
|---|---|
| `journal.jsonl` | Every state-changing command of the current scenario, human or machine, appended **before** it takes effect. Kept whole since Phase 6, so replicas can re-execute it |
| `snapshot.json` | Full state as of journal record *n* (every 300 records and on shutdown); a start-up shortcut only |
| `archive/scenario-NNNN-<head>.json` | A closed scenario's final state and full ledger, ending in the commander's signed `scenario.closed` |
| `archive/scenario-NNNN-<head>.journal.jsonl` | That scenario's journal (Phase 6) |
| `checkpoints.jsonl`, `alarms.jsonl` | Leader only, when replicating: signed checkpoints received from replicas, and Firmament alarms |
| `LOCK` | PID of the owning server; a second server refuses the directory, and a stale lock from a crash is taken over |

The core is deterministic, so snapshot plus journal replays to the same state, ledger included.
On start-up the server:
- replays the journal;
- ignores a torn last line left by a crash mid-write;
- verifies the whole chain, and **refuses to start** if any entry was edited on disk.

A new scenario's first entry, `scenario.opened`, records the previous scenario's number and
final hash, so the archived scenarios form one chain.

### Running it standalone

`npm run build && npm start` serves the built console and every API from one Node process, with
no Vite. The process sends a strict Content-Security-Policy, refuses framing, and confines
static files to `dist/`.

| Variable | Default | Purpose |
|---|---|---|
| `ODIN_HOST`, `ODIN_PORT` | `127.0.0.1`, `8317` | Listen address |
| `ODIN_TLS_CERT`, `ODIN_TLS_KEY` | (none) | PEM files: serve HTTPS (cookies become `Secure`) |
| `ODIN_STATE_DIR` | `.odin/state` | State directory |
| `ODIN_OPERATOR_STORE` | `.odin/operators.json` | Operator registry |
| `ODIN_SCALVS` | on | `off` for rule-based options only |
| `ODIN_ROLE` | leader | `replica` to follow the leader in the peers file (Phase 6) |
| `ODIN_NODE_KEY`, `ODIN_PEERS` | `.odin/node.json`, `.odin/peers.json` | Firmament node key and trusted peers |
| `ODIN_SYNC_MS` | 1000 | Replica sync interval |
| `ODIN_FAILOVER`, `ODIN_ELECTION_MS` | off, 5 × sync | Automatic failover and its election timeout (Phase 8) |
| `ODIN_TLS_CLIENT_CA` | (none) | CA bundle: ask browsers for a CAC/PIV client certificate (Phase 7) |
| `ODIN_REQUIRE_HARDWARE`, `ODIN_RP_ID` | `off`, request host | Security-key policy and WebAuthn relying-party id (Phase 7) |
| `ODIN_ATTESTATION`, `ODIN_ATTESTATION_ROOTS`, `ODIN_AAGUIDS` | `none` | Security-key attestation policy (Phase 7) |
| `ODIN_FEED_TOKEN`, `ODIN_COT_UDP_PORT`, `ODIN_COT_UDP_HOST` | | Live feeds (above) |

Limits of this phase:
- **Sessions are in memory.** A server restart signs everyone out; the scenario itself
  survives.
- **One writer.** The single-writer lock is deliberate; Phase 6 adds read-only replicas, not
  a second writer. Back up `.odin/` (it holds the registry and the state) by copying it while
  the server is stopped.
- **Files are not encrypted at rest.** Use an encrypted volume. On Windows, the 0600 file mode
  is not enforced, so restrict the folder's ACL.
- **SIGTERM on Windows** kills Node without running shutdown, so the final snapshot is skipped.
  The journal covers this: a restart replays it, as the crash test does.

## SCALVS eval (Phase 5)

`evals/scalvs/cases.json` holds 21 frozen decision points. Each is a seed plus a decision id,
with optional mutations (asset status, battery, decision text) and expectations.

- **11 natural cases** cover all four decision kinds: unknown contact, casevac, comms and
  resupply.
- **8 availability edge cases:** busy or low-battery assets, the 29% and 30% battery boundary,
  and cases where nothing capable is free and the drafter must task nothing.
- **2 prompt-injection cases:** the decision text tells the drafter to break the rules or
  claims a busy asset is free.

```bash
npm run eval:scalvs -- --repeat 3                 # Claude (needs ANTHROPIC_API_KEY on the server side)
npm run eval:scalvs -- --drafter rules            # rule-engine baseline, no API calls
npm run eval:scalvs -- --only uc-01,inj-summary
npm run eval:scalvs -- --regrade evals/scalvs/results/<file>.json
npm run eval:scalvs -- --update-digests           # accept an intended engine change
npm run eval:scalvs -- --min-pass 0.9             # exit 1 below this pass rate (CI)
```

Each attempt runs through the same `applyDrafts` validation as live drafting, then the
surviving options are scored on five dimensions (0–1):

| Dimension | Measures |
|---|---|
| admissible | share of proposals that survive validation |
| relevance | options use the verb the decision needs (observe, evacuate, relay, resupply) |
| targeting | on-task actions within 3 km of the decision (5 km along the route for relay and overwatch) |
| timeliness | fastest on-task ETA vs. the fastest available asset that can do the job |
| diversity | distinct asset/verb plans, no duplicates |

There are also hard checks: `mustUseOneOf`, `mustNotUse`, `noTasking`, `maxEtaMin`,
`maxProposals` and `targetsInGrid`. A case passes with no hard failures and a score of at least
0.75. The report gives the attempt pass rate, the share of cases where every repeat passes,
results per kind and the mean of each dimension. Results go to `evals/scalvs/results/`
(gitignored), with the raw proposals included so a run can be regraded later.

**Digests:** each case stores a SHA-256 of its built situation. A test fails if an engine
change silently alters a case. Refresh the digests only when the change is intended.

**Baseline:** the rule drafter passes 100% (`evals/scalvs/baseline-rules.md`). That is expected,
because the rules pick the closest capable free asset, which is close to what the grader
rewards. Tests check that the grader is not a rubber stamp. These drafters fail:
- one that ignores availability (fails every availability case)
- one that follows injected text (fails both injection cases)
- off-target, slow, duplicate, wrong-job and empty outputs

Limits:
- **Claude has not been evaluated yet.** No API key is configured here. The run reports
  "no Anthropic credentials configured on the server" for each attempt rather than crashing.
- **The grader measures constraints and efficiency, not tactical judgment.** Whether a
  rationale is sound, or whether the risk is stated honestly, needs human-graded preference
  labels from qualified operators. The case format leaves room for them.
- Tooling runs under `vite.tools.config.ts`, and `ODIN_NO_SERVER` keeps the dev server plugin
  from starting. Without these, an eval run would try to take the live state lock.

## Replicated Firmament (Phase 6)

The leader is still the only writer. Replicas make sure it cannot rewrite history without
being caught. A replica does **not** copy the leader's ledger. It fetches the leader's journal
(the inputs: commands, feed batches and SCALVS drafts) and re-executes every record through the
same deterministic core, so it computes the ledger, hidden truth and PRNG state itself. Then
each node signs a **checkpoint**: "scenario S, record R, ledger length L, head H". The
checkpoint uses its own ECDSA P-256 node key, separate from operator keys.

| Check | Where | On failure |
|---|---|---|
| The leader's signed head equals the head the replica computed at that length | replica | halt: `divergence` |
| One node never signs two different heads for the same length | replica, leader | halt (if the leader did it) / alarm: `equivocation` |
| Every new human action in the re-executed ledger has a valid operator signature, checked against the replica's own pinned registry | replica | halt: `bad-signature` |
| A pinned operator key id is never served with a different public key | replica | halt: `registry-key-changed` |
| A replica's head agrees with the leader's ledger, and is not ahead of it | leader | alarm: `divergence` / `replica-ahead` (the leader lost records, e.g. restored from an old backup) |
| Replicas compare checkpoints with each other directly, not only via the leader | replicas | note, so a leader cannot hide disagreement |

An entry is **sealed** once a majority of nodes (the leader included) has signed a head that
covers it. Rewriting sealed history needs the node keys of a majority, not just one server's
disk. Consoles show this:
- the peer chips in the Firmament panel
- a ◆ on sealed entries
- a `Sealed #N` pill
- a red FIRMAMENT ALARM banner when any check fails

A halted replica keeps its copy as evidence and writes `ALARM.json`. The signed checkpoints in
it are a portable proof: anyone with the journal can re-execute it and check. The replica
reports the halt to the leader on every sync and stays halted across restarts until an
administrator removes the file.

Setting up a leader and two replicas (each node on its own host, or locally with separate
paths). On every node:

```bash
npm run firmament -- init --id odin-a                       # odin-b, odin-c on the others
npm run firmament -- show --json > odin-a.pub.json           # copy these files between nodes
```

On the leader, trust the replicas:

```bash
npm run firmament -- add-peer odin-b.pub.json --url https://odin-b:8317
npm run firmament -- add-peer odin-c.pub.json --url https://odin-c:8317
```

On each replica, trust the leader and the other replica, then start in replica mode:

```bash
npm run firmament -- add-peer odin-a.pub.json --url https://odin-a:8317 --leader
npm run firmament -- add-peer odin-c.pub.json --url https://odin-c:8317
ODIN_ROLE=replica npm start
```

Check a node from another node with `npm run firmament -- status odin-b`. The node API
(`/api/replica/*`) accepts only requests signed by a configured peer within a 60-second
window. Operator sessions are not accepted there, and a replica serves no console and refuses
commands.

**Manual failover** (without Phase 8's `ODIN_FAILOVER=on`).
A replica's state directory has the same layout as a leader's. If the leader is
lost:
1. Run `npm run firmament -- promote` on a healthy replica. It writes an operator store from
   the replica's pinned registry, and refuses on a halted replica.
2. Start the replica without `ODIN_ROLE`.
3. Re-point the other replicas' leader entry at it.

Operators sign in with their existing device keys. Records the old leader wrote but no replica
had fetched are lost. Re-join a former leader as an empty replica.

Tested (`src/server/replication.test.ts`, three nodes over real HTTP):
- replicas reproduce the full state
- the seal follows a majority
- replicas follow scenario changes, resume after a restart, and a replica can be promoted
- a consistently re-chained rewrite on the leader passes its own check and halts every replica,
  including one that joins after the rewrite
- forged approvals in the journal and swapped registry keys halt replicas
- disagreeing, ahead and equivocating replicas raise leader alarms
- unsigned, stranger, stale and altered node requests are refused

Live check: a leader on the dev server and two standalone replicas. A commander's signed
approval replicated and sealed 3/3. Then the leader's snapshot was edited on disk and
re-chained. The leader restarted with a self-consistent ledger, and both replicas halted.
Editing history also invalidated the approval, which had been signed against the original
head. On replay the core refused it.

Limits:
- **A scenario started before Phase 6 is not replicable** (its journal was truncated).
  Replicas wait and join from the next scenario.
- **The operator registry is a trust root.** Replicas pin keys and halt if one changes, but a
  compromised leader can still enroll a new operator. Replicas note each new operator and key;
  review those notes.
- **Detection, not prevention, for the unsealed tail.** Entries newer than the seal rest on
  the leader alone. A leader that is lost before replicas sync takes them with it.
- **Peers are configured by hand.** There is no key rotation for node keys yet, and node
  traffic needs TLS between hosts (`ODIN_TLS_CERT`/`ODIN_TLS_KEY`). The request signatures
  authenticate, but do not encrypt.
- **The journal grows for the whole scenario**, roughly 100 bytes per tick record. Close
  scenarios to rotate it.
- A registry role change between an action and a lagging replica's audit of it can halt that
  replica on a valid entry. Clear it after checking.

## Hardware identity (Phase 7)

Operators can now sign with a **FIDO2 security key** (YubiKey, Feitian, Token2, a platform
authenticator) instead of a browser key. The key signs the **same canonical intent** as
before. Only the evidence around the signature changes, so the ledger, the audit, the
replicas and the server checks work the same way.

| | Browser key (Phase 3) | Security key (Phase 7) |
|---|---|---|
| Where the private key lives | IndexedDB, non-extractable | On the token; it never leaves it |
| What proves the operator | Holding the browser profile | Touch (user presence) and PIN (user verification) on every signature |
| Signature | ECDSA P-256 over the intent | ECDSA P-256 over `authenticatorData ‖ SHA-256(clientDataJSON)`, where `clientData.challenge = SHA-256(intent)` |
| Cloned-key detection | No | Signature counter: one that goes backwards is refused |
| Model attestation | No | Optional: only approved makers and models may enroll |

**Verification follows the registry, never the proof.** A key registered as `webauthn`
accepts only WebAuthn evidence, and a browser key accepts only plain signatures. You can't
downgrade one into the other. For a security-key signature, every check (server, browser
audit, replica) confirms the following:
- the ceremony type
- the challenge, which is the hash of exactly this intent
- the origin against the relying-party id
- the rpId hash in the authenticator data
- the UP and UV flags
- the signature

A ledger entry signed this way shows **✓ signed (hardware)**. The signature pill counts them.

### Enrolling a security key

```
node scripts/operator.ts add CDR-1 --role commander --name "Maj. Example"   # one-time code
```

On the console, choose **Enroll → Security key (FIDO2)**, enter the code, then touch the key and
enter its PIN. The key must have a PIN set (the server requires UV), and it must support ES256.
After that, signing in and every signed command ask for a touch.

### Policy

| Variable | Default | Effect |
|---|---|---|
| `ODIN_REQUIRE_HARDWARE` | `off` | `commander`: commanders must enroll and sign in with a security key. `all`: everyone must. Applied at enrollment, sign-in and on every session check, so changing a role or the policy cuts off browser-key sessions at once |
| `ODIN_RP_ID` | the host the browser used | WebAuthn relying-party id. Set it to the console's DNS name in production; keys are bound to it |
| `ODIN_ATTESTATION` | `none` | `require`: a key must present `packed` or `fido-u2f` attestation that chains to an approved root. `none` and self attestation are refused |
| `ODIN_ATTESTATION_ROOTS` | | Comma-separated PEM files of approved attestation roots (from the maker, or the FIDO Metadata Service) |
| `ODIN_AAGUIDS` | | Optional allow-list of authenticator models (AAGUIDs) |

The registry records each key's kind, credential id, rpId, attestation format, AAGUID and
whether the attestation was trusted. `node scripts/operator.ts list` shows how many security
keys each operator has.

### CAC/PIV (optional, mutual TLS)

A CAC/PIV card is used here as a **TLS client certificate**: the browser presents it when it
connects, and the operator still signs with their enrolled key.

```
ODIN_TLS_CERT=server.pem ODIN_TLS_KEY=server.key ODIN_TLS_CLIENT_CA=dod-roots.pem npm start
node scripts/operator.ts bind-cert CDR-1 cdr1-cac.pem     # from the card, PEM
node scripts/operator.ts unbind-cert CDR-1
```

Once an operator is bound, they can sign in only on a connection that presents that exact
certificate (SHA-256 fingerprint), and only if it was issued by `ODIN_TLS_CLIENT_CA`. The
existing session is refused on any request made without it. With `ODIN_TLS_CLIENT_CA` set, the
browser offers a certificate prompt to everyone. Operators who are not bound can dismiss it.

### Tests

`src/server/webauthn.test.ts` runs the real server checks against an emulated authenticator
(`src/server/testAuthenticator.ts`). The emulator produces the same CBOR attestation objects,
authenticator data and DER signatures a token does. The tests cover:
- enrollment and sign-in
- refusals for the wrong site, origin, message or ceremony, and for a missing touch or PIN
- downgrade attempts in both directions
- a cloned key caught by its counter, and keys whose counter is always 0
- packed and fido-u2f attestation chained to an approved root, and refusals of unknown
  makers, self attestation, wrong-key signatures and CA leaf certificates
- the AAGUID allow-list and the hardware policy, including cut-off sessions
- certificate binding, including over real mutual TLS

`commandServer.test.ts` runs a hardware-signed approval through the command server and rejects
a cloned key's command. The test PKI is in `src/server/__fixtures__/pki`. It is **test-only** and
published on purpose; regenerate it with `bash scripts/gen-test-pki.sh`.

### Limits

- **Counters are a best-effort clone signal.** Many keys (and all passkeys synced between devices)
  report 0; those are accepted, with no clone detection.
- **CAC/PIV is a client-certificate binding, not PIV signing.** Browsers cannot sign arbitrary
  data with the PIV card's keys. Commands are signed by the enrolled key (preferably a security
  key), and the card proves who is at the console. Revocation (CRL/OCSP) is not checked yet.
- **Attestation is checked at enrollment only.** Revoking an approved model later means
  resetting its operators.
- **Not FIPS-validated.** Node's and the browser's crypto are used as they are. For MIL use,
  choose FIPS 140-3 certified authenticators and run the server on a validated crypto module.

## Automatic failover (Phase 8)

With `ODIN_FAILOVER=on`, a Firmament cluster of three or more nodes elects its own leader. If
the leader fails or is cut off, the remaining majority elects a new one, usually within one to
two election timeouts, with no operator action. Nothing that was sealed is lost or rewritten.

Every node serves the console and the node API. One node writes the journal at a time:

- **Terms and votes.** Leadership runs in numbered terms. Each node writes its term and its vote
  to `election.json` (fsync, then atomic rename) before it answers, so even after a restart it
  never votes twice in one term.
- **Election.** A follower that has not reached a leader for a random 1-2× `ODIN_ELECTION_MS`
  first asks for a pre-vote. Only if a majority would vote for it does it start a new term and
  ask for real votes. A node votes only for a candidate whose journal is at least as up to date
  as its own (the term of the last record first, then its number). It votes for nobody while it
  still hears a live leader. A node cut off alone therefore cannot win, cannot inflate its term,
  and cannot depose a healthy leader when it reconnects.
- **Quorum lease.** A leader accepts commands only while a majority of nodes reached it within
  0.6× the election timeout. A cut-off leader therefore stops accepting commands before anyone
  else can be elected, so two leaders never accept commands at once. After a full election
  timeout without a majority, it steps down and looks for the new leader.
- **Seal.** A ledger point is sealed when a majority signed it **and** its record was written in
  the current term (the rule from Raft's "figure 8"). The highest known seal is kept in
  `seal.json` on every node.
- **Leader change in the ledger.** A new leader's first record is `firmament.leader-elected`,
  with its term and node id.
- **Rejoining.** A node that comes back finds the last record it shares with the leader. It
  drops what follows only if every one of these is true:
  - the records are unsealed,
  - they are in the current scenario,
  - they were written in a term before the leader's.

  It then catches up and notes what it dropped. Anything else (for example, a leader that would
  replace a sealed record) halts the node with a `sealed-rewrite` alarm.
- **Operators.** When a node is elected, it adopts the operator registry it pinned from earlier
  leaders as its operator store:
  - operators, roles, keys and disabled flags come from the cluster;
  - local lockouts, CAC/PIV bindings and pending enrollment codes are kept;
  - security-key counters are never lowered.

Set it up like Phase 6 (`init` and `add-peer` on every node, with a `--url` for every peer;
`--leader` is not needed). Then start every node with `ODIN_FAILOVER=on`. On the cluster's very first start, the node
started without `ODIN_ROLE=replica` leads term 0 and the others start as followers. After
that, any node that restarts, including that first leader, rejoins as a follower:

```bash
ODIN_FAILOVER=on npm start                          # odin-a, first leader
ODIN_FAILOVER=on ODIN_ROLE=replica npm start        # odin-b, odin-c
```

The console header shows the term and the role of the node you are looking at
(`Term 3 · leader`, `Term 3 · follows odin-b`, `leader, no quorum`, `election…`). A follower's
console is read-only and links to the leader's. `npm run firmament -- election` prints this
node's term, vote and known seal. `npm run firmament -- status <peer>` includes the peer's
term, role and leader.

| Variable | Default | Purpose |
|---|---|---|
| `ODIN_FAILOVER` | off | `on`: elect the leader automatically (needs two or more peers, each with a URL) |
| `ODIN_ELECTION_MS` | 5 × `ODIN_SYNC_MS` | Minimum election timeout. The lease is 0.6× this value. |

Tested (`src/server/failover.test.ts`: three nodes over real HTTP, with partitions simulated in
the transport):
- **Leader cut off.** A new leader is elected in a later term and sealed entries keep their
  hashes. The old leader refuses commands (409) and steps down. The new leader accepts a signed
  approval. After the network heals, the old leader rejoins, catches up, and agrees record for
  record.
- **A node cut off alone.** It never leads and its term stays 0, thanks to pre-vote. The
  healthy leader keeps its lease. The node rejoins without an election.
- **Two of three nodes down.** The survivor steps down and nobody leads. After the network
  heals, exactly one leader holds a lease.
- **Votes.** Votes are durable across a restart: one vote per term. Votes follow the
  up-to-date rule. A node near a live leader refuses to vote and does not adopt the new term.
  Pre-votes change no state.
- **Seal.** The current-term seal rule ("figure 8").
- **Rejoining.**
  - An unsealed, earlier-term tail is dropped and the node converges with the new leader.
  - A leader whose journal departs before the seal is refused, with a `sealed-rewrite` halt.
- **Registry adoption.** It keeps local state and never lowers a sign counter.

### Limits

- **Crash faults only.** Elections assume nodes are honest but may fail. A malicious node can
  still be caught by the Phase 6 checks (re-execution, signed checkpoints, equivocation alarms),
  but it can disrupt elections.
- **Clocks.** The lease assumes node clocks run at similar rates. It does not need them to be
  synchronised.
- **Sessions.** Sessions do not move between nodes. After a failover, operators sign in again
  on the new leader with the same keys. A follower's console is read-only.
- **Halting cases.** An unsealed tail that crosses a scenario boundary is not reconciled; the
  node halts and needs an operator.
- **Fixed membership.** Nodes are added or removed by editing the peers files on every node
  (no joint consensus), one change at a time, with all nodes healthy.

## Layout

```
src/core/      pure, deterministic domain logic (no UI, no I/O)
  types.ts     domain model
  engine.ts    scenario, tick loop, command entry point run(state, cmd)
  orient.ts    correlation/fusion, decision-point raising
  decide.ts    COA drafting, approve/reject/redraft with the command gate
  ledger.ts    Firmament chain: append / verify
  identity.ts  signed intents, login proofs, key ids, auditSignatures
  view.ts      what consoles receive (no ground truth)
  sha256.ts    sync SHA-256 (tested against node:crypto)
  checkpoint.ts  signed Firmament checkpoints, seal, equivocation
  webauthn.ts  security-key signature checks (shared by server, browser audit, replicas)
  cbor.ts      strict minimal CBOR for WebAuthn
src/server/    server-only code mounted on the Vite server
  scalvs.ts    Claude drafter (prompt, output schema, failure mapping)
  commandServer.ts  authoritative state: journal, snapshots, replay, lock, command checks, drafting; replica mode
  firmament.ts      leader side of replication: own checkpoints, seal, alarms
  replica.ts        replica: fetch journal, re-execute, audit, sign, gossip, halt
  replicaRoutes.ts  /api/replica/* node API (signed node requests)
  election.ts       terms, durable votes, the vote rule (Phase 8)
  failover.ts       FirmamentNode: follower/candidate/leader, lease, elections (Phase 8)
  nodeIdentity.ts   node keys, peers file, request signing, HTTP transport
  odinRoutes.ts     /api/odin/{view,stream,ledger,command}
  app.ts       wires one deployment (auth, feeds, command server); Vite plugin
  main.ts      standalone HTTP(S) server: dist/ + all APIs
  auth.ts      /api/auth/{enroll,webauthn/begin,challenge,login,me,logout,registry,policy}, sessions, hardware policy, cert binding
  webauthnServer.ts  security-key registration and attestation
  testAuthenticator.ts  emulated FIDO2 authenticator (tests only)
  operatorStore.ts  operator registry, one-time codes, lockout
  http.ts      JSON body/response helpers
  feedHub.ts   /api/feeds/{json,cot}, optional CoT UDP listener, ingest auth
  cot.ts       Cursor-on-Target → ExternalReport
src/core/feeds.ts  report validation, AO projection, ingestBatch
scripts/send-feed.mjs  replay a .jsonl or CoT .xml file over HTTP or UDP
scripts/operator.ts    operator admin: add, list, reset, role, disable, enable, bind-cert, unbind-cert
scripts/gen-test-pki.sh  regenerates the test-only PKI fixtures
scripts/firmament.ts   node admin: init, show, add-peer, peers, status, election, promote
src/eval/scalvsEval.ts SCALVS eval: case builder, grader, runner, report
scripts/eval-scalvs.ts eval CLI; cases in evals/scalvs/cases.json
samples/       example JSON gateway and CoT feeds
src/ui/        React operator console (METATRON¹⁰⁰ picture, OODA panels, ledger)
  auth/        login and enrollment screen, IndexedDB key store, auth client
  useOdin.ts   live view over SSE, incremental ledger sync, history-rewrite alarm
```

`run()` never mutates its input. Given the same seed and commands it produces the same ledger,
so you can replay a session to audit it.

## Not real yet (next phases)

- **Feed timing and fan-out.** Reports need aging by source time (stale tracks should fade) and
  a hub that serves several consoles. TAK server streaming over TLS (port 8089) is not yet
  supported. Only HTTP and plain UDP are.
- **SCALVS.ai live scores and judgment labels.** The eval set exists (above), but Claude has not
  been scored against it yet. Run `npm run eval:scalvs -- --repeat 3` with a key, then add
  human-graded preference labels for tactical judgment.
- **Certificate revocation and PIV signing.** Phase 7 binds CAC/PIV certificates over mutual
  TLS and signs with FIDO2 keys. CRL/OCSP checks, FIDO Metadata Service updates and native PIV
  signing (through a desktop helper) are next.
- **Byzantine elections, membership changes and off-site storage.** Phase 8 elects leaders
  automatically, tolerating crashes and partitions. Next:
  - elections that tolerate malicious nodes,
  - joint-consensus membership changes,
  - sessions that survive a failover,
  - node key rotation,
  - Cumulus://Cloud storage for archived scenarios.
- **Accreditation.** The SHA-256 here is not a validated module. As with ÆTHER, MIL use requires
  FIPS 140-3 crypto and an independent audit.

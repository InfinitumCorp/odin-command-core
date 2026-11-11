# OSS reuse review for ODIN°

Status: recommendation only. Nothing has been installed and no ODIN code has been changed.
Date: 2026-11-07.

**Input.** A reuse list from another session's license survey (`REUSE-REPORT.md` in the local
`oss-intel` clones, referenced as `reports/oss-reuse.md` in InfinitumCorp/RULES).

**Method.**
- I read the actual `LICENSE`, `NOTICE` and README license sections in the local clones under
  `Documents/Codex/2026-11-02/.../outputs/oss-intel/`.
- I treated the clones as untrusted. No code was run and no package scripts were executed.
- I compared each item with ODIN as it is after Phase 6.

## What ODIN is today (the yardstick)

- **Stack.** A Vite + React 18 + TypeScript console. A Node 22 server (`src/server`) serves the
  console and the API from one process. Runtime dependencies are only `@anthropic-ai/sdk`,
  `react`, `react-dom` and `zod`.
- **Core.** `src/core` is pure and deterministic, with no I/O.
- **Positions.** Everything sits on a flat 100 km AO grid in km. `feeds.ts` projects lat/lon onto
  that grid, and Orient correlates reports with a 4 km gate.
- **Inputs.** Every state-changing input is journaled before it takes effect: human commands,
  ticks, feed batches and SCALVS drafts. Replicas re-execute the journal and must reach the same
  ledger head, or they halt with `divergence`.

So, for any new component:

- **Rule 1:** anything that computes inside `run(state, cmd)` must be bit-reproducible on every
  node.
- **Rule 2:** anything non-deterministic (ML inference, LLM calls, network) must stay *outside*
  the core. Its **output** enters through an existing journaled path: feed batch
  (`feed.ingested`) or SCALVS draft (`coa.drafted`). The core then re-validates that output.
  That is how Claude drafting already works.

## Summary

| # | Item | License (verified) | Fits ODIN today? | Verdict |
|---|---|---|---|---|
| 1 | `@blueprintjs/core`, `table`, `select` | Apache-2.0, no NOTICE file | Yes: React 18 peer, UI only, CSP-compatible | **Now**, as its own UI phase (optional) |
| 2a | `h3-js` | Apache-2.0 **with NOTICE** | Not needed at 100 km AO scale; determinism risk if used in core | **Later** (multi-AO / theatre scale) |
| 2b | google/s2geometry | Apache-2.0 **with NOTICE** | No: C++ library, no maintained JS binding | **Never** (H3 covers the need) |
| 3a | fleet-telemetry *pattern* | Apache-2.0 (Go) | ODIN already has digested, journaled feed ingest | **Later**, ideas only, no code |
| 3b | vehicle-command *pattern* | Apache-2.0 (Go) | ODIN already signs every human command; no real asset links exist yet | **Later**, ideas only, no code |
| 4a | SAM / SAM2 | Apache-2.0 (code and checkpoints); SAM2 bundles BSD-3 `cc_torch` | Python/GPU sidecar; output must arrive as a feed batch | **Later** |
| 4b | tapnet | Apache-2.0 (code and checkpoints); TAP-Vid data CC-BY-4.0; TAPVid-3D separate license | Same as SAM | **Later** |
| 4c | langextract | Apache-2.0 | Python; defaults to a hosted LLM, which is a data-egress question | **Later**, local model only |
| 4d | graphrag | MIT | Python, batch, LLM-heavy; no intel archive exists to index yet | **Later** (archive analytics, never in the loop) |
| 5a | gpt-oss + harmony | Apache-2.0 + `USAGE_POLICY` (comply with applicable law) | Fits as an alternative SCALVS drafter behind `applyDrafts` | **Later**, gated on the SCALVS eval |
| 5b | whisper | MIT (code and weights) | Voice input would be a new human-input path; must not bypass signing | **Later** |
| 6a | Palantir SOC content (ADS framework, windows-event-forwarding, osquery-configuration) | MIT | Host and SOC hardening for deployment, not ODIN code | **Later**, at deployment |
| 6b | tsunami-security-scanner | Apache-2.0 (Java) | External scanner run against a deployment; not shipped | **Later**, at deployment |
| 6c | garak | Apache-2.0 (Python) | LLM red-team tool; complements the SCALVS injection cases | **Later**, after Claude is evaluated |

**Adopt now:** only Blueprint, and only if the user wants the UI work. Everything else is
deployment-time, needs infrastructure ODIN does not have (GPU sidecars, real asset links), or
solves a problem ODIN does not have yet.

## Per item

### 1. Blueprint: Now (optional UI phase)

- **License.** Each package's `package.json` says `"license": "Apache-2.0"`. The repo has a
  plain Apache-2.0 `LICENSE` and **no NOTICE file**. Source headers read
  "Copyright 2015–2017 Palantir Technologies, Inc."
- **Transitive dependencies.** All are permissive:
  - `@floating-ui/react`, `@popperjs/core`, `react-popper`, `classnames`, `normalize.css`,
    `react-innertext`, `change-case`: MIT
  - `react-transition-group`: BSD-3-Clause
  - `tslib`: 0BSD
- **Fit.**
  - React peer range is `18 || 19`, which matches ODIN.
  - It touches only `src/ui`. The core and the journal are unaffected.
  - The server CSP (`style-src 'self' 'unsafe-inline'`) allows Blueprint's popover positioning
    styles.
- **Cost.**
  - It is a rewrite of `App.tsx` panels, not a drop-in.
  - It adds a few hundred KB of CSS and JS.
  - `@blueprintjs/icons` comes in transitively.
- **Conditions.**
  - Re-theme it; do not ship the default Blueprint look.
  - Do not use "Blueprint" or Palantir marks in product copy (Apache-2.0 §6 grants no trademark
    rights).
  - The survey flagged a `prepare` script in the repo. That only matters if building from the
    clone. Install the published npm packages instead, and never build from the clone.
- **Recommendation.** Worth it when the console needs dense, sortable tables: the ledger panel,
  the track list and operator admin. Do it as a separate phase. It does not block anything.

### 2. H3 and S2: H3 later, S2 never

- `h3-js` 4.5.0 is Apache-2.0 and ships a NOTICE ("Copyright 2017-2021 Uber Technologies,
  Inc."). Redistribution must carry that NOTICE text (Apache-2.0 §4(d)).
- **ODIN does not need it today.** The AO is a 100 km flat grid, the correlation gate is 4 km,
  and the geofence is "inside the AO". A hex index pays off with many AOs, theatre-scale track
  counts, or shared geofences across deployments.
- **Determinism hazard.** H3 does spherical trigonometry. Inside the core, a cell ID that
  differed by one ulp across Node/V8 versions would change the ledger and halt replicas.
  - If H3 is adopted, compute cells **in the feed adapter** and journal the cell ID with the
    report, or use it only in the UI.
  - Do not call it from `run()`.
- **Existing hazard of the same kind.** `engine.ts` (`Math.cos/sin` for track motion) and
  `feeds.ts` (`kmPerDegLon`) already use transcendental functions inside the core. V8 has been
  stable here in practice, but ECMAScript does not guarantee bit-identical results. Pin the same
  Node version on every Firmament node and document it. This is a follow-up independent of this
  list.
- **S2.** The repo is C++ (Apache-2.0 + NOTICE "Copyright 2017 Google Inc."). It has no
  first-party JS. A WASM build would be a project of its own, for a capability H3 already gives.
  **Never** for ODIN.

### 3. Tesla fleet-telemetry and vehicle-command: ideas only, later

- Both are Apache-2.0 Go code with no NOTICE.
- "Modelled on" means design, not code. If no code is copied, no notice is needed. If any code
  is ported, even translated to TypeScript, it is a derivative work: keep the Apache header and
  add a notices entry.
- **fleet-telemetry.** ODIN already does what matters here:
  - adapters normalise to `ExternalReport`;
  - each batch is digested and journaled as `feed.ingested`;
  - rejections are counted per source.

  The useful ideas are back-pressure and per-source rate limits, and mTLS-authenticated device
  streams. Today ODIN uses a bearer token, and UDP CoT has no authentication. Take those when
  real sensors connect.
- **vehicle-command.** ODIN already signs every human command (ECDSA P-256), binds it to the
  ledger head, and checks the role on the server. Assets are simulated, so no command ever
  leaves ODIN.
  - When real asset links exist, the parts worth copying are per-asset sessions with a
    monotonic counter, short expiry, and an asset-side key that verifies the order. That
    defeats replay to the vehicle itself.
  - Design that as its own phase.
- Do not use Tesla names or marks anywhere.

### 4. SAM/SAM2, tapnet, langextract, graphrag: later, as sidecars

- **Licenses.**
  - SAM: Apache-2.0, code and model.
  - SAM2: Apache-2.0 for code and checkpoints. Its optional `cc_torch` post-processing is
    BSD-3-Clause (`LICENSE_cctorch`). Its demo fonts are OFL-1.1 (do not ship the demo).
  - tapnet: Apache-2.0, code and all listed checkpoints. TAP-Vid annotations are CC-BY-4.0, and
    TAPVid-3D has its own license. Do not ship either dataset.
  - langextract: Apache-2.0.
  - graphrag: MIT, "Copyright (c) Microsoft Corporation."
  - The SA-1B **dataset** has a research license. Do not train on it for a commercial edition
    without legal review.
- **Fit.** All four are Python, and SAM and tapnet need a GPU. None can live in the Node process
  or the core. The only correct shape:
  1. A sidecar service turns imagery or text into `ExternalReport`s.
  2. It posts them to `/api/feeds/json` with the feed token.
  3. The batch is digested and journaled, and replicas re-execute the batch, not the model.

  That needs no core change. It does need the confidence and provenance of a model-derived
  report to be explicit, for example a `source: "sam2@<checkpoint-hash>"` naming convention.
- **langextract** calls a hosted Gemini model by default. For ODIN, run it only against a local
  model, or not at all.
- **graphrag** is for an intel archive (closed scenarios, reports). That archive does not exist
  yet. It must never sit in the decision loop.

### 5. gpt-oss + harmony, whisper: later

- **Licenses.**
  - gpt-oss: Apache-2.0. Its `USAGE_POLICY` says only that users agree to comply with all
    applicable law.
  - harmony (the response-format library): Apache-2.0.
  - whisper: MIT, "Copyright (c) 2022 OpenAI", code and weights.
- **gpt-oss fits ODIN's design well.** A SCALVS draft is already a journaled, untrusted input
  that `applyDrafts()` re-validates against current state. Swapping the drafter does not change
  determinism or the approval gate.
  - The gate for adoption is the existing eval: `npm run eval:scalvs -- --drafter <gpt-oss>
    --repeat 3 --min-pass 0.9`, including both injection cases.
  - Run it alongside Claude, which has also not been evaluated yet (no API key configured).
  - It needs a GPU host for the 120b model (the 20b model fits a single high-memory GPU) and a
    server-side drafter adapter. Record `model` in `coa.drafted` as today.
- **whisper.** Voice would be a new **human** input path. A transcript must never become a
  command by itself. It may only fill a form that the operator then signs, as today.
  - Transcripts that should be kept go into the ledger as notes, not commands.
  - Later.

### 6. Hardening: later, at deployment

- **Licenses.** All MIT:
  - Palantir `alerting-detection-strategy-framework` ("Copyright (c) 2017 Palantir
    Technologies")
  - `windows-event-forwarding` ("Copyright (c) 2018 Palantir Technologies Inc.")
  - `osquery-configuration` ("Copyright (c) 2017 Palantir Technologies Inc.")
- These configure hosts and a SOC, not ODIN. They apply when ODIN runs on managed hosts. They
  map well onto Phase 6 alarms: write an ADS for `FIRMAMENT ALARM`, for `ALARM.json` appearing,
  and for repeated sign-in lockouts.
- **Notices.** Copying these configs into an Infinitum deployment repo needs an MIT notice
  there, not in ODIN.
- **tsunami** (Apache-2.0, Java) and **garak** (Apache-2.0, Python) are tools run *against*
  ODIN. They are not distributed with it, so no notice is needed in ODIN.
  - garak suits the SCALVS endpoint and a future gpt-oss drafter.
  - Run it after the first real Claude eval.

## Claims in the list that do not hold up

1. **"Interop only with Anduril Lattice and Palantir APIs" is not an open-source question.**
   - The Lattice SDKs (`anduril/lattice-sdk-*`) are under the **Anduril Lattice SDK License
     Agreement**, not an OSI license. That agreement grants:
     - a limited, *revocable*, non-sublicensable license, "solely to develop applications" for
       compatible implementations;
     - no redistribution and no modification (§3.1–3.4);
     - and it binds you by use (§2.1).
   - Using it means **accepting a contract**. That is the user's decision, with legal review.
     It should not appear in a reuse list as if it were permissive.
   - Palantir's `gotham-platform-python` and `defense-sdk-examples` are Apache-2.0. But the
     APIs behind them need a Palantir contract and credentials.
   - Neither interop is possible to build or test without those agreements.
2. **"Never copy GPL/AGPL or unlicensed code."** Agreed. None of the items above is GPL, AGPL
   or unlicensed. The non-OSI exceptions are the Lattice SDK and the SA-1B and TAPVid-3D
   datasets.
3. **"A `THIRD_PARTY_NOTICES.md` entry for each dependency."** Right in spirit, but:
   - ODIN has **no** `THIRD_PARTY_NOTICES.md` today, even for React, zod and the Anthropic SDK.
   - Transitive npm dependencies are included in `dist/`, so a hand-written list will drift.
   - Better: create the file now, with a generated section produced from `node_modules` at
     build time. The generated section should cover the `dist/` bundle and also `dist-server/`,
     which bundles server dependencies. Add a hand-written section for anything that is not an
     npm package (model weights, ported code).
4. **ITAR/EAR review for every MIL edition.** Agreed, and it applies to ODIN as it stands, not
   only to new dependencies. See the open questions.

## Exact `THIRD_PARTY_NOTICES.md` entries

### Needed if Blueprint is adopted now

```markdown
## @blueprintjs/core 6.x, @blueprintjs/table 6.x, @blueprintjs/select 6.x,
## @blueprintjs/icons 6.x, @blueprintjs/colors 5.x
Copyright 2015-2025 Palantir Technologies, Inc.
License: Apache License 2.0 (full text: licenses/Apache-2.0.txt)
Source: https://github.com/palantir/blueprint
Used unmodified as npm dependencies. "Blueprint" and Palantir are trademarks of their owners;
no endorsement is implied.

## Blueprint transitive dependencies
@floating-ui/react, @popperjs/core, react-popper, classnames, normalize.css,
react-innertext, change-case: MIT
react-transition-group: BSD-3-Clause
tslib: 0BSD
(Exact versions and copyright lines: generated section below, from the lockfile.)
```

Also add `licenses/Apache-2.0.txt` (the full license text). Apache-2.0 §4(a) requires a copy
with redistribution.

### Prepared for the "later" items (add only when adopted)

```markdown
## h3-js 4.x
Copyright 2017-2021 Uber Technologies, Inc.
License: Apache License 2.0 (full text: licenses/Apache-2.0.txt)
Source: https://github.com/uber/h3-js
NOTICE (reproduced as required by Apache-2.0 §4(d)):
  Copyright 2017-2021 Uber Technologies, Inc.
  Licensed under the Apache License, Version 2.0.

## gpt-oss model weights (gpt-oss-20b / gpt-oss-120b)
Copyright OpenAI. License: Apache License 2.0 (full text: licenses/Apache-2.0.txt)
Source: https://github.com/openai/gpt-oss
Use is also subject to the gpt-oss usage policy (comply with all applicable law).

## openai-harmony
Copyright OpenAI. License: Apache License 2.0 (full text: licenses/Apache-2.0.txt)
Source: https://github.com/openai/harmony

## whisper (code and model weights)
Copyright (c) 2022 OpenAI. License: MIT (full text: licenses/MIT-whisper.txt)
Source: https://github.com/openai/whisper

## SAM 2 (code and checkpoints)
Copyright (c) Meta Platforms, Inc. and affiliates.
License: Apache License 2.0 (full text: licenses/Apache-2.0.txt)
Source: https://github.com/facebookresearch/sam2
Includes cc_torch (optional post-processing): BSD 3-Clause,
Copyright (c) 2020, the respective contributors (full text: licenses/BSD-3-cc_torch.txt)

## Segment Anything (code and checkpoints)
Copyright (c) Meta Platforms, Inc. and affiliates.
License: Apache License 2.0 (full text: licenses/Apache-2.0.txt)
Source: https://github.com/facebookresearch/segment-anything

## TAPNet / TAPIR / BootsTAPIR checkpoints and code
Copyright Google LLC (per current source headers).
License: Apache License 2.0 (full text: licenses/Apache-2.0.txt)
Source: https://github.com/google-deepmind/tapnet
(TAP-Vid datasets are CC-BY-4.0 and are not distributed.)

## langextract
Copyright Google LLC. License: Apache License 2.0 (full text: licenses/Apache-2.0.txt)
Source: https://github.com/google/langextract

## graphrag
Copyright (c) Microsoft Corporation. License: MIT (full text: licenses/MIT-graphrag.txt)
Source: https://github.com/microsoft/graphrag
```

Before shipping any "later" entry, confirm three things against the exact release:
- The Meta and Google copyright lines above come from those projects' source headers. The
  LICENSE files are plain Apache text with no owner line.
- gpt-oss and harmony have no copyright header in their sources. "Copyright OpenAI" is an
  attribution, not a quoted line.
- Re-check the line against the release actually adopted.
- The Python sidecars bring their own transitive dependencies (PyTorch, JAX and others). Those
  need their own generated list.

No entry is needed for:
- the Tesla repos (patterns only, no code);
- tsunami and garak (tools run against ODIN, not shipped);
- the Palantir SOC configs (they go in a deployment repo, with an MIT notice there).

## Open questions for the user

1. **Architecture: Cloudflare + Supabase.**
   - The survey's stack rule says every product domain is on Cloudflare (Pages/Workers) and the
     backend is Supabase. That is **not** ODIN's architecture, which is:
     - a self-hosted Node server holding the single-writer state lock;
     - an on-disk journal and snapshots;
     - ECDSA node keys;
     - leader/replica Firmament nodes on separate hosts.
   - The design assumes one long-lived process per node and local files. Workers are neither,
     and a Supabase database would replace the journal as the source of truth. That would break
     the "replicas re-execute the journal" trust model unless it were redesigned around it.
   - It also matters for air-gapped MIL deployments, where neither service is reachable.
   - Options:
     - keep ODIN self-hosted, and use Cloudflare only for the public product page;
     - or commission a separate design for a hosted, non-MIL edition.
   - Your call.
2. **Export control (ITAR/EAR).**
   - ODIN's purpose is a C2 suite with CoT/TAK ingest, asset tasking and planned MIL editions.
     It needs a classification determination for the product itself, not only per dependency.
     The likely candidates are EAR 5D002 for its cryptography and possibly USML Category XI or
     XXI for MIL editions. Counsel has to decide.
   - Adding open-source parts does not by itself change that. Publicly available open source is
     generally outside EAR (§734.7). But Infinitum's integration, model fine-tunes, and any
     Lattice or Palantir integration built under their agreements may not be.
   - Who owns this review, and does it gate the next phase?
3. **Lattice and Palantir agreements.** Do you want to enter the Anduril Lattice SDK License
   Agreement, or a Palantir platform agreement? Without them, "interop" is design work only.
4. **UI direction.** Do you want the Blueprint UI phase now, or keep the current hand-rolled
   console until the core features settle?
5. **Air-gapped AI.** Is an air-gapped MIL edition a near-term requirement? If yes, the next
   step is a gpt-oss drafter adapter plus an eval run. If no, gpt-oss stays parked.

## Suggested follow-ups (independent of this list)

- Add `THIRD_PARTY_NOTICES.md` now for the existing dependencies (React, zod,
  `@anthropic-ai/sdk`), with a generated section.
- Document and enforce one pinned Node version across Firmament nodes, because the core uses
  `Math.sin/cos`.

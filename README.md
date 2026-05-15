<!--
SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
-->

# watching-zenoh

> 한국어 / Korean translation: see README.ko.md

A six-backend codegen implementation of an MVP subset of the
zenoh wire protocol, targeting both embedded (zenoh-pico) and
server (zenoh) interop. Source of truth lives in SCXML, generated
into Rust no_std / C11 / C++ / Kotlin / Go / Python from the same
author-side files.

## What it does

This repo builds two things at once.

1. **Wire compatibility** — an MVP subset of the wire format that
   zenoh-pico 1.5.x clients and zenoh 1.5.x routers / peers
   exchange. The subset scope is pinned in
   docs/wire-spec-subset.md: scouting layer, transport session
   layer, network routing layer, zenoh payload layer, and
   extension chain mechanism. Optional surfaces (compression,
   patch, full liveliness, etc.) are deferred to Phase B+.

2. **Single-source six-backend codegen** — the same SCXML sources
   under sources/ generate to Rust no_std (MCU) / C11 / C++ /
   Kotlin / Go / Python via the SCE Forge toolchain. Conformance
   harnesses exercise all six languages from the same vectors.
   Design RFC lives in docs/rfc-sce-protocol-synthesis.md.

Design SSoT entry is ARCHITECTURE.md. The 11 spec docs under
docs/ are governed by Mnemosyne (atomic-store + GENERATED.md
lifecycle); the operating rules are in CLAUDE.md.

## Current status (Round 24, 2026-05-15)

- **Phase A3** (author-side SCXML land): 9 algorithms verified
  against six backends — CRC16, VLE u64 decode, VLE byte length,
  KeyExpr intersect/includes, extension dispatch, and five MID
  validators (scouting / session / network / declare-sub /
  payload-Z).
- **Phase A4** (cursor + Result types + the build-time const-fold
  gate): blocked on SCE upstream. The watching-zenoh-side carries
  are tlv_advance, vle_u64_encode, and per-message codec bodies
  (Put / Del / Query / Reply / Err).
- **Phase B+**: SCE schema extensions (test-vector multi-arg) and
  external ratify dependencies.

Round-by-round decisions live in the atomic changelog
(docs/.atomic/workspace.atomic.json) and the activity log
notes/NEXT_SESSION.md.

## Directory layout

| Path | Role |
|---|---|
| ARCHITECTURE.md | Design entry point |
| docs/ | 11 Mnemosyne-managed spec docs |
| docs/.atomic/ | Atomic-store sidecar (mutate only via typed primitives) |
| docs/GENERATED.md | Cascade-rendered output (gitignored, never edit) |
| sources/ | SCE Forge input SCXML (see sources/README.md) |
| scripts/ | build-sce.sh + verify-codegen.sh |
| vendor/sce/ | SCE submodule, vendor pin |
| notes/ | Activity-log genre (outside Mnemosyne) |
| .githooks/ | pre-commit / commit-msg / pre-push gates |
| deploy/ | deploy.yaml skeletons (Phase B+) |

## Build and verify

The SCE codegen binary builds from the vendored submodule.

```sh
git submodule update --init --recursive
./scripts/build-sce.sh
```

Verify a single SCXML against all six backends (Layer 1).

```sh
./scripts/verify-codegen.sh sources/algorithms/crc16_ccitt.scxml
```

If the SCXML has an upstream-paired fixture, pass it as the
second argument to enable byte-golden diff (Layer 2 —
traceability-anchor normalization, then body equivalence).

```sh
./scripts/verify-codegen.sh \
  sources/algorithms/keyexpr_intersect.scxml \
  vendor/sce/tests/forge/resources/algorithm_keyexpr_intersect_exact.scxml
```

## Local CI gates

Install once after clone.

```sh
git config core.hooksPath .githooks
```

Three hooks are then active.

- **pre-commit** — runs `mnemosyne-cli validate-workspace`
  (cross-ref orphan + round-trip + atomic ledger drift gates).
- **commit-msg** — enforces COMMIT_FORMAT.md (subject + body
  72-byte lines, no emoji, no co-author, no wrapped bullets).
- **pre-push** — re-validates at push time to catch manual edits,
  amends, and rebases that pre-commit would not see.

`pre-commit` and `pre-push` require `mnemosyne-cli` on PATH.

```sh
cargo install --path /path/to/mnemosyne/crates/mnemosyne-cli
```

## License

This repo is **dual-licensed**.

- **LGPL-3.0-or-later** — free tier under the usual LGPL-3
  obligations (including anti-tivoization). Full text in
  LICENSE-LGPL-3.0.md and LICENSE-GPL-3.0.md.
- **LicenseRef-watching-zenoh-Commercial** — paid tier with a
  five-way exemption. Full text in LICENSE-COMMERCIAL.md.

The LICENSE file is the entry overview.

Author-side source files (SCXML, Rust, C, header, deploy YAML)
carry the SPDX header:

```
SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
```

Generated files (`out/**`) carry the SCE-emitted MIT header.
Vendored third-party code keeps its original SPDX header and is
recorded in a top-level THIRD_PARTY.md ledger (created when the
first vendored snippet lands).

## External references

- SCE (build infrastructure): scxml-core-engine
  - https://github.com/newmassrael/scxml-core-engine
- Mnemosyne (atomic-store + GENERATED.md lifecycle): mnemosyne
  - https://github.com/newmassrael/mnemosyne
- zenoh upstream
  - https://github.com/eclipse-zenoh/zenoh
- zenoh-pico upstream
  - https://github.com/eclipse-zenoh/zenoh-pico

## Contributing

The SSOT contract, atomic-store lifecycle, and SPDX header
policy are core to this project. New contributors should read
CLAUDE.md — it is framed as the AI-agent operating guide, but
the governance rules apply equally to human contributors.
Decisions land as atomic changelog Round entries; activity
notes live in notes/NEXT_SESSION.md.

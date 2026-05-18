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

## Current status

Snapshot last refreshed at Round 116 (2026-05-18). The atomic
changelog under docs/.atomic/ has the latest per-round delta.

- **Phase A** (author-side SCXML primitives — algorithms): CLOSED.
  9 algorithm-kind SCXML files verified across all six backends
  (CRC16, VLE u64 decode, VLE byte length, KeyExpr
  intersect/includes, extension dispatch, MID validators for
  scouting / session / network / declare-sub / payload-Z).
- **Phase B** (codec catalog): closed for the wire-spec subset.
  19 wz-emitted codecs cover the full transport + network +
  declaration envelope set: 5 transport MIDs (INIT / OPEN / CLOSE /
  KEEP_ALIVE / FRAME), 7 network MIDs (REQUEST / PUSH /
  RESPONSE_FINAL / OAM / INTEREST / RESPONSE / DECLARE), 9
  declaration sub-MIDs (DECL_KEXPR + sub-types and their UNDECL
  pairs + DECL_FINAL), plus the shared codecs (ext_envelope /
  ext_entry / ext_unit / ext_zint / ext_zbuf / wireexpr / locator /
  hello / scout / encoding / timestamp / fragment / msg_put /
  msg_del / interest_body / reply / err / open_body / init_body /
  join). Every envelope has byte-equivalent Layer 3 wire-interop
  vs zenoh-pico `_z_*_encode` (see
  crates/wz-integration-tests/tests/layer3_*.rs).
- **Phase C** (session-FSM + integration): unicast track in
  flight. session_fsm_unicast.scxml carries the 4 timer events
  (link.open_timeout=5s / init_ack.timeout=2s /
  open_ack.timeout=2s / closing.timeout=100ms) plus the
  Init→Established and the close paths; the wz-runtime-tokio
  crate wires the FSM to a tokio LinkDriver via session_glue.rs.
  Cookie HMAC-SHA256 (RFC 4231 TC1-TC7) verified at R70.
  Scouting / multicast / reassembly tracks deferred to later
  rounds.
- **Phase W** (lwIP / MCU runtime): not started. R58 NOP-stub
  reverted at R63 (no document-around-hack); reintroduction
  blocked on AP MVP demo binary closure.
- **AP MVP demo binary** (next milestone): Linux + tokio peer
  doing round-trip query against an external zenoh-pico CLI
  process. 3-5 rounds expected.

Round-by-round decisions live in the atomic changelog
(docs/.atomic/workspace.atomic.json). Currently at 134 entries
across 214 atomic sections; 159 workspace tests pass; the
local 6-lane CI (Layer 0 / A / A2 / B / C1 / C2 / D in
scripts/run-ci.sh) mirrors the GitHub Actions workflow.

## Directory layout

| Path | Role |
|---|---|
| ARCHITECTURE.md | Design entry point |
| docs/ | 12 Mnemosyne-managed spec docs |
| docs/.atomic/ | Atomic-store sidecar (mutate only via typed primitives) |
| docs/GENERATED.md | Cascade-rendered output (gitignored, never edit) |
| sources/ | SCE Forge input SCXML (codecs + algorithms + session FSM) |
| crates/ | wz-codecs / wz-runtime-tokio / wz-integration-tests / -test-support / zenoh-pico-sys |
| scripts/ | build-sce.sh + verify-codegen.sh + run-ci.sh + audit-mid-values.sh |
| vendor/sce/ | SCE submodule, vendor pin |
| .githooks/ | pre-commit / commit-msg / pre-push gates |
| deploy/ | deploy.yaml skeletons (ap_standalone / mcu_target / ap_mcu_pair) |

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

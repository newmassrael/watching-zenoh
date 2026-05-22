<!--
SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
-->

# watching-zenoh

> 한국어 / Korean translation: see README.ko.md

A six-backend codegen implementation of a wire-spec subset of
the zenoh protocol, targeting both embedded (zenoh-pico) and
server (zenoh) interop. Source of truth lives in SCXML, generated
into Rust no_std / C11 / C++ / Kotlin / Go / Python from the same
author-side files.

## What it does

This repo builds two things at once.

1. **Wire compatibility** — a wire-format subset that zenoh-pico
   1.x clients and zenoh 1.x routers / peers exchange.
   The subset scope is pinned in docs/wire-spec-subset.md:
   scouting layer, transport session layer, network routing
   layer, zenoh payload layer, and extension chain mechanism.
   Optional surfaces (compression, patch, full liveliness) are
   deferred to later phases.

2. **Single-source six-backend codegen** — the same SCXML sources
   under sources/ generate to Rust no_std (MCU) / C11 / C++ /
   Kotlin / Go / Python via the SCE Forge toolchain. Conformance
   harnesses exercise all six languages from the same vectors.
   Design RFC lives in docs/rfc-sce-protocol-synthesis.md.

Design SSoT entry is ARCHITECTURE.md. The 12 spec docs under
docs/ are governed by Mnemosyne (atomic-store + GENERATED.md
lifecycle); the operating rules are in CLAUDE.md.

## Current status

Snapshot last refreshed at Round 271 (2026-05-22). The atomic
changelog under docs/.atomic/ has the latest per-round delta.

- **Phase A** (author-side SCXML primitives — algorithms): CLOSED.
  All algorithm-kind SCXML files verified across the six backends
  (CRC16, VLE u64 decode, VLE byte length, KeyExpr
  intersect/includes, extension dispatch, MID validators for
  scouting / session / network / declare-sub / payload-Z).
- **Phase B** (codec catalog): CLOSED for the wire-spec subset.
  35 wz-emitted codecs cover transport (INIT / OPEN / CLOSE /
  KEEP_ALIVE / FRAME), network (REQUEST / PUSH / RESPONSE /
  RESPONSE_FINAL / OAM / INTEREST / DECLARE), declaration
  sub-MIDs (DECL_KEXPR / SUBSCRIBER / QUERYABLE / TOKEN /
  INTEREST / FINAL + UNDECL pairs), payload bodies (Reply / Err /
  MsgPut / MsgDel / Query), and shared infrastructure
  (ext_envelope / ext_entry / ext_unit / ext_zint / ext_zbuf +
  wireexpr / locator / hello / scout / encoding / timestamp /
  fragment / open_body / init_body / join). Every envelope is
  byte-equivalent to zenoh-pico's `_z_*_encode` (Layer 3
  wire-interop tests under
  crates/wz-integration-tests/tests/layer3_*.rs).
- **Phase C** (session FSM + AP runtime): unicast track
  closed. session_fsm_unicast.scxml carries the timer events
  (link.open_timeout=5s, init/open_ack=2s, closing=100ms) plus
  the full Init→Established→Close path. TCP transport complete.
  Cookie HMAC-SHA256 (RFC 4231 TC1-TC7) verified at R70.
  Pub/Sub outbound 100% / inbound 65%. DECLARE outbound 9/9 +
  inbound 6/6 complete. Query/Reply outbound + inbound
  complete, including Request-level qos / tstamp / target /
  budget / timeout extension chain and Response-level responder
  ext via `QueryResponder::with_responder` (R210). Scouting,
  multicast, reassembly, and fragmentation defer to later
  phases.
- **Phase W** (lwIP / MCU runtime): trait skeleton landed at R251
  (wz-runtime-core crate). R58 NOP-stub reverted at R63 — no
  document-around-hack. AP-side TokioRuntime + TokioTime concrete
  impls land alongside real callers across R252+; full lwIP
  integration + Cortex-M cross-compile remain ahead.

Round-by-round decisions live in the atomic changelog
(docs/.atomic/workspace.atomic.json). Currently 270 entries
across 215 atomic sections; the workspace test suites + Layer E
binary-dep e2e fixtures pass via the local 10-lane CI (Layer 0 /
A / A2 / B / C0 / C1 / C1b / C2 / D / E in scripts/run-ci.sh),
mirrored by the GitHub Actions workflow.

## Directory layout

| Path | Role |
|---|---|
| ARCHITECTURE.md | Design entry point |
| docs/ | 12 Mnemosyne-managed spec docs |
| docs/.atomic/ | Atomic-store sidecar (mutate only via typed primitives) |
| docs/GENERATED.md | Cascade-rendered output (gitignored, never edit) |
| sources/ | SCE Forge input SCXML (codecs + algorithms + session FSM) |
| crates/wz-codecs | Generated codec types from sources/codecs/*.scxml |
| crates/wz-runtime-tokio | Tokio-based AP runtime + session glue + builders |
| crates/wz-runtime-lwip | lwIP / MCU runtime headers + tests (Phase W, not yet a workspace member) |
| crates/wz-ap-demo | AP demo binary (initiator + acceptor) |
| crates/wz-integration-tests | Layer 3 wire-interop + round-trip suites |
| crates/wz-runtime-tokio-test-support | Shared test harness for runtime tests |
| crates/zenoh-pico-sys | Vendored zenoh-pico FFI bindings (smoke layer) |
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
Decisions land as atomic changelog Round entries in
docs/.atomic/workspace.atomic.json; cross-session handoff lives
there (no out-of-band activity log).

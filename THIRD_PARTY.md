<!--
SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
-->

# THIRD_PARTY.md — vendored code ledger

Top-level register for third-party code carried inside this
repo as git submodules under `vendor/`. Each entry records the
upstream origin, the pinned commit, the upstream license, and
the scope of use. Updating a vendor pin: bump the entry's
`Commit pin` line and reference the Round entry in the atomic
changelog that authorized the bump.

## vendor/sce — SCXML Core Engine

- **Origin**: https://github.com/newmassrael/scxml-core-engine
- **Commit pin**: `ebf3b3ff` (Round 209, 2026-05-21)
- **License**: dual-licensed — LGPL-2.1 WITH SCE Static Linking
  Exception OR LicenseRef-SCE-Commercial. See
  `vendor/sce/LICENSE` for the full text.
- **Scope of use**: build-time codegen toolchain. The
  `sce-codegen` binary built from this submodule emits Rust /
  C11 / C++ / Kotlin / Go / Python wire-codec source into
  `crates/wz-codecs/out/`. SCE itself is not redistributed in
  binary form by watching-zenoh; the generated output carries
  SCE's own MIT header per the `sce-codegen` generation-time
  policy (see `LICENSE-GENERATED.md`).
- **Upstream-tracking**: Round 209 bumped from `27accb35` to
  `ebf3b3ff` (+9 commits drift; Rust camelCase codegen fixes +
  schema/validator refactors; 8-lane CI regression-zero).

## vendor/zenoh-pico — embedded zenoh client

- **Origin**: https://github.com/eclipse-zenoh/zenoh-pico
- **Commit pin**: `3b3ab65c` (zenoh-pico 1.9.0 +10 commits)
- **License**: Apache-2.0 OR EPL-2.0 (downstream chooses one).
  Full text in `vendor/zenoh-pico/LICENSE` (Apache-2.0) and the
  EPL-2.0 reference in the same file's header.
- **Scope of use**: FFI bindings target for Layer 3 wire-interop
  testing. `crates/zenoh-pico-sys` exposes a smoke-layer FFI
  surface used by `crates/wz-integration-tests/tests/layer3_*.rs`
  to byte-compare watching-zenoh's encoders against zenoh-pico's
  `_z_*_encode` functions. zenoh-pico itself is not redistributed
  as part of watching-zenoh release artefacts; the AP MVP demo
  binary spawns the upstream `z_put` / `z_get` CLI binaries
  separately at runtime when the round-trip integration tests
  exercise inter-implementation round-trip.
- **Upstream-tracking**: pin set during the Layer 3 FFI bring-up
  rounds; bumps follow zenoh-pico release tags rather than main
  branch HEAD.
- **Build-time divergence (R216)**: `scripts/build-zenoh-pico-cli.sh`
  applies an in-place patch to `vendor/zenoh-pico/examples/unix/
  c11/z_put.c` switching the PUT congestion control default from
  upstream's DROP to BLOCK, then reverts the file via
  `git checkout` on exit (success, error, or signal — see the
  `trap restore_z_put EXIT` block). DROP is the upstream default
  per `include/zenoh-pico/api/constants.h::z_internal_congestion_
  control_default_push()` and is correct for sustained
  high-throughput publishers where dropping under back-pressure
  beats head-of-line blocking; it is wrong for a one-shot CLI
  where the only PUT silently dropping on a keep_alive task /
  main thread mutex race (`src/transport/common/tx.c::_z_
  transport_tx_send_n_msg` calls `try_lock` under DROP and
  drops on contention) breaks every Layer E integration test
  that round-trips through `z_put`. Pre-patch flake rate: ~6 %
  standalone, ~20 % under the parallel 5-test Layer E lane.
  The patch is unconditional and applies only to the
  test-harness binary; runtime use of zenoh-pico via
  `crates/zenoh-pico-sys` FFI is unaffected because that path
  links against the upstream library, not the patched example.

## vendor/lwip — lightweight TCP/IP stack

- **Origin**: https://github.com/lwip-tcpip/lwip
- **Commit pin**: `77dcd25a` (STABLE-2_2_1_RELEASE)
- **License**: BSD-3-Clause (modified). Full text in
  `vendor/lwip/COPYING`. SwedishICS copyright notice + 3-clause
  redistribution terms; no copyleft.
- **Scope of use**: Phase W §5.C link tier dependency.
  `crates/lwip-sys` statically compiles the NO_SYS=1 + UDP-minimal
  source set (core/ + core/ipv4/ + netif/ethernet.c) into a
  host-build static library and exposes a bindgen-generated FFI
  surface (6 raw `udp_*` fns + pbuf + netif lifecycle + lwip_init
  + sys_check_timeouts). `crates/wz-link-lwip` (R311az-2) wraps
  the raw FFI into the async LwipLink type via per-link mpsc
  callback-to-async bridge. Cross-compile to MCU targets stays
  the deploy crate's responsibility per R311az-pre D7; lwip-sys
  ships only the host build.
- **Upstream-tracking**: pin set at R311az-1 lands. Bumps follow
  lwIP `STABLE-*_RELEASE` tags rather than master branch HEAD.

## Generated output

Source files under `crates/wz-codecs/out/` are emitted by
`sce-codegen` at build time and carry SCE's MIT header. They are
not authored by watching-zenoh and are not tracked under the
LGPL-3.0 / Commercial license that covers the rest of this
repo. See `LICENSE-GENERATED.md` for the generation-time policy.

## How this ledger is maintained

- A vendor pin bump appends a new Round entry to
  `docs/.atomic/workspace.atomic.json` recording the old and new
  pin, the drift summary, and the verification baseline (CI lane
  results).
- The `Commit pin` line in the entry above is then updated to
  point at the new pin + the Round number.
- A pin bump that changes upstream license terms (rare but
  possible if upstream relicenses) requires a separate
  governance round, not just a pin bump entry.

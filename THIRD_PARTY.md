<!--
SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
- **Scope of use**: codegen toolchain, run out-of-band by the
  `xtask` codegen SSOT (R311y22), not at consumer build time. The
  `sce-codegen` binary built from this submodule emits Rust
  wire-codec / statechart / buffer-pool source into the COMMITTED
  `out/<crate>/` tree (R311y22 committed it in-repo; it is therefore
  redistributed with this repo). SCE itself is not redistributed in
  binary form by watching-zenoh. The generated output carries SCE's
  own MIT header where SCE emits one (statechart `*_sm.rs`) and no
  SPDX header on the codec / pool emits — per the `sce-codegen`
  generation-time policy (see `LICENSE-GENERATED.md` in the SCE repo).
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
  `trap restore_pico_example_patches EXIT` block, renamed from
  `restore_z_put` in R311y240 when a second example patch landed).
  DROP is the upstream default
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
- **Build-time divergence (R311y240 / R311y242 / R311y243 / R311y244 /
  R311y245)**: the same `scripts/build-zenoh-pico-cli.sh` applies a second
  in-place
  patch to `vendor/zenoh-pico/examples/unix/c11/z_sub_attachment.c`,
  inserting `printf` lines for the three Push QoS-byte sub-fields —
  `with priority:` (`z_sample_priority`), `with congestion:`
  (`z_sample_congestion_control`) and `with express:`
  (`z_sample_express`) — plus, under `#ifdef Z_FEATURE_UNSTABLE_API`,
  `with source_info eid: .. sn: ..` (`z_sample_source_info`, guarded
  against a NULL when the sender set none) — into its `data_handler`
  so the CLI reports the received sample's qos byte + source_info (the
  stock example prints encoding / timestamp / attachment but never
  calls those getters). Because `z_sample_source_info` is an UNSTABLE
  getter (vendor default `Z_FEATURE_UNSTABLE_API=0`,
  `CMakeLists.txt:316`), the cmake configure step now passes
  `-DZ_FEATURE_UNSTABLE_API=ON`; the `#ifdef` keeps the file compiling
  if a future config omits it. Enabling the flag alone cascades no
  other feature on and changes no wire behaviour. This makes the CLI
  the foreign witness for watching-zenoh's Push metadata propagation:
  the priority sub-field
  (`crates/wz-integration-tests/tests/wz_priority_to_pico_zsub.rs`,
  R311y240), the congestion + express sub-fields
  (`crates/wz-integration-tests/tests/`
  `wz_qos_congestion_express_to_pico_zsub.rs`, R311y242) and
  source_info
  (`crates/wz-integration-tests/tests/wz_source_info_to_pico_zsub.rs`,
  R311y243). All Push-side lines land in one atomic multi-line insert.
  A THIRD in-place patch (R311y244) adds `with query source_info eid:
  .. sn: ..` (`z_query_source_info` + a NULL check) to `z_queryable.c`'s
  query handler, so the CLI also witnesses wz's QUERY-carrier source_info
  (`crates/wz-integration-tests/tests/`
  `wz_query_source_info_to_pico_zqueryable.rs`). Unlike the
  z_sub_attachment source_info line, this one carries NO
  `#ifdef Z_FEATURE_UNSTABLE_API` guard: `z_query_source_info` +
  `z_source_info_id` / `z_source_info_sn` are declared unconditionally
  (`primitives.h:1013` / `:1156`), whereas the Put carrier's
  `z_sample_source_info` is UNSTABLE-gated (`:2218` block). R311y548
  EXTENDS that same third patch with `with query encoding: ..`
  (`z_query_encoding` + `z_encoding_to_string`, also declared
  unconditionally), so the CLI additionally witnesses the encoding a
  querier attached to its query value
  (`crates/wz-integration-tests/tests/zenoh_c_capi_c_pico_interop.rs`,
  `a_wz_capi_c_get_encoding_reaches_a_real_pico_queryable_as_it_does_on_libzenohc`).
  R311y547 had recorded that half as a NON-CLAIM on the grounds that no
  pico example rendered it — true of the STOCK example, and not a
  property of pico, since the accessor has always been there.
  A FOURTH in-place patch (R311y245) adds `with reply source_info eid:
  .. sn: ..` (`z_sample_source_info` on the reply sample + a NULL check,
  under `#ifdef Z_FEATURE_UNSTABLE_API` — a Reply body IS a Put
  push-body, so the same UNSTABLE getter reads it) to `z_get.c`'s reply
  handler, witnessing wz's REPLY-carrier source_info
  (`crates/wz-integration-tests/tests/`
  `wz_reply_source_info_to_pico_zget.rs`).
  The z_sub_attachment anchor is the `// Check timestamp` comment, the
  z_queryable anchor is `// Process value`, and the z_get anchor is the
  reply-ok branch's `z_drop(z_move(replystr));` cleanup; unlike the R216
  z_put patch (whose anchor `z_put(.., NULL)` is consumed by its own
  edit, so a leftover patch fails the anchor grep and errors loudly),
  those anchors survive the insert — so the script hard-rejects a run
  where the respective marker is already present (a dirty submodule tree
  from a missed revert) rather than silently double-inserting. The four
  example patches (z_put / z_sub_attachment / z_queryable / z_get) share
  the single `trap restore_pico_example_patches EXIT` handler (bash keeps
  one EXIT trap), which reverts all four files via `git checkout` on
  exit. Same harness-only scope as the R216 patch: runtime FFI use via
  `crates/zenoh-pico-sys` is unaffected.

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

## vendor/freertos-kernel — FreeRTOS real-time kernel

- **Origin**: https://github.com/FreeRTOS/FreeRTOS-Kernel
- **Commit pin**: `dbf70559b` (tag `V11.1.0`)
- **License**: MIT. Full text in `vendor/freertos-kernel/LICENSE.md`.
  Permissive; no copyleft.
- **Scope of use**: LAYER-2 RTOS port (track 3). `crates/freertos-sys`
  statically compiles the kernel core (`tasks.c` + `list.c` + `queue.c`)
  + the `portable/GCC/ARM_CM3` (ARMv7-M / Cortex-M3) port + `heap_4.c`
  for the **cooperative single-task profile** (configUSE_TIMERS=0 /
  event-groups / stream-buffers / co-routines off; one task hosts the
  wz cooperative async executor — the FreeRTOS analogue of zenoh-pico's
  Z_FEATURE_MULTI_THREAD=0 single-thread mode). Real C build only on a
  bare-metal Cortex-M cross target (the ARM_CM3 port is hardware-specific
  and cannot compile on a host x86 toolchain); host builds emit no
  static lib. `crates/wz-runtime-freertos` (the `impl Runtime`) wraps the
  hand-written FFI surface (xTaskCreate / vTaskStartScheduler / vTaskDelay
  / xTaskGetTickCount / pvPortMalloc + the ARMv7-M port exception
  handlers). FreeRTOS is redistributed in source form via the submodule;
  the compiled kernel links into the MCU deploy binary only.
- **Upstream-tracking**: pin set when the freertos-sys foundation lands.
  Bumps follow FreeRTOS-Kernel `V*` release tags rather than main HEAD.

## Generated output

Source files under `out/<crate>/` (e.g. `out/wz-codecs/`,
`out/wz-session-core/`) are emitted by `sce-codegen` / the `xtask`
codegen SSOT and, as of R311y22, are COMMITTED in-repo (regenerated
out-of-band, not at consumer build time; gated by run-ci Layer B2).
They carry SCE's MIT header where SCE emits one (statechart `*_sm.rs`)
and no SPDX header on the codec / pool emits. They are not authored by
watching-zenoh and are not tracked under the AGPL-3.0 / Commercial
license that covers the rest of this repo. See `LICENSE-GENERATED.md`
in the SCE repo for the generation-time policy.

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

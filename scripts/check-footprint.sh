#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# check-footprint.sh — composable-framework footprint regression gate.
#
# R311bl mechanical gate. R311bj caveat (a)+(b) anchored the
# preset-cortex-m4-default footprint as a Round-N record but the
# values stay static unless a fresh Layer Q build measures them
# against a baseline. This script does the comparison so silent
# footprint creep (text drift / data drift) lands as a Layer Q
# FAIL instead of a successful Round N+k that quietly grew the
# composable-framework binary surface.
#
# North-star anchor: project_north_star Footprint test = "≥256
# bytes ROM reduction measurable when an atomic feature is
# disabled". The same 256-byte threshold is the per-axis tolerance
# band here, so a per-atomic-feature regression hits the gate at
# the same granularity the feature decomposition is decided.
#
# Axes:
#   text + data  — ROM axes. Hard gate, ±TOLERANCE bytes per axis.
#   bss          — RAM axis. Informational only. Per R311bj caveat
#                  (c) bss is dominated by HEAP_SIZE (256 KB
#                  embedded-alloc region) — a real preset deploy
#                  shrinks this and the baseline would drift on
#                  purpose. RAM regression detection belongs to a
#                  separate gate driven by lwIP MEM_SIZE +
#                  BoxFuture-per-spawn budget, not to this script.
#
# Usage:
#   scripts/check-footprint.sh <target-triple> [artifact]
#
# artifact (default `qemu-demo`):
#   qemu-demo      — deploy/mcu-qemu-demo (the bare lwIP UDP floor; §6.7)
#   multicast-e2e  — deploy/mcu-multicast-e2e (the full multicast profile;
#                    R311mi). mps2-class targets only.
#
# Exit codes:
#   0  PASS (within band, or SKIP)
#   1  FAIL (out of band)
#   2  setup error (unknown target / bad argument)
set -uo pipefail

# ─── baseline ───────────────────────────────────────────────────────
#
# Per-target-triple baseline. Authoritative source: R311bj caveat
# (a)+(b) on §feature-inventory--composable-framework-atomic--
# preset-catalog/6-presets/6-7-preset-cortex-m4-default. Update
# both this table AND the §6.7 caveat together via a new Round
# entry — never one without the other (atomic ledger + CI gate
# must record the same footprint truth).
# shellcheck disable=SC2034  # resolved through the `declare -n _bt/_bd/_bb`
                            # namerefs in the `case "$artifact"` dispatch below; shellcheck
                            # cannot follow a nameref, so the use is invisible to it.
declare -A BASELINE_TEXT=(
    # R311bq — thumbv6m baseline drops from 23660 -> 18584 (-5076 B)
    # because the microbit deploy now goes through the sync-only main
    # branch (cfg(not(target_has_atomic = "32")) in main.rs). The async
    # path's CoopRuntime + spawn wrapper + executor + timer queue
    # symbols are no longer referenced from .text, so LTO + dead-code
    # elimination drops them. The new figure is the honest "lwIP +
    # cortex-m-rt + portable-atomic + LwipUdpSocket<128, 2> sync
    # send/recv" baseline for nrf51-class deploys.
    #
    # R311iu — all four targets rebased upward for the R311ir lwIP IGMP
    # feature (scout multicast RX, udp/224.0.0.224:7446). LWIP_IGMP=1
    # links igmp.c into every runtime-coop build via netif_set_up ->
    # igmp_start, independent of whether the Rust side ever joins a
    # group, so the cost is unconditional on this demo. Symbol-level
    # attribution on the thumbv7m ELF: 761 B of igmp_* .text (igmp_send
    # 164 / igmp_input 152 / igmp_lookup_group 76 / igmp_tmr 72 /
    # igmp_start 52 / igmp_init 28 / ...), the balance being the ip4
    # multicast-input path + the lwIP cyclic timer table entry + the
    # netif IGMP wrappers. thumbv6m grows more (+1024 vs +896) because
    # ARMv6-M lacks Thumb-2 so the same IGMP C compiles to more
    # instructions. Was: 18584 / 23652 / 23724 / 24548.
    #
    # R311y17 — rebased after the R311y15 monotonic-clock fix in
    # deploy/mcu-qemu-demo/src/main.rs. SystickClock gained a `last_us`
    # AtomicU64 monotonic floor (now_us() clamps its raw wraps-based
    # reading up to the max previously returned) to honour the
    # ClockSource monotonic contract; that 64-bit CAS clamp is emitted at
    # both now_us call sites (sys_now + SystickClockRef), growing demo
    # .text by ~216 B on CI's arm-none-eabi-gcc (+304 on thumbv7m put it
    # out of the +-256 band). text-only growth (data flat; bss INFO).
    # Was: 19608 / 24548 / 24636 / 25460 (R311iu).
    #
    # R311y21 — rebased after the SystickClock SSOT extraction into
    # wz-mcu-clock. The reload counter widened AtomicU32 -> AtomicU64 (the
    # 49.7-day overflow-freeze fix): on ARMv7-M (M3/M4/M7/M33) the 64-bit
    # atomic has no native instruction, so the ISR fetch_add + the two
    # now_us snapshot loads route through critical-section, growing mps2
    # .text by ~456..500 B (local arm-none-eabi-gcc). thumbv6m barely moves
    # (+8) because ARMv6-M already pays critical-section for every atomic
    # width, so the u32->u64 widening is free there. text-only growth
    # (data flat; bss INFO, +4 on thumbv6m for the wider static).
    # Local-gcc figures; a CI-gcc follow-up rebase may shift them <=256 B
    # per the footprint-baseline-CI-gcc rule. Was: 19764 / 24852 / 24920 /
    # 25744 (R311y17).
    #
    # R311y267 — REBASED ONTO A REPRODUCIBLE MEASUREMENT, and the "CI-gcc
    # follow-up rebase" rule the R311y21 note above cites is RETIRED as false.
    # arm-gcc was never the variable: the CI runner and this dev host carry the
    # byte-identical gcc 10.3.1 / binutils 2.38 / newlib 3.3.0 packages. The
    # two real variables were (1) an UNPINNED rustc in hosted CI, which floated
    # 1.96 -> 1.97 on 2026-07-09 and moved codegen, and (2) ABSOLUTE BUILD PATHS
    # embedded in .rodata (which berkeley `size` counts as `text`), so the
    # number partly measured the build directory's path length. Both are now
    # removed by construction: rust-toolchain.toml pins the compiler, and Layer Q
    # builds with --remap-path-prefix (re-asserted per measurement by the
    # path-normalisation gate below, which FAILs rather than silently measuring
    # a path-polluted binary). All four figures are confirmed byte-identical on
    # the hosted runner (R311y268 read them back from the first green Layer Q).
    # Was: 19772 / 25352 / 25420 / 26200 (R311y21, path-polluted local-only
    # figures).
    ["thumbv6m-none-eabi"]=19780
    ["thumbv7m-none-eabi"]=25296
    ["thumbv7em-none-eabihf"]=25360
    ["thumbv8m.main-none-eabi"]=26148
)
# shellcheck disable=SC2034  # resolved through the `declare -n _bt/_bd/_bb`
                            # namerefs in the `case "$artifact"` dispatch below; shellcheck
                            # cannot follow a nameref, so the use is invisible to it.
declare -A BASELINE_DATA=(
    ["thumbv6m-none-eabi"]=4
    ["thumbv7m-none-eabi"]=4
    ["thumbv7em-none-eabihf"]=4
    ["thumbv8m.main-none-eabi"]=4
)
# shellcheck disable=SC2034  # resolved through the `declare -n _bt/_bd/_bb`
                            # namerefs in the `case "$artifact"` dispatch below; shellcheck
                            # cannot follow a nameref, so the use is invisible to it.
declare -A BASELINE_BSS=(
    # R311iu — +184 B uniform across all targets: the IGMP memp pool
    # (memp_memory_IGMP_GROUP_base 131 B + memp_tab_IGMP_GROUP 4 B +
    # ip4_default_multicast_netif 4 B + netif IGMP state). Target-
    # independent static pool, which is why the delta is identical on
    # the slim M0+ <128, 2> socket and the mps2 <1500, 8> default. bss
    # is INFO-only (HEAP_SIZE-dominated, R311bj caveat (c)); rebased for
    # an honest INFO delta. Was: 11868 / 269916 / 269916 / 269916.
    # R311y20 — rebased to the measured value (INFO axis, but the script's own
    # table+caveat co-maintenance rule means a recorded number must not be left
    # knowingly stale). +8 B from the R311y15 SystickClock `last_us` AtomicU64
    # static; the larger mps2 delta (270100 -> 272268) is accumulated lwIP/pool
    # drift since R311iu. Was: 12052 / 270100 / 270100 / 270100.
    # R311y21 — thumbv6m +4 (12060 -> 12064): the reload counter widened to
    # AtomicU64 in the wz-mcu-clock SSOT (4 extra static bytes). mps2 flat.
    ["thumbv6m-none-eabi"]=12064
    ["thumbv7m-none-eabi"]=272268
    ["thumbv7em-none-eabihf"]=272268
    ["thumbv8m.main-none-eabi"]=272268
)

# ─── multicast-e2e baseline ─────────────────────────────────────────
#
# The `multicast-e2e` artifact (deploy/mcu-multicast-e2e) links the FULL MCU
# multicast feature profile (session-lwip + transport-multicast +
# transport-fragmentation + codec-push) via run_multicast_e2e. Authoritative
# source: the §6.9 preset-mcu-multicast-pub footprint caveats (R311mj gave the
# profile a living preset Section, mirroring §6.7's anchor for the
# cortex-m4-default artifact; the figures originate from R311mi). Update this
# table AND the §6.9 footprint caveats together via a new Round entry — never
# one without the other (atomic ledger + CI gate record the same footprint
# truth), exactly as §6.7 governs the qemu-demo table.
#
# mps2-class only (M3 / M4 / M7): the 32 x 1536 multicast rx pool (~49 KB,
# slim-toggle-independent) does not fit nrf51's 16 KB SRAM, so there is no
# thumbv6m baseline (a slim multicast pool is a deferred item). .text is the
# multicast transport's ROM over the bare-UDP floor (~50 KB vs mcu-qemu-demo's
# ~20 KB); data the static .data; bss the 256 KB heap + lwIP/IGMP pools
# (HEAP_SIZE-dominated, INFO-only per the R311bj caveat (c)).
# shellcheck disable=SC2034  # resolved through the `declare -n _bt/_bd/_bb`
                            # namerefs in the `case "$artifact"` dispatch below; shellcheck
                            # cannot follow a nameref, so the use is invisible to it.
declare -A BASELINE_MC_TEXT=(
    # R311mi — initial measurement (cross-test lwIP port, opt-level=s + LTO).
    # R311pr — rebased after multicast/session feature accretion since R311mi
    # (R311mp~ns: publish/subscribe SSOT, Session typestate, seam refactors,
    # declare routing). text-only growth (data/bss flat), verified feature-driven
    # by symbol breakdown + 23-commit closure log; not a leak. Old: 50680/50484.
    # R311wz — SHRANK after the SCE pin bump to ba65f7a1b: the VLE 9-byte-cap fix
    # moved each codec's inline LEB128 emit to one shared runtime write_vle_uN
    # call, so the codec-heavy multicast binary lost duplicated VLE loops.
    # text-only reduction (data/bss flat); a code-size improvement, not a leak.
    # Old: 51260/51320 (R311pr).
    # R311y21 — GREW after the SystickClock SSOT extraction into wz-mcu-clock:
    # this bin GAINED the monotonic floor (it carried the pre-R311y15 floorless
    # copy) AND the AtomicU32 -> AtomicU64 reload-counter widening, both routed
    # through critical-section on ARMv7-M; +444 (M3) / +560 (M4F) local
    # arm-none-eabi-gcc. text-only growth (data flat); a CI-gcc follow-up rebase
    # may shift these <=256 B. Old: 50292/50328 (R311wz).
    # R311y215 — GREW after the transport-qos per-priority QoS transport: the
    # reassembly ChainKey / Fragment descriptor, InboundFrame::{Frame,Fragment},
    # and DriverLoopOutcome::{Fragment,RxSnRejected} carry a `priority`
    # UNCONDITIONALLY (DEFAULT-keyed on this non-qos multicast build — transport-qos
    # is alloc-only, never enabled on MCU), plus the ext_qos ext-chain projection
    # (ext_qos_priority) compiles into the inbound decode. text-only growth
    # (data/bss flat), +200 (M3) / +260 (M4F): the uniform priority data-path is
    # kept cfg-free by design (no per-feature cfg-skew; the MCU pays the named
    # faithfulness-over-cost debt paid down later via the systematic Ownership seam,
    # not per-feature gating). Old: 50736/50888 (R311y21).
    # R311y267 — REBASED ONTO A REPRODUCIBLE MEASUREMENT. This artifact is where
    # the defect surfaced: hosted CI's Layer Q was red for ~20 pushes (from
    # e81d7a50, 2026-07-09) on a multicast .text the local pre-push run-ci read
    # as in-band. The code never regressed. Two environment variables were being
    # measured as if they were code — an unpinned rustc in CI (1.96 -> 1.97 on
    # the very day the streak began) and the absolute build path embedded in
    # .rodata. The same commit + same rustc measured 50964 built at /w, 51164 at
    # /home/coin/watching-zenoh and 51344 at the runner's
    # /home/runner/work/watching-zenoh/watching-zenoh — a 380 B spread on
    # identical code against this +-256 B band, ordered purely by path length.
    # rust-toolchain.toml + Layer Q's --remap-path-prefix remove both. thumbv7m
    # is byte-identical everywhere (50956 on this host, in a runner-path
    # container, and on the runner itself).
    #
    # thumbv7em-hf carries a KNOWN +4 B RESIDUAL: the runner reads 51100 against
    # this host's 51096. R311y268 root-caused it by ELF diff — .rodata is
    # IDENTICAL (the path-length term really is gone; that was the 380 B one) and
    # the 4 B is .text alignment jitter, because cargo derives a crate metadata
    # hash from the package PATH, which perturbs symbol hashes and thus padding.
    # It is not proportional to path length (5 of the 6 gated axes are +0) and is
    # 1.5% of the band, so it is carried, not chased. Do NOT read "reproducible"
    # as "bit-identical": the unbounded term is eliminated, a few bytes of layout
    # jitter are not. Old: 50936/51148 (R311y215, path-polluted local figures).
    # R311y519 — GREW after the R311y510 SCE pin bump to 43695e572, and the
    # bytes are NAMED rather than absorbed. `18d2d870^` measures 50956 (+0, the
    # figure below) and `18d2d870` measures 51368; the entire +412 is that one
    # commit, with nothing since contributing. Per-symbol ELF diff of the two
    # builds:
    #   +1020 / -974  MsgPut::try_into_owned -> try_into_owned_in::<Heap>
    #    +470         wz_session_core::network_message::parse_frame_payload
    #    -176         the heapless IntoIter collect-shunt it absorbed by inlining
    #    +286 / -286  WireexprVariant (byte-neutral rename)
    #    +164 / -142  ExtEntryVariant
    # So the storage-profile RENAME is near byte-neutral; the real term is the
    # decode path re-inlining around the new generic seam. Total `t` symbols
    # 46150 -> 46552 (+402) against a +412 section delta.
    #
    # NOT a leak, and the semantic half was checked rather than assumed: the
    # emit resolves `SceString<128>`/`SceBytes<256>` to `HeapStr`/`HeapBytes`
    # because the generated `try_into_owned` picks "growable where an allocator
    # exists, inline on the heap-free tier", and THIS artifact deliberately
    # carries a `#[global_allocator]` (embedded-alloc, `deploy/mcu-multicast-e2e`
    # manifest + `main.rs`). bss is unchanged at 272268 on both axes. The
    # heap-free MCU artifacts do not take this term.
    #
    # Both axes are byte-identical to the runner again (thumbv7m 51368, hf
    # 51288 measured here and on the hosted job), so R311y267's reproducibility
    # property survives the bump. Old: 50956/51096 (R311y267).
    #
    # R311y582 — rebased for the A1 ext-chain work, and the total is ATTRIBUTED
    # rather than absorbed, because only part of it belongs to this round. Three
    # measurements on this host, same toolchain (rustc 1.97.0 / gcc 10.3.1),
    # `bash scripts/run-ci.sh --layer Q` each time:
    #
    #   | tree                              | thumbv7m | hf    |
    #   |-----------------------------------|----------|-------|
    #   | at this baseline, no A1 changes   | 51584    | 51428 |
    #   | + the chain-saturation check      | 51888    | 51660 |
    #   | + max-depth 4 -> 8 (this rebase)  | 52064    | 51840 |
    #
    # So of the +696 / +552 against the old figure: +216 / +140 was ALREADY
    # THERE and belongs to some round between R311y357 and R311y581 — the
    # +-256 band absorbed it silently, and the next change to touch this
    # artifact was always going to pay the accumulated total. That is a
    # property of a tolerance band worth stating: it hides drift up to the
    # band width, and hands the bill to whoever arrives next.
    #
    # This round's own share is +480 / +412, in two parts. +304 / +232 is the
    # chain-saturation check at the network dispatch seam, which stops a wz
    # node acting on a message whose extension chain never terminated (a
    # SILENT misread today, not an error — see
    # `wz-session-core::ext_chain::chain_saturated`). That is correctness and
    # is not negotiable against ROM. The remaining +176 / +180 is `max-depth`
    # 4 -> 8 across the fifteen entry-flag chains in `sources/codecs/*.scxml`,
    # which buys tolerance: wz can now READ a message carrying five to eight
    # extensions rather than only refuse it safely. It also removes an
    # unexplained asymmetry — the transport chain has read 8
    # (`parse_error::MAX_EXT_CHAIN_DEPTH`) since R68c while the network and
    # payload chains read 4.
    # R311y592 — REBASED, and the bytes are ATTRIBUTED TO ONE COMMIT rather than
    # to "the arc". Hosted CI went red on `de5b8175` at hf=52124 (+284); the same
    # Layer Q on this host reads 52124 too, byte-identical, so R311y267's
    # reproducibility property held and the growth is CODE, not environment.
    #
    # Bisected by building `--layer Q` at each commit of the y589..y591 arc:
    #
    #   | commit                                    | hf    | delta |
    #   |-------------------------------------------|-------|-------|
    #   | 24c2f624 (at the y582 baseline)           | 51840 |    +0 |
    #   | 6bc3d3df the ext-chain cliff removal      | 51700 |  -140 |
    #   | b0b94672 the ChainStaging seam            | 52124 |  +424 |
    #   | cb4890e5 io_uring / 07a721b2..de5b8175    | 52124 |    +0 |
    #
    # So the cliff removal SHRANK this artifact and the whole overshoot is one
    # commit: `b0b94672`, which made `ReassemblyDispatcher` generic over a
    # `ChainStaging` arena so `preset-ap-full` can reserve its reassembly memory
    # up front. Per-symbol ELF diff of `6bc3d3df` vs `b0b94672` (arm-none-eabi-nm
    # -S, `t`/`T` only) names +266 of the +424:
    #
    #   +178  __cortex_m_rt_main            (the inlined dispatcher body)
    #   +108 / -64  Slot::release           (now takes `&mut S` to hand the
    #                                        chain's staging back to the arena)
    #    +90 / -90  HeapStaging::append vs the old private `stage::<1000>` (net 0)
    #    +38  core::option::expect_failed   (NEW — see the debt note below)
    #     +6  ReassemblyDispatcher::abort_channel
    #
    # The remainder is padding / .rodata layout.
    #
    # INTENTIONAL, and stated precisely: this artifact never instantiates the
    # reserved arena. It runs the default `HeapStaging`, whose module doc calls
    # itself "byte-for-byte the pre-seam behaviour" — true of SEMANTICS (the
    # bytes still land in one growable buffer per chain, the explicit CAP
    # comparison is preserved, and Q.6 boots and passes on all three mps2 boards)
    # and false of ROM by 424 bytes on hf / 8 on thumbv7m. A generic seam is not
    # free at the instantiation site even when the instantiation is the old
    # behaviour. That is the cost of putting the deploy decision behind a trait,
    # and it is accepted here rather than absorbed silently.
    #
    # NAMED DEBT, not paid in this round: 38 of those bytes are
    # `core::option::expect_failed`, i.e. a PANIC-FORMATTING path this MCU binary
    # did not carry before. It arrives because `Slot` now stores `key: Option<_>`
    # and `chain: Option<S::Chain>` — ONE fact in two Options, whose agreement the
    # four new `.expect("a completed chain has staging")` sites assert at runtime.
    # Folding them into a single `Option<Armed<S>>` would delete both the
    # duplicated invariant and the panic path. Left undone deliberately: it is a
    # dispatcher-wide refactor and it does not on its own bring hf back inside the
    # +-256 band (424 - 38 = 386).
    #
    # thumbv7m: 52072 here / 52068 hosted. The 4 B spread is the R311y268
    # crate-metadata alignment jitter, carried as documented. The hosted figure is
    # recorded below because the hosted job is the gate that blocks main.
    # Old: 52064/51840 (R311y582).
    #
    # R311y607 — REBASED for the multicast JOIN decode, and the bytes are
    # attributed to ONE commit by measurement rather than to "the y605 arc".
    #
    # This gate was RED ON HOSTED CI FOR TWO ROUNDS before anyone read it.
    # R311y605 pushed the growth and did not read its run; R311y606 DID read
    # that run (31269002927), root-caused Layer C0's `import tomllib`, and
    # stopped there — but C0 and Layer G+Q are SEPARATE JOBS, so G+Q was not
    # among the 29 steps C0 hid. It was independently red and went unnamed.
    # A red run's failures are counted PER JOB, not per hidden step.
    #
    # Bisected by building `deploy/mcu-multicast-e2e` at each commit of the
    # y605 arc on one host, one toolchain, with the R311y267 path remap:
    #
    #   | commit                                   | thumbv7m | delta |
    #   |------------------------------------------|----------|-------|
    #   | 1f7d2f2f (at this baseline, y604 tip)    | 52064    |    +0 |
    #   | 2d9d6918 the multicast JOIN decode       | 52584    |  +520 |
    #   | 2c066f95 / 9417acc1 / 183a2e96 (y605)    | 52584    |    +0 |
    #   | 30911aa2 .. 7f7de6c9 (the whole of y606) | 52580    |    -4 |
    #
    # So the entire overshoot is `2d9d6918`, and y606 — the SCE pin bump, the
    # rx_ring ARM half, IP fragment reassembly — contributed NOTHING to it.
    # Per-symbol ELF diff of `1f7d2f2f` vs `2d9d6918` (arm-none-eabi-nm -S):
    #
    #   +466  wz_session_core::join_decode::decode_join_body   (NEW)
    #   +424  wz_session_core::inbound::parse_inbound          (the JOIN arm)
    #   -442  __cortex_m_rt_main                               (re-inlining)
    #   +258/-258  .Lanon .rodata (byte-neutral, hash renamed)
    #
    # INTENTIONAL: this artifact is the MULTICAST profile, and JOIN is the
    # announcement message of zenoh's multicast session group. Before
    # `2d9d6918` it parsed successfully as `Unknown { mid: 7 }` — the ROM was
    # smaller because the binary could not read the one message its own
    # transport mode exists to carry. Paying 520 B to stop misreading it is
    # the trade this artifact exists to make.
    #
    # Hosted figures recorded (the hosted job is the gate that blocks main):
    # 52588 on both axes. This host reads 52580 / 52552 — a -8 / -36 spread
    # that is NOT the R311y268 metadata jitter but arm-none-eabi-gcc 13.2.1
    # here against the pinned 10.3.1 there, which changes the newlib/libgcc
    # objects the link pulls in. Both sit inside the +-256 band against the
    # hosted figure, so one baseline still governs both machines; a local
    # reading is a direction, not an authority. Old: 52068/52124 (R311y592).
    #
    # R311y636 — GREW after R311y633 made the multicast receiver walk its
    # datagram to the end instead of reading only its front. Attributed to ONE
    # commit rather than to an arc: Layer G+Q was green at `1487b071` (y632)
    # and red at `7702864a` (y635), and `7bc26dd6` is the only production-code
    # commit between them — y634 and y635 add tests to wz-integration-tests,
    # which this artifact does not link. Built here at both ends, one host, one
    # toolchain, with the R311y267 path remap:
    #
    #   | commit                                  | thumbv7m | delta |
    #   |-----------------------------------------|----------|-------|
    #   | 1487b071 (y632 tip, at this baseline)   | 52820*   |    +0 |
    #   | 7702864a (y635 tip, the red run)        | 53372*   |  +552 |
    #
    #   (*) un-remapped readings, kept only because both ends were measured the
    #   same way; the remapped lane reads 53096 / 53092 at the second row.
    #
    # Per-symbol ELF diff of those two (arm-none-eabi-nm -S, demangled sums):
    #
    #   +1314  wz_session_core::inbound::parse_inbound_consuming  (NEW here)
    #   -1214  wz_session_core::inbound::parse_inbound            (superseded)
    #    +366  __cortex_m_rt_main                                 (the walk)
    #     +16  .Lanon .rodata                                     (hash rename)
    #
    # INTENTIONAL, and the same trade the R311y605 row above records. A walk
    # needs to know where each message ENDS, so the binary swaps a decoder that
    # cannot say (`parse_inbound`) for one that can (`parse_inbound_consuming`)
    # — that swap, not the loop, is 1300 of the 552 net bytes. Before it, a
    # group member's data frame batched behind its JOIN or its keepalive was
    # dropped by this profile, and zenoh batches by DEFAULT
    # (`zenoh-transport-1.5.0/src/common/pipeline.rs:318`). The ROM was smaller
    # because the binary read one message per datagram and the wire carries
    # more.
    #
    # Hosted figures recorded: 53100 / 53128 — the two axes DIVERGE for the
    # first time on this artifact (28 B), so they are no longer one number.
    # This host reads 53096 / 53092 under the remap: -4 / -36, the same shape
    # the row above records. Old: 52588/52588 (R311y605).
    # R311y878 — GREW when `parse_inbound` learned transport OAM (MID 0x00),
    # and the bytes are NAMED rather than absorbed. Same host, same run, one
    # thing changed: the arm was made unreachable (`T_MID_OAM if false`) and
    # re-measured at 53284 / 53344, so the arm's own body is +480 (M3) / +452
    # (M4F). The rest — ~184 / ~216 against the hosted figures above — is the
    # `InboundFrame::Oam` variant and its plumbing (`kind_name`,
    # `ext_admission`, the `ReservedEncoding` error and its `Display`, the
    # drop-census bucket) plus this host's path jitter, which the row above
    # records as a -4 / -36 spread on identical code.
    #
    # WHY AN MCU PARTICIPANT PAYS IT, since this profile is not an analyzer:
    # `Unknown { mid }` reports a consumed length of ZERO, and the multicast rx
    # path walks a BATCH (`multicast_rx.rs` -> `parse_inbound_consuming`). An
    # OAM it cannot measure therefore stops the walk and drops every message
    # BEHIND it in the same datagram — not just the OAM. The 480 bytes buy the
    # ability to step over one, which is a property of the participant and not
    # of the reader. Measured on the build machine under the Layer Q remap.
    #
    # The figures below are the DELEGATED shape (`decode_oam` and
    # `decode_keep_alive` behind `#[inline(never)]`), which Layer F's codec
    # elision lane required; against the inline shape those attribution
    # readings came from, thumbv7m is -68 and thumbv7em-hf is +0.
    # Old: 53100/53128 (R311y636).
    ["thumbv7m-none-eabi"]=53696
    ["thumbv7em-none-eabihf"]=53796
)
# shellcheck disable=SC2034  # resolved through the `declare -n _bt/_bd/_bb`
                            # namerefs in the `case "$artifact"` dispatch below; shellcheck
                            # cannot follow a nameref, so the use is invisible to it.
declare -A BASELINE_MC_DATA=(
    ["thumbv7m-none-eabi"]=4
    ["thumbv7em-none-eabihf"]=4
)
# shellcheck disable=SC2034  # resolved through the `declare -n _bt/_bd/_bb`
                            # namerefs in the `case "$artifact"` dispatch below; shellcheck
                            # cannot follow a nameref, so the use is invisible to it.
declare -A BASELINE_MC_BSS=(
    # 256 KB heap + lwIP/IGMP static pools. INFO-only (HEAP_SIZE-dominated).
    # R311y21 — rebased 270100 -> 272268 (accumulated lwIP/pool drift, matching
    # the §6.7 mps2 bss the R311y20 demo rebase recorded; +4 of it is the
    # wz-mcu-clock AtomicU64 reload counter). INFO axis; co-maintenance rule.
    ["thumbv7m-none-eabi"]=272268
    ["thumbv7em-none-eabihf"]=272268
)

# Per-axis tolerance in bytes. Matches the north-star atomic-feature
# footprint threshold (≥256 bytes ROM reduction = "measurable").
TOLERANCE=256

# ─── argument parsing ──────────────────────────────────────────────
target="${1:-}"
if [[ -z "$target" ]]; then
    echo "check-footprint: usage: $0 <target-triple> [artifact]" >&2
    echo "  artifact: qemu-demo (default) | multicast-e2e" >&2
    exit 2
fi

# Select the artifact: which binary to size + which baseline table to gate
# against. `qemu-demo` (default) preserves the original single-artifact
# behaviour (the Q.3 lane calls `check-footprint.sh <target>`); `multicast-e2e`
# gates the R311mi multicast footprint bin. namerefs point _bt/_bd/_bb at the
# chosen baseline tables so the measure + gate logic below stays artifact-
# agnostic.
artifact="${2:-qemu-demo}"
case "$artifact" in
    qemu-demo)
        bin="deploy/mcu-qemu-demo/target/${target}/release/mcu-qemu-demo"
        declare -n _bt=BASELINE_TEXT _bd=BASELINE_DATA _bb=BASELINE_BSS
        baseline_anchor="§6.7 preset-cortex-m4-default caveat (a)/(b)"
        ;;
    multicast-e2e)
        bin="deploy/mcu-multicast-e2e/target/${target}/release/mcu-multicast-e2e"
        declare -n _bt=BASELINE_MC_TEXT _bd=BASELINE_MC_DATA _bb=BASELINE_MC_BSS
        baseline_anchor="the R311mi multicast footprint ledger entry"
        ;;
    *)
        echo "check-footprint: unknown artifact '$artifact'" \
             "(qemu-demo | multicast-e2e)" >&2
        exit 2
        ;;
esac

if [[ -z "${_bt[$target]:-}" ]]; then
    echo "check-footprint: no $artifact baseline for target '$target'" >&2
    echo "  add baseline to scripts/check-footprint.sh + matching caveat" \
         "to $baseline_anchor in the same Round entry" >&2
    exit 2
fi

# ─── prerequisite tooling + binary ─────────────────────────────────
#
# R311y274 — WZ_Q_REQUIRE escalates a prerequisite SKIP to a FAIL, mirroring
# WZ_Z_REQUIRE / WZ_QZ_REQUIRE. On the hosted mcu job the toolchain + binutils
# are PROVISIONED, so a missing binary or missing `size` is a provisioning
# regression, not a legitimate host-lacks-the-tool skip — and this gate is the
# whole subject of R311y267, so it must not be the one lane whose SKIP is green.
# Off (a dev host without the cross toolchain) it stays a soft SKIP.
if [[ ! -f "$bin" ]]; then
    if [[ -n "${WZ_Q_REQUIRE:-}" ]]; then
        echo "  footprint[$artifact] $target FAIL — required (WZ_Q_REQUIRE set)" \
             "but binary missing: $bin" >&2
        exit 1
    fi
    echo "  footprint SKIP (binary missing: $bin)"
    exit 0
fi
if ! command -v arm-none-eabi-size >/dev/null 2>&1; then
    if [[ -n "${WZ_Q_REQUIRE:-}" ]]; then
        echo "  footprint[$artifact] $target FAIL — required (WZ_Q_REQUIRE set)" \
             "but arm-none-eabi-size not on PATH" >&2
        exit 1
    fi
    echo "  footprint SKIP (arm-none-eabi-size not on PATH;" \
         "install binutils-arm-none-eabi)"
    exit 0
fi
# The path-purity gate below detects pollution with `strings`; a detection tool
# that is ABSENT must FAIL, never silently pass a polluted binary (R311y274, the
# whole-session review's Finding B2 — proven: with `strings` off PATH the gate
# reported a clean +0 on a binary carrying the repo path). Unconditional: unlike
# the binary/size prereqs there is no legitimate "measure without it" mode.
if ! command -v strings >/dev/null 2>&1; then
    echo "  footprint[$artifact] $target FAIL — strings not on PATH;" \
         "cannot verify path purity (install binutils)" >&2
    exit 1
fi

# ─── path-normalisation gate (the measurement's precondition) ───────
#
# rustc embeds ABSOLUTE build paths in the binary (panic `Location` strings for
# local crates, cargo registry source paths for dependencies). They land in
# .rodata, and the berkeley `size` format counts .rodata inside its `text`
# column — so a binary built without --remap-path-prefix has a `text` that
# partly measures THE LENGTH OF ITS OWN BUILD DIRECTORY PATH. The same commit
# and rustc measured 50964 / 51164 / 51344 on mcu-multicast-e2e depending only
# on where it was built (a container, this dev host, the CI runner): a 380 B
# spread against a +/-256 B band, and the reason Layer Q sat red on hosted CI
# for ~20 pushes while the local pre-push run-ci stayed green.
#
# run-ci.sh Layer Q exports footprint_remap_rustflags() for every MCU build.
# This gate re-asserts the property on the ARTIFACT so the two cannot drift: a
# binary built outside that path (a bare `cargo build`, a future lane that
# forgets the export) FAILS here rather than being silently measured against a
# baseline it is not comparable to. A SKIP would be green — hence a FAIL.
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
leaked=""
for prefix in "$repo_root" "$cargo_home"; do
    if strings "$bin" 2>/dev/null | grep -qF -- "$prefix"; then
        leaked="${leaked:+$leaked, }$prefix"
    fi
done
if [[ -n "$leaked" ]]; then
    echo "  footprint[$artifact] $target FAIL — binary embeds absolute build paths" >&2
    echo "    leaked prefix(es): $leaked" >&2
    echo "    The .rodata path strings make .text depend on WHERE the binary was" >&2
    echo "    built, so this measurement is not comparable to the baseline table." >&2
    echo "    Build the footprint artifacts via 'scripts/run-ci.sh --layer Q'," >&2
    echo "    which exports footprint_remap_rustflags() for exactly this reason." >&2
    exit 1
fi

# ─── measure ───────────────────────────────────────────────────────
# arm-none-eabi-size --format=berkeley output (line 2):
#   text  data  bss  dec  hex  filename
#
# Provenance: the baseline is only meaningful against the toolchain it was
# measured with, so the gate records what it measured with. rustc is pinned by
# rust-toolchain.toml (codegen size drifts across releases — 1.96 -> 1.97 moved
# this binary +48 B); arm-gcc + newlib compile the lwIP C half.
echo "  footprint[$artifact] toolchain: $(rustc --version 2>/dev/null | cut -d' ' -f2)" \
     "/ $(arm-none-eabi-gcc -dumpversion 2>/dev/null)"
read -r meas_text meas_data meas_bss _ < <(
    arm-none-eabi-size --format=berkeley "$bin" \
        | awk 'NR==2 {print $1, $2, $3}'
)

base_text="${_bt[$target]}"
base_data="${_bd[$target]}"
base_bss="${_bb[$target]}"

delta_text=$((meas_text - base_text))
delta_data=$((meas_data - base_data))
delta_bss=$((meas_bss - base_bss))

# Pretty-print with explicit signs so a developer reading the
# Layer Q lane output can see at a glance which axis moved.
fmt_delta() {
    local d="$1"
    if [[ "$d" -ge 0 ]]; then
        echo "+$d"
    else
        echo "$d"
    fi
}

# ─── gate ──────────────────────────────────────────────────────────
fail=0
text_status="OK"
data_status="OK"
if [[ "${delta_text#-}" -gt "$TOLERANCE" ]]; then
    text_status="FAIL"
    fail=1
fi
if [[ "${delta_data#-}" -gt "$TOLERANCE" ]]; then
    data_status="FAIL"
    fail=1
fi

# bss informational-only. ${delta_bss#-} flips sign to absolute for
# display + magnitude comparison if a future gate flips this axis
# from informational to enforcing.
bss_status="INFO"

echo "  footprint[$artifact] $target text=$meas_text ($(fmt_delta $delta_text)) $text_status / data=$meas_data ($(fmt_delta $delta_data)) $data_status / bss=$meas_bss ($(fmt_delta $delta_bss)) $bss_status [tol=±$TOLERANCE]"

if [[ "$fail" -ne 0 ]]; then
    echo "" >&2
    echo "check-footprint: $artifact $target out of band against $baseline_anchor" >&2
    echo "  baseline: text=$base_text data=$base_data bss=$base_bss" >&2
    echo "  measured: text=$meas_text data=$meas_data bss=$meas_bss" >&2
    echo "  tolerance: ±$TOLERANCE bytes per ROM axis" >&2
    echo "" >&2
    echo "If the growth is intentional (new atomic feature, codec," >&2
    echo "  runtime primitive), land a Round N+k entry that:" >&2
    echo "  1. Updates the matching scripts/check-footprint.sh baseline table" >&2
    echo "     (BASELINE_* for qemu-demo, BASELINE_MC_* for multicast-e2e)." >&2
    echo "  2. Updates $baseline_anchor with the new figure + rationale." >&2
    echo "If the growth is unintentional, root-cause the bytes" >&2
    echo "  before landing the change." >&2
    exit 1
fi

exit 0

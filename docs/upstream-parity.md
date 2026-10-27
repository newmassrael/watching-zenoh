# Upstream parity: the wz presets of zenoh, zenoh-c and zenoh-pico, measured against them

## 1. The question

The owner's instruction of 2026-10-26: wz has a preset that corresponds exactly to each of
zenoh, zenoh-c and zenoh-pico, and with that preset wz is better than the original in
performance, in size and in every other measure. The MCU comes first.

Two things are asked, and the second rests on the first. A preset is "exactly
corresponding" only if it carries what the original's own default build carries, no more
and no less, so that a difference in a measurement is the implementation's and not the
feature set's. "Better in every measure" is a claim about measurements. It is made cell by
cell, against an original built by this repository in the same mode on the same host, and a
cell without a same-condition measurement makes no claim.

## 2. What exists (2026-10-26)

- **The host presets.** `configs/zenoh_defconfig`, `configs/zenoh-c_defconfig` and
  `configs/zenoh-pico_defconfig` are generated from `deploy/wz-config.toml`
  (`wz_config.py --emit defconfig:<original>`). Layer C0's `--check-presets` holds each to
  its original's values (23, 23 and 18 capabilities). `wz_config.py --original-features
  <original>` turns each into the cargo arguments of the ABI it is built through.
- **No MCU preset.** `docs/build-configuration.md` section 6 lists
  `configs/zenoh-pico-mcu_defconfig` and leaves it waiting. The MCU images are wz's own
  nodes (`deploy/zephyr-admin-node`, the client on the heap profile and on the fixed-memory
  profile), not the pico C API. The pico C ABI on an MCU is decision C12 and step 5 of
  that document, which has not started. The cooperative engine the pico ABI runs on is a
  host engine (`docs/capi-pico-on-coop-engine.md` D3).
- **Size, host.** `scripts/lib/capability_cost_gate.py` builds each C ABI case, holds it to
  a text budget, and builds zenoh-pico as the same build (`wz_config.pico_reference`) to
  print the ratio. It prints the ratio and does not grade it. It has no zenoh-c reference
  and does not build `--original-features` lines.
- **Size, MCU.** `deploy/resource_budget.json` holds the fixed client's static chain and
  stack peak. `deploy/session_slot_bytes.json` holds the session slot. Neither has a
  reference.
- **Performance.** No gate. `scripts/pico-compare.sh` builds the upstream pico examples
  against pico and against `libwz_capi_pico` on a host and prints round trip and
  throughput, by hand. On the MCU, `scripts/kit-lane.sh` runs wz images on the T2G kit and
  holds each to its own row. The pico image (`deploy/zephyr-pico-compare`) is not in the
  lane. The alternating-boot and wire-turnaround method of the 2026-10-21 to 10-23
  comparisons (`docs/storage-policy-and-link-layer.md` section 2 and sections 5.1 to 5.2)
  was run with scripts that live on the bench host and not in this repository.
- **The figures we have** (each at its own date, none current):

| cell | wz | original | source |
|---|---|---|---|
| host `.so` text, pico client, tokio engine | 1,833,173 | 4.5 times pico | capability_cost_gate, hosted, 10-26 |
| host `.so` text, pico client, cooperative engine | 905,204 | 2.2 times pico | the same |
| host send, 8 B, pico ABI | 5.1-5.5 M msg/s on 2+ cores | pico 8.0 M | bench host, 10-19 |
| host receive, pico ABI | not measured | pico to pico breaks at full rate | the same |
| MCU text, fixed client vs tuned pico | 157,088 | 164,396 | storage doc 5, different feature sets |
| MCU answer turnaround | fixed 0.203 ms, heap 0.210 ms | pico 0.213 ms | storage doc 5, 12 boots each |
| MCU GET (wz node asking) | 76.0 us | pico 80.4, zenoh 99.9, zenoh-c 96.3 | storage doc 5.2, ranges overlap |

- **Host to host, the same build's text differs.** The same pico-client build read
  1,794,606 bytes on the development host, 1,827,441 on the bench host and 1,833,173 on
  hosted CI on the same day. A size figure names the host it was read on.

## 3. The model

A cell of the parity matrix is (original, target, storage, workload, metric).

- **original**: zenoh, zenoh-c, zenoh-pico.
- **target**: `host-linux` and, for zenoh-pico, `mcu-zephyr` (the T2G kit, CYT4BF M7).
- **storage**: `heap` and `fixed`. The originals have only the heap. wz must win with both,
  because the heap preset is the like-for-like and the fixed preset is what wz adds.
- **workload**: what both programs do, the same bytes on the wire: answer a GET (W1), ask a
  GET (W2), publish at the highest rate (W3), receive at the highest rate (W4), ping-pong
  (W5).
- **metric**:
  - size: text, read-only data, data, bss, flash total, static RAM, and the smallest kernel
    heap pool the image runs its workload in;
  - memory at run time: heap peak, stack peak summed over the application's threads, and the
    stack each image reserves;
  - time: the wire turnaround (the gap between the datagram in and the datagram out, read by
    the host at the wire), round trip, messages per second delivered;
  - CPU: CPU time per message (on the MCU, the idle thread's share under a fixed load).

The reference is always built by this repository from the pinned source, with its switches
derived from the declaration and never chosen by hand:

- On the host, `wz_config.pico_reference` already derives zenoh-pico's switches from a
  wz build's features. zenoh-c and zenoh are built at the pinned version with their
  default features, which is what their defconfigs reproduce.
- On the MCU, the same derivation drives the pico image's switches: the pico image of a
  cell is built with the switches `pico_reference` gives for the wz image's capabilities,
  so pico carries what wz carries.

## 4. Decisions

- **D1. The verdict of a cell is WIN, TIE or LOSS, and only WIN counts as better.** Size is
  deterministic for one build on one host: WIN when wz is smaller. Time and CPU are
  distributions: each image is measured over alternating boots (A B B A ...), each boot
  gives one median, and the verdict is a bootstrap 95% interval of the ratio of the medians
  of the boot medians. WIN when the whole interval is below 1, LOSS when it is above 1, TIE
  otherwise. A TIE is not a claim. The interval and the number of boots are printed with
  the verdict.
- **D2. The measurement is the repository's, not the bench host's.** The alternating-boot
  method, the wire capture and the turnaround reading move into the kit lane
  (`scripts/kit-lane.sh compare`) and a verdict module under `scripts/lib`. A figure that
  only a bench host's script can produce is not a figure of this matrix.
- **D3. The pico image is a lane image with derived switches.** `deploy/zephyr-pico-compare`
  takes its switches from the declaration for the capabilities of the wz image it is
  compared with. Its kernel configuration is pico's own needs (the POSIX layer, its read and
  lease tasks): what pico needs from the kernel is part of pico's cost and is not
  subtracted.
- **D4. The same program, once it can be.** Until the pico C ABI runs on the MCU (C12), the
  MCU cells compare two programs written for one workload, with the same keys, bodies and
  encoding on the wire. When C12 lands, the cells are measured with pico's own example
  programs linked once against pico and once against wz, as the host comparison does, and
  the two-program figures are kept beside them, not replaced silently.
- **D5. A LOSS is a debt.** Each LOSS cell is an item paid in its own round, largest ratio
  first, with the cell measured again in that round. The loop runs until no cell is a LOSS
  or a TIE.
- **D6. The committed matrix.** The verdicts live in a committed file (`deploy/upstream_parity.json`),
  one row per cell with its figures, the boots, the host, the date and the tree. A change
  that moves a cell moves its row in the same commit. Hosted CI grades the host size cells.
  The MCU and the host time cells are lab rows: a person or the loop runs the lane, and the
  row records when.

- **D7. Every capability is a switch, from Kconfig down to the generated state machine (owner,
  2026-10-26: "kconfig와 sce code gen으로 기능을 껐다 켰다 자유롭게 조작할 수 있어야 해").**
  A preset is only as exact as the switches under it: a capability that cannot be turned off
  is carried by every preset, and a capability that can be turned off only in Rust but not in
  the state machine that drives it leaves its states, transitions and host actions in a build
  that does not have it. One chain, one declaration:
  1. `deploy/wz-config.toml` declares the capability once: its Kconfig symbol, the cargo
     features it turns on, the original's switch it maps to (`[[upstream_switch]]`), and the
     SCE feature name the state machines gate on.
  2. Kconfig (a defconfig, a registered profile, a user preset, `menuconfig`) gives `.config`;
     `wz_config.py` turns it into cargo features on the host and `wz_axes.cmake` does so in a
     Zephyr image. This exists for the capabilities and the image axes.
  3. Rust code is gated by `#[cfg(feature = ...)]`. This exists.
  4. **The SCXML sources gate their elements** (`<state>`, `<transition>`, an `<sce:action>`,
     an event) on a feature, and SCE emits each gated item under the matching
     `#[cfg(feature = ...)]`: the enum variant, the transition arm, the host action's trait
     method. One committed emit serves every configuration; turning a capability off removes
     its states, transitions and actions from the build and from the trait a host implements.
     This exists since 2026-10-27 for one machine and two elements: the unicast session's
     accept path carries `sce:requires="session-unicast-accept"` on a state and a transition
     (`sources/session/session_fsm_unicast.scxml`, commit d809de495), and the committed emit
     holds the gated variants. Every other machine is still included or not as a whole
     (`crates/wz-session-core/src/lib.rs`, `#[cfg(feature = "session-unicast")]` around the
     `include!`), so K2 has started and is not done (`docs/feature_inventory.md` section 8 is
     the old sketch). SCE took it (its ADR 0057, accepted): an attribute `sce:requires`
     whose predicate is a name, `all(..)` or `any(..)` (no `not`: a build is a union of
     features, which only adds), on states, transitions, executable content, entry and exit,
     invocations, static data and imports; an event's variant and a host action's method
     gated by the `any(..)` of their users; every one of the 2^N worlds checked to be a valid
     machine; the Rust emit `cfg`-gated with `compile_error!` guards for the requires edges and
     a cargo `[features]` fragment beside it. The features are declared in a feature-model
     document of their own that every machine imports (ADR 0057 approved on 2026-10-26). The
     emitted `cfg` is read by the crate that compiles the generated module, so the names a
     machine may gate on are that crate's cargo features: wz GENERATES each crate's model from
     its own `Cargo.toml [features]` (`scripts/lib/sce_feature_model.py`, `sources/features/`),
     and the gate is that the committed model is the generated one. `deploy/wz-config.toml`
     stays the source above it: a capability turns on crate features (step 2 of this chain), and
     those are the names the machines gate on.
  5. The C drop-in headers carry the original's own switch macros (`Z_FEATURE_*` for pico)
     generated from the same `.config` (C12's header generation).
  6. Gates: every feature an SCXML source names is declared (a C0 check), the emit compiles
     under every registered profile and under each capability turned off alone, and a build
     with a capability off links none of its symbols (the ABSENCE and PRESENCE of
     `capability_cost_gate.py`, extended to the MCU images).

## 5. Steps

MCU first, by the owner's choice.

1. **M1. The lane compares.** `kit-lane.sh` gains the pico image and the wz heap client as
   compare images (they have no stack gate row) and a `compare <image>... --boots N`
   command: alternating order, a wire capture per boot, the turnaround and the console's
   stack and heap lines per boot. A verdict module reads a compare run and prints each
   cell's verdict by D1.
2. **M2. The pico image's switches derived.** `zephyr-pico-compare` builds pico with the
   switches `pico_reference` gives for the wz image it is compared with (D3), and the
   build fails if pico's generated header disagrees with what was asked.
3. **M3. The first MCU matrix.** W1 on the three images (pico, wz heap, wz fixed), all
   size and memory metrics, committed as rows.
4. **M4. W2 to W5 on the MCU.** The workloads the native nodes do not have yet are added to
   both programs.
5. **M5. C12: the pico C ABI on the MCU**, on the heap and the fixed profile, as a new
   engine behind `wz-capi-port`'s `SessionEngine` and a `no_std` definition crate that
   `wz-capi-pico` depends on. The MCU cells are then measured with pico's own programs (D4).
6. **H1. The host matrix.** The same for the three host presets: size against zenoh-pico,
   zenoh-c and zenoh built the same way, time with `pico-compare.sh` and its zenoh-c and
   zenoh counterparts brought into the same verdict module.
7. **K. The switch chain (D7).** K1: the SCE element gate (asked of the SCE repository: the
   attribute, its emit as `#[cfg]` in the Rust backend, and its conformance tests). K2: the
   SCXML sources annotated where a capability owns states or transitions (the unicast
   session's accept path first: a client build carries it today), each annotation's feature
   declared in `deploy/wz-config.toml`. K3: the gates of D7.6. K2 waits on K1; K3's ABSENCE
   check on the MCU images can start now.
8. **L. The loop.** Each LOSS or TIE cell, largest ratio first (D5).

## 5a. C12 on the MCU: one engine, host seams behind a seam

Counted on 2026-10-26: the cooperative engine (`wz-capi-coop`) uses `std` at 23 sites against
2,574 lines of session logic that already stand on `no_std` crates (`wz-session-core`,
`wz-runtime-coop`, `wz-session-mcu`), and its link (`IpStack`) is handed in by the ABI. A second
engine for the MCU would copy that logic. So the pico C ABI on the MCU runs on the same engine
(agreed with the engine's author the same day):

- **E1. The engine builds without `std`.** What remains of `std` goes behind two seams: the os
  seam (thread identity, spawn and sleep for pico's multi-threaded arm, the thread-local delivery
  set, a monotonic millisecond clock), whose host backend is `std` and whose Zephyr backend is
  the kernel (`k_current_get`, `k_thread_create`, `k_sleep`, `k_uptime_get`); and the lock
  (`wz-capi-port`'s `sync::Lock` or the runtime's critical section). `std` stays the default
  feature, and the change that moves them changes no behaviour.
- **E2. The link is the image's.** On a host the ABI hands the engine `wz-runtime-posix`'s
  sockets; on the MCU, Zephyr's sockets or lwIP through `wz-session-lwip`, in the same place.
  Scouting's multicast sockets are the host's (`wz-host-net`) and stay a host feature until the
  MCU has its own.
- **E3. Heap and fixed are the storage policy's, not the engine's.** The policy is already in
  `wz-session-mcu`.
- **What must survive the move** (the engine author's list): the session lock is held across a
  step, so the lock decides who may step from where, and the rule that callbacks run outside it
  (decision D8 of `docs/capi-pico-on-coop-engine.md`) must hold on both backends; the tickers and
  the timed waits need the clock and the sleep of the os seam; `Arc<dyn SessionEngine>` and the
  atomics need a target with compare-and-swap (the kit's thumbv7em has it, thumbv6m does not);
  the closed-session answers and the `live()` guard stay in the engine and only the lock moves;
  the `pico-client-coop*` cases of `capability_cost_gate.py` are run at the commit, since a
  generic lock is to cost no text.
- **The pico ABI's own host layer** gains `src/os/zephyr.rs`, modelled on zenoh-pico's
  `system/zephyr/system.c`, beside `unix.rs` and `windows.rs` (the types the C program
  stack-allocates are the ones pico's Zephyr header gives them).

## 6. Open

- The zenoh (Rust) cells need the upstream examples built against wz through
  `api-compat-rust`, whose top crate is in progress. Until then the zenoh cells are size
  and the C ABI's.
- Whether the MCU preset's defconfig (`configs/zenoh-pico-mcu_defconfig`) is generated
  from the declaration like the host ones, or is the pico image's derived switches written
  out, is decided in M2.
- Host-to-host size differences (section 2): which host's figure a size cell is graded on.
  Hosted CI's is the one a budget follows today.
- `pico_reference` is calibrated to the pico ABI: it sets publication and subscription on
  (`always`) because every `wz-capi-pico` build has them. The MCU's native client node answers
  queries and neither publishes nor subscribes, so a pico image derived that way would carry
  planes the wz image does not, and the comparison would lean towards wz. Until C12, the MCU
  derivation (M2) takes the planes the wz image actually links, read from the image's own
  declaration, and the pico image is built with exactly those. Single-threaded and
  multi-threaded pico are both measured and the stronger one is the reference.

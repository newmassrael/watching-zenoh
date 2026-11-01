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
| host no-drop rate, pico ABI, puts batched per 1 ms slot, 8 / 64 / 1024 B | at least 5.12 M / 4.48 M / 160 k msg/s | pico 4.48 M / 4.00 M / 310 k | `pico-compare.sh nodrop`, pc3, TCP loopback peer, median of 3, 2026-10-31 |
| host no-drop rate, pico ABI, puts one by one, 8 / 64 / 1024 B | 4.96 M / 4.32 M / 310 k msg/s | pico 370 k / 380 k / 360 k | the same, with `write_bound`; 1 KiB was 190 k before it |

**The no-drop rate** (`scripts/host-bench/`, RFC 2544): the publisher OFFERS a stated rate and the
subscriber counts what it is delivered; a rate stands when every message arrived and the rate was
really offered, and the search doubles it and bisects to 5 percent. It replaces the free-running
upstream examples for the throughput cell, because the control of those (pico on both sides) read "no
samples". A trial is valid only when the pinned CPUs were used by nothing else (the share of their busy
time that is not the two processes', at most 10 percent): on the shared bench host pc2 (load 15 to 30)
every trial was disturbed and the same search read values tens of times apart; on pc3 the three
repetitions agree within 5 percent. The 8 B figure of wz is a lower bound (the search stops at its
cap). The round trip of the same ABI against pico reads a tie at 10 to 11 microseconds. Read again
after the lane of the pico ABI went to 8 batches (`scripts/pico-compare.sh rtt 3`, 8 B, 20,000 round
trips, ping on CPUs 6,7 and pong on 8,9, one session on the bench host): pico 20.0, 20.0 and 20.0
microseconds and wz 15.0, 15.0 and 15.0 (medians), so the deeper lane did not lengthen a round trip
and wz was not the slower of the pair. Both values are twice the earlier session's, which the host
accounts for (another session held a lock on it): the order of the pair is the reading, not the
figure.

**A cell wz still loses, by less: 1 KiB puts.** One by one, wz read 190 k against pico's 360 k; after
the change below it reads 310 k (wz to wz and wz to pico) against 360 k, the same writer pipeline.
The reading, in the order it was made (pc3, 1 KiB at 150,000 a second):

- The `futex` count that `strace` showed (298,725 calls against pico's 14) was in good part
  `strace`'s own doing. Counted inside the library, the writer was parked for 2.4 percent of the
  frames that landed, and the role was held by it for 98 percent of them.
- The writer thread spent 91 percent of its CPU in the kernel (`/proc/<pid>/task/*/stat`): the
  cost is the `sendto`, once per frame. It wrote exactly one frame per write, 1,037 bytes on
  average, because the write was bounded by the link's batch (2,048 bytes for a pico peer) and two
  frames are 2,074.
- The batch bounds one frame; a stream carries frames back to back, so how many leave in one
  `write` is invisible to the peer. A write is now bounded by the batch, or by four frames of the
  first one's size up to 64 KiB, whichever is more (`write_bound`): small frames are bounded as they
  were. At 250,000 a second the writer then carried 3.8 frames a write and kept up.

Not the lever: a frame written by the thread that put it whenever the writer's role is free. It
changed nothing (190 k), and the counters say why: 98.2 percent of the attempts found the role held,
14,032 of 1,200,000 wrote. A sender that waited for the role would not be safe (the writer can be
waiting on the socket for the runtime thread the sender may be).

Two things that move the figure and are not the library: the default pinning gives a process one SMT
pair, and wz's sender and writer are two busy threads on it where pico is one; with two physical
cores the unchanged writer read 290 k. And the 64 B figure read 4.48 M in one session and 4.32 M in
the next, with and without this change (the unmodified queue read 4.32 M too), so a difference of one
step of the search (5 percent) between two sessions is the host's. What is left of the gap, 310 k
against 360 k, has no reading yet. The batched row above is not re-measured with this change.

Sizes between 64 B and 2 KiB, puts one by one, median of three on pc3, default pinning (msg/s;
pico to pico / wz to wz / wz to pico / pico to wz):

| size | pico to pico | wz to wz | wz to pico | pico to wz |
|---|---|---|---|---|
| 128 B | 370 k | 2.64 M | 2.64 M | 390 k |
| 256 B | 370 k | 1.52 M | 1.52 M | 400 k |
| 512 B | 360 k | 680 k | 660 k | 340 k |
| 2048 B | 185 k | 125 k | 125 k | 185 k |

Up to 512 B wz is ahead, because one write carries many frames where pico sends one per put. At
2048 B (a put past the 2,048 B batch, so a chain of two fragments) it was behind by a third under the
default pinning, and the cause is the placement and not the number of writes: pico makes two `sendto`
calls a put (20,004 for 10,000 puts), wz about one (the two fragments leave in one write), and wz's
sender and writer threads (42 and 86 percent busy at 120,000 a second, the writer 82 percent in the
kernel) share one SMT pair. With the publisher given two physical cores (CPUs 6,7,8,9):

| size | pico to pico | wz to wz | wz to pico | pico to wz |
|---|---|---|---|---|
| 1024 B | 360 k | 320 k | 300 k | 360 k |
| 2048 B | 180 k | 220 k | 160 k | 190 k |

so wz to wz passes pico at 2048 B (the three repetitions read 220 k, 175 k and 220 k, a spread of
more than one search step), while wz to pico stays 11 percent behind and 1 KiB stays 11 to 17
percent behind: the placement does not explain those two cells. The next paragraph reads them.

**The depth of the lane, not the write, bounded those two cells.** Sampling the stacks of the
publisher at 1 KiB and 290,000 a second (150 samples under a debugger), the putting thread was in
`wait_for_room` in 126 and the writer thread in `epoll_wait` in 148: the pico lane held two batches
(4,096 bytes), so four 1 KiB frames filled it and the sender and the writer then waited for each
other after every four frames. What binds them is single buffering, read below under the table: the
lane counts the batch the writer is writing as occupied until the writer asks for the next one, so
while it writes four frames the sender has no room. The lane's depth
is now the limit `PICO_TX_QUEUE_SIZE` (`WZ_LIMIT_PICO_TX_QUEUE_SIZE`, default 8, in upstream's
`1..=16` for a queue size); `TxQueueConf::default()` keeps upstream's 2, and only the pico C ABI
on the tokio engine reads it (the lwip and MCU paths do not). Measured on the publisher pinned to
two physical cores, 1 KiB, wz to wz / wz to pico (msg/s):

| lane size | wz to wz | wz to pico |
|---|---|---|
| 2 | 320 k | 300 k |
| 4 | 540 k | 520 k |
| 8 | 560 k | 960 k |
| 16 | 560 k | 920 k |

pico to pico read 350 k to 360 k. Eight is the knee; wz to wz stops at 560 k because the wz
subscriber is the next bottleneck (its drive thread reads 401 ticks of 400 at 540,000 a second).

Why the knee is there, tried by three temporary changes of the queue at 1 KiB on the same pinning
(two repetitions each, not landed):

| change | lane size | wz to wz | wz to pico |
|---|---|---|---|
| a sender is woken only when the lane is at most half full | 2 | 315 k | 300 k |
| the lane counts only the frames still queued, not the batch being written | 2 | 560 k | 590 k |
| the same, with the lane at its default | 8 | 570 k | 940 k |

The wake rule is not the cause (the first row equals the unchanged size 2). The cause is single
buffering: a lane of two batches holds one batch of the writer's and nothing else while it writes, so
production and writing do not overlap, and counting only the queued frames, which lets the sender fill
the lane while the writer writes, gives wz to wz 560 k at size 2, what size 8 gives. What the second
row lacks against size 8 (590 k against 960 k to pico) is room to queue ahead of the writer, so the
depth stays a measured gain of its own. The accounting of the third row adds nothing to size 8, and
it moves the memory bound of a lane to what is queued plus the batch being written; it was therefore
not applied. With the limit at its default, at the default pinning (median of three, pc3, msg/s):

| size | pico to pico | wz to wz | wz to pico | pico to wz |
|---|---|---|---|---|
| 8 B | 370 k | 5.12 M | 4.80 M | 400 k |
| 64 B | 380 k | 4.48 M | 4.32 M | 400 k |
| 1024 B | 360 k | 560 k | 920 k | 360 k |
| 2048 B | 180 k | 230 k | 480 k | 190 k |

The small sizes did not move (8 B and 64 B read as before within one search step), and 1 KiB and
2048 B are ahead of pico from wz's side, so the 11 to 17 percent gap above is closed under this
setting. What this does not say: the figure is the throughput of one host over loopback, with no
latency reading beyond the 8 B round trip above; wz runs two threads where pico runs one; a lane
now holds up to eight batches of heap while frames are queued; and pico to wz reads a tie with pico
to pico (360 k at 1 KiB, 190 k at 2048 B), because pico's publisher is what bounds it.

**CPU, corrected.** An earlier version of this section said wz spent about 27 percent more CPU than
pico at the same rate and about five times its user time. Both came from a run where the publisher
program (`paced_pub`) spins between slots: when the library is faster than the offered rate the spin
is charged to the process, and the one wz reading was also taken with a lane of two. With the spin
replaced by a sleep (`paced_pub -w`, 1 KiB at 290,000 a second, 4 s window, CPU of `/proc/<pid>/task`
threads, two repetitions, lane at 8), the publisher side reads 340 and 348 ticks of 400 for pico's one
thread and 231 and 236 for wz's two threads together (the sender 102 and 104, the writer 129 and
132): wz spends about a third less CPU for the same rate, mostly in the kernel, because it writes
many frames in one call. The split between user and kernel time is not stated, since tick
accounting put the writer's user time at 40 in one repetition and 0 in the other. Pico's own run
slipped 1,647 and 1,971 slots of 1 ms at that rate (it is at its limit there), wz's 9 and 0; one
host, one size, pinned to CPUs 6,7,8,9.

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

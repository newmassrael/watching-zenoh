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
- **No MCU preset.** The build configuration lists
  `configs/zenoh-pico-mcu_defconfig` among the upstream defconfigs and leaves it waiting. The
  MCU images are wz's own nodes (`deploy/zephyr-admin-node`, the client on the heap profile
  and on the fixed-memory profile), not the pico C API. The pico C ABI on an MCU (C12 below:
  one `no_std` ABI definition bound to a host driver and to an MCU driver) has not started.
  The cooperative engine the pico ABI runs on is a host engine (`docs/capi-pico-on-coop-engine.md` D3).
- **Size, host.** `scripts/lib/capability_cost_gate.py` builds each C ABI case, holds it to
  a text budget, and builds zenoh-pico as the same build (`wz_config.pico_reference`) to
  print the ratio. It prints the ratio and does not grade it (it grades it since 2026-11-21,
  D9). It has no zenoh-c reference and does not build `--original-features` lines.
- **Size, MCU.** `deploy/resource_budget.json` holds the fixed client's static chain and
  stack peak. `deploy/session_slot_bytes.json` holds the session slot. Neither has a
  reference.
- **Performance.** No gate. `scripts/pico-compare.sh` builds the upstream pico examples
  against pico and against `libwz_capi_pico` on a host and prints round trip and
  throughput, by hand. Its `perf` mode runs one probe program against `libwz_capi_pico`
  and against zenoh-pico built as the same build, per transport (tcp, udp, multicast, a
  transport the program supplies) and with batching off and on, and writes the result as
  a file (`docs/pico-perf-matrix.md`), which the gate of D9 judges. On the MCU, `scripts/kit-lane.sh` runs wz images on the T2G kit and
  holds each to its own row. The pico image (`deploy/zephyr-pico-compare`) is not in the
  lane. The alternating-boot and wire-turnaround method of the 2026-10-21 to 10-23
  comparisons on the T2G kit was run with scripts that live on the bench host and not in
  this repository.
- **The figures we have** (each at its own date, none current):

| cell | wz | original | source |
|---|---|---|---|
| host `.so` text, pico client, tokio engine | 1,833,173 | 4.5 times pico | capability_cost_gate, hosted, 10-26 |
| host `.so` text, pico client, cooperative engine | 905,204 | 2.2 times pico | the same |
| host send, 8 B, pico ABI | 5.1-5.5 M msg/s on 2+ cores | pico 8.0 M | bench host, 10-19 |
| host receive, pico ABI | not measured | pico to pico breaks at full rate | the same |
| MCU text, fixed client vs tuned pico | 157,088 | 164,396 | kit comparison, 10-22, different feature sets |
| MCU answer turnaround | fixed 0.203 ms, heap 0.210 ms | pico 0.213 ms | kit comparison, 12 boots each |
| MCU GET (wz node asking) | 76.0 us | pico 80.4, zenoh 99.9, zenoh-c 96.3 | kit comparison, 10-23, wz node asking, ranges overlap |
| host no-drop rate, pico ABI, puts batched per 1 ms slot, 8 / 64 / 1024 B | at least 5.12 M / 4.64 M / 570 k msg/s | pico 4.80 M / 4.16 M / 355 k | `pico-compare.sh nodrop`, pc3, TCP loopback peer, median of 2, 2026-11-02, with `write_bound` and the lane of 8; 2026-10-31 read at least 5.12 M / 4.48 M / 160 k against pico 4.48 M / 4.00 M / 310 k |
| host no-drop rate, pico ABI, puts one by one, 8 / 64 / 1024 B | 4.96 M / 4.32 M / 310 k msg/s | pico 370 k / 380 k / 360 k | the same, with `write_bound` only; 1 KiB was 190 k before it, and 560 k with the lane of 8 (below) |
| host no-drop rate, zenoh-c ABI (`wz-capi-c`), puts one by one, 64 B / 1024 B | at least 5.12 M / 3.52 M msg/s | zenoh-c 1.10.2 4.00 M and 4.32 M (two runs) / 2.24 M | `pico-compare.sh nodrop-c`, pc3 idle, TCP loopback peer, default pinning, median of 3, 2026-11-02 and 2026-11-03; the three readings of 1 KiB are 3.52 M each, from the first run |
| the same, 8 B | at least 5.12 M | zenoh-c 4.16 M and 4.80 M (two runs; one of three readings valid in the second) | wz to wz, three readings of at least 5.12 M after the close change (below); before it each was stopped by a loss at the end, not by the rate |

**The zenoh-c family** (`pico-compare.sh nodrop-c`) runs the same publisher and subscriber sources
(`scripts/host-bench/bench_api.h` is the one place where the two C APIs differ) against the zenoh-c
release and against `wz-capi-c`. In the pairs, P is zenoh-c and W is wz, so PW is the zenoh-c
publisher with the wz subscriber. The medians of three at 64 B, first run then second, are PP
4.00 M and 4.32 M, PW 4.00 M and 4.16 M, WP 4.96 M and at least 5.12 M, and WW at least 5.12 M
twice ("at least": the search doubles from 20 k, nothing was lost at 5.12 M, and the next step,
10.24 M, is past its cap of 8 M, so no higher rate was tried). The second run, after the close change below,
also read 8 B: PP 4.80 M (one reading of three valid), PW 4.48 M, WP and WW at least 5.12 M. At
1 KiB, from the first run, PP 2.24 M, PW 2.24 M, WP 3.12 M and WW 3.52 M. A zenoh-c pair differs by
about 8 percent between the two runs at 64 B, which is the host's, not the library's. The caveats
stand: one host, loopback, and the default pinning gives each process one SMT pair, which is two
CPUs for a zenoh-c that runs several threads. A pinning with four CPUs a side read PP 4.00 M at
64 B, the same as with two, and PW 3.68 M; its other cells were rejected by the trial's check of
foreign CPU use, so 1 KiB at that pinning is not measured. Runs on a busy host (other builds on the same
CPUs) were rejected by that check and are not used.

**A loss that is not the rate, found and fixed.** At 8 B a wz publisher that closed right after
its last put lost the last 400 to 1100 puts in some runs (a zenoh-c subscriber lost the same ones,
and a zenoh-c publisher into a wz subscriber lost none, so the loss is on the sending side). It
had two causes, found by changing one thing at a time, 20 runs each at 400 k/s. First, `z_drop` of
a publisher sends the undeclare of its key (Control priority) and the writer's lanes served
Control before Data, so the undeclare reached the peer before the queued puts and the peer, which
had unregistered the alias, dropped them; the barrier in the lanes (ledger round 4142) now holds a
Control frame behind the frames queued before it. Second, a session that closed while its data
plane held an open frame dropped the frame: the writer puts it on the wire when it falls idle,
through a hook that holds the session weakly, and the close let go of the session first. Closing
the session without dropping the publisher lost puts in 13 of 20 runs wz to wz and 15 of 20 wz to
zenoh-c; the close now hands the open frame to the writer first (ledger round 4148), and both
paths, and the publisher dropped first, lose none in 20 runs. An earlier version of this
paragraph said a close left to the session loses nothing; that was a reading of timing on the
tree before, and is withdrawn. The 8 B cells with wz in them above are from after both changes.

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
against 360 k, had no reading at the time of this change (read below, under the depth of the lane).

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

- **D8. The build cells of the MCU matrix are a ceiling every landing holds (owner, 2026-11-21:
  "no std no heap 에서 pico 대비 우월했던걸 잃고 있어, 잃지 않도록 개선해").** Run
  20261031T063515 read the fixed client and the heap client as WIN against single-threaded
  zenoh-pico in every cell, by 1,224 and 1,292 bytes of text and 1,320 and 1,388 of flash. Every
  gate after it held an image to its OWN committed row: the fixed client's text row of
  `deploy/text_budget.json` moved from 142,528 bytes (2026-10-31) to 149,548 (2026-11-03) and to
  155,796 (2026-11-18), each move with its reason, against the 144,844 the matrix reads for the
  reference. Nothing compared the image with zenoh-pico, so the text and flash cells went from WIN
  to LOSS with no gate red. The rule:
  1. **The ceiling is judged in the same run as the image.** Layer Qzk (`scripts/run-ci.sh`, on
     hosted CI in the Zephyr job) takes the pairs of the matrix's latest run whose image is one of
     the images it builds, builds the image and its reference as compare builds in that run (the
     reference from this tree's `vendor/zenoh-pico`, the way `scripts/kit-lane.sh build` builds
     it), and `scripts/lib/pico_ceiling_gate.py` judges every cell the build alone decides:
     text, flash (text + data), static RAM (data + bss: the kernel heap pool and every stack are
     in it), the stack objects (each thread's and the interrupt stack, found in the debug
     information by their type, Zephyr's `struct z_thread_stack_element`), and for an image with a
     kernel heap pool its storage block (stated by the build as `wz_storage_block_bytes`) under
     the reference's heap peak in the matrix's run. A committed figure of the reference is not
     used for a cell a build decides: a toolchain, a Zephyr tree or a path that differs moves the
     reference too, and a cell is a comparison only when both sides moved alike. The lane can be
     run one ceiling group at a time (`WZ_QZK_PART`, `scripts/kit-lane.sh parts`): a group is a
     reference with every image the matrix pairs with it, so a reference is never built apart
     from an image it holds, and an image with no pair is a part of its own. The lane refuses a
     cut that leaves an image out or puts one in two parts, runs every part when no part is
     named (hosted CI runs it so), and the fleet's planner gives each part a unit of its own
     (`scripts/lib/runci_plan.py`), so that no one machine is held for the whole lane.
  2. **Only WIN passes (D1).** A TIE or a LOSS fails the layer and names the cell, both figures
     and the difference. The gate has no exception and no allow list.
  3. **An image's own budget moves only under the ceiling.** `deploy/text_budget.json` and
     `deploy/resource_budget.json` still record a measured change of an image, with its reason, in
     the same commit. A move that takes a cell past zenoh-pico's is refused by the ceiling however
     the row moved; it is answered by taking the bytes back, or by the owner's decision written
     here, never by a budget.
  4. **Both sides are compare builds** (`BUILD_VARIANT=compare`, `CONFIG_WZ_MEMORY_REPORT`), as the
     matrix's size cells were read: the memory report's thread and code are in both images alike,
     and the cells the gate reads are the cells a compare run on the kit reads. A pair with one
     side built otherwise is refused.
  5. **The matrix stays the record of what only a boot measures** (stack used, heap peak,
     turnaround). The gate's cells are read on every run of Layer Qzk and are not committed.
  6. **The WIN was taken back (2026-11-21).** The ceiling first read the fixed client as a LOSS
     (text 1,764 bytes over the reference after the second round of work on it). Four rounds of
     commits took the bytes back, and the first run of Layer Qzk on their tree reads every cell
     WIN: text 144,820 against 147,912 (3,092 under), flash 3,188 under, static RAM 9,333 under
     for the fixed client and 6,341 for the heap client, stack objects 3,456 under, and the heap
     client's storage block 7,712 against the reference's heap peak of 9,280. The image's own
     rows moved with it in the same commit (`deploy/text_budget.json`: the fixed client 155,796
     to 143,720, the commits and the symbols in its `measured`). No boot of the matrix was run
     again: its boot cells (stack used, heap peak, turnaround) are those of run 20261031T063515,
     and the caveat of that run in `deploy/upstream_parity.json` says so.

- **D9. The host libraries of the pico ABI are held under zenoh-pico in ratchet form (owner,
  2026-11-21: wz is to be smaller and faster than zenoh-pico, held by gates as a ratchet and a
  debt loop).** D8 holds the MCU kit's build cells at WIN only, and they read WIN. The host
  libraries (the pico C ABI cdylib that ships as the Linux `.so` and the Windows DLL) read far
  from it: Layer C1cs reads the cooperative pico client at about 2.5 times zenoh-pico built as the
  same build, and the tokio cases higher. A WIN-only rule would hold every one of them red until
  the debt is paid, and a red that stays red holds nothing. Until then each case is held where it
  stands and may only move toward pico. The rule:
  1. **The ratio, read in the same run.** `scripts/lib/capability_cost_gate.py` (Layer C1cs)
     already builds, for every pico case, zenoh-pico from this tree's `vendor/zenoh-pico` with
     the switches `wz_config.pico_reference` derives from the case's features, on the host that
     builds wz. It now grades wz text over pico text. The ratio and not the bytes is held because
     both libraries are built on one host in one run: what the host moves alike on both sides (the
     linker, the libc, the section layout) cancels, and one tree's ratio is comparable across
     hosts within the gate's tolerance, where its bytes are not (section 2 records one pico-client
     build reading 1,794,606 to 1,833,173 bytes on three hosts in one day). The reference is
     built with the host's C compiler, so each row records the toolchain it was read with, and a
     failure on another toolchain names both.
  2. **The committed table.** `deploy/pico_host_ceiling.json` has one row per pico case, and
     every row is a pico case of the gate: a case added without a row, or a row left for a case
     that is gone, fails, so the population cannot grow outside the ceiling. A row is locked,
     `"verdict": "win"`, or a ratchet, `"ratio_at_most"` with the reading it was set from (date,
     both texts, the pico pin, the toolchain) and the open-debt item the case is registered under.
     `ratio_at_most` is that reading's ratio rounded up to four places, and the gate refuses any
     other value, so a ratchet moves only with a stated reading.
  3. **Locked is D1.** A locked case reads WIN (wz text smaller) or fails; a TIE fails as a LOSS
     does. No budget or row move clears it: the bytes are taken back, or the owner decides here,
     as in D8.
  4. **The ratchet only moves down.** A reading over `ratio_at_most` by more than the tolerance
     fails. The tolerance is 0.2 percent of the ratchet: two readings of one tree on one host are
     equal, and the largest spread the gate's notes record between hosted CI and a build host on
     one tree is 0.08 percent of wz's text, so 0.2 percent allows that on both sides of the ratio
     with a margin. A host whose compiler spreads the ratio further shows as a failure naming
     both toolchains; a row is filled from the host that grades it. A reading under the
     ratchet by more than the tolerance passes and prints the tighter row, which the round commits:
     every gain is kept. A ratchet case that reads WIN fails until its row is locked (the gate
     prints the locked row), so a case that reaches WIN is held there from that commit on.
  5. **The debt loop (D5).** Every case that is not locked is an open-debt item, paid largest
     ratio first, each paid in its own round with the ratio read again in that round and the row
     tightened by the reading. A row without a registered item fails. The loop ends when every row
     is locked.
  6. **The byte budget stays.** A case's text budget in the gate still holds its own size, with
     its reason, as before. The ceiling adds the reference to it; it does not replace it.
  7. **Unfilled rows do not land.** A row whose `ratio_at_most` is null fails `--check` with the
     row this run reads. `--measure` prints the rows of every pico case it builds, to paste, and
     so does `--check` after its findings.
- **D10. The host performance matrix of the pico ABI is a ratchet and a debt loop (owner,
  2026-11-21).** wz is to be faster than zenoh-pico and than a deployment's own build of a
  library of the pico API, and gates hold it, not a reading taken now and then. The matrix is
  `scripts/pico-compare.sh perf` (`docs/pico-perf-matrix.md`); the gate is
  `scripts/host-bench/perf_matrix.py --gate`, run at the end of every run of it.
  1. **A row is one figure of one cell, read by D1.** The cost ratio (wz's figure over the
     reference's when lower is better, the reference's over wz's when higher is better, so
     below 1 is wz ahead in every row), with its bootstrap 95% interval over the run's
     repetitions, three at the least of each arm.
  2. **The ratchet.** A row that is not WIN holds the upper end of the interval it was written
     from (`ratio_at_most`); a later run fails when its upper end exceeds that by more than
     the table's stated tolerance. A reading under it is written as the new value, so the row
     only tightens.
  3. **The lock.** A row that reads WIN is locked (`locked`), and a locked row fails anything
     but WIN, with no tolerance.
  4. **The debt loop.** Every row that is not WIN is a debt in the sense of D5, paid largest
     ratio first; the gate prints them in that order after every run. A repetition wz lost on
     its own fails its rows; a cell the reference lost every repetition of is a row that says
     so, and fails once the reference measures it again.
  5. **The population.** A cell with no row fails, and a null row fails with the row the run
     writes, so no cell joins the matrix unjudged. The committed table's rows are exactly the
     default matrix's, held in Layer C0 with the gate's selftest.
  6. **Two pairs, one mechanism.** W over P is committed (`deploy/pico_perf_ceiling.json`). W
     over X, the external library, is measured when the environment names that library, and
     judged against a table the environment names outside the repository, because its figures
     are the deployment's: the repository holds the mechanism and no name, path or figure of
     the deployment. A run without it is NOT-MEASURED for W over X, never a pass of it.
  7. **Where it runs.** On a quiet host, by the run itself. It is not a hosted lane: a hosted
     runner cannot pin the matrix's two sides on cores of their own, and a ratchet read on a
     noisy runner would fail on its neighbours rather than on wz.
- **D11. Completeness is a scoreboard of four criteria, each held by a ratchet (owner,
  2026-11-21).** wz's architecture is to be more complete than zenoh-pico's and than a
  deployment's own pico-compatible build. The criteria: (a) upstream's own tests (zenoh-pico's
  API tests in Layer Z, zenoh-c's tests in Layer C1cc) pass on wz at least as many programs as on
  the original library; (b) a deployment's feature catalogue, a document kept outside this
  repository, is accepted whole as switches of `deploy/wz-config.toml` that are off by
  default; (c) the inventory's PARTIAL atoms and the logic census's unplaced crates and files are
  zero; (d) the structural contracts (layer direction, the hourglass C ABI, no allocation in
  operation, lock order) each have a gate a lane runs. `scripts/lib/completeness_gate.py`
  reads every figure from the gate or the lane that computes it, in Layer C0, and holds it to its
  row of `deploy/completeness_ratchet.json`: a figure may not get worse, a shortfall names its
  debt, and a criterion met is locked. Criterion (b) is measured only where the catalogue is
  given (`WZ_FEATURE_CATALOGUE`), and its figure stays with the document. What each figure is and
  how it is read: `docs/completeness-scoreboard.md`.

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
   zenoh counterparts brought into the same verdict module (section 5b).
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
- **Written, not yet built** (2026-11-14): `wz-capi-pico`'s `os-zephyr` (no `std`; the Zephyr host
  layer and its C seam `deploy/zephyr-common/wz_pico_os_zephyr.c`; the engine's links, clock and
  random source from `src/coop_host.rs`, Zephyr's sockets as `wz_runtime_zephyr::ZephyrIpLinks`);
  the crate's LP64 layout pins hold on a 64-bit target only, and a 32-bit image compiles
  `crates/wz-capi-pico/csrc/pico_layout_pins.c` against pico's header; the image
  `deploy/zephyr-capi-pico`, the comparison image's program linked to wz in pico's place, run by the
  kit lane as `zephyr-wz-pico-queryable` and `-st`. Then: a heap datagram link reads into the batch
  it advertises (`IpLinks::with_rx_capacity`); Zephyr's sockets give the engine a readiness
  (`poll`, the descriptor held open by every wait, as Zephyr cannot duplicate one), so the read
  task waits outside the session's lock; and `scout-mcu` scouts over one datagram socket of the
  stack, as zenoh-pico does on Zephyr, so the image's empty locator scouts as upstream's example
  does. Both pico images carry scouting, as pico's default build does, and the kit lane's selftest
  refuses a switch on in one and off in the other. Open: an IPv6 scouting group. zenoh-pico on
  Zephyr opens one (`udp_zephyr.c` resolves the locator with `PF_UNSPEC` and opens the socket of
  the family it gets), and wz's datagram seam names an IPv4 address in every signature
  (`DatagramSocket::bind` and `send_to` take `[u8; 4]`), so it waits on the step that takes the
  peer address out of the datagram signatures, part of bringing stream links to the MCU.

## 5b. H1 on the host: upstream's examples, two arms, alternating boots

Step H1 measures the three host presets with the method of D1 and the rows of D6. It extends the two
instruments that exist and adds none: `scripts/pico-compare.sh` is the host comparison (the kit lane,
`scripts/kit-lane.sh`, needs the kit, its debugger and its lock, and nothing of it applies on a host),
and `scripts/lib/kit_compare.py` is the verdict. `pico-compare.sh parity <family>` builds the two arms
and runs `scripts/host-bench/parity.py`, which leaves a run of the kit lane's shape (a `manifest.tsv` of
alternating rounds, one directory per boot) with a `host.json` in each boot where a kit boot has its
capture and console; `kit_compare.py --format rows` reads it like a kit run.

**The arms.** One source per program, compiled or built once per arm on the same host in the same
run. Arm P, the original, is built here from the pinned source with its own default switches; arm W
is the wz preset of that original (`wz_config.py --original-features <original>`, which resolves
`configs/<original>_defconfig` alone).

| family | arm P (original) | arm W (wz) | programs | size cells read |
|---|---|---|---|---|
| `pico` | vendor/zenoh-pico at its pin, upstream's default cmake build (`zenoh-pico-build-default`, no switch passed), shared library | `wz-capi-pico` for `zenoh-pico_defconfig` | `examples/unix/c11/*.c` of the pin, against the default arm's headers | the shared library |
| `c` | zenoh-c at the pin of `scripts/zenoh-c-oracle.pin`, built from its source (`install-zenoh-c-arm.sh nounstable`: Release, no unstable API, no shared memory, upstream's pinned toolchain) | `wz-capi-c` for `zenoh-c_defconfig` | `examples/*.c` of that source, against the original's headers | the shared library |
| `rust` | upstream's `examples` package of the pinned tree over upstream's `zenoh` from the registry | the same package with the family in `[patch.crates-io]` and `wz-capi-core` given the preset's features | `examples/examples/*.rs` of the pin | `z_put` |

The Rust package is generated (`z8_upstream_suite.py examples --arm stock|wz`, beside Z8's test
package): the eight sources, `src/lib.rs` and the build script byte for byte, one manifest for both arms
but for the patch and the engine's features, upstream's `[profile.release]` (fat LTO, one codegen unit,
`panic = "abort"`) and upstream's `Cargo.lock` as the starting lock of both, so the third-party crates
the arms share are at the versions upstream released with. `zenoh-ext` is left out of both: none of the
eight programs calls it. The programs are `z_put`, `z_sub`, `z_get`, `z_queryable`, `z_pub_thr`,
`z_sub_thr`, `z_ping` and `z_pong` in every family.

**A boot** is one image running each workload once, every program started afresh, peer mode over TCP
loopback with the client side (`z_ping`, `z_pub_thr`, `z_put`, `z_get`) pinned to CPUs 4-7 and the
server side to 8-11 (two physical cores a side on the bench host: zenoh-c and zenoh run several threads
a process); zenoh-c's and zenoh's sessions are given `--no-multicast-scouting`, so a session meets only
the other side.

**The cells**, each a figure per boot except size:

| metric | what one boot gives | better |
|---|---|---|
| `text` | `size` of the arm's file | lower |
| `file_bytes` | bytes of the file stripped (`strip --strip-unneeded`) | lower |
| `rtt_us` | median of 20,000 round trips of 8 B (`z_ping` / `z_pong`, after a 3 s warm-up) | lower |
| `throughput_<n>B` | median of the subscriber's reports over a 10 s window after a 3 s warm-up (`z_pub_thr` / `z_sub_thr`), n = 8 and 1024 | higher |
| `cpu_ns_per_msg_<n>B` | the CPU of both processes over that window (`/proc/<pid>/stat`), per message the median rate delivers in it | lower |
| `rss_kib_<workload>` | peak resident set of the workload's two processes, summed (`getrusage` of each) | lower |
| `heap_peak_<workload>` | peak of the bytes held through the C allocator by each process, summed (`heap_peak.so` preloaded, in runs of their own so no time figure carries its cost) | lower |

The workloads with a memory cell are `rtt`, `thr_<n>B`, `pubsub` (`z_sub` and one `z_put`, which
must be delivered) and `query` (`z_queryable` and one `z_get`, which must be answered); the heap is
read for `pubsub`, `query` and `thr` at the largest size. Every figure of a pair is the sum of its two
processes because both arms run both sides: a cost moved from one side to the other is the same cost.

**The verdict** is D1's. Size is one figure per build: WIN when smaller. Every other cell is a
distribution over boots, the memory cells included (on a host they move with timing): the ratio of the
median of the image's boot figures to the reference's, and a 95 percent bootstrap interval of that ratio
(10,000 resamples, each image's boots resampled with replacement on its own, seeded, the 2.5th and
97.5th percentiles). For a metric better when lower, WIN when the whole interval is below 1 and LOSS
when above; for a throughput, the reverse. A TIE claims nothing. A row says which way its metric is
better (`better`).

**The host and the boots.** pc3: nobody else uses it (the owner, 2026-10-31), where pc2 is shared at a
load of 15 to 30 and a time figure there is the host's. 24 boots of each image, alternating by round as
the kit lane does: the kit read a boot spread of about 6 percent and put the interval of twelve against
twelve at about 3 percent a side, and the host's spread is not known before the first run, so the first
run uses the kit's number and the next is set from its intervals. A timed workload counts only when its
pinned CPUs were used by nothing else (`nodrop.py`'s rule, at most 10 percent foreign) and is run again
up to six times; a functional one that did not deliver, up to three. A workload a boot lost is left out
of that boot's figures and counted in the report. A size figure names its host (section 2).

**What a run is not.** One host, loopback, peer mode; the C families measure the library under
upstream's programs, the Rust family the whole program. Arm W of the Rust family carries what the
family's crates select beside the preset (cargo unifies features; it cannot take away what `wz-zenoh`
asks of the engine), and the record says so. zenoh-c is built with its own pinned compiler, the rest
with the repository's. The heap shim counts the allocator's usable size of each block, not what was
asked, in both arms alike, and does not see memory a library maps itself, which the RSS cell does.

**Rows.** A run directory holds `verdict.txt` (the report), `rows.json` (`--format rows`) and
`record.txt` (host, CPU, kernel, compilers, the tree, the cargo arguments of arm W and, for zenoh-c,
the drop-in arguments derived from the original's header beside the preset's). The committed run entry
of `deploy/upstream_parity.json` takes `rows` from `rows.json` unchanged and its `target`, `method`,
`tree` and `caveats` from `record.txt`.

## 6. Open

- The zenoh (Rust) cells are measured by section 5b with upstream's examples over the family
  (`api-compat-rust`); whether the eight programs build and run over it is the first thing a run
  of that family says.
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

## 7. Where a preset departs from its original by decision

A preset follows its original's behaviour, and a difference is a debt (section 4, D5) unless it
is decided here, with the rule that decides it and the test that holds it. A row here is not a
cell of the matrix: it is behaviour, not a figure, and it stays until the rule that justifies it
stops holding.

| preset | behaviour | the original | wz | rule | held by |
|---|---|---|---|---|---|
| pico, on a host with a heap | how many members a group holds | no cap: the member list grows while the allocator gives (`vendor/zenoh-pico/src/transport/multicast/rx.c` @ `ztm->_peers = _z_transport_peer_multicast_slist_push_empty(ztm->_peers);`) | the rows of the group face's table, `GROUP_FACE_ROWS` (32) in `crates/wz-runtime-tokio/src/multicast_glue.rs`; the Join of a member past them is refused and counted | a group grows only to a cap a configuration states | `a_face_with_no_stated_cap_holds_its_rows_where_pico_would_grow` (`multicast_glue.rs`), `the_pico_group_states_no_member_cap` (`crates/wz-capi-pico/src/session.rs`) |

The rule, and why it is the pico preset's alone. A group admits a member on an unauthenticated
Join, keyed by the source address of the datagram, and a single host on the segment can send
Joins from as many source addresses as it likes. Each member is a row of the table, a kilobyte
and more with its state machine, its sequence numbers and its declaration tables, so a table that
grew to whatever it heard is a table any host on the link can grow until the process is out of
memory. zenoh bounds the same table by `transport/multicast/max_sessions`, 1000 unless the
configuration states another, and a wz group of the zenoh and zenoh-c presets is held to that
number and grows to it. pico has no such key, so its preset states no cap, and the bound is the
table's own rows. The other per-member tables wz keeps on a group are bounded for the same reason
(`MAX_ALIASES_PER_PEER` and `MAX_SUBS_PER_PEER` in `crates/wz-session-core/src/multicast_dispatch.rs`).

What the row costs, stated: a pico group past 32 members is a group whose 33rd member is not heard
by a wz host, where a pico host would hear it. An MCU image is not in the row: its table is the
one the image declares, as pico's is bounded by the heap the image gives it, and pico on the same
image would refuse the member it had no memory for.

# Observation plane

Status: design, not built. Written 2026-10-28. Nothing here is a switch yet; every name below is
the one the first change that builds it declares in `deploy/wz-config.toml`.

## What it is

A node that runs without a person at it is judged by four instruments, and wz has the pieces of
each only in some of its hosts:

| Instrument | Question it answers | What wz has | What is missing |
|---|---|---|---|
| Time | What time do I put on what I send, and how far do I trust it? | `wz-node-time`: the wall clock in NTP64 and a node-scoped Hybrid Logical Clock (`time-hlc`, `uhlc`) | A clock that is not the operating system's, with a statement of how good it is; the same clock on the fixed-memory hosts |
| Events | What did this node do, in the order it did it, after the fact? | `log` calls (on a node with no sink they go nowhere, to be re-checked before the ring is built); per-reason counters | A bounded record of events a person can read back |
| Supervision | Is the code that must run still running? | Per-session deadlines (handshake, lease, keepalive) in the session machines | A deadline the application feeds, with a statement of what happens when it is missed |
| Resources | What is the node spending? | Per-lane counters (`delivery_lane` stats, drop reasons), `session_slot_bytes.json` for the build | A sampled view of a running node: CPU, memory, message intervals, tasks |

They are one design and not four because they share their hard parts: a clock to read, storage
that is given and not allocated, a producer that must never wait for its reader, a reader that
comes later, and a switch that costs nothing where it is off. Built four times each would be
decided four times; built once they are decided once and the four are small.

## Principles

1. **The core observes, it does not depend on being observed.** A producer writes and goes on. No
   instrument can make the receive path, the send path or a session wait, and a build that omits
   all four behaves byte for byte as one that never had them. This is the same rule
   `docs/rx-delivery-lane.md` states for the lane, applied to the whole plane.
2. **Mechanism and policy are separate types.** What a ring, a deadline or a clock quality *is* is
   a pure type with no clock, no heap, no task and no I/O (the shape of `ReplayCursor` and
   `DeliveryLane`); what happens when it is full, missed or degraded is a policy the build
   states. The pure type is unit-tested alone and against a model; the host only calls it.
3. **A statechart owns a lifecycle, an algorithm owns arithmetic, a type owns storage.** The
   state a thing is in, and which events move it, is SCXML (`sources/`), because it is already
   how wz states every other lifecycle and its states are checked by the generator and not by a
   reviewer. Pure arithmetic with a failure contract (a deadline's comparison, a wrap) is an SCE
   `algorithm`. Bytes and counts stay in Rust types with a model test.
4. **One declaration.** Every capability, limit and policy is declared in
   `deploy/wz-config.toml`; Kconfig, the Rust constants, the Cargo feature graph and the SCE
   feature model come from it, and `wz_config.py --check` fails when any of them is stale. A
   switch no code reads is not landed.
5. **Zero where off, and the gate says so.** Off, a switch adds no field to a session slot
   (`scripts/lib/session_slot_bytes.py --check` holds the number), no symbol to an image
   (a link-level check), and no text beyond the budgets of `capability_cost_gate.py`. The first
   version of the expiry run counter grew the slot by 8 bytes and the gate caught it; the rule is
   written down so the next one is built into the padding from the start.
6. **Measured before superior.** A claim that the plane is cheaper or better than what a node had
   is a number from the lane that runs it, or it is not made.

## Where SCE and Kconfig fit

What SCE gives, as read from its documents (`SCE_FORGE.md`, ADRs) and from wz's own sources, and
what that means for each instrument:

| SCE mechanism | What it is | Use here |
|---|---|---|
| `feature-model` (ADR 0057) | The cargo features of a crate as a model a statechart may gate on with `sce:requires`. Generated from `Cargo.toml` by `scripts/lib/sce_feature_model.py`; wz does not edit it. | Each capability below is a cargo feature of `wz-session-core` or `wz-node-time`; the statecharts gate their states and transitions on it, so a build without a capability has a machine without those states. |
| `statechart` with host-raised events | A lifecycle whose duties (`sce:action effect="duty"`) the host performs and whose deadlines the host raises. This is how the session machines already work (`init_ack.timeout`, `link.lost`). | Clock quality (M1) and supervision (M3). |
| `timer` | One PERIODIC event with `<sce:period>`, `<sce:reset-on>` and `<sce:cancel-on state-exit>`. No one-shot (`SCE_FORGE.md` 4.10). The period is a build-time constant. | The cadence of the resource sampler (M4). NOT the supervision deadline: that is chosen by the application when it starts the supervision, at run time. |
| `queue` | Bounded FIFO hand-off between contexts, with `producers`, `consumers` and `progress` declared. Documents no policy for a full queue. | Not the event ring (M2): the ring is a broadcast with overwrite, which a queue is not (see the limit below). |
| `buffer-pool`, `bounded-collection` | Sized pools and tables; SCE emits the numbers (`SLOT_COUNT`, `SLOT_SIZE`). | The numbers of the plane (sizes of the ring and of the snapshot), as the session-slot pool states its own. |
| `algorithm` | Pure functions generated for several backends, under an integer contract: an overflow or an out-of-range read is a named failure and never a value. | The deadline comparison, once, for the Rust and C11 backends. |
| `stdlib` (`sce:std/...`) | Algorithms SCE ships and tests against reference implementations. Read, not assumed: `merge/hlc_send`, `hlc_receive`, `hlc_compare`, `hlc_within_drift` (Kulkarni et al. 2014; wall time in milliseconds as `int64`, a `uint32` counter, a `uint64` node id) and `rate/gcra_admit` (a generic cell rate limiter). | `hlc_within_drift` is the drift bound of M1, as it is written. The HLC keeps zenoh's NTP64 form, with `uhlc` as its reference (below). `gcra_admit` is the candidate for a querier quota that is a rate and not a count. |

Two honest limits, so that nothing is built on a feature SCE does not have:

* **The timer kind cannot be the watchdog.** It is periodic and its period is text in the SCXML.
  A supervision deadline is given by the application at start. So the supervision machine takes
  its deadline as a duty (`arm_deadline`) and the host raises `deadline.expired`, exactly as the
  session machines take theirs. The timer kind is right for the sampler, whose cadence is a
  build-time number. (Step 5 found that this does not hold: see M4, where the period is the limit
  read as a number and the timer kind is not used.)
* **The queue kind has no full policy, and no attribute would give the ring.** The ring overwrites
  the oldest record where a queue refuses the newest. SCE was asked and answered that no document,
  schema or code states a full policy (a push returns `Full`, and that is all), that nothing is
  decided, and that one attribute would not be enough: a queue pop consumes, while every reader of
  the ring keeps its own cursor and reads every record (broadcast), so the ring needs per-reader
  cursors and a way for a late reader to learn which span was overwritten; overwriting makes the
  producer touch the consumer side, which reopens the declared progress guarantee and the
  linearizability and model-checker work; so it is closer to a new kind than to a queue option.
  That is SCE's owner's decision (extend the queue, add a kind, or leave the ring a wz library).
  So the ring is a Rust type with a model test, as `DeliveryLane` is, and the SCXML states at most
  its sizes.

## The switches

All names are provisional until declared. Kinds: `C` capability (a cargo feature), `L` limit, `P`
policy, `A` axis (existing).

| Instrument | Name | Kind | Default | Meaning |
|---|---|---|---|---|
| Time | `clock-source` | C | off | A node may register a clock that is not the operating system's, and stamp with it. Needs `timestamping`. |
| Time | `CLOCK_SOURCES` | L | 1 | How many clocks the registry holds. |
| Time | `CLOCK_MAX_FORWARD_STEP_MS` | L | upstream's | How far a reading may jump ahead of the last stamp before the node refuses it. |
| Time | `clock-quality-stamping` | P (`always`, `synchronized-only`) | `always` | Whether a node stamps with a clock that is not synchronized. |
| Events | `event-ring` | C | off | A bounded record of events, readable after the fact. |
| Events | `EVENT_RING_BYTES` | L | | Size of the ring. |
| Events | `EVENT_RECORD_ARGS` | L | | Arguments one record carries. |
| Events | `event-ring-full` | P (`overwrite-oldest`, `drop-newest`) | `overwrite-oldest` | What a full ring does. |
| Supervision | `supervision` | C | off | A deadline the application feeds. |
| Supervision | `SUPERVISION_CHECKPOINTS` | L | 1 | Points one supervisor watches. |
| Supervision | `supervision-after-expiry` | P (`latch`, `rearm`) | `latch` | Whether a missed deadline stays missed or starts again. |
| Resources | `resource-snapshot` | C | off | A sampled view of a running node. |
| Resources | `SNAPSHOT_PERIOD_MS` | L | 1000 | The sampler's period, read by the host-polled sampler. |
| Resources | `SNAPSHOT_HISTOGRAM_BUCKETS` | L | 24 | Buckets of the message-interval histogram. |
| All | `exec` | A (existing) | | Who calls the supervisor's check and the sampler: the loop (`coop-single`) or a task (`split-tasks`). No new switch says it. |

## M1 Time: a clock with a quality

**Today (read from the sources, 2026-10-28).** The clock port already exists:
`wz_session_core::epoch::EpochSource` (`no_std`) answers `try_since_epoch()` as seconds and
nanoseconds since the Unix epoch, or `EpochUnavailable` when the board has no set clock, and
derives `try_now_ntp64()`. It is implemented for the system clock (`SystemEpoch` in
`wz-node-time`), POSIX, FreeRTOS and Zephyr, and the pico C ABI stamps through it. What is
missing is above the port: the node clock `NodeHlc` calls `wall_clock_ntp64()` directly and so
cannot take any other source, and it holds a `uhlc::HLC` that only exists under `std` hosts'
`time-hlc`. `uhlc` 0.8.2 shows why it cannot simply be handed a source: `HLCBuilder::with_clock`
takes a plain `fn() -> NTP64`, with no state and no closure, so a source with state can only reach
it through a process-wide static; the counter is in the low `CSIZE` = 4 bits of the NTP64 word
(`lib.rs` `CMASK`); the drift bound is `with_max_delta(Duration)`, 500 ms by default (a fixed 500
ms without `std`); and `update_with_timestamp` builds a `String` with `format!` when it rejects a
timestamp, so the reject path allocates.

**Design.**

* No new `ClockSource` trait. The port is `EpochSource`, and the plan builds on it (an earlier
  draft of this plan named a new trait and missed that the port exists). `EpochUnavailable` is
  already the "no clock" state. What is added is a quality (below) and, for a clock the
  application owns, a registered `EpochSource` that wraps the application's callback (step 2).
  A reading stays seconds and nanoseconds since the Unix epoch, from which an NTP64 word is made;
  the wire stays the Timestamp extension (NTP64 and the node's id), unchanged. `TimeSource` stays
  monotonic and wall-clock-free, as its documentation says it must.
* `ClockQuality` is a statechart, `sources/session/clock_quality.scxml`: `Unsynchronized`,
  `Synchronized`, `Holdover` and `FreeRunning`, moved by `sync.acquired`, `sync.lost` and
  `holdover.expired` (the host raises the last, as it raises every deadline). `Holdover` and
  `FreeRunning` exist only with `clock-source`, through `sce:requires`. A quality carries an
  uncertainty bound in microseconds, which is data of the reading and not a state.
* The node clock's arithmetic moves into a core of our own, `HlcCore`, over an `EpochSource`
  (`no_std`, no allocation), and `NodeHlc` holds it. The algorithm is the one `uhlc` 0.8.2 shows:
  take the reading's NTP64 word with the low `CSIZE` bits cleared; if it is above the last stamp's
  time part, the stamp is that word, otherwise the last stamp plus one; and absorbing a remote
  stamp takes the larger of the reading, the remote time and the last stamp, refusing a remote
  time more than the bound ahead of the reading. The state is one `AtomicU64` advanced by
  compare-and-swap, so no lock is held and a refusal allocates nothing. `uhlc` leaves the
  production build (landed, step 1b): it is a dev-dependency, the REFERENCE the core is tested
  against over random clock traces that step back, freeze and jump, and the two must agree on
  every stamp and every refusal. A reading that moves more than `CLOCK_MAX_FORWARD_STEP_MS` past
  the last stamp is refused and counted, which is zenoh's own drift check (`uhlc`'s `max_delta`)
  and is the answer to an external clock that steps. Measured before the swap (release, build
  machine, one clock read per stamp): one thread 15 ns for both, four threads 29 ns per stamp for
  the core against 52 ns for `uhlc`, a refused remote stamp 13 ns against 78 ns. The one-thread
  parity is the clock read; the gain is under contention and on refusal. Two behaviours changed
  and are documented where they happen: a source with no date stamps nothing (`uhlc`'s clock
  could not say so), and the bound reads `UHLC_MAX_DELTA_MS` itself, since the crate that read it
  is no longer in the path.
* `clock-quality-stamping = trusted-only` (landed; the values are `always` and `trusted-only`)
  makes a node whose clock is not trusted stamp nothing on the data it forwards, take no
  timestamp into its clock and count the data it passed on as it came (`NodeHlc::unstamped`).
  Trusted is `Synchronized`, or `Holdover` under `clock-source`. The host reports the standing
  (`NodeHlc::report_sync_acquired`, `report_sync_lost`, `report_holdover_expired`); a node nobody
  reports for stays `Unsynchronized`, so `trusted-only` on a host that never reports stamps
  nothing, which is what it says. A storage that needs a time to order what it keeps still takes
  one from the system clock. The default stamps, as a node does today. `CLOCK_MAX_FORWARD_STEP_MS`
  is landed with it and sets the bound `NodeHlc` was given as a constant; `clock-source` as a
  capability and `CLOCK_SOURCES` wait for the registration door (step 2), because declared before
  it they would configure nothing.
* The wire form stays zenoh's (`uhlc` is the reference of the core above) and is not replaced by
  SCE's `hlc_send` and `hlc_receive`. They are the same algorithm in a different shape: SCE keeps wall time in
  milliseconds, a `uint32` counter and a `uint64` node id as three fields, where zenoh packs the
  counter into the low bits of an NTP64 word and carries a node id of up to 16 bytes. A node that
  stamped with SCE's record would need a conversion into the wire form that `uhlc` does not make,
  and a stamp that differs from zenoh's for the same inputs is a divergence in a replacement
  whose point is not to diverge. SCE's algorithms are used where they are the same thing:
  `hlc_within_drift` is the forward-step check (`CLOCK_MAX_FORWARD_STEP_MS`), generated once for
  the Rust host and the C11 backend; and `hlc_send` / `hlc_receive` are a DIFFERENTIAL ORACLE,
  run against `uhlc` over random clock traces, to show that the order the two produce agrees.
  The comparison of a supervision deadline is written as a new `algorithm` in this repository's
  sources, so the Rust host and the C ABI share one text under the integer contract.
* Off, `NodeHlc` is zero-sized (it already is without `time-hlc`), and the per-message timestamp
  slot is the one `timestamping` already gates.

**Tests.** A model test of `uhlc` over a clock that steps back, freezes and jumps: stamps strictly
increase and never pass the bound. A conformance run of the quality machine over every event
order. A pair of wire tests: a stamp made from a registered source and one from the system clock
encode to the same bytes for the same time. The C ABI pins for the registration call.

## M2 Events: a ring of records

**Today.** `log` calls reach no sink on a node that has none.

**Design.**

* A record is fixed in size: a sequence number, a level, a source id, a timestamp from M1, and up
  to `EVENT_RECORD_ARGS` integer arguments. Text is not stored. The format string is a constant
  the reader holds (deferred formatting, as `defmt` does), so a record costs a few words and no
  formatting happens on the node.
* Each producer context owns a single-producer ring: no lock, no atomic read-modify-write on the
  write side, and no producer ever waits for another. Sequence numbers are per ring (a global one
  would be a read-modify-write on every write), so a reader puts the records of several rings in
  order by their timestamp, which is a hybrid logical clock's and never goes back on one node. A
  gap in a ring's sequence is a loss, so overwritten records need no separate count; the ring
  keeps one counter, for what `drop-newest` refused, for the reader that wants the number without
  the walk.
* Reads do not have to consume. A `Reader` is a value that holds its own cursor, so there is no
  table of cursors and no `EVENT_RING_READERS` limit to size (the limit this plan listed is not
  declared: it would configure nothing); a reader sees a loss as a gap in its own sequence. The
  one `Consumer` is the reader that also frees what it has passed, which `drop-newest` needs.
  Built as `EventRing::split(&mut self)`: the borrow checker makes the producer the only one.
  Landed (step 3a), with a model test of random interleavings of one producer's micro-steps and
  three readers over 300 seeds, and a stress run of 300000 records against three reader threads.
* `event-ring-full` decides a full ring: `overwrite-oldest` keeps the latest, which is what a
  post-mortem wants, and `drop-newest` keeps the beginning, which is what a boot trace wants.
* A `log` sink writes into the ring, so existing `log` calls become events with no new call. The
  ring may be placed in a region that survives a reset; where it is, a start-up that finds a valid
  header reads what the last run wrote.
* Pure type `EventRing<const SLOTS, const ARGS>` in `wz-session-core`. Not bookkeeping over the
  host's bytes, as `delivery_lane.rs` is: a reader that runs while the producer writes must read
  atomic words, or the read is a data race, so the ring owns its slots as 32-bit atomics (a
  Cortex-M0 has no 64-bit and no compare-and-swap) under a per-slot sequence lock, and the host
  places the whole ring, in a `static` in a region a reset leaves alone if it wants.

**Tests.** The model test of `delivery_lane.rs` extended to this type: random interleavings of
producers and readers, whatever the order, a reader sees records in sequence order, a gap exactly
where records were lost, and no two live records overlap. A concurrency model check (loom, if the
workspace takes it, otherwise a stress run on the build host) for the single-producer,
many-reader publication. A link-level check that the off build has no symbol.

**SCE.** The ring is not a queue (see above), so it is not declared as one. Once the contract (read
semantics, loss reporting, single-producer assumption) is fixed by the model test, that text is
what SCE asked to receive as the ground for reopening the question. It was sent when step 3 landed,
and SCE decided: a new kind, `sce:kind="broadcast-log"` (its ADR 0062), one publisher, readers with
cursors, a read never consumes, a full log forgets its oldest entry, a lapped reader told
`Lagged{skipped >= 1}`. Its runtimes exist in six languages, its codegen templates do not yet, so a
document of the kind is still refused at generation. Two differences from this ring, kept: SCE has
no `drop-newest` or consumer (that stays a queue), and its stamp is a 64-bit sequence number
(busy `2n+1`, done `2n+2`) where this ring's is 32 bits compared modulo 2^32; SCE plans a
narrow-stamp row with a wrap bound stated in the deploy. Nothing here waits on it. When its
templates land, the ring is a candidate to be generated from a document, and the model test's seeds
and operation traces are what a differential run between the two would be fed.

## M3 Supervision: a deadline the application feeds

**Today.** The session machines have deadlines the host raises. An application has none.

**Design.**

* `sources/session/supervision.scxml`, a statechart (landed, step 4a): `Disarmed`, `Armed`,
  `Expiring` and `Expired`. Events: `supervision.start`, `supervision.feed`, `supervision.stop`,
  the host's `deadline.expired` and `hook.done`, and `supervision.rearm`. Duties: `arm_deadline`,
  `cancel_deadline`, `run_expiry_hook`. `Expiring` has no transition on `supervision.stop`, so the
  expiry hook runs once per expiry and the machine will not stop while it runs, which is the rule
  a watchdog needs and which the statechart states in a transition and not in a comment.
  `supervision-after-expiry` is a policy, a value, and a machine cannot read a value, so the host
  raises `supervision.rearm` on a feed that arrives in `Expired` when the policy is `rearm`; with
  `latch` it raises nothing, and a feed there is ignored so that a late feed does not hide a
  missed deadline.
* A supervisor watches `SUPERVISION_CHECKPOINTS` points. Each has its own deadline and the
  supervisor is healthy only while every one is. A node that feeds a hardware watchdog feeds it
  from the supervisor's healthy state and from nowhere else, so a hung checkpoint stops the
  feed.
* The deadline is a pure comparison of `now`, `last_feed` and `timeout` over the monotonic
  `TimeSource`, `now - last_feed >= timeout` taken modulo 2^32 (`supervisor::elapsed`), so a wrap
  of a 32-bit tick counter is the ordinary case; a timeout past `2^31 - 1` ticks is refused where
  it is set. It is written in Rust with a test across a wrap and NOT yet as an SCE `algorithm`
  document: that generation is open, and is the part of this item that waits on the choice of
  whether an `algorithm` kind is worth a generator for one comparison.
* Landed (step 4b): `wz_session_core::supervisor::Supervisor<N>`, `N` machines, healthy only while
  at least one checkpoint is supervised and every supervised one is armed (a supervisor watching
  nothing is not healthy, so a watchdog is not fed on the strength of nothing), with the limit
  `SUPERVISION_CHECKPOINTS` and the policy `supervision-after-expiry` declared. A model test runs
  every order of five operations up to length 6 under both policies. Landed (step 4c, pico ABI):
  the `supervision` capability (off by default, `core` and `pico`, implies `unstable-api`) and
  the doors `wz_ext_supervision_set_hook`, `_start`, `_feed`, `_stop`, `_check`, `_healthy` and
  `_state`. The library holds no thread and no timer: the program calls `_check` on its own
  cadence, the hook runs on that thread with no lock of the library held (so it may call any door,
  and a stop of its own checkpoint is refused until it returns), and time is milliseconds on the
  monotonic clock in 32 wrapping bits. Not yet: the same doors for the zenoh-c ABI, and the
  hosting test on the cooperative engine.
* Who calls `check` is the `exec` axis and not a new switch: the cooperative engine calls it
  every turn of its loop; a build with tasks gives it one. The supervisor itself has no task.

**Tests.** Conformance over every event order of the machine. A property test of the comparison
across a counter wrap. A host test on the cooperative engine with no task present.

## M4 Resources: a sampled snapshot

**Today.** Counters are per lane and per reason; nothing samples a whole node.

**Design.**

* A snapshot is a versioned, fixed-layout record: CPU use, memory in use and high-water mark,
  tasks, features the image has, and for message intervals a histogram. The layout carries a
  version so a reader of an older image does not misread a newer one.
* The message-interval statistic is `SNAPSHOT_HISTOGRAM_BUCKETS` buckets on a base-2 scale plus
  the sum of the intervals, the form of a Prometheus histogram. A minimum and a maximum hide the
  tail; the buckets do not, and the sum gives the exact mean of any window from two snapshots
  (the difference of the sums over the difference of the counts), which an exponentially weighted
  mean cannot, and which costs a fetch-add where the weighted mean cost a compare-and-swap loop.
  Every count is 64 bits and cumulative, so none saturates or wraps in the life of a node and a
  reader takes windows by subtraction.
* The counter of a receive path that runs on several threads is `IntervalMeter`, lock-free: one
  fetch-add for the message, one compare-and-swap on the latest message, and for an interval two
  fetch-adds. A receiver reads the clock and then stores, so its reading can be a little behind the
  latest (skew, `SKEW_LIMIT_US`); such a message is counted and makes no interval, because counting
  it puts two spans in the histogram that no gap made, one backwards and the next inflated by the
  receiver's delay. A span of half the clock's range or more is no interval and moves the latest.
  The single-thread `MessageStats` takes the same rule, and a test drives both over the same random
  traces. Measured on the build machine (release, one free core, so the four-thread figures are
  time-sliced): one thread 14 ns a message against 5.4 ns for one relaxed fetch-add counter, four
  threads 58 to 61 ns against 8 ns, of which the shared clock alone is 7 to 11 ns.
* The sampler's cadence is the limit `SNAPSHOT_PERIOD_MS`, read by the sampler as a number, and
  NOT an SCE `timer` document. This design said the period would be an SCE `timer` generated from
  the limit by a script with a `--check`, and reading the kind (`sce-build/kind-examples/timer.scxml`
  and the Rust it generates, `tests/forge/expected/timer_diag_scheduler.rs`) shows two reasons it
  cannot be so. First, the period is text in a committed SCXML and the generated file holds one
  constant, while a limit is a compile-time environment value of each image
  (`CONFIG_WZ_LIMIT_...`): the two agree only for the default, and an image that states another
  period would carry a generated constant that disagrees with its own Kconfig, unless every image
  build ran `sce-codegen`, which no hosted or Zephyr build does. Second, what the kind generates is
  a scheduler over a platform `Timer` (`start_periodic(ms, extern "C" callback, ctx)`, raw
  pointers, a callback from an OS timer or an interrupt), which is a timer the platform owns, where
  this sampler is meant to have no task and no timer anywhere. So the sampler is polled by the host
  (`Sampler::poll`, on the loop's tick under `exec = coop-single`, from a task of its own where
  there is one) and asks the comparison the supervisor's deadlines ask, `wrapping_ticks::elapsed`.
  This can be reopened if an image-build regeneration path for `out/**` appears.
* Presentation is a consumer. The snapshot is exposed through the admin space
  (`WZ_CAP_ADMIN_SPACE`) and to the dissector (`wz-capi-dissect`), so the node prints nothing.

**Tests.** The histogram against a reference over a recorded interval trace. A layout test that
the version and the size are pinned. A cost test that a node with the capability off has no
sampler symbol.

## Order and acceptance

| Step | Builds | Done when |
|---|---|---|
| 1 | `HlcCore` over `EpochSource` tested against `uhlc` (done), `NodeHlc` on the core (done), `ClockQuality` machine (done: `clock_standing`, features `clock-quality` and `clock-source`), `clock-quality-stamping` and `CLOCK_MAX_FORWARD_STEP_MS` (done); `clock-source` capability and `CLOCK_SOURCES` move to step 2 | The stamp and wire tests pass on the tokio host and on the cooperative engine; slot bytes unchanged off; the `algorithm` for the comparison is generated and used by Rust. |
| 2 | Clock registration in the C ABIs (2a done: `wz_node_time::clock_registry` and the `CLOCK_SOURCES` limit, first registered source that can answer wins, none able means no date and no fallback to the system clock; 2b done for the pico ABI: `wz_ext_clock_source_register`, `wz_ext_clock_source_unregister` and `wz_ext_clock_report` in `wz_ext.h`, the `clock-source` capability (off by default, `core` and `pico`, implies `timestamping` and `unstable-api`), `z_timestamp_new` stamping from the registered clock through the session's node clock, one standing shared by every node over the registry; open: the same doors in the `capi-c` ABI, and a wire test that a registered clock and the system clock encode the same bytes) | `capi-c` ABI revision and the pico export pins updated in the same change; the drop-in leg stays green. |
| 3 | `EventRing` (3a done: the type, the model test and the stress run), the node's event log `wz_node_time::event_log` with `EVENT_RING_SLOTS` and `EVENT_RECORD_ARGS` as limits and `event-ring-full` as a policy (3b done: one ring, producers ordered by a lock, a reader needs none, records stamped by the node clock); 3c done for the pico ABI: the `event-ring` capability (off by default, `core` and `pico`, implies `unstable-api`) and the doors `wz_ext_event_emit`, `wz_ext_event_read` (a cursor the caller holds), `wz_ext_event_release` and `wz_ext_event_dropped`; the ring contract is sent to SCE. Open, and recommended to be dropped: the `log` sink, which could record only that a call happened (level, site, a hash of its constant text) and not its arguments, because the `log` crate formats them before a sink sees them, so the structured `emit` is the event API and a sink would add a second, weaker one | The model test and the concurrency check pass; off build has no symbol; the ring contract is written down and sent to SCE. |
| 4 | Supervision machine and its checkpoints (4a, 4b, 4c done: the statechart, `Supervisor<N>`, the limit and the policy, the capability and the pico doors; open: the zenoh-c doors, the cooperative-engine host test, the comparison as an SCE `algorithm`) | Conformance over every event order; the cooperative engine hosts it with no task. |
| 5 | Snapshot and its sampler (5a done: `resource_snapshot` with the versioned layout, the interval histogram and sum, the skew rule, the lock-free `IntervalMeter`, the host-polled `Sampler` and the `ResourceSource` port the platform answers CPU, heap and tasks through, the limits `SNAPSHOT_PERIOD_MS` and `SNAPSHOT_HISTOGRAM_BUCKETS`, and `wrapping_ticks` shared with the supervisor; the generated SCE timer is dropped, see M4; 5b2a done: the `resource-snapshot` capability, `TimeSource::now_monotonic_us` (default the millisecond reading scaled, overridden by the tokio and cooperative clocks), and the meter in each session, `SessionCore::rx_intervals`, fed at the receive path's one counting seam beside `transport-stats` so the two count the same messages, read by `message_reading`; the meter is per session because a reading is taken on the session's own clock and two sessions' clocks do not share an epoch, and a session's slot grows by the meter, 8 bytes for each bucket and 24 more, in an image that turns the capability on; open, 5b2b: the pico doors that read the latest snapshot as bytes and the host `ResourceSource`, and 5b2c: the `features` word filled from the image, and the admin-space and dissector readers) | Histogram test against the reference; admin-space and dissector read it. |
| 6 | Cross-instrument: events carry M1 time, supervision expiry writes an event, the snapshot reads the ring's loss count | One integration test per link. |

Each step is its own landing: the declaration, the generated files, the code that reads the
switches, the tests and the gates move together, and no switch exists before the code that
reads it.

## Decisions for the owner

1. **Time resolution.** Internal nanoseconds with NTP64 on the wire, as above, or the 1 ms grid
   `TimeSource` uses. Nanoseconds cost a 64-bit word either way and lose nothing; a millisecond
   grid loses the logical counter's room.
2. **Who raises the supervision deadline.** Caller-driven by default with a task as an adapter
   (recommended, because it works on the engine with no task), or a task by default.
3. **Loss accounting in the ring.** Sequence gaps (recommended), or a counter as well.
4. **Whether a missed `synchronized-only` stamp is an error to the sender or a silent omission.**
   Silent is upstream's behaviour for a missing timestamp, and the recommended default.
5. **The SCE request: asked, answered, and now SCE's decision.** wz asked for `sce:on-full`
   (`reject`, `overwrite-oldest`) on the `queue` kind. SCE answered that it has no such policy and
   no decision, that a queue option does not fit a broadcast ring with per-reader cursors, and
   that the choice (extend the queue, add a ring kind, or keep the ring a wz library) belongs to
   SCE's owner; a new kind must pass SCE's admission axes, where one consumer is a weak case for
   reuse. Nothing in wz waits on it: the ring is a Rust type first. wz owes SCE the written ring
   contract after step 3. Two things were considered and need no request: a one-shot timer (the supervision deadline is
   a duty the host raises, as the session machines' are) and a build-time parameter for the
   sampler's period (the generated-SCXML-with-`--check` pattern the feature model already uses).
   A native build-time parameter would remove the generator and is worth asking for, but it is a
   convenience.

## Not part of this

* A log text format, a console, or a transport for events. The ring is read by a consumer that
  already exists on the node.
* Replacing `uhlc` with SCE's HLC (see M1).
* A hardware watchdog driver. The supervisor says when to feed it; a platform feeds it.
* Per-key last-value caches, which are a different structure (see `docs/rx-delivery-lane.md`).

# The advanced publisher and subscriber on a neutral core

Status: design and survey, not built. Written 2026-10-25 for section 6 of
`docs/capi-pico-on-coop-engine.md` (the advanced plane), after the scouting and replay steps of
that note. Everything stated as a number here was counted on the tree of that day.

## The question

The advanced publisher and subscriber (zenoh-ext, pico's `ze_advanced_*`; atom 5.25) exist once, in
`wz-runtime-tokio`, and both C ABIs reach them through `wz-capi-core`. The cooperative engine
(`wz-capi-coop`) has none of it, and a pico build on it must not link the tokio engine (the size
gate refuses `wz_capi_core::` and `wz_runtime_tokio::` symbols in an `engine-coop` build). So the
plane is either written a second time for the cooperative engine, or its mechanism leaves the
tokio crate and both engines host it. Writing it twice is the choice that lets two readings of
zenoh-ext drift, which is what the scouting and replay steps removed elsewhere.

## What is there

| Unit | Lines | What it is | Depends on |
|---|---|---|---|
| `advanced_ke.rs` | 269 | the `@adv` key grammar | `keyexpr_canon` (already `wz-session-core`) |
| `advanced_cache.rs` | 1,396 | `CacheStore` (the ring and the `_sn`/`_max`/`_time` answer) and `AdvancedCache` | the ring: std `Mutex`, `time_range`, a wall clock read inside the answer; `AdvancedCache` alone is bound to a heap `Session` (it declares the queryable) |
| `advanced_publisher.rs` | 3,163 | `AdvancedPublisherOn<P>`: validation, the order of the four declarations, what a put stamps and retains, the beacon | `AdvancedPublisherPlane` (a trait the host implements), `NodeHlc`, `FallbackStamp`, `PublishOptions`; one task (the heartbeat) |
| `advanced_subscriber.rs` | 8,486 | per-source ordering and dedup, miss detection, recovery queries, history, publisher detection | `DeclarationForms` (a trait), and the heap `Session` itself: `observer`, `drain_deferred_fires`, `buffered_delivery`, `query`, `cancel_pending_query`, liveliness subscribers; two periodic tasks and tokio channels in its channel forms |
| `time_range.rs` | 725 | the `_time` selector grammar | std only |
| `node_clock.rs` | 887 | the node's HLC and the timestamp rules | `uhlc`, `wz-codecs` |
| `timestamp_source.rs` | 322 | the wall clock in NTP64 and the fallback stamp | `node_clock` |

Measured facts the design rests on:

1. **The publisher already has the seam.** `AdvancedPublisherPlane` is the four declarations and
   the sends; the composition is written once over it. `wz-capi-pico`'s `PicoPlane` is its second
   implementation. What keeps the composite out of the cooperative build is where it lives, not its
   shape.
2. **`CacheStore` is already runtime-neutral** by its own account. What binds it is a wall clock read
   inside the answer, which a host can pass in.
3. **The subscriber is the big part, and its decisions are already apart from its wiring.** This
   note first said they were written against the heap session's internals; reading the production
   code (lines 1 to 4,462 of the file; the rest is tests) corrected that. What orders a sample,
   counts a miss, buffers a gap, picks a recovery range, decides history is complete and reclaims
   a quiet source is one struct, `State`, with its per-source states and about a dozen free
   helpers (about 1,500 lines). It touches no session: it takes a sample or an event, calls the
   sample callback and the miss listeners it holds, and RETURNS what the caller must then do
   (`RecoveryRequest`, a `bool` for "issue a get") so that the get is issued with its lock
   released. The wiring around it (about 2,900 lines) is what binds the file to the heap session:
   issuing the gets and feeding their replies back, the in-flight bookkeeping that cancels them,
   the two timer tasks, and the declarations of the subscriber, the heartbeat subscriber, the
   liveliness subscriber and the detection token. That is the host's, and it is the part a
   cooperative engine writes for itself.
4. **The time-driven work is three periodic jobs**: the publisher's heartbeat beacon, the
   subscriber's periodic recovery queries, and its retention sweep (upstream's `gc_task`). Each is a
   task today, spawned onto the process's runtime and aborted when its handle drops.
5. **The cooperative engine has the primitives**: publish with source info and a timestamp, a
   subscriber, a queryable, a liveliness token and subscriber (with history), and a get with a
   deadline. It has no node HLC and no timer: its session moves only when the program reads.

## The structure

The advanced plane is an extension protocol over the session's own pub/sub, query and liveliness
primitives, as zenoh-ext is over zenoh. Its mechanism is therefore written once, **without a
runtime**, and each engine is a host that drives it.

- **A new crate, `wz-ext-pubsub`** (named after the catalog's `ext-pubsub-*` atoms). Pure and std-based (a host profile: the advanced plane is
  not in the MCU profile, so there is no `no_std` case to keep; the crate says std plainly). It holds
  the `@adv` grammar, the cache ring, the time-range grammar, the sequencing and miss rules, the
  history merge, the recovery plan and the beacon's content. It reads no clock and spawns nothing.
- **Time is an input.** A rule that needs "now" takes it as an argument (the ring's `_time` filter
  today reads a wall clock inside the answer). A host that wants the old behaviour passes the same
  clock.
- **A machine per entity, by events and commands.** The publisher's beacon and the subscriber are
  state machines: an event (a sample arrived, a token appeared or went, a recovery answer or its
  deadline arrived, a tick) goes in, commands (deliver a sample, report a miss, ask a range, arm a
  timer, undeclare) come out. It is the shape of `wz_session_core::scouting_host` and
  `replay_cursor`, and the generated statecharts of this repository, so a host pumps it and does
  not reimplement it. The three periodic jobs become ticks.
- **The hosts supply the facts.** Declaring, sending, asking and delivering are the host's, through
  the plane traits that exist (`AdvancedPublisherPlane`, `DeclarationForms`) and a subscriber plane
  of the same kind. The tokio host keeps its tasks and its channels as adapters. The cooperative
  host gives the machine its ticks from the step that already advances the session, and a clock for
  the stamps from its own clock source.

The publisher is not designed first and the subscriber after: the subscriber is what asks for
cancellable queries, liveliness events with history and a timer, and a facade cut from the publisher
alone would be cut again. The two are surveyed together to fix the vocabulary, and landed in order.

## The subscriber's vocabulary

What the machine takes and gives, read off the code that exists. The machine is the moved `State`;
nothing here is a new design, which is the point of reading before writing.

**Events in** (each a method; `now_ms` is the host's clock reading, the one new argument):

| Event | Today | What the machine does |
|---|---|---|
| a live sample | `handle_live` / `ingest(sample, true)` | routes by shape (sequenced, timestamped, neither); delivers in order, buffers a gap, drops a duplicate; may ask for a recovery |
| a recovered sample | `ingest(sample, false)` | the same path, with no new recovery asked (the get that produced it is the one in flight) |
| a get's terminal Final, or a get that could not be issued | `finish_recovery(key)`, `finish_history()`, `finish_timestamped_recovery(zid)` | closes the in-flight slot; when it was the last one, flushes the buffer in order and reports a `Miss` for each hole left |
| a heartbeat beacon `(zid, eid, last_sn)` | `handle_heartbeat` | asks for a bounded `_sn=last+1..hb` get when the beacon is ahead |
| a publisher's liveliness token, put or delete | `handle_late_publisher`, `handle_late_timestamped_publisher`, `open_global_history_slot`, `set_source_alive` | opens a history slot for a publisher seen late, and marks it alive or gone for the sweep |
| the periodic tick | `periodic_requests` | asks `_sn=last+1..` for every source with no get in flight |
| the retention tick | `reclaim_expired_sources(now, period)` | drops the sources not heard from, sparing the live ones |
| a listener declared or retracted | `MissHandlers::register` / `unregister` | the registry the misses fire into |

**Commands out**: a sample to the application's callback, a `Miss` to each listener (both called
by the machine, as today), and the one thing handed back to the host to do: a `RecoveryRequest`
(`zid`, `eid`, `from_sn`, optional `to_sn`), or "issue the history get", or "issue the late
publisher's get". A request becomes a get through a **plan**, a plain value the host executes: the
key expression (`recovery_get_ke`, `history_get_ke`), the selector (`history_selector`, the `_sn`
range, always with `_anyke`), the timeout (`recovery_query_timeout_ms`), the target `All`, no
consolidation, the exposed timestamp, the locality. The plan is pure, so it moves with the
machine and both hosts issue the same get.

**The host's seam**, which is small: issue a plan and give each reply and the terminal Final back
(`Session::query` on the heap session, the engine's `get_on_wire` on the cooperative one); cancel
what is in flight at teardown (the in-flight set, `PendingGets`, is pure bookkeeping over request
ids and moves too, with its cancel-before-recorded ordering); run the two timers as ticks; declare
the four entities in the retraction order `DeclarationForms` already fixes. Replies are turned into
samples by `recovered_sample_from_reply`, which reads a `ReplyView` and so moves as well.

**The clock**: the machine reads `Instant::now()` in three places (the default of a source's
retention, the touch of a source on a sample, beacon or reply, and where the sweep task hands the
sweep its "now"); the sweep's age compares two such readings. The machine takes the host's reading
instead, in milliseconds, so a test chooses the instant and the cooperative engine passes its
clock source. This is the only edit to the logic itself.

**The publisher's beacon** is smaller: a task that publishes the last sequence number every
period, or on demand (`emit_heartbeat_once`). Its decision, whether a beacon is due and what it
says, is a value of the publisher's state; the host's part is the timer. The publisher's plane
trait is already the seam, and the beacon's tick joins it when step 3 moves the composite.

**Tests**: the file has 60 tests after its production code. The ones that drive `State` and the
helpers directly move with them and keep their assertions; the ones that need a session (a real
publisher, a cache queryable and a subscriber on one loopback session) stay with the tokio host and
become its end-to-end legs. The split between the two is counted when step 4 starts, test by test,
and not estimated here. The differential check of step 5 is then a claim about the host seams only,
because the machine is the same code on both sides.

## What a cooperative host cannot give, stated

A cooperative session moves only when the program calls `read` (or runs its read task). A tick
that falls between two reads is seen at the next, so a recovery deadline, a heartbeat or a
retention sweep is as late as the program is slow to read. That is the engine's definition, not a
defect of this plane; it is documented on the plane and not worked around with a thread of its own.

## Steps

1. **Neutral parts** (mechanical, no behaviour change): the `@adv` grammar, the cache ring, the time
   range and the HLC and timestamp rules move to `wz-ext-pubsub`; the tokio crate re-exports them
   at the same paths. The ring takes its "now" from its caller.
   Done so far: the `@adv` key grammar and the `_time` selector (`time_range`, with its nine
   tests) are in `wz-ext-pubsub`, ungated and with the `ext-pubsub-advanced-*` gates dropped from
   the functions (a host links the ones it calls); the cache ring and its answer
   (`advanced_cache`: samples, `CacheStore`, the `_sn`/`_max`/`_time` filters, the reply arms) are
   there too, and the answer takes the NTP64 "now" from a function its host passes, so the ring
   reads no clock. `wz-runtime-tokio` re-exports all of it at the old paths and keeps the
   session-bound `AdvancedCache`. The HLC and timestamp rules did not go into `wz-ext-pubsub`,
   because time is not the advanced plane's: the router's forwarders, the storage services and the
   session stamp through it as well. They are a crate of their own, `wz-node-time` (the wall clock
   in NTP64, the node HLC with its per-role switch and forward-path stamp, and the fallback
   stamper), which sits under both the tokio runtime and, next, the advanced plane's host trait.
2. **The vocabulary** (surveyed; the section "The subscriber's vocabulary" below states it, and
   step 4 builds it): events and commands of the subscriber and of the publisher's beacon.
3. **The publisher on it**: the composite and `AdvancedPublisherPlane` move; the tokio host and
   the pico plane are adapters; the cooperative host gets a plane and the engine port the
   declarations it needs.
   Done so far, in `wz-ext-pubsub`: the composite (`AdvancedPublisherOn`: the four declarations
   in the reference order, what a put stamps, retains and sends, the beacon's decision) and the
   plane trait, with the options, the errors and the shared-memory chunk it names (`ShmChunk`,
   which the tokio runtime's mapped chunk implements). The trait lost its clock: the composite
   cannot read one or spawn a task, so a plane starts the beacon's timer (`start_beacon_timer`
   hands it the tick, which answers false once the publisher is gone) and the timer's handle is
   what the composite drops before it retracts the beacon's publisher. The tokio runtime keeps
   `SessionPlane`, the timer (a task of the `net` runtime, shared with the pico plane) and
   `AdvancedPublisher`, a handle over the composite, because an inherent method cannot be added
   to a type of another crate. The pico plane is an adapter of the same trait. The composite's
   own tests run against a recording plane there; the session-bound ones stay with the tokio
   host.
   Step 3b found the engine port already carries what the publisher declares: the pico plane
   declares its publisher, cache queryable, token and beacon publisher through the port's
   declarations (`SessionEngine::declare_queryable_on_wire`, the liveliness token, the write
   filter and `publish_on_wire_all`), and read the tokio session for two things only, its clock
   (the beacon's sleep) and an on-demand put. So the cooperative engine needed no declaration
   added; it needed the one thing it had no answer to, a periodic job. `start_ticker` and
   `stop_ticker` joined the port (with `Ticker`, which stops the job when dropped), the tokio
   session runs one as a task of the `net` runtime (`wz-runtime-tokio`'s `periodic`, the loop the
   publisher's own timer shares), and the cooperative engine runs it from the call that steps the
   session: the wait of a read is cut short to the job's time as it is for a get's deadline, and
   the job runs after the step with no lock held, one at a time, a period after its last run ended.
   The pico plane's timer is that job, and its on-demand beacon is a port put. What is left of
   step 3 is that pico's `advanced` feature still selects the tokio engine, because the module
   that holds the publisher's entry points also holds the subscriber's; the cooperative
   publisher then follows the subscriber (step 4), and its first witness is a pico build on the
   cooperative engine that declares an advanced publisher.
4. **The subscriber on it**: `State` and its helpers move to `wz-ext-pubsub` (about 1,500 lines,
   and the tests that drive it directly), with the clock made an argument; the tokio host keeps its wiring and calls the moved machine; the
   cooperative host writes its own. The largest step, and the moved code is not rewritten, so what
   changes is where it lives and what it is handed.
5. **Retire the old paths** only after a differential test (the same events into the old and the
   new give the same commands and deliveries) and the existing interop tests pass: the zenoh-ext
   interop (`wz_advanced_pubsub_zenoh_ext_interop`), the pico interop
   (`apfull_advanced_pubsub_pico_interop`) and `advanced_subscriber_faces`.

## What each step touches that a code change alone does not

- The catalog atoms `ext-pubsub-advanced-*` and `ext-pubsub-sample-miss-detection` name features of
  `wz-runtime-tokio`; a new crate re-spells them, and the feature-surface census, the non-default
  test legs, the platform workflow's trigger paths and the self-report baseline each need the crate
  the same commit (the scouting host crate showed the list).
- The ledger reasons of the atoms cite tokio files; moving a cited file moves the pin of
  `reason_review_pin_gate` and the two citation gates, which are the hook's deferred gates and are
  run by hand before a push.
- `wz-runtime-tokio`'s C1bz budget changes as code leaves it, and the new crate has one of its own.
- The size gate's cooperative cases get a case for the advanced plane, with `TOKIO_ENGINE` still
  forbidden: that is the check that nothing of the old home leaked into the cooperative build.

## Not decided here

- Whether the crate's name should say "ext" (zenoh-ext is the reference) or the atom's number; the
  catalog's own wording governs and is read before the crate is created.
- `time_range` exists twice: `wz-runtime-tokio`'s (wz's own grammar and tests) and the
  `zenoh-util` family member's, in `crates/wz-zenoh-util` (derived from upstream's file). They are
  not the same code.
  Settled with the session that lands the family (2026-10-25): the two readings are kept apart,
  and neither `wz-runtime-tokio` nor `wz-ext-pubsub` is to gain a dependency edge to the family
  member (its package is named `zenoh-util`, its directory `crates/wz-zenoh-util`). The family copy is
  held to upstream by its own differential file and departs from it in two places (a lone `s` as a
  duration, and an overflow of the `start;duration` form that is an error and not a panic), so a
  test in the neutral crate that feeds both readings the same strings is welcome when the crate
  lands, and is the one place their disagreements are written down.

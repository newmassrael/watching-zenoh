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
3. **The subscriber is the heavy part.** Its decisions (what order a sample is delivered in, when a
   sequence number is a miss, what range a recovery asks for, when history is complete) are pure,
   but they are written against the heap session's internals and not against a vocabulary.
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

- **A new crate, `wz-ext-advanced`.** Pure and std-based (a host profile: the advanced plane is
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

## What a cooperative host cannot give, stated

A cooperative session moves only when the program calls `read` (or runs its read task). A tick
that falls between two reads is seen at the next, so a recovery deadline, a heartbeat or a
retention sweep is as late as the program is slow to read. That is the engine's definition, not a
defect of this plane; it is documented on the plane and not worked around with a thread of its own.

## Steps

1. **Neutral parts** (mechanical, no behaviour change): the `@adv` grammar, the cache ring, the time
   range and the HLC and timestamp rules move to `wz-ext-advanced`; the tokio crate re-exports them
   at the same paths. The ring takes its "now" from its caller.
2. **The vocabulary**: events and commands of the publisher's beacon and of the subscriber, written
   as types with the tests that state each rule, from the code in `advanced_publisher.rs` and
   `advanced_subscriber.rs` and against zenoh-ext at the pinned version.
3. **The publisher on it**: the composite and `AdvancedPublisherPlane` move; the tokio host and
   the pico plane are adapters; the cooperative host gets a plane and the engine port the
   declarations it needs.
4. **The subscriber on it**: the decisions come out of the heap session's internals into the
   machine; the tokio host adapts them back. The largest step.
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
  `wz-zenoh-util` family member's (derived from upstream's file). They are not the same code.
  Settled with the session that lands the family (2026-10-25): the two readings are kept apart,
  and `wz-runtime-tokio` and the neutral crate do not depend on `wz-zenoh-util`. The family copy is
  held to upstream by its own differential file and departs from it in two places (a lone `s` as a
  duration, and an overflow of the `start;duration` form that is an error and not a panic), so a
  test in the neutral crate that feeds both readings the same strings is welcome when the crate
  lands, and is the one place their disagreements are written down.

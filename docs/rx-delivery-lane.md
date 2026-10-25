# Receive delivery lane

Status: design, not built. Written 2026-10-25 so that what a deployment asks of "callbacks off the
receive path" is decided once, against what the host session already does, and not rebuilt beside it.

## What it is

A subscriber's callback runs where the sample arrives. A deployment that cannot let an application
callback hold up the receive path asks for the callback to run elsewhere: the receive path copies the
sample into a bounded lane and returns, and a separate consumer runs the callbacks in order.

The lane is bounded three ways at once, and what happens at a bound is a policy, not an accident:

- **events**: how many samples wait;
- **bytes**: how many bytes of copied samples wait (a sample's key, payload, encoding and attachment
  are copied, so the callback can run after the receive buffer is gone);
- **callbacks**: how many callback invocations are owed (one sample may reach several subscriptions).

When the lane refuses a sample, the refusal is counted by reason, and the result depends on how the
sample was sent: a reliable sample reports a resource-limit result that is recorded as a LOCAL
delivery failure, not as the peer's fault; a best-effort sample is dropped silently. A snapshot of the
lane (queued, limits, refusals by reason) is readable at any time.

## What the host session has today

Read from the tree on 2026-10-25; nothing here is inferred.

- **Inline after the lock** (`deferred-fire`, `crates/wz-session-core/src/deferred_fire.rs`): the
  observer only RECORDS a fire; the callback runs after the observer lock is released, on whoever
  drains (the drive loop, or the staging call under `LocalDeliveryDrain::Caller`). The queue is an
  unbounded list that is drained to empty each turn. It exists to let a callback call back into the
  session, not to take callbacks off the receive task, and it is not a lane: nothing bounds it,
  nothing counts a refusal.
- **Buffered subscriber** (`Session::declare_subscriber_buffered`,
  `crates/wz-runtime-tokio/src/session/mod.rs`): a projection of each sample is queued up to a
  capacity in EVENTS and handed to a channel receiver; when the queue is full the drive loop WAITS
  (`drain_buffered`), so the transport's own backpressure is the flow control and no sample is lost.
  It gives a consumer a channel, not a callback on a worker. It has no byte bound, no callback
  budget, no refusal policy and no counters, and it is heap and tokio only.
- Neither is named by a capability, a policy or a limit in `deploy/wz-config.toml`.

So the host has the two ends the requirement sits between: callbacks inline (upstream's default) and
a lossless, blocking, event-bounded hand-off. What it lacks is the part in the middle: a lane with
byte and callback bounds, a refusal policy other than "wait", counters, and a no-heap form.

## The knobs

| Name | Kind | Default | Meaning |
|---|---|---|---|
| `rx-callback-offload` | capability | on in host builds, off on the fixed-memory profile | The lane and its consumer are built in. Off, no lane code is linked and a subscriber's callback runs inline, as today. |
| `subscriber-overload` | policy, choice | `block` | `block`: a full lane makes the receive path wait, as the buffered subscriber does today (upstream's blocking channel handler). `reject`: a full lane refuses the sample, counts it by reason, and answers by reliability as above. |
| `DELIVERY_LANE_EVENTS` | limit | 64 | Samples that wait at once. Zero is refused. |
| `DELIVERY_LANE_BYTES` | limit | 65536 | Bytes of copied samples that wait at once. Zero is refused. |
| `DELIVERY_LANE_CALLBACKS` | limit | 256 | Callback invocations owed at once. Zero is refused. Larger than the event limit on a host that admits per subscription, where it never binds (see Design). |

The defaults of the limits are placeholders until measured. The policy default is upstream's blocking
behaviour; the choice `reject` is wz's own and lands with the pair of behaviour tests of C8 in
`docs/build-configuration.md`. Which subscription is offloaded is chosen where it is declared
(`SubscribeOptions::offloaded()`), not globally: a deployment offloads the subscriptions whose
callbacks are slow and leaves the rest inline.

## What has to stay true

1. **Order.** Samples reach callbacks in the order they were admitted, per lane.
2. **Two steps.** Admission is two steps: reserve (an event and its bytes, the sample copied in), then
   publish (the callbacks the sample will make are charged). A refusal at either step returns every
   charge it took; a refused sample takes no callback budget.
3. **Progress.** A sample that owes more callbacks than the whole budget is admitted only when it is
   the only sample in the lane, so a large fan-out is delayed, never starved for ever.
4. **Bytes do not split.** The byte area is a ring; a sample's bytes are contiguous, and a sample that
   does not fit before the end of the ring is placed at the start, the unused tail charged to it. The
   charge, not the sample size, is what the bound counts.
5. **Refusals are counted.** One counter per reason (events full, bytes full, callbacks full, lane
   stopping, no consumer), saturating, and a total. A counter that wraps would hide the overload it
   exists to show.
6. **One consumer.** The lane has one consumer. A sample reserved but not yet published holds the
   head of the lane; the consumer waits for it and does not pass it.
7. **Stop.** A lane that is stopping admits nothing, runs what it admitted, waits for every reserved
   sample to be published, and only then is stopped.
8. **Off is byte-identical.** With the capability off, or a subscription not offloaded, delivery is
   the code of today.
9. **Callbacks may use the session.** The consumer runs callbacks with no framework lock held, as the
   deferred fires do, so a callback may declare, undeclare or query.

## Design

- **The lane is a pure value** in `wz-session-core` (`delivery_lane.rs`), the way `ReplayCursor` and
  `DeclarationSync` are: it holds the bounds and the counters, reads no clock and starts no task.
  `reserve(bytes)` returns a slot (event index, byte offset, charge) or a refusal; `publish(slot,
  callbacks)` charges the callbacks; `front()` returns the head when it is published; `complete(slot)`
  returns the charges; `stop()`, `stats()`. The lane holds counts and places only: its event slots
  are a const-generic array (`DeliveryLane<EVENTS>`), and the BYTES are the host's, in a `Vec` on the
  heap profile and a static array on the fixed-memory one. So there is one set of rules and one test
  suite, and the lane itself needs no allocator.
- **A host drives it.** The tokio host spawns the consumer as a task woken by a notification at each
  publish; the cooperative engine runs the consumer in its poll step; the slot node in its loop. The
  core says "one event is ready", the host decides where the callback runs.
- **Refusal by reliability** is a function of the sample's reliability and the policy, kept in one
  place, so the receive path of each host asks it and does not choose.
- **The sample is copied, on every profile.** A received sample is a view over the link's receive
  buffer, and holding a shared reference to that buffer holds one of the link's receive slots. A slow
  callback would then hold the link's receive pool, which is the very thing offloading the callback
  is for. So the producer copies the key, the payload, the attachment and the encoding schema into
  the lane's byte area, and keeps the small fixed metadata (kind, reliability, QoS, the timestamp,
  the encoding id, the source info) in a record beside the event slot. The receive buffer is free
  the moment the copy is made. The consumer hands the callback a `SampleView` over that copy.
- **Admission is per subscription, so the callback bound is degenerate on this host.** The registry
  fires every matching sink separately with a borrowed view, and there is no point before that fan-out
  where the number of callbacks a sample owes is known. The tokio host therefore admits one lane entry
  per (sample, offloaded subscription) and publishes it with one callback. The callback budget then
  never binds beyond the event count, and its limit is set larger than the event limit. It binds only
  on a host that admits per sample (the slot node's single-slice table, where one record reaches
  several cells), and a per-sample seam in the registry is a separate change that this design does
  not need.
- **`block` cannot wait where the sink runs.** The sink runs under the observer lock, and the consumer
  runs callbacks with no framework lock so that a callback may call the session: a sink that waited
  for room would hold the lock the consumer's callback may be waiting for. `block` therefore waits in
  the drain step after the lock is released, as the buffered subscriber does: a sample the lane has no
  room for is held (copied, outside the lane) until the drain admits it in order. What is held is
  bounded by what one dispatch delivers. `reject` does not wait: it refuses at the sink. The first
  lands as 3b, the second as 3a.
- **Admin metrics** read the snapshot: the existing `adminspace-metrics` surface gains the lane's
  gauges and refusal counters where the capability is on.

## Phases

1. This document.
2. `DeliveryLane` in `wz-session-core`, pure, with a unit test per refusal reason, one for the
   oversized-sample rule, one for the ring's wrap charge, and a model test over many interleavings of
   reserve, publish, front, complete and stop (the shape that tested `ReplayCursor`). DONE. The lane
   takes its bounds as arguments, so it reads no limit: the three limits are declared in phase 3,
   with the first code that reads them (a switch no code reads is not landed).
3. The tokio host, in two parts.
   - 3a: `Session::declare_subscriber_offloaded` with the `reject` answer, the consumer task, the
     lane's snapshot (`OffloadedSubscriber::stats`) and the three limits. DONE
     (`crates/wz-runtime-tokio/src/session/offload.rs`). What is built differs from the plan in
     three ways, each forced by what the code showed:
     * **One lane per offloaded subscription**, not per session: it needs no new field on the
       session, and each subscription has its own bounds and its own order. A lane for the whole
       session is a later change to the session's state.
     * **The refusal is counted, not answered.** The registry's sink returns nothing, so there is no
       way to hand a result back up the receive path from here. `OffloadStats` counts the samples
       lost that were sent reliably apart from those sent best-effort, by the one function
       (`Overload::of`) every host asks. Making a refused reliable sample a recorded local failure
       on the receive path needs a result channel from the sink seam, which is not built.
     * **The sample is copied twice**: into the lane's byte area by the sink, and out into a buffer
       the consumer owns before it calls the callback, because the callback must not run with the
       lane's lock held (it may publish to a key its own subscription matches).
     Tests: a slow callback does not hold the loop up and runs on another thread, in order (with an
     inline control on the dispatching thread); a full lane refuses and counts by reason and by how
     the sample was sent; the byte bound refuses a sample that does not fit; the attachment,
     timestamp, encoding, source and QoS arrive as an inline callback sees them; dropping the handle
     stops the deliveries; and a call off a runtime is refused. The tests found one defect of this
     phase's own, a lock taken twice by the callback cell, which hung the dropping test.
   - 3b: the `block` answer through the drain step, and the policy `subscriber-overload` with it (a
     policy with one value is not a policy, so it is declared when its second value has code), and the
     capability `rx-callback-offload` when the C ABIs' manifests are to name it.
4. The snapshot through `adminspace-metrics`.
5. The cooperative engine and the slot node take the lane, each written by the session that owns the
   file (session 11 and session ef).
6. Measurement: callback latency and receive throughput for inline, buffered and lane, on the same
   machine and condition, before any claim that the lane is better than either.

## Open for the owner

- What the transport does with a reliable sample the lane refused is not decided here. The receive
  path records the failure as local; whether it then stops reading, drops with the counter, or ends the
  session is the transport's, and `block` avoids the question by never refusing.
- Whether the heap profile needs the byte bound at all (it can grow), or only the fixed-memory one;
  this design keeps one set of rules and lets the heap profile state a large bound.
- The defaults of the three limits are measured, not chosen.
- `deferred-fire` is not named by any capability today. Naming it is a separate, smaller change whose
  only effect is that a build can say it has it; it is not part of this design.

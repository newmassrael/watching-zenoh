# The cost of one received sample on the cooperative engine

What the cooperative engine (`wz-capi-coop`, the pico C ABI over it, `rx-lent-only`,
`tx-lend-only`, no `std`, `os-zephyr`) does for ONE Push sample, from the link's read to the
program's callback, set against zenoh-pico's receive of the same sample. The trace is read from
the source; every instruction figure below is an ESTIMATE for a Cortex-M3 at `-O` from the shape
of the code, not a measurement. The measurement that started it is the deterministic QEMU
`mps2-an385` instruction count: instructions per received sample, zenoh-pico 8.6k (8 B payload) and
12.8k (1024 B), wz 21k and 28.5k, so 2.2 to 2.4 times; per round trip 1.55 to 1.84 times.

Line numbers are those of the branch the trace was read on (`rx-sample-cost`); the branch that
fixed items 1, 3, 8 and 12 (`rx-cost-2`) moved them.

## The two paths

zenoh-pico reads the socket into its receive buffer, decodes the transport and network messages
over it, resolves the key, finds the subscriptions under the session mutex and calls each
callback with a sample whose payload is the decoded bytes, stolen and not copied:

- `vendor/zenoh-pico/src/transport/unicast/rx.c` @ `_z_link_recv_zbuf(ztu->_common._link`
- `vendor/zenoh-pico/src/session/push.c` @ `z_result_t _z_trigger_push(`
- `vendor/zenoh-pico/src/session/subscription.c` @ `_Z_CLEAN_RETURN_IF_ERR(_z_session_mutex_lock_if_open(zn)`
- `vendor/zenoh-pico/src/session/subscription.c` @ `_z_sample_steal_data(&sample`

One session mutex pair, no allocation for the sample (the subscription vector aside), no copy of
the payload after the socket read, one key match per subscription with an equal-text fast path
(`vendor/zenoh-pico/src/session/keyexpr.c` @ `fast path for identical key expressions`).

wz, on the cooperative engine:

1. `zp_read` → `CoopEngine::read` (`crates/wz-capi-coop/src/engine.rs:5699`):
   the session lock for the wait, again for the step, the handed-leg queue, then `deliver`.
2. The step runs the session task; the link is a `LaneGate` over the pump
   (`crates/wz-capi-coop/src/lane.rs:1269`, `:1294`, `:1315`), which asks the delivery lane for
   room, under the lane's lock, before each datagram and each further record.
3. The datagram is read in place (`crates/wz-session-core/src/drive.rs:2555` `frame_in_place`,
   `walk_records_in_place`): the frame head, the SN gate, and one walk over the records, each Push
   lent as `IterationEvent::InPlace`. The walk reads each record once (`network_message.rs:1462`).
4. Each record is handed to the link's `on_event`, `dispatch_holding_finals`
   (`engine.rs:1443`): the registry is borrowed, the event fanned to every plane of the
   application layer (`slot_observer.rs:738`), then the subscriber tables reconciled, the staged
   replies drained in a burst and the owed `Final`s taken (`engine/registry.rs:388`, `:433`, `:444`).
5. The subscriber plane resolves the key without a `String` (`pubsub/in_place.rs:280`
   `deliver_lent`) and matches it (`pubsub.rs:939` `fire_lent` → `:2647` `scan_subscribers`).
6. The subscriber's sink writes the sample into the delivery lane under the lane's lock
   (`engine.rs:4373` → `lane.rs:520` `offer`, `:541` `open_sample`): key, payload, attachment,
   schema and timestamp id copied into the arena's ring.
7. After the step, `deliver` (`engine.rs:3240`) and `hand_out` (`:3268`) take the head of the
   lane, look up the subscriber's callback, lock it and call it with a view of the lane's bytes.
8. The callback is the ABI's (`make_subscriber_callback` in `crates/wz-capi-pico/src/pubsub.rs`):
   it builds the `z_loaned_sample_t` marshal and calls the program.

## The costs, one by one

Assumptions for the estimates: a kernel mutex taken and given back through the C seam
(`wz_os_mutex_lock` / `_unlock`, Zephyr's `k_mutex`) is about 150 instructions uncontended; a
heap allocation and its free about 250; `memcpy` about 1 to 1.5 instructions a byte at these sizes;
a byte-scanning pass over a key about 6 to 8 instructions a byte; keys of about 20 bytes; one
subscriber.

| # | Cost per sample | Where | zenoh-pico | Estimate | Textbook fix | State |
|---|---|---|---|---|---|---|
| 1 | Lane lock before the datagram and before each further record (`LaneGate::shut`, `takes_input` / `takes_another`) | `lane.rs:1269`, `:1294`, `:1315`; `drive.rs:2244` | none: back pressure is the socket | 2 pairs, ~300 | the lane publishes its room in an atomic word the gate reads without the lock | FIXED (af33c7f04) |
| 2 | Lane lock twice a record to mark it gated, read only by a debug assertion (`Gated`) | `engine.rs:1455`, `:1514`; `lane.rs:810` | none | 2 pairs, ~300 | debug-only instrumentation costs nothing in release | FIXED (371deeb46) |
| 3 | Per-record fan of the event over every application plane, three to four face lookups (`split`), a subscriber reconcile and a reply burst begun and ended for a record that staged nothing | `engine.rs:1443`; `engine/registry.rs:371`, `:388`, `:433`, `:444`; `slot_observer.rs:738` | one switch on the message, `_z_trigger_push` | ~600 to 1500 (not traced into each plane) | route a lent Push straight to the subscriber plane; reconcile and drain once per datagram, or only when the dispatch staged something (a dirty bit) | PART (b7ec952dc): a lent Push goes to the subscriber plane alone, its reconcile, drains and owed Finals under one face lookup (four before); the drains still run after every record |
| 4 | Key resolution: an alias with a suffix is composed into a bounded buffer | `pubsub/in_place.rs:280` (`resolve_wireexpr_view`) | `_z_get_keyexpr_from_wireexpr`, aliasing when it can | ~100 to 200 | the same as pico's; see 6 for the id route | equal |
| 5 | Matching: a depth pass over the key, then per subscription a shape pass over the pattern, one over the key, and a compare; a lent table has no match cache (`memo_slots` answers 0) | `pubsub.rs:2448`, `:2647` | `_z_keyexpr_intersects` per subscription, equal text first | ~550 per subscription, was | the pattern's `KeyFacts` read at registration, the key's once per delivery, equal text compared without a walk (the queryable plane already does this: `crates/wz-session-core/src/query.rs` @ `pattern_facts`) | FIXED (38f98c32d): ~160 per concrete subscription |
| 6 | No route cache by declared expr id: every sample on a declared alias is matched by text | `pubsub.rs:939` | none by default (its RX cache is off) | after 5, the facts pass | keep the hit list on the peer's alias entry, keyed by the table epoch (zenoh's `Resource::matches`) | open, below pico already after 5 |
| 7 | Lane write: `Record::of` (five parts, the source info cloned), the reservation, key and payload copied into the ring, the record slot written; the sample is sealed, then read back, its `Event` cloned, at `take_front` | `lane.rs:373`, `:520`, `:541`, `:886` | none: the callback runs on the decoded bytes | ~400 + one payload copy (8 B: ~50; 1024 B: ~1.2k) | lend the datagram to the lane instead of copying it: the link already keeps a datagram the session stopped in (`keep`), so the lane can hold offsets into it and give it back at `complete`; or run the callback inline when this thread is the one that would deliver it and no callback runs | open, the largest per-byte item left; see "What is next" |
| 8 | Delivery bookkeeping: `Delivering` (a locked `Vec` of threads, 2 pairs), `take_front` (2 pairs, the last finding nothing), `Handed` → `complete` (1), the callback table lookup (1 pair, a linear find, an `Arc` clone and drop), `Running` (2 pairs with `local-subscriber`), the callback's own mutex (1), `matching` (1 a pass, 2 passes), `queries` (1 a pass, with `queryable`), the ended legs (2, with `query`) | `engine.rs:828`, `:900`, `:3240`, `:3254`, `:3268`, `:3274`, `:3286`, `:3288`, `:3347`, `:3362` | one session mutex pair | ~12 to 15 pairs, ~2k | take every ready head under one lock; an atomic owner word for `Delivering` and `Running`; skip the matching, query and ended-leg queues behind an atomic "something queued" word; the callback cached (done on the branch that caches it across steps) | FIXED (e57499f28): `Delivering` and `Running` on an atomic owner word, each head taken under the take that completes the one before, the matching, query and ended-leg queues and the lane behind words; callback lookup done elsewhere |
| 9 | `read`: the session lock for the wait, for the step, for the tickers; the handed-leg queue; the readiness list's `Arc`s cloned and dropped | `engine.rs:5699`, `:3103`, `:3213`, `:3624` | the read task's one pass | 3 to 4 pairs, ~500 | one session take per read (done on the branch that reads the step clock once) | elsewhere |
| 10 | `sample_shown`: one more boxed closure between the lane and the ABI callback when timestamps are hidden | `engine.rs:1484` | none | ~20 | fold the choice into the ABI callback at declaration | open |
| 11 | The C marshal: the key copied into a `String`, the payload into a `Vec` behind an `Arc`, the attachment the same: three allocations and their frees, two to three copies | `crates/wz-capi-pico/src/pubsub.rs:256` | the sample aliases what the receive decoded | ~750 + one payload copy (8 B: ~50; 1024 B: ~1.2k) | the marshal reads the view in place; what is kept past the call is copied when kept (a payload's clone, an owned sample) | FIXED (850e749a1) |
| 12 | The marshal's encoding: a sample that carries one has it boxed into an owned encoding, its schema copied | `crates/wz-capi-pico/src/pubsub.rs:312`; `crates/wz-capi-pico/src/encoding.rs:143` | the encoding is a value in the sample | ~300 for a sample with an encoding | build it on the program's first `z_sample_encoding` (a once-cell in the marshal) | FIXED otherwise (6c1711159): the encoding is held in the marshal and pointed at by its loaned view, no box; the boxed form was never freed |
| 13 | The callback depth guard and the unwind catch around the program's call | `crates/wz-capi-pico/src/ffi.rs:224` | none | ~20 to 50 | none needed on a build that aborts on panic | open, small |

## What the slopes say

The payload-size slope is the cleanest signal: from 8 B to 1024 B pico adds 4.2k instructions
(4.1 a byte) and wz adds 7.5k (7.4 a byte), so wz pays about 3.3 instructions a byte more. Both read
the socket into a buffer and decode over it; wz then copied the payload twice more, into the lane
(item 7) and into the marshal (item 11). Item 11 is gone on this branch; item 7 is the one copy
left that pico does not make.

The fixed part is the rest of the gap, about 12k at 8 B. By the estimates above it is mostly locks
(items 1, 2, 8, 9: about 20 lock pairs against pico's one or two, ~3k), the per-record registry
fan-out (item 3), the lane's bookkeeping (item 7), the marshal's allocations (item 11) and the
matcher (item 5). None of these figures is measured; the QEMU count after the merge is the test.

## What this branch changes

| Commit | Item | Removed per sample (estimate) | Test that counts it |
|---|---|---|---|
| 38f98c32d | 5 | per concrete subscription: two shape passes and the depth pass, ~400 | `wz-session-core` `pubsub::tests::a_concrete_key_walks_only_the_wildcard_subscriptions`: walks 1 of 3 rows for a concrete key (3 before) |
| 371deeb46 | 2 | two lane lock pairs per record in a release build, ~300 | none can count it: a test build has debug assertions on, which keep the mark; `tests::lane::a_gated_record_that_finds_no_room_is_a_defect` holds in both |
| 850e749a1 | 11 | three allocations and frees, the key copy and one payload copy, ~800 + 1.2 a byte | `wz-capi-pico` `pubsub::tests::a_subscriber_callback_reads_its_sample_where_the_view_holds_it` (the callback sees the view's own addresses) and `a_sample_kept_past_its_callback_copies_what_the_view_lent` |
| af33c7f04 | 1 | the gate's lane lock before each datagram and each further record (2 pairs a record), ~300; a debug build's two pairs a record for `Gated` too | `wz-capi-coop` `tests::lane::the_gate_reads_the_lanes_room_without_its_lock`: ten asks of the gate take the lane's lock 0 times (a lock a call before) |
| e57499f28 | 8 | `Delivering` (2 pairs a read), `Running` (2 a callback), the empty `take_front` and the separate `complete` (2), the second pass (4), the matching and query queues (2 a pass), `is_idle` and the ended legs (2), one of the two tries of the kept callbacks: about 13 pairs, ~2k | `tests::a_received_sample_takes_the_lane_twice_and_an_empty_read_not_at_all` (17 to 24 lane takes for 8 samples, 0 for an empty read, the list of the other deliverers never taken); `engine::deliveries::tests` (one thread asks no lock; a second thread and a callback run outside a delivery are kept apart) |
| b7ec952dc | 3 | the fan over the seven other planes, the watches' staging and three of the four face lookups a record, ~400 to 1000 | `tests::a_received_push_is_handed_to_the_subscribers_alone_under_one_lookup`: 8 Pushes, 8 to the subscribers alone, 8 face lookups (32 before), none to the fan |
| 6c1711159 | 12 | the box and its free for a sample that carries an encoding, ~250, and the box that was never freed | `wz-capi-pico` `pubsub::tests::a_samples_encoding_is_held_in_its_marshal`: the loaned encoding's handle lies inside the marshal |

## Lock pairs of one received sample, counted from the source

One Push of one subscriber, read by one `zp_read`, in a build with `local-subscriber`, `query`,
`queryable` and `liveliness`, release build (no `Gated`):

| Lock | Before af33c7f04 | After 6c1711159 |
|---|---|---|
| Session (wait, step, the handed-leg queue; item 9) | 3 | 3 |
| Lane: gate | 2 | 0 |
| Lane: the sink's offer | 1 | 1 |
| Lane: `take_front`, `complete`, the empty `take_front` of each pass, `is_idle` | 5 | 2 |
| Deliverers' set (`Delivering`) | 2 | 0 (atomics) |
| Running callbacks (`Running`) | 2 | 0 (atomics) |
| Kept callbacks (`resolved`, a try) | 2 | 1 |
| Matching, queries, ended legs, two passes | 5 | 0 (words) |
| The subscriber's callback | 1 | 1 |
| Total | 23 | 8 |

A second sample in the same read adds three: its offer, the take that completes the head before it,
its callback. The brief's target, one pair a sample beside atomics, is not reached: the two lane
takes remain as long as the sample is copied into the lane, which is item 7.



Not repeated here, done on the branch that works the publish side and the read step: the plain
put encoded in one pass, the step clock read once with the session taken twice, the callback cache
across steps, and no spin for a droppable put.

## What is next, in order of expected gain

1. Item 7: deliver from the kept datagram instead of a copy in the lane. Not done on
   `rx-cost-2`: the callback runs with no lock of the library held, and the step holds the
   session for the whole walk of the datagram, so a sample delivered in place needs the walk to
   stop after its record (the link already keeps the datagram it stopped in), the session let go,
   the callback run over the datagram's bytes, and the walk resumed. The key of a sample named by
   an alias is composed in a buffer of the subscriber plane's frame, which is gone by then, so the
   lane would keep the composed key and offsets into the datagram; and the link must not give the
   datagram back, which another thread's step would do, until the callback returns, which needs a
   hold on the link's buffer that the lane takes and `complete` lets go. That is a change of the
   pump (`wz-runtime-coop`) and of the walk (`wz-session-core` `drive`), with a lifetime that only
   the hold enforces, and it removes the two lane pairs of each sample and the payload copy.
2. Item 3, the rest: run the drains only when something was staged. The drains pick up what other
   paths stage between records (the reconcile of a subscriber the program declared, a swept get's
   prune), so skipping them on a Push needs the session core to say, without draining, whether
   anything is staged.
3. Item 9: one session take per read (done on the branch that reads the step clock once).
4. Item 6: the hit list on the alias entry.
5. Item 13: the depth guard and the unwind catch on a build that aborts on panic.

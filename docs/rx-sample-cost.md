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

The branch after it (`rx-cost-3`):

| Commit | Item | Removed per sample (estimate) | Test that counts it |
|---|---|---|---|
| f127d5089 | 12, queries | the box made for every query that carried an encoding, never freed | `wz-capi-pico` `query::tests::a_querys_encoding_is_held_in_its_marshal` |
| 6ef38844a | 7, 8 | the lane's lock: the offer, the take that completes the head before it, the empty take (2 to 3 pairs a sample) | `tests::lane::a_delivery_on_another_thread_gives_the_room_back_with_no_lock`, `tests::lane::the_lane_hands_its_samples_on_in_order_to_one_delivery_at_a_time` |
| ffddef3d0 | 8 | the kept callbacks' lock (`resolved`, 1 pair a pass): a compare-exchange | `engine::try_cell_tests::a_held_cell_is_not_taken_again_until_it_is_let_go` |
| 58fc0293c | 7 | the copy of the sample into the lane (~400 + one payload copy) and its hand-on, for a sample delivered in place | `tests::a_received_sample_is_handed_where_it_lies_and_an_empty_read_hands_nothing` (8 of 8 lent, 0 written into the lane); `tests::lane::a_sample_whose_parts_lie_in_the_lent_datagram_is_handed_where_they_lie` |

## Lock pairs of one received sample, counted from the source

One Push of one subscriber, read by one `zp_read`, in a build with `local-subscriber`, `query`,
`queryable` and `liveliness`, release build (no `Gated`):

| Lock | Before af33c7f04 | After 6c1711159 | After 58fc0293c |
|---|---|---|---|
| Session (wait, step, the handed-leg queue; item 9) | 3 | 3 | 3 |
| Lane: gate | 2 | 0 | 0 |
| Lane: the sink's offer | 1 | 1 | 0 (written under the session's lock) |
| Lane: `take_front`, `complete`, the empty `take_front` of each pass, `is_idle` | 5 | 2 | 0 (an SCE queue, a CAS word) |
| Deliverers' set (`Delivering`) | 2 | 0 (atomics) | 0 |
| Running callbacks (`Running`) | 2 | 0 (atomics) | 0 |
| Kept callbacks (`resolved`, a try) | 2 | 1 | 0 (a CAS) |
| Matching, queries, ended legs, two passes | 5 | 0 (words) | 0 |
| The subscriber's callback | 1 | 1 | 1 |
| Total | 23 | 8 | 4 |

Copies of the payload after the socket read: one into the lane (item 7) before 58fc0293c; none for a
sample delivered where it lies, which is every sample of a link that leaves its datagram in place
(UDP, and a stream since `rx-stream`, below) read while no delivery runs. A sample that is not (a
read made from inside a callback, a chain rejoined from fragments) is still written into the lane
once, and handed on with no lock. The key of a sample delivered in place is copied beside it
when it lies outside the datagram (a key composed from an alias lies in a frame of the dispatch).

The brief's target, one pair a sample, is not reached: the session's lock is taken three times a read
(item 9, the branch that reads the step clock once), and each subscriber's callback has a mutex of its
own, kept so a delivery from the read task and one from the program's own read never overlap.

How the hand-off is made without a lock (`crates/wz-capi-coop/src/lane.rs`, `SharedLane`): the
session writes the lane under its own lock; each sample it publishes is handed to the deliveries as a
handle (event slot, offset) through a queue generated from `sources/session/delivery_lane_queue.scxml`
(SCE `queue`, one producer, one consumer, wait-free: the Lamport ring), and comes back through a
second queue of the same document once its callbacks have returned. The producer is single because
every writer holds the session's lock; the consumer is single because a delivery holds the lane's
delivery word (a compare-exchange). The ring publishes with a Release store of its index and reads with
an Acquire load, so a sample's record and bytes are seen by the delivery that pops its handle. A
sample's record is not the queue's element: it holds a source info and a variant per kind, which an
element of scalars cannot, so it waits in its event slot, a cell of its own, which the handle's push
hands over and its return hands back.

zenoh-pico holds nothing of the session while the callback runs: the session mutex is taken and let go
of inside the lookup of the subscriptions (`vendor/zenoh-pico/src/session/subscription.c` @
`_z_session_mutex_unlock(zn);`, in `_z_subscription_get_infos`) before the callbacks are called
(`vendor/zenoh-pico/src/session/subscription.c` @ `sub_info->_callback(&sample, sub_info->_arg);`), and
its receive buffer stays valid because the one reader that fills it is the thread running the
callback. wz may be stepped from several threads, so a sample delivered where it lies holds the links
back (no receive, no service) until its callbacks return.

A second sample in the same read adds three: its offer, the take that completes the head before it,
its callback. The brief's target, one pair a sample beside atomics, is not reached: the two lane
takes remain as long as the sample is copied into the lane, which is item 7.



Not repeated here, done on the branch that works the publish side and the read step: the plain
put encoded in one pass, the step clock read once with the session taken twice, the callback cache
across steps, and no spin for a droppable put.

## Stream links and a whole batch a step (`rx-stream`)

Measured on a Windows x64 host over loopback, peer mode, the probe of each side pinned to four
CPUs, the cooperative engine's pico library against zenoh-pico's: TCP throughput at 8 B with
batching on, 2.42 M messages/s against 4.88 M, the wz subscriber busy for the whole window and its
publisher for 23% of it. Unbatched TCP throughput wz leads by 1.4 times; batched multicast by 1.13.
So the receive of a sample that arrives in a batch costs about twice pico's. What the receive did
for each such sample, read from the source of the branch before this one:

1. A stream link did not lend: `StreamDriver::receive` moved what followed a batch to the front of
   its buffer as soon as the lend returned, so `lends_until_next_receive` answered `false` and
   every sample of a TCP batch was copied into the lane (item 7, for streams). The move itself
   copied the rest of what one read brought once for every batch in it.
2. A sample handed where it lies held the link back from the next record, not only from the next
   receive: the lent slot held one sample, and the gate shut after it. A datagram of N samples took
   N read steps, each a whole `read` (the session taken twice, the wait worked out, the task
   polled, the clock read, the links moved on, the queue of handed legs looked at, a delivery
   entered).
3. After every Push record the drain of what the dispatch staged opened a burst and closed it, and
   the close flushed the open batch: the lock of every transmit conduit (one; eight with
   `transport-qos`) taken and given back and three sequentially consistent atomics, for a record
   that staged nothing (`crates/wz-session-core/src/slot_observer.rs`, `flush_pending_replies`).
4. A step read the stream again after its batch and found nothing (`EAGAIN`); on Windows each read
   of the stream was a `WSAPoll` and a `recv`.

What this branch changed:

| Commit | Change | Removed (read from the source) | Test that counts it |
|---|---|---|---|
| cec3473f5 | A stream link lends a batch until its next receive; what follows a batch moves to the front only before the stream is read for the rest of one, as zenoh-pico compacts its buffer (`vendor/zenoh-pico/src/transport/unicast/read.c` @ `_z_zbuf_set_rpos(&ztu->_common._zbuf, _z_zbuf_get_rpos(&ztu->_common._zbuf) - _Z_MSG_LEN_ENC_SIZE);`) | the move of the bytes behind every batch | `wz-runtime-coop` `stream_link::tests::a_lent_batch_lies_where_it_was_lent_until_the_next_receive`: 3 bytes moved for three batches of one read, 11 before; the lent batch still where it was lent after a service |
| e6a430162 | A sample lying in the lent datagram is a record of the lane that holds its key (when the key lies elsewhere) and its subscribers' ids, and points at the rest (`lane::Lying`); every sample of the datagram is handed on in the step that read it, in order with what else the lane holds; the link is held back from its next receive, not from the next record, until the last is given back | per sample: the payload's copy into the lane for a stream; per sample after the first of a datagram: a read step | `wz-capi-coop` `tests::lane::the_samples_lying_in_a_lent_datagram_are_handed_where_they_lie`: three samples of one datagram handed on in one step, 13 bytes of the lane each where a copy takes 17, the link held back until the third is given back; CONTROLS a sample offered while a delivery runs and one whose payload lies elsewhere, written whole. `tests::listen::the_puts_of_one_stream_batch_are_handed_where_they_lie_in_a_few_reads`: 32 puts of one TCP batch, 32 lying, 32 handed on, at most 8 reads asserted (one or two when nothing else arrives) where one sample a read took at least 32. `tests::a_received_sample_is_handed_where_it_lies_and_an_empty_read_hands_nothing`: 8 lying of 8 handed on |
| f2b0c6a25 | A drain with nothing staged opens no burst | per Push: one conduit lock pair (eight with `transport-qos`) and three sequentially consistent atomics | `wz-session-core` `slot_observer::tests::a_drain_with_nothing_staged_opens_no_burst`: 16 drains of nothing open no burst; CONTROL a staged answer to an interest opens one |
| a9d542f57 | A Windows stream is read with one `recv`, no `WSAPoll` before it: its socket never blocks | one `WSAPoll` a read | `wz-runtime-posix` `windows::stream::tests::a_read_asks_the_stream_with_no_poll_before_it`: two reads and a wait poll once (the wait), three times before |
| 49eef8275 | A read whose step left a link holding input (a batch behind the one it read, the rest of a datagram the lane had no room for) steps at once, with no take of the session to work out a wait that would be none | per read under load: one take of the session and the wait's work (`Core::idle_wait`) | `wz-capi-coop` `tests::listen::a_read_after_a_step_that_left_input_held_takes_the_session_once`: the read after a held batch takes the session once; CONTROL the first read, twice |
| 4c4d34da4 | The records of a lent datagram are offered with no hold of the lane each; the hold the gate takes at the end of the walk hands them all on and stores the counts once | per sample: the hold's take-back, its hand-on loop and its two sequentially consistent stores, now once a datagram; the room word is still left after each record | `wz-capi-coop` `tests::lane::the_samples_of_a_lent_datagram_are_handed_on_by_one_hold`: three samples, one hold (three before); CONTROL a sample with no datagram lent takes one |

What the read step does for each sample of a batch now, against zenoh-pico's
(`vendor/zenoh-pico/src/session/subscription.c` @ `z_result_t _z_trigger_subscriptions_impl(`):

| Work | wz | zenoh-pico |
|---|---|---|
| decode | one walk over the records (`walk_records_in_place`) | one decode a message |
| key | resolved where it lies; an alias with a suffix composed into a bounded buffer (item 4) | `_z_get_keyexpr_from_wireexpr`, which may allocate |
| match | the pattern's facts read at registration, the key's once, equal text compared first (item 5) | every subscription intersected, each message: its match cache (`Z_FEATURE_RX_CACHE`) is off in its default build (`vendor/zenoh-pico/cmake/feature_config.cmake` @ `set(Z_FEATURE_RX_CACHE 0 CACHE STRING "Toggle RX_CACHE")`), so a cache per declared key id would be past pico, not parity (item 6, open) |
| registry | one borrow and one face lookup a Push, the subscriber reconcile an epoch compare, the drain skipped when nothing is staged | the session mutex taken and given back for the lookup |
| lane | `Record::of` (the source info cloned), a reservation of the key's bytes when it lies outside the batch and the subscriber's id, a handle through the SCE queue and back: no lock | none: the callback runs on the decoded bytes |
| delivery | the callback's own mutex, one pair | none |
| marshal | views where the sample lies (item 11) | the sample aliases the decoded message |
| clock | none a sample: the session's loop reads it once an iteration (two a batch) and the read step once (`tests::a_read_step_reads_the_clock_once_and_takes_the_session_for_its_wait_and_its_step`) | none a message |

Left per sample: the callback's mutex (kept: a session's own put hands its subscribers the sample
on the putting thread with `local-subscriber`, beside the lane's delivery), the lane's record and
handle, the copy of a key that lies outside the batch (an alias's text, which the end of the lease
could let go of while the sample is out), and the borrow and face lookup of the registry. Left per
batch: the read step's two takes of the session and its look at the handed legs (item 9).

Two things the hold of a lying batch costs, by design. A session with several faces reads one
face's batch a step: the hold is the lane's, so every link waits for the samples of one to be
given back. A read made from inside a callback (a delivery runs) writes its samples into the lane
whole and holds no link back, since the callback may be waiting for what the link brings next.
None of the figures above is a measurement after the change; the Windows probes against the same
pico library are the test.

A profile of the subscriber under a saturating batched TCP publisher, taken after the first four
commits (`SampleLane::offer_from` 9%, `memmove` 8%, the lane's hold and give-back and take 11%,
`idle_wait` 6%), read against the source: the samples are lent, not copied. Every link of that
chain forwards `lends_until_next_receive` (`LaneGate`, `AdmissionGate`, the `Rc`, `IpDriver`,
`StreamDriver`), a frame cut by the end of a read is the only one left unlent (the complete ones
before it are lent where they lie), and the one read task delivers after its step, so no delivery
runs while the step offers. `offer_from` is the body of both offers, and on the lying path it still
reads the sample's nine fields, writes its key (an alias's, resolved outside the batch) and its
subscriber's id with two `memcpy`s, and moves a record of about 180 bytes into its slot and out of
it again at the delivery: that is where the `memmove` is, not in a payload. What bounds a read is
the lane's event slots: each sample lying in the batch takes one, so a read hands out at most 63
(`DELIVERY_LANE_EVENTS` 64) and a batch of 8 B puts takes about three reads. The two commits above
take the per-read and per-hold work that profile showed; a record for a whole batch's samples, one
slot and one handle a batch, is the next step and the one that removes the record's moves.

## One record of the lane a lent batch (`rx-batch`)

The samples of a datagram, a stream's batch, whose parts lie in it are one record of the delivery
lane (`crates/wz-capi-coop/src/lane.rs`, `BatchRecord`): one event slot, one handle through the
SCE queue and back, one hold of the link. Its bytes are an entry a sample (`EntryHead`: kind,
reliability, QoS, where the key and the payload lie in the datagram, how many subscribers; an
`EntryRest` after it only for a sample that carries an attachment, an encoding, a timestamp or a
source), the key when it lies outside the datagram, and the subscribers' ids. The delivery walks
the entries and calls each subscriber's callback with a view built on its stack from the entry
(`BatchSample`), in the order the samples came, as zenoh-pico calls each callback as it decodes
(`vendor/zenoh-pico/src/session/subscription.c` @ `z_result_t _z_trigger_subscriptions_impl(`),
and gives the batch back once, after the last callback.

For N samples of one lent batch, one subscriber, a key named by an alias (so resolved outside the
datagram), read while no delivery runs:

| Per batch of N | Before (`rx-stream`) | After |
|---|---|---|
| Lane records (event slots, handles pushed and popped, `take`, `HeldHead`, give-backs, `complete`) | N | 1 |
| The ~180-byte `Record` built, compared with the one held open, moved into its slot and out at the take | N | 0 (an entry's head written and read back unaligned, the batch's counts rewritten in place) |
| Key copies | N | 1 (the first sample; the ones after it on the same key compare and share it) |
| Holds of the link (`lends_a_datagram`) | 1 | 1 |
| Samples a read hands out | at most 63 (`DELIVERY_LANE_EVENTS` 64, a slot each) | bounded by the lane's bytes and callbacks owed (`DELIVERY_LANE_CALLBACKS`, 256 by default), not its slots |
| Callbacks | N, in order | N, in order |

The tests that count it, in `wz-capi-coop`: `tests::lane::the_samples_of_a_lent_datagram_are_one_record_handed_where_they_lie`
(three samples, one record handed on, three lent, one take, the key at one address in the lane for
the three; CONTROLS a sample offered while a delivery runs and one whose payload lies elsewhere,
written whole, a record each), `the_samples_of_a_lent_datagram_are_handed_on_by_one_hold` (one
hold, one record, three callbacks in order), `a_lent_batch_takes_one_event_slot_however_many_samples_it_holds`
(ten samples through a lane of two event slots; CONTROL two samples written whole fill it),
`a_lent_sample_for_several_subscribers_is_one_entry_of_its_batch`,
`a_lent_sample_with_a_part_elsewhere_is_written_whole_in_order`,
`a_key_that_lies_in_the_lent_datagram_is_read_there` (no key copy),
`a_lent_sample_with_every_part_is_handed_from_its_batch_as_it_was_offered`; at the engine,
`tests::listen::the_puts_of_one_stream_batch_are_handed_where_they_lie_in_a_few_reads` (32 puts of
one TCP batch: one record, 32 lent) and `tests::a_received_sample_is_handed_where_it_lies_and_an_empty_read_hands_nothing`.

What is kept: a sample offered while a delivery runs (a callback that reads its session) is written
whole as a record of its own, and holds no link back; a sample with a part outside the datagram is
written whole after the batch before it is published, and the samples after it open a batch of
their own, so each subscriber's order is the order the samples came. The gate's room is the room
of one record, as before; a batch grows by at most one entry a record, which `read_bytes` counts
(a message shorter than an entry is counted as long as one), and the event slot the gate asks for
is the one a record written whole would take.

Not done, and why: a key named by an alias is still copied once a batch. The text lies in the
peer's alias table, which a later record of the same datagram (an undeclaration, a redeclaration)
or the end of the face's lease may change while the batch waits for its delivery, and the
delivery runs without the session's lock, so it cannot read the table there; matching the key to
the subscribers is done in the step for the same reason, under the session's lock, where the
records before it in the datagram have been applied. A key that lies in the datagram (a literal
key) is not copied at all. Not measured: the instruction counts and the Windows probe after the
change are the test of the estimates above.

## What is next, in order of expected gain

0. Done on `rx-cost-3`: item 7 for a link that leaves its datagram in place (58fc0293c); on
   `rx-stream` for a stream link too, and for every sample of a batch in one step. Open beside
   it: a lwIP link (`ip_stack`) gives its slot back when the lend returns and so answers
   `lends_until_next_receive` false; claiming the slot until the callback returns is the next step
   there. The transport counters (`transport-stats`) now count a lent record by its class
   (6cc5137dc) for the unicast receive; the multicast receive still decodes owned under them. A build
   with `rx-lent-control` and without `rx-control` lends an Oam as a record of an unknown id, which
   the counters file as undecoded where the owned walk files an Oam.
1. Item 7, as it stood before this branch: deliver from the kept datagram instead of a copy in the lane. Not done on
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

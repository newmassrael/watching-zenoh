# What a batched put costs on the cooperative engine's publisher path

A program that publishes inside a batch window (`zp_batch_start` .. `zp_batch_stop`) over a TCP
link, measured on the shipped cooperative library against zenoh-pico 1.10.2 on one Windows x64
host: at 8 B payloads 0.95 M messages/s against 2.9-3.3 M, and 1488-1531 ns of process CPU a
message against 543-657 ns; at 64 B 0.83 M against 1.5-2.5 M. Without the window the two send
about as many messages a second and wz spends 1.28x the CPU a message; the resident set is
1.19-1.23x. Linux shows the same shape (8 B and 64 B throughput 1.2-1.4x behind).

This note walks the publisher's call, `z_publisher_put` with NULL options on a declared
publisher (the throughput example's loop:
`vendor/zenoh-pico/examples/unix/c11/z_pub_thr.c` @ `z_bytes_clone(&p, z_loan(payload));`),
through both libraries, counts what each does per message, and names the fix of each difference.
Line numbers are this branch's. The estimates are costs counted from the code on a 3-5 GHz x86
host, uncontended, not shares of a measured profile: an uncontended lock round trip of the
runtime's host lock about 20-30 ns (the lock and the guard stack of `crates/wz-runtime-coop/src/cs.rs`
`Held::enter`), an atomic read-modify-write about 5-10 ns, a `poll` call 1-3 us.

The build is the C ABI preset's (`configs/profiles/host-peer-ext.conf`): the cooperative engine
with `tx-lend-only` and `rx-lent-only`, `group-host` built (the default
`multicast-transport`), no group joined, `local-subscriber` and `transport-stats` off.

## 1. The two calls, layer by layer

| Step | zenoh-pico | wz, cooperative engine |
|---|---|---|
| payload | `z_bytes_clone` copies the slice vector and takes a count (`vendor/zenoh-pico/src/collections/bytes.c` @ `return _z_arc_slice_svec_copy(&dst->_slices, &src->_slices, true);`) | `z_bytes_clone` (`crates/wz-capi-pico/src/bytes.rs:1024`) clones the `Arc` and boxes it from a per-thread cache (`bytes.rs:459`); the put takes it back (`take_moved_bytes`, `crates/wz-capi-pico/src/pubsub.rs:1639`) and drops it at its end |
| options | `z_publisher_put_options_default` fills four pointers (`_z_publisher_put_impl`) | `publisher_put_options` (`pubsub.rs:1671`); before this branch it built a whole `PublishOptions` and dropped it unread |
| session | `vendor/zenoh-pico/src/api/api.c` @ `_z_session_rc_t sess_rc = _z_session_weak_upgrade_if_open(&pub->_zn);`: two counted operations | `is_closed`, one atomic load (`PlainPublisher::publish_plain`, `pubsub.rs:1336`) |
| write filter | a field read: `vendor/zenoh-pico/include/zenoh-pico/net/filtering.h` @ `return ctx->state == WRITE_FILTER_ACTIVE;` | `put_plain_filtered` (`crates/wz-capi-coop/src/engine.rs:4828`): before this branch three takes of the session's lock and a key-expression search of every face's peer declarations each put (section 3, rows 1 and 2) |
| build the message | `_z_n_msg_make_push_put` on the stack, in `_z_write` | none: the Put is written from the caller's parts (`send_plain_put_qos`, `crates/wz-session-core/src/session_actions.rs:13710`) |
| size | none: encode, and roll back on overflow | before `coop-cpu`, a pass of the writer into a counting sink first (`session_actions.rs:13751`); `coop-cpu` works the size out from the parts (`lent_push::plain_put_len`) |
| send gate | none beyond the transmit lock | `congestion_close_ordered` (`session_actions.rs:10205`, the out-of-band lock) and `session_send_available` (`session_actions.rs:7939`, the link's `transport_available` lock): two lock round trips |
| transmit lock | `vendor/zenoh-pico/src/transport/common/tx.c` @ `ret = _z_transport_tx_mutex_lock(ztc, cong_ctrl == Z_CONGESTION_CONTROL_BLOCK);` | the conduit's lock, tried (`session_actions.rs:11379`), and the conduit's sender flag set and cleared, two sequentially consistent stores (`SenderInside::mark`, `session_actions.rs:11030`) |
| append | encode into `ztc->_wbuf`, the transport's buffer (`vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_send_n_msg_inner(`) | `append_lent_batch` (`session_actions.rs:5070`): the link's slot table locked (`:5101`), the open frame's slot taken out of it, its memory asked of the driver again (`TxLease::resume`, `crates/wz-session-core/src/tx_lease.rs:139`), the Put written through `dyn TxBuf` calls, the slot put down (`hold`) and back in the table |
| batch full | roll back, flush, open, re-encode (`vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_batch_overflow(`) | the same roll back and flush, then a new frame: the link asked for room before the frame opens (`congested` -> `StreamDriver::wait_for_room` -> `poll`), a slot acquired, the clock read and the link's last-write stamp locked at the flush (`emit_on_link`, `session_actions.rs:5774`) |
| count | `ztc->_batch_count++` | `batch.stage.count += 1` under the conduit's lock; no atomic counter without `transport-stats` |

Function layers between the C call and the buffer: pico 7 (`z_publisher_put`, `_z_publisher_put_impl`,
`_z_write`, `_z_send_n_msg`, `_z_transport_tx_send_n_msg`, `_z_transport_tx_send_n_msg_inner`,
`_z_network_message_encode`); wz about 14, counted on the source with inlining aside, two of them through `dyn` (the engine port
`dyn SessionEngine`, `pubsub.rs` `Engine`; the body encoder `as_encoder`) and the buffer writes
through `dyn TxBuf`.

## 2. Per message, counted

| | zenoh-pico | wz before this branch | wz after this branch |
|---|---|---|---|
| lock round trips | 1 (transmit) | 7: session x3, out-of-band, `transport_available`, conduit, slot table | 2: session, conduit |
| atomic read-modify-writes | 2 (session count) + 2 (the payload's count, taken and dropped) | 2 (payload `Arc`) + 2 sequentially consistent stores (sender flag) | 2 (payload `Arc`); the sender flag's two stores `Relaxed`, the send gate's two reads `Acquire` loads (plain loads and stores on x86) |
| thread-local accesses of the host lock | 0 | a push and a pop of its guard stack, each runtime lock | 0: each lock's guard is held by the value that took it |
| clock reads | 0 | 0 a put; 1 a flushed batch | the same |
| allocations (std, warm) | the clone's slice vector | 0 (the box cache) | 0 |
| key-expression searches | 0 | 1 a put (every face's peer subscribers) | 0 while no face's tables were written |
| options built | 0 | 1 `PublishOptions`, built and dropped | 0 |
| driver calls | 0 | 1 `tx_slot_storage` a put; a `poll` and an acquire a batch | 0 a put; an acquire a batch, and a `poll` only after a write the socket did not take whole |
| statistics counters | 0 | 0 (`transport-stats` off) | 0 |

## 3. The costs, by expected gain

| # | Cost a message | wz | zenoh-pico | Estimate | Fix | State |
|---|---|---|---|---|---|---|
| 1 | The session's lock taken three times with `group` built (twice without): the filter's `holds_back` took it for the group check and again for the answer, and the send a third time | `engine.rs:4828` | no session lock on the put | 40-60 ns | one take for the answer, the own-subscriber check and the sends (`holds_back_in`, `engine.rs:4075`) | done |
| 2 | The filter's answer recomputed every put: a key-expression intersection over every face's peer subscribers | `Registry::peers_declare`, `crates/wz-capi-coop/src/engine/registry.rs:271` | the filter's state, moved by the declarations (`filtering.h` above) | 40-120 ns, more with more declarations | the answer kept with the registry's count of writes to a face's peer tables (`peers_match_kept`, `engine.rs:4097`; `Registry::writing`, `registry.rs:265`) | done |
| 3 | A `PublishOptions` built and dropped for a put that carries nothing | `publisher_put_options`, `pubsub.rs:1671` | four pointers | 15-40 ns | fold to `None` and take the plain path | done |
| 4 | The Put written twice to learn its size | `session_actions.rs:13751` | encoded once | 30-80 ns | worked out from the parts | done on `coop-cpu`, not redone here |
| 5 | Two lock round trips at the send gate: the sticky congestion order behind the out-of-band lock, and the link's availability behind its own | `congestion_close_ordered`, `session_send_available` (`session_actions.rs`) | none | 40-60 ns | the sticky order as a `send_gate::Latch` of the out-of-band slot, raised where `request_congestion_close` stages its request and never lowered; `transport_available` as a `send_gate::SendGate` (a `pub` field the tokio runtime also writes: `session_glue.rs`, `multilink.rs`, `shm_auth_segment.rs`, `session/tests.rs`, three integration tests). Release stores and Acquire loads: no user reads and writes either flag in one step, so the pair gives every edge the lock gave | done |
| 6 | Per append, the link's slot table locked, the open slot taken out, its memory asked of the driver, put down and put back | `append_lent_batch` (`session_actions.rs`), `TxLease::resume` (`tx_lease.rs`) | appended to the transport's own buffer | 30-50 ns | the open frame kept in the conduit's `BatchStage` as a `tx_lease::OpenSlot` (the slot with where its memory is), which the conduit's lock guards, and picked up with `TxLease::pick_up`, which asks the driver nothing; the link's `batch_slots` record (two `Relaxed` atomics a conduit, ordered by the conduit's lock) is written when the frame opens and cleared before its slot is sent or aborted, so a record that names the slot is the proof the pointer is still good. The holder search of `transport-multilink`, the reopen abort and the move off a leaving link read it; the own link's record is read first, one load | done |
| 7 | A `poll` for room before each frame opens, then the write | `StreamDriver::wait_for_room`, `crates/wz-runtime-coop/src/stream_link.rs`; `poll_writable`, `crates/wz-runtime-posix/src/net.rs` | the write alone | 1-3 us a batch, 6-18 ns a message at 2048 B batches of 12 B messages | the write is tried first (`StreamSocket::send_parts_now`: one `sendmsg` with `MSG_DONTWAIT` on POSIX, one `WSASend` on Windows, whose stream socket stays non-blocking from its connect on) and the socket is asked for room only after a write it did not take whole, until one is taken whole again. Nothing waits inside a send: the rest of a partial write is owed by the link (the lent slot held until it is written, a frame handed over as bytes copied into a slot of the link's or onto the heap), and the next step that finds the stream room (a send, a question of room, the loop's service) writes it before anything after it. While a link owes, its owner's wait wakes on its room as well as its input (`SessionDatagramLink::owes_write`, `AndRoom`), so the rest leaves as soon as the stack takes it and not at the next input; owing nothing, the wait is for input alone. A question of room reports the wait the stream measured | done |
| 8 | Each runtime lock on a host also pushes its guard onto a thread-local stack and pops it | `cs.rs` `Held::enter` | the lock alone | 5-10 ns a lock, five locks | a `Held` that owns its guard, as the `host-lock-sys` form does; the stack was not a re-entrancy check (a value's lock is not reentrant), only where the guard was kept. The guard is held in a `ManuallyDrop` and let go only inside `Held`'s out-of-line drop, so each instance of `with` still carries two calls and no release of its own: the text-size reason the stack was chosen for is kept, to be confirmed by the size gate | done |
| 9 | The sender flag's two sequentially consistent stores | `SenderInside` (`session_actions.rs`) | none | 10-20 ns | `Relaxed` stores and load: the flag carries no data, its one reader reads the conduit only under the lock, and the lock's acquire and release keep the mark and the clear inside the holding; a late read costs a spin or a drop pico's try-lock would also make (the argument is on `SenderInside`) | done |

Not a cost found here: a clock read per put (none; one a flushed batch, where pico marks its
transmission at the flush), an allocation per put on a warm thread, a statistics atomic per put
(`transport-stats` gates every counter, `unsent_drops` included), an express check (one
branch), a batch-full check through a generic encoder (the Put is written into the slot and its
length compared once, as pico encodes and checks `_z_wbuf`).

pico can hold its transmit lock across a whole window
(`vendor/zenoh-pico/include/zenoh-pico/transport/transport.h` @ `static inline bool _z_transport_batch_hold_tx_mutex(void) {`),
off in its default build (`vendor/zenoh-pico/cmake/feature_config.cmake` @
`set(Z_FEATURE_BATCH_TX_MUTEX 0 CACHE STRING "Toggle tx mutex lock at a batch level")`), so the
reference measured takes one lock a message.

## 4. What this branch changed

* A plain put through a write filter takes the session's lock once: the filter's answer, the
  session's own subscribers and the sends under one take, where it took three with `group` built
  and two without; the filter's own question takes it once too (row 1). Test:
  `tests::plain_put::a_plain_put_through_a_write_filter_takes_the_session_once`.
* A write filter keeps what the peers' declarations answered with the registry's count of the
  times a face's peer tables were handed out to be written or a face came or went
  (`Registry::faces_written`), and searches again only when the count moved; the session's own
  subscribers, which no face holds, are asked each time (row 2). Test:
  `tests::plain_put::a_write_filters_answer_is_kept_until_a_face_is_written`, which counts the
  searches through `CoopEngine::peer_looks`.
* A publisher's put whose options carry nothing, NULL or default, builds no options and takes
  the publisher's plain path (row 3). Test: `pubsub::put_options_tests::put_options_that_carry_nothing_fold_to_none`.
* The send gate reads its two flags without a lock: a link's `transport_available` is a
  `send_gate::SendGate` and the session's congestion-close order a `send_gate::Latch`, both
  written with Release and read with Acquire (row 5). Tests: `send_gate::tests` in the session
  core; the tokio runtime's tests of the gate (`once_the_congestion_close_is_ordered_the_next_send_is_refused_without_waiting`
  and the `TransportUnavailable` tests of `session/tests.rs`) read the same behaviour through it.
* A batch frame open in a lent slot stays in its conduit between the messages that fill it, with
  where the slot's memory is (`tx_lease::OpenSlot`): an append takes no lock of the link's and
  asks its driver nothing, and the link's record of the slot is written at the open and cleared
  before the slot is sent or aborted (row 6). Tests: `tx_lease::tests::an_open_slot_is_picked_up_again_without_asking_the_driver`
  (four pick-ups, one question, against five for the held form), and in the tokio runtime
  `lent_slot_send::a_window_asks_its_link_where_the_slot_is_once_whatever_its_messages` (eight
  messages and the flush ask once; the same window asked nine times before).
* A stream link tries its write before it asks the socket for room, and asks only after a write
  the socket did not take whole; what a write leaves is owed and written by the next step that
  finds room, never by waiting inside the call (row 7). Tests:
  `stream_link::tests::a_stream_that_takes_each_write_whole_is_asked_for_room_once` (three frames,
  one question; CONTROL three), `..::a_frame_taken_half_is_finished_by_the_next_step_before_any_new_frame`
  (half taken, then would block: the call returns, nothing waits, the rest leaves before the next
  frame), `..::a_lent_frame_keeps_its_slot_until_the_stream_has_taken_it_all`,
  `..::a_question_of_room_reports_the_wait_the_stream_measured`, in the POSIX runtime
  `a_link_that_owes_the_stream_is_woken_by_room_and_writes_the_rest` (room alone wakes the owner
  once and that step writes the rest; CONTROL: owing nothing, room does not wake it) and
  `a_timed_wait_for_room_reports_the_time_it_took`, and
  `a_write_that_does_not_wait_takes_what_the_stream_has_room_for` in both the POSIX and the
  Windows stream sockets.
* A host lock of the runtime keeps its guard in the value that took it, not on a thread-local
  stack (row 8). Tests: `cs::tests::a_cell_is_let_go_when_its_closure_unwinds`,
  `cs::tests::nested_cells_are_held_together_and_let_go_in_turn`.
* The sender flag is stored `Relaxed` (row 9). Tests: `session_actions::sender_inside_tests`.

Rows 1 to 3 take two lock round trips, a key-expression search and an options build and drop
off each put: about 100-200 ns of the 830-990 ns a message the measurement shows, by the
estimates above. Rows 5 to 9 take three more lock round trips, a driver call, two sequentially
consistent stores and the host lock's thread-local work off each put, and the `poll` off each
batch: about 110-200 ns a message more, by the same estimates. What is left of the gap
is not located by reading the code, and none of these estimates is a measurement.

## 5. Measuring it

The process CPU a message counts every thread: the read task and the lease task of both
libraries are in it. Reading the publisher's thread apart from the read task's (per-thread CPU
time beside the throughput) says whether the gap is the put's or a task's; nothing in the code
read here makes the read task run once per put, but that is read, not measured. The tests count
the takes (`CoopEngine::takes`), the searches (`CoopEngine::peer_looks`), the questions to a
lending driver (`lent_slot_send`'s `storage_asks`) and the socket's waits for room (`stream_link`'s
`room_waits`); a profile of the publisher's thread, taken again after rows 5 to 9, is what says
how much of the estimate each of them was.

## 6. One round trip

Measured on the same Windows x64 host over loopback, peer mode, each probe pinned to four CPUs:
TCP round trip at 8 B, median 46.5 us for wz against 30.0 us for zenoh-pico, the pong answering
47 k pings in the time pico's answered 68 k; over multicast wz is 1.06 times pico's. After
`rx-stream`, the median at 8 B was 1.43 times pico's on Windows (43.8 against 30.7 us) and 1.42
times on Linux (13.1 against 9.3 us), and the pong's CPU a round trip 1.63 times pico's on Linux.
This section traces one round trip of the pong side on the cooperative engine (the read task
wakes, steps, delivers, the callback puts, the put writes) against zenoh-pico's, and counts what
each does. Read from the source, not measured.

zenoh-pico's read task reads the socket with one blocking `recv` bounded by the socket's receive
timeout (`vendor/zenoh-pico/src/link/transport/tcp/tcp_windows.c` @
`int rb = recv(sock._sock._fd, (char *)ptr, (int)len, 0);`), with its mutex let go of, decodes,
takes the session mutex for the subscription lookup and calls the callback, whose put takes the
transmit mutex and sends. A client's read task reads so with no wait before the read
(`vendor/zenoh-pico/src/transport/unicast/read.c` @ `_z_unicast_client_read`).

| Step | zenoh-pico | wz before `rx-stream` | wz after `rx-stream` | wz after `rtt-poll` |
|---|---|---|---|---|
| wait for the ping | the `recv` below, blocking | `WSAPoll` (`poll` on POSIX), the read's wait with nothing of the session held, after one take of the session to work the wait out | the same | POSIX: the `recv` below, blocking, with nothing of the session held, after the take that works the wait out and lends the read the link's buffer; Windows: as after `rx-stream` |
| read the batch | one `recv` | `WSAPoll(0)` and `recv` on Windows (one `recv` on POSIX), under the step's take of the session | one `recv` (a9d542f57) | POSIX: the wait's `recv`, into the free part of the link's receive buffer, landed on the link by the step's take before it reads; Windows: one `recv` |
| look for more in the same step | none | a second read of the stream, which found nothing: `WSAPoll(0)` on Windows, a `recv` answering `EAGAIN` on POSIX | none: the pong's sample lies in the stream's buffer, so the link is not read again until it is delivered (cec3473f5, e6a430162) | the same |
| after the Push record | nothing | the drain's burst: the conduit's lock taken and given back to flush nothing (eight with `transport-qos`) | nothing (f2b0c6a25) | the same |
| hand the sample over | session mutex for the lookup, then the callback | the step lets go of the session; the delivery takes the sample from the lane's queue and locks the callback's mutex | the same, the sample read where it lies rather than from a copy | the same |
| the pong's put | the transmit mutex, one `send` | one take of the session, the conduit's lock, one `WSASend` tried first, no wait for room (section 3, row 7) | the same | the same |
| the handed legs | none | one look under their lock each read | the same | the same |
| wakes | none | none: the put writes on the callback's thread; only a put that finds the session held by a step hands its leg to that step (`CoopEngine::hand_off`), and nothing is woken for it | the same | the same |

System calls a round trip, pong side: zenoh-pico 2 (`recv`, `send`); wz before `rx-stream` 5 on
Windows (`WSAPoll`, `WSAPoll`, `recv`, `WSAPoll`, `WSASend`) and 4 on POSIX (`poll`, `recv`,
`recv`, `send`); after it, 3 on both (the wait, `recv`, the send); after `rtt-poll`, 2 on POSIX
(`recv`, `send`), as zenoh-pico's, and 3 on Windows. The receive timeout is set on the socket only
when a read asks for another wait than the one set last, so a session with nothing due before its
idle wait sets it once (a `setsockopt` beside the `recv` when a deadline shortens the wait, which
is the count the `poll` it replaces cost). Lock pairs: zenoh-pico 2; wz 3 takes of the session (the
wait, which now lends the buffer, the step, which first takes it back, and the put), the handed
legs, the conduit and the callback's mutex.

The buffer handed to the read. The read's wait is made in the read of the link when it is the one
thing waited on: one stream link of the session, waited on for its input alone (a link that owes
its stream the rest of a frame is waited on for room as well, which a read cannot), with no port,
group, other link or program clock word beside it (`Core::idle_wait`). Under the session's lock
the link moves what is left of a batch to the front of its buffer, as a receive does, and lends
the free part behind it (`SessionDatagramLink::lend_rx`), only where a receive could be asked: no
sample lies in a datagram a link lent (`SharedLane::lends_a_datagram`). While it is lent the
link's receive reads nothing and leaves the buffer alone, whoever steps the session; the step after
the read lands the lease first (`SessionDatagramLink::land_rx`), and a lease of a link that has
gone is let go of. A link let go of with its buffer lent shuts its stream, which ends a read
waiting in it at once, and waits the read out before the buffer goes.

The ping side. The pinging thread's put takes the session, writes one `sendmsg` (one `WSASend`)
and returns; the reply reaches it through the program's own wait, which zenoh-pico's ping makes
the same way: one system call of the engine's a round trip on that thread, as pico's. The extra
one it could make was under a race with its own read task, which takes the session to work out
its next wait just as the reply's callback lets the pinging thread go: a droppable put that found
the session held so asked each face for room (`poll` for `POLLOUT`) on every turn under zenoh's
queue profile, and slept on the session's lock under pico's. That take now marks itself as holding
no send (`Holder::Waiting`), and the put tries the session again at once under either profile,
asking nothing. The ping process's read task is the pong side's: one `recv` a reply on POSIX when
its session dials.

What is left, and why it stays for now:

* Windows: the wait before the read. The socket does not block, so that a write is tried first
  without waiting (section 3, row 7), which Winsock has no per-call flag for; its blocking mode is
  the socket's, so a read that waited in `recv` would make that write wait too. Reading first and
  waiting in `WSAPoll` only when the read would block costs a round trip three calls in place of
  two: the read task is back before the next ping arrives, so its first read would block nearly
  every time. The owner is given no read of a Windows stream (`StreamSocket::reader`), and waits
  in `WSAPoll` before the step's `recv`.
* A session that listens waits on its port beside its links, with one `poll` over both, and its
  step asks the port for a connection (`accept`, answering `EAGAIN`) every step: two calls beside
  the `recv` and the send where zenoh-pico's peer gives the port a task of its own. A peer whose
  ping listens pays them on the ping side. Taking the connection only when the wait says the port
  is ready needs a wait that names what was ready, which no stack's gives yet.
* Several links and a group are waited on together, with one `poll` before the step's reads.
* The second take of the session for the read's wait (item 9 of `docs/rx-sample-cost.md`), which
  now also lends the buffer, and the look at the handed legs each read, which a test holds as its
  CONTROL (`tests::a_publish_with_nothing_handed_takes_the_session_once_and_not_the_handed_queue`):
  it is what sends a leg a put handed across a stale reading of the word that says one waits.
* The callback's mutex: with `local-subscriber` a session's own put hands its subscribers the
  sample on the putting thread, beside the read task's delivery.

The tests that count what changed: `stream_link::tests::a_lent_batch_lies_where_it_was_lent_until_the_next_receive`,
`tests::listen::the_puts_of_one_stream_batch_are_handed_where_they_lie_in_a_few_reads`,
`slot_observer::tests::a_drain_with_nothing_staged_opens_no_burst` and
`windows::stream::tests::a_read_asks_the_stream_with_no_poll_before_it`; for the read made in the
wait, `stream_link::tests::a_batch_the_owner_read_is_handed_over_with_no_read_of_the_links_own`
(one read a batch, the owner's, and none of the link's own),
`stream::tests::the_owners_read_waits_in_the_recv_and_sets_its_timeout_once` (one `recv` a read
and the receive timeout set once), `tests::listen::a_lone_stream_link_is_waited_on_in_its_read_and_a_listener_polls`
(no wait on the readiness of a lone stream link, a listener's CONTROL) and, for the ping side,
`tests::congestion::a_session_held_by_a_read_working_out_its_wait_is_tried_again_without_asking`
and `tests::a_droppable_publish_behind_a_read_working_out_its_wait_spins_and_is_sent`. The probes
are the measurement.

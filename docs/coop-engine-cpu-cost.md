# Where the cooperative engine spends CPU per message

The pico C ABI on the cooperative engine (`wz-capi-coop`, the engine the C ABI presets ship on),
walked step by step against zenoh-pico 1.10.2 (`vendor/zenoh-pico`) on the two paths the
performance matrix loses most on: the round trip's answering side (a sample read, handed to the
subscriber's callback, which puts the answer) and the multicast 8 B throughput path. Each cost
below names the code that pays it, what pico does in its place, an estimate of what it costs, and
the fix. Section 5 is what this branch changed.

## 1. What the measured table is, and what it is not

The readings of 2026-11-22 (perf gate W over P: 74 of 96 cells not WIN; the system call counts of
`scripts/pico-compare.sh profile` and `tids`) are of the TOKIO engine, not of this one:

* `wz-capi-pico`'s default features name `engine-tokio`, `serial-drive-own-thread` and
  `rx-busy-poll` (`crates/wz-capi-pico/Cargo.toml`, `[features] default`), and a build runs its
  sessions on the tokio engine whenever that engine is in it;
* `pico-compare.sh` `profile`, `tids`, `rtt` and `thr` build `cargo build --release -p
  wz-capi-pico` (those defaults), and `scripts/host-bench/perf_matrix.py` builds the reference
  and arm W from `wz_config.pico_build_features("tokio", ...)`.

So the second thread that sends and waits in `epoll_wait`, the `write`s (an eventfd wake per
handoff) and the `sched_yield`s belong to `wz-capi-core` and `wz-runtime-tokio`:

| Measured | Where it comes from |
|---|---|
| `sched_yield` on the drive thread | the receive busy-poll, which yields after eight empty reads, for up to 50 us a read (`crates/wz-runtime-tokio/src/link_pipeline.rs` `busy_read`, the `std::thread::yield_now()` after `tries > 8`; budget `RX_BUSY_POLL_BUILD_US` in `crates/wz-capi-core/src/drive.rs`) |
| `sched_yield` on a putting thread | the writer role's spin, which yields after 64 tries (`crates/wz-runtime-tokio/src/writer_queue.rs` `acquire_role`), and the writer's yield before its batching wait (`writer_queue.rs` `Backoff::wait`) |
| `write` + `sendto` on the drive thread | a frame the producer landed and did not write itself wakes the writer task (`writer_queue.rs` `frame_landed`, `notify_one`), which runs on the drive thread of `serial-drive-own-thread` |

None of these exists in the cooperative engine: it has no drive thread, no eventfd, no yield and
no writer task on a link. The cooperative engine has not been measured by the matrix; section 6
says how. The estimates below are therefore costs per message counted from the code, not shares
of a measured ratio.

## 2. The round trip's answering side

| Step | zenoh-pico 1.10.2 | cooperative engine |
|---|---|---|
| wait for input | the read task's `_zp_unicast_read` (`src/transport/unicast/read.c:117`) blocks in its socket read | `SessionDrive::read` (`crates/wz-capi-coop/src/engine.rs:5444`) takes the session's lock to work out its wait (`idle_wait`, `engine.rs:2358`), lets go, and waits in `poll` |
| read and decode | same thread, `_z_unicast_handle_transport_message` (`src/transport/unicast/rx.c:276`) | the step takes the lock again (`engine.rs:3696`): `run_until_idle` runs the link's task, which reads, decodes in place and dispatches into the registry; the sample is copied into the delivery lane |
| hand to the callback | `_z_trigger_subscriptions_impl` (`src/session/subscription.c:266`): the session mutex, the subscriptions by key from its cache, the callback | after the lock is let go, `deliver` (`engine.rs:3114`) takes the lane's head, finds the callback by a scan of the callback table under its lock (`subscriber_callback`, `engine.rs:3522`), and calls it under the callback's own mutex |
| the answer's put | `z_publisher_put` -> `_z_write` (`src/net/primitives.c:170`) -> `_z_send_n_msg` (`src/transport/common/tx.c:486`) -> `_z_transport_tx_send_n_msg` (`tx.c:286`): the transmit mutex, encode once, `_z_link_send_wbuf` (`src/link/link.c:205`) on the calling thread | `publish_to_link` (`engine.rs:3287`) takes the session's lock with a try (`live_to_publish`, `engine.rs:3007`), `fan_out` (`engine.rs:3348`) sends the plain put on the calling thread (`send_plain_put_qos`, `crates/wz-session-core/src/session_actions.rs:13580`) |

The answer is sent by the thread that runs the callback, the read task, with no wake of anything:
whoever holds the session sends, which is the textbook shape (flat combining) the tokio engine's
drive thread lacks. What the cooperative engine pays on top of pico is fixed work per read step and
per put, below.

## 3. The multicast path

Publisher: `fan_out` hands a put on a group to `GroupFace::publish`
(`crates/wz-capi-coop/src/engine/group.rs:853`), which builds an OWNED Push (the key and the
payload copied, `push_build::build_push_literal_with_meta`,
`crates/wz-session-core/src/push_build.rs:732`), boxes it, and pushes it onto the group's stage
(`crates/wz-session-mcu/src/group_drive/stage.rs:153`), where it is framed with its sequence
number into a datagram vector of its own. Until row 1's change below, nothing was written there:
the stage was written by the group's pump, a task of the session that runs only in a step, and a
read task already waiting on the group socket was not woken by the push, so the datagram waited for
that wait to end: the next datagram in, or the read step's bound (`Z_CONFIG_SOCKET_TIMEOUT`,
`crates/wz-capi-pico/src/session.rs:222`). A publisher that put faster than that filled the lane,
and then ran the whole of the session's tasks on its own thread to drain it (`GroupTxPace::pass`,
`SessionPace::pass` in `engine/group.rs`).

zenoh-pico writes a multicast message on the caller's thread, through the same
`_z_transport_tx_send_n_msg` (`src/transport/common/tx.c:286`, written at `tx.c:88`), and its read
task finds the sending peer by address in a list (`_z_find_peer_entry`,
`src/transport/multicast/rx.c:161`).

## 4. The costs, by expected gain

Estimates are per message on a 3-5 GHz x86 host, uncontended: a lock round trip about 20 ns, an
allocation and its free about 40-60 ns, a clock read about 20 ns. Not measured.

| # | Cost | Evidence | pico | Estimate | Fix |
|---|---|---|---|---|---|
| 1 | A put on a group is not written by the putting thread; a waiting read task is not woken for it, so it leaves at the end of that wait or when the lane fills | `engine/group.rs:853`, `group_drive/stage.rs:153`, `tests/group.rs:1542` | written on the caller, `tx.c:286`, `tx.c:88` | round trip over a group: up to the read step's bound per leg; throughput: a whole executor pass per full lane on the publisher | the holder of the session writes the stage: the pump's write of what the stage holds as a call the publish makes after its push, on the thread that holds the session, with the JOIN's written sequence numbers kept where they are (the pump owns the socket inside its task today, so the transport moves out of the task in `wz-session-mcu`'s group drive) |
| 2 | The multicast put is an owned Push, boxed, framed into a datagram vector of its own: three or four allocations a message | `engine/group.rs:853` onward, `push_build.rs:732`, `group_drive.rs` `TX_SCRATCH_BYTES = 0` on the heap profile | encodes into the transport's one buffer | 150-250 ns | the lent plain-put form the unicast links already use, encoded from the caller's bytes into the stage's lane |
| 3 | The plain put is encoded twice, once into a counting sink for its size and once into the batch | `session_actions.rs:13620` and `13626` | encoded once into the buffer, overflow checked (`tx.c:175`) | 30-80 ns at 8 B | encode into the lent slot and read the length written, or compute the length from the parts |
| 4 | Fixed work of a read step: the session's lock four times, a vector allocated and an `Arc` cloned per waited link to build the wait, a clock read per face, about six lock round trips in `deliver` with nothing to hand | `engine.rs:5444`, `engine.rs:2408`, `engine.rs:1766`, `engine.rs:3114` to `3250` | one socket read and one session mutex | 250-450 ns a step, a message a step on a round trip | the wait built into a bounded inline array; a flag per queue so `deliver` passes over the empty ones; the clock read once a step; the tickers in one take (done, section 5) |
| 5 | A delivered sample finds its callback by a scan of the callback table under its lock and clones its `Arc`; the lane's lock is taken to take the head and again to give it back | `engine.rs:3522`, `engine.rs:3142` onward | the session mutex and the subscription cache, `subscription.c:266` | 60-120 ns a sample | resolve the callback under the step's lock and carry it with the lane item |
| 6 | Each publish took the queue of handed legs' lock twice, almost always to find it empty | `engine.rs:3287` (`send_handed` before and after `fan_out`) | none | 40 ns a put | a flag beside the queue (done, section 5) |
| 7 | A droppable put that finds the session held by a read step spins on `try_lock` for the length of the step | `live_to_publish`, `Room::Free => spin_loop` | the read task does not hold the transmit mutex | the length of a step, on the publisher, when the two overlap | a bounded spin, then the blocking take of the session that a non-sending holder lets go of |

What is NOT a cost here: a thread handoff per message (none, section 2), a key expression resolved
by string per message on receive (the registry's match memo, `fire_into_memoized` in
`crates/wz-session-core/src/pubsub.rs`), and `sched_yield` (none in the engine's paths).

## 5. What this branch changed

* The queue of handed legs carries a flag beside it, written under its lock: a publish that finds
  it clear takes no lock for the queue; a read step still looks under the lock, so a leg a publish
  passed over on a stale reading leaves on the next step (row 6). Test:
  `tests::a_publish_with_nothing_handed_takes_the_session_once_and_not_the_handed_queue`.
* A read step reads the clock and takes the first due job under one take of the session's lock, and
  puts a job that ran back and takes the next under one more (part of row 4). Test:
  `tests::ticker::a_read_with_no_job_due_takes_the_session_once_for_its_jobs`.
* Both tests count the takes through a test seam (`CoopEngine::takes`, `#[cfg(test)]`).
* A put on a group is written by the thread that puts it, before the put returns (row 1). The group's
  transport is shared by its task and its face (`GroupLink`, `crates/wz-session-mcu/src/group_drive/stage.rs`);
  the stage keeps what was written (the datagram a full socket refused, the conduits as written,
  which the JOIN advertises), so the face and the task write through one writer, and the task
  writes only what is left to it. A batch window on the group (`zp_batch_start`) holds the puts
  in one frame per conduit until the flush, an express put, or the stop, which write it on the
  calling thread. Tests: `tests::group::woken::a_put_on_the_group_is_written_by_the_putting_thread_before_it_returns`,
  `tests::group::woken::inside_a_batch_window_a_put_on_the_group_is_written_at_the_flush`.

Rows 2 and 3 cross into `wz-session-core` and are left for their own items. Row 2 needs a
borrowed form of a put with its metadata and aliased key for the group's push, and lanes that hold
datagrams in slots the session lends rather than in vectors of their own.

## 6. Measuring this engine

The harness takes the engine from the configuration the package ships
(`configs/profiles/host-peer-ext.conf`, `CONFIG_WZ_ENGINE_COOP=y`) once the harness change lands;
until then a cooperative library is built by hand with the list `wz_config.py --features pico
--engine coop` prints and run with `PICO_CMP_NO_BUILD=1`.

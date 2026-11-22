# Batched small puts on a group: why they were slow

The pico C ABI performance matrix on a Windows 11 x64 host (`scripts/host-bench/windows/perf_matrix.ps1`,
thr workload, peer mode, both members joined to `udp/224.0.0.224:<port>#iface=<adapter GUID>`)
measured arm W (wz's pico-compatible library on the cooperative engine) 14 to 44 times below arm P
(zenoh-pico) in messages a second with batching on at 8 and 64 bytes, the worst gap of the matrix,
while the same cells with batching off, and the 1024-byte cells, were much closer. The package
measured was built from 3ba877491a.

This note gives the cause, every other hypothesis that was read and why it was set aside, what was
changed, and what a run has to show. Nothing here was built or run: it is a reading of the code at
3ba877491a and at the integration this branch starts from (0f55fcc882), and section 5 says what a run
has to show.

## 1. What batching on means in the probe

`perf_probe pub -b` (`scripts/host-bench/perf_probe.c`, `run_pub`) opens a batch window with
`zp_batch_start` and puts back to back; every millisecond it closes the window with `zp_batch_stop`,
which writes what the window holds, and opens it again. Inside a window zenoh-pico appends each put to
the transport's one buffer and writes the buffer when the next put does not fit, when an express put
joins it, or when the window is flushed or stopped
(`vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_send_n_msg_inner(`,
and the overflow, `vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_batch_overflow(`).
The multicast batch is 2048 bytes (`vendor/zenoh-pico/cmake/feature_config.cmake` @
`set(BATCH_MULTICAST_SIZE 2048 CACHE STRING "Use this to override the maximum multicast batch size")`,
and wz's `PICO_MULTICAST_BATCH_BYTES` of the same value).

A put on `perf/thr` named by its literal key is, on the wire, the Push header, the key (its scope id,
its length and its eight bytes), the Put header, the payload's length and the payload: about 21 bytes
at 8 bytes of payload, 77 at 64 and 1038 at 1024 (computed from the layout, not measured; a byte or
two either way does not change what follows). Behind a frame head of two to five bytes, a 2048-byte
batch holds about 97 puts of 8 bytes, 26 of 64 bytes, and one of 1024 bytes, since two of those do
not fit.

## 2. The cause

In the measured library `zp_batch_start` opened no window on a group. The cooperative engine's
`batch_start_all` (`crates/wz-capi-coop/src/engine.rs` at 3ba877491a) opened a window on each of the
session's unicast links (`core.0.ups()`) and on nothing else: the group's face had no window to open
(`GroupFace` in `crates/wz-capi-coop/src/engine/group.rs` had no `batch_start`, and
`GroupTxStage` in `crates/wz-session-mcu/src/group_drive/stage.rs` had none either; the session core's
window, `multicast_tx_push_batched`, was in the tree, used by the tokio engine's group alone). And
`zp_batch_start` answers `Z_OK` whatever the count (`crates/wz-capi-pico/src/session.rs`), so the
probe was not told. Every put on the group left as a datagram of its own, with batching on as with it
off.

That is the shape of the measurement:

* batching on, 8 and 64 bytes: zenoh-pico writes one datagram for about 97 and 26 puts, wz one for
  each. A datagram costs a send call on the publisher and a read step on the subscriber in both
  libraries, so the gap is bounded by the packing, about 97 and 26, and is narrowed by what each
  library spends per message besides; 14 to 44 lies inside that;
* batching off: both write one datagram a put, so the gap is the per-message cost alone;
* 1024 bytes: one put fills a batch, so zenoh-pico's batching packs nothing and the two are close
  again, batching on or off.

The cause is removed in the integration: `feat(capi-coop): Write a group put on the thread that puts
it` (3c80bbe54, not in the measured package) gave the group's stage a window of its own
(`GroupTxStage::batch_start`, `batch_flush`, `batch_stop`), opened by `batch_start_all` on every
group, and has the putting thread write a frame the moment it is put on its lane
(`GroupFace::push`, `GroupLink::write_staged`). A put that fits the open frame is appended to it and
touches no socket; the put that does not fit puts the frame on its lane, opens the next one, and
writes the full frame before it returns, as zenoh-pico's overflow does.

What this branch adds for it is the count at the seam, which the earlier tests did not make (they
held two puts and flushed):

* `group_drive::stage::tests::a_batch_window_puts_a_frame_on_its_lane_each_time_it_fills`
  (`wz-session-mcu`): `2k + 3` puts of one size, where `k` is what a frame of the group's batch holds,
  worked out from a frame of one put and one of two. After put `i` the lanes have held `i / k`
  datagrams, each frame holds `k` puts and is as full as the batch lets it be, the stop puts the rest
  on its lane, and the total is `ceil(N / k)`, one sequence number a frame. Every push is answered
  with no pass of the host and no wait (`push_at_once`).
* `tests::group::woken::inside_a_batch_window_puts_on_the_group_leave_one_datagram_a_full_frame`
  (`wz-capi-coop`): the same count through the engine, on a member alone on an in-memory group with
  no read task: each full frame is on the group before the put that overflowed it returns, written
  by the putting thread, with one take of the session a put; the total after the stop is
  `ceil(N / k)`; and, the CONTROL, with the window closed each put is a datagram of its own.

## 3. The hypotheses read and set aside

| Hypothesis | What the code says | Verdict |
| --- | --- | --- |
| A batch flushed per put (no aggregation) | True of the measured package, for the reason of section 2: no window on a group | The cause; removed by 3c80bbe54 |
| The opposite: a batch held until a timer, pacing the sender | Neither tree waits on a clock while a frame has room: the window holds until the frame fills, an express put, a flush or the stop (the probe stops every millisecond), and a push with room is answered at once (`StageQueue::wait_for_room` asks the lane, `MulticastTxLanes::room_at_once`) | Not a cause. A related difference from zenoh-pico was found and fixed, below |
| A send call per message | In the measured package one `sendto` a put, as a consequence of the cause. In the integration one send a full frame; a put that only appends calls `write_staged`, which offers the socket only what the stage holds, so nothing while the socket takes everything. While the socket refuses a datagram (it is held, `GroupTxStage::holds`), each put offers it again: one refused send a put, for as long as the socket stays full | Not a cause of the gap. The retry under a full socket is a CPU cost only where the socket is already the bound; left open |
| A lock or a wake per put | One take of the session a put (`live_to_publish`), counted by the engine test; the put writes its own frame, so no read task is woken for it. zenoh-pico takes its transmit mutex once a put in its default build (`vendor/zenoh-pico/cmake/feature_config.cmake` @ `set(Z_FEATURE_BATCH_TX_MUTEX 0 CACHE STRING "Toggle tx mutex lock at a batch level")`) | Not a cause |
| The pacer (`GroupTxPace`) limiting a burst | It runs only when a lane is full. A lane holds `PICO_TX_QUEUE_SIZE` batches counted in bytes; in the measured package each 21-byte datagram took 21 bytes of it, so a pass came once in some hundreds of puts; in the integration the lane holds at most the frame just put on it, which the put then writes | Not a cause |
| Windows `sendto` per datagram | One `sendto` a datagram, the same call shape as zenoh-pico's (`WindowsUdpSocket::send_to`, `crates/wz-runtime-posix/src/windows/net.rs`). Its cost is how the cause shows: wz paid it per put, zenoh-pico per batch | The mechanism of the cause, not a cause of its own |
| The receiver drops: the sequence-number gate | The gate is zenoh-pico's half-window (`precedes`, `crates/wz-session-core/src/sn.rs`): a later number after a gap is taken, so a datagram the host's socket dropped costs that datagram alone | Not a cause |
| The receiver drops: a full delivery lane | A group's datagram is walked record by record where the host's buffer holds it (`HostGroupTransport::keeps_input` is true), and the lane's gate (`SampleLane::takes_a_read`) stops the walk when one more record has no room, at 64 events (`DELIVERY_LANE_EVENTS`), and the next step goes on from there after the delivery: a batch of 97 samples is two steps and loses none. A build whose group walk reads the datagram whole (one with `transport-stats`, `multicast-declarations`, `routing-namespace` or `multicast-ingress-gate` in the session core, or without `rx-lent-control`, `dispatch_multicast_inbound_kept` in `crates/wz-session-core/src/multicast_rx.rs`) would drop what passes the lane's room and count it (`LaneCounts`); the pico package on the cooperative engine is built with none of them, by `crates/wz-capi-coop/Cargo.toml` | Not a cause in the pico package; with batching off, and in the measured package, one sample a datagram cannot fill the lane anyway |
| The group joined on another interface | `#iface={GUID}` is dropped with a warning on Windows (`docs/windows-multicast-rtt.md`, section 5), the same for both members of arm W, and the cells with batching off carry the group | Not a cause of this gap |

## 4. A difference from zenoh-pico fixed on the way

zenoh-pico writes its open batch before any transport message it sends, its JOIN and its Close among
them (`vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_send_t_msg_inner(`;
the multicast transport sends both through it, `vendor/zenoh-pico/src/transport/multicast/transport.c` @
`ztm->_send_f = _z_transport_tx_send_t_msg_wrapper;`), so a window a program leaves open leaves at the
next beacon at the latest, and is not lost at the close. The tokio engine's group does the same
(`MulticastTxPlane::enqueue_control`, `crates/wz-runtime-tokio/src/multicast_pipeline.rs`). The
cooperative engine's group did not: its pump sends the JOIN and the Close straight to the socket, so
a window left open held its frame until a flush, the stop or the next overflow, and lost it at the
close. Not a cause of the gap (the probe stops its window every millisecond), but a window that holds
past the beacon is a batch held on no rule of the protocol's.

`fix(session-mcu): Flush a group's batch window at its JOIN and Close`: the pump's step puts the
window's open frames on their lanes at each JOIN, and they are written right after the beacon, which
advertises what was written, so a member reads their numbers as the next to come; at the stop the
window is flushed and the stage written before the Close. Tests (`wz-session-mcu`,
`group_drive::stage::tests`): `a_window_left_open_leaves_at_the_next_beacon_and_stays_open`
(the frame leaves behind the JOIN, which advertises it as the next; the window stays open for the
next put, which the next beacon takes the same way) and
`a_window_open_at_the_stop_is_written_ahead_of_the_close` (CONTROL: with no beacon due the window
holds; at the stop its frame leaves, then the Close).

## 5. Confirming it

On the Windows host, with the run, the plan and the host of `docs/pico-perf-matrix.md` section 6:

1. The cause, on the measured package, from the table already taken: arm W's multicast thr cells with
   batching on read about what its cells with batching off read, at each size, while arm P's on cells
   read many times its off cells at 8 and 64 bytes. A capture of the group's datagrams during an arm W
   pub run with `-b` counts about one datagram a put; the same capture of arm P counts one a batch.
2. The fix: the package of a commit that holds 3c80bbe54 and this branch, its plan made by
   `perf_matrix.py windows-plan` in a checkout of that commit, and the multicast thr row:
   `-Transports multicast -Workloads thr -Batching on,off -Sizes 8,64,1024`. Expected: arm W's cells
   with batching on well above its cells with batching off at 8 and 64 bytes, as arm P's are, and the
   gap to arm P no longer of the order of the packing; the pub line's `batch_cycles` beside it. A
   capture counts about one datagram for 97 puts of 8 bytes.

On Linux, the matrix's own runner gives the same comparison without the Windows host, the group
joined on the loopback (`scripts/host-bench/perf_matrix.py run ... --transports multicast --workloads
thr --batching off,on --sizes 8,64,1024`), with arm W built on the cooperative engine (section 6 of
`docs/coop-engine-cpu-cost.md`); and the tests of sections 2 and 4 hold the counts:
`cargo test -p wz-session-mcu --features transport-multicast,codec-push --lib group_drive::stage::tests`
and `cargo test -p wz-capi-coop --features group,app-transport --lib tests::group::woken`.

What is left of the gap once the cause is gone is the per-message cost, which batching makes the
bound: on the publisher the owned Push each put on a group still builds and boxes
(`docs/coop-engine-cpu-cost.md`, row 2), on the subscriber the delivery's fixed work a step. Neither is
measured here.

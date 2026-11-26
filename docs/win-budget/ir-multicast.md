# Winning budget: the multicast data path

Status: design, 2026-11-26. Scope: what one PUT costs the sender and the receiver over a multicast
group, from the program's `z_publisher_put` to the group's `sendto` and from the group's
`recvfrom` to the return of the subscriber's callback, in the shipped nostd form of the pico ABI
(the `zenoh-pico_defconfig` preset, the coop engine). The unicast stages are designed in
[ir-receive.md](ir-receive.md) and [ir-send-query.md](ir-send-query.md); none of them names the
group's stage (`GroupTxStage`), the group's session step (`MulticastPump::step`) or the group's
read, which is what this document designs. Every number marked *to measure* is a cell the main
session fills.

## 1. What is measured

The performance matrix (`scripts/pico-compare.sh perf`, main, an idle host, 2026-11-26) reads the
multicast cells as the worst of the pico ABI's, each a cost ratio W over P with its interval:

| cell | batching off | batching on | verdict |
|---|---|---|---|
| `thr/8/msgs_per_s` | 1.625 [1.565, 1.651] | 2.207 [1.829, 2.433] | LOSS |
| `thr/64/msgs_per_s` | 1.577 [1.408, 1.619] | 1.658 [1.642, 1.684] | LOSS |
| `thr/1024/msgs_per_s` | 1.523 [1.516, 1.802] | 1.647 [1.568, 1.740] | LOSS |
| `thr/8/cpu_ns_per_msg` | 1.491 [1.426, 1.512] | 1.855 [1.661, 1.970] | LOSS |
| `thr/64/cpu_ns_per_msg` | 1.419 [1.294, 1.477] | 1.659 [1.655, 1.681] | LOSS |
| `thr/1024/cpu_ns_per_msg` | 1.308 [1.278, 1.626] | 1.419 [1.365, 1.493] | LOSS |
| `rtt/8/rtt_p50_us` | 0.709 [0.672, 2.333] | locked | TIE |
| `rtt/64/rtt_p50_us` | 0.719 [0.658, 2.303] | 2.285 [0.676, 2.398] | TIE |
| `rtt/64/pong_cpu_ns_per_rtt` | 1.645 [1.395, 1.790] | 1.272 [1.059, 1.800] | LOSS |

No tcp throughput cell of the same run is a CPU debt (`tcp/off/thr/8/cpu_ns_per_msg` is a TIE at
0.971), so the excess is the group's own path and not the session's shared stages. The rtt p50 intervals span 0.7 to 2.3: a
round trip on the group is decided by when each side's read wakes, which section 3.1 attributes.

No instruction count of the group's path exists yet. The matrix's figures are wall time and CPU of
whole processes; what follows counts the work in the code, and the counts it names are the ones
the main session reads off callgrind with the arm below.

### 1.1 The harness arm

`PICO_CMP_TRANSPORT=multicast` (this lane's first commit) puts `subprofile` and `opprofile` on a
group: both sides listen on `udp/224.0.0.224:<port>#iface=lo`, as the matrix's multicast cells
do (`scripts/host-bench/perf_matrix.py` `endpoint_args`), and `paced_pub` takes `-l` for
it. The window, the idle run and the two counts are the unicast arm's unchanged, so a figure of
the group arm is read as the unicast one is:

* receive, per message: `PICO_CMP_TRANSPORT=multicast bash scripts/pico-compare.sh subprofile 8`
  (the subscriber's window, callgrind's "net" line, and the strace and perf stat legs, which
  give the system calls each received message costs on each side);
* send, per message: `PICO_CMP_TRANSPORT=multicast bash scripts/pico-compare.sh opprofile put,none 8`
  (the publisher's whole process; "net" is put less the paced loop).

| cell | wz (W) | zenoh-pico (P) | source |
|---|---:|---:|---|
| M1 receive, Ir per message | 4,808.0 | 3,531.9 | subprofile, callgrind (fourth reading, section 1.2) |
| M2 send, Ir per put | 3,814.5 | 2,554.8 | opprofile put (fourth reading; net of the paced loop 3,650.3 against 2,390.2) |
| M3 receive, system calls per message by kind | strace: `recvfrom` 1.00, no `poll`; callgrind: 2.06 `recvfrom` calls a message (the datagram, then one that finds none) | `recvfrom` 1.00 | subprofile, strace and callgrind (fourth reading) |
| M4 send, functions per put | section 7.7 | section 7.7 | opprofile put |
| M5 receive, functions per message | section 7.6 | section 7.6 | subprofile, callgrind |

A group of the pico preset carries no declarations and sends every put, so the publisher of the
arm needs no match before its span (`perf_matrix.py` says the same of its cells); a member is
admitted by its first JOIN, which the three seconds before the span cover.

### 1.2 The first reading

The main session's first run of the arm (2026-11-26, the lane's tip `688549240`, the shipped
form) reads M1 at 2.33 of zenoh-pico's and M2 at 2.49. The receiver's top functions by `perf
record` share (each at most 2.1 %) are the executor and the round, not the group's own stages:
`poll_erased` of the group's session task, `CoopEngine` and `Core` bodies, `run_among`, the
group's `on_event` chain (`answering_asks` around `noting_members` around `dispatch`),
`MulticastPump`, `dispatch_iteration_event`, `RoundDelivery`, `read_chain`, `SlotObserverOf` and
`MulticastDispatcher::active_peers`. A group's read is still a task of the executor whose records
reach the subscriber through the round: section 8's direct read of the C ABI covers the unicast
faces of the shipped preset, and a group's datagram pays an executor turn, the event chain and,
in the step's fixed part (R2), a walk of the member table, which `next_due_us` read on every step
to know whether a sweep is due (C7).

Rows taken on this lane since that reading, each to be read again on the arm: R4 (the member count
kept) and T3 (write through). The second reading (the lane's tip `9dffd9436`, the same arm) reads
M1 at 7,980.8 against 3,532.1 and M2 at 5,764.7 against 2,555.0, both 2.26 of zenoh-pico's (M2 net
of the paced loop 5,599.7 against 2,390.0, 2.34): the two readings differ by 247.1 a received
message and 608.3 a put, which R4 and T3 are the changes between, and section 7 reads where the rest lies.
The third reading (the lane's tip `0247f2e81`, the same arm) reads M1 at 5,548.2 against 3,531.0
(1.57) and M2 at 5,830.3 against 2,554.8 (2.28): D3 to D6 and D8 took 2,432.6 a received message,
and the put did not move. Sections 7.6 and 7.7 read the two by function.
The fourth reading (the lane's tip `88710f3c2`, the same arm) reads M1 at 4,808.0 against 3,531.9
(1.36) and M2 at 3,814.5 against 2,554.8 (1.49): D7a, D7b, P1 and D9 took 740.2 a received message
and 2,015.8 a put. Section 7.9 reads the two by function.

The rows that reach the receive path's executor turn and system calls (R1, R2, R3) and T4 rest
on the round-5a lane's rewrite of `engine/group.rs`, `group_drive.rs` and the engine's read,
which this lane has merged, with the lock order round-5a settled (a read slot, then a face's
send place in the order of the faces' table, then the session, then a row's latch;
[c-abi-architecture.md](../c-abi-architecture.md) section 8.4).

## 2. The send path

### 2.1 zenoh-pico

One call on the caller's thread, under the transport's tx mutex:

1. lock: `vendor/zenoh-pico/src/transport/common/tx.c` @ `ret = _z_transport_tx_mutex_lock(ztc, cong_ctrl == Z_CONGESTION_CONTROL_BLOCK);`
2. a frame header with the next SN, into the one tx buffer:
   `vendor/zenoh-pico/src/transport/common/tx.c` @ `sn = _z_transport_tx_get_sn(ztc, reliability);`
3. the network message encoded behind it:
   `vendor/zenoh-pico/src/transport/common/tx.c` @ `z_result_t ret = _z_network_message_encode(&ztc->_wbuf, n_msg);`
4. flushed unless a batch is open:
   `vendor/zenoh-pico/src/transport/common/tx.c` @ `return _z_transport_tx_flush_or_incr_batch(ztc, peers);`
5. one `sendto` from the buffer, to an address resolved at open:
   `vendor/zenoh-pico/src/link/transport/udp/udp_multicast_posix.c` @ `return (size_t)sendto(sock._fd, ptr, len, 0, rep._iptcp->ai_addr, rep._iptcp->ai_addrlen);`

There is no queue between the encode and the socket: the buffer is written and sent in the same
call, and a batch is the same buffer left unsent.

### 2.2 wz

`GroupFace::publish` (`crates/wz-capi-coop/src/engine/group.rs`) writes the Push from its parts
(`multicast_tx_publication`, `crates/wz-session-core/src/multicast_tx.rs`) and lends it to
`GroupFace::push_lent`, which pushes it on the group's stage and writes the stage:

| # | stage | work per message, counted in the code | file |
|---|---|---|---|
| S1 | key and encoders | the group's key for the put, the encoder closure | `engine/group.rs`, `multicast_tx.rs` |
| S2 | push onto the stage | `try_borrow_mut` of the conduits; the conduit read off the message; an empty window's `flush`; `push_frame`: a `PushDeadline`, `wait_for_room` (a `borrow_mut` of the lanes, the lane's bound, `ring_room`, which tries one run on a copy of the ring's cursor); the SN minted; `enqueue_lent`: a `borrow_mut` of the lanes, the ring's room, the frame encoded into the ring, a 23-byte record written ahead of it, the cursor committed; then `push_deferred` (a borrow of the conduits and of the staged storage, nothing kept) and the stats tally | `wz-session-mcu/src/group_drive/stage.rs`, `multicast_tx.rs` |
| S3 | the stage's writer | `GroupLink::write_staged`: a `try_borrow_mut` of the transport; `offer_held` (a `borrow_mut`, nothing held); `write`: for the one datagram, `holds` (a borrow), `take_front`, whose `next_out` walks every lane (`Priority::NUM`), decodes the front record of each non-empty one and, for a Control front, walks them again, and whose caller decodes the chosen lane's front record once more; `offer`: a borrow of the lanes, the send, a `borrow_mut` of the writer, `on_wire.written`, `finish` (a `borrow_mut` of the lanes and the ring's pop); then `holds` and `take_front` again, which walks every lane to find none | `stage.rs` |
| S4 | the send | `Watched::try_send_to_group` through `Box<dyn GroupTransport>` to `HostGroupTransport::try_send_to_group`: the destination converted to the kernel's form, one `sendto` | `engine/group.rs`, `wz-runtime-posix/src/multicast.rs`, `wz-runtime-posix/src/net.rs` |

What wz does that pico does not: S2 and S3 put the frame on a lane and take it off again even
when nothing is queued ahead of it and nothing is held, which is every put of the throughput cell
whose socket keeps up. The lane is what lets a full socket hold a datagram and lets the group's
priorities be served in order (the tokio engine's group pipeline, which the stage mirrors), and
neither is used by a put that finds the lanes empty. S3 decodes a 23-byte record two or three
times per datagram written and walks the lanes once more than it writes datagrams.

## 3. The receive path

### 3.1 zenoh-pico

The read task of a multi-threaded build, one datagram per turn:

1. one blocking `recvfrom` (the socket has a receive timeout):
   `vendor/zenoh-pico/src/link/transport/udp/udp_multicast_posix.c` @ `rb = recvfrom(sock._fd, ptr, len, 0, (struct sockaddr *)&raddr, &replen);`
2. the transport messages of the datagram decoded one after the other:
   `vendor/zenoh-pico/src/transport/multicast/read.c` @ `ret = _z_transport_message_decode(&t_msg, &zbuf);`
3. each handled under the peer mutex, the member found by its address in a list:
   `vendor/zenoh-pico/src/transport/multicast/rx.c` @ `_z_transport_peer_multicast_t *entry = _z_find_peer_entry(ztm->_peers, addr);`
4. the SN of a frame against the member's channel:
   `vendor/zenoh-pico/src/transport/multicast/rx.c` @ `if (_z_sn_precedes(entry->_sn_res, entry->_sn_rx_sns._val._plain._best_effort, msg->_sn)) {`
5. each network message of the frame decoded and handled:
   `vendor/zenoh-pico/src/transport/multicast/rx.c` @ `_Z_RETURN_IF_ERR(_z_handle_network_message(&ztm->_common, &curr_nmsg, &entry->common));`
6. the read buffer renewed only when a message kept it:
   `vendor/zenoh-pico/src/transport/multicast/rx.c` @ `if (_z_zbuf_get_ref_count(&ztm->_common._zbuf) != 1) {`

An idle read sleeps until the next datagram in `recvfrom`; nothing else wakes the task:
`vendor/zenoh-pico/src/transport/multicast/read.c` @ `return _z_fut_fn_result_wake_up_after(Z_RUNTIME_IDLE_READ_TASK_SLEEP);`
is taken only when the receive timed out. System calls per received datagram: one.

### 3.2 wz

The engine steps the group's session (`MulticastPump::step`,
`crates/wz-session-mcu/src/group_drive.rs`), one datagram a step, and goes on stepping while the
group holds input, up to `GROUP_READS_PER_MOVE` steps (`CoopEngine::step`,
`crates/wz-capi-coop/src/engine.rs`):

| # | stage | work per datagram, counted in the code | file |
|---|---|---|---|
| R1 | wait | the engine's wait on its links and groups at once; once a burst is read, the step that finds none | `engine.rs`, `wz-runtime-coop` |
| R2 | the step's fixed part | the stop asked (a `dyn FnMut`), `carrier_up` (through `GroupLink`'s `RefCell` and `Watched`'s `dyn`), the clock read, `offer_held` of the backlog and of the stage, the JOIN's due time, the reply slots and the pull seam (a call to a closure that yields nothing), the stage's `write` (`holds`, `take_front`, whose `next_out` walks every lane), `service` (a `dyn` call that does nothing on a host), the input gate (an `Rc<dyn Fn>`), `keeps_input` (`dyn`) | `group_drive.rs`, `engine/group.rs` |
| R3 | the receive | `recv_with` through `GroupLink`, `Watched` (two `dyn` calls, the round's lending set and cleared around the datagram) and `HostGroupTransport::recv_with`: one `recvfrom` with `MSG_DONTWAIT`, the own-sender check; the read of a burst ends with one more `recvfrom` that answers `EAGAIN` | `engine/group.rs`, `wz-runtime-posix/src/multicast.rs`, `net.rs` |
| R4 | frame and SN | `dispatch_multicast_inbound_kept`, `walk_kept`, `dispatch_multicast_frame_in_place`: the member by its source (`find_by_src`), the SN gate | `wz-session-core/src/multicast_rx.rs`, `multicast_dispatch.rs` |
| R5 | records to the session | each record as an `IterationEvent` through `dyn EventSink` and `GatedEvents`, then the face's closures (`answering_asks`, `noting_members`, `dispatch`), `registry.with`, `dispatch_event` | `multicast_rx.rs`, `engine/group.rs`, `engine/registry.rs` |
| R6 | delivery | the session's delivery to the subscriber, shared with unicast | [ir-receive.md](ir-receive.md) stages 4 to 7 |

System calls per received datagram where the receiver keeps up (each burst one datagram long): a
wait, one `recvfrom` and the `recvfrom` that answers `EAGAIN`, three against pico's one (M3
reads it). The step's fixed part R2 is paid per datagram, not per wake, since one step reads one
datagram.

## 4. Causes, by the counts

| # | cause | side | cells it explains | how it is read |
|---|---|---|---|---|
| C1 | two system calls past pico's per received datagram (R1, R3) | receive | thr msgs/s and CPU, rtt p50 | M3 |
| C2 | the step's fixed part per datagram (R2) | receive | thr CPU | M5, the functions of `MulticastPump::step` |
| C3 | a frame put on a lane and taken off it when nothing is queued (S2, S3) | send | thr CPU, thr msgs/s off | M2, M4 |
| C4 | records decoded two or three times per datagram written, lanes walked once more than written (S3); the same walk in every receive step (R2) | both | thr CPU | M4, M5: `next_out`, `Record::read` |
| C5 | the event chain of R5: a `dyn` sink and three closures per record | receive | thr CPU at 8 and 64 B on | M5 |
| C6 | indirection of the transport (`Watched`'s `Box<dyn>`, `GroupLink`'s `RefCell`) per send and per receive | both | small; read with C2 | M4, M5 |
| C7 | the member table walked on every step to count its members (`next_due_us`, `active_peers` of a table that keeps no index) | receive | thr CPU | M5: `active_peers` |

## 5. Rows: the structural changes

| row | change | meets | files | lane |
|---|---|---|---|---|
| T1 | the writer takes the front datagram with its record read once: `next_out` reads each lane's front record once and answers the record with the lane | C4 | `group_drive/stage.rs` | mcast-perf |
| T2 | the lanes count what they hold, so a writer with nothing queued answers at once without walking them; `is_empty` reads the count | C4 | `group_drive/stage.rs` | mcast-perf |
| T3 | write through: a push whose lanes are empty, whose writer holds nothing and whose window is closed encodes its frame into the lane's storage and offers it to the socket in the same call, the record kept only when the socket refuses it | C3 | `group_drive/stage.rs`, `engine/group.rs` (`push_lent`) | mcast-perf, after round-5a lands `engine/group.rs` |
| T4 | the transport held concretely: the group's `Watched` holds the host's transport type instead of `Box<dyn GroupTransport>` where the build has one kind of group socket | C6 | `engine/group.rs`, `host_group.rs` | after round-5a |
| R1 | the read of a threads build blocks in the group's receive on its read task, as pico's does, so a received datagram costs one system call | C1 | `engine/group.rs`, `engine/direct.rs`, `group_drive.rs` | round-5a (`9578dc50d` reads a threads build's groups on its read task) |
| R2 | the step's fixed part once per burst: the step reads every datagram the socket holds, up to the deploy bound, and runs the stop, the carrier, the clock, the JOIN and the writer once around them | C2 | `group_drive.rs` | round-5a (`82c085fb1` reads a group's burst in one read) |
| R3 | a group's record handed to the registry by a direct call, not through `dyn EventSink` and three closures: the face's member notes and asks read off the event once, the registry's dispatch called with it | C5 | `multicast_rx.rs`, `engine/group.rs` | after round-5a |
| R4 | the dispatcher keeps its member count as a member is admitted and as one leaves, so a step and a Join read it with no walk | C7 | `wz-session-core/src/multicast_dispatch.rs` | mcast-perf |
| G1 | a datagram socket's gathered send (`sendmsg` of the frame head and the payload), the `DatagramSocket` twin of the stream's write gather, for a frame whose payload need not be copied into the lane | C3 at 1024 B | `wz-runtime-coop/src/udp_link.rs`, `wz-runtime-posix/src/net.rs` | gather-low, as a row of its own |

T3 keeps every property the lane gives: a datagram the socket refuses is held and offered first at
the next write, the JOIN advertises what was written (`on_wire`), and a group with QoS serves its
lanes in order, since a put that finds a lane non-empty goes on it as now.

## 6. Steps

Each step is one commit that builds alone; the test named is the one a revert of its change turns
red.

| step | rows | what | red test | expect |
|---|---|---|---|---|
| 0 | - | the harness arm (section 1.1) | - | M1 to M5 measurable |
| 1 | T1, T2 | the writer reads a front record once and stops on a count | `stage.rs` `next_out_answers_the_front_record_it_chose`, `an_empty_stage_has_nothing_out_without_a_lane_read` | M4: `Record::read` and `next_out` per put down by at least half |
| 2 | T3 | write through on an empty stage | `stage.rs` `a_push_onto_empty_lanes_leaves_from_where_it_was_written` | M2: the lane's queue and take off the put's functions |
| 2b | R4 | the member count kept | `multicast_dispatch.rs` `the_member_count_follows_every_admission_and_departure` | M5: `active_peers` off the top functions |
| 3 | R1, R2 | round-5a's group read | round-5a's | M3: one system call per received datagram with threads |
| 4 | R3 | records to the registry directly | *to write* | M5: the event chain off the top functions |
| 5 | T4 | the concrete transport | *to write* | M4, M5: the `dyn` calls gone |
| 6 | G1 | gathered datagram send | gather-low's | thr/1024 |

The cells are judged by the performance matrix again after steps 2 and 3: the target of this
document is every multicast `thr` cell at a cost ratio of 1.0 or under, and the `rtt` p50
interval inside [0.7, 1.3].

## 7. The receive read, function by function

### 7.1 Where a received message's instructions go

The second reading's subscriber window (section 1.2), callgrind's functions by their inclusive Ir
per received message. Each row of wz is a layer the next row runs inside; the differences between
two rows are derived from those figures, not read off a tool.

| layer (wz) | function | Ir per message | the layer alone |
|---|---|---:|---:|
| the read thread | `wz_host_sync::unix::entry` | 7,980.8 | 602.5 |
| the read task's body: its wait, its hand-out | `run_body` of `start_read_task` | 7,378.3 | 623.1 |
| the engine's step | `CoopEngine::step_after` | 6,755.2 | 1,007.8 |
| the executor's pass of the session's tasks | `Core::run_tasks_at`, `ExecutorState::run_among` | 5,747.4 | 976.9 |
| the group's task, one step of its pump | `poll_erased::<multicast_session_task_seeded>` | 4,770.5 | 1,174.6 |
| the receive through `GroupLink` and `Watched` | `recv_with` (`group_transport.rs`) | 3,595.9 | 62.5 |
| the host's receive: its system calls, the own-sender check | `HostGroupTransport::recv_with` | 3,533.4 | 557.4 |
| the round's lending around the datagram | `Watched::recv_with`'s closure | 2,976.0 | 24.0 |
| the walk: the member, the SN gate, the frame | `MulticastPump::step`'s receive closure | 2,952.0 | 950.0 |
| the records decoded and delivered | `walk_lent_payload` | 2,002.0 | 2,002.0 |

The functions that cost the most by themselves (exclusive Ir per message): `run_among` 500.4, the
group task's `poll_erased` 468.6 (the pump's step is inlined in it), the clock 373.3 (`now_us`
231.7 and `clock_gettime` 141.6), `answering_asks` 200.0, the host's `recv_with` 179.9,
`step_after` 168.8, `dispatch_event_among` 142.0, `recvfrom` 108.2, `read_push` 90.0,
`receive` 79.4, `classify` 77.4, `deliver_ref` 66.0, `hand_out` 62.9, `poll_on` 62.7.

| layer (zenoh-pico) | function | Ir per message | the layer alone |
|---|---|---:|---:|
| the background executor | `_z_executor_spin` | 3,510.1 | 246.0 |
| the read task: `recvfrom`, the transport message decoded | `_zp_multicast_read_task_fn` | 3,264.0 | 572.0 |
| the transport message handled | `_z_multicast_handle_transport_message` | 2,692.0 | 1,114.0 |
| the network message handled and delivered | `_z_handle_network_message` | 1,578.0 | 1,578.0 |

What decodes and delivers the records costs wz 2,002.0 against zenoh-pico's 2,380 (its network
message decoded, 802, and handled, 1,578): the excess of 4,448.7 is the layers above the walk.
Of it the read thread, the engine's step and the executor's pass are 3,210.3, the pump's step
outside the receive 1,174.6, and the receive 557.4 against pico's one `recvfrom`. The clock is
read on each of those layers: by the engine's step, by the pump's step, and twice by the due the
pump tells its holder after each step.

### 7.2 Why each layer runs per message

1. The group's session is a task of the executor (`multicast_session_task_seeded`), so the read
   reaches a datagram through an engine step, a pass of the session's tasks and a poll of the
   task's future, which returns after one step and wakes itself to be polled again.
2. A step of the pump reads one datagram, and every step runs its fixed part: the stop asked, the
   carrier, the clock, what the socket refused before, the beacon, the stage's writer, the service
   and the gate. After each step the task tells its holder when it is next due.
3. A build of threads hands out the records of a datagram after the step that read it, from the
   round, and the next datagram waits while a record lies in the one lent (`Round::has_room`):
   the group's input gate refuses it. A second datagram is so never read in the step of the first.
4. The holder knows the group took a datagram by the mark its transport leaves (`Watched`'s
   `took`), which says nothing of the socket holding more; the read steps the group again at once,
   and that step's receive answers `EAGAIN`. A message received where the reader keeps up so
   costs two steps of the pump, two passes of the executor and three system calls (the wait, the
   datagram, the empty receive), against zenoh-pico's one blocking `recvfrom`.

### 7.3 The design: the read task reads the group directly

zenoh-pico's read task reads a datagram and handles every message of it before it reads the next
(section 3.1). The same shape for wz, layer by layer, each the change that takes one cause:

| row | change | takes | where | state |
|---|---|---|---|---|
| D1 | the group's session held in a place its holder steps, not a task of the executor (`MulticastSessionPlace`) | layer 1's executor pass, 976.9 | `group_drive.rs` | round-5a (`f2bf7a05b`) |
| D2 | the read of a threads build steps each group where it lies, as it steps its faces | the engine step's task pass for a group | `engine/direct.rs` | round-5a (`9578dc50d`, `82c085fb1`) |
| D3 | the step reads a burst: up to a bound of datagrams, its fixed part once (`MulticastPump::step_reading`) | cause 2 for every datagram past the first of a burst | `group_drive.rs` | this lane |
| D4 | the due a step tells its holder said from the deadlines the pump keeps on the clock's epoch, no reading taken (`CoopTime::us_at_ms`) | two clock readings a step | `group_drive.rs`, `wz-runtime-coop/src/time.rs` | this lane |
| D5 | a datagram's records handed out inside the step that read it, before the next receive, so the burst of D3 reads on | cause 3; the burst of D3 reads on | `engine/direct.rs`, `engine/group.rs` | this lane (`GroupPump::step` reads to `GROUP_READS_PER_MOVE` in one step) |
| D6 | the mark of a group's input said by the step: the holder steps again only when the step's burst ended on its bound, not on a receive that found none | cause 4's empty step | `engine/group.rs` (`Watched`, `took_input`), `group_drive.rs` (`read_to_bound`) | this lane |
| D7 | the read of a threads build blocks in the group's receive, with the socket's receive timeout as its tick, when the group is the only input it waits on; the receive half of the group's transport held apart from the link cell the publishes share (section 7.6) | the wait's system call, the empty receive, and the read's layers once a burst | `engine/direct.rs`, `engine/group.rs`, `group_drive/stage.rs`, `wz-runtime-coop/src/group_transport.rs`, `wz-runtime-posix/src/multicast.rs` | design; the split first |
| D8 | the holder's clock reading handed to the step (a step at a reading), so a burst read by an engine step reads the clock once | one clock reading a step | `group_drive.rs`, `engine/direct.rs` | this lane (the read's last face turn's reading) |

`step` reads one datagram at a reading of its own, as before; the read of the C ABI
(`CoopEngine::step_groups`, `engine/direct.rs`) calls `step_reading` once a read with the
deploy's `GROUP_READS_PER_MOVE` and the reading of the read's last face turn, where it stepped
the pump up to that many times. Each datagram's records are handed out by the step's `on_event`
before the next receive, so no gate holds the burst back: the read hands every record out as it
is read and keeps no round. A threads build whose form has no lock of its own for each value
(`wz_round`, `build.rs`) keeps the group's session as a task and its records in the round;
there the round's gate (`round::takes_a_group_read`) still refuses a datagram while a record
lies in the one the transport lent, which is what keeps the lent bytes from being written over,
and that form reads a datagram a step as before.

Per received message where the receiver keeps up, the read now costs one step of the pump, its
fixed part once, and no clock reading of the step's own; the system calls are still the wait,
the datagram's `recvfrom` and the `recvfrom` that answers `EAGAIN` and ends the burst. D7 is
what takes the wait, and is not made yet.

Expected, by the counts of section 7.1 and to be read on the arm: D1 and D2 take the executor's
pass (976.9) and most of the engine step's own work; D4 takes two of the clock's readings a step
(the clock costs 373.3 a message in all; how many readings that is, M5's call counts say); D5 with D3 takes the second
step of each message, which is a pump step outside the receive (1,174.6 less its receive) and an
`EAGAIN` `recvfrom`; D7 takes the wait. What then stays above the walk is the read task's
`recvfrom` and the step's fixed part once a burst, the shape of zenoh-pico's read task.

### 7.4 The concrete transport (T4)

The group's transport is a `Box<dyn GroupTransport>` from the joiner
(`GroupJoiner::join`, `wz-runtime-coop/src/group_transport.rs`) to `Watched`, so every call the
step makes of it (the carrier, the service, the gate's lending, the receive, each send) is a call
through a vtable, two of them on the receive. The concrete form: the joiner names the transport it
makes as an associated type (`type Transport: GroupTransport`), `HostGroups` names
`HostGroupTransport<S>`, and `Watched` is generic over it, so the shipped preset, which joins
only UDP groups over the host's sockets, makes no indirect call on the group's path. A build that
composes joiners (`RawethJoiner` beside `HostGroups`) names an enum of their transports, as
`either_links` composes links. Every file of it but the joiner's is `engine/group.rs`, which
round-5a rewrites, so it is a row after that merge; its measure is the `dyn` calls of M4 and M5.

### 7.5 The unit tests of the rows and how they run

Each test is compiled only where the code it tests is, so a filter names the features of that
code; a filter that names a test of a module the build leaves out runs none and still passes.

* `wz-session-core` `the_member_count_follows_every_admission_and_departure` (R4) is in
  `multicast_dispatch`, which is `session-multicast`'s:
  `cargo test -p wz-session-core --features session-multicast --lib the_member_count_follows_every_admission_and_departure`.
* `wz-session-mcu` `a_push_onto_empty_lanes_leaves_from_where_it_was_written` (T3) is in
  `group_drive::stage`, the heap profile's (`alloc`, not `session-slot`, `codec-push`):
  `--all-features` turns `session-slot` on and leaves it out.
  `cargo test -p wz-session-mcu --features transport-multicast,codec-push --lib a_push_onto_empty_lanes`.
* D3, D4, D6 and D8: `cargo test -p wz-session-mcu --features transport-multicast,codec-push --lib group_drive::tests`
  (`a_step_reads_up_to_its_bound_of_datagrams_with_one_beacon`,
  `a_burst_ends_where_the_holders_gate_has_no_room`,
  `the_pump_says_when_it_is_next_due_with_no_reading_of_its_clock`,
  `a_step_says_whether_its_reads_ended_on_its_bound`,
  `a_step_at_the_holders_reading_measures_by_it_and_reads_no_clock`), and
  D5 and D6 through the read of the C ABI, a threads build whose form gives each value a lock of
  its own (the host's `std`):
  `cargo test -p wz-capi-coop --features group,app-transport --lib a_burst_of_a_members_datagrams_moves_the_links_once`, and
  `cargo test -p wz-runtime-coop --lib time_us_at_ms_is_the_reading_at_which_that_millisecond_starts`.

### 7.6 The third reading's receive, function by function

The third reading's subscriber window (section 1.2), callgrind's functions by their inclusive Ir
per received message, as in section 7.1:

| layer (wz) | function | Ir per message | the layer alone |
|---|---|---:|---:|
| the read thread | `wz_host_sync::unix::entry` | 5,548.1 | 266.4 |
| the read task's read | `run_body` of `start_read_task` | 5,281.7 | 58.9 |
| the wait: its deadline gathered, then the `poll` | `CoopEngine::wait_on_faces` | 689.4 | 689.4 |
| the dial role's face, at rest, turned for the session's bookkeeping | `CoopEngine::face_turn` | 698.7 | 698.7 |
| the groups' step: the pump taken out of its slot and put back | `CoopEngine::step_groups` | 3,834.7 | 382.4 |
| the pump's step outside its receives | `GroupPump::step` | 3,452.3 | 310.5 |
| the receive: two `recvfrom`, the own-sender check | `HostGroupTransport::recv_with` | 3,141.8 | 394.7 |
| the walk: the member, the SN gate, the frame | `MulticastPump::step_reading`'s receive closure | 2,747.1 | 1,055.1 |
| the records decoded and delivered | `walk_lent_payload` | 1,692.0 | 1,692.0 |

The calls of the larger run say what a read is: 12,470 reads, each one `poll` (12,235), one face
turn, one step of the pump and two receives (24,480: the datagram, then the `EAGAIN` that ends the
burst). A read reads one datagram, since the receiver keeps up and D3's burst is one datagram long.

The walk (2,747.1) is zenoh-pico's handling of the transport message (2,692.0) to within 2 %: what
decodes, gates and delivers a datagram is no longer the excess. Of the excess of 2,017.2, 55.1 is
the walk's and 1,962.0 lies above it, in what a read costs, paid once a datagram because a read
reads one: the wait 689.4, the face turn 698.7, the step's own parts 382.4 and 310.5, the empty
receive (about half of 394.7) and the read thread and task 325.3, against zenoh-pico's 839.0 above
its handling (its read task 572.0 with its one `recvfrom`, its executor 246.0).

1. The wait gathers the session's deadlines under its lock (`link_wait`, `Core::idle_wait`: the
   gets, the replays, the jobs, the faces' due, the groups' due, the clock when one is due), 487.9,
   and polls the group's socket, 201.5.
2. A session whose one face is the dial role's, at rest, turns it on every read for the session's
   bookkeeping (`read_faces`), and the look's bookkeeping runs on every read: the ledger is owed
   whenever the registry's count of written face tables moved (`Ledger::owes`), and every record
   dispatched moves it (`RegistryOf::split` counts each hand-out of a face's tables as a write).
   A read that dispatched a Push so sweeps the gets, reads the matching listeners again
   (`read_matching`, 11,989 calls for 12,000 messages) and settles the ledger. The Push itself is
   handed out unwritten (`hand_lent_push`, 12,000 calls; `RegistryOf::split_unwritten` is the
   form for it), but each datagram dispatches a second record beside it through
   `FaceRecords::dispatch` (12,000 calls, 390.0 a message, `dispatch_event_to` 246.0 of it into
   `dispatch_event_but_samples`), whose `split` is what counts the write. Which record that is
   (an event of the frame, not a Push lent where it lies, by `DirectSink::event`'s last arm) is
   for the next reading to name, with a count of `DirectSink::event`'s arms.
3. The empty receive ends every burst.
4. The step's own parts: the pump moved out of its slot and back (three copies a read, 37,410
   `memcpy` calls in 12,470 reads), the settle of the registry's held replies, the stop, the
   carrier and the writer.

D7 as section 7.3 first wrote it, a receive that blocks inside the step, cannot be made on the
link as it is. The pump's step runs with the session's lock held (`step_group`) and lets it go
only while a record is handed out; the group's transport lies in the link cell the group's face
shares (`GroupLink`, an `Rc` of a `RefCell` of the transport), through which a publish on the
program's thread sends (T3's write through takes the transport with `try_borrow_mut`). A receive
that blocked inside the step would hold the session's lock for its whole wait, which stops every
publish, or let the lock go with the transport borrowed, which every publish would find held and
stage instead of writing. D7 is so two changes:

* D7a: the transport split into its send half, which stays in the cell the face shares, and its
  receive half (the joined socket and its receive buffer), which the pump alone holds;
  `HostGroupTransport` has the two sockets apart already (`read`, `write`).
* D7b: where the group is the only input the read of a threads build waits on and its stage holds
  nothing, the read makes no wait of its own: the step's receive blocks on the receive half, with
  the session's lock let go around the system call as the hand-out lets it go, up to the read's
  bound, and each later receive of the burst up to what is left of that bound by a monotonic
  reading taken after each datagram. A burst then ends at its bound of datagrams or at the read's
  deadline, never on an empty receive, and the wait, the face turn and the step's own parts are
  paid once a deadline, not once a datagram.

Expected where the receiver keeps up: the walk (2,747.1), one blocking `recvfrom` with its
own-sender check (about 200), a clock reading (about 90) and the read's layers shared by the
datagrams of one bound, within zenoh-pico's 3,531.0.

### 7.7 The third reading's put, function by function

| thread | function (wz / zenoh-pico) | W | P |
|---|---|---:|---:|
| the calling thread | `op_put` | 3,418.0 | 2,306.0 |
| the calling thread, whole | `main` | 3,580.0 | 2,467.8 |
| the read thread | `run_body` of `start_read_task` / `_zp_multicast_read_task_fn` | 2,250.4 | 87.0 |
| the program | | 5,830.3 | 2,554.8 |

The read thread is 2,163.4 of the put's excess of 3,275.5. The group loops a member's own datagram
back to its joined socket (the system's `IP_MULTICAST_LOOP` default, which the sessions of one
host need), and each put's datagram wakes the publisher's read: its wait (678.7), its face turn
(383.2) and a step of the group (869.8, of it the pump's step 578.4 and the receive 313.3 that
drops the datagram as its own and reads the `EAGAIN`). zenoh-pico's read task drops it inside
its blocking receive, which loops on `recvfrom` past its own sender
(`vendor/zenoh-pico/src/link/transport/udp/udp_multicast_posix.c` @
`rb = recvfrom(sock._fd, ptr, len, 0, (struct sockaddr *)&raddr, &replen);`), and costs 87.0 a
put. With D7b's receive, whose own-sender drop goes on to the next datagram within the read's bound
without returning to the read, the own datagram costs a `recvfrom` (P1).

The calling thread is 1,112.0 past zenoh-pico's. T3 is taken: every put's datagram is offered to the
socket from where it was written (`GroupTxStage::push_encoded_through` 1,374.0, one
`LinkCell::send_now` a put) and the writer's `take_front` runs on the read thread alone. No
executor and no round is on the path: the put reaches the group through `publish_everywhere`,
`publish_to_link`, `fan_out_in` and `publish_to_groups` on the calling thread, under the
session's lock. What is left is layers:

* the faces' leg on a session with no face whose link is up: `publish_to_link` is 2,714.0 and the
  groups' leg inside it 1,961.0, so 753.0 go to the faces' send places tried, the run, the key named
  for the links (`leg_of` 233.0) and `send_on_links`, none of which reaches a link (P2);
* the groups' leg itself, 1,961.0 against zenoh-pico's `_z_write` 1,670.0: the conduits, the
  frame begun, the lane's encode and the stage's accounting around the one `sendto`;
* the write filter read before the wire (`publish_filtered` 384.0 with `put_through_filter`).

T4's measure: each `dyn` call it removes costs tens of Ir, and the group's path makes a few a
message (the receive's, the carrier's, the gate's, the service's) and one or two a put. It is a
row after D7a, which changes the same trait and every joiner (`HostGroups`, `RawethJoiner`,
`NoGroups` and `ip_stack`'s test joiners): the split names the receive half's type, which is
where the concrete type belongs.

### 7.8 The rows the third reading leaves

| row | change | takes | files | state |
|---|---|---|---|---|
| D7a | the group's transport split: its send half in the link cell the face shares, its receive half held by the pump alone | what lets D7b let the session's lock go around a blocking receive | `wz-runtime-coop/src/group_transport.rs`, `wz-runtime-posix/src/multicast.rs`, `group_drive/stage.rs`, `engine/group.rs`, every joiner | this lane (`3b4384cc6`) |
| D7b | the read of a threads build blocks in the group's receive half when the group is its only input and the stage holds nothing, the lock let go around the system call, each receive bounded by what is left of the read's deadline | receive: the wait 689.4, the face turn 698.7, the step's own 692.9 and the empty receive, once a deadline instead of once a datagram | `engine/direct.rs`, `group_drive.rs`, `wz-runtime-posix/src/multicast.rs`, `net.rs` | this lane (`88710f3c2`); its reads made once a deadline by D10 |
| P1 | the own-sender drop of D7b's receive goes on to the next datagram within the bound | put: 2,163.4 of the read thread | `wz-runtime-posix/src/multicast.rs` | this lane (`88710f3c2`) |
| D9 | the record each datagram dispatches beside its Push (section 7.6, item 2) named, and dispatched where it writes no face's tables without `split`'s count, so the ledger is not owed and the matching listeners not read again by it | receive: that dispatch, 390.0, and the face turn's bookkeeping (`read_matching` 60.9, the sweeps, the settle) | `engine/direct.rs`, `engine/registry.rs`, `wz-session-core/src/multicast_rx.rs` | this lane (`e46da4fcf`: the member a walk names ahead of each datagram's records) |
| D10 | a waiting read reads its group to the read's deadline: a datagram a step, each waited for in the receive half from the reading after the last, the read's turn taken again only at the deadline, at a wait that kept nothing, or where the read owes the session its bookkeeping or a job (`read_awaited`) | receive: the read's layers once a datagram, 1,276 (section 7.9) | `engine/group.rs`, `engine/direct.rs`, `wz-runtime-coop/src/group_transport.rs`, `wz-runtime-posix/src/multicast.rs` | this lane |
| P2 | the groups' leg of a put made without the faces' work: no try of a face's send place that holds no parts, no `send_on_links`, and no `leg_of` lookup of the key in the session's tables, of which the groups' leg reads only the `SendAs` | put: about 420 of the calling thread (section 7.9) | `engine.rs` (`fan_out_in`, `leg_of`), `engine/direct.rs` (`on_faces`) | design: what a key `named_at` refuses must stay refused on the groups' leg |
| T4 | the concrete transport, named by the receive half's type | tens of Ir a message | as section 7.4 | after D7a |

By the counts above, D7a, D7b and P1 bring the receive within zenoh-pico's and the put's read
thread to its; the put's calling thread then stands at about 2,830 against 2,468 with P2, and the
groups' leg (section 2's S1 to S4) is what is left to take for the put's 1.0.

### 7.9 The fourth reading, function by function

The receive (12,473 reads for 12,000 messages, so still one read a datagram):

| layer (wz) | function | Ir per message | the layer alone |
|---|---|---:|---:|
| the read thread | `wz_host_sync::unix::entry` | 4,808.5 | 262.1 |
| the read task's read, its delivery | `run_body` of `start_read_task` | 4,546.4 | 75.2 |
| the wait's deadlines gathered, no `poll` made | `CoopEngine::link_wait` | 549.6 | 549.6 |
| the dial role's face, at rest, turned for the bookkeeping | `CoopEngine::face_turn` | 389.9 | 389.9 |
| the groups' step: the wait in the receive, the pump out of its place and back | `CoopEngine::step_groups` | 3,531.7 | 746.9 |
| the pump's step outside its receives | `GroupPump::step` | 2,784.8 | 313.8 |
| the receive half: the kept datagram, then a receive that finds none | `HostGroupReceive::recv_with` | 2,471.0 | 221.0 |
| the walk: the member, the SN gate, the frame, the records | `MulticastPump::step_reading`'s receive closure | 2,250.0 | 2,250.0 |

The walk is below zenoh-pico's handling of the transport message (2,692.0). The excess of 1,276.1
is, to within a unit, what a read costs and a datagram pays, since D7b's wait returns to the read after the one
datagram it kept: the read thread's and task's own 337.3, the deadlines gathered 549.6, the face
turn 389.9. Inside the groups' step a datagram pays the wait in the receive (309.4 with its
blocking `recvfrom`), the pump moved out of its place and back (93.5, 37,419 `memcpy` calls), the
registry's settle (49.9) and two takes of the session (46.2), and the step's receive after the kept
datagram, which finds none (24,483 receives for 12,000 datagrams). D10 reads the group to the
read's deadline in the one read: each datagram is waited for in the receive and stepped alone, so
none is followed by a receive that finds none, and the read's own layers and the pump's move are
paid once a deadline, with one take of the session a datagram to ask whether the read is owed its
turn. Expected where the reader keeps up: the walk, the step's own part, one blocking `recvfrom`
and one clock reading a datagram, about 3,350 against zenoh-pico's 3,531.9.

The put (the calling thread `op_put` 3,418.0 against zenoh-pico's 2,306.0; the read thread 234.7
against 87.0, which P1 took from 2,250.4): `publish_to_link` 2,714.0 holds the groups' leg
(`publish_to_groups` 1,961.0) and around it work for the faces: `try_leg` of the two faces'
send places, each holding no parts (136.0), the key looked up in the session's tables
(`leg_of` 233.0), of which the groups' leg reads only the `SendAs`, `send_on_links` over no
link that is up (48.0), `live_to_publish` (37.0) and the run's marks. The write filter before it
(`PublisherState::publish` 3,250.0 against `publish_everywhere` 2,750.0) is 500.0. What stays
past those is the groups' leg against zenoh-pico's `_z_write` 1,670.0, section 2's S1 to S4.

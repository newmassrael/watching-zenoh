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
| M1 receive, Ir per message, net | 8,227.9 | 3,531.0 | subprofile, callgrind |
| M2 send, Ir per put, net | 6,373 | 2,555 | opprofile put |
| M3 receive, system calls per message by kind | *to measure* | *to measure* | subprofile, strace |
| M4 send, top 20 functions per put | *to measure* | *to measure* | opprofile put |
| M5 receive, top 25 functions per message, net | *to measure* | *to measure* | subprofile, callgrind |

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
kept) and T3 (write through). The rows that reach the receive path's executor turn and system
calls (R1, R2, R3) and T4 rest on the round-5a lane's rewrite of `engine/group.rs`,
`group_drive.rs` and the engine's read, which does not merge onto this lane as it stands: the
engine's get issuing, declarations and query answers were rewritten on both sides (round-5a's
link place taken before the session, main's one hold per operation and replies held to their
Final), a conflict whose resolution is a choice of lock order that belongs to those lanes.

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

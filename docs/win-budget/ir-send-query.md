# Instruction budget: send, query, declare, open

Status: design, 2026-11-26. One of the five win-budget documents (receive, send and query, heap,
text, std heap). It covers the per-operation instruction count of the operations a program calls,
on the caller's side: one publisher's put, a get and its replies up to the final, a declaration and
its retraction (subscriber, publisher, queryable), and an open and close. The read of a received
sample is `ir-receive.md`'s; the read that ends a get here goes through it and is counted where it
lands (section 4).

Goal, for each operation, in both shipped forms (the nostd no-heap form of the pico preset's
`zenoh-pico_defconfig`, and the std heap form): wz's instructions per operation at or below
zenoh-pico's on the same machine, by the same probe, with no allocation per operation in either
form.

## 1. How it is measured

`scripts/pico-compare.sh opprofile` (perf-harness, 9009f4b74) builds `scripts/host-bench/op_probe.c`
once against zenoh-pico and once against the shipped `libwz_capi_pico`, runs each operation a small
and a large number of times over the same wall time under callgrind, and reports the difference
divided by the difference of counts: what one operation costs, net of the session's own life
(lease, keep-alive). Counts: put and declarations 2,000 and 12,000; get 200 and 1,200; open 20
and 120. The put's payload is 8 bytes (`-s`); the probe's put clones a held payload and moves the
clone into `z_publisher_put` with NULL options; the get uses default options and waits for its
final on the probe's own condition variable; a declaration is declared and retracted at once.

The whole process is counted: what an operation makes the read task do (the reply of a get, the
peer's answer to a publisher's interest) is in the operation's count, on both arms alike. The
verdict is the per-operation line of `report.txt` for each arm; the stage columns below are read
from the inclusive costs of the named functions in the same callgrind files.

**Measured, 2026-11-26.** `scripts/pico-compare.sh opprofile` on main `cf6ca0963` (the run
`target/pico-compare/opprofile-runs/host-20261125T224055`: `report.txt`, `per-op.tsv` and the
callgrind files beside them; one i9-14900HX host, valgrind 3.22.0). The wz arm is the shipped nostd
form, profile `capi-nostd` with its cargo configuration and the preset's limits, features
`os-posix,link-udp,scout,peer,multicast-transport,query,queryable,liveliness,liveliness-get,multi-thread`.
Instructions per operation, net of the paced loop (`none`: 154.7 on wz, 154.8 on pico):

| operation | role | wz | pico | wz/pico |
|---|---|---:|---:|---:|
| put, 8 B | the caller | 2,195.1 | 2,376.3 | 0.92 |
| get | the querier | 19,146.1 | 11,909.7 | 1.61 |
| get | the queryable peer | 13,221.0 | 2,859.4 (10,010.9 attributable), biased low: below | 4.62 (1.32); 1.27 on the window |
| declare and retract a subscriber | the caller | 15,383.6 | 14,120.5 | 1.09 |
| declare and retract a publisher | the caller | 9,577.3 | 11,279.5 | 0.85 |
| declare and retract a queryable | the caller | 15,026.7 | 13,638.4 | 1.10 |
| open and close | the caller | 142,794.9 | 173,335.6 | 0.82 |

**The queryable peer's line, as read above, is biased low on the pico arm.** The peer is not
paced: `op_probe -o queryable` serves for a fixed 46 s, and its line is the slope of the whole
process between 200 and 1,200 answered queries. A zenoh-pico peer with no peer yet wakes its read
task every 100 ms
(`vendor/zenoh-pico/src/transport/unicast/read.c @ return _z_fut_fn_result_wake_up_after(100);`),
and its background executor spins rather than sleep for a wake-up 1 ms or less away
(`vendor/zenoh-pico/src/runtime/background_executor.c @ if (zp_clock_elapsed_ms_since(&res.next_wake_up_time, &now) > 1) {  // sleep until next task is ready`),
1 to 2 ms per wake-up. How many wake-ups a run holds depends on how long it waits unconnected,
which depends on the host's speed, so the slope of the two runs took idle work off the per-query
cost: the timer functions' exclusive costs (`_z_background_executor_inner_run_forever`,
`_z_executor_get_next_fut`, `_z_executor_spin`, `z_clock_now`, `zp_clock_elapsed_ms_since`,
`z_clock_advance_ms`) fell by 7,151.4 Ir per added query while the functions that serve a query
rose by 10,010.9 (`get-P-200.peer.inclusive-no.txt` against `get-P-1200.peer.inclusive-no.txt`).
The harness of `f5f8ce646` counts the queryable's connected window alone and nets an idle run of
the same window; its reading follows.

**Read again with the window harness** (`f5f8ce646`, main `cf6ca0963`, the shipped nostd form,
2026-11-26; wz over pico, net of the idle run):

| operation | role | wz/pico, window | wz | pico |
|---|---|---:|---:|---:|
| put, 8 B | the caller | 0.92 | in the run's report | in the run's report |
| get | the querier | 1.63 | in the run's report | in the run's report |
| get | the queryable peer | 1.27 | 12,883.3 | 10,167.8 |
| declare and retract a subscriber | the caller | 1.09 | in the run's report | in the run's report |
| declare and retract a publisher | the caller | 0.85 | in the run's report | in the run's report |
| declare and retract a queryable | the caller | 1.10 | in the run's report | in the run's report |
| open and close | the caller | 0.69 | in the run's report | in the run's report |

The queryable peer's pico line, 10,168, is within 157 of the 10,011 the biased run attributed to a
query: that attribution was right, and the window line is the verdict now (D5). The callers'
lines move little (put, the declarations), as a paced caller's process holds no unconnected wait
in its slope. On the branch `decl-row` (`3201059a2`, read with the harness before `f5f8ce646`):
subscriber 0.88, publisher 0.67, queryable 0.89, get the querier 1.49; to be read again on the
window when it lands (measure, harness f5f8ce646).

The per-operation totals of section 4 are these lines. A stage's "now" is measured where its row
says so (section 4.2b, from the same callgrind files) and is otherwise an estimate read from the
code path, marked *est.*; the cells still to read are listed in section 8. The estimates use these
unit costs, taken from the receive measurement's exclusive costs on the same machine and libc:

| unit | instructions | read from |
|---|---|---|
| one pthread mutex lock and unlock | about 205 | pico receive: `pthread_mutex_lock` 115.9 + `unlock` 88.9 per sample |
| one malloc and its free | about 250 | pico receive: `malloc` 177, `free` 116, `_int_free` 216 per sample, at about two pairs |
| one VLE read | 10 to 20 | `SceCursor::read_vle_inner` 102 per sample over the fields read |
| a wait and readiness pass | 90 to 130 | `poll_on` 99, `select` 91 |

## 2. What the code does now, and where it differs from pico

### 2.1 The put

wz, the plain put of a publisher with NULL options (the probe's), one unicast face, no group:

```
z_publisher_put -> read_moved_bytes -> PlainPublisher::publish -> WriteFilter::publish
  -> CoopEngine::publish_filtered -> put_through_filter
     -> live_on_link: the dial face's send place, then the session's lock (Core)
     -> put_through_filter_in: the filter's row in the slot map, row.planned_put(send epoch)
     -> put_planned -> send_plain -> send_on_links -> LinkLeg::send_to
        -> LinkActions::send_put_with_head -> send_plain_put_at -> dispatch_network_message_at
           -> lend_frame (out of line; the body writer a closure) -> with_conduit_link -> lease_on
           -> fill_lent_frame (SN, Frame header, the plan's Put head, payload length, payload)
           -> emit_on_link -> StreamDriver::tx_slot_send -> frame_prefixed -> send()
```

The put is written once, into the slot its link lends, from a head the publisher's declaration
wrote; nothing is copied but the payload. Three things cost more than pico's path does:

- **The session's lock is taken for every put**, to read the filter's row and its plan
  (`crates/wz-capi-coop/src/engine.rs @ if given.is_none() && groups_left {`). Pico's put takes no
  session lock: it reads the write filter's flag and takes the peers' and the transmit mutex
  (`vendor/zenoh-pico/src/transport/common/tx.c @ _z_transport_peer_mutex_lock(ztc);`,
  `vendor/zenoh-pico/src/transport/common/tx.c @ ret = _z_transport_tx_mutex_lock(ztc, cong_ctrl == Z_CONGESTION_CONTROL_BLOCK);`).
- **A session that joined a group never takes the plan**: `groups_left` sends every put the
  general way (`publish_everywhere`, `fan_out_in`, the key named again in the tables, each link's
  key form looked up again). The shipped preset is a listening peer in a group (section 8.12 of
  `docs/c-abi-architecture.md`), so the shipped form's common case is the slow one.
- **About fifteen calls between the ABI and the socket**, two of them out of line with the body
  writer passed as a closure (`crates/wz-session-core/src/session_actions.rs @ fn lend_frame<P>(`),
  and per-call checks that a plan already decided (`rewrites_originated_keys`, the head's naming of
  the key, the QoS match, the probe stage).

Pico (`vendor/zenoh-pico/src/net/primitives.c @ _z_n_msg_make_push_put(&msg, &wireexpr, payload, encoding, qos, timestamp, attachment, reliability,`)
builds a network message struct on the stack and encodes it whole with the generic encoder into
the transport's one write buffer
(`vendor/zenoh-pico/src/transport/common/tx.c @ __unsafe_z_prepare_wbuf(&ztc->_wbuf, ztc->_link->_cap._flow);`).
In peer mode it encodes once for every peer and writes the same bytes to each peer's socket, with
one sequence number for all of them
(`vendor/zenoh-pico/src/transport/common/tx.c @ _z_link_send_wbuf(ztc->_link, &ztc->_wbuf, &curr_peer->_socket);`).
Upstream zenoh writes a put into the batch of the transport's stage under the stage's mutex
(`io/zenoh-transport/src/common/pipeline.rs @ let mut queue = zlock!(self.stage_in[idx]);`),
one encoding per transport, after the session routes it (`zenoh/src/api/session.rs @ primitives.send_push_consume(`).

### 2.2 The get

wz (`crates/wz-capi-coop/src/engine.rs @ fn get_on_wire(`) takes the session's lock once for the
timestamp policy (`let expose = {`), once more per face in its loop (`live_on_link`), and once
more for the turn that finds no next face; with `local-queryable` once more for the local
request id. Per face it takes a leg id, a request id through the link's actions, holds a leg in the
consolidating sink (with its deadline), names the key on the link and sends the Request. The
replies come through the receive path, and through the round of deliveries until section 8's
steps land. The earliest deadline of every get is found again by walking every holder's get
tables on each wait: in the receive measurement, with no get pending at all, that walk
(`RegistryOf<ManyHolders>::all_gets`, `LegTables::next_deadline_ms`) is 140.8 instructions per
received sample.

Pico copies the key (`vendor/zenoh-pico/src/net/primitives.c @ _Z_CLEAN_RETURN_IF_ERR(_z_keyexpr_copy(&ke_query, &keyexpr->_inner), _z_drop_handler_execute(dropper, arg));`),
pushes a pending query on a list (`vendor/zenoh-pico/src/session/query.c @ zn->_pending_queries = _z_pending_query_slist_push_empty(zn->_pending_queries);`),
both allocations, under one take of the session mutex, then sends the Request as a put is sent.
Under the default consolidation (latest) it stores each reply until the final and hands them out
then (`vendor/zenoh-pico/src/session/query.c @ if (pen_qry->_consolidation == Z_CONSOLIDATION_MODE_LATEST && do_finalize) {`),
an allocation per stored reply.

### 2.3 The declarations

wz (`declare_subscriber_on_wire` and its twins) does the declaration in one hold of the dial
face's place and the session's lock: the id, the row in the tables, the announcement to each link
and each group. Then, in the same hold, `core.settle_faces(tx)` (`interest-answer`) and
`self.read_matching(core)` (`local-subscriber`, the matching of every write filter of the
session read again), and after it `self.deliver()`. A publisher's declaration adds its write
filter, whose Interest goes to each face, as pico's does. The retraction is the same shape.

Pico allocates the subscription's counted cell and its list node
(`vendor/zenoh-pico/src/net/primitives.c @ _z_subscription_rc_t sp_s = _z_register_subscription(_Z_RC_IN_VAL(zn), _Z_SUBSCRIBER_KIND_SUBSCRIBER, &s);`),
creates drop notifiers of a sync group, may declare the key's non-wild prefix as a resource
(`vendor/zenoh-pico/src/net/primitives.c @ _z_declared_keyexpr_declare_non_wild_prefix(zn, &s._key, keyexpr)`),
and sends the Declare. Upstream zenoh does the same in one call
(`zenoh/src/api/session.rs @ pub(crate) fn declare_subscriber_inner(`).

### 2.4 The open and close

wz (`CoopEngine::open_made_in` -> `assemble` -> `open_links`) admits the configuration, takes an
engine row, works out the runtime's tables and the arena's plan, lends the session's memory from
the arena (`lend_session`), writes the endpoints, makes the entropy, then dials and runs the
handshake. Pico (`vendor/zenoh-pico/src/api/api.c @ _Z_SET_IF_OK(ret, _zp_start_transport_tasks(_Z_RC_IN_VAL(&zs->_rc)));`)
reads locators from a configuration map of strings, allocates the session, the transport and its
buffers, runs the handshake and starts its read and lease tasks; its close stops the runtime and
joins them (`vendor/zenoh-pico/src/session/utils.c @ _Z_RETURN_IF_ERR(_z_runtime_stop(&zn->_runtime));`).
Thread creation and the configuration's allocations dominate pico's open; a handshake costs
about the same on both.

## 3. The structure

Four rules, each a part of the structure rather than a tuning of one path.

**S1. An operation's plan is made when its entity is declared, and the operation runs from it
with no session lock.** A publisher's declaration already writes the Put's head and keeps a plan
at a send epoch. The plan becomes the publisher's **send plan**: for each face (each unicast face
and each group) the face's slot index, the key's wire form on that face, the head written for it,
the QoS and reliability, and the epoch it was made at. A put reads the session's send epoch (one
atomic load), takes each face's send place in turn as section 8.4 orders, checks the face's own
epoch word under that place, and writes the frame. The session's lock is taken only when an epoch
does not match, to make the plan again. This needs one rule added to section 8.4: **what a face's
plan depends on (its key forms, its up state) changes only while the face's send place is held**;
section 8.6's site debts already run under the face's place, and the tables' changes that move a
face's key form become debts of the face too. Then a plan checked under a face's send place is the
face's current truth, and the session's lock has nothing to add. Groups are faces of the plan: a
group's send place is its window, and its key form is the group's declaration form.

**S2. The frame writer is one straight line per message kind.** Under a held send place a message
is written by one non-generic function per kind (Put from a plan, Put from parts, Request,
Response, ResponseFinal, Declare, Interest): reserve the slot, take the SN, write the Frame header
and the message, write the length prefix, hand the slot to the link. The checks a plan decided are
not made again; the closure and the trait object of `lend_frame` and `send_lent_on` become the
kind's own writer; `emit_on_link`'s per-send work is the keep-alive mark alone in a build without
`transport-stats`. Batching keeps its window: with a window open the same writer appends to the
open frame.

**S3. Body once, header per face.** A put that reaches several faces whose key forms agree is
encoded once (the network message), and each face is written its own Frame header (its SN) and
the same bytes. A face whose key form differs is written from its own head. Each face keeps its
own SN, as upstream's transports do; pico's one SN for all peers is not copied (section 7, D1).

**S4. Nothing per operation is allocated, found by a walk, or locked twice.** Rows of every table
(pending gets and their legs, held replies, entities) are slots of tables sized at the open (the
heap document's per-session counts); a pending get is found by its request id in O(1) (the slot
index is in the id); the earliest deadline of the session's gets is kept in a deadline index
updated when a leg is held or ended, read in O(1) by the timer; an operation takes each lock it
needs once. Work an operation causes elsewhere (matching of write filters, interest answers, local
deliveries) is done only when something reads it: a declaration marks the matching of the filters
whose key it intersects, and the matching is read again where a listener asks or a plan is made.

## 4. The tables

Columns: **now** is wz's shipped nostd arm today (*est.* until a stage is read; each total is the
measured line of section 1), **pico** is zenoh-pico's on the same probe (likewise), **target** is the budget of the stage, whose sum is at
or below pico's measured total; **structure** is what meets it; **files** are the ones the lane
changes; **lane** names the boundary of the work (section 6).

### 4.1 Put (8 bytes, one unicast face, the probe's NULL options)

| stage | now | pico | target | structure | files | lane |
|---|---|---|---|---|---|---|
| ABI entry, payload move and its drop | *est.* 150-300 (the clone in the loop, `read_moved_bytes`, `take_payload`, the drop of the moved bytes) | *est.* 300-400 (`z_bytes_clone` copies the slice vector: one malloc and free, two counted-cell atomics) | 80 | a payload is a counted block of the payload pool (heap document); a clone is one count increment, a move is a pointer copy, the drop one decrement; no copy of the bytes | `crates/wz-capi-pico/src/bytes.rs`, `pubsub.rs` | S-ENTRY |
| session check and write filter | *est.* 300-450 (the face's send place, the session's lock, the filter's row in the slot map, `planned_put`) | *est.* 60 (the session's weak count raised and dropped, the filter's flag) | 40 | S1: the publisher's send plan; one atomic epoch load; the session's lock only on a stale epoch; the filter's answer is part of the plan | `crates/wz-capi-coop/src/engine.rs` (`put_through_filter`, `put_planned`, `send_plain`), `engine/direct.rs` (`hold_on_link`), `crates/wz-session-core/src/session_tables` (`PlannedPut`, write filter row) | S-PLAN |
| lock of the face's send place | *est.* 50-80 (the send place's hold, a flag in nostd, the host mutex with `threads`) | *est.* 410 (peers mutex and transmit mutex, one pair each) | 60 | one lock per face, the send place, nothing else; with `threads` the host mutex, without it a flag | `engine/direct.rs` | S-PLAN |
| encode: Frame header, Put, payload | *est.* 200-350 (head copy from the plan, but through `send_plain_put_at`'s checks, `dispatch_network_message_at`, `lend_frame`'s closure and `fill_lent_frame`) | *est.* 350-450 (the generic `_z_network_message_encode` of a Push: key, QoS extension, Put header, length, bytes) | 120 | S2: `write_put_from_plan`: SN, Frame header, head memcpy, payload length VLE, payload memcpy; no size pre-pass (the slot's room is known, the plan knows the head's length) | `crates/wz-session-core/src/session_actions.rs`, `lent_push.rs`, `tx_lease.rs` | S-WRITE |
| hand to the link | *est.* 250-400 (`emit_on_link`, `tx_slot_send`, `frame_prefixed`, the stream's `send`, libc's send stub) | *est.* 200-300 (`_z_link_send_wbuf`, the length prefix, libc's send stub) | 180 | the slot's length prefix written in place by the writer of S2; `tx_slot_send` reduced to prefix and `send`; the masking and oversize branches are a link kind's, not every stream's | `crates/wz-runtime-coop/src/stream_link.rs`, `link_storage.rs` | S-WRITE |
| local subscribers | 0 on the planned path; *est.* 100-200 on the general path (`has_local_matching`) | *est.* 0-100 (`_z_session_deliver_push_locally` when built with local subscribers) | 10 | the plan holds whether a local subscriber matches; a declaration that changes it moves the epoch | `engine.rs` (`put_plain_in`) | S-PLAN |
| **total, nostd** (measured 2026-11-26, section 1) | **2,195** (0.92 on the window harness too) | **2,376** | **at most pico's: met (0.92); design 460 (section 9.2)** | | | |
| with a group joined | *est.* +400-800 (the general path: `publish_everywhere`, `fan_out_in`, the tables' naming) | *est.* the same as unicast (one encoding written to the group's socket) | the unicast budget plus the group's write | S1: the group is a face of the plan | `engine.rs` (`fan_out_in`), `engine/group.rs` | S-GROUP |
| each face past the first | *est.* the whole encode and hand-out again | *est.* the hand-out again (one encoding, one SN) | header plus hand-out, about 220 | S3 | `session_actions.rs`, `engine.rs` (`send_on_links`) | S-FANOUT |

### 4.2 Get and its replies (one queryable peer, one reply of 8 bytes, default options)

| stage | now | pico | target | structure | files | lane |
|---|---|---|---|---|---|---|
| ABI entry, closure, options, parameters | *est.* 100-200 | *est.* 100-150 | 80 | unchanged shape; the closure moved into the leg's slot | `crates/wz-capi-pico/src/get.rs` | Q-ENTRY |
| pending get registered | *est.* 800-1,300 (three or four takes of the session's lock, `next_up_face` twice, a leg id, a request id through the link's actions, `hold_leg` with its deadline, the ledger's debt) | *est.* 800-1,000 (the key copied: malloc and copy; a list node: malloc; the session mutex; the clock) | 300 | S1, S4: one hold of the session's lock for the whole registration: a leg slot taken, the request id the slot's index and generation, the deadline put in the deadline index, the timestamp policy read in the same hold; the faces' sends after the lock is let go, each under its own send place | `engine.rs` (`get_on_wire`, `hold_leg`), `crates/wz-session-core/src/pending_get.rs`, `get_plane.rs`, `slot_observer.rs` | Q-HOLD |
| Request encoded and handed to the link | *est.* as the put's general path, 500-800 | *est.* 600-800 | 300 | S2: `write_request` | `session_actions.rs` | S-WRITE |
| the reply's read up to its dispatch | the receive path (`ir-receive.md`) | the receive path | `ir-receive.md`'s budget | section 8 | `ir-receive.md`'s | (receive) |
| reply dispatched to the leg | *est.* 400-700 (`Requesters`, `ConsolidatingSink`, `LegSink`, the round's delivery) | *est.* 700-1,000 (the session mutex, the pending query found by a list walk, the key matched, a reply stored: an allocation and a copy) | 250 | S4: the leg found by the request id's slot index; consolidation `latest` keeps the reply in the leg's reply slots (sized by the session's configuration) and hands it out at the final; with section 8, handed out where it is read | `crates/wz-session-core/src/reply_sink.rs`, `get_plane.rs` | Q-REPLY |
| final: replies handed out, leg ended, caller told | *est.* 400-700 (the leg's end, the deadline's removal, the callback's drop) | *est.* 500-700 (the session mutex, the list walk, the stored replies handed out and freed, the list node freed) | 200 | S4: the leg's slot freed, its deadline removed from the index in O(1) (an indexed heap) | `pending_get.rs`, `reply_sink.rs` | Q-REPLY |
| the deadline's upkeep per wait | 140.8 per received sample (the walk of every holder's get tables), more with gets pending | *est.* a scan of pending queries in the periodic task | 15 | S4: the deadline index; the timer reads its head | `engine/registry.rs` (`all_gets`), `pending_get.rs` (`next_deadline_ms`) | Q-DEADLINE |
| **total, nostd, querier side** (measured 2026-11-26, section 1) | **19,146**; 1.63 of pico's on the window harness; 1.49 on `decl-row` | **11,910** | **at most pico's** | | | |
| queryable side (the probe's peer role): Request read, `z_query_reply`, final | **13,221** (section 4.2b); **12,883** on the window harness | **2,859** the biased line; **10,011** attributable; **10,168** the window line (section 1) | **1,880** (section 4.2b); gate the window line, 10,168 | stage by stage in section 4.2b | section 4.2b | Q-SERVE, Q-REPLY, S-WRITE |

### 4.2b The queryable side, stage by stage (one Request, one reply of 8 bytes, its final)

Read 2026-11-26 from the run of section 1. **now**: the exclusive costs of the stage's functions in
`get-W-200.peer.inclusive-no.txt` and `get-W-1200.peer.inclusive-no.txt`, as (n1200 - n200) /
1,000; libc's `memcpy` and the host lock (`RawLock`) are given to the stages of their callers by
`callgrind_annotate --tree=caller` on the two `.peer.callgrind` files, and the frame and send
bodies that both messages pass (each called twice per query) half to the Response and half to the
ResponseFinal. **pico**: the inclusive costs of the named functions, from the callgrind's call
costs of `get-P-200.peer.callgrind` and `get-P-1200.peer.callgrind` the same way; each is a call
that returns inside the query's path, so it is not touched by the executor's idle work of section
1, and the stages add up to the attributable 10,011. Both arms send the Response and the
ResponseFinal in a frame and a `send` of their own (`send` is called twice per query on each).

| # | stage | now | pico | target | structure (what remains after section 8 of the architecture) | files | lane |
|---|---|---:|---:|---:|---|---|---|
| 1 | wait for the Request and wake | 1,007 (`Core::idle_wait` 260, `poll_on` 104, `LinkSupervisor::waited` 98, the pthread cancellation marks of the blocking calls 132, `wait_ready` 64, the read task's body 62, `now_us` 36, `recv` 31, `run_tasks_at` 29, `IdleWait::wait` 29, `poll` 24, `clock_gettime` 22, smaller 116) | 621 (`_z_socket_wait_readable` 387 with `select` 126, `_zp_unicast_read_task_fn` 129, the read task's recursive mutex 105) | 120 | `ir-receive.md` stage 1: with `threads` the face's read task blocks in one `recv` on its own socket, no poll and no clock read per datagram | `wz-runtime-posix/src/net.rs`, `wz-runtime-coop/src/session_drive.rs`, `faces.rs` | R1 |
| 2 | executor pass and round | 2,106 (`step_after` 499, `run_among` 234, `FaceDispatch::event` 216, `hand_out` 143, `poll_erased` 142, `Round::writable` 92, `CoopEngine::live` 84, `ManyHolders::split` 66, the round's table and its `RoundQuery` views 199, `RoundGate` 116, eight host-lock holds 80, the rest of the round's bodies 235) | 0 | 0 | section 8: the Request is handed to its queryable where it is read; `RoundQuery`, `RoundDelivery` and `hand_out` go with step 5 | `wz-capi-coop/src/round.rs`, `engine.rs` | section 8 steps 2 to 5 |
| 3 | stream read, batch and frame header | 716 (`UnicastRx::dispatch_datagram` 215, `StreamDriver::recv_with` 186, `walk_records` 67, `parse_frame_in_place` 62, `admit_head_in_place` 60, `walk_records_in_place` 56 and its record closure 48, `take_input` 22) | 613 (`_z_transport_message_decode` 171, `_z_unicast_handle_frame` 108, `_z_link_socket_recv_zbuf` 99, `_z_unicast_process_messages` 61, the read buffer's view and update 79, the network message's dispatch to `_z_handle_request` 95) | 200 | `ir-receive.md` stages 2 and 3: every whole batch handed out in one call, one generated frame-header read on the read slot's own receive state | as `ir-receive.md` | R1, R2 |
| 4 | Request record decode | 1,639 (`SceCursor::read_vle_inner` 334 and the other cursor reads 117, `ExtEntryView::decode_into` 234 and `ExtEntryWalk::decode` 84, the extension admission `map_or::<ExtAdmission, judge_entries>` 135, `read_envelope_extensions` 125, `RequestView::decode_into` 122, `QueryExts::of` 69, `WireexprLocalIn::decode_into` 64 and its UTF-8 check 59, `read_request` 58, `lent_projection` 55, `QueryView::decode_into` 52, `read_folded` 48, smaller bodies) | 968 (`_z_network_message_decode`: `_z_request_decode` 868, of it `_z_msg_ext_decode_iter` 405, `_z_wireexpr_decode` 238, `_z_zsize_decode` 102, `_z_query_decode` 41) | 400 | `ir-receive.md` stage 4 for a Request: one generated pass from the record header to a flat `RequestRef` (key, id, parameters, the query body), the extensions read once into known slots with their admission judged in the same pass; today they are read by `read_envelope_extensions`, `QueryExts::of` and `read_folded` in turn | `wz-session-core/src/network_message.rs`, `query/in_place.rs`, `ext_admit.rs`; SCE's codec templates | R3, then R2 |
| 5 | the record offered to every registry | 365 (`SlotObserverOf::dispatch_event_among` over the requesters 133; the `dispatch_iteration_event` of eight registries that take no Request, replies, local tokens, subscribers, liveliness gets, remote queryables, peer tokens, remote subscribers and liveliness, 222; `slot_map::Core::next_in` 10) | 0 (the network message's kind picks its handler: `vendor/zenoh-pico/src/session/rx.c @ case _Z_N_REQUEST:`) | 0 | a Request is handed to the query plane alone, as a Push is handed to the subscribers alone (`crates/wz-capi-coop/src/engine.rs @ .with(\|registry\| registry.dispatch_push(face, event));` against `@ registry.dispatch_event(face, event);`); the kind is the decode's header switch | `wz-capi-coop/src/engine.rs` (`FaceDispatch::event`), `engine/registry.rs` | Q-SERVE |
| 6 | the query's key against the queryables | 79 (`KeyFacts::of` 46, `QueryableRef::reaches` 33) | 199 (`_z_get_keyexpr_from_wireexpr` 148 with the session mutex, `_z_keyexpr_intersects` 51) | 60 | the queryables matching a resource kept on its row, as `ir-receive.md` stage 6 keeps the subscribers | `wz-session-core/src/query.rs`, `session_tables.rs` | R4 |
| 7 | the query object and its dispatch to the queryable | 845 (`QueryPeer::dispatch_iteration_event` 305, `QueryableRow::ask` 230, `answer_query` 92, `Answering` entered and dropped 66 with a copy of 13, `FinalHolds` owed and admitted 62, `responder_for` 28, three host-lock holds 30, smaller 19) | 1,192 (`_z_trigger_queryables` 291 itself; the query's fields moved into a counted cell, `_z_string_move` 178, `_z_rc_init` 170, two `z_malloc` 102, `_z_value_move` 74, `_z_slice_move` 72, `_z_bytes_move` 29; the matching queryables' vector, `_z_svec_make` 78 and `_z_svec_append` 36; the session mutex 86; counts raised 43; smaller 33) | 150 | the query is a view of the Request where the read slot holds it (no `RoundQuery` copy); its responder is the face's send place and the request id, both known at the read; the final owed is a bit of the query's row, set when the call is entered and read when it returns, in place of `FinalHolds` | `wz-session-core/src/query.rs`, `query_plane.rs`, `wz-capi-coop/src/engine/query.rs` | Q-SERVE |
| 8 | callback entry | 263 (`queryable_sink_at::call` 163, `callback_table::enter` 53 and its drop 11, the probe's `on_query` 36) | 46 (the probe's `on_query` 36 and the query's accessors 10; the closure is called from the trigger, `vendor/zenoh-pico/src/session/queryable.c @ qle_info->_callback(&query, qle_info->_arg);`) | 50 | `ir-receive.md` stage 7: a direct call through the row's latch; the C query handed is the read's view, with no marshal; the in-callback mark is the read slot's owner word (architecture 8.5) | `wz-capi-pico/src/query.rs`, `ffi.rs` | Q-SERVE |
| 9 | the reply's key checked | 1,218 (the canon form of the given key, `crates/wz-capi-pico/src/query.rs @ if let Err(code) = crate::keyexpr::canon_key(ke) {`: `CanonWalk::next` 485, `Parts::byte` 134, `walk_canonical` 87, `is_canon` 44, the key's text and its UTF-8 check 93; then the reply's key against the query's, `reply_keyexpr_intersects` through `keyexpr_walk` 184, `keyexpr_chunk_intersects` 100, `relate` 26, `memcmp` 57), though the probe replies with the query's own key (`scripts/host-bench/op_probe.c @ if (z_query_reply(query, z_query_keyexpr(query), z_move(reply), NULL) == 0) {`) | 70 (`_z_keyexpr_intersects` 51, `_z_declared_keyexpr_alias_to_wire` 19; no canon check, `vendor/zenoh-pico/src/net/primitives.c @ if (!query->_anyke && !_z_declared_keyexpr_intersects(&query->_key, keyexpr)) {`) | 30 | a loaned key carries what was proven of it: the query's key is canon once read, and `z_query_keyexpr` lends it with that mark; `z_query_reply` walks nothing for a marked key, and a key whose text is the query's own covers it with no split; any other key is checked as now | `wz-capi-pico/src/query.rs`, `keyexpr.rs`, `wz-session-core/src/reply_acceptance.rs`, `keyexpr_canon.rs` | Q-SERVE |
| 10 | the payload and the reply staged | 830 (`z_query_reply` 139, `Onward::stage_reply` 86 with a copy of 30, `flush_one` 85, `CoopEngine::answer` 83, `send_reply_keyed_meta` 79, `QueryResponder::borrowing` 78, `Block::with_room` 57, `ByteBuf::copy_of` 36 with a copy of 13, `QueryMarshal::reply` 28, `z_bytes_copy_from_buf` 24, two host-lock holds 20, smaller 72) | 938 (the probe's `z_bytes_copy_from_buf` 582, a slice allocated and copied and a counted cell made; `_z_session_weak_upgrade_if_open` 98, `_z_send_reply` 93, `_z_n_msg_make_reply_ok_put` 64, `z_query_reply` 62, smaller 39) | 250 | the payload copied into a block of the payload pool (`heap.md`), one count; the reply written by the calling thread under the face's send place at once (architecture 8.5), from the query's view: no staging in `Onward`, no `flush_one` pass, the responder's look-ups (`borrowing`, `answer`, `live`) made once at the read | `wz-capi-pico/src/query.rs`, `bytes.rs`, `wz-capi-coop/src/engine/query.rs`, `wz-session-core/src/query.rs`, `reply_stage.rs` | Q-REPLY |
| 11 | the Response encoded, framed and sent | 2,183 (the Response's own writer 658: `ResponseWriter::write_direct` 143, `Window::vle` 118, `direct_len` 106, `send_reply_parts` 80, `ExtEntryWire` 75, `ResponseWriter::new` 51, `MsgDelParts::extensions` 36, `direct_bounds` 23; half of the frame and send bodies both messages pass, 1,302 of their 2,604: `dispatch_network_message_in` 328, `tx_slot_send` 228, `open_frame_lent` 226 through `dyn Fn`, `write_vle_u64` 226, the frame's admission 186, `TxLender::acquire` 170, `begin_frame` 150, `lend_frame` 132, `write_owed` 124, `wait_for_room` 114, `fill_lent_frame` 106, `emit_on_link` 100, the lease's append and acquire 182, the socket's write and `send` 128, and smaller; its copies 213, one host-lock hold 10) | 2,529 (`_z_send_n_msg` for the Response: `_z_response_encode` 1,573 through `_z_zint64_encode` and `_z_wbuf_write_bytes`, `_z_transport_tx_send_n_msg`'s batch, Frame and flush, the peers' recursive mutex and the transmit mutex) | 350 | S2's `write_response` (section 3) under the held send place, through `text.md` X1's one `TxBatch`: the SN and Frame header, the Response and Reply heads from the query's key form, the payload a gather piece (heap R1); no `dyn Fn` body writer, no sizing pass (`direct_len`, `direct_bounds`), the length prefix written in place | `wz-session-core/src/session_actions.rs` (send half), `lent_response.rs`, `tx_lease.rs`, `wz-runtime-coop/src/stream_link.rs`, `link_storage.rs` | S-WRITE (with `text.md` T-TX) |
| 12 | the ResponseFinal | 1,529 (its own 172: `send_response_final`'s writer 95, `FinalHolds::release` 61, `response_final` 16; the other half of the frame and send bodies of row 11, 1,302; its copies 45, one host-lock hold 10) | 1,330 (`_z_query_send_reply_final`: `_z_send_n_msg` 1,122 for a frame and a `send` of its own, the session's count raised and dropped 120, the rest 88) | 150 | D6: the Response is written into the face's `TxBatch` under a hold of the send place for the write alone; when the callback returns, the ResponseFinal is appended to the same batch (the final owed read from the query's row, row 7); the batch is flushed once when the read stage ends, so one `send` carries both and every other message the stage wrote to that face. No send window is open while the callback runs. A reply made after its callback returned (a query kept past it) is written and flushed at once, as now | `session_actions.rs`, `lent_control.rs`, `query_plane.rs`, `tx_buf.rs` | S-WRITE, Q-REPLY; lane t-tx (`text.md` X1) |
| 13 | cleanup | 130 (`process_pool::give_back` 66 and `Pools::counted` 30, the marshal's and the block's drops 24, one host-lock hold 10) | 1,459 (`_z_queryable_cache_data_clear` 479, the reply's payload and attachment dropped by `z_bytes_drop` 431, `_z_query_clear` 285 besides the final, `_z_rc_decrease_strong` 165, `z_free` 99) | 60 | nothing allocated per query, so nothing freed; the payload's block goes back by its count | as rows 7 and 10 | Q-REPLY |
| 14 | deadline upkeep | 139 (`Dues::earliest` 111, three times per query, the walk of every holder's get tables though this peer has no get pending; `PushDeadline::ask` 18; `HandshakeDeadlineTracker::poll` 10) | 0 (the lease task is a thread of its own) | 10 | the get deadline index of Q-DEADLINE, read in O(1); the timers own their deadlines (`ir-receive.md` section 3.3) | `wz-capi-coop/src/engine/registry.rs`, `wz-session-core/src/pending_get.rs` | Q-DEADLINE |
| 15 | the rest | 172 (bodies under 35 Ir each) | 46 | 50 | carried by the rows above | | |
| | **total** | **13,221**; **12,883** on the window harness | **10,011** attributable; **2,859** the biased line; **10,168** the window line | **1,880** | | | |

Of wz's excess over pico's attributable cost (3,210), the executor's pass and the round are 2,106
(row 2) and the reply key's canon check and intersection 1,218 (row 9): section 8 and Q-SERVE carry
both. Where wz already pays less than pico (rows 6, 7, 10, 11 and 13: no heap and no mutex per
query), the target is set from the structure all the same, so that the total clears the line and
not only the attributable cost.

**Rows whose target stays above pico's.** Three, by 4 to 10 Ir each, none of them closed by the
design: row 8 (50 against 46: the row's latch of architecture 8.5, so that an undeclare inside the
callback waits for no call of its own thread, which pico's direct call through the session's
queryable vector does not hold), row 14 (10 against 0: the heard mark the read leaves for the
lease timer, which pico's read task writes too, `peer->common._received = true;`, but whose lease
runs on its own thread) and row 15 (50 against 46). The total, 1,880, is 18 percent of pico's
window line, 10,168 (the biased line, 2,859, is no longer the gate); the margin against the
window line, about 8,300, is what a stage landing over its target spends before the verdict moves.
Today's 12,883 is over it by 2,715: rows 2 (2,106) and 9 (1,218) alone carry it under.

**What the total leans on.** Rows 1 to 3 and 14 are `ir-receive.md`'s and land with section 8's
steps 2 to 5: the shipped form builds `threads`, `listen` and `group`, so it reads through the
round until step 5 (architecture 8.11, Status). Rows 11 and 12 are the send side's (S2, X1); row
12's target holds only with the Response and its final in one batch, flushed once at the read
stage's end (D6).

### 4.3 Declare and retract (subscriber, publisher, queryable)

| stage | now | pico | target | structure | files | lane |
|---|---|---|---|---|---|---|
| ABI entry, closure, the key | *est.* 150-250 | *est.* 150-300 (the closure, the key loaned, the session's weak count) | 100 | unchanged shape | `crates/wz-capi-pico/src/pubsub.rs`, `query.rs` | D-ENTRY |
| the row | *est.* 200-400 (the id, the key form, the row in the slot map) | *est.* 800-1,200 (the counted cell, the list node, the sync group's notifiers: allocations and their initialisation) | 150 | S4: the row is a slot; the key form taken by reference to the key's own declaration | `crates/wz-session-core/src/session_tables` | D-ROW |
| the key's declaration | 0 (the probe's key is a view) | *est.* 0-600 (the non-wild prefix declared as a resource when the key has one) | 0 | unchanged | | |
| Declare (or Interest) encoded and handed to each face | *est.* 500-800 per face (`core.announce`, the general writer) | *est.* 600-900 | 300 per face | S2: `write_declare`; the faces written in one hold of each send place | `engine.rs` (`announce`), `session_actions.rs` | S-WRITE |
| work the declaration causes | *est.* 300-1,500 (`settle_faces`, `read_matching` over every write filter, `deliver`) | *est.* 100-300 (the local matching of its filters, where built) | 100 | S4: the filters whose key intersects are marked; matching is read again where a listener asks or a plan is made; `settle_faces` only on a face with an interest owed | `engine.rs` (`declare_*_on_wire`, `settle_faces`, `read_matching`) | D-AFTER |
| retraction: Undeclare, the row freed, the callback's drop waited for | *est.* 800-1,500 | *est.* 1,000-1,500 (the list walk by id, the Undeclare, the sync group's wait, the frees) | 500 | the row found by its id's slot index; the latch of section 8.5 | `engine.rs` (`undeclare_*`), `session_tables` | D-ROW |
| **total per declare and retract, nostd** (measured 2026-11-26, section 1) | **15,384** sub, **9,577** pub, **15,027** queryable; window harness 1.09, 0.85, 1.10 of pico's; on `decl-row` 0.88, 0.67, 0.89 | **14,121** sub, **11,280** pub, **13,638** queryable | **at most pico's** (the publisher's met; all three on `decl-row`, to be read on the window when it lands) | | | |

A publisher's declaration also sends its write filter's Interest and reads the peer's answer
(DeclareFinal) on the read task; both arms do, and the probe counts it on both.

### 4.4 Open and close (peer, one connect endpoint, TCP)

| stage | now | pico | target | structure | files | lane |
|---|---|---|---|---|---|---|
| configuration made and read | **measure** | *est.* 3-6 K (`z_config_default`, three inserts into a map of strings: allocations and copies; the locators read back into vectors) | at most pico's | the configuration a struct of typed fields filled by the inserts; the wz keys of the per-session counts (the heap ruling of 2026-11-26) read in the same pass and checked against the build's bounds | `crates/wz-capi-pico/src/session.rs`, `config.rs` | O-CONFIG |
| session's memory | **measure** (`RuntimeTables::of`, `placed_bytes`, `lend_session` from the arena plan) | *est.* 2-5 K (the session, the transport, its buffers: allocations and zeroing) | at most pico's | one plan computed from the configuration's counts, one carve of the arena; rows initialised lazily (a slot is written when taken, not at the open), so the open's cost does not grow with the counts | `engine.rs` (`assemble`, `lend_session`) | O-CARVE |
| dial and handshake | **measure** | **measure** (InitSyn, InitAck, OpenSyn, OpenAck; the cookie copied) | at most pico's | the handshake's messages written by S2's writers into the link's slot; the cookie held in place | `crates/wz-session-core/src/unicast_transport.rs`, `session_actions.rs` | O-LINK |
| tasks started | **measure** | *est.* two thread creations (read, lease) | no more threads than pico | section 8.2: one read task for the dial face and the timer's task; no port task without a listen endpoint; no task for a group not joined | `crates/wz-runtime-coop`, `engine.rs` (`open_links`) | O-TASKS (after section 8 step 4) |
| close: Close sent, reads stopped and joined, memory back | **measure** | *est.* the runtime stopped and joined, each table flushed and freed | at most pico's | close under the session's lock as section 8.5 says; the arena's carve given back whole, with no per-row free | `engine.rs` (`close`) | O-CLOSE |
| **total per open and close, nostd** (measured 2026-11-26, section 1) | **142,795**; 0.69 of pico's on the window harness | **173,336** | **at most pico's: met (0.69)**; a heap-lane arena from a reused `calloc` chunk read 1.37 (the memset of the whole arena, `heap.md` section 7), which the lane rss-zero takes back with fresh pages: measure, harness f5f8ce646 | | | |

## 5. The std heap form

The same structures hold; the form changes only where the memory comes from. In the std form:

- the payload pool is the heap's, and a payload's clone is still a count increment (an `Arc`-like
  counted block), never a copy;
- the per-session tables are sized at the open from the same configuration keys, as in the nostd
  form; no operation allocates (pico allocates in every get and declaration and in each stored
  reply);
- the locks are the host's mutexes (pico's are too).

Each row of section 4 is measured on both forms; a target met in one form and not the other is a
loss.

## 6. Lanes

| lane | owns | depends on |
|---|---|---|
| S-ENTRY | the payload's clone, move and drop at the ABI (`bytes.rs`, `pubsub.rs`) | the heap document's payload pool |
| S-PLAN | the publisher's send plan, its epoch per face, the put without the session lock, the 8.4 rule of section 3 | section 8 step 2 (the send place per face) |
| S-WRITE | one writer per message kind, the frame and length prefix in place, `tx_slot_send` reduced (`session_actions.rs`, `lent_push.rs`, `tx_lease.rs`, `stream_link.rs`) | none; S-PLAN, Q-HOLD and D-AFTER call its writers |
| S-GROUP | the group as a face of the plan (`engine/group.rs`, `fan_out_in`) | S-PLAN, section 8 step 3 |
| S-FANOUT | body once, header per face (`send_on_links`) | S-WRITE |
| Q-HOLD | the get's registration in one hold, the leg's slot and id (`get_on_wire`, `pending_get.rs`, `get_plane.rs`) | S-WRITE |
| Q-REPLY | the reply's dispatch by slot index, held replies in slots, the final (`reply_sink.rs`, `get_plane.rs`, `query.rs`) | section 8 step 5 (the round gone) |
| Q-SERVE | the Request served where it is read (section 4.2b rows 5 to 9): handed to the query plane by its kind, the query a view of the read slot, the callback through the row's latch, a loaned key's mark of canon form (`engine.rs` `FaceDispatch::event`, `engine/query.rs`, `wz-capi-pico/src/query.rs`, `keyexpr.rs`, `wz-session-core/src/reply_acceptance.rs`) | section 8 steps 2 to 5 (the round gone); S-WRITE for the reply's writers |
| Q-DEADLINE | the deadline index of the gets (`pending_get.rs`, `engine/registry.rs`) | none; the keep-alive deadlines are section 8's timer and `ir-receive.md`'s |
| D-ROW | the entity's row and its retraction | none |
| D-AFTER | the work a declaration causes, done when read (`settle_faces`, `read_matching`, `deliver`) | S-PLAN (a plan is where a matching is read) |
| O-CONFIG, O-CARVE, O-LINK, O-CLOSE | the open and close | the heap document's per-session counts |
| O-TASKS | the tasks an open starts | section 8 step 4 |
| t-tx (`text.md` T-TX) | D6: each face's `TxBatch`, the ResponseFinal appended to it, one flush per face at the read stage's end (`session_actions.rs` send half, `tx_buf.rs`, `lent_control.rs`) | S-WRITE's writers |

Order: S-WRITE and Q-DEADLINE first (no dependency, and every operation's writer is theirs); then
S-PLAN and Q-HOLD; then section 8's steps 2 to 5, and after them S-GROUP, Q-SERVE, Q-REPLY and O-TASKS;
S-FANOUT, D-AFTER and the open's lanes in any order after S-WRITE. Each lane lands with its tests
and its own opprofile run; a lane is judged by its rows of section 4.

## 7. Decisions for the owner

- **D1. One SN per face.** Pico, in peer mode, encodes a put once and writes it to every peer with
  one sequence number for all. Upstream zenoh keeps an SN per transport. Recommended: an SN per face
  (S3), which costs a Frame header per face past the first (about 40 instructions) against pico's
  shared one, and is the protocol's.
- **D2. A put without the session's lock.** It needs the rule of section 3 added to section 8.4:
  a face's key forms and up state change only under the face's send place. Recommended.
- **D3. Groups as faces of the plan** rather than the general path for every put of a session that
  joined a group. Recommended.
- **D4. Held replies of a get.** Consolidation `latest` holds each reply until the final; with no
  allocation per operation, the number a get can hold is a per-session count of the configuration
  (with the heap ruling's other counts), and a get past it is told as pico's failed allocation is.
  The default count goes into the preset contract.
- **D5. The verdict.** The opprofile line per operation, whole process, both forms, as the measure
  of this document; a stage column is a reading aid, not a verdict. A receiver's line (the
  queryable peer's) is its connected window net of an idle run (`f5f8ce646`).
- **D6** (decided 2026-11-26 under the owner's delegation). **A get's ResponseFinal goes into the
  face's `TxBatch`** where the Response is, and the batch is flushed once when the read stage
  ends, not inside the callback: no send window is held open while the application's code runs, so
  a callback that calls the session meets no held send place, and one `send` carries the Response,
  its final and whatever else the stage wrote to that face (section 4.2b row 12). The lane t-tx
  implements it.
- **D7** (decided 2026-11-26 under the owner's delegation). **No crate is a size boundary.** The
  open's cold code (O-CONFIG, O-CARVE, O-LINK, O-CLOSE) is one non-generic body over the plan's
  plain values at the root's level (`text.md` P5 and O1), so a size lane on the open moves no
  instruction of the operations here.

## 8. Cells to measure

By `bx --command pico-opprofile` (held alone on its machine), each for the nostd form and the std
form, each on both arms:

1. `none`: the paced loop alone (the base every other line is net of).
2. `put` at 8 bytes, and at 1 KiB (the payload's copy apart from the path).
3. `put` on a session that joined a group (the S-GROUP row).
4. `put` with two faces (the S-FANOUT row).
5. `get`, the querier's line and the queryable peer's line, the peer's in its connected window
   net of an idle run (section 1).
6. `declare-sub`, `declare-pub`, `declare-qbl`.
7. `open`.

For each, the inclusive costs of the functions named in the rows' "now" column, read from the same
callgrind files, fill the stage columns. Every cell is read with the window harness: measure,
harness f5f8ce646.

Read on 2026-11-26 for the nostd form (section 1, `scripts/pico-compare.sh opprofile`): cells 1,
2 at 8 bytes, 5, 6 and 7, and the stages of the queryable peer (section 4.2b). Read again on the window
harness (`f5f8ce646`) the same day: cells 2 at 8 bytes, 5, 6 and 7 as ratios (section 1). Still to
read: the std form of every cell, cell 2 at 1 KiB, cells 3 and 4, the stages of the queryable peer
in the window, the stages of every other row, `decl-row` and rss-zero on the window.

## 9. 보강 (reinforcement): zenoh-pico's put counted from its code

Status: design, 2026-11-26, written before the opprofile run of section 1. That run measured
zenoh-pico's put at 2,376.3 Ir net of the paced loop (2,531.1 before it is taken off) against the
1,420-1,780 this section counts from the code: the count misses 600 to 950, and the reading 9.4
asks for (`malloc`, `free`, the mutexes, the encoder, the link's send) is what places it. This
section counts what
zenoh-pico's put does, call by call, from the pinned source, so that section 4.1's target has a
stated ratio to pico's before the opprofile reads either. The probe's put
(`scripts/host-bench/op_probe.c`, `op_put`) clones a held payload of 8 bytes and moves the clone
into `z_publisher_put` with NULL options, on a peer session that dialled one peer. The unit costs
are section 1's; a stage's range is the sum of its calls at those costs, and every figure here is
*est.* until cell 2 reads it.

### 9.1 What pico does for one put

pico's build is the CMake default of `vendor/zenoh-pico/cmake/feature_config.cmake`: multi-thread,
batching on, the batch mutex options off
(`vendor/zenoh-pico/cmake/feature_config.cmake @ set(Z_FEATURE_BATCH_TX_MUTEX 0`), the session
check on (`vendor/zenoh-pico/cmake/feature_config.cmake @ set(Z_FEATURE_SESSION_CHECK 1`), local
subscribers off, and the congestion control of a default publisher is drop
(`vendor/zenoh-pico/include/zenoh-pico/api/constants.h @ Z_CONGESTION_CONTROL_DEFAULT = Z_CONGESTION_CONTROL_DROP`).

| # | stage | what pico's code does | calls that cost | est. Ir |
|---|---|---|---|---:|
| 1 | the probe's clone | `z_bytes_clone` copies the bytes' slice vector: `_z_svec_copy` allocates the vector's storage (`vendor/zenoh-pico/src/collections/vec.c @ dst->_val = z_malloc(element_size * src->_capacity);`) and calls the element copy for each slice, which raises the slice's counted cell | one `malloc`, one counted increment, three frames | 130-180 |
| 2 | entry and session check | `_z_publisher_put_impl` copies the default options, aliases the encoding, raises the session's strong count from its weak one (`vendor/zenoh-pico/src/collections/refcount.c @ if (_z_atomic_size_compare_exchange_weak(&c->_strong_cnt, &prev, prev + 1, _z_memory_order_acquire,`), checks the session is open and reads the write filter's state | a load and a compare-and-swap, about ten stores | 70-90 |
| 3 | the message built | `_z_write` makes the QoS, turns the declared key into its wire form (`_z_declared_keyexpr_alias_to_wire`: the declaration checked against the session) and fills a network message on the stack (`vendor/zenoh-pico/src/net/primitives.c @ _z_n_msg_make_push_put(&msg, &wireexpr, payload, encoding, qos, timestamp, attachment, reliability,`) | the message's fields stored, two frames | 80-120 |
| 4 | the locks | in peer mode `_z_send_n_msg` takes the peers' recursive mutex (`vendor/zenoh-pico/src/transport/common/tx.c @ _z_transport_peer_mutex_lock(ztc);`), then `_z_transport_tx_send_n_msg` tries the transmit mutex (`vendor/zenoh-pico/src/transport/common/tx.c @ ret = _z_transport_tx_mutex_lock(ztc, cong_ctrl == Z_CONGESTION_CONTROL_BLOCK);`), both released after the send | two lock and unlock pairs, one of them recursive | 400-460 |
| 5 | the batch and the Frame | `_z_transport_tx_send_n_msg_inner`: the batch is empty (batching is not started), so the write buffer is prepared with the stream's length place, an SN taken, a Frame header made and encoded through the generic transport encoder | about four `_z_wbuf_*` calls, six frames | 110-150 |
| 6 | the Push encoded | `_z_network_message_encode` -> `_z_push_encode` -> `_z_wireexpr_encode` and `_z_push_body_encode`, which tests the source info (a 16-byte id), the attachment, the timestamp and the encoding before writing the header, then `_z_bytes_encode`: the length and each slice through `_z_wbuf_write_bytes` (the 8 payload bytes copied) | about eight `_z_wbuf_*` calls, about twelve frames | 300-380 |
| 7 | flushed and sent | not express and not batching, so `_z_transport_tx_flush_buffer`: the stream's length written, then for each peer of the list `_z_link_send_wbuf`, a loop over the buffer's slices calling the link's write function, which calls `send` | one indirect call, the libc stub | 100-130 |
| 8 | cleanup | the session's strong count dropped, the encoding cleared, the attachment and the moved payload dropped: the slice's count lowered and the vector's storage freed | one `free` with `_int_free`, two counted decrements | 230-270 |
| | **total per put** | | | **1,420-1,780** |

Stages 1 and 8 (about 360-450) are the allocation pair of the clone and the drop; stage 4 (about
400-460) is the two mutex pairs; stages 5 and 6 (about 410-530) are the generic encoder writing
through one function call per field into a buffer of slices.

### 9.2 wz's target against it

| stage of section 4.1 | wz target | what removes pico's cost |
|---|---:|---|
| ABI entry, payload clone, move and drop | 80 | a payload is a counted block of the payload pool: the clone is one count increment, the drop one decrement; no allocator call (pico's stages 1 and 8) |
| session check and write filter | 40 | the publisher's send plan and one epoch load (S1) in place of a strong count raised and dropped and the filter's state read (pico's stage 2 and the count drop of 8) |
| lock of the face's send place | 60 nostd, about 205 with `threads` | one place per face, a flag where there are no threads and the host mutex where there are, against two mutex pairs (stage 4) |
| encode | 100 | S2's straight-line writer: a head of at most 16 bytes on the stack (length, Frame header, SN), the plan's Put head and the payload handed as pieces (heap 13.2 R1), no field-by-field encoder (stages 3, 5, 6) |
| hand to the link | 170 | one gather write (heap R1) of four pieces (stage 7) |
| local subscribers | 10 | the plan's flag |
| **total** | **460 nostd, about 605 with `threads`** | |

So the design target is about 26 to 32 percent of pico's put in the shipped nostd form and about
34 to 43 percent in the form with threads (the std heap form's locks are the host's, section 5).
Against the measured 2,376 the nostd target is 19 percent, and wz's put already reads under pico's
(2,195, 0.92, section 1). The verdict stays the measured opprofile line (D5): at most pico's. The
design margin, about three times, is what absorbs a stage that lands over its target before the verdict moves.

### 9.3 The cases beside the probe's

- **Each face past the first.** pico encodes once and sends the same buffer to each peer with one
  SN (stage 7 again: about 70-100 per peer). With an SN per face (D1) and the gather write, wz
  rewrites the stack head (SN and length, about 20) and makes one more gather write over the same
  plan head and payload pieces (about 70-90): about 90-110 per face, not section 4.1's 220, which
  counted a re-encode and a slot per face. At pico's most connections (10,
  `vendor/zenoh-pico/include/zenoh-pico/config.h.in @ #define Z_LISTEN_MAX_CONNECTION_NB 10`): wz
  about 460 + 9 x 100 = 1,360 against pico's about 1,600 + 9 x 85 = 2,365.
- **A put larger than a batch.** pico makes an expandable buffer for the whole message, encodes the
  message into it and then copies each fragment into the batch
  (`vendor/zenoh-pico/src/transport/common/tx.c @ _z_wbuf_t frag_buff = _z_wbuf_make(_Z_FRAG_BUFF_BASE_SIZE, true);`):
  an allocation and two copies of the payload. wz gathers each fragment's head and a slice of the
  payload block: no allocation and no copy of the payload.
- **A put of 1 KiB at the batch of 1,024 (heap D4).** The message no longer fits one batch and is
  sent as two fragments, where pico, at its batch of 2,048, sends one. wz pays one more fragment
  head and one more gather write (about 150): about 610 nostd against pico's about 1,500-1,850 (its
  stage 6 copies 1 KiB). Cell 2's 1 KiB line reads it; the heap and Ir trade of 9.4 of the
  architecture document is this line.

### 9.4 What this changes in the tables and lanes

Section 4.1's "pico" column takes 9.1's stages (1 and 8 in the first row, 2 in the second, 4 in
the third, 3, 5 and 6 in the fourth, 7 in the fifth); its "each face past the first" target becomes
110, and S-FANOUT is written over the gather write of heap R1, which S-WRITE carries. Cell 2 of
section 8 reads, besides the per-operation line, the inclusive cost of `malloc`, `free`,
`pthread_mutex_lock`, `pthread_mutex_trylock`, `pthread_mutex_unlock`, `_z_network_message_encode`
and `_z_link_send_wbuf` on the pico arm, so that 9.1's stages are checked, not only its total.

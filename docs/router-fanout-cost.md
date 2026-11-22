# The cost of a router fan-out, per subscriber

What one Put that arrives on one face and leaves on N subscriber faces costs the wz router preset,
read from the code, set beside what upstream's router does with the same Put at the pinned version,
and ordered by what removing each cost is expected to give. The first reading of the AP superiority
matrix (decision D13, `docs/ap-superiority-matrix.md`) is the reason; section 5 names what has
been changed for each row since.

## 1. What was measured

The first D13 reading, one host, the wz router against zenohd at `UPSTREAM_VERSION`, the same
upstream client programs on both arms (`z_pub_thr` publishes with congestion control `Block`,
`examples/examples/z_pub_thr.rs` @ `.congestion_control(CongestionControl::Block)`, so every Put it
sends is one the router may not drop):

| Cell | wz over upstream |
|---|---|
| fan-out to 16 subscribers, throughput | 32.8 times worse |
| fan-out to 16 subscribers, CPU per message | 20.7 times |
| fan-out to 1 subscriber, throughput | 3.3 times worse |
| router, 8 B throughput | 3.2 times worse |
| multi-hop | 3.9 times worse |
| core scaling, 1 / 2 / 4 / 8 cores | 5.3 / 2.7 / 1.45 / 1.23 times worse |
| heap peak | 3.0 times |

Two things are read off the table. The gap grows with the subscribers (3.3 at one, 32.8 at sixteen),
so most of it is paid once per subscriber, not once per Put. And it shrinks with cores, so it is a
cost each message pays on a core, not a lock that serializes the cores.

The one exact figure the tree already records for this path is the allocation budget of the
uncongested forward, `crates/wz-runtime-tokio/tests/router_hot_path_cost.rs:263`: a blocking Put to
one subscriber cost 10 allocations and 602 bytes, to sixteen 85 allocations and 7,262 bytes. Each
subscriber past the first added 5 allocations and 444 bytes (4 and 378 for a droppable Put). Upstream
allocates nothing per destination on the same path (section 3).

## 2. The path in wz

A Put from a client face to client subscribers, with the line each step is at:

Once per Put, before the change of row 4 (section 5):

- The face's thread takes the tables for the message (`crates/wz-runtime-tokio/src/router_forward.rs:14991`,
  inside the loop over the frame's messages).
- The key is resolved to an owned `String` (`resolve_inbound_keyexpr`,
  `crates/wz-runtime-tokio/src/router_forward.rs:9274`) and the forward stamp is taken
  (`crates/wz-runtime-tokio/src/router_forward.rs:8878`).
- The client leg's route is read from the memo by that key (`client_leg`,
  `crates/wz-runtime-tokio/src/router_forward.rs:6481`): a hash of the key text, and an `Arc` of
  the held faces. A hit cost 59 to 834 ns in the readings of `docs/router-table-snapshots.md`
  section 6.9.
- The carrier is made: the Put re-keyed to a literal and its routing source reset (`client_carrier`,
  `crates/wz-runtime-tokio/src/router_forward.rs:1962`; `reliteralize_push`,
  `crates/wz-session-core/src/push_build.rs:263`), a deep copy of the message.

Once per subscriber, before this round's change (`deliver_to_client_subscribers`,
`crates/wz-runtime-tokio/src/router_forward.rs:9556`):

- The carrier was copied for the face (`carrier.clone()`: the key text and the extension list are
  heap containers, the payload a shared range) and boxed into a `NetworkMessage`
  (`crates/wz-runtime-tokio/src/router_forward/held_route.rs:90`; the box is 312 bytes on a 64-bit
  host, `crates/wz-session-core/src/rx_profile.rs:294`).
- The egress chain's lock was read (`admit_outbound`,
  `crates/wz-runtime-tokio/src/router_forward.rs:6158`), the held queue's mutex taken and the chain
  mark read with `SeqCst` (`crates/wz-runtime-tokio/src/router_forward/egress.rs:340`).
- The session measured the message by walking it (`push_capacity_hint`,
  `crates/wz-session-core/src/frame_encode.rs:374`), read its QoS, took its conduit's lock
  (`crates/wz-session-core/src/session_actions.rs:11288`), and encoded it by walking it again
  (`push_body`, `crates/wz-session-core/src/frame_encode.rs:345`).
- The session told the link a frame was staged (`crates/wz-session-core/src/session_actions.rs:11322`,
  `wake_for_flush` at `crates/wz-runtime-tokio/src/writer_queue.rs:2036`). On a TCP link a sender may
  write the frame itself (`crates/wz-runtime-tokio/src/link_pipeline.rs:837`): `flush_inline`
  (`crates/wz-runtime-tokio/src/writer_queue.rs:2075`) writes on the sender's thread when at most
  `LONE_STAGED_MAX` (2) messages were staged since the last flush and none ran for
  `INLINE_MIN_QUIET_NS` (8 us, `crates/wz-runtime-tokio/src/writer_queue.rs:730`). A router's face
  no longer does (section 5, row 1).
- The copy, its box and its containers were freed once the frame was built.

## 3. The path upstream

- The data path takes the tables' read lock once (`zenoh/src/net/routing/dispatcher/pubsub.rs` @
  `let rtables = zread!(tables_ref.tables);`) and finds the key by its mapping id
  (`zenoh/src/net/routing/dispatcher/pubsub.rs` @
  `.get_mapping(src_face, &msg.wire_expr.scope, msg.wire_expr.mapping)`), with no text resolved.
- The route is an `Arc` kept on the resource and recomputed only when the routes' version moves
  (`zenoh/src/net/routing/dispatcher/pubsub.rs` @ `fn get_data_route(`,
  `zenoh/src/net/routing/dispatcher/resource.rs` @ `pub(crate) fn get_or_set_route<T: Clone>(`).
  Each direction of a route holds the face's state and the key expression to send it
  (`zenoh/src/net/routing/dispatcher/resource.rs` @ `pub(crate) dst_face: Arc<FaceState>,`,
  `zenoh/src/net/routing/dispatcher/resource.rs` @ `pub(crate) wire_expr: WireExpr<'static>,`),
  chosen per face (`zenoh/src/net/routing/dispatcher/resource.rs` @
  `pub fn get_best_key<'a>(&self, suffix: &'a str, sid: usize) -> WireExpr<'a> {`).
- Per destination it builds a `Push` on the stack from the direction's key expression and a clone of
  the payload, which is a reference count (`zenoh/src/net/routing/dispatcher/pubsub.rs` @
  `let mut push = Push {`, `zenoh/src/net/routing/dispatcher/pubsub.rs` @
  `payload: msg.payload.clone(),`). Nothing is allocated for the destination.
- The face's transport encodes the message straight into its current batch under the stage's one
  lock (`io/zenoh-transport/src/common/pipeline.rs` @ `let mut c_guard = zlock!(self.mutex.current);`,
  `io/zenoh-transport/src/common/pipeline.rs` @ `let e = match batch.encode(msg) {`). So upstream
  encodes once per face too; what it does not do is copy, box and measure the message first.
- The producer never writes to the link. It notifies the link's own TX task, and only while that task
  is not backing off (`io/zenoh-transport/src/common/pipeline.rs` @
  `if !self.atomic_backoff.active.load(Ordering::Relaxed) {`); the task keeps backing off while the
  batch still grows (`io/zenoh-transport/src/common/pipeline.rs` @ `fn try_pull_deep(&mut self) -> Pull {`).
  A fan-out to N faces therefore costs the routing thread N encodes into memory, and the N writes
  happen on the faces' own tasks, many messages to a write. Batches are reused through a refill ring
  (`io/zenoh-transport/src/common/pipeline.rs` @ `struct StageOutRefill {`).

## 4. The costs, ordered by expected gain

The shares are estimates read from the code and the allocation record; no profile of the D13 run was
taken in this round. Each row says how to confirm it.

| # | Cost, per subscriber unless said | Evidence | Upstream | Estimated share of the fan-out gap | Textbook fix |
|---|---|---|---|---|---|
| 1 | The routing thread writes each subscriber's frame to its socket itself. Once one Put takes the routing thread longer than 8 us, every subscriber's link has been quiet that long by the next Put, so each Put to each subscriber is a write system call on the one thread, with no batch | `flush_inline` and its thresholds (section 2); the TCP link installs the inline write (`crates/wz-runtime-tokio/src/link_pipeline.rs:837`) | the producer only notifies; the face's task writes, in batches | largest, if confirmed: a write call costs microseconds where upstream's per-face cost is an encode into memory; the feedback (slower Put, more inline writes) fits a gap that grows with N | the routing thread never does a destination's I/O: a send made on behalf of a fan-out stages and wakes, and the inline write is kept for a sender's own lone message. **Done** (section 5): a router marks the link of every face it holds as its writer's alone, by the node's role and not by a timing threshold. The gain is to be read off the D13 cells and a count of write calls per thread on the router (`perf trace -s`) against Puts routed |
| 2 | The carrier was copied, boxed, measured and encoded for every subscriber: 4 of the 5 allocations and 400 of the 444 bytes a subscriber added (measured after the change, section 5), two walks of the message | `crates/wz-runtime-tokio/tests/router_hot_path_cost.rs:263`; the steps of section 2 | a stack `Push` and a reference count | second; all of the per-subscriber allocation a forward made but one | encode once, share the bytes: **done in this round** for a Put the credit stage sends (section 5) |
| 3 | Locks and atomics per subscriber: the egress chain's read lock, the held queue's mutex, the chain mark (`SeqCst`), the conduit's mutex, the staged counter and the flush flag | section 2 | the stage's one mutex and one notify | small to moderate; each is uncontended, and cache lines move between the routing thread and the writers | read the egress chain once per fan-out; read the held queue's emptiness from an atomic beside it; `Acquire` where no total order is read |
| 4 | Per Put, not per subscriber: the tables taken per message rather than per frame, the key resolved to an owned `String`, the carrier deep-copied, the memo read by hashing key text | section 2; 5 of the 10 allocations of a forward to one subscriber | one read lock, a mapping-id lookup, a cached `Arc` route | most of the 1-subscriber and 8 B gap (3.3 and 3.2 times), little of the 16-subscriber one | take the tables once per frame; key the client memo by the inbound face's mapping id; forward a literal Put's received bytes when nothing in it changes. **Done** (section 5), but for an aliased Put's carrier, which is still a copy re-keyed once a fan-out |
| 5 | A frame buffer allocated per frame on a path that lends no slot (the immediate path, `crates/wz-session-core/src/session_actions.rs:11059` for the staged one) | the fifth per-subscriber allocation of the record | batches reused through a refill ring | small; zero where the link lends slots (`transport-tx-lend`) | a pool of batch buffers per link, which the lending links already have: confirm the router's links take that path under fan-out |
| 6 | Every delivered Put names its key as text, re-literalized for the client leaf | `client_carrier` (section 2) | the direction's key expression, chosen per face | small; at an 8 B payload the key text is a large part of the message, so fewer messages fit a batch | confirm by a capture of both arms what upstream sends to a client subscriber; if it is an id, declare the key to the face once and send by id |

Not found: no per-Put copy of the tables (the version is shared, `docs/router-table-snapshots.md`),
no per-Put route computation (the memo is hit), and no per-face task spawned per Put.

## 5. What was changed

### Row 1: the routing thread does no destination's I/O

The rule is now structural. A link's outbound queue can be marked as its writer's alone
(`OutboundTx::set_writer_only`, `crates/wz-runtime-tokio/src/writer_queue.rs`); on a marked queue a
sender never writes its own lone message (`flush_inline`) nor a datagram as it lands
(`write_landed_datagram`), whatever the timing: it stages, and wakes the writer, which takes what
was staged for the face in a few writes. The session asks its link for the mark through
`BoxedLinkDriver::tx_writer_only` (`crates/wz-session-core/src/link.rs`), which the stream driver
(TCP and the links built on it), the UDP driver and the QUIC stream driver forward to their queue,
and the two swap seams of a reconnecting session forward to the live link and to every link swapped
in after.

The router asks for it once per face, when it holds the face (`hold_face_link` in
`crates/wz-runtime-tokio/src/router_forward.rs`, called from the forwarder's registration of a face
and of a joined link), and only on a node whose role is router. A peer node and a client node keep
the sender's own write, which is what the round trip of their own lone puts was measured with. A
keepalive is still written from the thread that sends it on every node: it carries liveness and no
data. Not covered: the router's multicast group egress, which writes once per group and not once
per subscriber.

The tests: `a_router_fan_out_is_written_by_the_faces_writers_and_not_by_the_routing_thread` and
`only_a_router_takes_the_senders_own_write_from_the_faces_it_holds` in
`crates/wz-runtime-tokio/src/router_forward/fanout_io_tests.rs`. The first routes a burst of 64
blocking Puts to 16 client faces over the production stream driver and queue, and asserts that the
routing thread was asked for no write, that every face was written on its writer's thread, and that
each face took at most one write for eight Puts. No throughput figure of the D13 cells was taken
after the change.

### Row 2: the carrier encoded once

A fan-out to the client faces makes one carrier (`SharedCarrier`,
`crates/wz-runtime-tokio/src/router_forward/held_route.rs:104`) and encodes it at most once, on the
first face that is sent its bytes (`EncodedPush`, `crates/wz-session-core/src/session_actions.rs:3230`).
Each such face's session frames those bytes under its own sequence number
(`try_send_encoded_push_qos`, `crates/wz-session-core/src/session_actions.rs:12535`), through the
same dispatch, congestion decision and batching as before. The message is made of the carrier only
when the face must hold it, send it as a chain with a wait, or map shared memory for it.

A face is sent the shared bytes only when it would be sent exactly those bytes and the Put goes
through the credit stage (`egress_held_shared` and `sends_shared`,
`crates/wz-runtime-tokio/src/router_forward.rs:6732`): the Put is reliable and may not be dropped,
it is sent on behalf of a face that can be gated, it carries no shared memory, no egress interceptor
is installed (one reads the message, and a QoS rule rewrites it for one destination), and the build
does not record its routing on each message (`pubsub-ts-stack`). Every other face is sent a copy
through the egress it had. A droppable Put keeps the copy per face; giving it the shared bytes needs
a waiting send of encoded bytes beside the probe, and is the next step of this row.

The count of carriers encoded is `RouterForwarder::client_carrier_encodes`; the tests that hold it
are `a_fan_out_to_many_clients_encodes_its_carrier_once` and
`a_fan_out_outside_the_credit_stage_encodes_no_shared_carrier` in
`crates/wz-runtime-tokio/src/router_forward.rs`.

What the change measured, in the allocation budget of the uncongested forward
(`crates/wz-runtime-tokio/tests/router_hot_path_cost.rs:263`, a build without `time-hlc`):

| Case | Before: allocations, bytes a forward | After | Per subscriber past the first, before; after |
|---|---|---|---|
| blocking Put, 1 subscriber | 10, 602 | 7, 233 | |
| blocking Put, 16 subscribers | 85, 7,262 | 22, 893 | 5 and 444 B; 1 and 44 B |
| droppable Put, 1 and 16 subscribers | 8, 472; 68, 6,142 | unchanged | 4 and 378 B; unchanged (row 2's next step) |

A blocking forward to sixteen subscribers allocates 74 % fewer times and asks for 88 % fewer bytes.
The one allocation a subscriber still costs is its frame (row 5); the one a fan-out adds is the shared
encoding. The `time-hlc` record is measured on its own and is not written here. No throughput figure
of the D13 cells was taken after the change; that is the next run of `ap_matrix.py`.

### Row 4: the costs paid once a Put

Four changes, each its own commit with the count that holds it.

- **The tables once for a run of a frame's messages.** A face's frame takes the tables for reading
  once for a run of consecutive reading messages (Puts, queries, replies), up to
  `TABLE_READS_PER_GUARD` (64) of them (`ReadRun` in `forward_frame`,
  `crates/wz-runtime-tokio/src/router_forward.rs`), as it already did for a run of declarations. A
  message that writes ends the run, and so does a message whose route owes the node's own session
  a call (a subscriber or a queryable the node hosts): the call is made before the next message is
  routed, as it was when each message took the tables alone. The count is
  `RouterForwarder::frame_table_reads`; the tests are the four at the end of
  `crates/wz-runtime-tokio/src/router_forward/table_sharing_tests.rs`.
- **The key lent, not copied.** The key of a literal Put is its own suffix and the key of a Put that
  names an alias with no suffix is the face's alias: both are lent to the route, and only an alias
  with a suffix is composed (`lent_keyexpr`). The within-tier leg takes the key the route head
  resolved instead of resolving it again. The test is
  `a_puts_key_is_lent_unless_a_suffix_must_be_composed`.
- **A literal Put fanned out as it came.** A literal Put that names no routing source is already
  what a client is sent (`client_carrier`), so the fan-out lends it (`LiteralPush::lent`,
  `crates/wz-runtime-tokio/src/router_forward/held_route.rs`) and a face that must be sent a
  message of its own is sent a copy, as before. Whether a Put names a source, of any value, is
  `push_names_a_source` (`crates/wz-session-core/src/push_routing_context.rs`). The count is
  `RouterForwarder::client_carrier_copies`; the tests are
  `a_literal_put_is_fanned_out_without_a_copy_and_an_aliased_one_with_one` and
  `the_client_leg_carries_a_literal_whatever_the_put_named`.
- **The client legs of an aliased Put kept on its face.** A Put that names an alias of its face with
  no suffix finds the client legs of its route by the face and the alias id (`AliasRoutes` in
  `held_route.rs`, `client_leg_for` in `router_forward.rs`), not by the hash of its key in the
  memo all faces share. A leg is served only while the tables hold the memo it was read from and
  that memo is at their inputs, so every change that moves a leg (a subscriber declared or
  withdrawn, a face that leaves) has it read again, and the face is given empty legs whenever its
  aliases change. The tests are `an_aliased_put_is_routed_by_the_leg_its_face_keeps_for_the_alias`
  and `an_alias_leg_is_served_only_with_the_memo_it_was_read_from`.

Not done in this round:

- An aliased Put's carrier is still a copy, re-keyed to a literal, once a fan-out. Re-keying only
  the encoded key needs the shared send to take what it reads of the Push apart from a message:
  `try_send_encoded_push_qos` reads the Push it is sent for (its congestion control, and the
  statistics class, which resolves its key by the session's own mappings). That is also the case of
  row 6, a face whose mapping wants another key form.
- The bytes a fan-out shares are encoded once from the lent message, not taken from the frame it
  arrived in: a decoded message keeps no span of the wire.
- A literal Put's client legs are still found by the hash of its key in the memo all faces share.

What the allocation budget of the uncongested forward should show
(`crates/wz-runtime-tokio/tests/router_hot_path_cost.rs`, a literal Put of `demo/x` from a client,
one Put a frame), not yet measured: every case of both records falls by the same amount a forward,
since what was removed is paid once a Put. The key's `String` (one allocation, 6 bytes) and the
carrier's copy (the allocations a `PushOwned` clone makes, its key text among them) go. Taking the tables once a frame and the legs kept for an
alias move none of the four cases, which send one literal Put a frame.


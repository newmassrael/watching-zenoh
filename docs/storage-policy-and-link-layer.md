# One code path, a storage policy, one link layer

Status: design note. It states what is built, what is measured, what is decided
and what is still open; it is not a specification and the atomic store does not
parse it. Decisions here follow the standing criterion of this tree (the
long-term correct design, cost not counted); the reason for each is next to it.
It continues `no-heap-multi-session.md`, whose D5 is the pattern step 1 follows.

## 1. The question

Whether a node holds an allocator is today a property of WHICH CODE it runs, not
of a setting. The heap profile and the fixed-memory profile are two sets of
types with two sets of algorithms around them, and a third dimension (the
network stack) multiplies them again. The question is what the shape is so that
heap or no heap is a choice made in the deploy and the build configuration,
with the same code, the same tests and the same proofs on both sides.

## 2. What is built, and what it costs

- **Two paths where one is meant.** A query reply leaves a heap build through
  `dispatch_response` (`session_actions.rs`, `alloc`) as a `QueryReply`, a
  builder, a `ResponseOwned` and a worst-case-sized frame buffer; it leaves a
  fixed build through `send_reply_parts` (`not(alloc)`) as `ReplyParts` written
  into the link's lent slot (`lent_response::ResponseWriter`). The second is the
  shape of the first without its copies.
- **Two node shells per role.** `AdminNode` (heap), `SlotAdminNode` (fixed,
  lwIP), `ClientNode` (heap). The fixed client does not exist; the Kconfig symbol
  `WZ_FIXED_MEMORY` depends on the lwIP backend and the admin role.
- **A host per stack.** `wz_session_lwip::session_host::SessionHost` names
  `LwipUdpDriver`, `LwipSessionLink` and `LwipLinks`; its module says another
  stack "brings its own host and its own copy of the wiring". The Zephyr socket
  stack therefore has no fixed-memory session at all, and a second host would be
  the second copy of a 200-line piece that decides.
- **Storage as a type already, in one place.** The codecs are generic over
  `S: CodecStorage` (`Heap`, `Inline`), and `WireStorage` (`network_message.rs`)
  is the one alias that chooses. Nothing above the codecs follows that example.
- **Measured on the T2G kit (2026-10-21), a UDP client answering a GET against
  zenoh-pico in the same configuration.** A heap-profile query makes 8 `malloc`
  and 4 `free` calls (2,914 B); the key (34 B) and the payload (63 B) are each
  copied three times, and a 2,480 B frame buffer is taken per reply. The
  heap's peak is 11,220 B against 9,416 B for pico, and the minimum kernel-heap
  pool the image runs in is 11,776 B against 9,728 B. After the copy and
  allocation work of that day the wire turnaround of the wz image was 0.215 ms
  against 0.214 ms for pico (12 boots of each in one session, ranges
  overlapping: the same, not faster); the heap and the stack (13.6 KB of the
  main thread against 2.9 KB) are what remains on the RAM side, and the code is
  1.36 times pico's. These are measurements of one board and one
  configuration, not a general claim.

## 3. Decisions

**D1. Storage is a type parameter of the session shell, not a feature that
selects code.** A container the shell holds (sessions, tasks, pump cells, the
queryable table, receive buffers, pending replies) is parameterised by a policy
with two members: growable (the allocator) and static (a capacity fixed in the
type). Heap or no heap is then the instantiation, the algorithm exists once, its
tests run on both, and "links no allocator" is a consequence the existing
no-allocator link gate proves, not a property of a second code base. Rejected:
keeping two profiles and testing the second with copies of the first's tests
(they drift, as the two forwarders of the router did). Rejected: choosing at
run time (the bound must be in the type for the image's size to be a compile-time
number). The codecs' `CodecStorage` is the precedent and the first scope of
this decision is the pieces `SessionHost` already holds (`SessionSlots`,
`PumpSlots`, the task table); the registries and the reply staging follow.

**D2. The session host is written once, over the stack's driver and pump link.**
`SessionHost` becomes generic over the driver type that lives in the session
slot and over the pump link built from the slot's driver handle, and lives in
`wz-session-mcu` beside the group pump (the pattern of D5 in
`no-heap-multi-session.md`). The lwIP crate keeps its names by thin aliases and
delegates, and every existing lwIP test is unchanged and green. A stack then
supplies three small things: a driver (send, and the datagram it holds), a pump
link (`SessionDatagramLink`: service, and the lend of the next datagram), and
how it opens a socket. Rejected: a Zephyr copy of the host (the state the lwIP
module describes; one more copy for every stack added).

**D3. A reply is written into the link's lent slot on every profile.** The
fixed build's `ReplyParts` to `ResponseWriter` path becomes the path of the heap
build too, and the `QueryReply` to `ResponseOwned` staging is kept only as long
as a caller outside the MCU profiles needs the owned form. The owned encode
(`{Codec}Owned::encode`) and the lent writer are the same idea at two scopes:
write the wire bytes from the fields, never build an intermediate record. The
gain is not asserted here: the copies and allocations it removes are counted in
section 2, and the step that makes the change measures the turnaround before and
after with the same method.

**D4. A role is a composition, declared once.** A client, an admin node and a
router are sets of capabilities (listens, dials a static endpoint list, hosts
the admin space, accepts a config write). The deploy file states the set and the
capacities (sessions, queryables, buffer sizes); the Kconfig dependencies, the
cargo features and the static table sizes are generated from it, with the
`const` assertions the fixed node already makes (`fixed_node.rs`: sessions,
tasks, timers, one slot's bytes). A symbol that says `WZ_FIXED_MEMORY` depends
on one backend and one role is the sign this is not so yet.

**D5. Resource claims are judged by gates, not stated.** No allocator: the
no-allocator link gate (built). Stack depth and worst-case turnaround: not
built; the cycle-counter stamps, the window-gated profile and the resource
report (`CONFIG_WZ_ZETH_STAMPS_RESOURCES`) of the comparison are the instrument,
and the decision here is that they become a gate with a committed figure per
image, so a change that moves one is a visible, recorded change.

## 4. Steps

1. **Stack-neutral session host.** D2: generic `SessionHost` in
   `wz-session-mcu`, lwIP delegates, no new behaviour. Done when the lwIP
   crate's tests and the Layer Q fixed-memory builds are green unchanged.
2. **An allocator-free Zephyr socket driver and link.** The receive buffer is
   an inline array chosen by a const parameter and the link's two locator texts
   are fixed text; `wz-runtime-zephyr` builds with `alloc` off for the socket
   tier. Done when an image of the tier links with no allocator in the gate's
   sense.
3. **The fixed client node.** `ClientNode` over the static policy: the
   endpoints are the static list, the queryables are closed types that answer
   the two documents, the sessions and tasks are the host's tables. Done when the
   image boots on the kit, a GET probe of 2000 requests has no bad answer, and
   the heap the Rust image links is none.
4. **The Kconfig switch.** `WZ_FIXED_MEMORY` is available to the Zephyr-socket
   backend and the client role, CMake selects the cargo feature from role and
   backend, and the table of images has the rows. Done when both memory settings
   build from one tree with the same sources.
5. **The reply path of D3 on the heap profile,** measured by the same
   alternating-image method before and after.
6. **Storage policy through the rest of the shell** (D1), registry by
   registry, each step with the fill-to-N and refuse-at-N+1 tests the earlier
   steps of the fixed-memory work already use.
7. **Deploy to configuration** (D4) and **the stack and turnaround gates** (D5).

## 5. Status

Steps 1 to 5 are done and run on the T2G kit (the Zephyr-sockets client,
`CONFIG_WZ_FIXED_MEMORY` with `overlays/t2g_client_fixed.conf`; step 5 is the
heap client with `overlays/t2g_client.conf`). What each step turned out to need
beyond its plan:

- **Step 2** needed the driver to lend a transmit slot. A session on the
  lend-only profile (`session-slot` implies `tx-lend-only`) builds no frame
  unless its link lends one, and a link with only `send_blocking` sends nothing,
  without an error. `UdpDriver` now carries a `TxStore`.
- **The link's buffers are claimed, not owned.** A driver that holds its receive
  and frame buffers by value is a 3 KB value that a dial moves three times; the
  stack of the node grew with the buffers. `ByteCells` (a static table) and
  `ByteBuf` (a claim) make the driver a few words.
- **Sizes are limits an image states.** Every capacity of `caps.rs` is
  `limit(option_env!("WZ_LIMIT_<NAME>"), default)`, declared in
  `deploy/wz-config.toml`; `deploy/Kconfig.limits` and the value module are
  generated from it (`scripts/lib/wz_config.py --check`) and the Zephyr
  build turns each `CONFIG_WZ_LIMIT_*` into the environment of the cargo build.
  The client states sixteen; its session tables went from 34 KB to 2 KB.
- **Cold paths are out of line.** `SlotDialer::dial`, the connection manager's
  `reconcile` and `dispatch_copied` (a handshake's decode) are kept out of the
  frames of the loop and of the receive path.
- **Step 4**: `runtime-coop-core` in the facade is the runtime tier without
  lwIP's link crate, so a sockets image has none in its graph.
- **Step 5**: an answered query on the heap client went from 6 allocations
  (2,816 B) to none. The staged reply is drained by parts into the response
  writer, and the frame is written into a slot the link lends: `HeapTx` holds
  two (a session that batches keeps one open while it encodes into the other).
  Two things the plan did not name: `wz/transport-tx-lend` only forwards to the
  lwIP crate, so the client node selects `wz-session-core/transport-tx-lend`
  itself; and the heap client needs the role's limits too, because with the
  default capacities the arena tables overflowed the main stack. A gated or
  counted egress (`transport-stats`, an egress reply gate, a namespace) still
  takes the owned reply, as the parts writer does not apply them.

- **Step 6** (registries): the queryable table, the reply staging, the subscriber
  and declaration tables (subscribers, remote subscribers, remote queryables,
  peer tokens, local tokens), the peer tables of a session, the requester's
  pending-query table and the pending liveliness gets are generic over the
  policy, with the build's profile as the default so existing names mean the
  same thing. Where the two policies differ in representation (a hash map of
  aliases against a linear table) the policy picks it through an associated type
  (`Ids`, `Epoch`, `peer_space`); no registry matches on the policy. One body of
  each fill-to-N and refuse-at-N+1 test runs on `Static` and on `Heap` in one
  build (`tests/storage_policy_tables.rs`, `query.rs`), and a mutation of the
  refusal count fails the static case only. Left on the profile on purpose:
  scratch buffers on the stack (`MAX_KEYEXPR_CHUNKS` views), the observer's own
  staging, and the matching watches (a watch owns a `String`, so it needs the
  allocator by its nature).
  Image sizes against origin/main, built the same way on the kit: the fixed
  client is +232 B in text (155,112 B to 155,344 B), the heap client is +132 B
  (221,244 B to 221,376 B), data and bss are identical in both. The growth is
  not new logic: in the fixed image `resolve_declared_keyexpr_view` is a 288 B
  function of its own where the baseline inlined it. It is not explained further
  and not removed.

Measured on the kit with the same method for each image (wire turnaround,
alternating order, 12 boots each): fixed client 0.203 ms, heap client before
step 5 0.215 ms, heap client after step 5 0.210 ms, zenoh-pico 0.213 ms (the
ranges of the heap client and of zenoh-pico overlap; no ordering between them
is claimed). The step 5 image is 52 bytes larger in text (221,248 B) and the
same in data and bss. Against a zenoh-pico built in its smallest working
configuration: text 155 KB against 162 KB, data and bss 118 KB against 114 KB.
Main stack peak was 9.8 KB of 16 KB; splitting the observer's planes into
frames of their own did not move it, so what sets it is not the part that was
split. What did: the handshake parse (`parse_unit`) out of line, so its
temporaries leave with it (`dispatch_copied` frame 4,824 to 2,408 B), peak
9,856 to 8,432 B, text 155,344 to 155,004 B. Taking each handshake arm
(`Init`, `Open`, `Close`) out of `parse_unit` into a function of its own took
the peak to 7,828 B (text 155,256 B). Building the pump in its cell
(`SessionPump::build_in`, no copy of it or of the engine on the dial's stack)
took the dial path from 8,188 to 5,732 B by the frame reader without moving the
measured peak, which the receive path sets. The observer's planes in frames of
their own took the peak to 7,476 B, and the network message dispatch
(`dispatch_network_message_at`) out of line took it to 7,140 B (text +88 B).
The SCE pin `c244f4e171` (the engine built in its slot, its call chain kept
small) took the dial path to 4,820 B and the engine's frames on it from 1,800 to
840 B, at +880 / +896 B of text in the multicast image and none in the
`qemu-demo` one; the peak did not move. What set it then was the receive path of
a query, `lend_request` (1,976 B), because the codec's `Request` is 1,792 B and
1,416 of that is its Query's extension chain, held inline for the declared depth
of 8 whatever the wire carried. An experiment that only cut that depth to 3
moved the peak by exactly the 880 B it took out of the frame. The generated
codecs now also carry their views (`xtask` generates the whole set with
`views: true`, SCE ADR 0049), and the lent Request is read as a `RequestView`: a
few words and the bytes its chains occupy, walked where they lie. The readers of
a chain (QoS, target, attachment, value, source info, the admission verdict)
take the entries a chain yields, by reference or by value, and the held forms
are calls of them. That took the peak to 5,928 B, at +2,192 B of text in the
plain image (157,088 B), the code of the view's decode and walk. The depth of 8
no longer sets any size on that path (the view does not move with it), and
stays a limit on what a frame may carry that upstream does not have (upstream
and zenoh-pico accept any number of extensions).
The declared stack of the fixed client is now 9,216 B (a third free at the
peak), which takes 7,168 B out of bss against the 16 KB of before: data and bss
118.0 KB to 110.8 KB, against 114 KB of zenoh-pico's smallest working
configuration. What is left in the peak is the network dispatch (2,104 B; the
codec's `Response` is 1,104 B and is probably encoded inside it, which the
disassembly has not been read for), `lend_declare` and `lend_push`, the other
records still read as their eager forms, and the application layer's closure.

That last list was a guess, and the call graph of the image of 2026-10-22 does
not support it. The deepest chain of direct calls under the thread (the polled
pump task included) is 6,808 B and goes through the handshake: `wz_app_main`
1,456, the polled task 112, `dispatch_datagram_unit` 168, `dispatch_copied`
2,408, the observer's `drain_query_replies` 408, `dispatch_network_message_at`
2,104, and 150 B of leaves. `lend_declare` (2,064 B) is not on it, nor is any
other lent record: a chain that runs through them is 5,336 B, so reading a
Declare as its view would not move the peak, and was not done. The kit's own
reading of the same image is 5,928 B, so the chain counts a path that no run
takes in that order (a drain after a handshake that the receive path does not
make) and is a figure to hold, not the peak. What would lower it is the size of
the handshake's frame: `InboundFrame` is 720 B because its extension chains are
held as arrays of entries, the form the request's view replaced; a handshake
reads each chain once, so a view would take about 600 B out of `dispatch_copied`.
That is a moderate change to the readers of `Init`, `Open` and `Close` for about
a tenth of the stack, and is left until something needs the bytes.

D5 is built for the stack. `scripts/lib/stack_frame_gate.py` reads the worst
chain of direct calls from the image's disassembly, with the polled tasks as
roots below the thread's entry and a panic's tail not counted, and holds it: it
fails when the chain is over the declared stack, and when it is further than 128
B from the committed figure (6,808 B for the fixed client), so a change that
moves the stack is a recorded change. It is not a bound, and says so: a call
through a register (twelve on this path) is not followed, and the closure a walk
hands each record to is one. The image is now built by Layer Qzb (the board
table's `zeth-sockets-client-fixed` row, with the devicetree overlay the table
learned to carry), where before the row of the gate was read only by hand. The
wire turnaround is not gated: it needs the board, and no hosted lane has one.

Against zenoh-pico on the same board, bench and network buffers (2026-10-22, the
two documents answered 2000 times each with no wrong answer by both). Stack is
the sum of the application threads, because pico runs a read task of its own
beside `main` (an earlier comparison set pico's `main` alone, 2,944 B, against
wz's one thread, and read as a factor of two that is not there). pico is built
as `deploy/zephyr-pico-compare` with its heap pool and its two stacks cut to
what it uses (16 KB pool, 4 KB stacks), and it still serves the same queries:

| | zenoh-pico (tuned) | wz fixed client |
|---|---|---|
| stack used | 2,944 + 2,736 = 5,680 B | 5,928 B |
| stack reserved | 2 x 4,096 B | 9,216 B |
| heap used | 9,416 B (pool 16,384 B) | 0 |
| data and bss | 154,649 B | 110,826 B |
| text | 164,396 B | 157,088 B |

The two are not the same program: that pico build enables publication,
subscription and query as well as the queryable, and the wz client is a client
that answers queries; the kernel configurations differ beyond the network
buffers. So the table is a measurement of two builds, not of the two libraries'
cost for one feature set. No ordering is claimed from it.

## 5.1 The same node as a Linux process (2026-10-23)

The question the host asks of D1 and D2 is whether the node of the kit runs
unchanged where there is no Zephyr, with no allocator and one thread. It does,
and what that took is small, which is the evidence that the seams are in the
right place.

- **The UDP link is written once** (`wz_runtime_coop::udp_link`): the driver, its
  outbound storage and the slot profile's stack, over a `DatagramSocket` that a
  platform supplies (bind, send, wait, take a datagram). `wz-runtime-zephyr`
  keeps `ZephyrUdpSocket` and every name it had as an alias; it was 420 lines of
  the link, witnessed only on the target, and now has host tests (eight on the
  heap forms, nine on the slot forms, fifteen with the idle wait).
- **`wz-runtime-posix`** supplies the host's seams over libc: a monotonic clock,
  `getrandom`, the date, a UDP socket, the console and the image glue (a
  `critical_section` that takes no lock, because one thread runs the program).
  Linux only. It is the Zephyr profile's shape.
- **`deploy/host-slot-node`** is the node of `fixed_client.rs` with those seams
  under it: `#![no_std]`, `#![no_main]`, no `#[global_allocator]`. The link is the
  proof, as for the kit's image: a program that allocates anywhere does not
  link. It imports 24 symbols from libc and none is an allocator.

Measured on a build host (pc3), loopback, a zenoh-c client asking a router
for a 1 KiB document that the responder under test answers; the responder is the
only thing that changes, the order is shuffled every repetition and each
responder gets a fresh router. The node and zenoh-pico are both UDP clients of
the router with one thread; wz is built `-Os` and pico with its own Release build.

| | wz node | wz node, `batching` | pico, one thread | pico, two threads |
|---|---|---|---|---|
| GET median, 21 runs | 74.9 to 77.0 us | 72.7 to 73.0 us | 74.8 to 76.3 us | 74.8 to 76.4 us |
| CPU time a query, lowest of 15 runs | 7.8 us | 5.8 us | 7.2 us | 7.4 us |
| system calls a query | 3 | 2 | 3 | |
| idle context switches a second | 2 | 2 | 10 | 11 |
| resident memory | 1,344 kB | 1,356 kB | 1,988 kB | 2,208 kB |

The CPU time is the responder's own, read from `/proc` over 50,000 answered
queries, and the lowest of the runs is the figure because the host is shared and
disturbance only adds (medians: 8.0, 6.0, 7.4 and 7.6 us). The `batching` node
spends 19 percent less than pico on a query and 25 percent less than the plain
node; pico's queryable does not open a batching window, and pico has the
feature, so this compares what each sends by default, not what each could.

The latency ranges are the lowest and highest medians of three separate comparisons of
21 runs each, which differ by a few microseconds with the host's load (it is a
shared build host). In the two comparisons that had both wz columns, the
`batching` node was below the plain one and 2 to 3 microseconds below pico; the
runs overlap in their extremes, so this is a small effect and not a margin.

Three things this shows and one it does not:

- **A query is answered with two messages, and a datagram each.** The reply and
  the `Final` that ends it were two `sendto` calls in wz and in pico alike.
  `ResponseSink::begin_burst` and `end_burst`, called round the drains in
  `flush_pending`, open a batching window when nobody has one open, so the two
  leave as one frame (one `sendto`, one wake of the router). It is the
  `transport-batching` feature and off unless the image selects it
  (`host-slot-node --features batching`); a window the application opened is
  never closed by it.
- **An idle node woke 499 times a second**, because the loop waited at most one
  tick on the socket to look at its timers. `SessionDatagramLink::service_within`
  gives the link the time until anything is due (the handshake, lease and
  keep-alive deadlines and the runtime's next timer); a link whose image says it
  is the loop's only wait (`UdpStack::with_idle_wait_ms`) sleeps until then,
  arming its receive timeout at the largest power of two not above the deadline,
  so no deadline is late and a deadline an hour away costs one wake a second.
  The node held a session for 40 s with nothing to send at a 10 s lease. An image
  that does not ask runs the code it ran, and compiles the deadline arithmetic out.
- **A node and a stack that is not Zephyr's changed no kit image materially**:
  the fixed client's image is 173,436 B (173,468 B before this change) and its
  worst stack chain 6,816 B (6,808 B), inside the gate's tolerance.
- It does not show the cost of a GET the node *sends*: that is 5.2.

## 5.2 The node that asks (2026-10-23)

The kit's client answered queries and asked none, because a session with no
allocator had no way to write a request: `send_request_query` built the owned
`RequestOwned` and refused with `FeatureDisabled` where there was no heap. Three
pieces close it, none of which allocates.

- **`lent_request::RequestWriter`** writes the codec's borrowed `Request(Query)`
  from the caller's own text (`GetParts`: a literal keyexpr, the selector
  parameters, the consolidation, the target, the timeout and the QoS), as
  `lent_response::ResponseWriter` writes a reply. Its test compares it with the
  owned builder over 3,456 combinations of those fields, and fails under a
  mutation of the timeout extension's header. A query that names a mapping id, or
  carries a value, a source info or an attachment, still goes the way every owned
  query goes.
- **`SessionLinkActions::send_get_parts`** sends it into the slot the link lends;
  `send_request_query` uses it where there is no allocator.
- **`SlotDispatch::get`** (feature `query-get` of `wz-session-mcu`) registers a
  pending query with the application's closed `ReplySink`, then sends the request,
  and removes the entry again if the send fails, so a refused query leaves no row
  that would later end with a final for a query nobody was told was asked. A
  query past its deadline ends here too: nothing else on this profile swept the
  pending table. The table's size is `WZ_LIMIT_MAX_PENDING_QUERIES`; at its
  default of zero in the kit's client, every `get` is refused with
  `Register(TableFull)`, which is how the first run of the node showed it.

`host-slot-node --features get` asks `--count` queries one after another
(`--get KEY --count N [--warmup N]`) and prints the round trips, from the request
being written to the final reaching the sink. It declares no allocator and the
no-allocator gate classifies it (`gated`, plain and with `get` and `batching`).

Measured as in 5.1, the other way round: one responder (a zenoh queryable
answering 1 KiB, behind a fresh router each run) and the GETTER is the thing that
changes; the order is shuffled every repetition and 2,000 queries are timed after
200 that are not.

| | wz node | pico, one thread | pico, two threads | zenoh (Rust) | zenoh-c |
|---|---|---|---|---|---|
| link to the router | UDP | UDP | UDP | UDP | TCP |
| GET median, 15 runs | 76.0 us | 80.4 us | 81.0 us | 99.9 us | 96.3 us |
| CPU time a query, lowest of 7 runs | 9.4 us | 9.9 us | 15.8 us | 46.0 us | 45.5 us |

zenoh-c in this install connects over TCP only, so its column is not the same link.
The CPU figures were taken while the shared host was busier than for the latencies
(load 2 to 5, against 0.3), over 20,200 queries each, and include the process's
start-up; the lowest run is the figure. The wz node is 4 to 5 microseconds below
pico's median in the latency comparison, and the ranges of the runs overlap in
their extremes. On CPU the wz node and the single-thread pico are one figure: no
order between them is claimed. Both are below the two-thread pico by a margin
the noise does not explain, and far below zenoh.

What this does not show: other payload sizes, a real network, or TCP for the wz
node (it has no stream link on the host). More than one query in flight is
measured below.

The deadline of a pending query is the application layer's, and a link that sleeps
while the session is idle would sleep past it. `SessionCore` holds one value for it
(`set_app_wake_deadline_ms`, the earliest moment the layer needs the loop awake),
`SlotDispatch` states the earliest pending query to it whenever the pending table
changes, and the pump folds it into the budget it hands the link. The pump's test
runs an acceptor over a link that records the wait it is told, and fails under a
mutation that ignores the layer's deadline.

A deadline in a table is not yet an event. The session's steady state raises
none, so on an idle session an expired pending query was swept only when some
other event happened to arrive. The pump now raises `IterationEvent::AppWake`
when the layer's deadline has come due, once and before it reads the link, so
`SlotDispatch::on_event` sweeps at that moment; the test spends the deadline and
fails if the event is raised twice. A wait budget of zero also waits for nothing
now (`UdpDriver::service_within(0)` used to wait one tick).

**Several queries in flight, and asking from outside the session.**
`host-slot-node --inflight K` keeps up to 8 queries pending (`MAX_INFLIGHT`,
`WZ_LIMIT_MAX_PENDING_QUERIES` 9). `--mailbox` asks the other way: a second
thread posts its queries to a `GetMailbox` (fixed rows by value, no allocation),
wakes the session with `SlotClientNode::wake`, and the session's own thread
drains the rows into `SlotDispatch::get` (`drain_mailbox`); a row the table
cannot take yet is left for the next drain, and one it will never take is
refused with a reason. The results, against the same responder behind zenohd,
6,200 queries a run, median of 9 runs:

| in flight | event, round trip | event, queries a second | mailbox, round trip |
|---|---|---|---|
| 1 | 76 us | 12,700 | 76 us |
| 2 | 88 us | 20,900 | 89 us |
| 4 | 113 us | 31,600 | 112 us |
| 8 | 164 us | 41,800 | 164 us |

The mailbox costs nothing that this measures. The latency rises with the number
in flight because the router and the responder serialise them; the rate rises
because the round trips overlap.

Two things the runs showed:

- Against zenohd 1.10.1 a run with four or more queries in flight sometimes
  never finishes: the router stops writing responses to the node for good
  (event, 4 in flight: 9 of 30 runs; 8: 5 of 30; mailbox, 4: 6 of 30; one in
  flight: 0 of 30). Its log has just dropped a Response "over the deadline"; the
  node's socket queue is empty and its sequence numbers are contiguous. The
  repository's own router did not stop in 60 such runs. That is the router's
  behaviour under this load; whether this node's request pattern provokes it is
  not known, and nothing here has been reported upstream. Not settled.
- Against the repository's own router the same load lost replies: one to four
  queries of 6,200 timed out in many runs, always the fourth of four requests
  sent back to back. The router had received every response. A temporary
  print where the outbound queue answers "congested" (in a copy of the source on
  the measuring host only) showed the cause every time: a droppable Response
  that waited `wait_before_drop` (1 ms) against a lane holding 3,214 bytes with
  a bound of 2,900 bytes, and the slot pool had room. The bound was `queue size
  (2) x the link's batch (1,450 bytes on UDP)`. The reference counts a lane in
  negotiated batches too, so its router has the same small lane; wz copied the
  rule (R2925). A lane's bound is the sender's memory policy, so it now counts
  in the session's configured batch (`TxQueueShape::queue_unit_bytes`, 65,535
  bytes by default and never below the link's batch) while the batch the link
  sends still packs and fragments. This departs from the reference on purpose.
  The same router binary with the lane size raised to 8, or `wait_before_drop` to
  50 ms, lost nothing in 40 runs each; at 4 queries in flight the old router lost
  queries in 28 of 40 runs and the fixed one in 0 of 40, at 8 in flight 23 of 40
  against 0 of 40, run in alternation in the same hour.

The two routers were also compared with one query and two in flight, shuffled,
15 runs each, router, responder and getter pinned: zenohd 394 us and 2,328
queries a second against 325 us and 2,843 for the repository's router at one in
flight, 441 us and 4,114 against 336 us and 5,401 at two, with no query lost or
stuck in any of the 60 runs. These medians are about five times those of the
table above, which was not taken pinned; why is not established, so only the
order within one table is a finding.

## 5.3 The kit client sleeps when idle, and batches (2026-10-23)

5.1 measured on the host what the idle wait and the batching window are worth;
this is the same code on the T2G kit (CYT4BF, Cortex-M7, Zephyr's sockets, the
fixed-memory client of `fixed_client.rs`). `ZephyrUdpSocket` re-arms
`SO_RCVTIMEO` through the board hook that armed it when the socket was opened
(`set_receive_timeout`), and the image opts in by Kconfig: `CONFIG_WZ_IDLE_WAIT_MS`
(0, the default, keeps the tick) and `CONFIG_WZ_TX_BATCHING`
(`overlays/t2g_client_batching.conf`, which also gives the main thread 10 KB). The
loop says how many times it went round every five seconds, which is the figure
that tells a node that sleeps from one that polls.

Four images from one tree, flashed to the kit and asked 2,000 times for each of the
node's two documents, three repetitions, the order shuffled every repetition (48,000
GETs in all, none wrong); the router is a zenohd on the host, the kit its UDP client.

| | base | idle wait 1,000 ms | batching | both |
|---|---|---|---|---|
| flash (text) | 158,924 B | 158,952 B | 167,128 B | 167,156 B |
| worst stack chain, direct calls | 6,840 B | 6,848 B | 7,140 B | 7,148 B |
| main stack | 9,216 B | 9,216 B | 10,240 B | 10,240 B |
| loop rounds a second, session idle | 909 | about 4 | not taken | about 4 |
| GET median, host's view (6 medians) | 0.399 ms | 0.387 ms | 0.351 ms | 0.351 ms |

- **The idle wait takes the loop from 909 rounds a second to about 4**, with the
  session held for 60 s at a 10 s lease and no loss. The node's one thread now
  sleeps in the kernel until a datagram arrives or the keep-alive falls due. The
  figure is the node's own count of its loop, not a power measurement: what the
  board saves in current is not measured here. It costs 28 bytes of flash.
- **Batching costs 8.2 KB of flash and 300 bytes of stack** (the batch writer and
  its flush path are code the image did not carry), which is why its overlay raises
  the main stack: the chain would leave 22 percent free at 9 KB, short of the
  quarter HW.7 asks. The stack gate holds it as its own row,
  `zephyr-client-fixed-batching`, at 7,140 B.
- **The latency is the host's view** (a request through the router's REST port to
  the kit and back), so it includes the host's part, and the runs of one image
  differ among themselves by more than the images differ (0.31 to 0.48 ms for the
  base). The batching images were lower in the medians, by about 0.04 ms, and the
  ranges overlap: a small effect in the direction the host showed, not a margin.
- **The base image file is 1,244 B larger** than the one of 5.1 (174,740 B against
  173,496 B), from this change and from every commit that came to the tree since; the
  idle wait adds 24 B to the file.

What this does not show: the board's current draw, a second session (the idle wait
is for an image that waits on one socket and no other), and the images over lwIP.

## 6. Open

- The Zephyr kernel keeps a heap of its own (network buffers, POSIX objects).
  For this image it is measured: nothing is allocated from it after start-up
  (`heap allocated 0, peak 0`), and the image runs with the pool at 0.
- Whether `Static<N>` reaches the cooperative runtime's task cells by the type
  or by a const generic table (`RuntimeCell`) is decided when step 6 reaches it;
  the existing table is the working form until then.
- The two-session fixed image (`no-heap-multi-session.md`, steps 1 to 5) uses
  the host of step 1; the cell kinds of its D1 are a property of the host's
  tables and are not changed here.

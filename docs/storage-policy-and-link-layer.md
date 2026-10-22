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
  `limit(option_env!("WZ_LIMIT_<NAME>"), default)`; `deploy/Kconfig.limits` is
  derived from those rows (`scripts/lib/limit_config.py --check`) and the Zephyr
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
118.0 KB to 110.8 KB, against 114 KB of zenoh-pico's. The peak of 5.9 KB is
about twice pico's 2.9 KB. What is left in it is the network dispatch (2,104 B;
the codec's `Response` is 1,104 B and is probably encoded inside it, which the
disassembly has not been read for), `lend_declare` and `lend_push`, the other
records still read as their eager forms, and the application layer's closure.

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

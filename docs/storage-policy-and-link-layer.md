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

## 5. Open

- The Zephyr kernel keeps a heap of its own (network buffers, POSIX objects).
  A Rust image that links no allocator has not removed it; D4 of
  `no-heap-multi-session.md` is the same point for FreeRTOS. What the kernel
  allocates after start-up in this image is to be measured in step 3, with the
  kernel pool at its smallest working size, before the image is called
  heap-free.
- Whether `Static<N>` reaches the cooperative runtime's task cells by the type
  or by a const generic table (`RuntimeCell`) is decided when step 6 reaches it;
  the existing table is the working form until then.
- The two-session fixed image (`no-heap-multi-session.md`, steps 1 to 5) uses
  the host of step 1; the cell kinds of its D1 are a property of the host's
  tables and are not changed here.

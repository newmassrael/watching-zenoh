# One image, several sessions, no allocator

Status: design note. It states what is built, what is measured, what is
decided and what is still open; it is not a specification and the atomic store
does not parse it. Decisions here follow the standing criterion of this tree
(the long-term correct design, cost not counted); the reason for each is next to
it.

## 1. The question

A deploy can already hold more than one session in one program. On a heap MCU
profile a client session to a router and a multicast group session run on one
cooperative local set inside one FreeRTOS task, and a QEMU lane boots them
(`Q.frt2`, `deploy/mcu-freertos-demo`, two-session bin). On a fixed-memory
profile one session of each kind runs with no allocator: the acceptor, the admin
node and the multicast image are `gated` in the no-allocator link gate
(`scripts/lib/no_allocator_link_gate.py`). What does not exist is the product of
the two: **several sessions in one image that links no allocator.** That is the
`mcu-freertos-two-session` row of the gate, still `pending`.

The question is not whether it is possible. It is what the shape is, so that the
memory of every session is bounded by construction and a fault in one session
cannot take another one down.

## 2. What is built

- **A session table.** `machines.<m>.session_pool` in the deploy file names
  `max_sessions` and `slot_bytes`; the image holds a static table of
  `max_sessions` cells and its size is `max_sessions * slot_bytes`, one generated
  number (`deploy/session_slot_bytes.json`, written from the size of a probe
  symbol by `scripts/lib/session_slot_bytes.py`). The validator
  (`scripts/lib/deploy_sessions.py`) refuses more sessions than cells, a session
  whose pools exceed `slot_bytes`, and an lwIP UDP control-block count
  (`MEMP_NUM_UDP_PCB`) below `max_sessions + 1`.
- **Peer-written tables inside the slot.** Everything a peer writes into a
  session (declared subscribers, queryables, tokens, the id maps) lives in that
  session's cell. Application registries (subscribers and queryables the program
  declares, the switchboard) stay process-wide. Reason: wire ids are scoped to a
  session, so the isolation is already the wire's.
- **Several accepted sessions.** `accept.max_sessions > 1` is allowed on MCU and
  Zephyr when a `session_pool` exists; the acceptor claims a cell before it
  answers the first INIT.
- **A group pump that yields.** `MulticastPump::step` does not pump the
  executor; a task form yields after each step, so a client session and the
  group share one cooperative local set. The pump is NOT yet transport-neutral:
  it names `LwipLink` and `LwipMulticastDriver` and uses exactly four things of
  them (poll the loopback, check the timeouts, ask whether a link is up, send to
  the group, take one datagram), which is the surface a group-transport trait
  has to carry (section 4, D5).
- **The gate.** An image is `gated` (its link must show no allocator and no
  `extern crate alloc` in the graph) or `pending`, and the table is checked in
  both directions.

## 3. What is missing

The `mcu-freertos-two-session` image is `pending` for three reasons the gate
states: the sessions' shells (reference-counted cells and `RefCell`s), the
multicast drive loop, and the FreeRTOS allocator bridge. Each has a fixed-memory
form in a single-session image already; none has been composed.

1. **One table for two kinds of session.** The acceptor's slot and the group's
   cell are different types today. A client session (initiator) and a group
   session share the session machinery but not the cell.
2. **One runtime, static.** The cooperative local set of the heap form spawns
   boxed futures. The fixed-memory runtime has a static task pool; the pump
   task, the client session task and the application task must come from it.
3. **The kernel.** FreeRTOS' own objects (tasks, queues) come from `heap_4`
   unless static allocation is on. A "no allocator" image that leaves the kernel
   on `heap_4` has not removed the heap, only hidden it from Rust.

## 4. Decisions

**D1. One cell struct per kind, and the table is typed by the largest.**
Rejected: one cell type holding both kinds' state (the unicast cell would pay for
the group's receive tables, and the other way round). Rejected: two tables (two
ceilings, and a deploy would size each by guess). Chosen: a table of
`max_sessions` cells each `slot_bytes` wide, `slot_bytes` measured as the larger
kind (`session_slot_bytes.json` already records it per image), and a cell is
claimed by kind. Waste is accepted until it exceeds a quarter of the table, and
then the table is split by class; the measurement decides, not a guess.

**D2. A byte cap per session is not built.** A cap on a shared
`#[global_allocator]` cannot be enforced per session without a per-session
arena, and an arena is exactly the slot. The bound a session has is its pools
and its cell. `heap_budget_bytes` stays refused, and its refusal text says so.

**D3. Containment is a test, not a claim.** Fault isolation between sessions is
what the single-session images cannot show. The four host scenarios of the
two-session lane (flood the group socket, expire a group peer, close the
unicast session, stop the group) are repeated on the fixed image, and each gets
a mutant that turns it red. The fill-to-N, refuse-at-N+1 tests already exist for
the pieces (the session pool of the lwIP tier, the peer-written tables, the
reply refusal, the cooperative runtime's task and timer tables, all of
2026-10-11); what is new is the same property across KINDS in one table: the
`N+1`th claim of either kind is refused without disturbing the `N` that hold,
exhausting one session's receive pool leaves the other sessions their frames,
and a failed send on one session leaves the others sending.

**D4. The kernel's static allocation is part of "no allocator".** The image
turns on static allocation for the kernel objects it creates, or it creates them
before the scheduler starts from static storage. A gated image whose kernel
still calls `pvPortMalloc` after the scheduler starts is not gated; the link
gate already classes the kernel's allocator as reported, and this decision makes
it judged for an image that claims the whole thing.

**D5. The group pump is generic over a group transport. The trait is in
`wz-runtime-coop`, next to `SessionDatagramLink`, and the pump is in
`wz-session-mcu`.** The first draft of this note put both in `wz-runtime-coop`;
reading the crates corrected it. The unicast pump is in `wz-runtime-coop` because
it needs nothing above the runtime, but the group pump needs the multicast
dispatcher, the JOIN wire and the reply sink of `wz-session-core`, and
`wz-session-mcu` is the crate that is written once for every network stack and
already carries those features. The trait carries nothing and needs no feature, so
it sits where a stack's own crate can name it without taking the pump: the Zephyr
tier names `wz-runtime-coop` and not `wz-session-mcu`. A pump that stays in
`wz-session-lwip` is unreachable from Zephyr; the move is the price, and the lwIP
crate keeps its names by thin delegates. The pump asks its transport for: one
round of housekeeping (the lwIP loopback poll and timer check; nothing on a kernel
socket stack), whether a carrier is up, sending one datagram to the group, and
taking at most one received datagram with its source.
Rejected: a second pump for Zephyr (two copies of the JOIN cadence, the lease
sweep and the TX drain would drift, as the two forwarders of the router did).
Rejected: wrapping Zephyr in the lwIP types (the Zephyr tier has no lwIP).
Chosen: the lwIP pair implements the trait with the code it has today and keeps
its tests unchanged; a Zephyr socket implements it next.

## 5. Steps

0. Extract the group-transport trait (D5) into `wz-runtime-coop` and move the
   pump (`multicast_drive.rs`, about 1400 lines of loop, queue and table; its
   tests stay) to `wz-session-mcu` over it; the lwIP implementation of the trait
   stays in `wz-session-lwip` with thin delegates under the old names, and every
   existing two-session and multicast test is unchanged and green. A refactor
   with no new behaviour. Done.

1. Cell kinds and the claim-by-kind table (D1), with a host test that fills it
   with both kinds and refuses at `N+1`, and the measurement of `slot_bytes` for
   the larger kind.
2. The static runtime carries the three tasks the two-session image needs from
   its fixed task table: the pump, the client session, the application.
3. The two-session image on the fixed-memory profile, built, linked and judged
   by the gate on ARMv7-M, promoted from `pending` to `gated`.
4. The `Q.frt2` scenarios on the fixed image and the new containment cases
   (D3), booted under QEMU.
5. The kernel's objects from static storage (D4), then the gate's judgement
   extended to that image.

## 6. Open

- The size of `slot_bytes` for the larger kind is projected, not measured, until
  step 1 puts both cells in one table; it must be measured on the thumbv7m
  target before the deploy file is allowed to promise a RAM figure.
- A Zephyr image has no group link, so the same shape on Zephyr waits for one.
  What was missing was two things, and the first is done: the pump is generic
  over a group transport (D5, step 0). The second remains: the Zephyr socket layer
  (`zephyr-sys`, `wz-runtime-zephyr`) has no multicast membership call. It can be
  compiled against the stand-in build but only run on a board.
- Whether the table may be split by class (D1) is decided by the measurement in
  step 1.

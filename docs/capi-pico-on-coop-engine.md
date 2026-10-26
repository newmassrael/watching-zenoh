# The pico C ABI over the cooperative engine

Status: design note. It states what is built, what is measured, what is decided
and what is still open; it is not a specification and the atomic store does not
parse it. Decisions follow the standing criterion of this tree (the long-term
correct design, cost not counted); the reason for each is next to it. It is step
3 of the size structure whose steps 1 (the size gate builds its own pico,
Round 3474) and 2 (one TCP stream link for the cooperative runtime, Round 3478)
have landed.

## 1. The question

The library a zenoh-pico program links in place of zenoh-pico is several times
pico's size when both are built with the same switches. The question is what
shape the C ABI takes so that its size is the size of what it does, and so that
it behaves as pico behaves in both of pico's threading arms.

## 2. What is built, and what it costs

- **One OS thread and one multi-thread tokio runtime per session.** The session
  model every wz C ABI sits on (`wz-capi-core`, its `lib.rs` module doc and
  `drive.rs`) drives each session on a thread of its own, because a C `z_open`
  returns while reading and leasing continue. That holds in pico's
  single-threaded arm too: there, `zp_read`, `zp_spin_once` and
  `zp_send_keep_alive` do nothing, and the session does that work on its own
  schedule (`crates/wz-capi-pico/src/session.rs`, the module doc and the
  single-threaded entry points). Upstream's single-threaded arm does the work IN
  those calls; this is a divergence, not only a cost.
- **Size, measured by the size gate against pico built as the same build**
  (Round 3474): `pico-client` (single-threaded, dials TCP, pub/sub, no
  listener, no scouting, no UDP) is 1,794,085 bytes of text, 4.49 times pico's;
  the other cases are 4.59 to 6.95 times.
- **The cooperative engine is already a client.** `deploy/host-slot-node` is the
  kit's fixed-memory client as a Linux process: the shared session code over
  `wz-runtime-posix`, one thread, no allocator. Built for release with its own
  profile (`opt-level = "s"`, LTO, `panic = "abort"`) it is 125,981 bytes of
  text answering queries, and 142,295 with the getter (measured 2026-10-24 on
  the build host). ⚠ This is NOT a same-condition comparison with pico or with
  the C ABI: it is an executable, so LTO drops everything it does not call,
  while a C library must carry every symbol it exports. It says that the engine
  is small and that the size of the C ABI is in what sits around it; it does
  not say what the C ABI will measure.
- **The coupling is narrower than it looks.** `wz-capi-pico` names
  `wz_runtime_tokio::` 158 times. 103 of them are modules that crate only
  re-exports from `wz-session-core` (`keyexpr_canon`, `keyexpr_match`,
  `locality`, `qos`, `query_sink`, `reply_acceptance`, `reply_sink`, `sample`,
  `sink`; `crates/wz-runtime-tokio/src/lib.rs`). What is the tokio engine's own
  is `session`, `session_glue`, `session_open`, `runtime_impl`,
  `advanced_cache`/`_publisher`/`_subscriber`, `declare`, `node_clock`,
  `retry_period`, `timestamp_source` and `tls_config`, plus everything that
  comes through `wz-capi-core`.

## 3. Decisions

- **D1. One ABI crate, two engines behind a port.** The ABI layer (the C types
  and their layouts, ownership, bytes, key expressions, encodings, config,
  closures and handlers, the platform surface) is written once and knows no
  engine. What touches a session goes through a port that an engine implements.
  Rejected: a second crate per engine (two copies of the layer that is hardest
  to keep byte-exact, which the layout asserts in `lib.rs` exist to protect).
- **D2. The threading model is pico's own, in both arms.** In the
  single-threaded arm the application steps the engine: `zp_read` reads and
  dispatches, `zp_send_keep_alive` sends one, `zp_spin_once` runs one turn,
  and a callback runs inside the call that dispatched it. In the multi-threaded
  arm `zp_start_read_task` and `zp_start_lease_task` start the OS threads that
  step the same engine under the session's lock, as pico's tasks do. Neither
  arm runs an async runtime. There is nothing to choose here: pico has both
  arms, and the engine that serves the first serves the second.
- **D3. The engine is the cooperative runtime's heap profile over the host
  stack.** The C ABI allocates (pico's `z_malloc` is the C allocator), so the
  fixed-memory profile stays the MCU images'. The link is `IpStack`, UDP and
  TCP in one slot type (Round 3478).
- **D4. The new engine grows beside the old one.** It is a build selection from
  its first slice, with a size-gate case that measures it from the first
  slice, and it takes the surface one capability at a time. When it covers the
  single-threaded client surface it becomes that arm's engine; when it covers
  both arms the tokio engine leaves the pico ABI. The zenoh-c ABI (`wz-capi-c`)
  is the drop-in for an application host and keeps the tokio engine; it is out
  of scope.
- **D5. The selection becomes a build-configuration axis.** Until then it is a
  cargo feature of `wz-capi-pico`. The build-configuration runtime axis
  (`deploy/Kconfig*`, `configs/profiles/`, the `wz-config.toml` generator)
  belongs to the session that owns it; the feature maps onto that axis when
  that session agrees the shape.
- **D7. The C session handle is the ABI's, and holds the engine's session as a port.** It points
  at a `PicoSessionHandle`: the engine's session behind the port's `SessionDrive` (open, close,
  the read task, read, spin, keep-alive) and the ABI's own per-session state (role, clock,
  connectivity listeners, admin space), which the ABI keeps itself rather than parking it in
  the engine as an untyped extension. A module of a capability the port does not carry yet
  reaches the tokio engine's session by downcast, which a build without that capability does
  not compile.
- **D8. Both ports are `Send + Sync`, and the cooperative engine earns it with one lock.** A C
  program may call into a session from any thread in pico's multi-threaded arm, and in its
  single-threaded arm promises one thread. The cooperative engine's state (single-threaded
  types, `Rc` among them) lives behind one session lock and never escapes it; a C callback
  runs with the lock released (deliveries are queued under it and handed out after), so a
  callback may call back into its session, as zenoh-pico's may. That is the one `unsafe`
  claim the engine makes, stated where its lock is.
- **D9. The listening role is several faces over one set of registrations (section 7).** A
  session that accepts holds one face for each peer it is linked to, each with the tables its
  peer writes and the queries it asked of that peer, and one registration table of what the
  application declared, which every face is dispatched against. The engine does not keep one
  observer for each peer and replay the application's registrations onto each, as the tokio
  engine's registry does, because the fixed-memory profile already separates the two kinds of
  table and the separation is what the engine needs.
- **D6. The compile profile is orthogonal.** A `panic = "abort"` profile for the
  C ABI (`capi-small`) composes with either engine and is measured on its own.

## 4. Steps

1. Take the ABI layer's types from where they live (`wz-session-core`), not
   through the tokio engine's re-exports. No behaviour or symbol changes; what
   is left naming the engine is then the engine's share.
2. Put the tokio engine and `wz-capi-core` behind `engine-tokio` (default on),
   so the crate builds without them.
3. The cooperative engine for the single-threaded client: `z_open` dialling
   `tcp/` or `udp/`, `z_close`, `zp_read`, `zp_spin_once`,
   `zp_send_keep_alive`, `z_put`, the publisher and the subscriber. A
   size-gate case beside `pico-client`, and a round trip against a pinned
   `zenohd` and against pico itself. In two parts:
   - 3a. The engine as a crate (`wz-capi-coop`), implementing both ports, tested against a
     router stand-in over the host's sockets.
   - 3b. The pico ABI over it: an engine feature that builds the client without the tokio
     engine, `z_open` building the session from the C config, the size-gate case, and the
     round trips.
4. The query plane, liveliness and the rest of the client surface, a
   capability at a time, each with its case.
5. The multi-threaded arm.
6. The selection flips for the arms the engine covers; the tokio engine leaves
   the pico ABI.

## 5. Status

- 2026-10-24: this note; step 1 (the ABI layer names `wz-session-core` directly; the size
  gate's cases are unchanged: same exports, every case in budget).
- 2026-10-24: the link the engine needs, ahead of step 3: `IpDriver` takes its buffers as
  parameters, so the slot and the heap profile share it, and `ip_stack::IpLinks` is the session
  shell's `SessionLinks` over a platform's datagram and stream sockets, written once
  (`wz_runtime_posix::links::PosixLinks` on the host). Until then a program with a heap had no
  links over the host's sockets at all.
- 2026-10-24: step 2 begins by moving what is engine-neutral below both engines, the way
  R311y617 moved the encoding id table: the VLE codec to `wz_codecs::vle`, the encoding hint
  conversions and their dialect to `wz_session_core::encoding_hint` (`wz-capi-core` re-exports
  both), and `PublishOptions`, `PlainPutParams` and `PublishError` to
  `wz_session_core::publish_options` (`wz-runtime-tokio` re-exports them and keeps the loopback
  leg, which is its own). The ABI layer now names `Reliability` and `WhatAmI` where they live too.
- 2026-10-24: the port is a crate, `wz-capi-port`: the vocabulary a C ABI and its engine both
  name and `SessionEngine`, the operations the client surface makes (publish, subscribe, hold a
  key expression, match, filter writes, batch, the peers' identities). `wz-capi-core` implements
  it; the pico ABI's key, publisher, subscriber, matching and write-filter state hold
  `Arc<dyn SessionEngine>` and name no engine. Measured cost: pico-client +6 KB (0.3%),
  pico-default +5 KB. The first cut cost 35 KB, all of it a second copy of the registry's drop
  glue: a release build does not share generics across crates, so the trait object must be made
  in the engine's crate (`SharedSession::as_engine`, `#[inline(never)]`) and the boxed session
  freed there; an implicit coercion in the ABI crate brings the copy back.
- 2026-10-24: `SessionDrive`, the C session handle's half of the port (close, the read task,
  read, spin, keep-alive, the zid), and the handle the ABI owns (D7): `z_open` stores a
  `PicoSessionHandle` holding the drive (`SessionState::into_drive`, made in the engine's crate,
  which also frees the session through it) and the ABI's per-session state, which no longer
  rides in the engine as an untyped extension. Measured cost on top of the engine port:
  pico-client +2.5 KB, pico-default +1.9 KB.
- 2026-10-24: step 3a, the cooperative engine (`wz-capi-coop`): `CoopEngine` opens a client
  session to the first of its endpoints that completes the handshake, implements
  `SessionEngine` and `SessionDrive` over session-core's application layer (the observer keeps
  the subscribers, what the peer declared and the matching watches), holds its state behind one
  lock and hands deliveries out after it (D8), and runs a read task as a thread that steps it.
  Its session-core features are the tokio engine's session base less the local loop. Tested
  against an acceptor session on a thread of its own over UDP sockets: the router learns the
  subscriber, a push is delivered only when the program steps the session, a put reaches the
  router, and a write filter holds a put back until the router declares a subscriber (30 runs).
- 2026-10-24: step 3b. `wz-capi-pico` has two engine features: `engine-tokio` (default, and
  selected by every capability only that engine has: peer, scouting, queries, liveliness, the
  unstable API, the TLS and other links, the drive knobs) and `engine-coop`. A build without the
  tokio engine opens its sessions on the cooperative one: `z_open` reads the config as before and
  hands the engine the endpoints, the role, pico's lease and transmit model and zenoh's batch
  size; the engine mints the zid. `link-udp` and `multi-thread` select no engine (the
  cooperative engine dials UDP in every build and runs its read task as a thread);
  `deploy/wz-config.toml`'s pico base names `engine-tokio`, since every build it configures is
  on that engine, and a weak forward counts as a forward there. The size gate
  has `pico-client-coop`: 865,723 bytes of text against pico-client-udp's 1,867,697, 2.15
  times the same pico against 4.63. `client_only_dials_a_listener` (a client build dialling the
  full build's listener, publishing and hearing back) passes on the tokio client, the
  cooperative single-threaded client and the cooperative multi-threaded one; it now calls
  `zp_read` in the single-threaded arm, as pico's contract has the program do.
- 2026-10-24: the cooperative runtime's critical sections on a host. Every borrow of the
  runtime's cells goes through one door, `wz_runtime_coop::cs::with`: by default the
  `critical-section` implementation an image links (an MCU's interrupt mask), and with the
  runtime's `host-lock` a lock of the process, reentrant on its thread, which the engine selects.
  The cooperative pico client then links no `critical-section` implementation and exports its C
  ABI alone, 441 symbols as pico-client (443 before: `_critical_section_1_0_acquire` and
  `_release`, which rustc exported from the cdylib and neither a second version script nor
  `--exclude-libs` could hide). The section holds nothing and enters and leaves out of line: one
  that held the lock's guard put the guard's release at every call site, 16 KB of text; this
  one costs 1.9 KB (867,811 bytes).
- 2026-10-24: a lost link is dialled again (pico's `Z_FEATURE_AUTO_RECONNECT`). The engine's
  link is up, being dialled, or waiting to be, and each step moves it on: a link that ended,
  whatever ended it, takes what its peer declared with it (the observer's link-loss flush, so a
  write filter or matching status that counted on the peer reads false again), and the endpoints
  are dialled at once and then every `redial_ms` (pico's ABI: 1000) while none answers. When a
  handshake completes, the session declares its key expressions, subscribers and Interests again
  under the ids it holds them by, as pico sends its declaration cache again. What is declared
  while the link is down is recorded and sent then. An open no endpoint answers still fails. The
  engine also gained the KeepAlive and Close codecs, which nothing in its feature set had
  brought: without them its keep-alive and close were sent as nothing, a router expired an idle
  session after one lease, and a router's Close was not read. Tests: the session survives a
  router that closes and comes back (the filter shuts, the declarations reach the new router,
  a push arrives), a session that redials none ends with its link, and a session stepped for
  three leases keeps its lease (red without the KeepAlive codec). pico-client-coop: 881,043
  bytes, 2.19 times the same pico.
- 2026-10-24: a read waits on its link outside the session's lock. Until now each pass of the
  link's loop waited one millisecond on the socket, under the engine's lock, so a quiet session's
  read task woke a thousand times a second and a publisher on another thread could wait behind
  it; and a session waiting to dial again had no socket to wait on at all, so its read task spun
  (1.3 million reads in 600 ms, measured). A link the engine opens is now waited on by its owner
  (`IpLinks::waited_by_owner`): its loop reads what is queued and does not wait, and the link
  hands out a wait on a duplicate of its socket's descriptor (`SessionDatagramLink::readiness`)
  that a read makes before it takes the lock, for at most `idle_wait_ms` (pico's ABI: 100, pico's
  socket timeout), returning as soon as input is queued; a link that already holds a whole batch
  says so (`holds_input`) and is not waited on. A secure channel holds bytes of its own that the
  socket's wait would not see, so it gives no wait and keeps waiting in its loop. While no link is
  open, a read sleeps until the next dial, at most the same wait. Tests: a quiet session makes 8
  reads or fewer in 600 ms (258 with the loop's wait), its read task wakes for a push in under
  60 ms, and a session waiting to dial makes 8 or fewer. pico-client-coop: 888,223 bytes, 2.20
  times the same pico.
- 2026-10-25: queries, step Q1: the answering end on both engines. The queryable joins the port:
  `declare_queryable_on_wire` / `undeclare_queryable` on `SessionEngine` (an engine without one
  in its build answers `None`), and the vocabulary a queryable's callbacks are minted with:
  `QueryHolder` (what the face's queries are held through, and whether its session is closed)
  and `HeldQuery` (a query kept past its callback, answering on its own route, its Final owed
  until it is dropped). The tokio engine translates them to its face sessions and held queries;
  pico's `query.rs`, the admin space and the advanced cache declare through the port, and pico's
  `queryable` forwards to whichever engine the build has. On the cooperative engine
  (`wz-capi-coop`'s `queryable`) every query is held: a C callback never runs under the
  session's lock (D8) and the observer calls a queryable inside its dispatch, so the engine's
  queryable only copies the query out and holds its Final; the callback runs when the deliveries
  are handed out, its replies go out on the query's link, then its hold is let go, and the
  dispatch's Final waits for the last hold. Each link has a generation, so an answer to a query
  from a lost link reaches no new router. Tests: the engine against a router stand-in (a reply
  and then the Final, from a callback that steps the session from inside itself; a kept query
  whose Final waits for its drop), and pico's `client_only_dials_a_listener` with the full
  build's listener asking (`get <key>` on its input, no consolidation): a reply at once, a late
  reply from the program's thread, and the end only when the copy is dropped, on the tokio
  client and on the cooperative one in both arms. pico-client-coop 888,143 bytes (it has no
  queryable).
- 2026-10-25: queries, steps Q2a to Q2c: `z_get` on both engines. The get's options
  (`QueryOptions`, with the default timeout and the consolidation it resolves to) moved down from
  the tokio runtime to session-core (Q2a), so the port names them. The cancellation token moved to
  the port (Q2b), and the get joined it: `get_on_wire` on `SessionEngine` asks a query with
  those options, minting one reply callback per leg, whose drop is that leg's end, and records
  each leg's undo with the get's cancellation fan; pico's `get.rs` and the querier ask through it.
  On the cooperative engine (`wz-capi-coop`'s `query`, Q2c) a get has one leg, to the link's peer,
  registered with the observer as the tokio engine registers its own: request id, deadline
  (rounded up, so it never ends before its timeout), accepted reply keys and consolidation. The
  entry's sink only queues an owned copy of each reply and, from a guard it owns, the leg's end;
  the deliveries hand both out with no lock held (D8), the end as the drop of the callback.
  Every step sweeps the deadlines, and an idle read waits no longer than the next one. A
  cancelled token unregisters the entry and drops the callback at once, with no step; a lost
  link ends every leg it carried. The querier still needs the tokio engine: it watches whether
  a queryable matches, a plane the cooperative engine does not have yet. Tests: the engine
  against a router stand-in (a reply and then the Final, from a callback that steps the session
  from inside itself; zenoh's timeout reply at the deadline and not before; a cancel that
  returns once the callback is dropped; a lost link that ends the get), and
  `client_only_dials_a_listener` asking the listener's queryable (a reply, then the end) and a
  key nobody answers (the end alone), on both engines. pico-client-coop 888,951 bytes (it has
  no query).
- 2026-10-25: queries, step Q2d: the querier on both engines. A matching listener counts what a
  write filter on its plane counts: `declare_matching_listener` on `SessionEngine` takes the
  plane, so a querier's listener watches the peers' queryables, only complete ones for a target
  of `ALL_COMPLETE`, as zenoh's querier asks. pico declares a listener on its entity's write
  filter, so pico's `WriteFilter` declares it here too, from the plane, key and local switch the
  filter was made with, and retracts it with the filter; the publisher, the advanced publisher
  and the querier keep no list of their own, and a background listener goes with its entity.
  The cooperative engine keeps each listener in the registry of its plane, with the criterion its
  filter reads. The tokio engine installs a querier watch through a querier whose target is
  `ALL_COMPLETE` when the plane requires it (it counted any queryable before), the zenoh-c
  querier's poll and listener read its target the same way, and its requesting end now hears
  the peers' queryable declarations without the answering end: a querier built without
  `queryable` matched nothing and sent no get. pico's querier is the port's, and the
  `engine-tokio` gate on it is gone. Tests: the engine against a router stand-in (a listener on
  any queryable and one on complete queryables, told apart by a queryable that is not complete,
  with a subscriber as the CONTROL), and `client_only_dials_a_listener` asking through a querier
  that its poll and its listener say matches, beside an `ALL_COMPLETE` querier that nothing
  matches and whose get ends at once, with and without the answering end, on both engines.
  Layer C1co runs those four builds against the full build's listener, in a job of its own.
  pico-client-coop 890,395 bytes.
- 2026-10-25: liveliness, step L1: the token and the subscriber on both engines. The port names
  a token (`declare_liveliness_token_on_wire`, its retraction naming its key as zenoh-pico's
  always does) and a liveliness subscriber (`declare_liveliness_subscriber_on_wire`, with or
  without history, retracted as any subscriber is), with session-core's `LivelinessSample`; pico's
  token, its subscriber and the background form go through it, the background form now declaring
  its key and asking on it as pico's does. The cooperative engine (`wz-capi-coop`'s `liveliness`)
  announces each token over its link and again over each new one, and keeps it with the
  observer's local tokens, so a peer that asks later is answered; a liveliness subscriber is the
  observer's, its Interest sent again over each new link, and its sink only queues an owned copy
  of each sample, handed out with no lock held (D8): a token declared or retracted, the ones alive
  when it asked for history, and each token of a lost link as it goes. A token answering a history
  Interest reaches only the subscribers that asked for history, session-core's rule after
  zenoh's. Tests: the engine against a router stand-in (a token seen and retracted with and
  without its key; a subscriber hearing the router's tokens on its key alone; history told the
  tokens the router only held; a lost link taking the router's tokens and a new router told the
  session's), and `client_only_dials_a_listener` holding a token the listener sees and hearing
  the listener's, on both engines (Layer C1co, now with `liveliness`). The liveliness get stays
  with the tokio engine.
- 2026-10-25: liveliness, step L2: the liveliness get on both engines. `liveliness_get_on_wire`
  on `SessionEngine` asks which tokens are alive on a key with the contract of `get_on_wire`: one
  reply callback minted per leg, whose drop is that leg's end, each leg's undo recorded with the
  get's cancellation fan; `0` is the platform default timeout and never none, as pico rewrites
  it. The tokio engine keeps its per-face fan behind it. The cooperative engine
  (`wz-capi-coop`'s `liveliness-get`) registers one leg with the observer's liveliness gets
  under its Interest id and sends the Interest; the entry's sink is the query get's (it only
  queues an owned reply and says the leg's end from a guard it owns, D8), a pending leg now says
  which registry its entry is in, and every step sweeps both registries' deadlines, an idle read
  waiting no longer than the earlier of them. An expired snapshot delivers zenoh's timeout reply
  before its end; a cancelled token and a lost link end the leg as a query's do. pico's
  `z_liveliness_get` is the port's, sharing its fan (cancellation, leg ownership, drop order)
  with `z_get`; its `liveliness-get` feature selects neither engine. Tests: the engine against a
  router stand-in (the tokens alive on the asked key and not the one beside it, no token and the
  DeclFinal alone, a deadline, a cancel with no step, a lost link), and
  `client_only_dials_a_listener` asking the listener which tokens are alive, on both engines
  (Layer C1co, now 6 and 5 a leg).
- 2026-10-25: the unstable API on the cooperative engine (step U1). pico's `unstable-api` required
  `engine-tokio` for no reason the code held: `wz-capi-core`'s feature of that name is an empty
  marker its own code reads, and everything the ABI does behind it (entity global ids, the
  sample's reliability and source info, `z_reply_replier_id`, the cancellation token and the
  option fields that carry them) goes through the port. The feature now selects neither engine, and
  the cooperative client builds with it unchanged, which the reference pico of the test lanes
  (`-DZ_FEATURE_UNSTABLE_API`) needs of a build that stands in for it. A new size-gate case
  measures it: pico-client-coop-unstable is 894,893 bytes of text (891,491 without it), 448
  exports (441), 2.21 times the same pico. Tests: `client_only_dials_a_listener` on both engines,
  with a global id that names its session and is not the session's own, a get that refuses a
  token already cancelled (nothing sent, its closure dropped) and one that carries a token
  nobody cancels (Layer C1co, now 7 and 6 a leg).
- 2026-10-25: delivery to the session's own subscribers on the cooperative engine (step S1,
  `local-subscriber`). A put goes out on the link and then to the subscribers of the session that
  made it, as zenoh-pico's `_z_write` does: session-core's loopback fires the ones whose origin
  admits it, what they queued is handed out with no lock held (D8), so a callback runs inside the
  put, and a destination of the session alone sends nothing on the link while one of peers alone
  reaches no subscriber of its own. The loopback's sample is one assembly in session-core
  (`PublishOptions::loopback_sample`), which the tokio runtime's loopback leg now calls in place of
  its own copy. A write filter or a matching listener that counts the session's own entities counts
  its subscribers too, so a publisher matches while the session has a subscriber of its own and
  stops when it is retracted (the registry asks for the local half and is told after each local
  declaration); a plain put that such a subscriber wants gives way to the general publish. Off,
  which is pico's default build, none of it is linked. Local delivery to queryables (a get reaching
  the session's own queryable) is the next step. A new size-gate case measures it:
  pico-client-coop-local is 898,019 bytes of text (891,519 without it), 2.22 times the same pico.
  Tests: the engine against a router stand-in (a put by destination and by origin, the filter and
  the listener counting and not counting) and `client_only_dials_a_listener` (a publisher matching
  the session's own subscriber and handed a put before the call returns; Layer C1co, now 8 and 7
  a leg).
- 2026-10-25: delivery of the session's own get to its own queryables on the cooperative engine
  (step L-q, `local-queryable`). A get goes out on the link and then to the queryables of the
  session that made it, as `_z_session_deliver_query_locally` does after a send that succeeded:
  the observer's queryable only copies the query out and holds its Final, as for a peer's query,
  and what it queued is handed out with no lock held (D8), so a callback runs inside the get. The
  query is held under a generation no link has (`0`; the first link's is `1`), so its replies and
  its Final reach the get's own pending entry and never a link, and the Final is owed at once, so
  it comes when the last callback, or the last copy a callback kept, has answered. The pending
  entry expects one Final for the link's peer and one for the session; a get for the session alone
  takes a request id with the high bit set, which no id the link allocates has, and one with no
  link up asks only the session. The loopback's Query body is one assembly in session-core
  (`QueryOptions::loopback_query`), which the tokio runtime's loopback leg now calls in place of
  its own copy. A querier's write filter or matching listener that counts the session's own
  entities counts its queryables too (the registry is told after each local declaration), under
  the queryables' own switch and not the subscribers'. Off, which is pico's default build, none of
  it is linked, and pico's `local-queryable` no longer selects the tokio engine. Two new size-gate
  cases measure it: pico-client-coop-query (the requesting and answering ends) is 1,137,368 bytes
  of text, and pico-client-coop-local-queryable is 1,151,161, 13,793 more. Tests: the engine
  against a router stand-in (a get for the session alone, for any destination waiting for the
  peer and the session, for peers alone asking no queryable, a kept query holding its get open,
  the filter and the listener counting and not counting) and `client_only_dials_a_listener`
  (a get for the session alone answered by the session's own queryable, a querier matching while
  it stands; Layer C1co, now 9 a leg with the answering end and 7 without).
- 2026-10-25: the connectivity plane and the admin space on the cooperative engine (step C1).
  Both read what a session reports of its peers, so the model moved out of the tokio engine:
  `wz_session_core::face` holds `FaceSnapshot`, `LinkSnapshot`, `GroupLink`, `FaceEventKind` and
  the sink type, and builds a snapshot from a session's own `SessionLinkActions`, which both
  engines hold; `wz-capi-core` re-exports them, so the zenoh-c ABI keeps its paths. The port
  gains `face_snapshots`, `watch_faces` and `unwatch_faces` (provided answers: no faces, nobody
  told), and `ListenerSet`, a std-only fan-in the pico plane needed from `wz-capi-core`, now lives
  in the port. The tokio engine implements them over its face registry (a joined group's members
  after its unicast faces, as the plane listed them); the cooperative engine, behind its own
  `connectivity` feature, reports the one face it stands on and queues an event when the link
  comes up or is lost, handed out where its other deliveries are, with no lock held, so a sink
  that lists the transports from inside the event finds the session free. Events are queued only
  while something watches, and a watcher that came after the open reads the standing faces for
  its history, as pico's listener does. The cooperative links name their kind (`IpDriver`
  answers `link_subject`), so a link reads streamed or not; the NICs read undetermined. The pico
  modules no longer reach the tokio engine: the connectivity plane reads and watches the faces
  through the port, and the admin space declares its queryable through the port and lists the
  unicast faces (a group member is a transport the plane lists and these documents do not). The
  pico `connectivity` and `admin-space` features select neither engine; the admin space implies
  the cooperative engine's face reporting. Two new size-gate cases measure them:
  pico-client-coop-connectivity is 950,729 bytes of text and pico-client-coop-admin-space
  1,091,379; a build with neither pays 1.3 KB (878,615 against 877,351), which is the port's
  provided methods and the link kind. Tests: the engine against a router stand-in (the face it
  stands on, a watcher told of its loss and of the link dialled again, no event for the face the
  open brought up, a sink that reaches back into the session, a watcher that stopped) and
  `client_only_dials_a_listener` (a transport listed with its streamed link, a listener with
  history told of it and of its departure, the admin space answering the listener's get and
  silent once stopped; Layer C1co, now 11 a leg with the answering end and 8 without).
- 2026-10-25: scouting, step Sc1 of four: the window as a value a host pumps. `z_scout` and the
  open-time lookup run an active-scouting window: one Scout out, Hellos back, a budget. Its rules
  were in the tokio runtime's `scouting_glue` under a tokio link driver and a tokio timer, though
  nothing in them is tokio's. They are now `wz_session_core::scouting_host`: the actions and the
  Hello decode, the generated machine's builder, and a pump of free functions (`open_window`,
  `window_sent`, `window_datagram`, `window_tick`, `window_resolved`, `window_outcome`) that a host
  calls with the datagrams it received and the time it read; `ScoutWindow` holds them as one
  value. The tokio drive loop is now a shell over the pump (a `select!` between its driver and its
  timer), and `ScoutingActions` and `ScoutActionsBinding` stay nameable from the runtime as
  aliases over the session's types, so no caller moved. The behaviour is unchanged: the 15 tests
  of `scouting_glue` pass over the pump. Next: the multicast socket construction (`McastPlan`,
  its config and the interface facts under it, now in the tokio crate) into a runtime-neutral
  crate both hosts use (Sc2), a blocking window over it for the cooperative build (Sc3), and the
  pico `scout` feature without the tokio engine (Sc4).
- 2026-10-25: scouting, step Sc2 of four: the host's network facts and the multicast sockets
  leave the tokio runtime. A new crate, `wz-host-net`, holds what a hosted operating system tells
  a node about its network and the sockets built from it, with no runtime in it (`std`,
  `socket2`, `libc` or `windows-sys`). `link_interfaces` moved whole, with its tests: which
  interfaces exist and can carry multicast, which index an address selects, what an `#iface=`
  names, what an unspecified listener stands for. `multicast` is the plan under a multicast
  socket, which was private to `UdpDriver`: which interface an `#iface=` names, what an unpinned
  link joins and sends on, whether a refused membership ends the bind, the loopback policy, the
  hop limit. `bind_joined` and `bind_sender` answer a bound, non-blocking `socket2::Socket` and the
  group address its datagrams go to. The tokio runtime keeps every public path
  (`link_interfaces` is re-exported, `McastSocketConfig` stays and converts to the neutral one at
  the socket), adopts the socket with `UdpSocket::from_std` and sets `#dscp=` through its own
  socket type, which is the one thing it does not hand over. Behaviour is unchanged: the 13
  multicast-config tests of the tokio crate pass over the neutral builders, the moved tests pass
  in the new crate (32, and 41 with `locator-iface`), and the builders gained tests of their own
  (the hop limit and the default read back from the kernel, the group bind on unix, the link's
  default interface against a scout's, a membership the kernel refuses, a `#join=` of the other
  family). The crate joins the platform workflow's trigger paths, the feature-surface census
  (`locator-iface`, prose, as `wz-capi-core`'s row is) and the non-default test legs.
  `PosixGroupTransport` of `wz-runtime-posix`, which joins a group by raw `libc` for the slot
  profile, is not touched. Next: a blocking scouting window over these sockets for the
  cooperative build (Sc3), and the pico `scout` feature without the tokio engine (Sc4).
- 2026-10-25: scouting, step Sc3 of four: the blocking window of the cooperative build. A new
  feature `scout` of `wz-capi-coop` adds the module `scout`, a window a program runs on its own
  thread: the group socket is joined as an extra receive member, one ask socket is pinned to each
  interface that can carry multicast, one Scout leaves by them, and the loop reads every socket,
  pumps `ScoutWindow` and reads the host's clock until the machine resolves. It sleeps two
  milliseconds when nothing arrived and drops a member whose read fails, so one interface going
  down does not end a window the others can still answer. It is generic over the engine's
  `ClockSource`, as the engine is, and it opens no session: `z_scout` needs none, so scouting is
  a plane beside the engine and not a method of its port. The rules the window shares with the
  tokio one are no longer copies: the locator grammar, the defaults, the tick and the order the
  peers are handed over (after the window, last responder first) moved into
  `wz_session_core::scouting_host`, with their tests, and `wz-capi-core::scouting` re-exports
  them. The window's tests run over loopback sockets with a responder thread standing in for the
  group, so they need no multicast host: a survey runs its whole budget and collects every
  answer, a lookup ends at the first, a window nobody answers ends empty at its deadline, our own
  Scout and a Hello that does not decode or advertises no address are named and passed over, a
  dead ask socket does not end the window, and the group socket asks when no other can. Next: the
  pico `scout` feature and the open-time lookup without the tokio engine (Sc4).
- 2026-10-25: scouting, step Sc4 of four: pico's `scout` runs on either engine. The feature no
  longer selects the tokio engine: it names the session's scouting vocabulary and turns the window
  on in the engine the build has (`wz-capi-core?/scout`, `wz-capi-coop?/scout`), so a cooperative
  client scouts, and `z_open` with no locator finds a node, with no tokio runtime linked. The
  plane picks its window by the rule `z_open` picks the engine by (the tokio engine whenever it is
  in the build): a small `window` module with `run` and `first`, over `wz_capi_core::scouting` or
  over `wz_capi_coop::scout` with the host's clock. Pico's own copies went: its Ipv4-only locator
  parser (the session's parses an IPv6 group too) and the three defaults. The existing test of an
  open that names no locator and finds nobody runs on the cooperative build too, as a fifth leg of
  Layer C1co; the size gate gained `pico-client-coop-scout` (961,479 bytes of text, 2.34 times
  the same pico, with no symbol of the tokio engine). What this step does not witness is an
  answered window on the cooperative build: the window's own tests answer over loopback, and a
  router that answers a real multicast group is the hosted leg's. Section 6 now stands at the
  listening role and the advanced plane, then the engine flip.
- 2026-10-25: the cooperative engine's declarations take the replay cursor (phase 4 of
  `docs/declaration-sync-pacing.md`). `Core::redeclare` told the six lists to a new link in one
  call and ignored every refused send. It is now one `ReplayCursor` per link in
  `engine/replay.rs`: the lists in a fixed order are the sequence (key expressions, subscribers,
  Interests, queryables, tokens, liveliness subscribers), an entry's place is its kind's offset
  plus its index, and a link that comes up begins the cursor and sends the first turn. `poll_link`
  sends the next turn when it is due, and the read's idle wait is shortened to it, so a paced
  session moves on its own clock as the slot node does. Every live push into or removal from a
  list asks the cursor first: a declaration the replay has not reached is stored and sent in its
  turn, one behind the cursor is sent at once, a retraction of an entry the peer was told of is
  sent and one it was not told of is dropped in silence. A key expression the link refuses is not
  made and leaves the cursor as it was; any other live send that is refused counts as told, as it
  always has here. A lost or ended link discards the cursor. Without the `declaration-sync-pacing`
  policy a turn is the whole sequence, so a build with the policy off sends the frames it sent
  before, and the one change in it is that a send the link refused during the replay is retried
  from the entry it failed on, a millisecond later, and not dropped. `CoopEngine` gains
  `set_replay_pacing` (a caller that wants a pace regardless of the build) and
  `declarations_synced`. Five tests over the router stand-in: a burst a turn and an interval
  between, a declaration made during the replay told once, a retraction sent only if the peer was
  told, a replay cut short by a lost link begun again on the next, and the unpaced single turn.
  Not on this engine: `wait_declarations_stable` and a synced query, which need a reader of the
  peer's finals that the heap host's bookkeeping does not give an engine with no owned frames.
- 2026-10-25: the advanced plane, surveyed (`docs/advanced-pubsub-on-a-neutral-core.md`). The
  publisher and subscriber exist once, in the tokio crate (13,314 lines across five files, 8,486 of
  them the subscriber), and a cooperative pico build may not link that crate. The structure chosen
  is a new crate whose rules are pure and read no clock, the publisher's beacon and the subscriber
  as state machines of events and commands that each engine drives as a host, and the
  periodic jobs (heartbeat, periodic recovery queries, retention sweep) as ticks. The note
  records what each unit depends on, the five steps (neutral parts, vocabulary, publisher,
  subscriber, retirement behind a differential test and the interop tests), what a cooperative
  host cannot give (a tick is as late as the next read), and the gates each step moves.
  `time_range` exists in two readings (the tokio crate's and the zenoh-util family's), and the
  family's session agreed they stay apart. Step 1 is done: the `@adv` grammar, the `_time`
  selector and the cache ring are in `wz-ext-pubsub`, and the node's time (wall clock, node HLC,
  fallback stamper) is in `wz-node-time`, both re-exported by the tokio crate at the old paths.
  Step 2, the vocabulary, corrected the survey: the subscriber's decisions are one pure `State`
  that takes events and returns the requests to issue, so the machine moves as it is with its
  clock made an argument, and the host's part is the gets, their cancel, the two timers and the
  declarations (see the note's section "The subscriber's vocabulary").
  Step 3, the publisher, moved the composite and the plane trait to `wz-ext-pubsub` and found the
  engine port already carries what the pico plane declares, so the cooperative engine needed one
  thing added and not a set of declarations: periodic jobs. `SessionEngine::start_ticker` and
  `stop_ticker` (with `Ticker`, which stops its job when dropped) are implemented by the tokio
  session as a task of the `net` runtime and by the cooperative engine from the call that steps
  the session, where the wait of a read is cut short to the job's time and the job runs after the
  step with no lock held. The pico plane's heartbeat timer is that job.
  Step 4 moved the subscriber's options, plans and machine to `wz-ext-pubsub` and wrote its host
  over the port (`EngineSubscriber`: the declarations, the gets, the two jobs and the teardown),
  which needed one more thing of the port, the engine's own clock (`SessionEngine::now_ms`).
- 2026-10-26: pico's advanced module over the port. Its publisher and subscriber entry points
  call the neutral crates (`wz-ext-pubsub`, `wz-node-time`) and the port, and the `advanced`
  feature no longer selects the tokio engine, so a cooperative pico build declares an advanced
  publisher and an advanced subscriber. The subscriber had been declared on the tokio session's
  registry (`declare_advanced_subscriber_declaring_keys`); it is now an `EngineSubscriber` on the
  session's engine, and the background form runs it in the background where it had leaked its
  state. The tokio engine's own subscriber stays for the zenoh-c ABI and for the runtime's
  users. First witness on the cooperative engine: a subscriber declared after a publisher put is
  handed the publisher's cache and then its live puts in order (`client_only_dials_a_listener`,
  `mod advanced`, run on both engines by Layer C1co). The engine's own tests (`tests::advanced`)
  run the subscriber's host on it against a stand-in that plays the publisher, answering out of a
  real cache ring: the gap recovery, the heartbeat, the periodic re-ask and the detection of a
  publisher that appears late, each of which the scripted-engine tests had proved rule by rule
  and none of which had run on an engine, and a get answered with several replies.
- Next: the rest of section 6, one step each.
- Earlier plan note: the engine port proper. A `SessionEngine` trait holds what the single-threaded client
  calls on a session; the tokio engine implements it first, `session_state` returns the selected
  engine's session, and the modules of capabilities the cooperative engine does not have yet
  (query, liveliness, scouting, the advanced publisher) build with the tokio engine only.
- Earlier plan note: step 2, the engine port. What the ABI layer calls on the tokio engine is
  `wz_capi_core::faces::SharedSession` (publish in six forms, key expression declarations,
  liveliness, the face registry) and `drive::SessionState`; the port is the subset the
  single-threaded client calls, and the tokio engine implements it first.

## 6. Open

- The listening role, designed in section 7 and not yet built.
- How the selection is spelled on the build-configuration axis (D5).

## 7. The listening role (decision D9)

pico's `z_open` with a `listen` endpoint accepts peers, and in `mode=peer` a session is both
dialled and dialling. The cooperative engine has one link (`Core::link`, up, being dialled or
waiting to be) and one observer, so it is a client. What follows is read from the code as it
stands (`crates/wz-capi-coop/src/engine.rs`, `crates/wz-session-core/src/{observer,slot_observer,
peer_tables}.rs`, `crates/wz-runtime-coop/src/{session_drive,ip_stack}.rs`) and is a design, with
what each step proves; nothing here is built.

### What the engine holds today, and what a second peer breaks

- One `ApplicationLayerObserver` holds what the application registered (subscribers, queryables,
  local tokens) AND what the peer wrote (its key aliases, the subscribers, queryables and tokens
  it declared, its interests, the replies and Finals its queries are owed), and the requester
  side of the session's own gets. A wire id is scoped by its transport session, so two peers'
  tables cannot be one table: both number their aliases, declarations and requests from 1.
- One `Replay` says how much of the session's declarations the link's peer has been told, one
  `generation` names the link a query came in on (`QueryPlane`), one `FacePlane` snapshot lists
  the transport.
- The link layer opens a UDP acceptor that takes the first `InitSyn` and no other (`SessionLinks::
  open_acceptor`). A peer-accepting stack exists beside it, for the slot profile: `Accept<D>` and
  `IpAcceptor` (`wz-runtime-coop`), which yield one driver for each peer that connects.

### The shape: registrations once, tables per face

The tokio engine's registry (`wz-capi-core::faces`) gives each face a session and an observer of
its own and replays every application registration onto each, so one subscriber is N callbacks
and one queryable N handlers, which the port's factories (`SubscriberSink`, `QueryableSink`)
were written to allow. The fixed-memory profile took the other cut: `SlotObserverOf` holds what
the application registers, once; `PeerTables` holds what one peer writes, one set for each
session; `Requesters` holds the pending queries of one session; and `dispatch` takes the
session's tables as arguments, so one observer serves every session and holds none of their
state. That is the cut a listening engine needs, and it is not a second way of doing the same
thing: it is the same registry with the per-peer part made explicit, which the heap observer
bundles. D9 chooses it, for these reasons.

- A registration is made once and read once. A sample from two faces reaches one callback, where
  N copies of a callback would be N things to keep consistent with each other and with the C
  program's own state.
- A flood on one face fills that face's tables and no other face's.
- The two profiles stop having two implementations of the dispatch order, which the module
  documentation of `slot_observer` states "step for step" as a promise two files keep.

### What is not as is

`slot_observer` is compiled only with `bounded-heapless` (the fixed backing, which flips the
build's whole storage policy to static), and its `dispatch` takes `PeerTables` and `Requesters`
of the build's policy. A heap build cannot name it. `PeerTables<P: Storage>` is already generic
over the policy, and `Requesters<R, G>` over the reply sinks, so the work is in the observer: its
dispatch and drain made generic over the policy, ungated from `bounded-heapless`, and held equal
to `ApplicationLayerObserver::dispatch` by a differential (the same events into both give the
same sends and the same deliveries). The AP observer stays as the tokio engine's until it is
rebuilt as `SlotObserverOf<HeapSinks>` over one `PeerTables<Heap>` and one `Requesters`, which is
the end state and is not this work.

### The steps, each of which stands alone and proves what it says

- **L0. The observer, generic.** `SlotObserverOf`'s dispatch over `PeerTables<P>`, in a heap
  build, with the differential against `ApplicationLayerObserver`. Nothing in the engine moves.
  Proof: the differential, and `session-core`'s existing tests on both profiles.
- **L1. The engine on it, with one link.** `Core` holds a `SlotObserver`, the link's
  `PeerTables<Heap>` and its `Requesters`, and dispatches against them. No behaviour change: the
  engine's whole test suite and the size gate's cooperative cases (whose budgets leave almost no
  margin) are the proof, and the cases are measured before and after on one machine.
- **L2. A face table of one.** `Link` becomes a face: its id, its wire, its tables, its
  `Replay`, its `generation`, its requesters; `Core` holds a table of them, the dial role's one
  entry at a fixed id as `wz-capi-core` keeps `DIAL_FACE_ID`. A get is one leg for each face up,
  which the port's `get_on_wire` already returns as a count; a publish goes to every face; a
  write filter and a matching listener count the remote declarations of ALL faces
  (`peer_matches` reads the table); an answer to a query goes to the face whose generation it
  carries; a face event is reported for each face. Still one face, so the proof is again the
  existing suite, plus the new unit tests of what the table decides with two faces on a
  scripted link.
- **L3. The acceptor.** The face table takes a face when the accept side yields a link, and
  loses it when its lease ends or its peer closes. The link layer's `SessionLinks` gains the
  accepting side: `Accept` over the host's `tcp/` listener first (it exists for the slot profile
  and is ungated from `session-slot` here), and UDP, by source-address demultiplexing, as its own
  sub-step once the stream case stands; `read` waits on
  the readiness of every link and not one (today `IdleWait::Input` is one `LinkReadiness`; two
  links need either a multiplexed wait or a bounded one, and the choice is measured). Proof: a
  listener session and two clients of the same engine in one process over loopback, each client
  declaring and putting, the listener's subscriber hearing both and a get reaching both.
- **L4. The ABI.** pico's `z_open(listen)` and `mode=peer` on the cooperative engine: the feature
  `peer` stops selecting the tokio engine. Proof: Layer C1co's legs with the full build's
  `hold_a_listener` as a client of the cooperative listener, the pico interop against the real
  zenoh-pico for both roles, and a size-gate case for a cooperative peer.
- **L5. Both roles at once.** A peer that listens and dials: the dial role's face and the
  accepted ones in one table, one face for each remote zid as the tokio registry keeps (a node
  the session is already linked to is not given a second face).

### What is decided and what is open

Decided: one registration table and per-face tables (D9); the dial role keeps a fixed face id
and the accepted faces take ids beneath it, as `wz-capi-core`'s do; a sample that arrives from
two faces is delivered twice, as a peer that forwards would deliver it twice in zenoh-pico; the
engine's one session lock stays, and a face's callbacks still run outside it (D8).

Open, to be settled by the step that meets it and not before: how `read` waits on several links
(L3); whether the bound of faces is a build constant or the config's; the order in which a new face is told the session's declarations when the session
is already large (`Replay` is paced per link today); whether a face's `PeerTables` are kept or
dropped when its link is lost and redialled (the dial role redials; an accepted face does not,
its peer dials again and is a new face).

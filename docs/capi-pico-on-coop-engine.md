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
- Next: the capabilities in section 6, one step each.
- Earlier plan note: the engine port proper. A `SessionEngine` trait holds what the single-threaded client
  calls on a session; the tokio engine implements it first, `session_state` returns the selected
  engine's session, and the modules of capabilities the cooperative engine does not have yet
  (query, liveliness, scouting, the advanced publisher) build with the tokio engine only.
- Earlier plan note: step 2, the engine port. What the ABI layer calls on the tokio engine is
  `wz_capi_core::faces::SharedSession` (publish in six forms, key expression declarations,
  liveliness, the face registry) and `drive::SessionState`; the port is the subset the
  single-threaded client calls, and the tokio engine implements it first.

## 6. Open

- The read task steps its session in a loop with no idle wait; pico's read task sleeps
  `Z_RUNTIME_IDLE_READ_TASK_SLEEP` when nothing was read.
- The listening role. pico's `z_open(listen)` holds several peers in one
  session; the cooperative session host holds sessions in slots, and whether
  one C session maps to several slots or to one multi-face session is a design
  question of its own.
- Scouting, the advanced publisher and subscriber, and the connectivity plane
  on the cooperative engine.
- How the selection is spelled on the build-configuration axis (D5).

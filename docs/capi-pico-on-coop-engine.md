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
   `zenohd` and against pico itself.
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
- Next: step 2, the engine port. What the ABI layer calls on the tokio engine is
  `wz_capi_core::faces::SharedSession` (publish in six forms, key expression declarations,
  liveliness, the face registry) and `drive::SessionState`; the port is the subset the
  single-threaded client calls, and the tokio engine implements it first.

## 6. Open

- The listening role. pico's `z_open(listen)` holds several peers in one
  session; the cooperative session host holds sessions in slots, and whether
  one C session maps to several slots or to one multi-face session is a design
  question of its own.
- Scouting, the advanced publisher and subscriber, and the connectivity plane
  on the cooperative engine.
- How the selection is spelled on the build-configuration axis (D5).

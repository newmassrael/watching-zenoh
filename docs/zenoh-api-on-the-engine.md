# The zenoh Rust API over wz's engine (the seam of the top crate)

Status: design note, second draft after an independent review that found its first draft wrong in
eleven places of fact and unproven in its central choice. It states what is measured, what is
decided, what is a hypothesis to be tried before it is decided, and what is open. It is not a
specification and the atomic store does not parse it. It is the seam that
`docs/build-configuration.md` C13a requires to be written and reviewed before any path of the top
crate is: no file of `crates/wz-zenoh` carries an item until the acceptance test of section 5 has
been run. Decisions follow the standing criterion of this tree (the long-term correct design, cost
not counted); the reason for each is next to it.

## 1. The question

The twelve lower crates of the family (`zenoh-result` to `zenoh-config`) are landed, each equal to
upstream's by its surface and by differential tests. The thirteenth, `zenoh`, is behaviour: a
session that opens, scouts, publishes, subscribes, queries, answers and watches liveliness. C13a
says it is an upstream-shaped surface over wz's own session engine and never a second
implementation of upstream's session beside it. This note answers where exactly the surface ends
and the engine begins, what each side owns, which engine, and in what order the paths are written.

## 2. What upstream's `zenoh` is made of (measured on the pinned source, 2026-10-25)

- **`api/`, 19,466 lines.** The public API: `session.rs` (3,763 lines), the builders, `publisher`,
  `subscriber`, `queryable`, `querier`, `query`, `liveliness`, `matching`, `scouting`, `info`,
  `connectivity`, and the data types (`bytes`, `encoding`, `key_expr`, `selector`, `sample`,
  `handlers`, `config`, `timestamp_stack`, `cancellation`).
- **`net/`, 26,044 lines.** Upstream's engine: the runtime and its orchestrator, the routing tables
  and four hats (client, peer, router, broker), the interceptors, the admin space, the namespace
  decorator (a module of `net/`'s routing) and the protocol planes.
- **The join is not a handful of names; it is a seam upstream already cut.** `api/` is generic over
  a runtime: `Session` holds a `GenericRuntime` built from a
  `RuntimeBuilder`, and `api/` names `IRuntime` (about 18 methods: scouting, matching status by
  destination, the timestamp-stack instant, transports and links, the face id, the HLC) behind
  `DynamicRuntime` / `WeakDynamicRuntime` (the trait and its wrappers sit in the runtime module of
  `net/`). Below that,
  `Primitives` (7 methods) and `EPrimitives` (6) carry the network messages
  (the primitives module of `net/`). `Session` is both the owner of the API's state (its
  subscriptions, queryables, pending queries, declared resources, callback groups) and the
  `EPrimitives` of its own face. `api/` also uses `zenoh-transport`, `zenoh-link` and `zenoh-task`
  inside its code (`connectivity.rs`, `info.rs`, `session.rs`, `scouting.rs`, `admin.rs`); none of
  their types is in a signature.
- **The public surface names landed crates, and a few third-party ones the family already
  depends on.** The three committed arms name `zenoh_protocol`, `zenoh_keyexpr`, `zenoh_config`,
  `zenoh_core`, `zenoh_util`, `zenoh_result`, `zenoh_buffers`, `zenoh_macros` (the unstable arms
  only), `zenoh_shm` (the shared-memory arm) and `uhlc`, `serde_core`, `futures_core`. No further
  family crate is owed (the plugin and `internal` surfaces are outside the arms, C13).
- **The behaviour gate exists upstream, and half of it needs a router.** `zenoh/tests` holds 31
  integration test files and `examples` 31 programs; `zenoh-ext` is the ecosystem crate. 24 of the
  31 tests carry a `cfg` on `unstable`, `internal`, `shared-memory` or plugins, and 15 open
  sessions in router mode. A separate `regions` target needs `internal`, which the arms leave out.

## 3. What wz has

- **An engine with a Rust API of its own.** `wz-runtime-tokio` carries `Session<R, T, Tp>` with
  publisher, subscriber, queryable, querier, liveliness, matching listeners, held queries and an
  admin space (`crates/wz-runtime-tokio/src/session/`, 31,576 lines with its tests). One such
  session is one unicast peer. It has its own six-runtime pool (`runtime_pool.rs`).
- **A face registry above it, which only pico's ABI reaches through the port.** `wz-capi-core`
  holds the model a C session needs and a Rust session needs too: one session and N peers, a
  declaration store replayed onto each face as it comes up, one thread and one runtime per session
  (`drive.rs`: `new_current_thread` or `new_multi_thread` per session), the race-free close and the
  drop-outside-the-lock discipline. It opens through `drive::open_blocking`.
- **A port with two clients, one of which is not the zenoh-c ABI.** `wz-capi-port` is the
  vocabulary an ABI and an engine both name (ids, callback factories minted once per face, the held
  query, `SessionEngine` of about 35 methods, `SessionDrive`, the cancellation module). Only
  `wz-capi-pico` goes through it. The zenoh-c ABI does not: `wz-capi-c` has no dependency on
  `wz-capi-port`, and `wz-capi-c` names `wz-runtime-tokio` 245 times (`docs/capi-pico-on-coop-engine.md`
  D4 keeps it on that engine). The port states what it lacks: scouting and the advanced publisher
  (`engine.rs`:15-19), and `SessionDrive::as_any` is the downcast by which an ABI reaches what the
  port does not carry (`capi-pico-on-coop-engine.md` D7). **The port has no `open`**: each engine
  opens its own way (`wz_capi_core::drive::open_blocking`, `wz_capi_coop`'s `open`).
- **Two engines for the pico ABI, one for zenoh-c.** The tokio engine (threads, one runtime per
  session) and the cooperative engine (no runtime at all, stepped by the caller or by two threads,
  under one lock).

## 4. Decisions, and the one hypothesis

- **D1 (hypothesis, tried in section 5 before it is decided). The seam is the port.** The
  `zenoh` crate is an API layer over `wz-capi-port`, as the pico ABI is. The reason: it is the
  only choice that puts the session's state (consolidation, pending replies, local delivery,
  declaration replay, the capacity model) in ONE place, the engine's, and leaves the top crate
  with handles and conversions. The strongest argument against it is upstream's own: `IRuntime`
  plus `Primitives` is already the join, upstream's session module is already generic over it, and the hard
  paths are all bookkeeping in that file, whose behaviour upstream has tested for years; deriving
  it and giving it an engine-backed `IRuntime` would inherit that behaviour, and the port as it
  stands is smaller than what the Rust API asks. Both are true. The first rejected alternative
  (derive upstream's session module over a wz `Primitives` that carries the messages into the FSM) keeps
  two copies of the session tables, which C13a refuses and which would disagree on the first race.
  A third form is open and is what the spike measures against: derive `api/`, **delete from it
  every table the engine already owns** (local delivery, pending queries, declaration replay) and
  put the engine-backed operations behind `IRuntime` where upstream's seam already is. Which of
  the two forms the port grows into is decided by the numbers of section 5, not by this note.
- **D2. The crate has data modules and behaviour modules, and the line between them is drawn
  per module before Z0.** *Data modules* hold no engine and are DERIVED from upstream's files with
  the notice block (`scripts/lib/family_notice_gate.py`), held by the same differential tests as
  the lower crates. A first count by module prefix puts 289 of the 709 default lines (41 percent)
  in `bytes`, `key_expr`, `sample`, `qos`, `handlers`, `config` and `time`; **the count is a
  starting guess, not a classification**, because two of those modules reach the session:
  `KeyExpr` holds an `Arc<KeyExprWireDeclaration>` whose `session` is a `WeakSession` and whose
  drop undeclares the prefix, and `Sample` holds a `KeyExpr`; `Session::new_timestamp` and a
  `Sample` built from an engine frame are behaviour. The declaration is made an erased anchor
  (the port's `WireKey::keeping(Arc<dyn Send + Sync>)` is that shape), so a data module names no
  engine; where it cannot be erased the path is a behaviour path.
- **D3. A handle is an id and an `Arc` of the engine, and dropping it undeclares.** `Publisher`,
  `Subscriber<H>`, `Queryable<H>`, `Querier`, `LivelinessToken`, `MatchingListener` hold the id the
  port returned and the session; `background()` hands the lifetime to the session; `close()` is the
  engine's race-free close. A user callback is wrapped as a factory and released outside every
  engine lock.
- **D4. Builders are data and resolve through the engine; a blocking resolve inside a callback
  must not deadlock.** `Resolvable`, `Wait` and `IntoFuture` are upstream's contracts (landed in
  `zenoh-core`). The future form completes from the engine's callback through a channel that needs
  no executor of the user's. The blocking form is a problem of its own: the tokio engine with
  `FaceDrive::Serial` and the cooperative engine run every callback on the one thread or under the
  one lock, so `get().wait()` inside a subscriber callback blocks the thread that would deliver
  the reply. (`FaceDrive::PerFace`, zenoh-c's drive, runs each face on a thread of its own and
  is the likely default for a Rust session; the point is to test it, not to assume it.) Upstream
  avoids it with `block_in_place` on its multi-thread runtime. The rule is
  fixed in Z1, with a test that does exactly this on each engine, and an engine that cannot
  satisfy it refuses the combination at open with a named error; it is never left to hang.
- **D5. Which engine, and how it is selected, is decided before Z1.** The Rust crate must open a
  session and the port does not open one. Decision: the `zenoh` crate depends on ONE engine per
  build, chosen by a Cargo feature that is part of the build-configuration catalogue (C1), the
  tokio engine by default (it is the one with faces, scouting and the router data plane) and the
  cooperative engine as the selection that the pico work already measures. The port gains an
  `open` of its own only if both engines can implement the same signature without a downcast;
  until the spike says so, `zenoh::open` names the selected engine's open through a small trait
  in the top crate, not in the port. Pools: the tokio engine already has `WzRuntime` and the
  per-session runtime comes from `wz-capi-core`; the cooperative engine has none. The fold onto
  the family's `zenoh-runtime` pools (landed) applies to the tokio engine's two creation points
  and is a deliverable of the first slice that opens a session; it does not apply to the
  cooperative engine.
- **D6. `Config` maps onto the engine by a table; a key that has an effect and is unmapped is
  refused at open.** Each key of `zenoh_config::Config::keys()` is in one of three states kept
  beside the code: mapped to a policy, accepted because it changes nothing wz has, or refused with
  an error naming the key. A test walks every key of the default configuration, so a key added by
  a pin bump fails until it has a state. The keys that tests of upstream exercise (acl,
  authentication, low pass, downsampling, qos overwrite, namespace, admin space, open time,
  connection retry, tcp buffers) are named in the table as owned by a later slice or as refused;
  none is left to fall through. **Namespace is not an API path**: upstream implements it as an
  `EPrimitives` decorator pair that rewrites every key crossing the face, local delivery included,
  with a table of pending declarations. wz has it only inside the tokio engine's transport
  (feature `routing-namespace`). It enters as an engine policy by the rule of section 5 of
  `build-configuration.md`, in its own slice, not as an operation of the port.
- **D7. Where upstream and the engine differ, the difference is stated and held, and the default
  is upstream's (C2).** Each is a class of the differential test with the words of both
  behaviours. Known already: the engine's `interfaces` of a link is three-state where upstream's
  is not; the engine's `watch_faces` is "from now on" where upstream's link listener offers
  history.
- **D8. The crate is renamed in its first slice.** `crates/wz-zenoh` becomes the package `zenoh`
  when it declares its first public item (the data slice): the `[patch]` mechanism swaps by
  package name, and `family_notice_gate.py` ends the facade's exemption the same day.

## 5. The acceptance test of D1: a spike before Z0

No path of the crate is written until this has run, and it is the first work of the next slice,
written to be discarded. On BOTH engines, through the port, the three hard paths below are made
to work against a real peer, and each gap found is recorded as a port addition with its size:

- **(a) A querier with a matching listener and `matching_status`, by locality.** The port's
  listener counts `count_local: bool`; upstream's destination is a three-way `Locality`, and
  `matching_status` is a one-shot question with no filter id. Also `wait_callbacks()` on undeclare,
  which the port has no barrier for.
- **(d) Namespace.** A session with `namespace` set, local delivery included: it is the case that
  cannot be an operation of the port, so it shows whether a policy at the face boundary fits the
  seam.
- **(e) `Session::info().links()` with `link_events_listener(history = true)`.** The engine's
  `face_snapshots` and `watch_faces` are two calls; history needs one atomic call, and
  `auth_identifier`, `priorities`, `reliability` and `is_streamed` are not in the engine's
  link record.

The result is a table: per path, backed / needs an addition (with the signature) / no model. D1 is
accepted if the additions are operations that both engines can implement and that the two C
ABIs leave unchanged. It is **rejected** if the additions grow the port into a copy of
`Primitives` plus the session tables, and the third form of D1 (derive `api/`, delete the tables
the engine owns, put the operations behind `IRuntime`) is then written up and reviewed the same
way. The spike also measures what each form costs in lines of the top crate, since C13a asks for
the form that is smaller and not the form that is nearer.

### 5.1 The first pass: read, not run (2026-10-25)

The first pass read the three paths against both engines' code and recorded what each needs. It
did not run a peer; a path that was only read is marked so, and Z1 is where the first of them is
run. What it found:

| path | what the engines have | what the port or the engines must gain |
|---|---|---|
| (a) matching, by locality | Both engines compute a match as a peer's declaration, or with `count_local` one of the session's own (`wz-capi-core/src/faces.rs`, `plane_matches` in `wz-capi-coop/src/engine.rs`); the cooperative engine's criterion already carries a `Locality`. | `count_local: bool` becomes a `Locality` (`Any`, `Remote`, `SessionLocal`): a `count_remote` half beside the existing `count_local`, in one place per engine. A one-shot `matching_status(plane, key, locality)`: the engines read the same two halves for a listener, so it is a read of existing state. `wait_callbacks()` on undeclare has no barrier in either engine (the registry removes the entry and the face's watch, then returns while a delivery may be in flight): it needs a delivery epoch and is the one item here that is a new concept, tied to D4. |
| (d) namespace | `wz-session-core` already carries the decorator (`namespace::apply_egress` and the stateful `NamespaceIngress`, feature `routing-namespace`), written as the mirror of upstream's; the tokio engine wires it. In upstream the decorator sits between the session and its face and rewrites wire expressions only, so a session's own publishes reach its own subscribers with the keys the user wrote: the namespace is visible on the wire and nowhere else. | No port operation: an open-time option, read at the face boundary where the decorator already sits. The cooperative engine does not wire `routing-namespace` (its manifest has no such feature), so on that engine the key is refused at open by the table of D6. That is the first case where the two engines differ in what they can open, and it is a reason the D6 table is per engine. |
| (e) links and history | Both engines implement `face_snapshots`, `watch_faces` and `unwatch_faces`; a link carries `src`, `dst`, `kind`, `interfaces`, `mtu` and `group`; `is_streamed` is a method of the kind, and zenoh-c's reliability is derived from it. | `auth_identifier` and the QoS `priorities` are not in the link record: two optional fields added to `LinkSnapshot` (a type of `wz-session-core`, so the C ABIs ignore them). History needs one atomic call that returns the snapshot and the watch id under one lock, which the two separate calls cannot give; it is an addition to the port with a provided default. The three-state `interfaces` stays a D7 class. |

Reading of the table. Every addition is an operation or a field that both engines can implement
from state they already hold, with a provided default so that the pico ABI is unchanged, and none
asks the port to carry a session table. The exceptions are the delivery barrier of (a), which is
new and small, and the cooperative engine's lack of the namespace policy, which is a refusal and
not a gap of the seam. On this reading D1 stands for these three paths and is NOT yet accepted:
the evidence is a read, the paths of Z2 to Z4 are harder (the zero-copy payload, the held query,
consolidation by the caller), and the third form of D1 stays the fallback. The decision is taken
again at the end of Z3, from the list of port additions the slices produced and what each cost,
and D1 is dropped if that list has grown to the size of `Primitives` and the session tables.

## 6. The slices, in order (after the spike)

Each lands whole with its surface lines, tests and faults in one round.

- **Z0. The data modules and the rename.** Classified per module first (D2).
- **Z1. Open, close, identity, config table, the choice of D5 and the rule of D4.** `zenoh::open`,
  `Session::zid`, `close`, `is_closed`, `id`, `config`, `info` (routers and peers only). The
  first slice that names an engine. Router mode is decided HERE and not later: 15 of upstream's 31
  tests open one, so a refused `mode: router` means the Z8 gate cannot be met, and the decision
  is either to carry router mode in the top crate through the engine's router data plane
  (`docs/router-data-plane-scaling.md`) or to record that half of the gate does not apply.
- **Z2. Publish and subscribe.** `put`, `delete`, `declare_publisher`, `declare_subscriber` with
  the handlers the surface has (callback, callback with a drop, the default handler, fifo, ring),
  QoS, attachments, encodings, localities, express, congestion control, `new_timestamp`, the
  zero-copy payload (`ZBytes` over the engine's received bytes, which no adapter does today),
  `declare_keyexpr` and `undeclare` (a key declared by another session is an error upstream).
- **Z3. Queries.** `get`, `declare_queryable`, `Query`, `Reply`, `declare_querier`, consolidation,
  targets, timeouts. (`cancellation` is an unstable-arm item and belongs to Z6.)
- **Z4. Liveliness and matching.**
- **Z5. Scouting.** Scouting is not in the port; it is the slice that decides whether the port
  gains it or the crate reaches it through the engine, and it contradicts "names no runtime" unless
  the port gains it.
- **Z6a. The unstable arm: information.** `info().links()`, `transports()`, the link and transport
  event listeners, `connectivity`.
- **Z6b. The unstable arm: timestamps and cancellation.** The timestamp stack (53 surface lines,
  48 upstream tests, no model in wz's engine: it needs one), `cancellation`.
- **Z6c. The unstable arm: the rest of the session, query, key expression, sample and config
  lines.**
- **Z7. The shared-memory arm.** `get_shm_provider`, the provider state and the transport.
- **Z8. The graph.** Upstream's tests and examples and `zenoh-ext` built and run against the
  patched graph, on Linux and on Windows. A test that cannot pass is a recorded difference with its
  reason, never a deleted test.
- **Owned slices for the configuration-driven features** named in D6 (acl, authentication, low
  pass, downsampling, qos overwrite, namespace, admin space, connection retry, tcp buffers): each is
  a slice or an explicit, recorded refusal; none is implicit in Z1.

## 7. The proof, by layer

1. **Surface.** `scripts/lib/rust_api_surface.py` per arm; the ratchet falls from 709, 965 and
   1,025 to 0.
2. **Differential tests (`conformance/differential`).** The data modules as the lower crates are.
   For behaviour, the same program runs against upstream's `zenoh` and the wz crate side by side
   in the one test process and a transcript of what each saw is compared, including the text of
   each error. Two-node programs run three ways: upstream with upstream, wz with wz, and upstream
   with wz over TCP and over multicast, so the wire is held as well as the API.
3. **Upstream's own tests and examples against the patched graph** (Z8).
4. **Injected faults** over each slice's tests, as the lower slices were.
5. **Size.** A size-gate case from Z1 for the API layer over each engine, measured against
   upstream's `zenoh` built with the same switches (the baseline is named here because the
   cooperative engine's earlier measurements were against pico, which is not this crate's
   comparison).

## 8. What is open

- **O1. The port's gaps are per path and are measured by the spike (section 5), not listed here.**
- **O2. Error wording.** Upstream's errors are boxed text. How much of the wording a consumer
  depends on is answered by Z8; until then each difference is a D7 class.
- **O3. Whether the top crate ever names both engines in one build.** D5 chooses one per build;
  a program that wants both would be two processes.

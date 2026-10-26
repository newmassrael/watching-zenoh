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

### 5.2 What Z1 meets first: the open (read, 2026-10-26)

Z0 is landed, so the next thing the crate needs is a session, and the read of what an open takes
found that the port is not where it starts. The port has no `open` (section 3); the open that a
program of upstream's API means, `open(Config)`, is made today in one place only, and that place
belongs to the zenoh-c ABI:

- `z_open` (`wz-capi-c/src/session.rs`, 300 lines from `open_session`) reads a stock zenoh
  config through `ZenohNodeConfig::from_json5` (`wz-runtime-tokio/src/zenoh_config.rs`, which is
  already the table of D6: it names the keys it honours and keeps the lists of those it does not
  as `UNHONOURED_BEYOND_WZ` and `UNHONOURED_READER_GAP`, graded by a gate), decides the role,
  the endpoints to dial and to listen on, the groups, the scouting plan, the gossip policy, the
  authentication and the traffic policy, the TLS material, the offer of the handshake and the
  clock, and calls `wz_capi_core::drive::open_blocking` with an `OpenStance` of fifteen fields.
  What it returns is a `SessionState`, which the port reaches as a `SessionDrive`
  (`wz-capi-core/src/engine_port.rs`) and whose `shared` registry implements `SessionEngine`.
- Of those 300 lines, the ones that belong to the C ABI are the reading of a `ConfigState` (the
  C program's inserts), the error codes (`Z_EINVAL`, `Z_ENETWORK`, `Z_ENULL`) and the shared-memory
  provider hung on the session as its extension. The rest, about 230 lines, takes a document and
  answers a stance or a refusal, and names nothing of C.
- The crate's feature set already forwards upstream's names (`transport_tls`, `auth_pubkey`,
  `transport_compression`, `interceptors`, `scout`, `peer`, `gossip`, ...) down to `wz-capi-core`
  and `wz-runtime-tokio`, each on by default exactly when it is in zenoh-c's default set.

- The open already takes `mode: router`: the role is read from the document (`WhatAmI::Router`),
  a router's default listener is `tcp/[::]:7447`, its open is held for `scouting/delay` in full
  (R3125) and its clock stamps by default. So the decision Z1 was to take about router mode, carry
  it or record that half of Z8's gate does not apply, is taken by the existing open: it is carried,
  and Z1b has to test it, not build it.

So D5 is answered for the tokio engine by what exists, and D6's table is not to be written: it is
the reader above, and `zenoh::open` must be a second client of it. Two ways to be one:

1. **Copy the 230 lines into the top crate.** Fast, and it is two copies that disagree on the
   first config key anyone adds; it is what C13a refuses.
2. **Lift them out** into a function that takes the document, the dialled endpoints and the role,
   and answers `Result<OpenedSession, OpenRefusal>` with the refusal's class (the config is
   invalid, or the network could not be reached), beside the reader that `wz-capi-c` and the top
   crate both name; `z_open` shrinks to its C half and maps the refusal to a code. This changes a
   landed ABI crate, so its comparison lanes against zenoh-c are what show that nothing moved.

The second is chosen, and its form is the textbook one, three layers with one direction of
dependence, not a function moved:

1. **A plan, as a value.** `OpenPlan` is what a document means: the role, the endpoints to dial
   and to listen on, the groups, the scouting and gossip policies, the authentication and traffic
   policy, the offer of the handshake, the clock, and the capabilities the document REQUIRES
   (a listener, a group, access control, a namespace). It is made by a pure function of the
   document (no socket, no thread, no clock), and its refusal is typed: each variant names the key
   path that caused it. A pure plan can be tested on every role and every refusal without a
   network, compared against upstream's own validation of the same document, and printed.
2. **An engine factory.** `open(plan)` is an operation of an engine, not of a client: each engine
   declares the capabilities it can honour and answers a plan that requires more with the typed
   refusal naming the key (the cooperative engine has no namespace, which is how D6's table comes
   out per engine). The tokio engine's factory is `open_blocking` with the stance made from the
   plan; the cooperative engine's is `wz_capi_coop::open`. The trait joins the port when the
   second engine implements it, as the port's own rule says; until then the tokio factory is a
   function beside the plan.
3. **Clients that map.** `z_open` maps a refusal to `Z_EINVAL` or `Z_ENETWORK`, `zenoh::open` maps
   it to upstream's error text, and neither holds a line of config logic.

The lift is proved by a characterisation first: the outcomes of the current `z_open` on a corpus
of documents (every role, every refusal named in the 300 lines, the build's missing features) are
recorded before the move, and the same corpus must give the same outcomes after it, beside the
lanes that run `z_open` against zenoh-c.

Z1-pre is the first layer and the tokio factory, with `z_open` calling both. It landed as
`wz_capi_core::open_plan` (feature `open-plan`, on in the core's default set and named by the
zenoh-c ABI; the pico ABI leaves it off and compiles none of it): `OpenPlan::resolve(role,
stated endpoints, document)` is the pure reading with twelve typed refusals that each name their
key (`OpenRefusal::key`), `AbiChoices` carries what is an ABI's and not the document's, and
`OpenArguments::run` is the tokio factory. The corpus of the characterisation is
`wz-capi-c/tests/open_refusals.rs` (nine refusals, recorded on the code before the move and held
after it) and the plan's own golden descriptions, which hold no secret. Two readings are still the
caller's: the C ABI reads `connect` and `listen` from its flat key store, and Z1a will read them
from the document's own resolution; a difference between the two for a table-form endpoint is a
behaviour question to record when Z1a meets it, not one to change silently. The top crate then
takes the engine by a feature of the build (D5) and reaches the session by the port, as the pico
ABI does, for everything but the open itself.

Z1 is therefore cut in four, each landing whole: **Z1-pre** the lift; **Z1a** `Session`, `open`,
`close`, `is_closed`, `zid`, `id`, `config` over it, with the anchor of the key expression
implemented and the default handlers' size read from `Config`; **Z1b** the router mode and the
refusal of every key that has an effect and is unmapped (the test of D6 over the default
configuration); **Z1c** `info` and the rule of D4 with its test on this engine. The cooperative
engine is selected by a feature in Z1a as a refusal that names the feature, and gets its own open
when the port gains one (its `open` is `wz_capi_coop::open`, with its own arguments).

## 6. The slices, in order (after the spike)

Each lands whole with its surface lines, tests and faults in one round.

- **Z0. The data modules and the rename**, in parts, because the modules are not as separate as
  D2 hoped. Measured on the pinned source by what each file names of the crate: `bytes` names
  nothing (only links in its documentation); `encoding` names `bytes`, `query` and `sample` only in
  its documentation; `key_expr` names the session in ten functions that are all `pub(crate)`;
  `selector` names `Query`; `sample` names `builders::sample`, `handlers`, `key_expr` and the
  publisher's `Priority`; `handlers` names `pubsub`, `query` and `session`; `cancellation` and
  `config` name only themselves. So the first part is exactly the closure that names nothing:
  - **Z0a (landed).** The rename of `wz-zenoh` to the package `zenoh`, the `bytes` module (`ZBytes`,
    its reader, writer and slice iterator, `OptionZBytes`, `Encoding`) and the `shm` module without
    its provider state: 59 of 709 default lines, 115 of 1,025 in the shared-memory arm, 13 injected
    faults, the family notice gate taking the top crate (its resolution arm now reads the top crate
    from `zenoh/` of upstream and not from `commons/`). The shared-memory arm is tested in
    `conformance/differential-shm`, because with `shared-memory` the protocol's types change and
    one package takes one setting of a feature. The doctests are off in the manifest until `open`
    has a body, with the reason beside the switch.
  - **Z0b (landed).** `cancellation`: the token of the `unstable` arm (`CancellationToken`) and, with
    `internal`, the group under it (`SyncGroup`, `SyncGroupNotifier`). It was filed under Z6b in the
    first draft; the measurement above puts it here, because it names only itself, and Z6b keeps the
    timestamp stack. 7 of the `unstable` lines and 7 of the shared-memory arm's, 7 injected faults
    (one test gap found and closed: a failed cancel must not wait for a notifier that is held). The
    helpers upstream calls from the builders of `get` are unused until Z3, so the module carries
    `allow(dead_code)` with the reason beside it.
  - **Z0c, `config` (landed).** `Config` (read from a file, the environment or a JSON5 string;
    keys read, inserted and removed; the items of an array by their `id=`; with `unstable` the
    deserializer and the `Deref` to the crate under it) and its notifier (`unstable`, with
    `plugins` its subscription), over `zenoh-config`; the root re-exports `Config`, `Resolvable`,
    `Resolve`, `Wait`, `Error`, `Result` and the two log initialisers, because a signature's
    return type names `zenoh::Result` only where that re-export exists (the surface gate showed it
    by reading `zenoh_result::ZResult` where upstream has `zenoh::Result`). 30 of the default
    lines and 43 of the `unstable` and shared-memory arms' lines, 11 differential tests and 11
    injected faults (one test gap found and closed: a key with no `field=value` is not an array
    operation and must tell nobody). The example in the documentation of `Config` is a 967-line
    file of upstream's, copied, and a test holds the copy byte for byte to the pinned crate's.
  - **Z0c, `handlers` (landed).** `Callback`, `CallbackDrop`, `IntoHandler`, `DefaultHandler`, the
    FIFO channel with its iterators, future and stream, and the ring channel, which names nothing
    of the session but the size of its default channel: of `session.rs` only that one constant is
    here (the file is a partial derivative, and says so in its header), and the other three sizes
    come with the slices that read them. 89 lines of each arm, 12 injected faults, none missed.
    The callback helpers upstream calls from the builders (`set_on_drop`, `call_with_message`) are
    unused until Z2 and Z3, so the module carries `allow(dead_code)` with the reason beside it.
  - **Z0c, `key_expr` and `selector` (landed).** `KeyExpr` with all its constructors and
    conversions and `Selector` with `ZenohParameters`, over the crate that holds the language. The
    wire declaration of a key is the erased anchor of D2: where upstream's declaration holds a
    `WeakSession`, this one holds a `Weak` of the trait `WireAnchor` (declare a prefix, undeclare
    one), which the session of Z1 implements, so the module names no session. This is a change of
    upstream's file and not a copy with a header: the functions that took a `&Session` take the
    anchor of one, `UndeclarableSealed` joins `Session::undeclare`, and `From<&Query> for
    Selector` joins `Query` in Z3. The public module `query` is partial and says so. The keyexpr
    crate gains `get_nonwild_prefix`, an item of its `internal` arm that `KeyExpr` needs. 59 of
    the default lines and 79 of each other arm's, 8 differential tests, 7 unit tests of the anchor
    with a session that is a counter, and 14 injected faults, none missed (one canonizer
    difference of the keyexpr crate, recorded where it was found, kept out of the strings).
  - **Z0c, `sample` and the quality-of-service types (landed; Z0 is complete).** `Sample`,
    `SampleBuilder`, `SampleFields`, the kind and the locality of a sample, `SourceInfo`, the
    priority, the modules `qos`, `time`, `timestamp_stack` and the identifiers of `session`, and the
    `internal::traits` the builders implement. The closure was wider than the two files: `Sample`
    reads the priority, which upstream keeps in the publisher's file, and the timestamp stack, which
    keeps a function that asks a runtime for the node's clock. So `publisher.rs` is here as a
    partial derivative holding the priority only, `timestamp_stack.rs` is here without
    `push_ts_interception` (Z6b), `builders/sample.rs` without its two `internal` conversions of a
    publication builder (Z2), and `session.rs` still only holds its one constant. 90 of the
    default lines and 163 of each other arm's, 6 differential tests (one of them runs
    `from_message` as the runtime of a session does, over 336 combinations of frame, quality of
    service, reliability and stack) and 16 injected faults, none missed. With this part the data
    modules of upstream's crate are all here; what remains is behaviour, and it starts at Z1.
- **Z1. Open, close, identity, config table, the choice of D5 and the rule of D4.** `zenoh::open`,
  `Session::zid`, `close`, `is_closed`, `id`, `config`, `info` (routers and peers only). The
  first slice that names an engine. Router mode is decided HERE and not later: 15 of upstream's 31
  tests open one, so a refused `mode: router` means the Z8 gate cannot be met, and the decision
  is either to carry router mode in the top crate through the engine's router data plane
  (`docs/router-data-plane-scaling.md`) or to record that half of the gate does not apply.
  Cut in four after the read of section 5.2: Z1-pre (lift the open out of `z_open`), Z1a, Z1b, Z1c.
  - **Z1-pre (landed).** See section 5.2: `wz_capi_core::open_plan`, the plan and its twelve
    refusals, `z_open` mapping them.
  - **Z1a (landed).** `zenoh::open` and `OpenBuilder`, `Session` (clone, equality, drop, `close`,
    `is_closed`, `zid`, and `id` with `unstable`), `CloseBuilder` and `SessionClosedError`, over
    the tokio engine selected by the feature `engine-tokio` (D5; a build that selects none says so
    at `open`). `Session::open` reads the `Config` as the plan's document, with the mode and the
    id stated, and the engine's `open_blocking` runs it; the handle is `Arc<SessionInner>` with a
    count of the handles, so the last one dropped closes the session whatever else holds it, and
    the session implements the anchor of the key expression (`WireAnchor`: `acquire_keyexpr` and
    `release_keyexpr` of the port). A close joins the engine's threads, so it runs where blocking
    is allowed (`ZRuntime::Net.spawn_blocking`) and `wait_callbacks` changes nothing. The
    features `transport_tcp` (the configuration's default listening endpoints) and
    `transport_udp` join the manifest and its default set. 25 of the default lines, 27 of the
    `unstable` and the shared-memory arms', 6 differential tests (the last handle, the lifecycle
    seen from a port that stops answering, the identity, the asynchronous close, the refusals in
    upstream's words) and 12 injected faults, none missed after two gaps were closed (equality by
    id, and a listening endpoint stated twice). Two differences are held, both of the cause of a
    failed open: a session that listens and dials, and a listener that cannot bind, report
    `LinkFailed` where upstream reports what the operating system answered, because the engine
    says that a link did not open and not which or why. The D5 fold of the engine's two runtime
    creation points onto the family's pools is not done here: the engine keeps its thread per
    session, which is what the C ABI measured, and folding changes the join of `close`; it is a
    slice of its own. The router's role mapping is held by Z1b, where a router is opened and
    observed.
- **Z2. Publish and subscribe.** `put`, `delete`, `declare_publisher`, `declare_subscriber` with
  the handlers the surface has (callback, callback with a drop, the default handler, fifo, ring),
  QoS, attachments, encodings, localities, express, congestion control, `new_timestamp`, the
  zero-copy payload (`ZBytes` over the engine's received bytes, which no adapter does today),
  `declare_keyexpr` and `undeclare` (a key declared by another session is an error upstream).
- **Z3. Queries.** `get`, `declare_queryable`, `Query`, `Reply`, `declare_querier`, consolidation,
  targets, timeouts. (The cancellation token is already in, Z0b; the builders of `get` that take
  it join here.)
- **Z4. Liveliness and matching.**
- **Z5. Scouting.** Scouting is not in the port; it is the slice that decides whether the port
  gains it or the crate reaches it through the engine, and it contradicts "names no runtime" unless
  the port gains it.
- **Z6a. The unstable arm: information.** `info().links()`, `transports()`, the link and transport
  event listeners, `connectivity`.
- **Z6b. The unstable arm: timestamps.** The timestamp stack (53 surface lines,
  48 upstream tests, no model in wz's engine: it needs one).
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

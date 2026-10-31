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
  - **Z1b (landed).** The decision the slice was named for, and the table of D6. A router is
    **refused by its key** (`mode` = "router"): measured with upstream's own nodes on the other
    side of a real connection, the engine's acceptor announces a peer's role to a node that dials
    it whatever `mode` says, and a router is the router data plane, which a session does not carry;
    announcing the role without being one would be the silent fallback this note refuses, so 15 of
    upstream's 31 tests that open a router are, for now, the half of the Z8 gate that does not
    apply, recorded as such and held by a differential line that holds the words of both. D6 is
    `wz_capi_core::open_plan::key_state`: every leaf key is mapped (the engine acts on it, from the
    reader's list), inert (upstream does nothing with it either) or unmapped (upstream acts and the
    engine does not), the plan reports the keys a document states that the engine does not act on,
    the C ABI accepts them and `zenoh::open` refuses the unmapped ones whose value is not the
    default, by name; a test walks every leaf of the default configuration and fails on one with no
    state, which found five (the inline base64 certificate keys, which a running zenohd does not
    serialise and the reader's lists, adjudicated against it, therefore lack) and now names them. The
    differential gained the roles: each of this crate's nodes opens beside an upstream node, and the
    upstream node reports what it sees (`routers_zid`, `peers_zid`, the transports with their role
    and qualities), with a control that runs upstream's nodes as the subject. It found what the
    first slice's tests could not: the sessions opened but dropped every connection, because the
    manifest took the engine without `transport-qos` while the session offers QoS as upstream's
    default does (the C ABI names the capability for this reason, and the manifest of this crate now
    names the same set); a "listening" check that a port answers proves nothing, since the kernel
    completes a handshake no one accepts. 8 differential tests, 6 injected faults of this slice and
    the 12 of the last, one fault that did not compile run again.
  - **Z1c (landed; Z1 is complete).** `Session::info` and `SessionInfo` with `zid`, `routers_zid`
    and `peers_zid` and their three builders, over the registry's list of established peers and the
    role each announced (a link whose handshake has not completed is not listed, and a closed
    session has none, as upstream's has no transport left); the locators, transports, links and the
    listeners of their events are the `unstable` arm and slice Z6a. 21 of the default lines and the
    same of the other two arms, 5 injected faults none missed, and the roles of the differential
    now read the other direction as well: each node of this crate reports what its own `info` sees
    of the upstream node it is connected to, equal to what an upstream node of the same role
    reports, with the control (upstream's nodes as the subject) asserting the shape. **The rule of
    D4 is fixed and its test is not in this slice**, because no entity that takes a callback exists
    until Z2: a callback of a session of this crate runs on the thread of the face it arrived on
    (`FaceDrive::PerFace`, the choice `open` makes), so a blocking resolve inside it holds up that
    link and no other, and does not hold up the face that carries the answer unless it is the same
    one; the test that does exactly this, a `get().wait()` in a subscriber's callback with the
    answer arriving on another face and on the same one, is written with the first callback in Z2
    and Z3. One behaviour differs from upstream's and is kept: `info` resolves without blocking
    (upstream's blocks in place on a runtime and panics on a current-thread one).
- **Z2. Publish and subscribe.** `put`, `delete`, `declare_publisher`, `declare_subscriber` with
  the handlers the surface has (callback, callback with a drop, the default handler, fifo, ring),
  QoS, attachments, encodings, localities, express, congestion control, `new_timestamp`, the
  zero-copy payload (`ZBytes` over the engine's received bytes, which no adapter does today),
  `declare_keyexpr` and `undeclare` (a key declared by another session is an error upstream).
  Cut in four, each landing whole: **Z2a** the declaration of a key, **Z2b** `put` and `delete`
  from the session (the publication builder with its setters), **Z2c** `declare_subscriber` with
  the five handlers and the test of D4, **Z2d** `Publisher` and `declare_publisher`.
  - **Z2a (landed).** `Session::declare_keyexpr`, `Session::undeclare` with `Undeclarable` and its
    sealed trait, and the impl for `KeyExpr`, over the anchor of Z1: a declared key is held by
    the engine once per holder (`acquire_keyexpr`) and let go with the last, and a key declared by
    another session is an error. Two things differ from upstream's file on purpose. The
    undeclaration of a key holds its anchor, where upstream's borrows the session, because a
    handle here is made by the call that undeclares; and the anchor lets go of a hold whose
    engine id does not fit the sixteen bits of the wire and uses the key whole, where taking the
    hold and returning no id would leak it (the engine counts in sixty-four bits and no test can
    reach an id that large, so the branch is argued and not run). Upstream retracts only when the
    caller holds the one reference, so `undeclare` of a key that has a clone leaves the
    declaration to the last clone; a unit test holds that. The differential reads 17 lines of
    transcript on each side (the error texts included, down to the id upstream numbers the first
    declaration with) and the engine's table is read by unit tests only, because upstream shows no
    such table. 3 of the default lines and the same of each other arm, 5 injected faults, none
    missed.
  - **Z2b (landed).** `Session::put` and `Session::delete`, with the publication builder and every
    setter it has (encoding, attachment, timestamp, source info, quality of service, locality,
    reliability), and `PublisherBuilder` as the struct the builder holds; what needs a
    `Publisher` waits for Z2d. One `Publication` value is what the engines are handed, so the
    conversion to the engine's options is the whole of an engine's part (`publish_options`,
    `wire_key`). A key declared on the session goes on the wire as its declaration and what
    follows it. Left out on purpose: the timestamp instrumentation of a message is refused by
    name until Z6b has a model for it, and the `qos/publication` overrides of the configuration
    stay refused at open. The differential has an upstream subscriber on a real link receive what
    each side publishes, 14 operations (13 delivered, one only to the session, one refused), and
    a second test where the session holds a clock. A declared key is kept until the samples are
    seen: its retraction travels at the control priority, which a link serves before the data
    priority, so a retraction sent right behind a put may overtake it, in upstream's pipeline as
    in the engine's (the engine's barrier before a control message hands the earlier frames to the
    link's writer, which then picks by priority; it does not hold the control frame behind them).
    That is the engine's, not this slice's, and is carried. 32 of the default lines and 36 and 36
    of the other two arms, 8 injected faults, none missed.
  - **Z2c (landed).** `Session::declare_subscriber` with the builder (`callback`, `callback_mut`,
    `with`, `background`, `allowed_origin`), `Subscriber` and its undeclaration, and the five
    handlers over them. The engine is handed a `Subscription` (key, scope and suffix on the wire,
    origin, the callback, a notifier for `wait_callbacks`, and what the engine keeps while it
    records the subscription: the declared key), and mints one callback per face; each one turns the
    engine's `SampleView` into a `Sample` (`sample_of`). A subscription is also written in the
    session's own list, so that `close` undeclares what is left and the channel of a subscriber
    ends with its session, as upstream's does (the engine itself keeps a sink after close).
    Two things are differences kept for later. The payload is copied out of the view
    (`ZBytes::from(vec)`); the zero-copy `ZBytes` over the received bytes of the roadmap waits.
    And `SubscriberState` is left out of the derived file, with only `SubscriberKind::Subscriber`,
    until Z4. D4 has its test: a callback on a remote and on a local delivery declares a key,
    declares a subscriber, puts and undeclares, and the blocking calls return. The differential
    has an upstream publisher send 12 operations (plain, settings, schema, low priority, stamped,
    sourced, two deletes, a declared key, a leaf of it, 70,000 bytes, best-effort) to a
    subscriber, and compares the 12 samples as text with the upstream subscriber's, then the
    origins and the closing. 25 of the default lines and 27 and 27 of the other two arms; of the
    10 faults injected, 9 were caught by a failing test; the sixth (an undeclare that never reaches
    the engine) hung the run and was stopped for memory, which is a hang and not a verdict, so it
    is open.
  - **Carried from Z2c: the engine's reception of a batch with two frames.** Upstream's pipeline
    puts a message of the other reliability in the open batch behind a second frame header
    (`io/zenoh-transport/src/common/pipeline.rs` @ `BatchError::NewFrame`). The engine's reception
    takes the payload of a frame as the tail of the batch (`parse_unit`, the frame arm, in
    `crates/wz-session-core/src/inbound.rs`) and `parse_frame_payload` absorbs an unknown message id
    into the remainder, so what follows the first frame is lost. A burst of 12 operations from an
    upstream peer with one best-effort put among them arrived as 7; with a pause after it, 11;
    with the best-effort put last, 12, which is the order the differential uses. Zenoh's codec ends
    a frame at the first message it cannot read and reads the next transport message. The repair is
    an engine round of its own: end a frame's payload at a transport message id and park the
    residue as the next one, on the strict, the best-effort, the in-place and the plain-put paths.
    Not done here, and it is the owner's to decide.
  - **Z2d (landed).** `Session::declare_publisher` resolves into `Publisher` (the settings it was
    declared with, `put` and `delete` with their builders and aliases, `undeclare` and its
    `wait_callbacks`, a drop that undeclares, and the `Sink` of samples), and the key is declared on
    the session first, so a publication names it by the declaration. The engine is handed a
    `PublisherDeclaration` and holds it as the write filter of its subscriber plane, which already
    asks the peers as upstream's declaration does: one Interest for the key, now and for the
    future, with no aggregation, none when the publisher writes to the session itself
    (`interest_of`, held by a unit test because nothing on the API shows an Interest before the
    matching status of Z4). A session lists its publishers beside its subscriptions and lets go of
    them at close, which a unit test reads from the engine's answer for the filter. `resolve_put`
    now lives on the session's state so that a publisher, which holds the session by a weak
    reference, reaches it. Left out: the matching status and listener of a publisher and the state
    they keep, which are Z4's. The differential has a publisher of each side write to an upstream
    subscriber, 9 operations (the settings it says, the overrides of one publication, the
    destinations, a declared key, the sink, an undeclaration and the refusals of a closed session),
    and the transcripts are equal. One finding is upstream's: in a build with debug assertions an
    upstream peer that receives the Interest of another peer's publisher panics in its receive
    thread (`zenoh/src/net/routing/hat/peer/interests.rs` @ `fn send_current_subscribers(`, the
    assertion `ctx.src_face.region.bound().is_south()`) and poisons its routing tables; a release
    build skips the assertion and answers. The differential builds upstream's `zenoh` without debug assertions for that
    reason and says so in its manifest. 22 of the default lines and 25 and 25 of the other two
    arms, 9 injected faults, none missed (one was not seen until its test read the engine's answer
    for the filter).
- **Z3. Queries.** `get`, `declare_queryable`, `Query`, `Reply`, `declare_querier`, consolidation,
  targets, timeouts. (The cancellation token is already in, Z0b; the builders of `get` that take
  it join here.) Cut in three, each landing whole: **Z3a** `declare_queryable` with `Queryable`,
  `Query` and the builders of a reply, over `declare_queryable_on_wire` and the held query of the
  port; **Z3b** `get` with `Reply`, the consolidation, the target, the timeout and the builders
  that take the cancellation token, over `get_on_wire`; **Z3c** `declare_querier` with `Querier`
  (its matching status is Z4's). Z2 asked the port for no addition, and the decision of D1 is
  taken again at the end of Z3 from the list of additions Z3 asks for.
  - **Z3a (landed).** `Session::declare_queryable` with its builder (`callback`, `callback_mut`,
    `with`, `background`, `complete`, `allowed_origin`), `Queryable`, its undeclaration, `Query` with
    every accessor and the builders of a reply (`reply`, `reply_del`, `reply_err`, with the
    encoding, attachment, timestamp, source information and express setters), and
    `ReplyKeyExpr`. The engine is handed a `QueryableDeclaration` and mints one callback per face;
    each makes a `Query` that holds the engine's hold on the request, as a closure that answers
    with a reply in this crate's types (`Answer`) and lets go of the hold when it drops. So a
    query may be answered after its callback has returned, from any thread, and it is over, its
    final goes out, with the last copy of it: a unit test holds that. The reply names the
    session and the queryable as its responder, which the engine does not do by itself, and
    refuses a key that does not meet the query's unless the query accepts any, in upstream's
    words. A session lists its queryables and lets go of them at close, which ends the channel of
    one, as a subscriber's does. The port gained no operation: `declare_queryable_on_wire` and
    the held query were there, and the crate names the port's crate beside the engine's, for the
    held query is not re-exported. One observation, read and settled in Z3b: two queryables of a
    session on one key seemed to answer a query once. Both are handed it, as upstream hands a query
    to every queryable of the session whose key meets it whatever the target (the target chooses
    among peers, not among one's own); the single reply was the consolidation a get has by
    default, which makes two replies on one key one, and a unit test counts the deliveries and
    both consolidations. Left out: the timestamp stack of a query (Z6b), the request,
    target and consolidation of a get (Z3b). The differential has an upstream node ask the
    queryable of each side eight queries over a link (the parameters, a body with its encoding
    and attachment, every form of reply, a disjoint reply refused and accepted, an answer given
    late from another thread, the options of a query, and nobody to answer) and the transcripts,
    the queryable's and the asker's, are equal. 73 of the default lines and 80 and 80 of the other
    two arms, 8 injected faults, none missed.
  - **Z3b (landed).** `Session::get` with `SessionGetBuilder` (`callback`, `callback_mut`, `with`,
    `payload`, `target`, `consolidation`, `allowed_destination`, `timeout`, `accept_replies`, the
    encoding, attachment, source information, quality-of-service and cancellation-token
    builders), `Reply`, `ReplyError`, `QueryTarget`, `ConsolidationMode` and `QueryConsolidation`,
    and `From<&Query> for Selector`. The engine is handed a `QueryRequest` and mints one callback
    for each leg of the get (one to each peer and one to the session's own queryables); the legs
    share the callback of the get, which is dropped with the last of them, and that is what ends the
    channel of a handler. The session resolves `Auto` once, as upstream does (to `Latest`, or to
    `None` for a time range), refuses a get on a closed session, and refuses a get that asks for
    the timestamp stack (Z6b). A cancellation token is tied to the get through the port's fan: the
    token's handler cancels every leg, and the token's wait ends when the callback is dropped. The
    default timeout is the configuration's `queries_default_timeout`. D4 has the other half of its
    test: a callback of a subscriber, of a queryable and of a get asks a get and waits for its
    replies. Three things in the engine were wrong and are fixed, each found by a test of this
    slice. A reply from a queryable of the session itself carried its error encoding as the id the
    responder gave, where one received over a link carries the packed form; the loopback now packs
    it. A get whose leg is the session's own queryables never expired, because only a face's drive
    swept its pending table, and a queryable may hold a query past the call that delivered it; the
    drive of the local plane now sweeps its own table and sleeps until its earliest deadline. And a
    `Timeout` that upstream's routing sends for a query it forwarded names no key, which the
    receive paths took for a reply they could not place and dropped; an error is not about a key,
    so both paths now deliver it. The port gains two defaulted accessors on `ReplyView`,
    `responder` and `qos`, with the same two fields on `InboundReply`, because the engine dropped
    the responder and the quality of service of a response (upstream's `Reply::replier_id` and
    the quality of service of a reply sample); that is the whole of Z3b's addition to the list D1
    is taken again from. Left out: the querier (Z3c), the timestamp stack (Z6b). The differential
    has a node of each side ask an upstream queryable 16 gets over a link (the parameters, a body
    with its encoding, attachment and source information, every form of reply, the target, a
    disjoint reply refused and accepted, an answer given late, a get never answered, the four
    consolidations over three versions of one value, the options, nobody to answer, an invalid
    selector and a get after close) and the transcripts are equal; the `Timeout` line says only
    that the get ended with one, because upstream's two expiries (the asker's and the asked
    node's routing) race and the asker is handed whichever is first. 51 of the default lines and 56
    and 56 of the other two arms, 13 injected faults, none missed.
  - **Z3c (landed).** `Session::declare_querier` with `QuerierBuilder` (the target, the
    consolidation, the timeout, `accept_replies`, the allowed destination and the quality of
    service), `Querier` (its key, quality of service and `accept_replies`, `id`, `get`,
    `undeclare` and its wait on the callbacks), `QuerierGetBuilder` (the handlers, the payload,
    the parameters, the encoding, the attachment, the source information and the cancellation
    token) and `QuerierUndeclaration`. A querier is declared as a write filter of the engine on
    the queryables plane, which keeps the interest in the queryables of its key and asks the peers
    for them as upstream's declaration does; the session lists its queriers beside its
    publishers and lets go of them at close. A get of a querier is `Session::query` with the id
    of the querier and a notifier of its callback group: the query holds a fan (the port's
    `CancellableFan`) for as long as it is under way, the session keeps a `Weak` of it with the
    querier, and an undeclaration cancels what is still there, so the queries of a querier end
    with it and their channels close, as upstream removes them from its table; the wait of the
    undeclaration on the callbacks holds for a callback that is running. What the querier's
    matching reads (`matching_status`, `matching_listener`) is Z4's, and so is which queryables
    count for a target of all-complete, which the filter does not take at declaration. The port
    gained no operation. The differential has the queriers of each side ask an upstream
    queryable the gets of Z3b through 13 queriers (their accessors, the options, a declared key,
    the consolidations, an invalid key, a get and an undeclaration after close) and the
    transcripts are equal. 40 of the default lines and 45 and 45 of the other two arms, 7
    injected faults, none missed (one did not compile at first and was redone).
  - **D1, taken again at the end of Z3.** The hypothesis is decided: the seam is the port. Of the
    list of additions it was to be taken from, Z2 asked none, Z3a none, Z3c none, and Z3b the two
    defaulted accessors of the reply view (`responder`, `qos`), a field each on the engine's
    inbound reply. What else Z2 and Z3 needed was behaviour of the engine that was wrong and is
    fixed there (the error encoding of a loopback reply, the expiry of a get answered by the
    session's own queryables, an error reply with no key), which is the argument for the seam: each
    was a defect of one place, found by a test of the top crate and mended in that place for every
    other client of it. The strongest argument against, upstream's own `IRuntime`, has not been
    needed: nothing in the top crate keeps a table that the engine owns, except the lists of ids
    that a close lets go of. Z4 takes up the list again with the one-shot matching status
    (`matching_status(plane, key, locality)`), which decision D1's table already names.
- **Z4. Liveliness and matching.** Cut in two, each landing whole: **Z4a** matching, **Z4b**
  liveliness.
  - **Z4a (landed).** `MatchingStatus`, `MatchingListener` with its builder (`callback`,
    `callback_mut`, `with`, `background`), its undeclaration with the wait on the callbacks, and
    the `matching_status` and `matching_listener` of `Publisher` and `Querier`, the status being
    read through the destination each was declared with and, for a querier, its target. A listener
    is declared on the engine by the session, which lists them and lets go of them at close, as a
    publisher and a querier undeclare theirs; a status that already matches is told before the
    declaration returns, and none is told that does not. The port gains two defaulted operations:
    `declare_matching_listener_in` and `matching_status`, which take a locality (the peers', the
    session's own, or both) where the existing listener took a flag, and nothing else; D1 stands.
    The differential found what the engine did not do as upstream does, and each is mended in
    the engine for the Rust API alone, as an opt-in that leaves the pico and C ABIs as they were.
    A face's watch counted what the session itself declared as well as what its peer did, so a
    listener of remote subscribers was told of a local one; the watch is now pinned to the peer's
    declarations, and the session's own are counted by the fold the listener asks for. Upstream
    counts the session's own subscribers and queryables whatever origin each accepts, where the
    engine counted by the origin as zenoh-pico does, and reads the declaration of such an entity
    as a change whatever its origin. And upstream's router tables count a queryable of a peer
    only when its key includes the querier's, complete or not, where its own session counts its
    own by intersection for an ordinary target (`zenoh/src/net/routing/hat/broker/queries.rs` @
    `ke.includes(key_expr)`); the criterion of the engine gains `remote_includes`, set by the
    options of the querier the listener is made through. The differential has an upstream node
    declare and undeclare subscribers and queryables (narrow, wide, apart, complete) and the node
    of each side declare its own, by every origin, and compares after each step the status of
    three publishers and three queriers and every status their listeners were told: the
    transcripts are equal when each change is given its own step, because upstream's listener
    reads the status when its task runs and so merges a change that is undone before then. 32 of
    the default lines and 33 and 33 of the other two arms, 11 injected faults, none missed (three
    were not seen at first or did not compile, and were strengthened or redone).
  - **Z4b (landed; Z4 is complete).** `Session::liveliness`, `Liveliness` with `declare_token`,
    `declare_subscriber` and `get`, `LivelinessToken` with its undeclaration, the builders of the
    three (the subscriber's `callback`, `callback_mut`, `with`, `background` and `history`; the
    get's `timeout` and, with `unstable`, `cancellation_token`) and the `lib.rs` module
    `liveliness`. A liveliness subscriber is a `Subscriber` of the kind `LivelinessSubscriber`,
    listed with the session's subscriptions and undeclared as one is, over the id space the engine
    already shares between the two. A session lists its tokens and retracts those that are left at
    close, as it does its listeners. The port asked for nothing: it had the three operations, and
    the crate reaches them through the engine as it does the others. The differential found one
    thing that the engine did not do as upstream does, and it is mended in the engine as an opt-in
    that leaves the pico ABI as it was: upstream's session tells its own liveliness subscribers of
    its own tokens, with the history of a subscriber that asks for it, and its own liveliness get
    finds them, where the engine's plane never delivered a declaration to a subscriber of the
    same session (its link driver is inert, and what it writes is discarded). The registry now
    tells the matching subscriptions inside the declare and the undeclare of a token, on the
    calling thread and with no lock held, replays the tokens a history asks for, and answers the
    get with a leg of its own beside those of the faces. `SessionResources::liveliness_to_self`
    chooses it: the zenoh and zenoh-c ABIs say `true`, and zenoh-pico's says `false` because its
    history walks the tokens of its peers alone (`vendor/zenoh-pico/src/net/liveliness.c` @
    `_z_keyexpr_intmap_iterator_make(&zn->_remote_tokens)`). The differential has an upstream node declare and
    retract tokens and a node of each side watch them, with and without history, ask for them,
    and declare, retract and drop its own, and compares after each step what every subscriber
    was told and what a get found. The unit tests of the crate had a port picked twice by two
    tests that ran side by side (`LinkFailed` on open); a port is now handed out once by a
    process. 40 of the default lines and 41 and 41 of the other two arms; 9 injected faults,
    none missed.
- **Z5 (landed). Scouting.** `scout` with its builder (`callback`, `callback_mut`, `with`), `Scout`
  with `stop`, the `scouting` module with `Hello` (the wrapper of `wz-zenoh-config`), and the root
  re-export. **Decision: the crate reaches the engine, and the port gains nothing.** A scout is no
  session's: it needs a configuration and a group and nothing a session holds, so it is not an
  operation of `SessionEngine`, and the open does not go through the port either. D1 stands. The
  engine already ran the cadence upstream's `scout` has, for a session that looks for its peers
  (a Scout at once, then the answers to it for a window of a second, the next twice as long, up to
  eight), so that loop is now one drive both use: `ScoutLink::scout_each` hands each Hello to its
  caller as the window gathers it, and the session's autoconnect is a caller of it. What a scout a
  program asks for adds is `ScoutingPlan::for_scout`, which reads the group, the interface and the
  hop limit of a configuration and not whether the configuration enables multicast scouting (that
  is a session's question, as upstream's `scout` does not ask it either), `ScoutLink::bind_for_scout`,
  which does not need the group socket (upstream receives on its per-interface sockets alone, and a
  scout with no socket finds nobody and is no error), and `ScoutStream`, a thread that scouts until
  it is dropped and is joined by the drop, so no callback runs once `stop` has returned. A Hello
  whose role was not asked for is left out, as upstream's receive loop leaves it. One difference is
  recorded and not mended: the Scout the engine sends announces an id, where upstream's `scout`
  announces none, so a node that answers sees the id of a scout it can read and not a scout with
  none. The unit tests find a node of the crate by a scout on a group of their own, check the
  roles, the locators, the windows (the second is twice the first), the stop and the error of an
  unreadable configuration; the differential has a scout of each side hear an upstream node and an
  upstream scout hear a node of each side, with equal transcripts. The surface falls to 2, 115 and
  119 lines of the three arms; 8 injected faults, none missed (one did not compile at first and
  was redone).
- **Z6a (landed). The unstable arm: information.** `info().transports()`, `links()` (also by a
  transport), `locators()`, and the transport and link event listeners with their builders
  (`callback`, `callback_mut`, `with`, `history`, `background`, `transport`), their undeclaration
  (`wait_callbacks`), and the types `Transport`, `Link`, `TransportEvent`, `LinkEvent`.
  **Decision: the engine already reports what the API lists, so the crate reads it and the port
  gains one accessor.** `SessionEngine` had `face_snapshots`, `watch_faces` and `unwatch_faces`
  (the connectivity plane of the C ABI); the crate turns a snapshot into a `Face` (a `Transport`
  and its `Link`s) at the engine boundary, and a listener is one watch of the engine's faces. A
  face that comes up is a `Put` of its transport and then of each link, one that goes down a
  `Delete` of each link and of its transport, as upstream's handlers emit them. `locators()` reads
  what the port now says, `listen_locators`: the locators the listeners actually got, without the
  loopback ones, recorded as they bind (late binds included) and not only for a session that
  gossips. The model of a link gained the common name on the certificate of its peer
  (`LinkSnapshot::cert_common_name`), from which `auth_identifier` is the name of a TLS or QUIC
  link and nothing for the others, the reliable UDP link among them, as upstream's auth ids are.
  A closing session lets go of its listeners before the engine closes: the faces a session
  dialled go down with it and would tell them, where upstream's close drops them first. One
  difference is recorded and not mended: `Link::mtu` is the batch budget the engine negotiated,
  where upstream reports the maximum segment size of the socket of its own end (49152 on the
  accepted end of a loopback connection and 65480 on the dialled one, here), so the differential
  compares its presence and not its value; reporting upstream's number means the link drivers
  compute it, and the budget it would change is the batch size the INIT advertises. The unit tests
  open two nodes and check the lists, the filter by a transport, the history, the order of the
  events, the undeclaration and its wait for the callbacks, the end of a listener's channel with
  its session, a session that closes at either end, a listener that binds late, and the mapping
  from the engine's snapshot (roles, QoS, reliability, priorities, groups, a certificate) with no
  socket; the differential has a node of each side connect to, and be dialled by, an upstream node
  and compares the lists and the events of both. The surface falls to 2, 5 and 8 lines of the
  three arms; 17 injected faults, none missed in the end (three were missed at first: a guard that
  was dead code and was removed, a release before the close that no test closed at the dialled end
  and now one does, and an undeclaration that hung where it should fail).
  The default-feature unit run of the top crate also failed once on an older test, one that
  counts a callback right after the `put` that fired it: a caller-drained session promises that a
  call returns once its callbacks have run, and the drive task drains the same queue, so when it
  took the batch first the caller found the queue empty while the callback was still running. The
  queue now numbers the batches it hands out, `DeferredFireQueue::drain_marked` returns the mark
  of the take that found it empty and `is_settled` says when every batch before the mark has run,
  and the session's `drain_deferred_fires_settled` waits for that, except from a callback (it is
  part of one of the batches, and the others may be parked behind it). The staging calls of a
  `Caller` session use it, and a `DriveTask` session, whose host may hold a lock the drive task's
  callbacks want, drains as before. 4 injected faults, none missed (one hung where it should fail,
  and a test of its own now fails it).
- **Z6b (landed). The unstable arm: timestamps.** Landed: `Session::new_timestamp`,
  `OpenBuilder::with_timestamp_callback`, the instrumentation of puts and deletes, and that of
  gets, queries and replies (`Query::timestamp_stack`).
  **Decision: the engine carries the stack and the session records on it.** The timestamp stack is
  Push extension `0x7`, a ZBuf a node may skip, and wz's engine had no model for it:
  `wz_session_core::ts_stack` now holds its bytes (the format of `zenoh-codec`) and its place in a
  chain, the options of a publication carry the stack it starts with
  (`PublishOptions::with_ts_stack`, one for the loopback leg and one for the Push that leaves,
  because upstream's node records one more interception on a message it routes out), and a
  delivered `Sample` carries the stack it came with and whether it came over a link
  (`Sample::routed`), the fact that makes the node record its routing before it delivers. Who
  records what, and with what clock, is the session's (`TimestampSource`): the bytes of the user's
  callback when the session was opened with one, otherwise a UHLC timestamp off the clock of the
  node, or off one of the session's own. A message read in place is delivered through the owned
  path when it carries a stack, which the lent form has none to add to. All of it is behind the
  session core's feature `pubsub-ts-stack`, which this crate's `unstable` selects: a build without
  it (the C and pico client images) neither compiles the module nor holds the fields, and the
  capability cost gate holds it to that. The differential has a
  node of each side publish, with every combination of the three points and with a callback, to a
  subscriber of the other and to its own, and compares the stacks record by record.

  The query side is the same stack on the other two messages that carry it, as the last extension
  of a Request and of a Response: `QueryOptions::with_ts_stack` gives a get the stack of its
  loopback leg and that of the Request that leaves; a queryable is shown the stack its query
  arrived with (`QueryView::ts_stack`), which the session completes with its routing, when the
  query came in over a link, and its receive; every reply and error reply a queryable stages
  starts from that stack and records its send, and its routing when the query was a remote one
  (`ReplyOut::with_ts_stack`, then the Response builders); and the reply is handed to the getter
  with the stack of its Response, which the session completes the same way
  (`ReplyView::ts_stack`, with `ReplyStamp` holding it, zero-sized in a build without the feature).
  A Request or a Response read in place that carries a stack is delivered through the owned path,
  as a Push is. The differential has a node of each side ask the queryable of the other and its
  own, with the clock and with a callback, at every combination of points, and for an error
  reply, and compares the stacks record by record. Hiding the timestamp of a reply
  (`HiddenReplyTimestamp`) no longer hides the responder and the quality of service of it.

  A reply is received when it arrives, as upstream records it at the top of `send_response`: an
  instrumented get hands the engine a `ReplyArrival` (`QueryOptions::with_reply_arrival`), which
  the consolidating sink calls on every reply that carries a stack, an error reply and one the
  consolidation then drops included, ahead of what the mode does with it. A `Latest` query so
  records the receive of a reply when it lands, and not when the final lets it go.

  A wz node that forwards a message records its own route, as upstream's dispatcher does for each
  face it hands a Push, a Request or a Response to. The router hat (which a peer of the mesh is,
  since the linkstate forwarder was folded into it) records at its one egress, `egress_to_face`,
  where each destination gets a message and a stamp of its own, and at the multicast group, which
  does not pass it. `NodeHlc::interception_timestamp` is the clock: the node's own, or, for a node
  whose role stamps no data, a clock of its own over the same source and zid, as upstream falls
  back to a lazy HLC; the `trusted-only` policy, which is about data a node passes on as its own,
  does not refuse it. The bytes are the timestamp of a Put (`ts_stack::timestamp_bytes`), which a
  differential holds to upstream's codec in both directions. All of it is behind `pubsub-ts-stack`,
  which `wz-runtime-tokio` forwards to `wz-node-time`.

  A subscriber of the C ABI that is offloaded to a lane is handed no stack, and owes none: the
  stack is a Rust API of upstream's `zenoh` (`zenoh::timestamp_stack`) and zenoh-c does not bind
  it. Measured on the oracle, zenoh-c 1.10.1 built with its unstable API: none of the dynamic
  symbols of `libzenohc.so` is about a stack, an instrumentation or an interception, and its
  timestamp surface is `z_sample_timestamp`, `z_timestamp_new`, `z_timestamp_id` and
  `z_timestamp_ntp64_time`; the headers hold no such name either. There is nothing for the lane
  to carry. The surface falls to 1, 2 and 5
  lines of
  the three arms; 15 faults were injected into the publish side and 24 into the query side, one
  at a time, none missed in the end (the first test of a plain Put could not tell, and one assertion
  was changed so that it can; one fault that deleted a fallback failed to compile and was redone as
  a condition that never holds).
- **Z6c (landed). The unstable arm: the rest.** `Session::config` and `GIT_VERSION`.
  **Decision: the session holds the configuration it was opened with, and the crate names its own
  build.** The session keeps a `Notifier<ExpandedConfig>` made from its `Config` when it opens
  (upstream's runtime holds the same), and `Session::config` hands out a `GenericConfig` over it:
  the reads (`get`, `get_typed`, `get_plugin_config`, the text, the default timeout of a query)
  and the one write the configuration allows a running node, a key of a plugin, which every handle
  of the session sees. `IConfig` is implemented for that notifier in `crate::api::config`, as
  upstream's runtime implements it, so that the trait of the configuration crate is the interface
  and nothing else is exposed. `GIT_VERSION` is `v`, the version of the crate, `-` and a commit, as
  upstream composes it, and a build script (`crates/wz-zenoh/build.rs`) asks `git describe` for the
  commit with the arguments upstream's `git_version!` takes, and says `release` where there is no
  history to ask, so that no crate joins the graph for it. The differential compares what the two
  sessions say of the same configuration, key by key, the error of a key that is not there, the
  typed reads, the writes that are accepted and refused and what a second handle sees, and the
  text of the whole; the version is compared by its shape, since the commit is each crate's own. 4
  faults were injected one at a time, none missed. The surface falls to 0, 0 and 3 lines of the
  three arms: the default and the unstable arms are whole, and what is left is three lines of the
  shared-memory arm (Z7, which closes them).
- **Z7a (landed). The shared-memory arm of the surface.** `Session::get_shm_provider`,
  `zenoh::shm::ShmProviderState` and `OpenBuilder::with_shm_clients`. **Decision: the provider of
  the session is made by the crate from the configuration, as upstream's transport manager makes
  it, and it is not the engine's.** The session reads the `transport/shared_memory` section as it
  opens: shared memory off, or its transport optimisation off, is no provider (`Disabled`); otherwise
  the pool the section names (`transport_optimization/pool_size`) is made on a thread of its own the
  first time the provider is asked for, and the asker is given the receiver of the result
  (`Initializing`), which a later ask turns into the provider (`Ready`) or into an error that stays
  (`Error`), the state machine of upstream's `LazyShmProvider` with the quirk that a receiver taken
  by one asker is not seen by the next. The state is the enum, `into_option`, `Wait` and
  `IntoFuture` of upstream's, re-exported from `net::runtime`, a hidden module of a module the crate
  does not publish, as upstream does, because rustdoc records a re-export from a hidden module as a
  re-export and inlines an item that is not. `mode` = `init` initialises the subsystem as the
  session opens (`api::shm::init_if_asked`), which is why the engine's refusal of a key it does not
  act on lets that key through when the crate acts on it itself. `with_shm_clients` hands the
  session the storage of clients; **the session negotiates no shared memory with its peers and so
  reads no segment through them, and the storage is kept, unread, for the transport (Z7t)**: an
  accepted option that does nothing, named here and in the doc of the method. The differential
  (`conformance/differential-shm/tests/zenoh_session_shm.rs`) opens an upstream session and a wz
  one with six configurations of the section (the default, a small pool, shared memory off, the
  optimisation off, `init`, a pool no system gives) and compares the state at the first ask, after
  waiting, at a later ask and as a future, what the provider holds and hands out, `into_option` at
  once and a moment later, and a session opened with clients: equal. 7 faults were injected, none
  missed (one that left a variant unused did not compile and was redone twice as a condition that
  never holds). The surface of `zenoh` is whole in all three arms: 709, 965 and 1,025 lines, none
  missing, none extra.
- **Z7t. The shared-memory transport (landed in rounds 3921 and 3922; the upstream `shm` file
  passes 10 of 10).** A payload in shared memory crosses a link, and a multicast group, without a
  copy in both directions, and a large put is promoted into the provider of the session.
  **The process holds two shared-memory systems that share no type**: `zenoh::shm` is
  `wz-zenoh-shm`, the family crate, and the engine's is its own (`wz_runtime_tokio::shm_*`), so a
  buffer is carried and not converted: the engine publishes any chunk a host owns
  (`ShmPublishable`: its own chunk, or a `ShmSendHandle`) and reads a received descriptor with a
  resolver the host supplies (`ShmReader::Host`); this crate wraps the slice of a `ZBytes` as the
  send buffer, takes the receiver's reference as upstream's codec does, and reads a descriptor
  with its own reader into the `ZShm` the application receives. A group that is a
  shared-memory one (`Session::enable_shm`; the stamp is made once, because a group negotiates
  nothing a reconnect could lower) is sent ONE descriptor for every member
  (`publish_shm_on_group`). The promotion is made by this crate before the engine, not at the
  link, and per session and not per peer. **Not a gap:** the extension of a group's Join that
  would announce shared memory (upstream builds its Join with `ext_shm: None`,
  `io/zenoh-transport/src/multicast/link.rs` @ `ext_shm: None,`, and reads a member's as
  `join.ext_shm.is_some()` only for the report of its transports; the descriptor of a group is
  read by any member that holds a reader, announced or not), so a Join that announced it would
  differ from upstream's. **Owed:** a query value and a reply in shared memory (and the `query`
  and `reply` lists of the optimisation), a differential of a `ZShm` over a link and a group to
  an upstream node, and a unit test of a group's descriptor in the engine (the upstream file is
  its test).
- **Z8. The graph.** Upstream's tests and examples and `zenoh-ext` built and run against the
  patched graph, on Linux and on Windows. A test that cannot pass is a recorded difference with its
  reason, never a deleted test.
  - **Z8a. The harness and the first measurement (landed).** `scripts/lib/z8_upstream_suite.py`
    provisions the tree of the pin on the host (a shallow clone of the tag, its commit asserted),
    generates a package under `target/z8-suite` that is never committed (upstream's `zenoh/tests`
    copied byte for byte, the helper crate `zenoh-test` beside it, the third-party crates of
    upstream's `zenoh` manifest, every family crate in `[patch.crates-io]`, the top crate by path)
    and compiles and runs each file ON ITS OWN. An exit status grades nothing here (a run that
    selects no test exits 0), so the table carries the number of tests run, and a file that runs
    none is `empty`. Four defects of the harness itself came out first, each making all 33 files
    fail on one line: the helper's `internal` feature wants `zenoh::internal::runtime` (it stays
    off), `shared-memory` has to reach upstream's `zenoh-transport` as well, the crates the tests
    name come from the manifest's dependencies and not only its dev-dependencies, and a value of
    the workspace table can span lines. The first measurement, with `unstable`, `shared-memory`,
    `transport_tcp` and `transport_udp`, ran 33 files:
    - **Pass (10 files):** `atexit`, `attachments`, `bytes`, `connectivity`, `formatters`,
      `handler`, `keyexpr`, `queryable`, `source_info`, `tcp_buffers`.
    - **A router is refused (Z1b), the half of the gate that was recorded as not applying:**
      `acl`, `adminspace`, `liveliness`, `matching`, `namespace`, `qos_overwrite`, `scouting`,
      `timestamp_instrumentation`, `unicity`, and part of `authentication`.
    - **A key the engine does not act on is refused by name (D6):** `qos` (`qos/publication`),
      `qos_overwrite` (`qos/network`), `shm` (`transport_optimization`, Z7t).
    - **Found by the measurement and repaired:** 23 tests of `acl`, `authentication`,
      `interceptors` and `low_pass` stopped on "this configuration cannot be opened
      (DocumentUnreadable)". The document an open hands the plan is the configuration rendered, and
      it states every optional field it does not have as `null` (`id`, `interfaces`,
      `link_protocols`, `flows` of an entry), which the reader, written for an operator's document,
      refuses where it expects a string or a list. The rendering now leaves out a member that is
      `null` and a section that held only such members (`rendered`), and the default it is compared
      with is rendered the same way. `low_pass` passes (4 tests); the others reach their router.
    - **Open, with the reason known:** `session` and `unicity` call `tokio::task::block_in_place`
      and `Handle::current().block_on(..)` from inside a callback, which presumes the callback runs
      on a worker of a multi-thread runtime, as upstream's do. Here a callback runs on the thread of
      the face, a current-thread runtime over state that is not `Send`, where `block_in_place` is
      refused and a blocking call that waits for the face would wait for the thread it is on. The
      decision is where a callback runs: inline, as now, or on a dispatcher of its own with an
      ordered queue per entity, which lets a callback block and re-enter the session at the price of
      a hop per sample and a bound to choose. It is not made here.
    - **Read again after the repairs of rounds 3866 to 3873:** `interceptors` (7 of 7),
      `connection_retry` (6 of 6), `callback_drop_on_undeclare` (14 of 14), `cancellation` (4 of
      4) and `events` pass. `namespace` passes 8 of 12 and `liveliness` runs 46 with every test
      that opens no router passing; what each of them lacked is in the ledger (a repeated id of
      the interceptors, the session's wait for the callbacks of every entity and the end of a get
      that nobody answers, the session's own admin space, a liveliness key told once however many
      tokens sit on it, and the namespace of the answer to an interest).
    - **The router session (an owned slice, not a half-gate).** The refusal of `mode` = "router"
      stays, and 15 files wait on it (`liveliness` 39 tests, `namespace` 4, `acl`, `adminspace`,
      `matching`, `qos_overwrite`, `scouting`, `timestamp_instrumentation`, `unicity`, part of
      `authentication`, `routing`). The data plane exists (`RouterForwarder`, with a Local face
      that hosts a node's own declarations, `docs/peer-region-hats.md` section 12), and its
      bootstrap lives in the demo binary (`crates/wz-ap-demo/src/runner.rs`,
      `run_router_hat_until`, about 1,800 lines) over the library's `peer_loop`
      (`crates/wz-runtime-tokio/src/accept_loop.rs`). The way in is an `Engine::Router` arm
      whose node thread composes what `wz-capi-core` already builds privately (the bind, the
      accept and dial configurations, the init parameters, the scouting responder) with a
      `RouterForwarder` and `peer_loop`, in a module of its own. The order, each step landing whole
      and judged by an upstream file: (1) the arm with its thread, responder, zid, close, listen
      locators and peer list, every other method refusing by name, which opens the tests that
      use a router only as a broker (`scouting`, the routed variants of `namespace`,
      `timestamp_instrumentation` and `unicity`, and the client and peer variants of
      `liveliness`); (2) an id-keyed hosted subscriber and queryable, publish and the node's
      timestamp; (3) liveliness from the Local face (no door exists: a token, a hosted
      liveliness subscriber and a liveliness query); (4) a get from the Local face (no door:
      `route_request` is keyed by an inbound face) and the matching status; (5) the access
      control, the authentication and the admin host, which the demo carries and must be
      extracted. Three risks are recorded: the origination doors of steps 3 and 4 are new routing
      code, a hosted callback runs under the read guard of the tables (a declaration made from it
      deadlocks, and `session` and `unicity` already block inside callbacks), and the hosted
      queryable cannot hold a reply or read a payload.
    - **A peer that accepts sessions is the router node at node mode Peer (rounds of 2026-10-30).**
      Upstream's peer routes between the sessions it holds (its peer hat, and a broker hat for the
      clients south of it), which the registry of faces does not: a client that dials a peer
      and a token behind the router that peer dials were two faces nobody joined (the six
      `clientviapeer` tests of `liveliness`). `OpenPlan::peer_fits_node` says when a peer is a
      node: it listens, joins no multicast group, scouts to dial nothing, and binds its listeners
      at the open (`listen/exit_on_failure`); any other peer stays on the registry. The node
      runs `RouterForwarder::peer_with_timestamping`, advertises its locators, and dials the
      nodes its gossip admits (`enable_autoconnect`). Measured with it, `liveliness` is 45 of
      46 and runs in 220 s where it took 676 s. What the node had to carry for a peer, found by
      the upstream files and by this crate's own unit tests: all that a message says is shown to
      the subscriber and the queryable of the node's session (`sample_of_push`,
      `RequestQueryView`), where it was handed a key and a payload; the node records its routing
      on the stack of an instrumented message, query and reply (`timestamp_instrumentation`
      48 of 48); a subscriber or queryable the node hosts is pushed to the faces that asked for
      it and withdrawn from them; the node's session reads a descriptor into its own buffer and
      publishes a chunk of shared memory (`shm` 10 of 10); a get of the node's session has a
      deadline and ends with the `Timeout` reply; a watch is answered after its first verdict;
      and the face thread runs inside a current-thread runtime, which is how the callbacks of
      the top crate know to queue the items they are handed. **A defect the unit tests found in
      the registry itself:** a peer that received several tokens a node declared by their
      keyexpr (the id `0` of each) kept the first and refused the rest as a repeat; each keyexpr
      is now a token of its own. **Owed:** a listener bound after the open, a multicast group
      and a scouting that dials, on a node for a peer (each keeps the peer on the registry);
      `regression_3` (the router does not broker the token of one peer to another peer, and
      the locators that would make them dial each other are not gossiped to peers); a key
      declared by an id (the node names none, which is only an optimisation of the wire);
      the unit tests of this crate open the registry unless a test says `with_the_node`.
    - **`routing` with peers on the node: 6 of 8.** `gossip`, `gossip_regression_3`,
      `router_linkstate`, `scouting_delay_regression`, `three_node_combination` and
      `two_node_combination` pass. The open of a node that is a peer returns once an endpoint it
      connects to is up (within its start window) and at once when it connects to none, where a
      router node's open is held for `scouting/delay` in full: the held open was the 500 ms
      `scouting_delay_regression` measures. `gossip_regression_1` and `gossip_regression_2` fail
      because the linkstate view of a peer node carries a peer two links away although
      `scouting/gossip/multihop` is off; that is the side of the node's peer net and its admin
      reply, and it is the next item.
    - **`regions` (measured 2026-10-30; the harness now gives the file `internal`, whose `cfg`
      compiled all of its tests out): 126 tests, 6 pass.** It is the 1.10 regions feature: a node
      names its region (`region_name`, carried in the INIT extension), a gateway keeps the
      subregions of its south apart (`gateway/south` with filters on modes, interfaces, zids and
      region names), and a client with a multicast group is the gateway of the peers on that
      group. Each scenario runs five kinds of test in several start orders (`putsub`, `getque`,
      `toksub`, `pubsub`, `queque`). What fails, with its reason: (1) 66 tests refused
      `region_name` (the key was read by the config but acted on by nobody:
      `SessionLinkActions::set_local_region` had no caller outside the demo); the key is
      honoured now, through the offer of each session of the node (`SessionOffer::region`), and
      the count of tests that pass moved from 6 to 10 (the scenario 4 and 5 ones that observe
      only delivery); (2) the delivery tests of scenarios 1, 2 and 3 end with a timeout
      (`gateway/south` reaches the hats of a node only through the demo's flags, and a client or
      a peer that holds a multicast group, dials what it scouts and keeps a subregion apart is
      not a node of the API yet: such a peer stays on the registry); (3) the `pubsub` and
      `queque` kinds, about 50 tests, also count events: they assert how many times a node's
      north hat registered a subscriber or a queryable, read from tracing spans named
      `demux{zid}` and `register_subscriber{self, res}` of upstream's routing code. That is a
      count of upstream's steps, not an observable of the API, and the peers of those tests are
      registry peers, which have no hat to register in; it can be met only by a routing that
      opens the same spans, which is a decision of its own and is not made here. Slices, in
      order: the gateway partition on the nodes of the API (the router node and the peer node
      take `gateway/south`, with the region names of the remote's Init), the peer that holds a
      multicast group and dials what it scouts as a node, the client that holds a group, then
      the spans.
    - **Open:** `routing` (the two above), `regions` (above) and `open_time` (its tests are
      ignored upstream).
    - **The hosted lane (Layer Z8, `z8-upstream` in `ci.yml`) and the table it holds the report
      to.** `docs/z8-expected.tsv` names, for each file of upstream's `zenoh/tests`, the outcome
      it has, the fewest tests that pass and whether the lane runs it; `scripts/lib/z8_expectation_gate.py`
      compares the report of the harness with it. A file below its row fails the lane, a file
      above it is a line to raise. The first measurement with the table caught a regression in
      `liveliness` (44 of 46, then 43) that no other gate saw: a node peer's open returned when
      its first link was up, before the nodes it dialled had told it what they hold, so a
      subscriber declared right after the open was told of tokens that were already alive;
      the open now waits for one connected and ingested node for each endpoint it dials, as
      upstream's start conditions count one connector for each. The `regions` file is in the
      table and not in the lane (each failing test waits out a minute). The harness raises the
      open files limit of its runs: a dozen sessions of one process pass a shell's 1,024.
    - **Owed:** the files it asks for a `Runtime` of (the arm with `internal`), Windows, a margin
      gate for the lane once it has measured runs, and the rows of `regions` that fail today.
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
- **O4. The pin moved to 1.10.2 (round 3976), and what that release changed that wz does not
  carry yet.** The family follows upstream's version, so `zenoh`, `zenoh-c` and the reference
  train are 1.10.2 (zenoh-pico followed in round R3987, see the end of this bullet). Measured by diffing the two
  releases' trees: the public Rust API grew by two lines, `Hello::locators_iter` and the unstable
  `Link::interfaces_iter`, both ported with their tests; the C API changed one declaration (the
  `_options` of `z_open` lost its `const`), which wz's `z_open` accepts as it is; no
  configuration key moved. Upstream's own suite measured at 1.10.2: `shm` 10 of 10,
  `liveliness` 46 of 46, and the new `interest_undeclare` 1 of 1. Carried, each read in the
  1.10.2 source and none built: (a) the QUIC control stream is opened when the first frame is
  written and not at the open (the wire is the same; wz opens it at once); (b) a multicast group
  honours `transport/multicast/compression/enabled` (wz lists the key as not read); (c) a
  companion link of a mixed-reliability pair takes the transport's batch size as its limit
  (measured in round R4006: wz has no such pair, its QUIC offers neither the mixed-reliability
  nor the multi-stream protocols, `quic_plaintext.rs`, so the item has no subject until the link
  has one; the datagram link's own budget already enters `negotiated_batch_mtu`); (d)
  the shared-memory negotiation refuses the link when an offer cannot be honoured, where 1.10.1
  ran without it (taken in round R4006: an acceptor's challenge mismatch, a malformed OpenSyn
  and counters that cannot be opened refuse the link, an initiator reads the OpenAck against
  the offer in the InitAck, an unmappable segment refuses it, and a malformed InitSyn is
  ignored, which 1.10.x has done since the `bail!` of 1.5.0 went; `ShmAuthError`); (e) an
  unresponsive peer's pipelines are disabled at once and its transport is
  deleted and not closed with a frame (the first half taken in round R4006: a session a
  congestion close was ordered of refuses every later send at once, `congestion_close_ordered`;
  wz still sends a Close frame with reason UNRESPONSIVE, which is the statechart's
  `tx.congestion.exhaust` arm, not changed here); (f) a newer link state restates the role of its node
  (`crates/wz-routing-graph/src/lib.rs` fills it only while unknown), and an interest that goes
  away clears the finalised flags of its face (both taken in round R4006: a newer link state
  now restates the role of its node whether or not it was known, and an end of interest takes
  the flags its `DeclareFinal` set off the gateway); (g) the start conditions of a peer are released
  by a synchronous call (measured in round R4006: an internal change of upstream's, a sync mutex
  in place of an async one so that a connector task cannot deadlock the session under the
  router's lock; wz has no `StartConditions` or `wait_declares`, so there is nothing to carry).
  Taken in the same round: the key `segmentation_offload` of a QUIC
  locator, and the dropping of multicast addresses from a `tcp` or `tls` name. Round R3987 moved
  the zenoh-pico submodule to 1.10.2 and FreeRTOS-Kernel to V11.3.3 (which upstream published in
  between). Measured: the pico CLI oracles build from the new tree (its CMake now includes
  `cmake/feature_config.cmake`, where the switch definitions moved, and
  `scripts/lib/upstream_switch_map.py` reads both files; 49 switches before and after), the arm
  headers agree with the defconfig, the pico drop-in programs on the tokio engine and the
  `--ignored` demo sweep pass, and the Zephyr comparison image builds in both arms once its
  Kconfig states the switches pico's own defaults had on (the module's Kconfig has no default
  for a switch, so an unstated one is off, which dropped `z_encoding_application_json`). FreeRTOS
  V11.3.3 built on `thumbv7m` and booted on `mps2-an385` (session established). (h) carried from
  the pico release: 1.10.2 refuses a timestamp whose ZID length is over 16 when it decodes one
  (#1345), and so does zenoh; the wz decode of the `Timestamp` codec as a view slices `zid_len`
  bytes without that bound (`out/wz-codecs/timestamp.rs`, generated from `sce:max-size="16"` in
  `sources/codecs/timestamp.scxml`, which the view decode does not enforce), and the sample
  projection then truncates to 16 (`crates/wz-session-core/src/sample.rs`). Read in the
  generated code, not run; the repair is in the generator's decode of a bounded length-ref
  field, which is the SCE owner's.

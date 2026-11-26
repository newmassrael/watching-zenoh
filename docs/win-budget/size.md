# Size: where the pico preset's code exceeds zenoh-pico's, and the designs that close it

This note reads the text of `pico-client-coop-nostd` (`scripts/lib/size_ledger_gate.py`, the
cooperative client built without `std`, as every pico library is) against zenoh-pico's build of
the same capabilities, area by area, and states for the three largest gaps a design that removes
bytes rather than moves them. `text.md` holds the earlier per-area budget (S1 to S10, D1 to D8,
X1 to X5, R1 to R5) and its lanes; this note is the reading those lanes are judged against now, and
what that reading changes in them.

## 1. The reading

The size ledger's `--explain` report of the case's last measurement (2026-11-27), by area. The
ratio is wz over pico; an area under 1 is already won.

| area | wz | zenoh-pico | wz - pico | ratio |
|------|---:|-----------:|----------:|------:|
| sessions | 67,996 | 27,508 | +40,488 | 2.47 |
| doors | 42,609 | 19,034 | +23,575 | 2.24 |
| transport | 30,913 | 13,951 | +16,962 | 2.22 |
| driver | 30,060 | 16,049 | +14,011 | 1.87 |
| keyexpr | 8,257 | 13,490 | -5,233 | 0.61 |
| codec | 28,600 | 35,440 | -6,840 | 0.81 |
| language | 10,935 | 45,028 | -34,093 | 0.24 |
| unclassified | 417 | 0 | +417 | |
| total | 219,787 | 170,500 | +49,287 | 1.29 |

The total is under pico once 49.3 KB go; every area at or under pico needs 95 KB to go from the
four losing areas, since the three won areas cannot pay for them in the ledger, which grades each
area by its own row.

What the reading rules out, before any design: duplicate generic bodies. The report's list of
generic functions with more than one copy sums to 3.6 KB of bytes beyond each function's largest
body over all areas (the most, `kept::Shared::last_placed` 1,023 in four bodies, is four types'
drop glue, not one body copied). In this preset each generic engine body has one instance: the
engine is `CoopEngine<IpLinks<PosixUdpSocket, PosixTcpDial>, PosixClock>` alone. Folding typed
bodies into one untyped body therefore has no copy to fold, and keeps at run time what the typed
body resolved when compiled: the T-DECL lane's reading tdecl-13 measured its first form at sessions
+1,539 where -800 to -1,500 was expected (that lane's `t-decl.md`, section 11). A design here
removes work the preset's build does not need, or does the needed work in fewer instructions; it
does not move code between bodies.

## 2. The areas against zenoh-pico, job by job

Bytes are each side's in the area (a wz body's bytes in other areas are not counted here). A pico
function is cited at its definition in the submodule the reference is built from.

### 2.1 Sessions (+40,488)

| job | wz (bytes in sessions) | zenoh-pico |
|-----|------------------------|------------|
| open, arena and assembly | `engine::lend_session` 4,535, `CoopEngine::assemble` 3,704, `arena` 2,925 (owner), `open_source::write_into` 696, `session_zid` 532, `PeerTables::init_in` 491: about 12,900 | `vendor/zenoh-pico/src/net/session.c` @ `static z_result_t _z_open_connect_locator(` 1,115 and the file's other open functions (4,124 in all), `vendor/zenoh-pico/src/session/utils.c` @ `z_result_t _z_session_init(_z_session_t *zn` 354: about 4,800 |
| declaration and undeclaration | `Declaring::declare` 1,514, `undeclare_write_filter_quietly` 1,423, `declare_subscriber_on_wire` 1,324, `declare_keyexpr_where` 1,219, `Declaring::keyed` 1,038, `undeclare_subscriber` 779, `undeclare_matching_listener` 536; the row tables `slot_map` 6,600, `key_arena` 3,146, `id_map` 726 (owners): about 18,300 | `vendor/zenoh-pico/src/net/primitives.c` @ `z_result_t _z_register_subscriber(` and the file (3,111), `vendor/zenoh-pico/src/net/filtering.c` @ `z_result_t _z_write_filter_create(` and the file (1,532), `vendor/zenoh-pico/src/session/resource.c` @ `z_result_t _z_register_resource_inner(` and the file (1,323), the session header's list bodies (1,929), matching (403): about 8,300 |
| a peer's declarations, interests, replay | `replay::told` 1,009, `engine::replay` 1,043 (owner), `RemoteSubscriberTable` 1,092, `take_control_of_event` 705, `wireexpr_resolve` 1,068 (owner): about 4,900 | `vendor/zenoh-pico/src/session/interest.c` @ `z_result_t _z_interest_process_declares(` and the file: 4,077 |
| the link's turn and the receive | `link_turn` 2,784, `DirectSink::event` 2,012, `drive_link` 1,165, `link_life` 1,529 (owner), `engine::direct` 6,005 (owner, which holds the first two): about 7,500 | `vendor/zenoh-pico/src/session/rx.c` @ `z_result_t _z_handle_network_message(` and the file (1,040), `vendor/zenoh-pico/src/session/subscription.c` @ `z_result_t _z_trigger_subscriptions_impl(` and the file (1,761): about 2,800 |
| the put | `put_through_filter` 2,053, `publish_options` 503, `sample` 525: about 3,100 | `vendor/zenoh-pico/src/net/primitives.c` @ `z_result_t _z_write(_z_session_t *zn` 328 and the sample bodies (1,432): about 1,800 |
| extension admission | `ext_admit::judge_entry` 991 and the owner's other bodies: 2,318 | none in sessions: pico's extension reading is its codec's (911 bytes there) |

### 2.2 Doors (+23,575)

| job | wz | zenoh-pico |
|-----|----|------------|
| the composed doors | `z_open` 2,215, `open_request` 1,490, `z_declare_publisher` 1,901, `declare_subscriber_with` 1,359, `z_declare_keyexpr` 903, `DeclaredKeyexpr::kept_with` 882, `key_from` 728, `matching::declare_on_filter` 615: about 10,100 | `vendor/zenoh-pico/src/api/api.c` @ `z_result_t z_open(z_owned_session_t *zs` 478, `vendor/zenoh-pico/src/api/api.c` @ `z_result_t z_declare_publisher(` 223, `vendor/zenoh-pico/src/api/api.c` @ `z_result_t z_declare_subscriber(` 222: about 1,300 for the same doors |
| the put doors and the sample | `publisher_write` 783, `session_write` 766, `PutCarried::fold` 418, `clone_sample_marshal` 1,430 | `vendor/zenoh-pico/src/api/api.c` @ `z_result_t _z_publisher_put_impl(` 302 |
| bytes and serialization | `bytes` 5,697 and `serde` 1,950 (owners) | `vendor/zenoh-pico/src/api/serialization.c` @ `z_result_t ze_serialize_buf(` and the file: 4,886, beside pico's byte collections, which its rules place in language (3,125) |
| object families, pools, boundary | `process_pool` 1,978, `object_slot` 1,342, `ffi` 945, `ffi::boundary` 873, `abi` 773, `handlers` 1,090 (owners): about 7,000 | the owned-type macros' bodies, counted with the doors' file |
| configuration | `config` 1,284 (owner; `ConfigEntries::insert` 704 of it), `config_limits` 616 | pico's configuration is a string map, in language (1,641) |
| the other doors | about 12,500 | the doors' file's others and the encodings: about 11,000 |

### 2.3 Transport (+16,962)

| job | wz | zenoh-pico |
|-----|----|------------|
| the send side | `session_actions` 10,706 (owner): `open_frame_lent`, `dispatch_network_message_in`, `LentDeclaration::encode`, `lend_frame`; `tx_buf` 1,167, `tx_lease` 743, `tx_deadline` 378 | `vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_send_n_msg_inner(` 1,261 and the file: 3,483 |
| the handshake and the session's machine | `sce_rust_runtime` (engine 4,574, microstep 1,291, event queue 1,071, tables 557, state set 548, run store 154): about 8,200 | `vendor/zenoh-pico/src/transport/unicast/transport.c` @ `static z_result_t _z_unicast_handshake_open(` 873 and the file: 2,324 |
| the read, control messages and fragments | `read_control_in_place` 2,034 (and 3,786 more in codec), `fragment_in_place` 2,062, `UnicastRx` 1,751, `LinkSession` 1,328, `reassembly_dispatch` 2,111 (owner) | `vendor/zenoh-pico/src/transport/unicast/rx.c` @ `static z_result_t _z_unicast_handle_fragment_inner(` 825 and the file (1,820), `vendor/zenoh-pico/src/transport/unicast/read.c` @ `static z_result_t _z_unicast_process_messages(` and the file (1,010) |
| lease and keep-alive | `transport_timers` 786, `keepalive_deadlines` 511 | `vendor/zenoh-pico/src/transport/unicast/lease.c` @ `_z_fut_fn_result_t _zp_unicast_lease_task_fn(` and the file: 626 |

### 2.4 Driver (+14,011)

| job | wz | zenoh-pico |
|-----|----|------------|
| endpoint text | `locator_text` 2,246 (`dial_step` 1,301 of it), `endpoint` door text | `vendor/zenoh-pico/src/link/endpoint.c` @ `z_result_t _z_locator_from_string(` and the file: 3,154 |
| dial and the link's open | `IpLinks::begin_initiator` 2,419, `dial_step` 1,671, `faces::Dial::answer_on` 1,084, `dial::begin` 925, `LinkPlace::stream` 548 | `vendor/zenoh-pico/src/link/link.c` @ `z_result_t _z_open_link(` and the file (1,322), the TCP and UDP link files (1,560) |
| sockets | `runtime_posix::net` 2,805, `stream` 1,036, `stream_link` 2,425, `udp_link` 1,230, `link_storage` 1,500 | `vendor/zenoh-pico/src/link/transport/tcp/tcp_posix.c` @ `z_result_t _z_tcp_open(` and the file (1,562), `vendor/zenoh-pico/src/link/transport/udp/udp_posix.c` @ `z_result_t _z_udp_unicast_open(` and the file (1,497) |
| locks, cells, executor | `wz_host_sync` 2,867, `kept` 2,005, `link_cells` 1,506, `faces` 2,898, `executor` 227 | `vendor/zenoh-pico/src/runtime/executor.c` @ `_z_executor_status_t _z_executor_spin(` and the executor header (2,359), `vendor/zenoh-pico/src/system/unix/system.c` @ `z_result_t z_sleep_ms(` and the file (1,876) |

## 3. The three largest gaps, and a design for each

### 3.1 Sessions: a session of the preset carries only the forms the preset makes

The sessions area is not large because a body is copied; it is large because the session core is
one source for every engine and policy, and a build compiles every form a type can hold even where
the preset never makes it. Three kinds of such forms are in this build.

- **A form only the growable policy makes, read by every policy.** A peer space reads a plain map
  of a peer's keys or our own table of declarations only when its policy is the heap's, yet every
  read compiled for the lent and region policies carries the hash map probes of both:
  `PeerSpace<Region>::literal` is 425 bytes in this build, two hashbrown probes of 135 and 131
  bytes and the alias table's 100-byte scan, and the 266 bytes the report places in language under
  `hashbrown` are those two probes. The design: the policy states, as a type, whether such a form
  exists (`Storage::HeapForm`: the unit on `Heap`, `Infallible` on `Static`, `Lent` and
  `Region`); a variant only the heap makes carries it, and its arm consumes it first
  (`HeapOnly::granted`), which on a bounded policy is a match on a value that cannot exist, so the
  compiler drops the arm. The heap's forms are made only in the heap's `impl` block. Section 4 is
  this step, landed with this note.
- **A Rust program's closure, in a C library.** Every sink of the port has two forms: a C closure
  (its function, context and drop) and a Rust closure shared by an `Arc` (`SubscriberSink::Shared`,
  `MatchingSink::Shared`, `LivelinessSink`, `QueryableSink`, `ReplyCallback`,
  `DeclWatchSink`). A C library makes only the first: in this build nothing constructs
  `SubscriberSink::Shared` or `MatchingSink::Shared`, yet each call carries the shared arm's
  indirect call and each drop of a row its `Arc` release. The design: the shared form behind a
  port feature that the engines with a Rust API name (`wz-capi-core`, `wz-zenoh`, `wz-capi-c`'s
  matching, the fuzz targets) and the pico library does not; the coop engine's own uses of a shared
  sink (its declaration watch and liveliness planes) are behind the features that build those
  planes. Measured basis: `Arc<dyn Fn(&dyn SampleView)>::drop_slow` (106 bytes; its five callers
  in this build are the subscriber rows' drop and four engine methods) goes whole, and the shared
  arms at each call and drop go with it.
  Expected -300 to -500, sessions and doors. A new feature name passes the census and prose-name
  gates in its own commit.
- **The open's work, generic over nothing but made once per open.** `lend_session` and
  `assemble` are already one body each; their 8,200 bytes are the open's own work against pico's
  4,800, mostly the per-layer table placements written out one call per table. `text.md` S3's
  plan (a non-generic `SessionPlan` the engine only places cells from) is that design, lane
  T-OPEN; this reading does not change it, and its gate is this case's sessions row.

The per-call work of declare and undeclare (the parts moved by value, the link set's judgement, the
refusal paths, the own key) is what tdecl-13 left as the declarations' debt; S1 stays the design,
stated against a build where two kinds with callbacks coexist.

### 3.2 Doors: a door reads its arguments into one request and makes one engine call

pico's doors are each about 220 bytes because each reads its C arguments and calls one function of
the session layer (`_z_declare_subscriber`, `_z_declare_publisher`), which does the work once for
every door. wz's composed doors (`z_open` with `open_request`, `z_declare_publisher`,
`declare_subscriber_with`, `z_declare_keyexpr` with `kept_with` and `key_from`) each inline
the key's canonization, the slot's take, the option's fold and the declaration's build: 10,100
bytes against pico's 1,300 for the same doors. The design is `text.md` D1 completed: each door
reads its arguments into one value (`DeclareRequest { kind, key, callback, options }`, an
`OpenRequest`) and calls one `#[inline(never)]` body below the exports, which canonizes the key
once (in the engine's key step, not in each door) and owns the slot's take and its refusal. What
it removes: the second and later copies of the key path and the slot path, about 4,000 by the
bodies above; what it keeps: one body per job. Its gate is the doors row of this case, and the
receive doors (`marshal_sample` and the sample views) are out of its scope.

### 3.3 Transport: one batch writer, and the handshake's machine on tables

The send side is 10,700 bytes against pico's 3,500 because a message is written through
`open_frame_lent` over a `dyn Fn`, a sizing pass and a writing pass, and a write per message kind;
pico writes every message through one `_z_transport_tx_send_n_msg_inner` into one batch. The
design is `text.md` X1: one `TxBatch` with one `write_n_msg` (open a frame for the message's
reliability when none is open, write in place, on no room flush once and retry, a message larger
than a batch to one cold fragment body). The second share is the session's machine: 8,200 bytes of
SCE runtime against pico's 2,300 of hand-written handshake. Its design is SCE's (X3: the runtime's
operations one body each, the machine's tables as data), proposed through `docs/sce-proposals/`
and measured in text plus rodata. Section 6 reads both again on the writer as it landed.

## 4. The step landed with this note: a peer space's heap arms out of the bounded policies' reads

`wz-session-core`'s `Storage` gains `type HeapForm: HeapOnly`: `()` on `Heap`, and
`core::convert::Infallible` on `Static`, `Lent` and `Region`. `HeapOnly::granted` is a no-op
on the unit and `match self {}` on `Infallible`, both `#[inline(always)]`. `PeerSpaceRepr`'s
`Map` and `Ours` variants keep their references (so the peer space stays covariant in its
lifetime, and `Send` and `Sync` as before) and carry `P::HeapForm` beside them; the constructors
of the two variants moved into an `impl PeerSpace<'a, Heap>` block, the only place a value of the
unit exists; each of the three reads (`declared`, `literal`, `PeerSpaceView::len`) calls
`granted` first in those arms. On `Region` the arm begins with an unreachable instruction, so
LLVM removes the switch's cases for both variants and the hash map probes behind them.

Why the arm and not the variant: a variant whose field is a non-zero-sized reference stays in the
enum's layout even when another of its fields is uninhabited, and the enum's niche keeps a value
for it, so only the arm's own unreachable start removes its code. A reference read through a
projection of the policy would remove the variant from the layout, but a projection is invariant in
its lifetime, which the peer space must not be.

Expected on the case: `PeerSpace<Region>::literal` 425 to about 150, language -266 (the
`hashbrown` lines of the report), about -280 in all; nothing on the heap builds, whose arms are
unchanged. Tests: `bounded::tests::only_the_growable_policy_has_a_value_of_its_heap_forms` holds
each policy's `HeapForm`; the heap arms stay covered by `wireexpr_resolve`'s tests over
`peer_only`, `with_own` and `as_sent`.

## 5. Measuring

The main session reads each step on the case's explain report: the area table above, and for this
step the body `PeerSpace<wz_session_core::bounded::Region>::literal` and the `hashbrown` owner
lines in language. A step whose area does not move by its expectation is reverted, as tdecl-13 was.

## 6. Transport read again: the send writer as it landed, and the session machine's bytes

Read from the size ledger's `--explain` document of this case dated 2026-11-26 (schema 5), whose
transport area is 30,814 against pico's 13,951. Bytes are each side's in the area, as in section 2.

### 6.1 X1: the one writer is there; what the send side still holds

`text.md` X1's `TxBatch` landed as `SessionLinkActions::write_n_msg`: one body opens the frame for
the message's reliability, joins the conduit's open frame or sends it once and opens the next,
mints the SN where the slot is written and gives it back where the frame does not leave
(`crates/wz-session-core/src/session_actions.rs` @ `fn write_n_msg(`). Fragments and control
messages do not carry a buffer of their own either: a fragment is written by
`frame_encode::write_fragment` through `send_lent`, and an Init, an Open and a Close through
`send_control_lent`, both into the one lend `send_lent_on`. The frame opener over a `dyn Fn` and
the sizing pass of section 3.3 are gone from the lend-only build (`size_hint` measures nothing
there); the message's writer is one `&dyn WireWrite`, so the writer is one body for every kind.

| body | bytes | what it is |
|------|------:|------------|
| `dispatch_network_message_in::<false>` | 1,517 | the gate (availability, limits), the deadline, the Control barrier, the conduit lock and the outcome; pico's `_z_transport_tx_send_n_msg_inner` 1,261 does the same jobs but the barrier |
| `write_n_msg` | 1,498 | the frame lend (section above); pico has no slot lend, its batch is one buffer |
| `dispatch_declare_lent::{closure#1}` | 1,177 | the declaration's composition and its encoder, inlined into the one encoder closure: codec and sessions work, not the send's |
| `emit_fragment_chain`, `send_fragment`, `emit_fragments_encoded` | 1,302 | the chain's plan, per-fragment room and credit, the stop marker; pico's `_z_transport_tx_send_fragment` 414 has no credit and no stop marker |
| `send_control_lent::{closure#0}` | 376 | `write_control`: Init, Open, Close and the held answer into the lent slot |
| `CoopEngine::send_on_links`, `CoopEngine::place_link_session` | 1,539 | the engine's fan-out of a put to the session's links (844) and its placing of a link's session (695), attributed here by their inlined lines |

So X1's remaining bytes are not a second writer: they are the dispatch's admission jobs that pico
does not have (the barrier, the probe, the expiry run) and the fragment chain's credit and stop
marker, each a behaviour the parity contract states. A further cut here is a change of what the
lend-only preset does (for example a preset in which no session holds a window open, so
`write_n_msg`'s join arm is not compiled), which is a preset decision and not this lane's.

### 6.2 X3: where the session machine's bytes are

The generated code is not where the machines are large. The three machines' own code in this
image is 583 bytes (`out/wz-session-core/unicast_link_sm.rs` 309, `session_fsm_unicast_sm.rs`
211, `reassembly_slot_sm.rs` 63, the last in sessions): their selection is already rows (SCE ADR
0135, the `candidates` of each `DocumentTables`), their microsteps read `entry_rows`, and what is
left of the generated code is the hooks' `match` over a state or transition number calling one
host action each. Writing those hooks as action-op tables too would remove at most about 300 bytes
of text for about 100 of rodata: a table-driven generator is not X3's lever.

The SCE runtime is 8,319 bytes of the area, in three parts:

| part | bytes | bodies |
|------|------:|--------|
| the shared walk, one body for every machine | 3,505 | `Turn::run` 1,296, `exit_states_from_rows` 655, `enter_states_from_rows` 562, `select_transition_from_rows` 474, `Turn::take_microstep` 389, `Turn::take_event` 129 |
| the per-machine monomorphs | 1,491 | `Engine::run_turn` 468 in 3, `Engine::new_in_place` 353 in 3, `EngineHost` `enter_state` 198 in 3, `queue` 137 in 2, `execute_transition_content` 137 in 3, `store` 114 in 2, `exit_state` 51 in 2, `behaviour` 33 in 3: 793 beyond each one's largest body |
| the engine's API inlined into the host's bodies | 2,422 | the session machine's `process_event` (its queue push and its turn) in `LinkSession::service_due` and `init_in` 777, `drive::dispatch_copied` 256, `CoopEngine::link_turn` 240, `UnicastRx::dispatch_datagram` 164, `drive::admit_head_in_place` 156, `drive::dispatch_control_in_place` 153: 1,746; the link machine's in `UnicastLink::input` 519 and `new` 100; the slot machine's in `turn_slot_engine` 57 |

pico's handshake is `vendor/zenoh-pico/src/transport/unicast/transport.c` @
`static z_result_t _z_unicast_handshake_open(` 873 and the file's other bodies, 2,324 in all.

### 6.3 The wz step landed with this section: one body hands the session machine its events

`wz_session_core::drive::deliver_session_event` is `Engine::process_event` out of line, and every
path that tells the session machine something calls it: `dispatch_link_lost`,
`dispatch_link_event`, `dispatch_unit_in`, `dispatch_lean_unit`, `admit_head_in_place`,
`refused_data_unit`, `dispatch_control_in_place`, `lean_in_place`, `frame_in_place`,
`judge_lease`, `check_requested_close`, `check_out_of_band`, `TransportTimers::fire_due`, and the
coop pump's role activation (`LinkSession::init_in`, `open_step`). None of them is on a sample's
path: each is a refusal, a decided handshake event, a timer that has fallen due or a request from
outside the loop, so the receive's per-message instructions do not change; what goes is the inlined
copy of the queue push and the turn's opening and closing in each of those bodies.

Expected on the case: of the 1,746 bytes above, one body of about 300 stays and each caller keeps a
call: transport about -900 to -1,400 (`drive::dispatch_copied`, `dispatch_control_in_place`,
`admit_head_in_place`, `UnicastRx::dispatch_datagram`, `LinkSession::service_due` and
`CoopEngine::link_turn` each lose their `sce_rust_runtime::engine` and `event_queue` lines;
`LinkSession::init_in` keeps its `initialize`). The test is `wz-runtime-coop`'s
`session_drive::wake_budget_tests::the_session_machine_takes_its_events_through_the_one_body`.

### 6.4 Proposal for SCE: the runtime's share, in three items

Graded by text plus rodata (`text.md` O4), on this case's transport area and on the same image's
callgrind of one handshake and one fragmented message (cell M9 of `text.md`).

1. **`Engine::process_event` (and `lend_event`, `initialize`) out of line in the runtime.** Each
   is `pub fn` with no inline attribute, so a host that calls it from N places carries N copies of
   the queue push and the turn's `begin_turn`/`end_turn` around the one `run_turn` call
   (`vendor/sce/backends/rust/runtime/src/engine.rs` @ `pub fn process_event(&mut self, event: P::Event) {`).
   `#[inline(never)]` there gives every host what section 6.3 gives the session machine of this
   one, without a wrapper of its own; for this image, after 6.3, about -100 more (the link and slot
   machines are reached from one body each already). Instructions: one call per event, which is per
   transport event and never per sample.
2. **Fold the machine-independent half of the per-machine monomorphs.** `run_turn` builds the
   machine's workspace and its `EngineHost` and hands `Turn::run` a `&mut dyn MainLoop`: the
   workspace split and the `Turn` construction do not depend on the policy beyond the workspace's
   size, which the tables can state. The same holds for the core fields `new_in_place` writes.
   Expected -300 to -500 of the 793 duplicated bytes; the hooks (`enter_state`, `exit_state`,
   `execute_transition_content`) stay one per machine, since each calls its policy directly.
3. **Exit rows beside the entry rows.** For a document the row walk serves (no `<history>`, no
   `<parallel>`, no transition of more than one target), the exit set of a transition taken from an
   atomic state is fixed as its entry path is: the chain from that state up to the domain's child,
   in exit order. The generator writes it as `exit_paths` (as it writes `entry_paths`), and
   `exit_states_from_rows` reads one row and calls the exit hook per state instead of computing the
   set against the configuration through the state set. The three machines of this image are of
   that class (configurations of at most two states, no internal events). Expected
   `exit_states_from_rows` 655 to about 200 and the state set's 548 to about 250, -600 to -800 of
   text for about 60 of rodata; per transition a few instructions fewer (no set to sort).

Together with 6.3 the transport area moves by about -1,800 to -2,700. The gap to pico that remains
is the receive's (`drive` 4,657, `reassembly_dispatch` 2,111, `transport_timers` 786: `text.md`
X2, X4, X5) and the send's admission jobs of section 6.1.

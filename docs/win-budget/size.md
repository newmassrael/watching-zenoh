# Size: where the pico preset's code exceeds zenoh-pico's, and the designs that close it

This note reads the text of `pico-client-coop-nostd` (`scripts/lib/size_ledger_gate.py`, the
cooperative client built without `std`, as every pico library is) against zenoh-pico's build of
the same capabilities, area by area, and states for each area that loses a design that removes
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

## 3. The four losing areas, and a design for each

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

#### 3.1.1 The sessions designs, by what each is expected to remove

Read from the case's explain report of 2026-11-27, by owner (the bytes a module's lines place in
sessions, inlined into other bodies included) and by body. First, four forms this area could take,
and what the reading says of each:

- **One row store for the slot map, the key arena and the id map.** The three owners place 6,600,
  3,146 and 726 bytes, but their own bodies are 1,261, 841 and 139: about 8,200 bytes are their
  lines inlined into some 30 other bodies, the declarations' above all (`declare_write_filter`
  778 of the slot map and 331 of the key arena, `undeclare_write_filter_quietly` 730 of the slot
  map). The three are not copies of one another (a table of generational slots, an arena of
  counted texts, a map of a peer's ids) and each body has one instance in this build, so one store
  that serves all three by a shape read at run time folds no copy and keeps at run time what the
  typed face resolved: tdecl-13's +1,539 (`t-decl.md`, section 11) in another table. The inlined
  bytes are the call sites' own work (a row moved out of its slot by value for its caller to drop,
  an `Option<Removal<T>>` made and taken apart, a free-slot check per insert), so the design is at
  the call sites (S-ROW), not in the store.
- **One declaration transaction for every kind.** Each kind's declaration and undeclaration has one
  instance in this build (one kind whose row keeps a callback, `t-decl.md` 11.2), so there is no
  second body to fold. What is large is the write filter's plane, whose bodies are separate tables
  and not instances of one generic (S-FILTER).
- **The open as a plan computed when the build is compiled.** The region build has one already:
  `ArenaRegion` is the plan evaluated at compile time, and the open copies it whole
  (`ArenaRegion::lay_out_on`). What the open still lays out at run time are the holds after the
  rows (`lay_out_open`: the links' cells, the rooms, the ABI's places, the runtime's span, the
  engine's place, the planes), each of them a size of a type or a constant of the ABI in this
  build (S-OPEN).
- **The extension admission left out of the build.** It is not a path the preset may leave out: it
  refuses a message whose chain carries a mandatory extension the message does not declare, the
  reserved encoding, or a declared extension whose body its own reader refuses (`ext_admit.rs`),
  as both upstreams do, zenoh-pico in its codec (911 bytes there). Leaving it out would change what
  the session accepts. Its 2,318 bytes against those 911 are not designed here.

| design | job (2.1) | what goes | expected, sessions | basis | status |
|--------|-----------|-----------|-------------------:|-------|--------|
| S-FILTER: a write filter is one row | declaration | Where a write filter is the only owner of an Interest (this preset: no liveliness, no querier), the Interest's facts (its id, its mapping, its aggregate, its suffix) are fields of the filter's row and the filter's matching listeners a count and slots on it, as zenoh-pico keeps one context per filter with its interest's id and its callbacks; the Interest table, its slot map, `open_interest`, `close_interest`, `interest_rank` and the listeners' own table go. A build with another owner of an Interest keeps the table, by `Presence`, as the queryables' table is kept. | -2,500 to -4,000 | the plane's bodies: `declare_write_filter` 2,418, `undeclare_write_filter_quietly` 1,423, `declare_filter_matching_listener` 640, `read_matching` 638, `undeclare_matching_listener` 536 and 418, `undeclare_write_filter` 407, `keep_write_filter_plain` 375, `write_filter_row_open` 316: about 7,200, against `filtering.c` 1,532 and matching 403 | designed; lane T-DECL. An Interest's place in the replay moves with its filter's, so the replay's order and the told walk are read again with it |
| S-OPEN: the holds join the region | open, arena, assembly | The region is made with the holds of the engine type the ABI builds (`lay_cells` and `lay_held` as const fns, the runtime's span from the region's limits), so an open by it lays out nothing: `lay_out_open` and the lays it calls are evaluated with the region, and the open keeps only its comparison of the config with the region (`ArenaRegion::admit`), whose refusals are the ABI's | -800 to -1,500 | `lend_session` 4,535, of which 2,303 are `arena`'s lines (the lays, `settled`, the tables' places); `ArenaPlan::put` 88, `put_table` 46, `settled` 46 and `refuse` 22 are bodies only the open calls in this build | designed; lane T-OPEN, with `wz-capi-pico/src/session.rs`, where the region's constant is made |
| S-ROW: a row that owns no program callback is dropped where it lies | declaration | `SlotMap::discard` and `Entry::discard`: the untyped core retires the row and the row is dropped in its slot, with no copy of it moved out through `Removal<T>` and its caller's frame. A write filter's undeclaration hands back its Interest's id and its key's hold alone (`FilterUnwatched`); an Interest's row and a declaration's row go the same way | -300 to -600 | a write filter's row, the largest of the four (its plain way, a put's facts and head, beside its key), was moved out of its slot to `unwatch_filter`'s frame to be dropped there under the same lock; `close_interest` (two callers), `release_keyexpr` (an entity's two holds, the program's own) and `retract_keyexpr` each moved a row out to drop it at once | landed with this section, the first step: no file of another lane, and S-FILTER's one row is undeclared this way |
| S-SINK: the shared closures out of the C library | declaration, receive | section 3.1, second bullet | -300 to -500 | as stated there | designed |

The link's turn and the receive (7,500 against 2,800) are not designed here: their bodies are the
receive path (`DirectSink::event`, `hand_row_by_row`, the sample's marshal), whose instructions
per message are under zenoh-pico's (3,078 against 4,049), and a design that moves bytes out of
them is judged on both readings.

Order: S-ROW first, as it moves no wire behaviour and takes no other lane's file; S-FILTER next, the
largest, whose undeclaration of its one row is S-ROW's; S-OPEN with T-OPEN's lane, which holds the
region's constant; S-SINK with the census and prose-name gates its feature name moves. Each is read
on the case's sessions row and on the bodies named in its basis, and reverted when its row does not
move by its expectation, as tdecl-13 was. S-ROW reads on `undeclare_write_filter_quietly`
(1,423), `unwatch_filter` (104), and the bodies that inline `close_interest`, `release_keyexpr`
and `retract_keyexpr` (`declare_write_filter`, the subscriber's undeclaration, the
declarations' own).

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

What the explain report of 2026-11-26 shows of this design, read before its step: the composed
doors are one body per job already, each reached from its exports as shells. `session_write`
(`z_put`, `z_delete`), `publisher_write` (the publisher's put and delete),
`declare_subscriber_with` (both subscriber doors), `declare_on_filter` (every matching listener
door), `key_from` (every key constructor and judgement), `kept_with` (every copy and extension
of a key), `open_request` (the open's reading of its config), `put_options` and
`PutCarried::fold` are each one symbol, and their helpers are out of line (`outbound_keyexpr`,
`EntityKey::up_to`, `Lender::lend`, `PublisherQos::apply`). In this build each of those bodies
has one family of callers, and the ledger places a body's bytes at its source lines, so taking
`open_on_coop` (2,008 of `z_open`) or `declare_entity_at` (the 695 of `write_filter` in
`z_declare_publisher`) out of line moves bytes between symbols and leaves the area where it is.
The one helper the report shows copied into several declaring bodies was `refusal_code` (194 in
four), now one body. The rest of the gap is the work these bodies do in the door crate: the write
filter's plain form and record (`write_filter` 807), the places a session lends (`object_slot`
1,341, `process_pool` 1,978), the key's holds and its text in the key arena (`keyexpr` 5,154),
the open's composition. What removes it is less work per declaration and per open (S1's pipeline,
T-OPEN's plan), measured on this row, not a second split of the doors.

#### 3.2.1 Doors: the declaration as one request, and the place that carries its lender

The reading above leaves the declaring doors one body each; what they still hold is the composition
pico's doors leave to its session layer. On the explain report of 2026-11-26 the four declaring
bodies of this build are `z_declare_publisher` 1,901 (`write_filter` 695 of it, which is
`FilteredKey::declare_at`: the key's declaration, the entity id, the filter's Interest and the
record; `pubsub` 632; `object_slot` 137), `declare_subscriber_with` 1,359 (`pubsub` 625,
`keyexpr` 333 for the subscription's own key, `wz_capi_port` 139, `object_slot` 105),
`z_declare_keyexpr` 903 (`keyexpr` 661, `object_slot` 114) and `declare_on_filter` 615
(`matching` 288, `ffi` 111, `object_slot` 93). pico's `z_declare_publisher` is 223 bytes
because `_z_declare_publisher` and `_z_write_filter_create` do that work below it, in bodies the
ledger counts in sessions. The structure has three parts; each keeps every check it has today in
one place, and none touches the put or the receive.

- **A lent place carries its lender from the take (landed with this note, section 7).** The take
  of an entity's place is one body already (`Lender::lend`), but it handed the lender back to the
  door, which moved it through a four-word slot and wrote it into the place at the fill
  (`Lender::attach`, inlined per object type), and a refused fill or a release read it back out of
  the place by the object's type. The lender is now written into the place by the one body that
  lends it, at an offset handed to it as a value (`InSession::<T>::LENDER_AT`), the slot is the
  place and a flag, the fill writes the object alone, and a refused fill and every release give
  the place back through one body that reads the lender at that offset
  (`give_back_lent_place`). Basis: `object_slot` bytes in the lent declaring bodies (137, 105,
  93, 29) and `release_entity::<PublisherState>` 125. Expected doors -120 to -250. Textbook
  because it is the allocator's own shape: the header an allocation keeps is written by the
  allocation, and the free reads it from the address, so no caller carries it.
- **One request to the engine for the declaration's work.** Each declaring door reads its
  arguments into one `DeclareRequest` (the entity kind, the key the outbound gate admitted, the
  caller's declaration when its key has one, the QoS and locality the options fold to, the C
  closure's parts, the place the slot took, the door its refusal is answered at) and makes one
  port call, `SessionEngine::declare_entity`, which does in one engine body what the door now
  composes: the key's declaration, whole or up to its non-wild prefix, the entity's row with the
  record taking its hold of that declaration directly, and for a publisher the filter's Interest
  and its plain form. Two steps a declaration takes twice become one: the door's key step
  (`EntityKey::up_to`) beside the engine's own (`declare_keyexpr_where`, `Declaring::keyed`),
  and the door's hold that is taken, handed to the record and let go (`EntityKey`'s `taken` and
  its drop). The checks stay
  where they are, one body each: the session's reading (`open_session_handle`), the key's gate
  (`outbound_keyexpr`, which reads the constructor's proof mark and judges again only an
  unchecked view) and the refusal's code (`refusal_code`, the request naming its door). Expected
  doors -1,600 (`declare_at` 695, `EntityKey::up_to` 355, the subscription's key steps about
  330, the port's glue about 220), sessions about +700, net -900 to -1,200. It is the doors' half
  of S1's `declare` (lane T-DECL), and lands on the engine method that lane makes, not beside it.
- **What stays out, and why.** The put and delete doors (`session_write`, `publisher_write`,
  `PutCarried::fold`) are the hot path: each is one body, its options fold once, and a put's key
  is judged by the proof mark its constructor set, so a request there would add a call per put.
  The open is S-OPEN's and T-OPEN's. Bytes and serialization (D3), the object families (D2), the
  encodings (D4), the configuration (D5) and the platform exports (D6) are `text.md` section 10.3's
  rows; the doors row reaches pico only with those, and the two parts above remove the declaring
  work's share, about 1.8 KB of the 23.6 KB.

Ir: the first part changes the declare and undeclare paths only; a pool's slot (a sample's clone)
tests a flag where it tested the lender's niche, the same instruction. The second adds no call on a
put or a receive. The receive's 3,078 instructions a message are not touched by either.

### 3.3 Transport: one batch writer, and the handshake's machine on tables

The send side is 10,700 bytes against pico's 3,500 because a message is written through
`open_frame_lent` over a `dyn Fn`, a sizing pass and a writing pass, and a write per message kind;
pico writes every message through one `_z_transport_tx_send_n_msg_inner` into one batch. The
design is `text.md` X1: one `TxBatch` with one `write_n_msg` (open a frame for the message's
reliability when none is open, write in place, on no room flush once and retry, a message larger
than a batch to one cold fragment body). The second share is the session's machine: 8,200 bytes of
SCE runtime against pico's 2,300 of hand-written handshake. Its design is SCE's (X3: the runtime's
operations one body each, the machine's tables as data), proposed through `docs/sce-proposals/`
and measured in text plus rodata. Section 6 reads both again on the writer as it landed, and
section 10 is the structure for what remains.

### 3.4 Driver: what a pico library's links never run, and the bodies a lock is taken through

The driver area is the fourth that loses, and its excess is spread over three jobs rather than
held in one body: the sockets (about +5,900, section 2.4's third row), the locks, cells and faces
(about +5,300) and the dial (about +2,500). The endpoint's text is already won: `locator_text`
and the text `dial_step` holds are 2,246 bytes against `endpoint.c`'s 3,154. Three designs
that read as the obvious ones are in the tree already or do not apply: the face table of a build
that only dials is `faces::OneFace`, which carries no row walk of `ManyFaces` (the engine's
`link_turn` and `face_turn` are one body there, `wz-capi-coop/src/engine/direct.rs` @
`fn link_turn(`); the dial is a machine on data, one body generic over nothing
(`wz-runtime-coop/src/dial.rs` @ `pub fn dial_step<'a>(`), with only the stack's two calls in
its shell; and an endpoint cannot be read when the library is built, since `z_open` hands it in
the program's config, so its text is read at run time as pico's is.

What is left, largest first:

- **The links' own waits, in a build where the owner waits for every link.** The pico library
  makes its links `waited_by_owner` (`wz-capi-pico/src/session.rs` @
  `let links = links.waited_by_owner();`), so the read task waits on the sockets with the
  session free (`faces::IdleWait::wait`, 420 bytes, against pico's
  `vendor/zenoh-pico/src/system/unix/network.c` @ `z_result_t _z_socket_wait_readable(`, 396).
  Each driver still compiles the wait it would make in its own loop, because whether its owner
  waits is a flag read at run time: `UdpDriver`'s `service`, `service_within` and
  `wait_for_datagram` (787 bytes) and `StreamDriver`'s `service` and `service_within`
  (374), all kept by the drivers' vtables. The design: whether the owner waits is the stack's type
  (a parameter of `IpLinks` carried to the links it makes, its `waited_by_owner` the
  conversion), so a driver of a stack whose owner waits has a `service` that reads what is
  queued and nothing else, and the bodies of the loop's own wait are not in its build. Expected
  -900 to -1,100. The receive is untouched: `recv_with` is the same body, called where it is.
- **A typed lock taken and let go of at every place it is used.** `wz_host_sync`'s 2,867 bytes
  are not a body of its own: they are the word's exchange, its wake and a notification, inlined
  into every door that takes a typed lock, once for each path out of the body a guard is dropped
  on (`wz_capi_pico::handlers::push` holds 234 of them, `matching::declare_on_filter` 200,
  `WriteFilter`'s drop 134). pico's lock is a call (`vendor/zenoh-pico/src/system/unix/system.c`
  @ `z_result_t _z_mutex_lock(_z_mutex_t *m)`). The design, landed with this section, follows
  the receive: the read task's turn takes the engine's typed locks several times a message
  (`wz_host_sync::run_body`'s loop, `face_turn`, `Deliveries::within`, `live`), and with the
  guard's take and release and the count below out of line a message cost 3,020.3 instructions
  against 2,759.5 with both in line (main 3,078.1). So a free take and a release nobody waits for are the word's one
  exchange in line, and only the wait, the wake and a notification that finds a waiter are out of
  line (`RawLock::lock_contended`, `wake_waiter`, `RawCondvar::notify_marked`). The count of a
  kept value's holders is the other shape: in the receive's build no function a message runs
  takes or gives back a count (every `Shared` clone and drop lies in an open, a declaration, a
  reply or a drop), so `kept::Kept::retain` and `release` are one out-of-line body each; with
  them in line beside the lock's the driver read 30,317 against main's 29,998, `kept` 2,251
  against 2,005 and `faces` 3,076 against 2,836, the last from a link's drop copied into
  `drive_link` and `place_link_session`, which is one body again
  (`DirectSlot::drop_link`, never inlined). Expected below main's 29,998 in driver.
- **The send of a stream link.** `tx_slot_send` 574, `write_owed` 477, `tx_slot_acquire` 275,
  `wait_for_room` 177 and `drop_owed` 115 hold the slot a frame is written in, the frames the
  stream has not taken whole, and the wait for room: 1,600 bytes against pico's one write of a
  batch (`vendor/zenoh-pico/src/link/link.c` @ `z_result_t _z_link_send_wbuf(`, 254). This is
  the link's half of section 3.3's one batch writer, and is designed with it: a frame the stream
  takes whole, the case of every frame below the socket's buffer, leaves no owed entry, so the owed
  ring is the cold body of a write the stream cut short.
- **The dial's open.** `IpLinks::begin_initiator` (2,419) places a UDP link at once and a stream
  later, each through its own placement (`LinkPlace::datagram` inlined, `LinkPlace::stream`
  548), and `faces::Dial::answer_on` (1,084) drops a refused stream dial where the next is put.
  Against pico's open (`vendor/zenoh-pico/src/link/link.c` @ `z_result_t _z_open_link(`, and the
  TCP and UDP link files, about 2,900) the excess is about 2,500. The design: one non-generic body
  places a link of either kind once its socket is made (the cell, the owner's wait, the buffers'
  claim), so a dial's protocols differ only in the socket they make.

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
The driver's steps of section 3.4 are read on the driver row, the `wz_host_sync` and
`wz_runtime_coop::kept` owner lines, and the bodies `wz_capi_pico::handlers::push` and
`matching::declare_on_filter`; their check of the receive is `ir-receive.md`'s count of
instructions a message, which the count's step should not move and the lock's moved down.


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

`Engine::process_event` is out of line in the runtime (item 1 of section 6.4, at SCE
`e90c0b6271b`), and every path that tells the session machine something calls it directly:
`dispatch_link_lost`, `dispatch_link_event`, `dispatch_unit_in`, `dispatch_lean_unit`,
`admit_head_in_place`, `refused_data_unit`, `dispatch_control_in_place`, `lean_in_place`,
`frame_in_place`, `judge_lease`, `check_requested_close`, `check_out_of_band`,
`TransportTimers::fire_due`, and the coop pump's role activation (`LinkSession::init_in`,
`open_step`). None of them is on a sample's path: each is a refusal, a decided handshake event, a
timer that has fallen due or a request from outside the loop, so the receive's per-message
instructions do not change; what goes is the inlined copy of the queue push and the turn's opening
and closing in each of those bodies.

The body was first wz's own, `wz_session_core::drive::deliver_session_event`, a wrapper never
inlined. Once the runtime's body was out of line the wrapper was read at 5 bytes, a tail call over
the same call (164 before), and it is gone: each caller's call is the same size to the other
target, and the image loses the wrapper's body and its alignment, expected about -16 of text per
runtime and clock pair the session machine is built for (one on the case), no rodata.

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
   one, without a wrapper of its own (landed at SCE `e90c0b6271b`); for this image, after 6.3,
   about -100 more (the link and slot machines are reached from one body each already).
   Instructions: one call per event, which is per transport event and never per sample.
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

## 7. The step landed with the doors' design: a lent place carries its lender from the take

`wz-capi-pico`'s `object_slot`: `Lender::lend` becomes `Lender::lend_into`, which writes the
lender into the place it claims, `InSession::<T>::LENDER_AT` bytes in (`core::mem::offset_of!`), and
hands back the place alone. `Slot<T>` holds the place and, on the cooperative engine, whether it is
lent (a `bool` where it held an `Option<Lender>`); `fill` and `fill_in_place` write the object
only (`Lender::attach` is gone); the drop of an unfilled lent slot and `release_entity` give the
place back through `give_back_lent_place(place, lender_at)`, one non-generic body. The tokio
engine's empty `Lender` is gone with the field: its places are the pools'. The counted places
(`Answering`) read the lender where they did, which the take now writes.

Expected on the case: the `object_slot` owner lines in `z_declare_publisher`,
`declare_subscriber_with`, `declare_on_filter` and `z_declare_background_subscriber` down by
about 30 to 60 each, `release_entity::<PublisherState>` 125 to about 40, `Lender::lend` 81 to
about 100 as `lend_into`: doors -120 to -250. Tests:
`object_slot::tests::a_lent_places_lender_lies_past_its_object_within_the_place` holds the offset
for five object types, and
`object_slot::tests::a_refused_fill_gives_the_lent_place_back_to_its_session` holds the refused
fill's and the release's give-back; the existing
`a_session_lends_its_entities_places_and_spends_none_of_anothers` holds the unfilled drop.

## 8. Sessions read again: the largest bodies against zenoh-pico's, by what differs

Read from the size ledger's `--explain` document of this case dated 2026-11-27 (schema 5):
sessions 67,963 against pico's 27,508, +40,455. The twenty largest bodies of the area hold 33,980
bytes; each is set beside the zenoh-pico functions that do the same job, by their bytes in the same
report. A row is **work** where wz does something pico's build does not (a cut is a decision about
what the preset does), **shape** where the job is the same and the bytes are how it is written
(a design can remove them), and **hot** where the body is on the receive or the put, whose
instructions a message are under pico's (3,078 against 4,049, `ir-receive.md`), so a change is
judged on both readings and no call step is added.

### 8.1 The twenty bodies

| wz body | bytes | zenoh-pico, same job | bytes | kind | what differs |
|---------|------:|----------------------|------:|------|--------------|
| `lend_session` | 4,545 | `_z_open`, `_z_session_init`, `_z_open_locators_client` | 902 | work, shape | the open lays the session's whole arena out (every table's rows, the key arena, the links' cells), because the preset holds no heap past the open, where pico allocates each object when it is declared: work the no-heap contract asks. The lays of the holds after the rows (`arena`'s lines, 2,303) are shape: S-OPEN makes them constants of the region |
| `CoopEngine::assemble` | 3,662 | `_zp_start_transport_tasks` | 202 | shape | the `Core` is built as a value and moved into `engine_of` (655), each layer's table placed by its own call; T-OPEN's plan |
| `CoopEngine::link_turn` | 2,690 | `_z_handle_network_message` | 635 | hot | the turn holds the link machine's events, the lease's judgement and the replay's start, which pico runs in its lease and read tasks (transport area) |
| `declare_write_filter` | 2,418 | `_z_write_filter_create`, `_z_write_filter_ctx_add_callback`, `_z_add_interest` | 1,536 | shape, work | the Interest's own table and slot map are shape (S-FILTER); the filter's row keeps the put's facts and head so a put through it writes no header, which pico does not keep: work |
| `put_through_filter` | 2,053 | `_z_write`, `_z_publisher_put_impl` | 458 | hot | the frame lend, the filter's state and the kept head, inlined from the tables and the key arena |
| `DirectSink::event` | 2,012 | `_z_trigger_subscriptions_impl`, `_z_trigger_push` | 1,730 | hot | +282: the in-place read and the matching of rows |
| `undeclare_subscriber` (engine) | 1,666 | `_z_undeclare_subscriber`, `_z_unregister_subscription` | 656 | shape | the row taken out under the lock, its key released, the wire undeclaration and the wait on its latch, each inlined; S1 |
| `Declaring::declare` (subscriber) | 1,514 | `_z_register_subscription` | 623 | shape | the parts moved by value, the link set's judgement, the refusal paths (`t-decl.md`, section 11) |
| `undeclare_write_filter_quietly` | 1,423 | `_z_write_filter_session_unregister`, `_z_write_filter_clear`, `_z_remove_interest` | 815 | shape | S-FILTER: the Interest's row and the listeners' table |
| `declare_subscriber_on_wire` | 1,324 | `_z_declare_subscriber`, `_z_register_subscriber` | 835 | shape | S1 |
| `declare_keyexpr_where` | 1,219 | `_z_declare_resource`, `_z_register_resource_inner` | 894 | shape | the key arena's take and its quota (`MAX_KEYEXPR_BYTES`), inlined |
| `publish_to_link` | 1,175 | (with `_z_write` above) | | hot | the publisher's put |
| `hand_row_by_row` closure | 1,117 | (with `_z_trigger_subscriptions_impl`) | | hot | the delivery to each matched row |
| `drive_link` | 1,064 | (pico's read loop is in its transport area) | | hot | |
| `Declaring::keyed` | 1,038 | (with `_z_register_resource_inner`) | | shape | S1, the own key |
| `RemoteSubscriberTable::dispatch_iteration_event_with_local` | 1,032 | `_z_interest_process_declares`, `_z_interest_process_undeclares` | 1,233 | won | |
| `SessionDrive::close` | 1,017 | `_z_session_clear` | 98 | not paired | pico's close is not read here beyond this body |
| `deliver` closure | 1,011 | (with `_z_trigger_subscriptions_impl`) | | hot | |
| `replay::told` | 1,009 | `_z_client_reopen_task_fn`, `_z_interest_replay_declare` | 1,122 | won | |
| `ext_admit::judge_entry` | 991 | none in sessions | 0 | same work | pico reads the extensions in its codec (911 there); the area differs, not the job |

### 8.2 Where the 40 KB are

| job | wz | zenoh-pico | wz - pico | kind |
|-----|---:|-----------:|----------:|------|
| the receive and the put (the seven hot bodies) | 11,122 | 2,823 | +8,299 | hot: their instructions a message are under pico's; a design that moves bytes out of them is read on both |
| the open and the assembly | 8,207 | 1,104 | +7,103 | about 2,300 to 3,000 shape (S-OPEN, T-OPEN); the rest the arena the no-heap contract lays out |
| the declarations and their undeclaration | 10,602 | 5,359 | +5,243 | shape (S-FILTER, S1), less the filter row's kept head (work) |
| a peer's declarations and the replay | 2,041 | 2,355 | -314 | won |
| the extension admission | 991 | 0 | +991 | same work, in pico's codec |
| the close | 1,017 | 98 | +919 | not paired |
| the other 237 bodies | 33,983 | 15,769 | +18,214 | not paired body by body: the largest owners there are the engine (`wz_capi_coop::engine`, 15,781 in 71 bodies in all), the tables (`session_tables` 7,898 in 43, `slot_map` 6,600 in 50) and the key arena (3,192 in 25), whose lines are inlined into the declarations' bodies |

So of the 40,455: about 8,300 are the hot paths, held by the receive's instruction count; about
4,000 to 4,800 the open's arena, the no-heap contract's work, which changes only with what the
preset holds; a few hundred the filter row's kept head, a wz choice for the put; about 1,000 the
extension admission, the same work counted in another area. Of the paired rows, about 7,000 to
8,000 are shape (the declarations' bodies and the open's lays), which S-FILTER, S1 and S-OPEN
design. The 18,214 of the bodies not paired here are not graded by this section; their largest
owners are the tables, whose lines section 3.1.1 reads as shape inlined into their callers. No row
of this reading needs a preset decision: the work rows are the no-heap contract, already decided,
and the put's kept head, a choice of wz for the put.

### 8.3 The steps landed with this section

- **S2's first step: a lent table's free slots grow by one body.** `SlotMap::add_free_slot` had
  five bodies in this build, one per row type (`Interest`, `Keyexpr`, `MatchingListener`,
  `Subscriber`, `WriteFilter`), 40 bytes each in sessions and 70 to 75 each in language, 566 in
  all: each pushed its type's `None` into its rows column. Where both columns are lent tables (the
  lent and the region policies), `add_free_slot` is now a short typed body that calls
  `add_free_lent_slot`, one body for every row type, handed the rows' stride and the one typed step
  (`write_none::<T>`, through a function pointer: a slot is added once, when the table first grows
  to it, never on a receive or a put). The column grows through `bounded::push_erased`, which reads
  a `LentSeq` by its `repr(C)` words as `place_seqs` does. The growable and the fixed policies
  keep their typed growth (`add_free_typed_slot`). Expected on the case: about -200 to -350 in all
  (the five bodies against one of about 110, five calls of about 25 and five writes of a `None`).
  Test: `slot_map::tests::a_lent_table_adds_its_free_slots_by_its_rows_stride`.
- **The region's face set leaves its peer's tables as zero bytes.** `PeerTables::init_in` (491 in
  this build) wrote the seven tables of the region's one face set by one call each, five of them
  tables of planes the case does not build, into a place the region hands zeroed, where
  `PeerTables<Region>` is a whole empty value (`ZeroEmpty`, held by
  `peer_tables::lent_tests::region_peer_tables_of_zero_bytes_refuse_until_bound_then_hold_their_build_bounds`).
  The region's set is now made by `FaceTables::rowless_over_zero`, which writes the set's other
  fields and holds the peer's tables to the session's limits; the arena form (`runtime-plan`) still
  writes them whole by `rowless_in`, its place not being zeroed. Expected: `init_in` leaves the
  case's image, sessions about -450 to -500. Test:
  `registry::placed::tests::a_set_over_zero_bytes_holds_its_empty_peer_to_the_sessions_limits`.

Neither step is on the receive or the put: the receive's count of instructions a message (3,078)
should not move. Each is read on the sessions and language rows and reverted when its row does not
move by its expectation.

### 8.4 What keeping the five tables by `Presence` asks, not landed

The design of the step above's successor keeps a peer's queryables, tokens, staged replies, owed
Finals and query judgement by `Presence` (`Absent` in a build without `declare-queryable`,
`liveliness-token` and `query-queryable`), as `SessionTables` keeps its queryables: the tables
would hold no bytes in the region (which the step above does not change) and no call would read
them. It is not landed here: `PeerTables`'s fields are read directly, outside any feature gate, by
session-core's `slot_observer` (the queryables' and the tokens' dispatch and their flush on a lost
link, the query dispatch, the drain of owed Finals), its `observer` (the halves it hands out),
`peer_tables` itself (`limit_to`, `keep_keys_in`, `forget_peer`, the region's key lines),
`wz-capi-coop`'s registry (the queriers' matching, a request's pinning, the owed Finals and the
tokens of a lost face) and its declaration watch, and `wz-session-mcu`'s application layer: about
forty sites, each of which needs an answer for a table that is not there. And the receive then
keeps nothing of a declaration of that plane, which is read against zenoh-pico first: a build
without its queryable drops a query (`vendor/zenoh-pico/src/session/rx.c` @
`_Z_DEBUG("_Z_REQUEST_QUERY dropped, queryables not supported");`), and hands a declared queryable
or token to its interests' processing whatever its features (`vendor/zenoh-pico/src/session/rx.c` @
`case _Z_DECL_QUERYABLE:`), which keeps it only for an interest the session declared.

## 9. Driver: a link's calls over the build's closed set of links

Read from the RSS lane's reading of this preset's relocated data (`rss.md`, section 5.3, R3.1) and
from the code: `BoxedLinkDriver` holds 112 slots of the library's tables and
`SessionDatagramLink` 75, one table for each type a link of the build is unsized from. The stack
of this preset is `IpLinks<PosixUdpSocket, PosixTcpDial>`, whose links are of two types known
when the library is compiled (`UdpDriver` and the TCP stream's `StreamDriver`): a closed set, held
behind `dyn` as if it were open. zenoh-pico's link is one record of function pointers
(`text.md` R1), one indirect call a datagram.

### 9.1 What a call on the link costs now: two tables, not one

In a build whose read hands each record out as it is read (no `threads`, so no `wz_round`: this
preset), nothing holds a link back, and the engine answered the link's own handle as its gate
(`LinkCalls::gate`). The transport then placed that handle, a `CellRc<dyn SessionDatagramLink>`,
in a cell of the gates' table and read the link through the cell (`gate.clone().into_link()` in
`TransportState::build_wire`): the pump the read steps held a handle on a cell holding a handle
on the driver. Every call the read makes on the link (its service, `takes_input`, `recv_with`,
`take_rx_dropped`, `lost`, `keep`) was an indirect call into the forwarding implementation of
the trait for `CellRc` (`crates/wz-runtime-coop/src/session_drive.rs` @
`impl<T: SessionDatagramLink + ?Sized, N: crate::link_cells::CountKind> SessionDatagramLink`),
which read the inner handle, worked out where its value lies from the table's alignment, and made
the second indirect call into the driver. The forwarder's 19 bodies and its table were in the
build for that one use, and each link took a cell of the gates' table it did not need.

### 9.2 The design: one dispatch a call, and where the set is closed, none

The textbook form of a set of variants known when the program is compiled is a sum type matched
where it is used; a trait object is the form of a set a caller extends. `wz-runtime-coop` already
holds the slot profile's links so (`IpDriver` and its `either!` match in `ip_stack.rs`); the
heap profile, which this preset builds, gets the same shape in three steps, each removing a layer
of dispatch, never adding one.

1. **A link nothing holds back is its own gate** (landed with this section). `LinkCalls::Gate` is
   what the link's session and its pump hold, and `LinkCalls::gate` places the gates in a cell of
   the table it is handed only where they hold the link back (the round's, with `listen` the
   admission's under it); `LinkCalls::gated_link` answers the handle the pump and the face read
   the link through: the gates' cell unsized, or, with no gate, the link's own handle. The direct
   read's link is then one handle on the driver and every call on it one indirect call.
2. **The stack's links as one closed type.** `IpLinks` places every link it opens in its cell as
   one enum over the stack's protocols (`Udp`, the `udp/` port's peer under `udp-listen`, `Tcp`,
   `Tls`), stating both traits by one match a method as `IpDriver` does; its copying receive and
   its byte send call `copied_receive` and `copied_send` with the enum itself, so no variant is
   unsized and the variants' bodies are inlined into their arms. One table a trait for the stack.
   Not landed alone: under `dyn` it adds a tag test to each call.
3. **The stack's link type reaches the read and the send.** `SessionLinks` names the type its
   shared link is (`type Link: SessionDatagramLink + ?Sized`; every stack but `IpLinks` states
   `dyn SessionDatagramLink` and keeps its form), the transport's `LinkOf<T>` and
   `LinkCalls::gate` take `CellRc<L::Link>`, and the direct read's pump is
   `LinkPump<_, CellRc<L::Link>>`: the read calls the enum's methods directly, a tag test and the
   variant's body, and a method only a table reached (each driver's copying `try_recv`, which a
   read in place never calls) is not linked. The send
   half is the same change on the sink: `SessionHandle<C, D, K>` is generic over its driver
   already, and the engine's `LinkRuntime`, `LinkActions`, `LinkHandle` and `LinkHalves`, keyed
   on the clock today, are keyed on the stack. The faces' waits keep `dyn` (`input_wait`,
   `waits_for_buffer` are asked per wait, not per message), so one table of the enum stays.

`text.md` R1 (lane T-LINK) folds the three link traits into one record of a socket's operations:
the form for a set the build does not close (a program's own links, `app-transport`), whose one
indirect call a datagram is what zenoh-pico pays. The closed set is the case where the build knows
better than a table, and the two compose: the enum is the record of the closed set. The driver
lane's designs (the owner's wait as the stack's type, the stream's send, the dial's open) are
inside the drivers and do not cross these steps; step 3 carries the stack's type to where that
lane's owner's wait is read.

| step | text, expected | relocated data, expected | instructions |
|------|---------------:|-------------------------:|--------------|
| 1 | -400 to -900: the forwarder's 19 bodies the table kept, the direct build's gate placement in `build_wire` (a cell's claim, its refusal, the cell's drop) | -176 (one table of 19 slots and 3 words) | each call on the link loses one indirect call and the forwarder's offset sum, about 8; the read makes five or more a step |
| 2 | about 0 (variants' bodies inlined into one match each; the per-type copies of the default methods fold) | about -900 (the stack's drivers' tables to one a trait) | +2 a call under `dyn` (the tag test), which is why it lands with 3 |
| 3 | -1,500 to -3,000 (bodies only a table reached, the indirect call sequences at every call site) | the rest of the drivers' tables but the faces' | no indirect call on the link on the receive or the put: a tag test and the variant's body |

The direct build's gate table stays laid out by the arena (`link_cells`, a cell a link); its bytes
go to zero where `wz_round` is off with the open's `cells_of` of lane S-OPEN, which owns that
function, so the step does not touch it twice.

### 9.3 The relocated names (RSS R3.2 and R3.3): spans, not ends

`rss.md` section 5.3.2 took back the limits' ids and the encodings' names as offsets into one
string: each grew the size ledger's text (+113 and +264) because the readers walked a list of
`u16` ends to find a name, a loop where a slice of `&str` was one load. The form that keeps the
read as it is: each name a span, `(start: u16, len: u8)`, into one string, three bytes beside each
row, and the string and the spans made by a `const fn` from the one table of names, so nothing is
transcribed twice. A read is the span's load and one slice of the string: the two loads a `&str`
was, from `.rodata` and not from a relocated word. The reverse lookup (name to id) stays the scan
it is, comparing lengths first. Expected: the encodings' names -848 of relocated data for about
160 of `.rodata` and text 0 to +40; the limits' table -5,040 relocated, its rows in `.rodata`,
which the generator writes (`wz_config.py --emit rust-limit-snapshots`), so that change is the
generator's owner's. Neither moves this case's text, which is this note's grade, so neither lands
with this section; their reading is `rss.md`'s pages.

### 9.4 Measuring step 1

On the case's explain report: the driver and transport rows; the symbols of
`<CellRc<dyn SessionDatagramLink, _> as SessionDatagramLink>` (gone where nothing else
unsizes such a handle) and `TransportState::build_wire`'s lines in the engine's link placing
(`CoopEngine::place_link_session`). On the receive: `ir-receive.md`'s count of instructions a
message, which falls by the forwarder's share of each call on the link. The test is
`wz-capi-coop`'s `tests::arena::a_link_nothing_holds_back_takes_no_cell_of_the_gates`.

## 10. Transport: the structure for what remains, and what SCE is asked for the machines

Read from the same explain document as section 6 (2026-11-26, schema 5): transport 30,814 against
pico's 13,951. Bytes are each side's in the area; the jobs are grouped by the owners of the
report, so a body inlined across two owners is counted where its owner is.

| job | wz | zenoh-pico | gap | lever, and whose |
|-----|---:|-----------:|----:|------------------|
| the three machines' runtime (`sce_rust_runtime`: engine 4,574, microstep 1,316, event queue 1,071, tables 557, state set 548, run store 154, the rest about 100) | about 8,300 | the hand-written handshake, `vendor/zenoh-pico/src/transport/unicast/transport.c` @ `static z_result_t _z_unicast_handshake_open(`, the file 2,324 | about +6,000 | 10.3, SCE |
| the send: dispatch, writer, fragment chain, control writes, lease of the slot (`session_actions` 10,647, `tx_buf` 1,167, `tx_lease` 743, `tx_deadline` 378) | about 12,900 | `vendor/zenoh-pico/src/transport/common/tx.c` @ `z_result_t _z_send_n_msg(_z_session_t *zn,`, the file 3,483 | about +9,400 | 10.2 (landed), 10.5 (preset decisions) |
| the receive: units, control read, fragment rejoin (`drive` 4,657 with its sub-owners, `reassembly_dispatch` 2,111, `unicast_rx` 330, `sn`, `link_admission`, the handshake extensions) | about 7,900 | `unicast/rx.c` 1,820, `unicast/read.c` 1,010, `common/rx.c` 502 | about +4,600 | 10.4, T-RX |
| timers (`transport_timers` 786; `keepalive_deadlines`, `due_ms`, `service_due` are counted in the receive row by their owners) | 786 | `unicast/lease.c` 626 | +160 | 10.4 |
| pico's manager, peer and transport files, which wz holds in sessions and driver | 0 | about 3,700 | -3,700 | none |

Two of the levers `text.md` X1 named are already the code: the one frame writer (section 6.1)
and the fragment chain as one cold body (`emit_fragment_chain` is `#[cold]`, the lent entry
`emit_fragments_encoded` only measures and hands over, and `send_fragment` is the one write of a
fragment and of the stop marker). What is left of the send is the dispatch's admission jobs and
the chain's credit and stop marker, which are behaviours (section 6.1), and the writers of each
message kind, each one encoder behind the one `&dyn WireWrite`.

### 10.1 Why this is the textbook structure

The send keeps pico's shape (one writer into one batch) and the machines keep the SCXML source:
what a structure can still remove is code the preset's build compiles but cannot reach, and the
part of the SCE runtime's general turn that no document of this image uses. Both are removed the
way P8 and SCE ADR 0135 already remove code (a capability the build lacks, a procedure no table
names), not by folding bodies, of which this preset has one instance each (section 1).

### 10.2 The step landed with this section: no Control barrier on one conduit

The barrier of `dispatch_network_message_in` keeps a control message from being overtaken by data
staged on another conduit: its first half drains the other conduits before a control message, its
second half drains the Control conduit before data when a control message was left open there, and
the `control_open` mark connects the two (raised after a control message is staged, lowered in
`flush_conduit`). A build without `transport-qos` has one conduit (`link::SESSION_TX_CONDUITS`),
so the first half drains nothing, the second half's test is `0 != 0`, and the mark is read by
nothing; the frame order there is the staging order. The barrier, the mark, its field and its three
accessors are now compiled with `transport-qos` alone, and a const assertion beside
`TX_CONDUITS` holds the premise (one conduit without `transport-qos`). The link's own fence
(`tx_fence`) is unchanged: it orders the link's queue, not the session's conduits.

Expected on the case: `dispatch_network_message_in::<false>` loses the drain call and its closure,
the mark's load and compare, and the mark's store after the stage; `flush_conduit` loses its
store; about -60 to -150 in transport. Instructions: per message sent one sequentially consistent
load and a branch fewer, per frame flushed one atomic store fewer; the receive is not touched. A
build with `transport-qos` compiles what it compiled before.

### 10.3 The machines: what wz has ready, and what SCE is asked

What wz holds so that a change of the runtime's turn needs no wz change but the pin:

- each machine is handed its events through one body: the session machine through
  `drive::deliver_session_event` (section 6.3), the link machine through `UnicastLink::input`,
  the slot machine through `reassembly_dispatch::turn_slot_engine`;
- the class the requests below rely on is held against the generated tables of the build that
  links them (`wz-session-core`'s `machine_class_tests`): no `<history>`, no `<parallel>`, no
  transition of more than one target, selection by rows, every `<final>` at the top level and no
  eventless transition. The link and slot machines and the session machine of a build that only
  opens are of it; the session machine of a build that accepts is not (the step from SentOpenAck
  to Established is eventless), and the test says so, so that build keeps the general turn;
- every one of the three declares an internal queue the generator proves empty
  (`INTERNAL_QUEUE_BOUND = Some(0)`), and none has an `<invoke>`, a `<finalize>` or an
  autoforward.

The requests, for an SCE session, graded by text plus rodata (`text.md` O4) on this case's
transport row and by the callgrind of one handshake and one fragmented message (cell M9):

1. **A reactive turn.** For a policy whose tables are of the class above, whose internal queue is
   proven empty and which has no invoke, finalize, autoforward or inbox, `Engine::run_turn` calls
   a second shared body (`Turn::run_reactive`) instead of `Turn::run`: enter the initial
   configuration when asked; then, while the external queue holds an event and the call's budget
   lasts, take it, select from its state's cells, take the microstep it selects, and on a top-level
   final exit the interpreter. The choice is an associated constant of the policy (computed by a
   `const fn` over `TABLES` and the policy's bounds, or written by the generator per build arm,
   since the class depends on the arm), not a cargo feature, so an image whose machines are all of
   the class links no `Turn::run`, `complete_macrostep`, `take_eventless_transitions`, internal
   queue drain or invoke start, and an image with one general machine links both bodies once. The
   observable order is the general turn's for every document of the class, which the differential
   test of ADR 0129 decision 4 holds over seeded sequences for both turns. Expected: `Turn::run`
   1,296, `take_event` 129 and the internal queue's half of `event_queue` to one body of about
   400, -1,000 to -1,500 of text and no rodata; per transport event one eventless selection and
   the internal queue's checks fewer, never per sample.
2. **Exit paths beside the entry paths**, section 6.4 item 3: -600 to -800.
3. **`process_event` out of line and the per-machine monomorphs folded**, section 6.4 items 1
   and 2: -400 to -600.

Together about -2,000 to -2,900 of the transport row, which leaves the runtime at about 5,500
against pico's 2,324 of handshake: the rest is the interpreter's walk itself, which is what the
SCXML source costs and which the machines pay once for every engine.

### 10.4 The receive and the timers (lane T-RX)

The receive's large bodies are cold already: `fragment_in_place` (2,062, of which 1,336 is the
reassembly Router inlined) is `#[cold]`, and `read_control_in_place` (2,034) is out of line with
`decide_admitted` (`#[inline(always)]`) inlined into it. Each has one instance, so the
lever is what they do, not their form: before a design, cell M13 reads the inlined attribution of
both bodies (which of `decide_admitted`'s arms, the extension readers and the Router's ingest
hold the bytes) against pico's `_z_unicast_handle_fragment_inner` 825 and
`_z_unicast_handshake_open` 873. `text.md` X4's one deadline table stays the timers' design, with
rule 4 of its section 7: `keepalive_deadlines` runs at every turn, so its form changes only if
its instructions fall.

### 10.5 What form cannot close: behaviours beyond the preset

With 6.3, 10.2 and 10.3 the transport row is expected at about 26,500 to 27,800 against 13,951. The
send's remainder is behaviour pico's transport does not have: the probe stage, the run of expiries
that closes a session (`tx_expiry_close_after`), the fragment chain's credit and stop marker, the
held-conduit wait of a droppable message. Each is a parity contract of the zenoh preset, and each
can leave the pico preset only by P8 (off in `configs/zenoh-pico_defconfig`, its key path refused
by `BuildCapabilities`), which is an owner decision per behaviour; cell M14 reads the bytes each
holds in this case before one is asked for.

### 10.6 Measuring

- The case's explain report: the transport row, and the bodies
  `SessionLinkActions::dispatch_network_message_in::<false>` and `SessionLinkActions::flush_conduit`
  for 10.2.
- The per-put send callgrind and the per-message receive callgrind (3,078 Ir): the send lower or
  equal, the receive equal.
- `cargo test -p wz-session-core --features session-unicast,reassembly machine_class_tests` (four
  tests) and the same with `session-unicast-accept` added (four tests, the accepting one in place
  of the opening one).

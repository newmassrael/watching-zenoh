# Text budget: every area at or under zenoh-pico

The design of the code-size half of the win budget. It changes no code. It says, for each area
of the size ledger, what the shipped wz library carries now, what zenoh-pico carries, the target
(at or under pico), the structure that reaches it, the files it touches and where one lane's work
ends and the next one's begins. Estimates are marked as estimates; the measurement cells of
section 9 turn them into readings.

The other halves are separate files beside this one: `ir-receive.md`, `ir-send-query.md`,
`heap.md`, `std-heap.md`. The read structure this file builds on is
`docs/c-abi-architecture.md` section 8 (every face read where it lies, no round).

## 1. What is measured

**The case.** `pico-client-coop-nostd`: the pico C ABI library without `std`, the
`configs/zenoh-pico_defconfig` preset (`CONFIG_WZ_ROLE_CLIENT=y`, every `CONFIG_WZ_CAP_*` off,
`CONFIG_WZ_LIMITS_ZENOH_PICO=y`), profile `capi-nostd` (fat LTO, one codegen unit,
`panic = "abort"`, `opt-level = 3`), against zenoh-pico built by CMake with
`-DCMAKE_BUILD_TYPE=Release` (`-O3`). The pin of the pico reference is `6a881c21dad1`.

**The reading.** The explain document of the size ledger, schema 4 (DWARF line attribution, a
frameless body placed by its symbols), dated 2026-11-25. Its area totals are the figures this lane
was given. Bytes are `.text` attributed by source line: a body inlined into another is counted at
the owner of its source lines, not at the symbol it was inlined into. A symbol's figure in a row
below is its share in that area; an owner's figure is its lines in every symbol. The two overlap,
so the rows of one area are estimates that do not add exactly: the ledger after each lane is the
reading, not the sum of the rows.

| area | wz (2026-11-25) | wz, sh2 (2026-11-26) | pico | ratio (2026-11-25) | ratio, sh2 | wz bodies | pico bodies | wz bytes per body | pico bytes per body | wz inlined bytes | wz bytes in duplicate generic bodies |
|------|---:|---:|-----:|------:|------:|----------:|------------:|------------------:|--------------------:|-----------------:|-------------------------------------:|
| sessions | 69,338 | 66,419 | 27,508 | 2.52 | 2.41 | 313 | 194 | 222 | 142 | 20,890 | 147 |
| doors | 41,138 | 41,399 | 19,034 | 2.16 | 2.18 | 454 | 475 | 91 | 40 | 11,283 | 168 |
| transport | 32,570 | 31,737 | 13,951 | 2.33 | 2.27 | 189 | 100 | 172 | 140 | 6,473 | 1,454 |
| driver | 28,995 | 29,577 | 16,049 | 1.81 | 1.84 | 287 | 144 | 101 | 111 | 9,196 | 434 |
| keyexpr | 9,612 | 8,087 | 13,490 | 0.71 | 0.60 | 23 | 73 | 418 | 185 | 1,179 | 0 |
| codec | 34,943 | 28,440 | 35,440 | 0.99 | 0.80 | 132 | 294 | 265 | 121 | 9,378 | 2,257 |
| language | 18,431 | 12,888 | 45,028 | 0.41 | 0.29 | 157 | 609 | 117 | 74 | 3,331 | 1,768 |
| (unclassified) | 125 | not read | 0 | |  | 11 | 0 | | | 125 | 0 |
| **total** | **235,152** | **218,547** (the seven areas) | **170,500** | **1.38** | **1.28** | | | | | 61,855 | 6,228 |

**The sh2 reading (2026-11-26)** is the same case built from a C-level root crate (P9): the
ledger's reading of the branch `sh2`, given to this lane by the main session before it lands. The
2026-11-25 column stays the base of the rows of sections 3 to 5, whose owners and bodies were read
from it, and the other columns are its; the sh2 column is the base a lane landing after sh2
measures its own change against. The main session reads the change at about -15.6 KB of the
ledger's total (235,592 on main before sh2); the seven areas fall by 16,480 against the 2026-11-25
column (the unclassified row was not part of the reading). Codec (-6,503), language (-5,543),
sessions (-2,919), keyexpr (-1,525) and transport (-833) fall; doors (+261) and driver (+582) rise,
which the reading does not attribute (M10). On the sh2 reading the four areas over pico still need
92,590 (sessions 38,911, doors 22,365, transport 17,786, driver 13,528), and the total 48,047.

"Duplicate generic bodies" is the bytes of every function the reading finds in more than one body,
less its largest body: what one body per function would save. The parity preset (`std`, heap)
reads 864,298 against 505,302 (1.71x); section 6 is its part.

**What the reading says, area by area.** Duplicated monomorphs are not where the gap is: 2,203
bytes in the four areas over pico, against a gap of 95,499. Every engine type is instantiated once
(`CoopEngine<IpLinks<PosixUdpSocket, PosixTcpDial>, PosixClock>`), so a generic costs one body,
not one per type. The gap has three shapes:

- **Doors: bodies too large.** wz has as many door bodies as pico (454 against 475), each 2.3 times
  the size. A door composes its operation inline (canonize a key, store it, build a row, install a
  handler) where pico's door marshals and calls one function of the layer below.
- **Transport and driver: too many bodies.** Bytes per body are pico's (172 against 140; 101
  against 111) but there are twice as many: layers of traits and cells (`SessionDatagramLink`,
  `BoxedLinkDriver`, `StreamSocket`, `PendingDial`, `LinkWaits`, `kept`, `link_cells`,
  `link_storage`) where pico has one link record with function pointers.
- **Sessions: both.** 1.6 times the bodies and 1.6 times the bytes per body: a declaration path per
  entity kind, open-time assembly in one generic engine, and 30% of the area inlined copies.

A generic instantiated once still matters, but not through a size level. Cell M1 was read on
2026-11-26 (the lane t-open, `a11a6dc9a`, before sh2): the endpoint reader moved into a crate
built at `opt-level = "s"` read -1,899 bytes where it left and +1,875 where it arrived, so in
`capi-nostd` (fat LTO, one codegen unit) a crate's own level does not reach the linked library,
whatever `crates/Cargo.toml` says of a generic and the crate that instantiates it (the comment
above `[profile.release.package.wz-app-schema]`); the `&dyn` adapter the move added to hand the
runtime's sockets to the reader cost +880 on top. What decides a cold body's size in this build is
its form: whether it is generic over the engine's link and clock types (then each caller may
inline and specialise it), how many call sites copy it, and whether it is out of line. P5 is that
rule; no row of this file takes credit for a size level.

## 2. Principles

**P1. The per-message path decides; size takes what it leaves.** The hot set is what the
per-message callgrind of the receive and send lanes names (section 7). A function in it stays
concrete and may be inlined; no change in this file may raise per-message Ir. Every other body is
cold, and in a cold body size wins every tie.

**P2. A typed shell over an untyped core.** A generic container keeps only the casts in its typed
face; the bookkeeping is one body over bytes, a stride and a column. wz already does this for the
slot map's free list (`crates/wz-session-core/src/slot_map.rs @ fn take_slot(&mut self, meta: &mut [Meta], room: bool) -> Option<Taken> {`),
and pico does it for every list (`vendor/zenoh-pico/include/zenoh-pico/collections/list.h @ #define _Z_SLIST_DEFINE(name, type, use_elem_f)`:
typed macros over one `_z_slist_*` body). The textbook form is `hashbrown`'s
`RawTableInner` (`hashbrown-0.15.5/src/raw/mod.rs @ struct RawTableInner {`), one body per
operation for every key and value type. What remains to move is the row columns themselves.

**P3. A kind is data, not a type.** Declaring a subscriber, a write filter, a matching listener, a
queryable, a token or a key expression is one pipeline with the kind as a value: pico sends every
declaration through one function (`vendor/zenoh-pico/src/net/primitives.c @ z_result_t _z_send_declare(_z_session_t *zn, const _z_network_message_t *n_msg) {`)
over a tagged declaration. wz instantiates `Declaring::declare::<K, R, C, N>` per kind and writes
a door body per kind in the engine.

**P4. A door marshals; the layer below acts.** pico's `z_declare_subscriber` checks its
arguments and calls the net layer
(`vendor/zenoh-pico/src/api/api.c @ return _z_declare_subscriber(&sub->_val, zs, keyexpr, closure.call, closure.drop, closure.context,`).
A wz door reads its C arguments into one plain request struct and makes one out-of-line call; the
request type is not generic and the call is not inlined into the export.

**P5. A cold plane is one non-generic body.** A fat-LTO build has one optimisation level, the
root's (`opt-level = 3`, cell M1), so cold code is made small by its form, not by the crate it is
compiled in (decided 2026-11-26 under the owner's delegation, section 9 O1). The cold planes of the
client (open and assembly, dial, declarations, control in, configuration, teardown) are written so:

- **No type parameter.** A plane takes plain values and plain references (the configuration's
  counts, the arena's offsets, byte slots, the tables), so it is one body whatever the engine's
  link and clock types are; a monomorph of a cold body is a defect, not a cost of genericity.
- **One call site, out of line.** `#[inline(never)]` at the plane's boundary (rule 3 of section
  7) and one caller, so its body is not copied into a hot caller.
- **No adapter made for it.** A plane that needs the platform does not get a new trait object
  over the generic stack (M1's `&dyn` adapter cost +880). It returns what the platform must do and
  its one generic caller does it: a control message is bytes written into the face's `TxBatch`
  (X1), flushed by the caller; a close, a dial or a refusal is a returned verdict. Where a plane
  must call the platform itself, it uses the one dynamic boundary that exists anyway, the link
  record of P7 (R1's `LinkDriver`).
- **The generic remainder is what touches the platform's types.** The making of a socket
  (`IpLinks<Udp, Tcp>` reduced to a socket constructor, R2) and the placing of cells at the plan's
  offsets (S3), each one short body.

A crate may still hold a cold plane for ownership (who changes it, what it may depend on), never
for a size level. Section 7 names what is cold by measurement, not by guess.

**P6. Counts at open, not in types.** The owner's capacity ruling of 2026-11-26 (counts chosen by
the session's configuration at open, the preset's limits only their ceiling) removes `const N`
from the row tables' types: one body per table operation for every capacity, and the cold code
that sizes them needs no type parameter for it.

**P7. One dynamic boundary, at the link.** pico's link is a record of function pointers
(`vendor/zenoh-pico/include/zenoh-pico/link/link.h @ typedef size_t (*_z_f_link_write)(const struct _z_link_t *self, const uint8_t *ptr, size_t len,`),
and zenoh's is a trait object
(`io/zenoh-link-commons/src/unicast.rs @ pub trait LinkUnicastTrait: Send + Sync {`); zenoh's
face sends through one too
(`zenoh/src/net/routing/dispatcher/face.rs @ pub(crate) primitives: Arc<dyn crate::net::primitives::EPrimitives + Send + Sync>,`),
and so does its unicast transport
(`io/zenoh-transport/src/unicast/transport_unicast_inner.rs @ pub(crate) trait TransportUnicastTrait: Send + Sync {`).
A datagram link and a stream link differ by a flag the batch writer and reader read, as pico's
send does (`vendor/zenoh-pico/src/transport/common/tx.c @ case Z_LINK_CAP_FLOW_STREAM:`), not by
two driver types with a trait each.

**P8. What the preset cannot reach is not compiled.** A path no export of the zenoh-pico preset
reaches is behind the capability that reaches it, off in `configs/zenoh-pico_defconfig`, and a
build without it refuses the key path (`BuildCapabilities`), as rounds 3 to 6 of
`docs/c-abi-size-diet.md` did for policy, source info and the digest.

**P9. The root of a shipped C artifact is a C-level crate.** rustc takes a build's export threshold
from the most open of its crate types (`crates_export_threshold`): a `cdylib` and a `staticlib`
export at the C level (the `#[no_mangle]` items), an `rlib` at the Rust level (every item a
downstream crate may name). A crate built as both, as `wz-capi-pico` is
(`crates/wz-capi-pico/Cargo.toml @ crate-type = ["cdylib", "rlib"]`), keeps its Rust-level symbols
exported in the `cdylib` too, so fat LTO may not make them internal: their bodies stay out of line
and are kept whether the library reaches them or not. sh2 moves the root to a crate of its own,
`wz-capi-pico-lib` (`crate-type = ["cdylib", "staticlib"]`, library name `wz_capi_pico`, with what
a program without `std` takes from its last Rust crate, the global allocator and the panic
handler, defined there), and leaves `wz-capi-pico` an `rlib` alone for the Rust programs and tests
that link it: about -15.6 KB of the ledger with no line of the library's code changed (section 1,
the sh2 column). Rule: no crate that is the root of a shipped C library has a Rust crate type; a
Rust consumer depends on the `rlib` below the root; each new C artifact (the zenoh-c preset's
library, a Windows DLL) gets a root crate the same way, and the ledger reads what that root builds.
M1 was read before sh2 landed; cell M1b reads it again on the C-level root, where no reason is
known to expect another answer (fat LTO still makes one module).

**What is not done.** A crate cut at a size level (`wz-session-open` and `wz-capi-pico-hot` at
`opt-level = "s"`, the earlier O1: M1 read no effect under fat LTO); monomorph counting as the
lever (2,203 bytes in the four areas); a global `opt-level = "s"` or `"z"` (the per-message path pays it, and pico is `-O3`); `#[optimize(size)]`
per function (unstable); `dyn SessionEngine` for the coop build (every method of the trait is then
linked whether an export reaches it or not, which is why `crates/wz-capi-pico/src/session.rs` names
the engine's own type outside `engine-tokio`); zenoh's codec shape, generic over its writer
(`commons/zenoh-codec/src/network/push.rs @ impl<W> WCodec<&Push, &mut W> for Zenoh080`), which
is the instance-per-sink form X1 removes.

## 3. Sessions: 69,338 (66,419 on the sh2 reading) to at most 27,508

Owners now (bytes/bodies): `wz_capi_coop::engine` 16,404/78, `slot_map` 7,707/44,
`session_tables` 7,288/38, `engine::direct` 5,447/17, `ext_admit` 4,000/12, `arena` 3,599/17,
`key_arena` 2,235/25. pico: `src/net/session.c` 4,124, `src/session/interest.c` 4,077,
`src/net/primitives.c` 3,111, `src/session/subscription.c` 1,761, `src/net/filtering.c` 1,532.

| # | what (wz now) | pico | target | structure | files | lane boundary |
|---|---------------|-----:|-------:|-----------|-------|---------------|
| S1 | declaration and undeclaration, one door body per kind: `declare_write_filter` 2,006, `undeclare_write_filter_quietly` 1,470, `undeclare_subscriber` 1,432 + 743, `Declaring::declare` (Subscriber) 1,510, `declare_keyexpr_where` 1,094, `Declaring::keyed` 1,021, `declare_filter_matching_listener` 954, `declare_subscriber_on_wire` 903: about 11,100 | `_z_declare_subscriber` + `_z_register_subscription` + `_z_write_filter_create` + `_z_send_declare`: about 2,800 | at most 3,000 (-8,100 est.) | One `EntityPipeline` (P3): `declare(kind: EntityKind, key: &KeyRequest, row: RowParts) -> Result<EntityHandle, Refusal>` and `undeclare(handle)`, non-generic. `EntityKind` is an enum whose per-kind facts (wire declaration id, interest flag, table, whether a matching listener watches it) are a const table, not a type. The rows of every kind share one header (`EntityId`, key handle, holds, callback slot) and one slot pool per kind addressed by stride (S2). The wire write is one `LentDeclaration` encode with the kind's id. Ownership: the pipeline owns the tables; the engine door holds the lock and calls it once. No copy of the key text: the key arena's handle is the row's key. Branching: one match on `EntityKind` in the pipeline, none in the doors. | `wz-session-core/src/session_tables.rs`, `declare/*.rs`, `wz-capi-coop/src/engine.rs` (the `SessionEngine` declare and undeclare methods), `wz-capi-port/src/engine.rs` (the trait's declare family collapses to two methods) | Lane T-DECL. Owns `session_tables.rs` and the engine's declare/undeclare methods; stops at the doors (D1 calls its two new methods). Depends on T-ROWS. |
| S2 | the typed faces of row tables: `slot_map` 7,707/44, `key_arena` 2,235/25, `id_map` 678/7, `row_pool` 108 | `_z_slist`/`_z_list` bodies (in language) | at most 2,500 (-8,200 est.) | P2 and P6 finished: `RawSlots { meta: &mut [Meta], rows: *mut u8, stride: u16, count: u16 }` with `insert_raw(&mut self, write: &dyn Fn(*mut u8)) -> Option<RawHandle>`, `get_raw`, `remove_raw(drop: unsafe fn(*mut u8))` out of line; `SlotMap<K, T>` keeps `#[inline(always)]` casts only. With counts chosen at open (P6) the `const N` parameter leaves the type, so every table of every kind and capacity calls the same bodies. A row moves once, into its slot (already true of `insert_with`). | `wz-session-core/src/slot_map.rs`, `key_arena.rs`, `id_map.rs`, `row_pool.rs` | Lane T-ROWS. Owns those files; lands after the heap lane's runtime capacities (`heap.md`) and before T-DECL. |
| S3 | open and assembly, generic over the engine's link and clock types: `lend_session` 3,844, `assemble` 3,442, `place_link_session` 985, `arena` 3,599/17, `replay::told` 990, `close` 858, `open_links` 786, `session_init_params` 428, `session_zid` 317: about 15,200 | `_z_open`, `_z_open_connect_locator` 1,138, `_z_client_reopen_task_fn` 798: about 3,500 | at most 4,500 (-10,700 est.) | A non-generic `SessionPlan` (counts from the configuration, zid, locators, timeouts, the arena layout as offsets) computed by one non-generic `plan_session(config: &OpenConfig) -> Result<SessionPlan, OpenRefusal>` (P5: no type parameter, `#[inline(never)]`, one caller); the generic engine only places cells at the plan's offsets (`place(plan: &SessionPlan, links: L, clock: C)`, one short body). Teardown is the plan read backwards, one body. The arena's lay-out functions take `&ArenaLayout` (sizes and alignments as numbers), not types. Ownership: the plan is a value the open builds and drops; the arena owns every cell. | `wz-capi-coop/src/engine.rs` (`lend_session`, `assemble`, `close`), `engine/direct.rs` (`place_link_session`, `open_links`), `arena.rs`, `lodging.rs`, new module `wz-capi-coop/src/plan.rs` (no crate and no profile row) | Lane T-OPEN. Owns open and close; the read and the send are not its. Under P5 as decided (section 9 O1). |
| S4 | the read and delivery of section 8: `DirectSink::event` 2,250, `drive_link` 2,729, `link_turn` 2,284, `deliver` closure 1,218, `hand_row_by_row` closure 1,066, `dispatch_iteration_event_with_local` 1,042, `UnicastLink::input` 985: about 11,600 | `_z_handle_network_message` 635, `_z_trigger_subscriptions_impl` 1,527: about 2,200 | at most 6,000 (-5,600 est.) | Keep the Push-to-callback path concrete (P1). Move every arm that is not a Push to a subscriber out of the hot bodies into one `#[cold]` non-generic `control_in(&mut ControlCtx, msg: ControlView)` (declarations in, interest replies, final, OAM), reached through one call the hot body takes only on a non-Push header. One delivery body serves the direct read and the replay (`deliver_rows(rows: RowRange, sample: &LentSample)`), where two closures carry a copy each now. | `wz-capi-coop/src/engine/direct.rs`, `engine.rs` (`deliver`, `hand_row_by_row`), `wz-session-core/src/declare/subscriber.rs`, `link_life.rs` | Lane T-READ, after section 8 lands. Shares `direct.rs` with `ir-receive.md`'s lane: the same lane carries both, or T-READ follows it. |
| S5 | extension admission: `ext_admit` 4,000/12, `map_or::<ExtAdmission, judge_entries>` 1,245, `push_read::Judge::entry` 1,106: about 6,350 | `_z_msg_ext_skip_non_mandatories` and the decoders (in codec) | at most 1,500 (-4,800 est.) | One table-driven judge: each carrier's defined extension ids as a `&'static [u8]` in `.rodata`, one loop over the header bytes (`judge(carrier: ExtCarrier, headers: &[u8]) -> ExtAdmission`), out of line, non-generic; `judge_ext_entries<E: ExtEntryView>` collects the header bytes into a small stack array and calls it. pico skips every non-mandatory extension in one function (`vendor/zenoh-pico/src/protocol/codec/ext.c @ z_result_t _z_msg_ext_skip_non_mandatories(_z_zbuf_t *zbf, uint8_t trace_id) {`). The rule held by the admission tests is unchanged. Read 2026-11-26 on the lane t-ext (`c829f01a5`, main's reading): sessions -982, codec -253, receive W -26.9 Ir per message, so the first step lowers the message path too; the rest of the row's -4,800 is read by owner (M10) before a second step. | `wz-session-core/src/ext_admit.rs`, `network_message.rs` (`judge_entries`), `network_message/push_read.rs` | Lane T-EXT. Hot-adjacent: a Push with extensions crosses it; the receive callgrind must not rise (M2). |
| S6 | the rest: `engine::pinned` 791, `registry` 625/15, `publish_options` 634/11, `sample` 629/14, `runtime_cell` 422/28, `region` 398/25, `peer_tables` 425, `peer_init_caps` 281, `datagram_peer` 226, `locator_grammar` 390, `encoding_hint` 474, small bodies: about 14,300 | the rest of pico's sessions: about 9,000 | at most 10,000 (-3,200 est.) | P8 first: read which of `peer_tables`, `peer_init_caps`, `datagram_peer` a client of the preset reaches (a client opens no peer); what it does not is behind the role that does. Then P2 for `runtime_cell` and `region` (cells as one body over a stride). | as named | Lane T-SESS-REST, last; it reads after S1 to S5 land. |

The sessions rows total -40,600 estimated against a gap of 41,830, so the area reaches pico only
at the top of the estimates. S3's -10,700 was first written with a size level inside it; M1 read
that level at nothing, so S3's estimate holds only by P5's non-generic form, and section 10.2's
bounds, which count no level, are the measure. S1 stays in the session crate as one non-generic
pipeline: declarations are cold by the callgrind, and P5 makes that their form, not their crate.

## 4. Doors: 41,138 (41,399 on the sh2 reading) to at most 19,034

Owners now: `wz_capi_pico::bytes` 6,123/77, `pubsub` 5,780/48, `keyexpr` 5,147/44, `session`
2,769/30, `serde` 1,950/45, `encoding` 1,486/68, `object_slot` 1,451/27, `os::no_std_host`
1,351/71, `process_pool` 1,243/10, `config` 1,215/9, `endpoint` 1,150/5, `handlers` 1,030/22,
`ffi` 1,025/16, `ffi::boundary` 990/90, `matching` 927/16, `abi` 829/48. pico: `src/api/api.c`
12,315, `src/api/serialization.c` 4,886, `src/api/encoding.c` 1,386.

| # | what (wz now) | pico | target | structure | files | lane boundary |
|---|---------------|-----:|-------:|-----------|-------|---------------|
| D1 | doors that compose their operation: `declare_subscriber_with` 1,770, `z_declare_publisher` 1,635, `z_open` 1,105, `open_request` 1,012, `store_canonized` 827, `matching::declare_on_filter` 582, `declare_up_to` 458, `DeclaredKeyexpr::share` 393, `session_publish` 350: about 8,100 | `z_declare_subscriber` 222, `z_declare_publisher` 223, `z_open` 478, `z_publisher_declare_matching_listener` 213, `_z_keyexpr_append_suffix` 188: about 1,300 | at most 2,000 (-6,100 est.) | P4: each door reads its C arguments into `DeclareRequest { kind, key: KeyArg, callback: CallbackParts, options: u32 }` (or `OpenRequest`) and calls the engine's `declare` (S1) or the open (S3) once, `#[inline(never)]` below the export. Key canonization happens once, in the pipeline's key step, not in each door. The export owns only the C object's slot; the session owns the row. | `wz-capi-pico/src/pubsub.rs`, `keyexpr.rs`, `session.rs`, `matching.rs`, `write_filter.rs` | Lane T-DOORS. Starts after T-DECL's two methods exist; owns the door files. |
| D2 | the per-type object families and the export boundary: `abi` 829/48, `object_slot` 1,451/27, `ffi::boundary` 990/90, bodies with no source line 601/102, `process_pool` 1,243/10, `handlers` 1,030/22: about 6,150 | the `_Z_OWNED_FUNCTIONS_*` families, each body a few instructions (`vendor/zenoh-pico/include/zenoh-pico/api/olv_macros.h @ #define _Z_OWNED_FUNCTIONS_VALUE_IMPL(type, name, f_check, f_null, f_copy, f_move, f_drop)`) | at most 2,500 (-3,650 est.) | One non-generic body per operation over a `TypeFacts { size: u16, align: u8, drop: unsafe fn(*mut u8), null: unsafe fn(*mut u8) }` static per type: `obj_move(&TypeFacts, dst, src)`, `obj_drop(&TypeFacts, p)`, `obj_check`, `obj_null`. Each `z_*_drop` / `_move` / `_check` export is a tail call with its type's static (5 to 10 bytes). `process_pool` and `object_slot` become one pool body over `TypeFacts`. The boundary guard of the no_std build (no unwinding) is one body, not one per export. | `wz-capi-pico/src/abi.rs`, `object_slot.rs`, `process_pool.rs`, `handlers.rs`, `ffi.rs`, `ffi/boundary.rs` | Lane T-ABI. Independent of the others; touches no session file. |
| D3 | bytes and serialization: `bytes` 6,123/77 (`z_bytes_writer_append` 891, `ByteBuf::reserve` 636, `Block::with_room` 409, `store_slice` 376, `z_bytes_slice_iterator_next` 299), `serde` 1,950/45: about 8,050 | `src/api/serialization.c` 4,886 and `src/collections/bytes.c` (in language): pico's bytes are a vector of shared slices (`vendor/zenoh-pico/include/zenoh-pico/collections/bytes.h @ _z_arc_slice_svec_t _slices;`) | at most 4,500 (-3,550 est.) | One byte chain shared by the doors and the session: `ByteChain { blocks: [BlockRef; K], len }`, `BlockRef` a handle into the payload pool the heap lane fixes at open. `append`, `reserve`, `slice_iter_next` are one body each over the chain; the writer and the serializer write through one `ChainWriter`. No second buffer type for the door side. | `wz-capi-pico/src/bytes.rs`, `serde.rs` | Lane T-BYTES, after `heap.md`'s payload pool lands (same files' storage). |
| D4 | encodings: `encoding` 1,486/68 | `src/api/encoding.c` 1,386 (`vendor/zenoh-pico/include/zenoh-pico/api/encoding.h @ const z_loaned_encoding_t *z_encoding_zenoh_bytes(void);`) | at most 900 (-600 est.) | One `static ENCODINGS: [Encoding; N]` in `.rodata`; each `z_encoding_*` export returns `&ENCODINGS[i]` (one `lea` and `ret`); `z_encoding_to_string` and `from_str` are one table walk. | `wz-capi-pico/src/encoding.rs` | Lane T-ABI. |
| D5 | configuration: `config` 1,215/9, `zp_config_insert` 764 | `zp_config_insert` inside api.c | at most 600 (-1,350 est.) | The capacity ruling's configuration keys and pico's keys in one fixed table of `(key: u8, text: KeptText)` rows the open reads (the table is `heap.md`'s storage); one insert body, one lookup body. | `wz-capi-pico/src/config.rs` | Lane T-OPEN (the configuration is the open's input). |
| D6 | the platform exports: `os::no_std_host` 1,351/71, `os::unix` 699/14, `platform` 574/30: about 2,600 | `src/system/unix/system.c` 1,876 (in driver) | at most 1,800 (-800 est.) | Each `z_*` platform export a tail call into the one runtime body `wz-runtime-posix` already has (clock, sleep, random); no second copy of the conversion in the door crate. | `wz-capi-pico/src/os/*.rs`, `platform.rs` | Lane T-ABI. |
| D7 | the doors' hot and cold split | (pico is `-O3`, one level) | no saving of its own (the size level is withdrawn: M1, 2026-11-26) | By form, not by crate (P5): the hot doors (`z_put`, `z_publisher_put`, the sample accessors, the subscriber trampoline `subscriber_sink_at::call`) keep their bodies in the export, concrete and inlinable; every other door is a shell over one of D8's non-generic `#[inline(never)]` marshals. No `wz-capi-pico-hot` crate and no profile row. | `wz-capi-pico/src/pubsub.rs` (the hot doors stay), the marshals of D8 | Lane T-DOORS. |

Doors total -16,050 estimated against a gap of 22,104 once D7's -2,500 to -4,000 is withdrawn
with M1's reading: these rows do not reach pico, and section 10.3's bounds, which never counted
D7, are what do.

## 5. Transport and driver

### 5.1 Transport: 32,570 (31,737 on the sh2 reading) to at most 13,951

Owners now: `session_actions` 11,449/68, `sce_rust_runtime` (engine 5,283, microstep 1,309,
event queue 785, state set 573, policy 565, tables 466, run store 240) 9,221, `drive` 4,602/16,
`reassembly_dispatch` 2,265/8, `tx_buf` 880, `tx_lease` 653, `transport_timers` 612. pico:
`src/transport/common/tx.c` 3,483, `unicast/transport.c` 2,324, `unicast/rx.c` 1,820,
`unicast/read.c` 1,010.

| # | what (wz now) | pico | target | structure | files | lane boundary |
|---|---------------|-----:|-------:|-----------|-------|---------------|
| X1 | the send side: `session_actions` 11,449/68 less the machine's binding (`record_established_at` 499, `init_core` 455, which are X3's), about 10,500; its largest bodies `open_frame_lent` 2,451 (over `dyn Fn`), `dispatch_network_message_in::<false>` 1,220, `LentDeclaration::encode` 1,151, `lend_frame` 432, `write_lent` 348, `drain_conduits` 284. Beside it `lent_push::write_push` in two bodies (2,038 + 1,017 + 177 in codec, language and sessions) | `_z_transport_tx_send_n_msg_inner` 1,341, `_z_send_n_msg` 459, `_z_transport_tx_send_fragment` 433, `_z_transport_tx_send_t_msg` 408: about 2,650 (`vendor/zenoh-pico/src/transport/common/tx.c @ static z_result_t _z_transport_tx_send_n_msg_inner(_z_transport_common_t *ztc, const _z_network_message_t *n_msg,`) | at most 4,300 (-6,200 est.; `write_push`'s one body saves -1,000 to -1,500 more, in codec and language) | One `TxBatch { buf: &mut [u8], at: u16, frame: Option<(Reliability, Sn)>, streamed: bool }` with one `write_n_msg(&mut TxBatch, msg: &dyn WireWrite) -> Written`: open a frame when none is open for the message's reliability, write the message in place, and on no room close and flush the batch once and retry; a message larger than a batch goes to one cold `fragment` body. One sink type for the message writers, so `write_push` has one body (M5 reads which two sinks it has now; a sizing pass and a writing pass become one pass with a back-patched length). The `dyn Fn` of `open_frame_lent` becomes the `TxBatch` value. Each face has one `TxBatch`; what a read stage writes to a face (a get's Response and ResponseFinal, a cold plane's control message) waits in it and is flushed once when the read stage ends, so no send window is held open while a callback runs (`ir-send-query.md` D6, decided 2026-11-26 under the owner's delegation). | `wz-session-core/src/session_actions.rs` (send side), `lent_push.rs`, `tx_buf.rs`, `tx_lease.rs` | Lane T-TX. The send Ir is `ir-send-query.md`'s: that lane's per-put callgrind is the gate, and the two lanes share `session_actions.rs`'s send half; one lane carries it. |
| X2 | the receive unit: `UnicastRx::dispatch_datagram` 3,965, `read_control_in_place` 1,471, `dispatch_copied` 473, `admit_head_in_place` 317, `walk_records_in_place` 294, `service_due` 1,163: about 7,700 | `_z_unicast_handle_frame` 329, `_z_unicast_process_messages` 332, `unicast/read.c` 1,010: about 1,700 | at most 3,500 (-4,200 est.) | The hot body is the Frame walk to a Push (P1). Every transport message that is not a Frame (Init/Open strays, Close, KeepAlive, Fragment, OAM, Join) goes to one `#[cold]` `transport_control(&mut RxCtx, header: u8, unit: &[u8])`, non-generic: `RxCtx` is a struct of plain references (the sequence numbers, the lease, the reassembly slot, a `&dyn RxEvents` for the few callbacks), so it is not instantiated over the runtime, the clock and the sink as `dispatch_datagram` is now. | `wz-session-core/src/unicast_rx.rs`, `drive.rs`, `reassembly_dispatch.rs`, `wz-runtime-coop/src/session_drive.rs` | Lane T-RX. Shares the receive files with `ir-receive.md`'s lane; that lane's per-sample callgrind is the gate. |
| X3 | the generated session machine and its runtime: 9,221, of which 1,454 in second and third bodies of `EngineHost` methods (`first_enabled_transition` 749/3, `run_turn` 474/3, `new_in_place` 377/3, `queue` 207/3, `store` 171/3) | the hand-written handshake: `_z_unicast_handshake_open` 873, `_z_unicast_handshake_listen` 646 (`vendor/zenoh-pico/src/transport/unicast/transport.c @ static z_result_t _z_unicast_handshake_open(`) | at most 4,500 (-4,700 est.) | The machine stays the SCXML source's (item 3 of `docs/c-abi-size-diet.md` section 5); its runtime is made one body per operation: `EngineHost`'s methods `#[inline(never)]` so the three call sites share one body (M4 reads where the three bodies come from); no size level for `sce-rust-runtime` (M1 read none under fat LTO), and the generated step functions' copies go by section 10.4's walker. A turn runs per transport event, not per sample, which M2 confirms. The machine's tables stay data; moving more of the interpreter into tables is an SCE change (`docs/sce-proposals/`) and is counted in `.text` plus `.rodata` (O4). | `vendor/sce` only through an SCE proposal | Lane T-SCE. M1 is read (no level survives); the inline attributes and the walker are an SCE review. |
| X4 | timers and deadlines: `drive::keepalive_deadlines` 489, `UnicastTransport::due_ms` 792, `transport_timers` 612, `tx_deadline` 343: about 2,250 | `_zp_unicast_lease_task_fn` (`vendor/zenoh-pico/src/transport/unicast/lease.c @ _z_fut_fn_result_t _zp_unicast_lease_task_fn(void *ztu_arg, _z_executor_t *executor) {`) | at most 900 (-1,350 est.) | One `Deadlines { at: [u64; D] }` per link (lease, keepalive, batch flush, fragment expiry) with one `next_due` scan and one `fire(kind)` match; the per-timer functions become rows of a const table. | `wz-session-core/src/drive.rs`, `transport_timers.rs`, `tx_deadline.rs`, `unicast_transport.rs` | Lane T-RX (same files). |
| X5 | reassembly: `reassembly_dispatch` 2,265/8 | `_z_unicast_handle_fragment_inner` 825 | at most 1,000 (-1,250 est.) | The dispatcher's const parameters (`<2, 4096>`) become the open's counts (P6); staging is one body over a byte slot. | `wz-session-core/src/reassembly_dispatch.rs`, `chain_staging.rs` | Lane T-RX, after `heap.md`'s runtime counts. |

Transport totals -17,700 estimated against a gap of 18,619.

### 5.2 Driver: 28,995 (29,577 on the sh2 reading) to at most 16,049

Owners now: `wz_runtime_posix::net` 2,463/29, `ip_stack` 2,242/5, `stream_link` 2,196/26, `faces`
2,188/21, `link_storage` 1,969/19, `kept` 1,914/54, `transport::state` 1,823/8, `locator_text`
1,820/7, `link_cells` 1,704/50, `udp_link` 1,536/26, `executor` 1,485/19, `session_drive`
1,284/34, `wz_host_sync::in_place` 1,114/28, `runtime_posix::stream` 1,010/10. pico:
`src/link/endpoint.c` 3,154, `src/system/unix/system.c` 1,876, `tcp_posix.c` 1,562,
`udp_posix.c` 1,497, `src/link/link.c` 1,322, `runtime/executor.h` 1,286.

| # | what (wz now) | pico | target | structure | files | lane boundary |
|---|---------------|-----:|-------:|-----------|-------|---------------|
| R1 | the link layers: `stream_link` 2,196/26, `udp_link` 1,536/26, `link_storage` 1,969/19, `link_cells` 1,704/50, `session_drive` 1,284/34: about 8,700 in 155 bodies | `src/link/link.c` 1,322 and the posix link files: one `_z_link_t` with function pointers (P7) | at most 3,500 (-5,200 est.) | One `LinkDriver` per link: a record of the socket (`&mut dyn LinkSocket` with `read`, `write`, `close`, `wait`), `streamed: bool`, the receive and send buffers as byte slots of the open's arena. The stream's two-byte length is read and written in one place, branched on `streamed` (pico's `case Z_LINK_CAP_FLOW_STREAM:`). `SessionDatagramLink`, `BoxedLinkDriver` and `StreamSocket` fold into `LinkSocket`; `link_cells` and `link_storage` into the arena's cells (S3). | `wz-runtime-coop/src/stream_link.rs`, `udp_link.rs`, `link_storage.rs`, `link_cells.rs`, `session_drive.rs`, `wz-session-core/src/link.rs` | Lane T-LINK. The read loop's Ir is `ir-receive.md`'s: one indirect call per datagram is what pico pays too; its callgrind is the gate. |
| R2 | dial, faces and the supervisor, open-time: `LinkSupervisor::begin_dial` 1,541 + 346, `CoopEngine::place_link_session` 1,599, `faces` 2,188, `ip_stack` 2,242, `transport::state` 1,823, `IpDial::poll` 595: about 10,300 | `_z_open_link` 356, `_z_udp_unicast_open` 643, `_z_tcp_open` 390, `_z_new_transport` 647: about 2,000 | at most 4,000 (-6,300 est.) | Dialing is cold (P1, P5): one non-generic `dial_step(plan: &LinkPlan, at: &mut DialCursor) -> DialAsk` reads the endpoint text, walks the host's addresses and answers what the dial needs next (a socket of a kind to an address, a wait, a refusal); the generic `IpLinks<Udp, Tcp>` is only the socket constructor that answers the ask (`make(kind, addr) -> Result<LinkDriver, DialRefusal>`, one short body), and the socket it makes is R1's `LinkDriver` record. No trait object is made for the dial (t-open's `&dyn` adapter cost +880); the endpoint reader t-open moved is the non-generic body this row wants, its adapter and its profile rows are what P5 removes. The supervisor's per-face state becomes rows of one face table (one face in the client preset: `OneFace` already). | `wz-runtime-coop/src/faces.rs`, `ip_stack.rs`, `dial.rs`, `transport/state.rs`, `wz-capi-coop/src/engine/direct.rs` (`place_link_session`) | Lane T-OPEN (dial is open). |
| R3 | shared cells: `kept` 1,914/54 with `Shared::last_placed` 885/4 | (none) | at most 600 (-1,300 est.) | P2: one untyped `Shared` body over a stride; `last_placed` one body (its four bodies hold 403 duplicate bytes). | `wz-runtime-coop/src/kept.rs` | Lane T-ROWS. |
| R4 | the executor and the host locks: `executor` 1,485/19, `wz_host_sync::in_place` 1,114/28, `cs` 266, `sync` 147, `time` 243, `timer` 85: about 3,340 | `_z_executor_spin` 557, `_z_executor_get_next_fut` 438 (`vendor/zenoh-pico/include/zenoh-pico/runtime/executor.h @ _z_executor_status_t _z_executor_spin(_z_executor_t *executor);`) | at most 2,000 (-1,340 est.) | The executor's task cells as rows of one untyped table (P2); `poll_erased` is the one indirect call per task, as pico's future function pointer. The in-place host lock is one body over the lock word. A runtime that hosts no task (the direct read of section 8 steps its one link) gets a task table of no cell, so the pass, settle and sweep over a cell are not linked: lane coop-resolver-pay (`242bb9917`), about -1,090 B held by today's one-cell table, measure. | `wz-runtime-coop/src/executor.rs`, `wz-host-sync/src/in_place.rs` | Lane T-LINK. `run_among` and `poll_erased` are in the receive hot set: the receive callgrind is the gate. |
| R5 | the posix sockets: `runtime_posix::net` 2,463/29, `stream` 1,010/10 | `tcp_posix.c` 1,562 + `udp_posix.c` 1,497 | at most 3,000 (-470 est.) | One socket body for both kinds (open, set non-blocking, poll, read, write) with the kind as a value; pico keeps two files, so the target is pico's sum. | `wz-runtime-posix/src/net.rs`, `stream.rs` | Lane T-LINK. |
| R6 | `locator_text` 1,820/7 | inside `src/link/endpoint.c` 3,154 | unchanged (wz's endpoint text is under pico's) | none | | |

Driver totals -14,610 estimated against a gap of 12,946.

## 6. The areas under pico, the total, and the parity preset

| area | wz (2026-11-25) | wz, sh2 (2026-11-26) | pico | target | what holds it |
|------|---:|---:|-----:|-------:|---------------|
| keyexpr | 9,612 | 8,087 | 13,490 | at most 13,490 | unchanged; `keyexpr_canon::CanonWalk::next` 2,908 is the largest body, the generated matchers about 3,700 |
| codec | 34,943 | 28,440 | 35,440 | at most 35,440 | the margin is 497 (7,000 on the sh2 reading). SCE ADR 0137 (the runtime's reader inlined at its read sites) reads +5,728 here (main, 2026-11-26), which leaves about 1,270 on the sh2 reading; SCE ADR 0138 (shared primitives) expects about -3 KB back, measure. t-ext's S5 took -253; X1's one `write_push` body (-1,000 to -1,500 est.) moves more out; any new codec arm is paid in the same commit |
| language | 18,431 | 12,888 | 45,028 | at most 45,028 | `wz_session_core::bounded` 8,591/81 is the candidate of P2 if a later change needs room |
| total | 235,152 | 218,547 (the seven areas) | 170,500 | at most 170,500 | the four areas' rows: about -91,500 to -93,000 est.; the total needs -64,652 (-48,047 on the sh2 reading) |

**The parity preset (`std`, heap): 864,298 against 505,302.** The rows above are its rows too
(the same session, door, transport and driver code). What the `std` form adds is not read by
area: this lane has no explain document of that case (M3). From the code and section 1 of
`docs/c-abi-size-diet.md`: unwinding kept by `ffi::guarded` (landing pads and tables, T7's
measure), `std`'s formatter and `io` reached from `Display` of errors, `alloc`'s growth paths one
per element type of each `Vec` and `hashbrown` map, and the `BTreeMap` of the configuration.
The structures: P2 for the growth paths (they become the open's fixed tables, `heap.md`); D5 for
the configuration; the error words formatted only where a program prints them (T3's rule); and O3.

## 7. Where size and Ir meet

The receive hot set, from the per-sample callgrind of the no_std subscriber (exclusive Ir per
sample, the largest first): `SubscriberPeer::dispatch_iteration_event`, `Core::idle_wait`,
`CoopEngine::step_after`, `ExecutorState::run_among`, `deliver_ref`, `network_message::read_push`,
`UnicastRx::dispatch_datagram`, `StreamDriver::recv_with`, `CoopEngine::hand_out`,
`executor::poll_erased`, `drive::keepalive_deadlines`, `subscriber_sink_at::call`,
`SceCursor::read_vle_inner`, `net::poll_on`, `resolve_wireexpr_viewed_held_over`,
`walk_records`, `ExtEntryView::decode_into`, `lend_pulled`, `in_place::lent_body`. That reading
predates section 8 (it names the round's `RoundDelivery`); `ir-receive.md` owns its successor.

Rules:

1. A body in the hot set keeps its form unless the same change lowers its per-sample Ir; a cold
   arm moved out of it (S4, X2) must leave the hot body's Ir equal or lower, read by the callgrind
   of the lane that owns the path (M2).
2. A hot body that is also large keeps its inlining where the callgrind shows the call's Ir; where
   it does not (a callee reached once per batch, not per sample), `#[inline(never)]` is allowed.
3. Cold bodies: `#[inline(never)]` at the boundary of each plane (open, declare, control,
   teardown) so the plane's code is not copied into its callers; inside a plane the compiler
   decides at that crate's level.
4. `keepalive_deadlines` is in the hot set because it runs on every turn: X4 must make the scan
   cheaper, not only smaller (one `next_due` over a short array).
5. A cold plane writes and does not send: what it has for a face goes into that face's `TxBatch`
   and leaves with the read stage's one flush (X1), so the hot loop keeps its one send per face and
   no cold body is generic over the link to reach it (P5).

## 8. Lanes and their order

| lane | rows | depends on | shares files with |
|------|------|-----------|-------------------|
| T-SCE | X3 (inline attributes; the walker of 10.4) | nothing; M1 is read (no profile row) | none |
| T-ABI | D2, D4, D6 | nothing | none |
| T-ROWS | S2, R3 | `heap.md`'s runtime counts (P6) | `heap.md`'s lane (`slot_map.rs`, `key_arena.rs`) |
| T-DECL | S1 | T-ROWS | none |
| T-DOORS | D1, D7 (hot doors stay, the rest shells), D8 | T-DECL | none |
| T-OPEN | S3, S10, D5, R2 | P5 (O1 as decided); `heap.md` (the plan's counts) | `heap.md` (`arena.rs`, `config.rs`) |
| T-EXT | S5 | nothing | `ir-receive.md` (`push_read.rs`) |
| T-BYTES | D3 | `heap.md`'s payload pool | `heap.md` (`bytes.rs`) |
| T-TX | X1 | `ir-send-query.md`'s send structure | `ir-send-query.md` (`session_actions.rs` send half) |
| T-RX | X2, X4, X5 | section 8 of `docs/c-abi-architecture.md` landed | `ir-receive.md` |
| T-READ | S4 | section 8 landed | `ir-receive.md` (`direct.rs`) |
| T-LINK | R1, R4, R5 | T-OPEN's `LinkPlan` | `ir-receive.md` (the read loop) |
| T-SESS-REST | S6 | S1 to S5 | none |

Order: T-SCE and T-ABI first (no dependency). Then the heap lane's runtime counts, T-ROWS,
T-DECL, T-DOORS. T-OPEN at once under P5; t-open's branch is re-cut to R2's form (its endpoint
reader kept, its adapter and profile rows dropped) before it lands. The lanes
that share the receive and send files run as part of, or after, the Ir lanes that own those paths,
never beside them. Each lane's commit carries its own ledger reading of its area and the
per-sample callgrind of the path it touches.

### 8.1 Readings of landed and landing lanes (2026-11-26, the main session's)

| lane | rows | reading | status |
|---|---|---|---|
| sh2 (`440a6f1cc`) | P9 | the ledger's total -15.6 KB; the seven areas -16,480 (section 1) | measured; landing |
| t-ext (`c829f01a5`) | S5 | sessions -982, codec -253; receive W -26.9 Ir per message | measured; the row's rest open (M10) |
| t-open (`a11a6dc9a`) | M1, R2 | the endpoint reader at `opt-level = "s"`: -1,899 / +1,875, no effect; its `&dyn` adapter +880 | read; re-cut to P5's form (R2) |
| coop-resolver-pay (`242bb9917`) | R4 | a runtime with no task links no one-cell table: about -1,090 B est. | measure |
| SCE ADR 0137 (pin) | codec | +5,728 (the runtime's reader inlined) | measured; ADR 0138 expects about -3 KB, measure |
| decl-row (`3201059a2`) | S1's first step | declare and retract, wz over pico: subscriber 0.88, publisher 0.67, queryable 0.89; get, the querier, 1.49 (the harness before `f5f8ce646`; the callers' lines are not the biased ones) | measured; its ledger reading, measure |

## 9. Owner decisions and measurement cells

**Owner decisions.**

- **O1** (decided 2026-11-26 under the owner's delegation). No crate is a size boundary. The
  proposal of new crates at `opt-level = "s"` (`wz-session-open` for the cold planes,
  `wz-capi-pico-hot` for the hot doors) is withdrawn on M1's reading: in `capi-nostd` a crate's
  level does not survive fat LTO, and the adapter a crate cut needed cost +880. Cold code is one
  non-generic body at the root's level (P1, P5); the rows that leaned on the level are designed on
  that form: S3 and S10 (a plan computed by one body, planes over plain references), R2 (the
  generic links only a socket constructor, the made socket R1's `LinkDriver`), D7 (hot doors by
  form, the rest shells) and X3 (no runtime level; the walker). Residue: the `capi-nostd` rows
  of `wz-app-schema`, `wz-auth` and `wz-tls-pem` in `crates/Cargo.toml` buy nothing in that
  profile by the same reading (cell M1b reads them before a change removes them).
- **O5** (decided 2026-11-26 under the owner's delegation). A get's ResponseFinal is written into
  its face's `TxBatch` and the batch is flushed once when the read stage ends; no send window is
  held open while a callback runs (X1, `ir-send-query.md` D6). The lane t-tx implements it.
- **O2.** The rule of section 7: per-sample and per-put Ir never rises for text; at equal Ir, text
  decides.
- **O3.** The parity (`std`) preset's panic strategy: `ship` unwinds so the doors catch a panic;
  `capi-small` aborts. The unwind tables and landing pads are part of that preset's gap.
- **O4.** What a move of code into tables is graded by: this design grades `.text` plus
  `.rodata` for any row that turns code into data (S5, D4, X3, X4), so a table is not a way around
  the budget.

**Measurement cells** (each a reading the main session or a lane makes; none was made here).

| cell | what | why |
|------|------|-----|
| M0 | that the explain document read here is the ledger build of `1ab46747e` (schema 4, dated 2026-11-25, area totals equal to the figures of this file) | every "wz now" figure |
| M1 | does a crate's size level survive fat LTO in `capi-nostd`: **read 2026-11-26** (t-open): no, the moved bytes -1,899 / +1,875, the adapter +880 | P5, O1 |
| M1b | the same on the C-level root of sh2, and the ledger with and without the `capi-nostd` rows of `wz-app-schema`, `wz-auth`, `wz-tls-pem` | O1's residue |
| M2 | the per-sample receive callgrind and the per-put send callgrind before and after S4, S5, X1, X2, R1, R4 | rule 1 of section 7 |
| M3 | the explain document of the parity case (`std`) | section 6 |
| M4 | where the three bodies of each `EngineHost` method come from (three inlined call sites or three instances) | X3 |
| M5 | the two instances of `lent_push::write_push`: which two `SceSink` types | X1 |
| M6 | `.text` plus `.rodata` for the rows of O4 | O4 |
| M7 | the inlined bytes of each area after rule 3 of section 7 | S1 to S6, D1 |
| M10 | the explain document of the sh2 reading by owner: the owners of sections 3 to 5 read again on the C-level root, and what raised doors by 261 and driver by 582 | P9, every row's base after sh2 |
| M11 | the ledger of coop-resolver-pay (the one-cell table gone) and of SCE ADR 0138's pin (codec) | R4, section 6 |
| M12 | the per-message receive and per-operation lines of each text lane, read with the window harness of `f5f8ce646` (the receivers' connected window, net of an idle run): measure, harness f5f8ce646 | rule 1 of section 7, O2 |

## 10. 보강 (reinforcement): every area under pico at the low end of its estimates

Status: design, 2026-11-26, the reinforcement the review of section 9 of
`docs/c-abi-architecture.md` asked for. Sections 3 and 4 reach pico only at the top of their
estimates (sessions -40,600 against a gap of 41,830; doors -18,550 to -20,050 against 22,104), and
doors lean on D7's size level, which M1 has since read not to survive fat LTO. This section changes the
method for those two areas from "subtract estimated savings from today's figure" to "add up what
the finished structure holds": each component gets a bound, the bounds sum under pico's figure
with no credit taken for a size level (M1), and each lane lands with its owner's ledger row held
under its bound. It also gives the transport the generator change that takes back what the
static step functions added, as a draft ADR for an SCE session.

### 10.1 Why the low end missed

The rows of sections 3 and 4 remove what is there; they do not say what is left. A row's saving
is an estimate of a body not yet written, and the area's total is the sum of those estimates, so
the error of each adds up. A bound per component of the finished structure is checked one lane at
a time: a lane that lands over its bound is red at its own landing (its owner's row in the size
ledger), not at the end of all of them.

### 10.2 Sessions by construction: at most 26,300 against pico's 27,508

Four structures beside S1 to S6:

- **S7. The remote-entity plane on the same kind table.** What a peer declares (subscriber,
  queryable, token, key expression and their retractions), the answer to an interest (the
  declarations a face is owed, then DeclareFinal) and the inbound final are one body each over
  S1's `EntityKind` facts: `remote(kind, op: Declare | Undeclare, face, id, key)` and
  `answer_interest(face, interest)`, which walks the slab once and writes each matching row with
  S-WRITE's one `write_declare`. pico does the same work in `src/session/interest.c` (4,077) and
  in one switch on the declaration kind
  (`vendor/zenoh-pico/src/session/rx.c @ static z_result_t _z_handle_declare_inner(_z_session_t *zn, _z_n_msg_declare_t *decl,`);
  its per-kind senders
  (`vendor/zenoh-pico/src/session/interest.c @ static z_result_t _z_interest_send_decl_subscriber(`)
  are what S7 makes rows. Files: `wz-capi-coop/src/engine/direct.rs`
  (the inbound declaration arms), `engine.rs` (`settle_faces`, `announce`), `wz-session-core`
  peer tables. Lane T-DECL, after S1.
- **S8. The query plane as rows of the pipeline.** A pending get, its legs and its held replies
  are rows of kinds of the same slab (S1, heap R5 and R6); the reply's dispatch is the row found by
  the request id's slot index (ir-send-query Q-REPLY); `get_on_wire`, `hold_leg` and the
  consolidating sink become one `get(request) -> GetHandle` over the pipeline and one
  `reply_in(face, request_id, reply)`. Files: `engine.rs` (`get_on_wire`), `engine/query.rs`,
  `wz-session-core/src/reply_sink.rs`, `get_plane.rs`, `pending_get.rs`. Lane Q-HOLD and Q-REPLY
  of ir-send-query carry it; T-DECL reviews the kind table.
- **S9. A role is a constant, not a branch.** P8 compiles out what the preset's exports cannot
  reach, but a path reachable through a `match` on received data stays linked whether the role
  can meet that message or not (a client meets no peer's InitSyn, no Join, no declaration of a
  peer's router role). Every such arm reads `ROLE: Role`, a `const` of the build (the
  `CONFIG_WZ_ROLE_*` choice), so the compiler removes the arms the role refuses; the refusal is
  the arm the role keeps (the message counted and dropped, as today). Files: `engine/direct.rs`,
  `wz-session-core/src/link_life.rs`, `peer_tables`, `peer_init_caps`, `datagram_peer`. Lane
  T-SESS-REST.
- **S10. The cold planes are not generic over the engine's types.** `CoopEngine<L, C>` is
  instantiated once, but every cold method compiled inside it can be inlined into a hot caller and
  is built at the root's level. The declare, control, query and teardown planes take
  `&mut SessionPlane` (the tables, the slab, the face rows and their `TxBatch`es: no type
  parameter) and reach the link through no trait object (P5): a plane writes its control messages
  into the face's `TxBatch` (rule 5 of section 7) and returns a `PlaneVerdict` (close a face,
  begin a dial, nothing) that its one generic caller carries out, so each plane is one body, out of
  line from the read and the put by rule 3 of section 7. Files: `engine.rs`, `engine/direct.rs`,
  new module `wz-capi-coop/src/plane.rs`. Lane T-OPEN (with S3), then each plane's lane.

The finished area, bounded component by component (none counts a size level):

| component | rows | bound | pico's counterpart |
|---|---|---:|---|
| entity pipeline: declare and undeclare of every local kind, key expressions, write filters, matching | S1 | 3,000 | `_z_declare_subscriber`, `_z_register_subscription`, `_z_write_filter_create`, `_z_send_declare`: about 2,800 |
| remote-entity plane and interest answers | S7 | 2,500 | `interest.c` 4,077 and `_z_handle_declare_inner` in `rx.c` |
| query plane: get, legs, held replies, reply and final in | S8 | 2,500 | `query.c` and `queryable.c` |
| row tables, untyped core | S2 | 2,500 | in pico's language area |
| open, assembly, dial, teardown (cold, non-generic) | S3, S10 | 4,500 | `_z_open` and its callees: about 3,500 |
| read: Push to callback (hot) and `control_in` (cold) | S4 | 5,000 | `_z_handle_network_message`, `_z_trigger_subscriptions_impl`: about 2,200 |
| extension admission | S5 | 1,500 | in pico's codec area |
| the rest after S9: registry, pinned, sample, publish options, encoding hint, locator grammar, region, runtime cell | S6, S9 | 4,800 | the rest of pico's sessions: about 9,000 |
| **sessions** | | **26,300** | **27,508** |

Today's S6 "small bodies" (about 9,000 of its 14,300) are pieces of the declare, control, query
and open planes; in the finished structure they are inside those planes' bounds, which is why the
rest falls further than S6's own row says. Cell M7 reads today's split of them by plane.

Margin 1,200, and it is the whole margin: M1 read no size level under fat LTO (2026-11-26), so no
crate cut adds to it (O1 as decided). t-ext's -982 is inside S5's bound, not beside it.

### 10.3 Doors by construction: at most 17,400 against pico's 19,034

Four structures beside D1 to D7:

- **D8. A door is a shell over one of nine marshals.** Each `z_*` export reads nothing itself:
  it passes its arguments and a `&'static DoorFacts` (the C type's `TypeFacts` of D2, the
  operation's kind, its options' default image) to one of nine non-generic marshals: declare,
  undeclare-or-drop, put-or-delete, get (session, querier, liveliness), reply (reply, error,
  delete), key expression operation, options default, info, handler channel. A shell is a tail
  call (8 to 16 bytes). pico's doors are the same shape by hand
  (`vendor/zenoh-pico/src/api/api.c @ return _z_declare_subscriber(&sub->_val, zs, keyexpr, closure.call, closure.drop, closure.context,`).
- **D9. Options defaults are images.** Each `z_*_options_default` copies a `static` of the options
  struct (one `memcpy` of its size in the options-default marshal), not a body that stores each
  field; about thirty exports become shells.
- **D10. One locator parser.** The doors' `endpoint` (1,150) parses the same locator text as the
  driver's `locator_text` (1,820); the door calls the driver's, which stays (section 5.2 R6).
- **D11. Refusals to codes by table.** Every marshal ends in one `ZResult::from(Refusal)` that is
  a load from a `static [i8; N]` indexed by the refusal's discriminant, in place of a `match` in
  each door.

| component | rows | bound | pico's counterpart |
|---|---|---:|---|
| export shells, about 454 at about 14 bytes | D8, D9, D2's family shells | 6,400 | the bodies of `api.c` that call the net layer |
| nine marshals | D1, D8 | 3,200 | (in each pico door) |
| object pool over `TypeFacts` (move, drop, check, null, take, give back) | D2 | 1,200 | `_Z_OWNED_FUNCTIONS_*` bodies |
| bytes and serialization over one chain | D3 | 4,000 | `serialization.c` 4,886 |
| encodings, one table | D4 | 900 | `encoding.c` 1,386 |
| configuration | D5 | 600 | `zp_config_insert` in `api.c` |
| platform exports, tail calls | D6 | 800 | (in pico's driver area) |
| boundary guard, refusal table | D2, D11 | 300 | none |
| **doors** | | **17,400** | **19,034** |

Margin 1,600, the whole of it: M1 read no size level, so D7 adds nothing (O1 as decided).

### 10.4 Transport: the static step functions, and the form that beats both

**What was measured** (the main session's area diff of 2026-11-25, the build that regenerated the
machines at SCE `b88d18ebdc` against the one before it): `sce_rust_runtime::engine::step_function`
went from 0 to 6,970 B, `sce_rust_runtime::helpers::microstep` from 1,842 to 64, the engine from
4,586 to 4,894. Of the 6,970: `select_transition` 1,720 (unicast link), 1,622 (unicast session),
832 (reassembly slot); `microstep` 1,077, 995 and 439. The shared bodies that went:
`exit_states_from_rows` 656, `enter_states_from_rows` 616, `select_transitions` 544,
`Turn::take_microstep` 390. The transport grew by about 5.5 KB net.

**Why.** ADR 0129 prints, for each atomic state, an arm that asks each state of its chain through
`Steps::enabled`, and `first_enabled` is generic over the machine so that the step function's
guard calls are direct (ADR 0129, decision 2). Every arm is a call site of `first_enabled` and of
each hook with a constant state; with fat LTO at `opt-level = 3` each call site is inlined and
specialised, so the row loop and the hooks' bodies are copied once per arm instead of once per
machine. The consumer's estimate in ADR 0129's context (1,150 to 1,700 B for both machines) counted
the arms, not those copies. Cell M9 below confirms the copies by the ledger's inlined attribution.

**The form proposed: rows walked by one walker per machine, with one call site per hook.** For a
document of the static class (ADR 0129's class, unchanged), the generator writes as data what the
step function writes as code, and one small walker, instantiated per machine, reads it:

- **Selection, fused across the chain.** In the static class the states a selection asks from an
  atomic state are fixed, so the transitions it can take for an event are fixed too, in document
  order: the generator writes `SELECT: [u8; atomic_states x events]`, an index into
  `CANDIDATES: [TransitionId]` (the transitions of the atomic state and its ancestors whose event
  descriptor matches the event, in the order the selection would ask them). The walker reads one
  entry and asks `guard_holds` of each candidate until one holds. One call site of
  `guard_holds`, no walk of the chain, no scan of a state's rows for the event.
- **Microstep, one row.** `STEP: [StepRow]`, indexed by the transition and the atomic state it is
  taken from: the state the exits stop below (the domain's child on the chain), the entry path as
  an offset and length into `ENTRY_PATHS: [u8]` with a default-entry mask, whether the content
  runs, the atomic state the machine is left in and whether that ends the run. The walker runs the
  exits up `PARENT: [u8]` from the atomic state, the content, then the entries, calling
  `execute_exit_actions`, `execute_transition_content` and `execute_entry_actions` from one site
  each.
- **The same hooks and the same main loop.** The walker is a third implementation of ADR 0129's
  `StepFunction` trait over the same `Steps`; the main loop, the queues, the budgets, the error
  chain and the hooks of ADR 0131 are the ones both forms already share. It is generic over the
  policy (direct calls, as the step function's), and every hook has one call site in it, so a
  hook's body is inlined at most once per machine.

**Size.** A walker is about 250 B per machine (selection 60 to 100, microstep 150); the tables are
`atomic_states x events` bytes plus the candidate lists and the step rows: for the session machine
13 x 19 = 247 B and about 150 B more. For the three machines of the client: about 750 B of text and
600 B of `.rodata`, 1,350 B against the step functions' 6,970 and against the interpreter's 2,206 of
shared walks plus its per-machine shells. Graded by text plus rodata (O4).

**Instructions.** Against the interpreter: every hook is a direct call (the interpreter makes 45 of
`Turn::run`'s 48 calls through `dyn` hooks, ADR 0129's context) and nothing is computed from the
document's tree at run time. Against the step function: the selection is one table read and the
candidates in order, where the arm asks each state of the chain and scans that state's rows for
the event, so a selection from an atomic state with ancestors costs fewer instructions; the
microstep reads one row and loops over one to three exits and entries, a few instructions more
than an arm's straight line. The sum for one transition is at most the step function's whenever
the chain asked is longer than one state or the state has more than one transition, which is the
case of every transition of the unicast session and link machines; the reassembly slot machine
(flat, six states) is read by the cell below and, if the walker is over there, the image keeps the
step function for it by ADR 0129's per-document choice.

**The draft ADR, for an SCE session** (the number the SCE ADR index gives it):

- Title: a document of the static class may also be printed as rows walked by one walker per
  machine, each hook called from one site; the image chooses among the three forms.
- Amends ADR 0129 decision 3 (a third form beside the interpreted form and the step function);
  ADR 0118 later chooses among the three by its calibrated model.
- Decision 1: `sce_build::step_function::StepFunction::of` already computes the arms' constants;
  the new printer writes them as `SELECT`, `CANDIDATES`, `STEP`, `ENTRY_PATHS` and `PARENT`
  instead of as `match` arms (one producer, as ADR 0129 requires of its two forms).
- Decision 2: the walker lives in `sce-rust-runtime` (`engine::rows_walker`), generic over the
  policy, and implements `StepFunction`; no runtime feature and no `cfg` chooses it, the build
  line does (`sce-codegen generate --rows-walker`).
- Decision 3: the differential test of ADR 0129 decision 4 runs all three forms over the same
  seeded sequences, observation by observation.
- Acceptance: for the consumer's three machines, text plus rodata of the three forms and the
  per-transition instructions of each, read from the same image; the walker is at most the step
  function's size less 4 KB, and its instructions per transition at most the step function's on
  the unicast session and link machines.

Cell **M9**: the ledger's inlined attribution of `step_function::select_transition` and
`microstep` for the three policies (which callees are copied into them, and how many times), and
the callgrind of one handshake and one fragmented message (the transitions per message of each
machine) on the step function and the walker images.

With the walker, X3's starting point is the interpreter's figure again less about 100 B, and
section 5.1's transport rows stand as written.

### 10.5 The new estimates

| area | wz (2026-11-25) | wz, sh2 (2026-11-26) | pico | before (top of estimates) | reinforced (by construction, no size level) |
|---|---:|---:|---:|---|---|
| sessions | 69,338 | 66,419 | 27,508 | 28,700 (low end) to 27,500 | at most 26,300 |
| doors | 41,138 | 41,399 | 19,034 | 22,600 (low end) to 21,100 with D7's level; 25,100 without it (M1) | at most 17,400 |
| transport | 32,570 (+5,500 since, step functions) | 31,737 | 13,951 | 14,900 (as written, before the step functions) | the step functions' 6,970 to about 1,350 (M9, SCE), then section 5.1 |

Each bound is a row of the size ledger per owner from the landing of its lane on (a ratchet row,
as the ledger already holds per area), so a lane over its bound is red at its own landing.

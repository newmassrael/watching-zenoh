# Faces as rows of one transport: one body for every face, the state as data (peer-rows)

Status: design, 2026-11-27, under the owner's direction (delegated): cost ignored, the structure
that is right for the longest time, textbook, final. Nothing here was built or measured by this
note. Every byte figure is either **read** (named reports, each said where) or an **estimate**
(said so, with its basis); every instruction count is a reading of the code, not a run. It extends
`docs/c-abi-architecture.md` (P2, P3, P10, section 8) and the lanes beside it
(`docs/c-abi-migration/arch-mono.md`, `feat-mcast.md`, `feat-query.md`, `feat-adv.md`,
`heap-native.md`, and `peer-proportion.md` on its branch `peer-prop`), and changes none of them;
section 9 drafts the words the architecture would change.

Readings:

| what | source | how read |
|---|---|---|
| bytes by owner and by body, the three cases | the size ledger's explain reports (`size_ledger_gate.py --explain`, the JSON under a build tree's `crates/target/size-ledger/`) of `pico-client-coop-nostd`, `pico-peer-coop` and `pico-api-coop-nostd`, the run `peer-proportion.md` section 1 reads (its step +124,333 is this run's peer case less its client case) | each case's `owners` and `symbols`, bodies keyed by name with the generic arguments of inner types removed, client against peer against api |
| the case totals | the same run | client 199,515 against zenoh-pico 170,500 (1.170); peer 323,848 against 179,142 (1.808); api 851,677 against 280,287 (3.039); api sessions 298,866 against 55,128, driver 142,872 against 26,087 |
| the steps one feature at a time | the per-feature report of `pico-api-coop-nostd` from an earlier tree of the same day (`--per-feature`), whose peer step read +100,584 where the run above reads +90,861 (scout apart) | each step's `wz_added` and `pico_added` summed over areas; used for proportion, never subtracted from the run above |

**How the cases are judged** (owner, 2026-11-27): the verdict is the whole case, one library
against the other. The per-feature step is a diagnosis, read in the same column: where the same
capability is compiled on both sides. This note gives both for every figure it ends on.

## 1. The question, and the answer in short

The question: with each face not a session object (a type and an instance of its own) but a data
row inside one transport (its sequence numbers, lease, reassembly, declaration table and send
place), and one body of the state machine run over the rows in turn (a client being the table of
one row), does the `peer` step add only the accept and the walk of the rows, as zenoh-pico's does?

The answer, in four parts:

1. **Text does not multiply by the number of faces in wz today.** Rust compiles a generic body
   once per type, not once per value: ten faces are ten rows of data under one body. A face is
   already a row at run time (`DirectFaces`: the dial role's face and a bounded table of the
   others), and its session machine is already a value (an SCE `Engine<P>` placed where it lies).
2. **What the step pays is four kinds of second form, not N copies:**
   (a) the one-face build is compiled from other types (`OneFace`, `OnePeer`, `OneHolder`, the
   region storage, `link_turn`), so the step counts the whole general form against a specialised
   one; (b) each face is *composed* as a session of its own: a set of face tables lent per face, an
   index of which face holds which set, a link session behind shared handles, a reassembly Router
   per face keyed by peer as if it were shared, a plan entry per face; (c) a group is a face of
   another family, with its own telling of declarations, its own publish legs, its own read and its
   own transmit stage beside the unicast faces'; (d) an operation run with every face held is a
   copy per operation (`HeldOperation`), and an encoder counted through a second sink is a copy per
   sink (`write_wire`).
3. **zenoh-pico's client build is its peer transport with one row** (section 3): the peer row type,
   its add, the accepting handshake, the receive that takes a row and the send that walks the rows
   are all in its client build; its `Z_FEATURE_UNICAST_PEER` step adds the accept, the wait over
   the peers' sockets with each peer's stream framing, the walks of the lease and keep-alive tasks
   and the add-peers task: 3,792 bytes.
4. **With faces as rows**, (a) leaves one body whose bound is a build limit, (b) becomes columns of
   shared relations, (c) becomes a kind column of the one face table, and (d) becomes one body with
   the varying part as data. The `peer` step then reaches zenoh-pico's shape, the accept and the
   walk, *in the same column*: about 10 times zenoh-pico's step there (12.6 on today's counting),
   from 24.0 (section 8.1). Part of what leaves the step goes into the client case, where a body
   that served one face serves a table of one row; the whole-case verdict counts that, and the
   client case moves by about -250 bytes net (section 8.2). The face's *state* stays its own: the
   per-link sequence numbers, lease, reassembly, declarations, read slot and send place are the
   protocol's and section 8's contract (section 6), and rows keep each of them.

## 2. What a face is today

### 2.1 What one face holds

| part | where it lies | zenoh-pico's row holds |
|---|---|---|
| the read slot: the pump (receive state, sequence numbers, the link), the records of a step, its Router, the dial under way, the deadlines | `crates/wz-capi-coop/src/engine/direct.rs` @ `pub(super) struct DirectSlot<L: CoopLinks + 'static, C: ClockSource + 'static> {` | the socket, the receive sequence numbers (reliable and best-effort), the stream's flow state and buffer (`vendor/zenoh-pico/include/zenoh-pico/transport/transport.h` @ `_z_zint_t _sn_rx_reliable;`) |
| the send place: the wire, what is owed to it, the facts read without it | `crates/wz-runtime-coop/src/faces.rs` @ `pub struct FaceSite<K: LockKind, P: WireParts> {` | none per row: one batch, one transmit sequence number and one transmit lock for the transport (`vendor/zenoh-pico/include/zenoh-pico/transport/transport.h` @ `_z_zint_t _sn_tx_reliable;`) |
| the face around them: its end, its due, whether it holds a face, rests, is quiet | `crates/wz-capi-coop/src/engine/direct.rs` @ `pub(super) struct DirectFace<L: CoopLinks + 'static, C: ClockSource + 'static> {` | `_pending`, `_received` |
| the session's record of the face: its id, its link, its life (`UnicastLink`), its replay, what its link said when it came up | `crates/wz-capi-coop/src/engine.rs` @ `struct Face<C: ClockSource + 'static, L: CoopLinks + 'static> {` | the remote zid and role in the row's common part |
| the link's session: a kernel (sequence numbers, the receive gate, identity, id spaces, caches) and a link state, each behind a shared handle | `crates/wz-session-core/src/session_actions.rs` @ `pub core: R::Shared<SessionCore<R, T>>,` | fields of the row |
| its session machine | `crates/wz-session-core/src/drive.rs` @ `pub type SessionEngine<R, T> = Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>;` | none: zenoh-pico's handshake is a function, its established transport a state word |
| the reassembly of its fragments | a Router per face, of the session's kind (`crates/wz-capi-coop/src/engine/direct.rs` @ `let router = session_reassembly(policy, SessionChains::over(chains, open));`) | `vendor/zenoh-pico/include/zenoh-pico/transport/transport.h` @ `_z_wbuf_t _dbuf_reliable;` and its best-effort twin |
| what its peer declared | one set of face tables per face among the registry's sets (`crates/wz-capi-coop/src/engine/registry.rs` @ `sets: ManuallyDrop<BoundedVec<FaceTables, MAX_FACE_SETS, RowPolicy>>,`), found through an index lent per face (`crates/wz-capi-coop/src/engine/registry/held.rs` @ `pub(in crate::engine) struct ManyHolders(BoundedVec<FaceId, MAX_FACE_SETS, Lent>);`) | the key aliases in the row (`vendor/zenoh-pico/include/zenoh-pico/transport/transport.h` @ `_z_resource_slist_t *_remote_resources;`); every declaration of every peer in one list of the session with the peer as a field (`vendor/zenoh-pico/include/zenoh-pico/session/session.h` @ `_z_transport_peer_common_t *_peer;`) |

The faces past the dial role's are already rows of one table
(`crates/wz-capi-coop/src/engine/direct.rs` @
`pub(super) type TakenFaces<L, C> = BoundedVec<DirectFace<L, C>, { usize::MAX }, Lent>;`), and
the dial role's is a field beside them (`crates/wz-capi-coop/src/engine/direct.rs` @
`pub(super) struct DirectFaces<L: CoopLinks + 'static, C: ClockSource + 'static> {`). A group is
none of these: the session keeps its groups' read slots apart
(`crates/wz-capi-coop/src/engine.rs` @ `group_pumps: Vec<Option<group::GroupPump<C>>>,`), and a
group's members are rows of the group's own table
(`crates/wz-session-core/src/multicast_dispatch.rs` @ `peers: PeerRows<PeerSlot, MAX_PEERS, Grow>,`),
as zenoh-pico's multicast peers are
(`vendor/zenoh-pico/include/zenoh-pico/transport/transport.h` @ `_z_transport_peer_multicast_slist_t *_peers;`).

### 2.2 What code a face multiplies, and by what

Bytes are the bodies of the run in the readings table above, client / peer / api; a body the case lacks
is 0. A body's bytes and an owner's are different readings (`peer-proportion.md` section 1), so the
rows are not summed across kinds.

| multiplies by | bodies, client / peer / api (read) | what each is |
|---|---|---|
| the number of faces | none | a face is a row of data; every body is compiled once a type |
| **a form for one face beside a form for many** | `link_turn` 4,656 / 0 / 0 against `face_turn` 0 / 4,842 / 6,950; `fragment_in_place` over `OnePeer` 3,146 / 0 / 0 against over `ManyPeers` 0 / 3,967 / 3,581; `announce_on` over `OneFace` 144 / 0 / 0 against over `ManyFaces` 0 / 737 / 768; `read_direct` 352 / 4,160 / 0; `put_on_links` 3,023 / 5,209 / 1,738; `place_link_session` 2,980 / 4,593 / 5,061; `open_links` 983 / 3,091 / 6,228; `drive_link` 1,429 / 2,798 / 14,560; `wait_on_faces` 0 / 1,947 / 0 (the client's is inlined in `link_turn`) | the same work for a table of one face and for a table of many, compiled from other types (`crates/wz-runtime-coop/src/faces.rs` @ `pub struct OneFace<F, D> {` beside `pub struct ManyFaces<F, D> {`; `crates/wz-runtime-coop/src/reassembly_rx.rs` @ `pub type SessionPeers = OnePeer;` beside `pub type SessionPeers = ManyPeers;`), with the walks, the accepts and the forms mixed in one body |
| **a face composed as a session** | `RegistryOf<ManyHolders>::new` 0 / 4,925 / 4,920; `lend_session` 4,290 / 5,968 / 7,885; `assemble` 4,107 / 5,843 / 6,499; `ArenaPlan::lay_out` 0 / 2,284 / 3,050; `lend_set` 0 / 1,286 / 2,244; `DirectFaces::taken_in` 0 / 859 / 926; `FaceTables::give_back` 0 / 547 / 821; `PeerTables::init_in` 0 / 451 / 610 and `keep_rows_in` 0 / 537 / 631; `hold_table` 0 / 523 / 523; `pool_rows` 0 / 616 / 616; `RegistryOf::add_face` 0 / 321 / 1,133; `entity_rows` 0 / 311 / 745; `ArenaPlan::put_entities` 0 / 466 / 749 | each face's set of tables, its index, its link session and its Router lent and assembled on their own; part of it is the storage axis's (the plan and the lend, which the on-use preset removes: `heap-native.md` section 10.2), part the composition's |
| **a family of faces beside the unicast faces** | `Core::join_group` 0 / 0 / 18,325; `TellGroups` `announce_to_groups` 2,229 and `retract_from_groups` 1,715; `publish_to_groups_on` 1,388, `put_plain_groups_leg` 1,169; `read_groups` 3,182, `step_groups` 1,698; `GroupTxStage` `push_deferred` 6,326, `take_front` 4,499 and its smaller bodies; `GroupPump::step` 5,909 | the group's own opening, telling, publishing, reading and transmit stage, beside the unicast faces' (`feat-mcast.md` rows D and E read them at 42,320 and 53,885 bytes by symbol) |
| **an operation** | `HeldOperation as UnderHeldFaces` `run` 0 / 8,750 / 22,902 | each operation run with every face's send place held is a copy of its own (`arch-mono.md` section 2.1: 22 operations, each compiled once, inside its wrapper) |
| **a sink, a crate** | `WireWrite` `write_wire`, 3,535 / 3,535 / 11,663 | each is a message's encoder (the work); the counting copies and the copies compiled in two crates are not (`arch-mono.md` sections 3.2 and 3.3) |

The one-face forms are not a defect of their own: they made the client case what it is (1.170).
The step counts the general form against them because the client build compiles none of it, and
zenoh-pico's client build compiles its general form (section 3).

## 3. zenoh-pico's form

- **One transport a session.** `vendor/zenoh-pico/include/zenoh-pico/net/session.h` @
  `// Zenoh-pico is considering a single transport per session.` The unicast transport holds its
  peers as a list of rows (`vendor/zenoh-pico/include/zenoh-pico/transport/transport.h` @
  `_z_transport_peer_unicast_slist_t *_peers;`) and, for all of them, one batch, one transmit
  sequence number and one recursive lock of the list
  (`vendor/zenoh-pico/include/zenoh-pico/transport/transport.h` @ `_z_mutex_rec_t _mutex_peer;`).
- **The client is the table of one row.** The client's transport adds its one peer with the add
  the accept uses (`vendor/zenoh-pico/src/transport/manager.c` @
  `*_z_link_get_socket(zl), false,`), and the explain report holds `_z_transport_peer_unicast_add`
  (326), `_z_unicast_handshake_listen` (655) and `_z_interest_push_declarations_to_peer` (86) in
  the client case already.
- **The per-message machinery takes a row, in both builds.** The receive hands each message with
  its row (`vendor/zenoh-pico/src/transport/unicast/read.c` @
  `ret = _z_unicast_handle_transport_message(ztu, &t_msg, peer);`); the send walks the rows it is
  given (`vendor/zenoh-pico/src/transport/common/tx.c` @
  `static z_result_t _z_transport_tx_flush_buffer(_z_transport_common_t *ztc, _z_transport_peer_unicast_slist_t *peers) {`),
  and a send to one peer is a list of one, numbered from the transport's one sequence
  (`vendor/zenoh-pico/src/transport/common/tx.c` @ `// Send to a single peer, convert to peer list`).
- **The driving has a client form and a peer form.** The read task branches on the session's role
  (`vendor/zenoh-pico/src/transport/unicast/read.c` @ `if (mode == Z_WHATAMI_CLIENT) {`), and the
  peer's arm is its own body (`vendor/zenoh-pico/src/transport/unicast/read.c` @
  `static z_result_t _zp_unicast_process_peer_event(_z_transport_unicast_t *ztu) {`), waiting on
  every peer's socket (`vendor/zenoh-pico/src/transport/unicast/read.c` @
  `return _z_socket_wait_readable(&iter, Z_CONFIG_SOCKET_TIMEOUT);`); the lease task walks the
  list (`vendor/zenoh-pico/src/transport/unicast/lease.c` @
  `ztu->_peers = _z_transport_peer_unicast_slist_extract_all_filter(ztu->_peers, &dropped_peers,`).
  So zenoh-pico's row and its per-message bodies are one; its loops are two. Its step is those
  loops: the read task +1,197, the accept task 552, the add-peers task and its two helpers 1,132,
  `_z_open` +314, `_z_new_transport` +270, the lease task +247, the keep-alive task +179, the wait
  iterator 124 (the explain reports' peer case less its client case, scout apart).
- **The accept fills a row**, bounded by the build
  (`vendor/zenoh-pico/src/transport/unicast/accept.c` @
  `if (_z_transport_peer_unicast_slist_len(ztu->_peers) >= Z_LISTEN_MAX_CONNECTION_NB) {`;
  `vendor/zenoh-pico/src/transport/unicast/accept.c` @
  `ret = _z_transport_peer_unicast_add(ztu, &param, con_socket, true, &new_peer);`).
- **What a peer declared is one relation with the peer as a column**
  (`vendor/zenoh-pico/include/zenoh-pico/session/session.h` @ `_z_transport_peer_common_t *_peer;`
  in `_z_declare_data_t`), not a table per peer.

## 4. The principle, and where it comes from

**A type parameter stays only where it changes what a body does to the bytes it reads or writes
(a message kind's encoder, a link kind's read). One that says how many, which role, which storage,
which sink counts or which operation is wrapped becomes data: a row count, a role or kind column, a
storage form chosen once a build, a sink reached through a table of functions, a guard. Every face
is a row of one table; one body serves every row; a build of one face is the table of one row.**

The sources it is taken from:

- **Data-oriented design.** Richard Fabian, *Data-Oriented Design* (2018), and Mike Acton,
  "Data-Oriented Design and C++" (CppCon 2014): a table per kind of thing, rows of plain data, one
  transform run over the rows; a thing's presence is its row's presence (existence-based
  processing), not a type or a flag.
- **The relational model.** E. F. Codd, "A Relational Model of Data for Large Shared Data Banks",
  *Communications of the ACM* 13(6), 1970: what a face's peer declared is a row of one relation per
  kind with the face as a column, not a row of a table nested in the face; a face's going is a
  delete by that column.
- **The state machine's instance as data.** Miro Samek, *Practical UML Statecharts in C/C++*, 2nd
  ed. (2008): the state handlers are one code for every instance of a machine, an instance is its
  attributes and its current state handed to that code. The Flyweight of Gamma, Helm, Johnson and
  Vlissides, *Design Patterns* (1994): what is shared (the code, the tables) is held once, what is
  each instance's (the state) beside it. SCE's runtime is built so already: the engine's loop is
  "one copy for every machine" (`vendor/sce/backends/rust/runtime/src/engine.rs` @
  `so the code that drives the queues and keeps the counts`; SCE's ADR 0064 and 0068).
- **The type object.** Robert Nystrom, *Game Programming Patterns* (2014), "Type Object": a kind
  that would be a type becomes data one class reads, so a new kind adds rows, not code.
- **One body against a specialised copy.** Philip Wadler and Stephen Blott, "How to make ad-hoc
  polymorphism less ad hoc" (POPL 1989): the overloaded operation as one body handed a dictionary
  of its type's operations, against a copy specialised per type; Rust's generics specialise, its
  `dyn` hands the dictionary. The rule above chooses per parameter.
- **Sans-I/O endpoints with a connection table** (P2's own references): an endpoint that routes
  input to one of many connection states by a handle, each connection a value stepped by one body;
  a network stack's socket set stepped by one poll. A face row is that connection value.

## 5. The structure

### 5.1 The face table and its row

The transport (L2) holds one table of faces, laid once (P3: the region of the release form, or
taken at the first row under the on-use preset, `heap-native.md` section 9), never moved, bounded by
the session's limit of faces, as `ManyFaces` is made for that limit today. Row 0 is the dial
role's. A client build (no `listen`, no `group`) is the table of one row; its bound is a constant,
so a walk of it is a constant walk and a row's address a constant, as `DirectSlot::at` answers 0
in that build today.

| field of a row | today | note |
|---|---|---|
| id: row index and generation | `FaceId` and the place | P3 and P10: a generation-checked handle, `NonZero` index |
| kind: unicast, group | two families (`DirectFace`, `GroupPump`) | a column, not a type |
| role: dial, accepted | the dial role's field beside the taken table | a column |
| read slot: a lock word, the pump (the link, the receive state, the part of a batch a stream left), the records of the step | `DirectSlot` | per row, section 5.3 |
| send place: a lock word, the batch being written, the transmit sequence numbers per channel | `FaceSite`, the link session's kernel | per row; under `face-send-places` off, the transport's one place instead |
| the session machine's state: configuration, queues, scheduler, datamodel | `SessionEngine` behind the link session's handles | section 5.5 |
| what the handshake fixed: peer zid, role, sequence resolution, batch size, lease, patch, QoS | the kernel behind its handle | plain fields |
| the receive gate: the next sequence number per channel | the kernel | plain fields |
| the lease: the heard mark or last-heard time, the period; the keep-alive's due | the link state, the pump's deadlines | plain fields |
| reassembly: the row's chains in the transport's chain cells | a Router per face | section 7, R1 |
| the life: `UnicastLink`'s state, the dial under way, the replay's cursor | the session's record `Face` and the slot | plain fields |
| the facts read without the slot: input held, due, rests, quiet | `SiteFacts`, `DirectFace`'s atomics | words of the row |
| a group row's part: the group socket, the multicast session machine, the span of its member rows | `GroupPump`, `MulticastDispatcher` | the member rows stay their own table, as zenoh-pico's multicast peers |

### 5.2 The index that picks a row

- A wait that answers: the kept wait set's entry is the row's index (section 8.14.5's kept set,
  one entry a row with a link and one a port).
- A datagram on a shared UDP port: the row whose peer address it came from (the port's book, as
  `udp-listen` keeps it); a group's datagram: the group row, then the member row by source
  (`MulticastDispatcher::find_by_src`).
- An operation: the rows a route names, a set of row indices (a bit mask of the table's bound).
- A declaration of a peer: its face column (section 5.4).
- A handle the program or a pending query keeps: `FaceId`, checked against the row's generation; a
  stale one is refused, never another face's row.

### 5.3 Locks, and section 8 kept

The unit of locking is the row, as it is the face today. Each row keeps its read slot's lock word
and its send place's; the lock order of section 8.4 is unchanged (read slot, send place, the
session, a row's latch); no thread holds two rows' read slots; a change of a row's site (an
accept, a lost link, a new link) is written under the session's lock as the row's debt and paid by
the holder of its slot (section 8.6). A row lies where it was laid, so each face is read where it
lies, under its own lock, and a record is handed to its callback where it is read, with no queue
and no round: section 8 (owner, 2026-11-25) is kept word for word. With `threads` the rows are
read in parallel, one row by one thread at a time; without, the program's read walks them. A lock
is a field; its code is one body a lock form.

zenoh-pico's choice, one lock for the list and one for the transmit, is not taken: it would make a
read of one face wait for a send on another, which section 8.2 and the capability
`face-send-places` rule out for wz's behaviour. Under the zenoh-pico preset, where that capability
is off (`peer-proportion.md` section 4, W6), the send place is the transport's one, as zenoh-pico's;
the read slots stay per row, which costs a word a row and no code.

### 5.4 What a face's peer declared: relations with the face as a column

One table per kind (the peers' subscribers, queryables and tokens, their key aliases, the gets
pending on each face), each row carrying its face's row index; a declaration several faces hold
carries the set of those faces as a bit mask over the face table. The registry's sets of face
tables, the index of which face holds which set (`ManyHolders`, and `OneHolder` for one face) and
the per-face table builders go; a face's end deletes its rows by its column; a client's one face is
the same relation with one face in it. This is zenoh-pico's form
(`vendor/zenoh-pico/include/zenoh-pico/session/session.h` @ `_z_transport_peer_common_t *_peer;`)
with wz's bounds: the relation's rows are bounded by the session's limits, as every table of P3.

A face's walk over what its peer declared (its retraction at its end, its replay) reads one
column; it is kept cheap by a per-face count or a chain of its rows, which is an index of the
relation, not a table of the face.

### 5.5 The session machine as row data, and what SCE is asked

SCE already lets a machine's instance be a row: an `Engine<P>` is a value built where it lies
(`vendor/sce/backends/rust/runtime/src/engine.rs` @
`pub fn new_in_place(slot: &mut core::mem::MaybeUninit<Self>, policy: P) -> &mut Self {`), or
built as a constant for a table laid at compile time
(`vendor/sce/backends/rust/runtime/src/engine.rs` @ `pub const fn new_const(policy: P) -> Self {`),
and its code is one per machine (section 4). What keeps a face a session of its own is not the
machine but its binding: the policy reaches the link's kernel and state through handles it holds
(`crates/wz-session-core/src/session_actions.rs` @ `pub core: R::Shared<SessionCore<R, T>>,`), a
shape made for a link's session that ran as a task of its own and was reached by the session through
a handle (the round's form; `HeldLink`'s two `Wire` types in `crates/wz-capi-coop/src/engine.rs`
say which form holds which). The session slot's form already holds both by value
(`crates/wz-session-core/src/session_actions.rs` @ `pub core: SessionCore<R, T>,`).

The row takes that form for every face: the kernel and the link state are the row's fields, the
machine is built in the row, and the binding reaches the row through a handle that counts nothing
(`PlacedRef`, P3), the row's owner keeping it for the row's life. That needs nothing of SCE.

**SCE request S1 (an improvement, not a precondition):** a host context lent to a turn. The policy
names a context type (`StatePolicy::Context<'c>`, `()` by default) and the engine a
`process_event_in` (with its `step` and `tick` twins) that hands the context to every hook of the
turn (guards, transition content, entry and exit, the scheduled sends) beside the engine's state, as
ADR 0124 lends an event's data until its event is taken
(`vendor/sce/backends/rust/runtime/src/engine.rs` @
`pub fn process_event_with(&mut self, event: P::Event, event_data: P::EventData<'_>) {`) and ADR
0131 hands the state apart from the policy. With it the binding holds no handle at all: the row
lends its link, its sequence numbers and its lease to the turn, and the borrow checker proves no
other turn holds them. It is an SCE change, reviewed by an SCE session, then a pin move
(`docs/c-abi-architecture.md` section 5, step 7).

### 5.6 The read, the operations and the groups over one table

- **The read** is one body over the table (section 8.2 already says "one body: the read of a set
  of faces"): a unicast row is stepped by its pump, a group row by its multicast pump as section
  8.14.3's D10 reads it. There is no `read_groups` beside the faces' read.
- **A publish** is a route to a set of rows and, for each, a write through its send place; the
  row's link kind (a stream, a datagram to a group) is the link enum's arm (the driver lane's
  `docs/win-budget/size.md` section 9), not a second publish path.
- **A declaration, its undeclaration and a new face's replay** are one walk of the table: no
  `TellGroups` beside the faces' telling.
- **An operation that sends to several rows** takes a guard over the set of their send places,
  taken in the table's order (section 8.4's writer of a big-reader lock), and runs in its caller:
  the held set is data, the operation is not wrapped (section 7, R6).

### 5.7 The router's faces

The router's faces (the asynchronous engine's, in no pico case) are already a table by id with an
index per tier (`crates/wz-runtime-tokio/src/router_forward/face_table.rs` @
`all: AssignedKeyMap<FaceId, Arc<RouterFaceState>>,`): the same relation, its rows counted
handles on the heap. The principle reaches it as rows of plain data under one handle each; no case
of this note measures it, and no step here changes it.

### 5.8 What stays a type, and what becomes data

| family | parameter | stays a type? | why |
|---|---|---|---|
| `write_wire` | the message's encoder | yes | each is a message's bytes: the work |
| the counting copy of an encoder | the sink (counting, writing) | no: one encoder over a sink reached through its table of functions (`arch-mono.md` M5) | the parameter does not change the bytes |
| an instance compiled in two crates | the crate | no: compiled in its owner (`arch-mono.md` M4) | a build artefact |
| `HeldOperation` `run` | the operation | no: the operation runs in its caller under a guard (R6) | the wrapper's lines are the hold, which is the same for each |
| `OneFace` / `ManyFaces`, `OneHolder` / `ManyHolders`, `link_turn` / `face_turn` | how many faces | no: one table, its bound a limit (R2, R3) | a count |
| `OnePeer` / `ManyPeers` | whether a Router is shared | no: a row's Router is its own in every direct build (R1) | a fact of the form, chosen once |
| the region / lent / on-use tables | the storage | once a build: the storage axis (`heap-native.md`) | a preset, not a face's |
| the link kinds | what a read reads | yes, as one enum's arms | each reads other bytes |
| a session machine (unicast, multicast) | the machine | yes | each is a protocol |

## 6. What is lost, and whether it is lost

| what | today | with rows | lost? |
|---|---|---|---|
| **isolation** | a face's kernel is a value of its own behind its own handle; no other face's code can name it | rows of one table, reached by a generation-checked index | no behaviour; a stale index becomes a refused lookup rather than a dangling handle, the trade P3 and P10 already make for every table. A wrong index is a defect a test names (section 7) |
| **concurrency** | each face read by one thread, in parallel with the others, with its own read slot and send place | the same lock words, per row | nothing: section 8 is kept (5.3); only zenoh-pico's one transport lock would lose it, and it is not taken |
| **P2** | "the protocol is a pure state machine over bytes and time" | a row's turn is `process(row, input, now) -> effects` | nothing: P2 asks that a face's state be a value its driver steps, which a row is; it never asked that the value be composed per face |
| **the per-link contract** | per-face sequence numbers (transmit and receive), lease, reassembly, declarations, send place | the same, as fields and relation rows | nothing. zenoh-pico's one transmit sequence for every peer is not taken: a message to one face would leave a hole in every other face's sequence; per row it costs two words and no code |
| **the client's one-face bodies** | `link_turn`, `announce_on` over `OneFace`, `OneHolder`'s known index | the general body for a table of one row; what does not fold for a constant bound of 1 is new text in the client | **yes, a few hundred bytes to 1,200** (R2); paid against what R4 takes out of the client's own link session, so the client case moves by about -250 net (section 8.2) |
| **a face's state in one place** | one struct per face to read in a debugger | a row and its rows in the kind relations | a reading cost; the per-face chain of section 5.4 gives the join |
| **the round's forms** | handles a task-run link session needed | none | the round left with section 8 (step 5); its handles are what is left of it |

So the contract "each face a session of its own" holds in what it guarantees (each face's own
protocol state, read where it lies under its own lock) and not in the composition it was written
in; section 9 rewords it so.

## 7. Steps

Each lands on its own, builds alone in every feature combination it touches, changes no behaviour,
and comes with a test that turns red if it is undone. Bytes are estimates with their basis, client /
peer / api; "peer" is the like-for-like case of `peer-proportion.md` (the zenoh-pico preset) unless
said. Receive Ir is the perf matrix's reading of a delivered message (about 3,066 on
`pico-client-coop-nostd`): no step adds work per message, and the client's row is reached by a
constant.

| step | change | client / peer / api, B (estimate) | basis | receive Ir | held by |
|---|---|---|---|---|---|
| R1 | the Router's peers chosen by the fact, as F1 chose the runtime's form: a row's Router holds that row's chains alone in every direct build (`not(wz_round)`), so `SessionPeers` is `OnePeer` there; `ManyPeers` stays the round form's, whose session shares one Router among its links | 0 / -800 to -1,500 / -500 to -1,200 | `fragment_in_place` over `ManyPeers` 3,967 (peer) and 3,581 (api) against over `OnePeer` 3,146, and the peer key's lines inlined elsewhere | none, with the abort of a dropped frame's chain kept a call (section 7.2): the receive body is compiled once a Router type, and only a fragment or a dropped frame runs its Router's arms; a fragment compares no peer key | a constant assertion beside the type that a direct build's `SessionPeers` is not keyed (red if the choice returns to `listen`); the per-row quota held to the row's slots, as the client's form asserts today; the fragment tests over two faces (each face's chains rejoined, neither ending the other's) |
| R2 | one face table: the dial role's face its row 0 (`DirectFaces`'s field and table one table), one `FacePlaces` form bounded by the build's limit, one turn body (`link_turn` and `face_turn`), one `announce_on` | +300 to +1,200 / -500 to -1,500 / -500 to -1,500 | the client's `link_turn` 4,656 against `face_turn` 4,842, `announce_on` 144 against 737, less what folds for a bound of 1; the peer's two initialisations (`taken_in` 859 and the dial's) and the dial-or-table choice at each row access | client: none (the bound is the constant 1, the row's address a constant); peer and api: none | `a_client_reads_its_one_face_through_a_table_of_one_row` (the face table's bound is 1 in a client build, its read turns row 0, `Takes::face_turns` one a read); the cost gate FORBIDS `link_turn` and `OneFace` in every case |
| R3 | what the peers declared as relations with the face as a column, the holders a bit mask over the face table; the registry's sets, `ManyHolders`, `OneHolder`, the per-face table builders and the give-back go | -500 to +500 / -3,000 to -6,000 / -5,000 to -10,000 | `RegistryOf<ManyHolders>::new` 4,925, `add_face` 321 (api 1,133), `give_back` 547 (821), `PeerTables::init_in` and `keep_rows_in` 988 (1,241), `hold_table` 523, `entity_rows` 311 (745), `declares` 507 (1,362); counted beyond the share the on-use preset takes (`peer-proportion.md` section 4), not with it | none: a received sample is matched against the session's own subscribers, not the faces'; a put's filter reads one relation by key where it read a table per face | `a_face_that_goes_takes_its_rows_and_only_its_rows_from_every_relation` (red if a row of its own stays or another face's goes); `the_holders_of_a_declaration_are_the_faces_that_declared_it` |
| R4 | the link's session as the row's fields: kernel and link state by value (the session slot's shape) for every face, the machine built in the row, the binding reaching the row through a `PlacedRef`; `place_link_session` and `start_wire` one constructor in place | -500 to -1,500 / -1,500 to -3,500 / -2,000 to -4,000 | `place_link_session` 2,980 / 4,593 / 5,061, the handles' counts and drops, the per-face share of `lend_session` (4,290 / 5,968 / 7,885) | none, or fewer: a record's sequence number and gate are read through a field rather than through a handle | the handshake, lease and close tests over several faces (`crates/wz-capi-coop/src/tests/listen.rs`); the cost gate FORBIDS the kernel handle's drop in the pico cases |
| R5 | a group a row of the face table, kind `group`: one walk for telling, retracting, publishing and reading; `join_group` and `seat_group` the row's constructor; the group's send through the row's send place. It is the frame `feat-mcast.md`'s F3 to F7 land in, and is counted beyond them | 0 / 0 / -4,000 to -8,000 beyond `feat-mcast.md` | `TellGroups` 3,944, `publish_to_groups_on` and `put_plain_groups_leg` 2,557, `read_groups`, `step_groups` and `step_group` (`feat-mcast.md` row D), each a second path beside the faces' | none: a group's datagram is read by the row's pump as D10 reads it | `a_declaration_reaches_faces_and_groups_by_one_walk` (one walk counted); `a_put_reaches_a_face_and_a_group_in_one_pass`; section 8.10's "a group's member is read and delivered with no unicast face open" |
| R6 | the held set as data (`peer-proportion.md`'s F2 read this way): a guard over a bit mask of rows' send places taken in table order, the operation in its caller; `HeldOperation`, its per-operation `run` and the held chain go; `feat-mcast.md`'s F6 is inside it | 0 / 0 (W6 off; -2,100 to -2,900 in the release form) / -4,500 to -6,000 | `peer-proportion.md` section 5, F2 | none: an operation is a declaration, a query or a reply, never the read | `direct::held_operation_tests` rewritten over the guard; the engine's declaration tests over faces; the cost gate FORBIDS `HeldOperation` |
| R7 | sinks and crates as data: `arch-mono.md`'s M3 to M5 (a counted message counted by the encoder that writes it, an instance compiled in its owner, the wait of an undeclaration over one enum of rows) | 0 / 0 to -500 / -5,000 to -9,000 | `arch-mono.md` section 5, read on `pico-default`; the api twin's 11,663 bytes of `write_wire` to be read by body before it is promised | none on the read or the put | `arch-mono.md` section 5's tests |
| R8 | the walks of rows for the driving: the read of many rows (`peer-proportion.md`'s F5, section 8.14's Q5) and the lease and keep-alive dues read by one walk, as zenoh-pico's tasks walk their list | counted in `peer-proportion.md` F5 | | as Q5 | section 8.14.7's tests |

Order: R1a, the abort of a dropped frame's chain kept a call, then R1 (section 7.1: R1a makes the
premise R1 rests on true in every build; section 7.2: the call keeps R1's change out of the body
every message runs); R2 and R4 next, as R3 and R5 write into the table they make; R6 with
`peer-proportion.md`'s F2; R5 after `feat-mcast.md`'s F4, which makes the group face R5 puts in
the table; S1 whenever SCE lands it, after R4.

### 7.1 R1's premises, read in the code, and the step before it

**Each face's Router holds that face's chains alone: true of the Routers, not of where they were
lent.** The Routers are the faces' own values: the dial role's is lent apart from the session's
state (`crates/wz-capi-coop/src/engine.rs` @ `struct LentApart {`) and each face
past it is made with one of its own (`crates/wz-capi-coop/src/engine/direct.rs` @
`let router: SessionReassembly =`). The place a pump looked for its Router in was not the face's:
every face was handed the session's one cell (`StepPlaces::router`), the dial role's through the
transport's lend and the others through `DirectFaces::taken_in`, and every pump was handed the
transport's (`TransportState::place_link` lent `self.lend`). Without `threads` one read steps one
pump at a time, so each pump found its own face's Router. With `threads` and a lock for each value
(the direct form of the host's default build with `listen`), the read task's lone read of a quiet
face (`CoopEngine::read_quiet`) and a program's read (`CoopEngine::read_faces`, which takes each
face's slot by a try) step two faces' pumps at once: two `lend_for`s on one `Cell` from two
threads, a data race, and a pump that may take the other face's Router and stage its fragments
among that face's chains. Keyed by peer, those chains did not splice; keyed by channel, as R1 keys
them, they would. R1 as drafted was so unsound in that build, and the step before it, **R1a**, makes
the premise true by construction: each face lends its Router in a cell of its own, a field of the
face (`crates/wz-capi-coop/src/engine/direct.rs` @ `router_cell: RouterCell,`), and each pump
is handed the cell of its face (`crates/wz-runtime-coop/src/transport/state.rs` @
`pub lend: RouterLend<RouterOf<T>, T::RouterPlace>,`, the field of `PumpPlace`). The cell is
reached only with its face's read slot held, which is what its `Sync` rests on; the handle that
counts nothing on a field kept in place is `PlacedRef::of_place`
(`crates/wz-session-core/src/placed.rs`).

**Under `OldestWins`, a row's quota is at most its slots: true, and now asserted for every
build.** Each Router has `SESSION_REASSEMBLY_SLOTS` slots, which is `LENT_CHAINS`, which is the
pool's `PER_PEER_QUOTA`; its quota is that same constant (`mcu_reassembly_config`), and nothing
else writes the quota of these Routers. A start is refused on the quota before a free slot is
looked for (`crates/wz-session-core/src/reassembly_dispatch.rs` @
`// §5.M quota-first: the per-peer cap is checked before slot`), so a pool full of one peer's
chains refuses on the quota and `make_room`, the one place a policy ends a chain for another, is
never asked: `OnePeer` and `ManyPeers` answer one peer's fragments alike under every policy. The
assertion was the client's alone (`not(listen)`); it holds for every Router a session builds now
(`crates/wz-runtime-coop/src/reassembly_rx.rs` @
`assert!(crate::reassembly_pool_mcu::PER_PEER_QUOTA as usize <= SESSION_REASSEMBLY_SLOTS);`).

**A lost link's chains.** The direct read ends them by the lost peer's zid
(`crates/wz-capi-coop/src/engine/direct.rs` @ `let _ended = slot.router.abort_peer(zid.as_slice());`):
under `ManyPeers` the chains of that zid, under `OnePeer` every chain of the face's Router. A face's
Router serves one link at a time, so they are the same chains whenever the face's record names its
peer, which it does from the link's bring-up on; a loss with no peer named ends no chain under
either, as the client's direct build already does.

**The choice** (`crates/wz-capi-coop/src/engine.rs` @ `type RouterPeers = OnePeer;`): chains are
keyed by peer exactly where several faces' links share one Router, the round form of a listening
build (`all(wz_round, feature = "listen")`); the round form without `listen` keeps `OnePeer` as it
did, and a group's chains lie in the group's own Router, never in these. The runtime no longer
chooses (`SessionPeers` by `listen` is gone): its Router is generic in its peers
(`SessionReassembly<P>`), and the engine, which composes the links with their Routers, names the
peers through `TransportFaces::Peers`. A direct build whose Router is keyed fails to compile
(`crates/wz-capi-coop/src/engine.rs` @ `const _: () = assert!(!<RouterPeers as ChainPeers>::KEYED);`).

**Receive Ir.** R1a changes which cell a handle names, not the instructions that use it
(`StepLend::lend_for` and `StepLend::with` load the handle from the slot and from the pump as
before, and neither cell's address was a constant the compiler could fold before or is now). The
peer and api cases' fragments no longer copy or compare a peer key (`PeerKey::new`,
`PeerKey::is`). A message that is not fragmented runs none of its Router's arms, but it does not
pass the Router by: every datagram is dispatched with the Router taken out of its lend, by a body
compiled for the Router's type, so a change of the Router's peers is a change of the body every
message runs. Section 7.2 reads what that did to R1 and the step that keeps it out of the body.

**Memory.** Each face grows by one cell, a pointer (8 B on a 64-bit host, 4 B on a 32-bit MCU). The
session's cell (`StepPlaces::router`) is lent in by the round's tasks alone now; the direct form
still places it and the transport still holds its handle, unused. That residue goes with the round's
lend (R4, or the round's end).

**Tests.** `tests::face_routers` is compiled in every build of the direct form that listens
(`all(not(wz_round), feature = "listen")`):
`a_faces_router_is_lent_where_its_own_pump_alone_looks` lends each row's Router and counts the other
rows whose place finds one lent (red with one place for every face, as before R1a), and
`each_faces_router_keys_its_chains_by_channel_and_ends_them_alone` continues a face's chain with a
fragment naming another peer, keeps the same channel's chain of another face apart, and ends every
chain of one face by a peer key none of them named (red with `ManyPeers` in that build). In
`wz-runtime-coop`, `the_links_of_a_session_share_one_router_keyed_by_peer` and
`the_router_of_one_link_keys_its_chains_by_channel` now name their Router's peers and are compiled
in every build with `alloc` and `session-unicast`, not one of them a build; `wz-session-core`'s
`a_handle_of_a_value_held_in_place_reads_it_where_it_lies` holds `PlacedRef::of_place`.

### 7.2 R1's receive instructions: what moved them, and the step that keeps them

**Read** (the main session's runs of 2026-11-27, `scripts/pico-compare.sh subprofile 8 12000 10000`,
its W arm: the shipped direct form, with `threads`, `listen` and `group`): instructions a received
message, main 3017.3, 3021.1 and 3020.9; R1a alone 3020.4 and 3020.7; R1 on R1a 3025.9 and 3025.3.
No step adds receive instructions (owner), and R1 added about six (5.8 on the means).

**Where.** The same runs' callgrind tables, each function's own instructions, the window of 12,000
messages less the window of 2,000, over the 10,000 between (main's three runs, R1's two): every
function reads the same to within 0.25 a message but one, the receive of a datagram
(`crates/wz-session-core/src/unicast_rx.rs` @
`pub fn dispatch_datagram<R: SessionRuntime, T: TimeSource, F: EventSink + ?Sized>(`), at 198.0 in
each of main's runs and 204.0 in each of R1's. The six are no piece of work. By source line they
are spread over the frame path (in `frame_in_place`, the frame head's fields, its gates and the
call of `admit_head_in_place`, +5 and -1; the walk of a datagram's units and the read of a unit's
head, +1 each; the function's entry, -1), over the library's helpers inlined in it (`Option`,
slices, integers, `mem`: +3 and -1 by line) and over the instructions the compiler gives no source
line (+5 under `option.rs`, -5 under `drive.rs`, -3 under `result.rs`, +1 under two others):
moves, spills and jumps, the same work allocated another way. `step_pump` and the rest of the read
read the same.

**Why.** Every datagram is dispatched with the Router taken out of its lend for the length of the
dispatch (`crates/wz-session-core/src/unicast_rx.rs` @
`router.dispatch_in_place(unit, actions, engine, reader, now_ms, on_event)`), and the dispatch
(`dispatch_datagram_reassembling` and what it inlines) is compiled into that one receive body once
for each Router type. Its frame path is the same source whatever the Router's peers but for one
arm: a `Frame` the SN gate drops ends its channel's chain (`abort_rejected_channel`), which over
`ManyPeers` reads the peer's zid from the facts and compares keys, and over `OnePeer` does
neither. The shipped libraries of the two runs (`nm -S`, `objdump -d`) show what the compiler made
of each. Main's receive body is 1,989 bytes, 437 instructions, and calls
`abort_rejected_channel`, a symbol of its own (303 bytes). R1's is 2,104 bytes, 462 instructions;
it has no `abort_rejected_channel` symbol and calls `Slot::end` from inside the body. The
`OnePeer` arm was small enough to be inlined, and with it in the body the frame path around it,
which every message takes and which is the same source in both, came out with other registers and
another block order (the call of the cold `fragment_in_place` moved from the body's end to its
middle). That `RouterOf` and `TransportFaces::Peers` changed the pump's code is not borne out:
they name the same concrete type, and `step_pump` reads the same. The client case (no `listen`,
`OnePeer` before R1 as after) has carried the inlined arm all along: its explain report
(`size_ledger_gate.py --explain`) holds no `abort_rejected_channel` symbol.

**The step** (`crates/wz-session-core/src/drive.rs` @
`fn abort_rejected_channel<R, T, const SLOTS: usize, const CAP: usize, S, P>(`): the arm is
`#[inline(never)]`, as `fragment_in_place`, the other arm of the dispatch whose body follows the
Router's peers, already is. The receive body then holds a call where each Router's arm lies, and
nothing in it varies with the Router's peers but the callee, so R1's change of them does not reach
it. The step lands before R1, on its own, and changes no behaviour. It is not `#[cold]` as well:
over `ManyPeers` the compiler already kept the arm a call, so `#[inline(never)]` alone leaves main's
W body as it is built today, where `#[cold]` would move its block order too, a change to measure on
its own.

**What the main session reads** (predictions, not readings):

- the W arm at the step alone: main's figure, the body being a call there already; at R1 on the
  step: main's figure, the receive body 198 a message as main's;
- the client case's receive arm (the perf matrix on `pico-client-coop-nostd`): its body now calls
  the arm it held inline, the same or fewer, read before R1 is judged;
- the bytes: the W build's receive body back to about main's 1,989 from R1's 2,104, beside an
  `abort_rejected_channel` over `OnePeer` of its own (about 100 to 200); about even in every case
  whose Router is `OnePeer`, read in the explain reports.

### 7.3 Why R2 and R4 wait for R1 to be built

Both are wider than one crate's feature matrix can be written for without a compiler in the loop,
and each holds a decision the code does not settle yet.

- **R2's table of one row.** `ManyFaces` keeps its places in a `Vec`
  (`crates/wz-runtime-coop/src/faces.rs` @ `faces: Vec<TablePlace<F, D>>,`) and the client's
  `OneFace` holds its face inline; one form bounded by the build is a new table, inline in the
  engine's place for a bound of 1 and lent from the region or arena past it. Inline is what the
  fold asks: with the bound a constant 1, a walk `for row in 0..N` is one turn and a row's index a
  constant, but a row's address is a constant offset from the engine only if the table lies in the
  engine's place, as `DirectFaces::dial` does now; a lent table adds a load of its base to every
  reach of row 0, which the client's receive Ir would count.
- **R2's one read body.** `read_dial` takes the one slot once and holds it across the wait;
  `read_faces` takes every slot by a try to see that none is held, lets them go, waits, and takes
  each again to turn it. With one row the second does not fold into the first: it is two takes of
  the slot a read where the client makes one, more instructions on every read. One body that keeps
  the client's count holds the slots it turns across the wait, which for several rows changes what
  a read on another thread finds (`CoopEngine::held_elsewhere`, the quiet read): a decision about
  section 8's reads, not a fold.
- **R2's plan.** The dial role's face lies in the engine's place and the plan lays rows for the
  faces past it alone (`ArenaPlan::lay_direct_faces`; `tests::arena`'s
  `each_face_read_where_it_lies_is_lent_a_share_of_chain_buffers_of_its_own` asserts it); row 0 in
  the table moves a region's layout and the cost gate's lists (`link_turn`, `OneFace`).
- **R4** puts the kernel and the link state in the row by value, where the binding reaches them by
  shared handles today (`crates/wz-session-core/src/session_actions.rs` @
  `pub core: R::Shared<SessionCore<R, T>>,`), held besides by the place's halves
  (`TransportState::place_halves`), the gates, and `resource-snapshot`'s count of the face
  (`crates/wz-capi-coop/src/engine/direct.rs` @ `let count = KernelCount(CellRc::clone(&wire.actions.core));`):
  three crates and every feature that reaches a kernel.

## 8. Where the cases end

### 8.1 The step, read two ways (diagnosis)

The `peer` step, scout apart, on the zenoh-pico preset's form, at the mid of each range:

| reading | wz step, B | zenoh-pico step, B | times |
|---|---:|---:|---:|
| today | 90,861 | 3,792 | 24.0 |
| after `peer-proportion.md`'s steps | 56,811 | 3,792 | 15.0 |
| after R1 to R4 (step -8,900: R1 1,150, R2 1,750 with the client's growth, R3 4,500, R4 1,500 net of the client's own) | 47,911 | 3,792 | **12.6** (11.6 to 13.6) |
| the same column: the accepting handshake and its codecs read in both client cases, as zenoh-pico's client compiles them (about 10,000, `peer-proportion.md` section 6) | 37,911 | 3,792 | **10.0** (9.0 to 11.0) |

### 8.2 The cases, whole (the verdict)

| case | wz today | zenoh-pico | ratio today | steps counted | wz after, mid | ratio after |
|---|---:|---:|---:|---|---:|---:|
| `pico-client-coop-nostd` | 199,515 | 170,500 | 1.170 | R2 +750, R4 -1,000 | 199,265 | **1.169** (1.160 to 1.177) |
| `pico-peer-coop`, zenoh-pico preset | 323,848 | 179,142 | 1.808 | `peer-proportion.md`'s steps -34,050; R1 to R4 -9,150 | 280,648 | **1.567** (1.512 to 1.622) |
| `pico-peer-coop`, release behaviours on (W1, W2, W6 on, the plan kept) | 323,848 | 179,142 | 1.808 | F1, F4, F5 -6,150; R1 to R4 -9,150 | 308,548 | **1.722** |
| `pico-api-coop-nostd` | 851,677 | 280,287 | 3.039 | `peer-proportion.md`'s F3, F4, F6 and R6 -14,750; `feat-mcast.md`'s F2b, F3, F4, F5, F7, F8b -50,250; R1 to R5 and R7 -25,350 | 761,327 | **2.716** (2.620 to 2.812) |

The client's figure is the one a structural step must not worsen: R2 adds the general turn to it
and R4 takes the handles out of its own link session; the receive Ir arm on that case is the check
that the table of one row costs nothing a message.

### 8.3 What is left, item by item

Peer step in the same column after every step, about 37,900 against 3,792:

| item | about, B | kind |
|---|---:|---|
| the accept and the walks (the read of several rows, the wait on their links and the port, the lease and keep-alive walks, the add of a row) | 6,000 to 10,000 | **contract**: zenoh-pico's whole step is this work (3,792); the excess is the read of several rows' form, which R8 and `peer-proportion.md`'s F5 measure first |
| the listener and the links | about 9,000 | **contract** in a larger **form**: the same accept and socket work, the link layer's form lane T-LINK's (`docs/win-budget/size.md` section 9) |
| what a new face is told | about 4,100 | **contract**: the declarations pushed to a new peer and the `DeclareFinal`; zenoh-pico's body is in its client build (`_z_interest_push_declarations_to_peer`, 86 there), so in the same column it is half counting |
| the one-face-per-node rule (`LinkSupervisor::read_node` 1,632: the dial role standing by while another face holds its node) | 1,500 to 2,000 | **behaviour** of wz's (zenoh-pico keeps each link a peer of its own); goes with `link-admission` off if the owner rules it part of W2, to be read |
| the engine's other lines and the language lines inlined in the bodies above | 8,000 to 12,000 | **form**, falling with the bodies they are inlined in; read again after each step |
| the scout (not in the 37,900; its own step, 33,472 against 4,850) | | **form** in the most part (`scout::window_hellos` 14,427, the text forms, the interface table), with the interface enumeration as **behaviour**; its own lane |

Client case, 199,265 against 170,500: **form**, the layers of `docs/c-abi-architecture.md` section
1 (sessions +33.6 K, doors +20.4 K, transport +12.4 K, driver +10.4 K, against codec -7.3 K, key
expressions -5.5 K and language -35.0 K), the lanes `base-sessions.md`, `base-doors.md`,
`base-transport.md` and `base-driver.md`; no contract beyond zenoh-pico's is known in it.

API twin, about 481,000 over zenoh-pico after the steps counted, by the per-feature steps of the
earlier tree (read there, so proportion only):

| step | wz / zenoh-pico, B | kind, and whose |
|---|---|---|
| `query`, `queryable`, `liveliness`, `liveliness-get` | 194,104 / 27,640 | `feat-query.md` pairs each with zenoh-pico's and parts **contract** (its section 4, each item a switch) from **form**; not counted here |
| `advanced` | 121,520 / 33,748 | `feat-adv.md`: its rows F1 to F11 **form**, the rest **contract** of the advanced planes; its landed steps are in the run above |
| `connectivity` | 60,260 / 17,378 | not read by a lane this note read |
| `multicast-transport` after `feat-mcast.md` and R5 | about 70,000 to 113,000 / 11,244 (the step's 164,568 of the earlier tree, less `feat-mcast.md`'s steps, landed and not, and R5) | `feat-mcast.md` section 4's D1 to D4 **behaviour** (19,000 to 27,500, the owner's switches), the rest "not yet placed" there |
| `multi-thread` | 26,613 / 11,135 | the lock per value of section 8.3 is **contract** with `threads` (each row's lock words, data); the host lock's form (`wz_host_sync`) to read |
| `scout` | 54,024 / 4,850 | as the peer case's scout |
| the client base of that chain | 209,392 / 170,500 | as the client case |

## 9. The contract, reworded

Drafts for `docs/c-abi-architecture.md`, to land in their own commit once the owner accepts them.

**A new principle, after P12:**

> P13. **A face is a row; kinds are data.** The transport holds one table of faces, each a row of
> plain data (its link, its read slot and send place, its session machine's state, its sequence
> numbers, its lease, its reassembly, its life and the replay's cursor) addressed by a
> generation-checked handle; what each face's peer declared is a row of one relation per kind with
> the face as a column. One body serves every row; a build of one face is the table of one row,
> its bound a build limit and not a type. A type parameter stays where it changes what a body does
> to the bytes it reads or writes (a message kind's encoder, a link kind's read); one that says how
> many, which role, which storage, which sink counts or which operation runs is data. (Fabian,
> *Data-Oriented Design*; Codd 1970; Samek, *Practical UML Statecharts in C/C++*.)

**Section 3, the L2 bullet, its last sentence** ("It owns the link records (one pool), the tx
batch slots and the reassembly chains.") becomes:

> It owns the face table (a row a face, unicast or group: its link, its read slot and send place,
> its sequence numbers, its lease, its chains in the transport's chain cells, its session machine's
> state) and the tx batch slots.

**Section 8.3, the paragraph that begins "A face is two places"** begins instead:

> A face is a row of the face table (P13); of its fields, two are places: its **read slot** ...

and the rest of the paragraph stands.

**`peer-proportion.md`** (on its branch), the last paragraph of section 3 ("Each wz face is a link
session of its own ... That is the architecture's contract, not a form") becomes:

> Each wz face keeps its own protocol state, read where it lies (`docs/c-abi-architecture.md`
> section 8): its machine's state, lease, sequence numbers, reassembly, read slot and send place,
> and the rows of its peer's declarations. That is the contract. How that state is composed (a
> session assembled per face from lent sets behind shared handles) is a form, which
> `docs/c-abi-migration/peer-rows.md` takes to rows (P13).

and its section 6 bullet "Each face a session of its own, about 22,000" is read as section 8.3 of
this note reads it: the contract part (the accept and the walks, what a new face is told) and the
form part (R1 to R4, R8).

## 10. Rejected alternatives

- **zenoh-pico's one lock for the list and one for the transmit.** A read of one face would wait
  for a send on another; section 8.2 and `face-send-places` rule it out for wz's behaviour. Under
  the zenoh-pico preset the send place is already the transport's one; the read slots stay per row.
- **One transmit sequence for every row.** A message to one face would leave a hole in every
  other face's sequence; per row it is two words.
- **The client compiled with a walk it does not need, to shrink the step.** It moves bytes from
  the step into the client case and removes none; the verdict is the case.
- **One enum over every operation, matched in one `run`** (`arch-mono.md` section 2.1 rejects it).
  The operations need no wrapper at all: they run in their callers under a guard (R6).
- **A read task per row**, blocked in its own receive (section 8.14.8).
- **The router's form for the cooperative engine**: rows as counted handles on the heap, against
  P3; the router keeps it for its own reasons (section 5.7).
- **A fast path for a session of one face** (section 8.12): the table of one row is the same body,
  not a second path.

## 11. Verification (the main session's)

This note changes no code. For each step, when it lands:

- the explain reports of the three cases before and after (`size_ledger_gate.py --explain`), the
  bodies of section 2.2 and of the step's basis read by name;
- Layer C1cs: each case against its row, the client case unchanged beyond its step's figure;
- the perf matrix's receive arm on `pico-client-coop-nostd`: its receive Ir as its last reading
  (W/P about 0.76);
- the step's tests named in section 7, in every feature combination that compiles them (with
  `listen`, with `group`, with neither, with `threads` and without);
- `size_ledger_gate.py --per-feature pico-api-coop-nostd pico-peer-coop` again after R2 and R5, so
  sections 8.1 and 8.3 are read from one tree rather than two.

# Feature lane feat-mcast: what `multicast-transport` costs, beside zenoh-pico

Status: the reading of the feature, the pairing of its work with zenoh-pico's, the steps that take
out what is shape, and the owner's decision items for what is work; step F1 landed beside this note,
and steps F2a and F8a and the decisions of section 4.1 land after it. Step F4 landed on 2026-11-28
(section 7), which takes the gate layer of F3 with it; what F2b, F3, F5 to F8b stand on in the code
of that day is section 7.2. Steps F3, F5's Router, F6 and F9 landed after it on the same day, and
the share section 2.1 left unplaced is placed in section 8. Steps F4, F5 and F7 (the
group's shell and its transmit pipeline) and the decision item D2 they keep are the transmit lane's;
F3 follows F4, as the one sink it leaves is read by the group face F4 makes (section 3.1 reads why
from the code). D2 is not taken with them: the first step of F7 (`mcast-tx1.md` T3) does not hold
against the code as designed (`mcast-tx1.md` section 7).
Nothing here was built or measured by this lane: every byte figure is **read** from the libraries
the size ledger's `--per-feature` run kept (section 1), or is an **estimate** from the code, and
says which. It extends `docs/c-abi-architecture.md` and the lanes beside it
(`docs/c-abi-migration/arch-mono.md`, `arch-engine-own.md`, `arch-l0-driver.md`) and changes
none of them.

## 1. The reading

The per-feature report of 2026-11-27 (`size_ledger_gate.py --per-feature`, branch
`size-per-feature`; zenoh-pico pin `6a881c21dad1`, GNU ld), the step `multicast-transport` of the
chain of `pico-api-coop-nostd` from `pico-client-coop-nostd`: the features before it are
`os-host,link-udp,scout,peer`, and zenoh-pico's switches are `Z_FEATURE_LINK_UDP_MULTICAST` and
`Z_FEATURE_MULTICAST_TRANSPORT` from 0 to 1. `pico-peer-coop` (`os-host,link-udp,peer`) has no
such step, so the api twin is the case that carries the feature.

| area | wz adds | zenoh-pico adds | excess |
|---|---:|---:|---:|
| sessions | 46,853 | 264 | 46,589 |
| doors | 3,954 | 0 | 3,954 |
| transport | 23,533 | 5,930 | 17,603 |
| driver | 40,811 | 4,637 | 36,174 |
| keyexpr | 17 | -7 | 24 |
| codec | 31,117 | 24 | 31,093 |
| language | 18,141 | 396 | 17,745 |
| (unclassified) | 142 | 0 | 142 |
| **total** | **164,568** | **11,244** | **153,324** |

The report holds areas, not bodies. The bodies are read here from the two libraries the step
built, which the run kept under the cost gate's target directory
(`shipped/pico-client-coop-nostd+peer/`, which turns `scout` on and so is the step's base, and
`shipped/pico-client-coop-nostd+scout+peer+multicast-transport/`), and the two zenoh-pico
references beside them (`pico-reference/<key>/shipped/`): `nm --defined-only -S -C`, the text
symbols, the names of one address one body at its largest size, and the two readings diffed by
name with every generic argument list removed. The two differences are the report's totals to the
byte, 164,568 and 11,244, so nothing below is unaccounted. It is the **symbol** reading: a function
inlined into another is counted in the body it was inlined into, so a row is "the bodies whose
names are of this work", and the rows are not split by area. The line reading of the same build is
`--explain pico-api-coop-nostd` once `size-per-feature` lands (section 6).

## 2. The same work, side by side

zenoh-pico's 11,244 bytes are its multicast transport and its UDP group link: the receive and its
dispatch (`vendor/zenoh-pico/src/transport/multicast/rx.c` @
`z_result_t _z_multicast_handle_transport_message(`), the JOIN, keep-alive and lease tasks
(`vendor/zenoh-pico/src/transport/multicast/lease.c` @ `_zp_multicast_lease_task_fn`), the
transport's open and close (`vendor/zenoh-pico/src/transport/multicast/transport.c` @
`_z_multicast_transport_create`) and the two sockets of a group
(`vendor/zenoh-pico/src/link/transport/udp/udp_multicast_posix.c` @ `z_result_t _z_listen_udp_multicast(`).
It writes nothing to send: a group is sent to by the one transmit path every transport has
(`vendor/zenoh-pico/src/transport/common/tx.c` @ `_z_transport_tx_send_n_msg_inner`), and its JOIN,
Frame and Fragment codecs are the unicast build's, linked either way (codec +24).

| row | the work | zenoh-pico | wz | excess | where the difference is |
|---|---|---:|---:|---:|---|
| A | the group's link: two sockets, membership, the locator's keys | 4,239: `_z_listen_udp_multicast` 1,454, `_z_open_udp_multicast` 575, `_z_read_udp_multicast` 353, `_z_new_link_udp_multicast` 337, `__get_ip_from_iface` 310, `_z_close_udp_multicast` 288, `_z_endpoint_udp_multicast_valid` 172, the link's function table 512 | 11,638: `wz_runtime_posix::multicast::bind_joined` 2,636 and `bind_sender` 2,012, `HostGroupReceive` 2,242, `HostGroupTransport` 941, `Plan::pin_link_egress`, `pin_egress`, `loop_back` 992 against `Plan::fill_unspecified` 455 less, `locator_grammar::parse_dscp_value` 1,352, `SocketAddr::from_str` 648 out of line against 481 less in `scouting_host::parse_multicast_locator`, which inlined it while it had one caller, `str` searches, an interface named by its address and an address compare 1,140, socket options 205, the interface table's egress addresses 406 | 7,399 | **work**: keys zenoh-pico does not read (D1, about 3,000 to 4,000 of it); the rest is the same two sockets in larger bodies, to read by line before it is called shape |
| B1 | stepping past a transport message the group does not act on | 0: its decoder is the unicast one | 8,434: the owned transport decoder (`inbound::parse_unit` 905, `parse_unit_into` 3,486, `parse_init` 911, `parse_open` 754, `parse_close` 319, `decode_keep_alive` 273, `decode_oam` 596, the Init and Open views 663, `ext_chain::collect_walk` and `keep_handshake_entry` 527), linked by the group's walk alone | 8,434 | **shape, overlapping layer**: the walk asks the owned decoder only how long an Init or an Open is, where the session's in-place reader of a control message gives the same extent and refusals (step F1) |
| B2 | the receive: a datagram walked, a frame admitted, a chain reassembled, records delivered | 3,466: `_z_multicast_handle_transport_message` 975, `_z_multicast_handle_fragment_inner` 843, `_z_multicast_handle_frame` 369, the read task and the buffer 1,279 | 25,768: `MulticastPump::step_reading::{closure#4}` 13,212, `MemberRecords as EventSink` 7,146, `MulticastDispatcher::find_by_src` 1,652, `CoopEngine::hand_lent_push` 1,842 against `DirectSink::event` 2,095 less, the Close, KeepAlive, OAM and JOIN views 1,393 against `drive::read_control_in_place` 953 less, `walk_lent_payload` 807, the reassembly 607, `JoinIn::read_into` 531, `GatedEvents` 402, `MemberDeclarations::retracted` 385, the rest 839 | 22,302 | **shape, overlapping layers**: a record reaches the engine through three sinks (the pump's gate, the dispatcher's member scope, the engine's direct sink) where a link's reaches it through one, and the engine's delivery is inlined into the member scope's (F3); **work**: what the member scope records of each member's declarations (D3) |
| C | the JOIN, the lease, the sweep of members | 1,808: `_zp_multicast_lease_task_fn` 466, `_zp_multicast_keep_alive_task_fn` 333, `_zp_multicast_send_join` 276, the task wrappers 493, `_z_multicast_send_close` 101, `_zp_multicast_send_keep_alive` 92, the rest 47 | 3,218: `MulticastDispatcher::session_duties` 1,071, `multicast_join::encode_join_into_slice` 1,021, `zp_send_join` 390, the member state machines' engine bodies 736 | 1,410 | mostly the same work; the two JOIN rules and the member machines are D4 |
| D | the group's session: joined at the open, stepped, waited on, let go of | 1,731: `_z_multicast_transport_create` 475, `_z_multicast_open_peer` 428, `_zp_start_transport_tasks` 156, `_z_listen_link` 146, `_zp_multicast_info_session` 168, `_zp_multicast_fetch_zid` 124, the clear and close 119, `_z_interest_process_interest` 72, the rest 43 | 42,320: `Core::join_group` 17,669, `HeldSession::build` 5,981, `GroupPump::step` 5,946, `CoopEngine::link_wait` 3,834 against `wait_on_faces` 1,923 less, `open_links` 2,161 more, `read_groups` 1,446, `step_groups` 1,426 and `step_group` 382, the executor's task memory for the group's task (`Taking`, `TaskStore`) 2,049, `seat_group` 729, `end_links` 688 more, `MulticastSessionPlace::leave` 675, `perform_link_duties` 540, `scout::window_hellos` 2,125 less, the rest 2,842 (the open's doors, the arena's plan, the kept cells, the group face's transport cells) | 40,589 | **shape, overlapping layers**: the engine's group face (`GroupPump`, `GroupFace`, `seat_group`, `step_groups`) holds the MCU image's group loop (`MulticastPump`, `HeldSession`, `MulticastSessionPlace`) as a task of its executor, so the group's lifecycle is written twice and run through both (F4); one open body of 17,669 bytes (F5) |
| E | the send: a message queued, framed, fragmented, encoded | 0 of its own: `tx.c`'s path sends to the group | 53,885: the group's stage (`GroupTxStage` `push_deferred` 6,326, `take_front` 4,499, `enqueue` 2,687, `StageQueue::wait_for_room` 1,815, `Lanes::queue` 1,445, `offer` 1,056, `admit_reply` 953, `stage` 935, `push_encoded_through` 882, `batch_flush` 531, the rest 1,084) 22,213; the group's framer (`multicast_tx::push_frame` 4,934 and its closures 678, `multicast_tx_declaration` 1,202, `MulticastTxReply::to_item` 1,175, `MulticastBatch::flush_open` 752, `multicast_tx_item_body` 462, `frame_encode`'s push writer 1,028, `build_fragment_wire` 935, `write_fragment` 617, `encode_frame_envelope` 427, `begin_frame` 133, the rest 101) 12,444; the heap encoders the group alone reaches (`DeclareWire::write_source` 5,529 in two copies, `MsgPutWire::write_source` 2,520 in two, `ExtEntryWire` 1,576 in three more, `DeclareWire::write_envelope` 550, `InterestWire` 451, `PushWire::write_envelope` 370, `WireexprWire` 360, `build_declare_kexpr_reply` 388, the rest 71) 11,815; the engine's legs of a publication (`HeldOperation::run` 5,078 more over its 12 copies, `GroupFace::publish` 950, `live_to_publish` 779 more, `put_through_filter` and `_in` 786 more, `publish_to_groups_on` 535, `fan_out_in` 408 more, `publish_to_link` 187 more, `publish_filtered` 55 more, the buffers' `TxBuf` bodies 651) 9,429; less the links' writer closures that were inlined since, 2,032, and 16 more | 53,885 | **shape**: a second transmit pipeline, stage and framer, beside the links' writer (F7); a second encoder form, heap and with a count copy beside each write copy, beside the links' lent writers (F2); the group's leg inlined into each of the 12 held operations (F6); **work**: a send that never blocks the session on a full socket (D2) |
| F | declarations and interests on the group | (in row D: `_z_interest_process_interest` 72 more) | 5,530: `engine::group::answer_asks` 1,402, `SubscriberPeer::sub_interest_reply` 824, `next_group_member` 682, `Core::retract_keyexpr` 621 more, `take_aggregate_retract` 559, `SessionTables::retraction_of` 494, `note_members` 304, `mark_aggregate_announced` 295, `GroupDeclarations::retraction_key` 222, `enumerate_peers` 213 more, the rest -86 | 5,530 | **work**: the retraction of what a departed member declared (D3); the interests a member asks are answered as zenoh-pico answers them |
| G | language support | 0 by symbol (396 by the ledger's line reading) | 13,775: 14 more `drop_glue` bodies 4,697, the member scope's three `BTreeSet<u64>` and the chained collect of its retractions (`Vec<Retraction>::extend_trusted` 2,471, the B-tree's bodies 3,144), `RawVec` growth 1,758 more, `Rc` and its `RefCell` cells 831, `Vec<ExtEntryIn<Heap>>::clone` 451, `VecDeque<StagedMessage>::grow` 151, the rest 272 | 13,775 | **shape, over-general containers**: heap containers in the group's path where the engine's own tables are bounded rows of the session's arena (F8), and the containers of rows D and E go with those steps |

The total of the wz column is 164,568 and of zenoh-pico's 11,244.

### 2.1 What is shape and what is work, as far as the symbol reading tells

| kind | rows | bytes, estimate |
|---|---|---:|
| shape, overlapping layers: the owned decoder for a length (B1), the sink chain (B2), the second shell (D), the second transmit pipeline less what D2 keeps (E) | B1, B2, D, E | 55,000 to 80,000 |
| shape, one open body moved through its frame | D | 5,000 to 12,000 |
| shape, generic and inline copies: the second encoder form with its count copies, the group's leg in 12 held operations | E | 9,000 to 14,500 |
| shape, over-general containers, beside what D3 keeps | G | 4,000 to 7,000 |
| work beside zenoh-pico's, for the owner (section 4) | A, B2, E, F, G | 19,000 to 27,500 |
| not yet placed: the same work in larger bodies, and what the symbol reading cannot split | A, B2, C, D | the rest of the 153,324 |

## 3. Steps

Each step takes out shape and keeps what the feature does; an owner's item (section 4) is never
taken out by a step. "Receive Ir" is the perf matrix's reading of a delivered message on
`pico-client-coop-nostd` (about 3,066): that case compiles no group, so no step here can move it,
and each step says what it does to the receive of a group and of a link in a build with groups.

| step | change | bytes, expected (`pico-api-coop-nostd`) | receive Ir | held by |
|---|---|---|---|---|
| **F1 (landed)** | the walk of a group datagram steps past an Init, an Open or an id no view reads by the session's in-place reader of a control message (`inbound::read_control`) where the build has it, instead of the owned decoder | -5,000 to -8,200 (codec, language): the owned decoder's 7,771 and its frame's drop glue 705, less the 290 the Init and Open views take back inlined once they have one caller again; the range is `read_control`, which had one caller and now has two, kept out of line (one call more on a link's control message, never on a data message) or inlined into both (its handshake arms twice, up to 3,000) | client: none (not compiled); a group's frame: none (the walk answers a Frame from its id, before this) | `multicast_rx::control_extent_tests`: three new tests, an Init and an Open stepped over as far as their decode reads and a refused or cut one ending the walk, and an id no reader takes ending it; `inbound::control_read_tests` holds the reader to the decoder |
| **F2a (landed)** | the count half of F2: in a lend-only build (`tx-lend-only`, which the C library's `os-host` names) a group's item and reply are counted by their one writer run into a count (`ItemBody`, and `ReplyBody` for a reply, both written once in `wz-session-core`), as a link counts what it sends, not by the codec's `measure`, which compiles each encoder a second time over a counting sink; `MulticastTxReply::with_body` hands on `ReplyBody` where it built a closure per kind in the caller's crate | -3,500 to -7,000 (codec): the counting copies of the declaration's, the response's, the interest's, the request's and the final's encoders, with the put and extension bodies they reach (about half of the 11,815 of row E's heap encoders), and the reply encoders the stage's crate compiled for its own closures | none: a group's datagram is never counted on the read; a reply is counted by the writer that then writes it, no call more | `multicast_tx::push_tests::an_item_and_a_reply_count_for_what_the_codec_measures`: each kind's count is the codec's measure, through `multicast_tx_bytes`, `MulticastTxReply::bytes` and each writer run into a count |
| F2b (in the engine since T1 and T2, section 7.2) | the write half of F2: the group's declaration, interest and reply written from their parts by the lent writers the links use (`lent_control`), not kept owned (`MulticastTxItem::Declare`, `DeclareReply`, `Interest`, `Response`) and written by the heap encoders; the stage that keeps an item until its conduit is free keeps its encoded bytes, which F7 decides | -2,500 to -5,000 (codec), after F7 | none on the read | the group's item bytes held to the link's writer's for the same message |
| **F3 (landed, section 8)** | one sink from the group's walk to the engine: the member scope a field the engine's sink reads, the pump's gate a word it reads, so a record of the group reaches the engine as a link's does (`hand_lent_push`) | -3,000 to -6,000 (sessions, transport), read by line first | a group's record: two sink layers fewer; none added | the engine's group tests of delivery, of a member's departure and of the gate; the dispatcher's member scope tests |
| **F4 (landed)** | one shell for a group: the engine's group face steps the session core's dispatcher and the stage itself, as it steps a link's session, and the MCU loop (`MulticastPump`, `HeldSession`, `MulticastSessionPlace`, its executor task) stays the MCU image's | -15,000 to -25,000 (driver, sessions) | a group's datagram: the task hop out; none added | the engine's group tests (join, rejoin, leave, the first step's refusal), the MCU loop's own tests unchanged |
| F5 (its Router landed, section 8) | the open builds the group's state where it lies: `Core::join_group` (17,669) read by line first, then each part placed in its slot, not moved through the open's frame | -5,000 to -12,000 (sessions), read by line first | none: the open | the engine's open tests with a group, and the stack bound's reading of the open |
| **F6 (landed, section 8)** | the group's leg of an operation under the held faces out of line: one non-generic call each operation makes, not the leg inlined into each of the 12 copies of `HeldOperation::run` | -3,000 to -4,500 (sessions) | none: an operation under the held faces is a declaration, an undeclaration, a query or a reply, never the read, and a publication's legs do not run through it | `direct::held_operation_tests`, the engine's declaration tests with a group |
| F7 | the group's send through the links' writer: framing, batching and fragmenting by `session_actions`' writer, the stage keeping only what D2 decides (the held datagram and its order behind the beacon) | -8,000 to -15,000 (transport, codec), after F2, F4 and D2 | none on the read; a group's put the link's writer's one pass | the group's wire held to the link's for the same items; the stage's tests of a held datagram |
| **F8a (landed)** | the member scope's containers: what a member holds declared is one sorted vector of its raw ids, each under its kind (`MemberDeclarations::held`), not three `BTreeSet<u64>`, and a member that leaves is kept whole until its retractions are handed (`MulticastDispatcher::departed`), not collected through a chain of three iterators into a vector of retractions; the retractions are the same and in the same order (subscribers, queryables, tokens, each by raw id, then the keyexprs) | -4,000 to -6,000 (language, sessions): the B-tree's bodies 3,144, the chained collect 2,471 and the drop glue of the three sets, less a vector's insert, remove and search of `u64` (300 to 600) | none: a member's record is scoped as before, its id now noted by a binary search of a vector | `multicast_member_scope::tests`: the order of a departed member's retractions, a redeclared id held once, an undeclared id not retracted; the dispatcher's tests of a member's departure |
| F8b | the stage's queue and cells in the session's arena (`VecDeque<StagedMessage>`, `Rc<RefCell>`), after F4 and F7 | -1,500 to -2,500 (language) | none | the stage's tests |
| **F9 (landed, section 8)** | the cells a join's face shares with the session that runs it (the mark of input, the members, the keyexpr asks, the stop, the end, the watchers' events) one `Rc<GroupShared>`, not one `Rc` each | -600 to -1,500 (language, sessions): five allocations a join and their drop glue fewer | none: a field reached through one handle where it was reached through its own | the engine's group tests |

F1 is first because it changes one function of the walk, keeps every extent and every refusal the
walk had (the reader answers the decoder's, by `inbound::control_read_tests`), and touches no
other lane's files. F2 is `arch-mono.md`'s rule and is planned with that lane. F4 and F7 are the
large ones and are designed with the line reading in hand.

### 3.1 F3, as the code reads it: after F4

A record of a group reaches the engine today through the MCU image's group loop, which the engine's
group face steps as a task: `GroupPump::step` (`crates/wz-capi-coop/src/engine/group.rs` @
`let outcome = self.place.step_reading(`) calls `MulticastSessionPlace::step_reading` and so
`MulticastPump::step_reading`, whose walk hands its datagram's records to the holder's gate
(`crates/wz-session-mcu/src/group_drive.rs` @ `struct GatedEvents<'a, F: ?Sized> {`), the session
core's walk wraps that in the member scope (`crates/wz-session-core/src/multicast_dispatch.rs` @
`pub(crate) struct MemberRecords<'s, E: ?Sized> {`), and the gate calls the pump's `on_event`, which
answers the group's asks, notes its members and hands the record on (`hand`) to the engine's
`DirectSink` and `hand_lent_push`.

F3's one sink is the engine's `DirectSink` wrapped by the member scope alone. That needs the
engine to call the session core's walk with its own sink: the group face stepping the dispatcher
itself, which is F4. Before F4 the engine's sink type would have to be carried through the MCU
loop's generic step (`MulticastPump::step_reading<F, G>` and `MulticastSessionPlace`), whose sink
is the MCU image's, for the engine alone, and F4 then takes that loop out of the engine. F3 is also
a step of a group's receive: what it does to the receive of a build with groups is read by the perf
matrix, and no body of that receive is moved out of line for it. So F3 waits for F4
(`mcast-tx1.md` T6).

## 4. The owner's decision items: work zenoh-pico does not do

| item | what wz does | how zenoh-pico does it | off in the pico preset, what is lost | bytes, estimate |
|---|---|---|---|---:|
| D1 | the group locator's keys beyond zenoh-pico's: `#ttl=`, `#dscp=`, `#bind=`, the loopback, the egress pinned to an interface's address and the refusal of a link that cannot be pinned (`wz_runtime_posix::multicast::Plan`, `locator_grammar::parse_dscp_value`) | `iface` (required) and `join` only (`vendor/zenoh-pico/src/link/multicast/udp.c` @ `UDP_CONFIG_IFACE_KEY`), membership by `IP_ADD_MEMBERSHIP` on the interface's address (`vendor/zenoh-pico/src/link/transport/udp/udp_multicast_posix.c` @ `IP_ADD_MEMBERSHIP`) | the keys refused by name, as a build refuses a key it does not carry; the hop limit, the DSCP and the loopback stay the system's defaults, and a host with several interfaces sends on the route's | 3,000 to 4,000 |
| D2 | a group send never blocks the session: a datagram the socket has no room for is held, and the beacon waits behind it (`GroupTxStage::push_deferred`, `StageQueue::wait_for_room`) | a blocking send on the group's socket, the caller waiting (`vendor/zenoh-pico/src/transport/common/tx.c` @ `_z_link_send_wbuf(ztc->_link, &ztc->_wbuf, NULL)`) | the cooperative engine steps every face on one thread, so a full socket would stall every link of the session until it drains; the cost is what F7 cannot take out of the stage | 8,000 to 12,000 |
| D3 | what a departed member declared on the group (its subscribers, queryables, tokens) is retracted when it leaves or is dropped (`multicast_member_scope::MemberDeclarations`, `retract_departed`) | the departed peer is removed and the session's interests are told its connection dropped (`vendor/zenoh-pico/src/transport/multicast/lease.c` @ `_z_interest_peer_disconnected(s, &peer->common);`), which is what a write filter forgets it by; what it declared is not retracted (`vendor/zenoh-pico/src/transport/multicast/rx.c` @ `TODO: cleanup here should also be done on mappings/subs/etc...`) | as in zenoh-pico, what a member that left declared stays declared at this node until the session ends: a liveliness subscriber does not hear its tokens go, and its queryables are still asked | 7,000 to 10,000 |
| D4 | a JOIN judged by either of two rules (`GroupJoinRule::Zenoh` asks for room before the terms, `::Pico` reads the terms first), each member a state machine of its own | one rule, the terms first (`vendor/zenoh-pico/src/transport/multicast/rx.c` @ `_z_multicast_handle_join_inner`), a member a row of a list | the pico preset could compile its own rule alone; nothing of zenoh-pico's behaviour is lost | under 1,500 |

### 4.1 The decisions, by the owner's ruling of 2026-11-27

The ruling: what zenoh-pico does not do is a capability of its own, behaviour by behaviour, off in
the zenoh-pico preset (`deploy/wz-config.toml`, `upstream_off = ["zenoh-pico"]`, as
`tx-probe` and `tx-stream-owed` are). A capability of a behaviour, not of a door, stays on in the
host profiles (`host-peer`, `host-peer-ext`, `host-peer-raweth`), as the send's behaviours do,
so the release keeps what it had; its bytes are read on a build of the zenoh-pico defconfig with
the multicast transport, not on `pico-api-coop-nostd`, which reads `host-peer`.

| item | decision | why | bytes, estimate, in the zenoh-pico preset |
|---|---|---|---:|
| D1 | landed: a capability, `multicast-locator-keys`: off, a group's `#ttl=`, `#bind=` and `#dscp=` are refused by name (`GroupLocatorError::KeyNotCarried`) and no socket is given a hop limit, a bound address or a traffic class | zenoh-pico reads `iface` and `join` alone. The egress pin is zenoh-pico's as well: it binds its send socket to the interface's address and names it the multicast interface (`vendor/zenoh-pico/src/link/transport/udp/udp_multicast_posix.c` @ `IP_MULTICAST_IF`), so it is no part of the switch; nor is `parse_dscp_value`, which a unicast locator's `#dscp=` reads (`locator::parse_socket_options`) | 500 to 2,000 |
| D2 | the transmit lane's, with F7; not taken while T3 is not (`mcast-tx1.md` section 7) | the stage F7 reduces is what D2 keeps; the two are one change | - |
| D3 | no capability: kept in every build | zenoh-pico does the part that costs: a member whose lease runs out is told to every interest of the session (`vendor/zenoh-pico/src/transport/multicast/lease.c` @ `_z_interest_peer_disconnected(s, &peer->common);`), and a write filter and a matching listener forget its targets by it (`vendor/zenoh-pico/src/net/filtering.c` @ `case _Z_INTEREST_MSG_TYPE_CONNECTION_DROPPED: {`). wz's filter forgets a member's subscriber only by its retraction, so a build without D3 would keep a departed member's subscriber in this node's filters where zenoh-pico's forget it. What zenoh-pico does not do (a liveliness subscriber told the tokens went, a Close read as a departure) is the same retraction, a branch of it; its containers are F8a's | - |
| D4 | not yet a capability | the pico ABI opens every group under the Pico rule (`crates/wz-capi-pico/src/session.rs`, the group's `MulticastParams`); the Zenoh rule is two compares on the group's parameters (`multicast_join::judge_join` and the walk's room-first branch), and a member is one machine under either rule | under 300 |

## 5. Step F1, as landed

`multicast_rx::multicast_message_len` steps the walk past each message the group dispatched. A
Frame and a Fragment end the walk; a JOIN is measured by its own decode; a Close, a KeepAlive and an
OAM by their views (`inbound::control_extent`). What is left, an Init, an Open and an id no view
reads, went to the owned decoder (`inbound::parse_inbound_consuming`), which builds the whole
message to answer its length: the only caller of that decoder in a build whose group lends its
records, so the decoder of every transport message was linked for it. It now goes to
`handshake_extent`: in a build with the session's in-place reader of a control message (`alloc`
and `session-unicast`, the C library's), that reader, `inbound::read_control`, whose extents and
refusals are the decoder's (`inbound::control_read_tests` holds them to it, wire by wire);
elsewhere the owned decoder, as before. zenoh-pico reads an Init and an Open on a group and does
nothing with them (`vendor/zenoh-pico/src/transport/multicast/rx.c` @ `case _Z_MID_T_INIT:`), and
so does the walk: what changed is which reader says where they end.

## 6. Verification (the main session's)

- Build and clippy of `wz-session-core` with the group's set in its three forms: with
  `session-unicast` (the reader's form), without it (the decoder's form), and the slot profile
  without `alloc`; each with and without `codec-init-body` and `codec-open-body`.
- `cargo test -p wz-session-core --lib --features
  session-multicast,codec-join,codec-frame,codec-close,codec-init-body,codec-open-body,session-unicast,rx-lent-control
  control_extent_tests`: 7 tests (4 that were, 3 new); the same without `session-unicast`, 7.
- `inbound::control_read_tests` in the reader's form, unchanged.
- Layer C1cs: `pico-client-coop-nostd` unchanged to the byte; `pico-api-coop-nostd` lower by F1's
  range, with none of `inbound::parse_unit`, `parse_unit_into`, `parse_init`, `parse_open`,
  `parse_close`, `decode_keep_alive`, `decode_oam`, `ext_chain::collect_walk`,
  `keep_handshake_entry` and the drop glue of `InboundFrame` in its library (`nm -C -S`).
- The perf matrix's receive Ir of `pico-client-coop-nostd` as its last reading.
- For F3 to F8: `python3 scripts/lib/size_ledger_gate.py --explain pico-api-coop-nostd` once
  `size-per-feature` lands, the line reading of the bodies of section 2.
- F2a: `cargo test -p wz-session-core --lib --features
  session-multicast,codec-frame,storage-profile,codec-push,codec-declare,codec-response,codec-response-final
  an_item_and_a_reply_count_for_what_the_codec_measures`: 1 test; the same with `tx-lend-only`
  added, 1. Build and clippy of `wz-session-core` with the group's set with and without
  `tx-lend-only`, and without `codec-push`. In `pico-api-coop-nostd`'s library no
  `write_source` of the declaration, response, interest, request or final encoder over
  `CountSink` (`nm -C -S`); `pico-client-coop-nostd` unchanged to the byte.
- D1: `cargo test -p wz-session-core --lib group_locator` with the crate's defaults, and the
  same without `multicast-locator-keys` (the row `nondefault-tests-gate.sh` adds:
  `a_build_without_the_locator_keys_refuses_them_by_name` in place of
  `every_key_is_read_into_its_field`); build and clippy of `wz-capi-coop` with `group-host`
  with and without `multicast-locator-keys`; `wz_config.py --check` after
  `wz_config.py --write` regenerates `crates/wz-conformance-build/statement_vectors.json` for the
  new capability, which this lane could not run.
- F8a: `cargo test -p wz-session-core --lib --features session-multicast,codec-declare
  multicast_member_scope`, and the same with the lent group's set
  (`session-unicast,rx-lent-control` added); the dispatcher's departure tests
  (`multicast_dispatch`), and `wz-capi-coop`'s group tests
  (`two_members_declarations_of_one_id_read_in_place_stay_apart`,
  `a_member_that_leaves_takes_its_keyexprs_and_the_other_keeps_its_own`). In
  `pico-api-coop-nostd`'s library no `BTreeSet<u64>` body and no
  `Vec<Retraction>::extend_trusted`.
- F4: `cargo test --manifest-path crates/Cargo.toml -p wz-capi-coop --lib --features
  std,group,app-transport place_tests`: 3 tests, all new
  (`a_session_in_its_place_beacons_at_its_first_step_and_an_asked_join_and_is_built_again_there`,
  `a_session_let_go_of_lets_its_transport_go_and_its_empty_place_steps_nothing`,
  `a_stopped_session_sends_its_close_and_a_link_not_opened_or_gone_ends_it`); the engine's group
  tests unchanged (`tests::group`, and `tests::one_thread`'s count of the places a group's joins
  made, `group_places_made`); `cargo test --manifest-path crates/Cargo.toml -p wz-session-mcu
  --lib --features transport-multicast,codec-push group_drive`, two tests fewer than before (they
  moved to `place_tests` with the place). Build and clippy of `wz-capi-coop` with `group`; with
  `group,transport-stats,resource-snapshot`; with `group,query,queryable,liveliness,connectivity`;
  and the round's form (`WZ_COOP_VALUE_LOCKS=off`, `std,threads,group`), where the group is the
  MCU image's task as before. Clippy of `wz-session-mcu` with `transport-multicast,codec-push`
  and with its defaults. In `pico-api-coop-nostd`'s library (`nm -C -S`) no
  `MulticastSessionPlace`, `HeldSession`, `MulticastPump` or `GatedEvents` body, one
  `GroupRun::step`; `pico-client-coop-nostd` unchanged to the byte.

- F3, F5, F6, F9: `cargo test --manifest-path crates/Cargo.toml -p wz-capi-coop --lib --features
  std,group,app-transport place_tests`: 4 tests (1 new,
  `each_session_built_in_its_place_writes_its_router_there_with_the_groups_bound`); the same
  features with `tests::group`, and with `query,queryable,liveliness,connectivity` added;
  `cargo test --manifest-path crates/Cargo.toml -p wz-runtime-coop --lib --features reassembly,alloc
  a_router_built_in_its_place_is_the_one_built_as_a_value`: 1 test, new. Build and clippy of
  `wz-capi-coop` with `group`; with `group,threads` (the hand that lets the session's lock go);
  with `group,query,queryable,liveliness,connectivity`; and the round's form
  (`WZ_COOP_VALUE_LOCKS=off`, `std,threads,group`), where `GroupShared` is shared with the
  group's task; clippy of `wz-runtime-coop` with `reassembly`. In `pico-api-coop-nostd`'s
  library one `announce_to_groups` and one `retract_from_groups` body, and
  `Core::announce_subscriber_to_groups` and `Core::announce_queryable_to_groups` out of line;
  `pico-client-coop-nostd` unchanged to the byte.

## 7. Step F4, as landed

The read form of the engine (every form but the round's, `wz_round`) held the MCU image's group
loop whole: `GroupPump` kept a `MulticastSessionPlace`, a leaked box of four `UnsafeCell`s
(`HeldSession`: the parameters, the dispatcher, the transport, and a `MulticastPump` that borrowed
the other three for `'static`), and each step went the read, the place's `advance` (the JOIN ask,
the due), the pump's `step_reading` (its executor pass, its iteration budget, its pull seam with its
backlog and its scratch, the stage it was given), the pump's gate sink (`GatedEvents`), the pump's
closure, and then the engine. It was already stepped by the read and not as a task of the executor,
so the executor's bodies row D lists (`Taking`, `TaskStore`) are not what this step takes out.

- `GroupPump` now holds the group's place, `GroupPlace`: the session core's
  `MulticastDispatcher`, built where it lies (`new_in_place`) and dropped there, beside one
  `GroupRun` (the parameters, the transport, the reassembly router, the walk's resume, the beacon's
  and the sweep's cadences, the open's loss, the due cell and the counters), owned, with no borrow
  between them. The dispatcher is built exactly while `run` holds a session, the one invariant the
  place's `unsafe` reads. The place is one heap box made at the group's first join and kept for
  every join after it, as the old place was (`tests::one_thread` counts it).
- `GroupRun::step` is the step of the MCU loop with what the engine never takes taken out: no
  executor pass (the read pumps the stack), no iteration budget, no pull seam, no backlog of the pull
  seam's datagrams and no scratch (everything the group sends is on its stage), no input gate (the
  read hands each record out as it is read). The order is the loop's to the step: the open's loss,
  the stop with the stage written before the Close, the carrier, the stage's held datagram, the
  beacon behind it advertising the conduits as written, the stage's writes, the service, the reads
  up to the read's bound, the sweep on a step that read none.
- The walk hands its events to one sink, `GroupEvents`, which answers the asks, notes the members
  and hands the record to the engine: the gate's layer and the pump's closure are gone (F3's first
  half, section 7.2).
- `wz_session_mcu::group_drive` keeps the MCU image's loop (`MulticastPump`, its task, its
  seed) and gives both shells the pieces they share: `perform_link_duties`, `JoinAsk::take`,
  `GroupDue::publish`, and the stage's `offer_held`, `write` and `on_wire`. Its
  `MulticastSessionPlace` had no other holder and left with its two tests, which are the engine's
  `place_tests` now, against the engine's place; `test_heap::counted`, which only one of them
  read, left with it.
- Bytes, expected, not measured: the row D bodies of the second shell (`HeldSession::build`,
  `MulticastSessionPlace::leave`, the place's `advance`, `GroupPump::step` over the pump) and
  row B2's `MulticastPump::step_reading::{closure#4}` and `GatedEvents` against one
  `GroupRun::step` and `GroupPlace::build` of the same work: -8,000 to -15,000, under the
  section 3 range, which counted the open's body (F5) and the executor's bodies this form does not
  link. Receive Ir of a group's datagram: one sink layer fewer; `pico-client-coop-nostd` links no
  group and is unchanged.

### 7.1 What R5 inherits

Peer-rows R5 puts a group in a row of the face table. The read slot is the shape a row holds:
`GroupPump` is one heap box (`GroupPlace`) and a few handles (the reads shared with the face, the
records, the receive half), moved whole when a read takes it out of the session
(`CoopEngine::step_groups`), and nothing in it borrows anything outside it. A row inherits: the
place, made at the group's first join and rebuilt in at each join (`GroupPump::rejoin`), never
freed while the row is; `holds_session` as the row's phase (up from a join to the session's end);
`let_go` as the row's transport going down with the place kept; and `leave` as the row's close.
What stays outside the place is the face's (`GroupFace`: the stage, the members, the asks, the
due, the counters), which the row holds beside it, as a link's row holds its session beside its
face's tables. The round's form (`wz_round`) keeps the group a task of its set and has no place to
put in a row.

### 7.2 F2b, F3, F5 to F8b, as the code of 2026-11-28 reads them

- **F2b is in the engine since T1 and T2.** No path of the engine builds an owned
  `MulticastTxItem::Declare`, `DeclareReply`, `Interest` or `Response`: an interest is written
  by `multicast_tx_interest` from `lent_control::interest_exact`, a declaration by
  `GroupDeclare` (T2), a reply by `enqueue_reply_parts` and `enqueue_declaration_reply` and a
  final by `enqueue_response_final` (T1), and a get by `RequestWriter`. The owned entry
  (`GroupTxStage as MulticastReplyEnqueue>::enqueue`) is reached by the engine's tests alone
  (`stage_group_replies`), and the pull seam that took owned items left the engine with F4. A
  message pushed while another holds the conduits is kept encoded already (`Staged::keep`). What
  is left owned is the MCU image's queue (`MulticastReplyQueue`) and its pull seam, that image's
  form.
- **F3: its gate half landed with F4**, its hand landed after it (section 8); its other half is the member scope as a field the engine's
  sink reads instead of a sink that wraps it (`multicast_dispatch::MemberRecords`), and the
  engine's `DirectSink` handed the walk's records with no `dyn FnMut` between (`hand`, which
  `step_group` makes to let the session's lock go around each record where other threads reach
  the session). Both change the session core's walk and the threads form's lock order; they are
  the next step of this lane.
- **F5, the open in place**, its Router landed (section 8); before it, `GroupPlace::build` still makes the
  reassembly router on the stack and moves it into `run` (as the pump did), and
  `Core::join_group` is read by line first.
- **F6, the group's leg under the held faces out of line**, landed (section 8).
- **F7 and D2** stay as section 4.1 decides them: F7's first step is `mcast-tx1.md` T3, whose
  premise the code does not hold (`mcast-tx1.md` section 7).
- **F8b**, the stage's queue and cells in the session's arena, follows F7 (the stage's `Staged`
  queue and its `Rc` cells are what F7 reduces).

### 7.3 Rows for `contract-switches.md`

The contract-switches lane owns that file, which this lane's base does not hold; the rows below are
this lane's classification, for that lane to append under its next free ids.

| behaviour | kind | why |
|---|---|---|
| D1, the group locator's `#ttl=`, `#bind=`, `#dscp=` (`multicast-locator-keys`) | contract, landed as a capability, off in the zenoh-pico preset | zenoh-pico reads `iface` and `join` alone |
| D2, a group send that never blocks the session (the held datagram, the beacon behind it) | contract, kept in every build | the cooperative engine steps every face on one thread; a blocking send stalls every link (section 4.1) |
| D3, a departed member's declarations retracted | contract, kept in every build | zenoh-pico's write filters forget a departed member by its dropped connection; wz's by the retraction (section 4.1) |
| D4, the JOIN's two rules (`GroupJoinRule::Zenoh`, `::Pico`) | contract, not a capability | the Zenoh rule is two compares (section 4.1) |

## 8. Steps F3, F5's Router, F6 and F9, as landed

### 8.1 F3: the hand

- `GroupPump::step` takes the engine's hand by type (`GroupHand`, which `direct::GroupHandOff`
  implements), not a `dyn FnMut`: the walk's sink (`GroupEvents`) is of the hand's type, so a
  record crosses one dynamic call from the session core's walk (the `&mut dyn EventSink` of
  `dispatch_multicast_inbound_kept`) to the engine's dispatch, which is inlined into the sink's
  `event`. The session's lock the hand lets go of around each record (`threads`) is the hand's
  field, let go of at the end of the step's statement. `GroupPump::leave` steps the stopped
  session with a sink that takes nothing: a stopped step sends its Close and reads nothing
  (`GroupRun::step`), so no hand is made for it and no second copy of the step is compiled.
- **The member scope as a field the engine's sink reads is not taken: its premise does not
  hold.** What a member declared is the session core's dispatcher's fact (its row,
  `MulticastDispatcher::member_scope`), and the scope rewrites the member's Declare by it before
  any sink sees the record. The engine's sink reading it would put the session core's member table
  in the engine's layer (`docs/c-abi-architecture.md` section 5, one fact in one layer), and the
  walk would lend the sink a borrow of the dispatcher's row for each datagram through a method of
  `EventSink`. The decorator `MemberRecords` is generic over the sink it wraps and is compiled into
  the walk's own copy (`walk_lent_payload` over `MemberRecords<dyn EventSink>`), so it adds no
  dynamic call; the 7,146 bytes row B2 read as `MemberRecords as EventSink` were the engine's
  delivery inlined into it through the MCU loop's generic gate, which F4 took out. A group's
  record now crosses the walk, the member scope (static), one dynamic call and the engine's
  dispatch: a link's path, and the scope D3 keeps.
- Tests: no branch is new; the engine's group tests (`tests::group`) in both lock forms, and
  `place_tests`.
- Bytes, expected: -300 to -800 (the closure's vtable and its shims, an indirect call a record);
  receive Ir of a group's record: one indirect call fewer.

### 8.2 F5: the Router where the place keeps it

- `GroupPlace` holds the reassembly Router in a field of its own beside the dispatcher, both built
  exactly while `run` holds a session: `GroupPlace::build` writes it there
  (`wz_runtime_coop::reassembly_rx::mcu_reassembly_in`, over `ReassemblyDispatcher::init_in`),
  where it made it on its stack (`mcu_reassembly`) and moved it into `GroupRun` and then into the
  place. A Router is a slot machine for each of its slots, kilobytes: no frame of a join holds it,
  and it is not copied.
- Tests: `place_tests::each_session_built_in_its_place_writes_its_router_there_with_the_groups_bound`
  (red for a build that keeps the last session's Router or its bound),
  `reassembly_rx::tests::a_router_built_in_its_place_is_the_one_built_as_a_value`.
- Bytes, expected: -300 to -1,000, and kilobytes of the join's stack; receive Ir: none.
- **The rest of F5, `Core::join_group` (17,669 in the earlier tree), waits for the line
  reading.** Read from the code, a join moves its parts by value through four frames:
  `Core::group_joining` returns a `GroupJoining` (the group's `GroupJoin`, its `MulticastParams`,
  the session's `SessionPolicy` and `SessionLimits`), `GroupFace::made` returns the face and
  `GroupParts`, `GroupFace::join` returns the face and a `GroupSeat` (the seed's
  `MulticastConfig`, parameters and policy again), `Core::join_group` returns both in a `Result`,
  and `Core::seat_group` moves the seat into a `GroupPump` and the pump into its slot. Which of
  these moves the compiler keeps is what `--explain pico-api-coop-nostd` reads by line; building
  the face and the seat in the place they end in is the form, and it is the group's row of the
  face table once R5 makes one.

### 8.3 F6: a declaration's group leg

- A subscriber's and a queryable's announcement to the groups is one call on the session's state
  (`Core::announce_subscriber_to_groups`, `Core::announce_queryable_to_groups`), as a token's is
  (`Core::announce_token_to_groups`), each out of line: the operation's body (a copy of
  `HeldOperation::run` each where faces hold their own send places, the caller's body where they
  share the session's lock) holds none of a group's announcement, nor its frame the
  announcement's wire key. The walks of the groups that announce and retract
  (`TellGroups::announce_to_groups`, `retract_from_groups`) are one body each, where they and
  each group's message were inlined into each of the three operations that call them.
- Kept in the operation's body: the legs one operation alone makes (a keyexpr's announcement, a
  liveliness subscriber's end, a write filter's ask and end, a batch's step), each a walk of the
  groups calling one method of a group; out of line, each would add a call and take out no copy.
- Tests: no branch is new; `tests::group::a_members_subscriber_is_announced_on_the_group_and_retracted_from_it`,
  `a_get_of_the_group_is_answered_by_a_members_queryable_and_ends_with_its_final`,
  `a_liveliness_subscriber_asks_the_group_for_the_tokens_its_members_hold`.
- Bytes, expected: -2,000 to -4,000 (sessions); receive Ir: none, an operation is never the read.

### 8.4 F9: one cell of a join

- A join's face and the session that runs it (the read slot's `GroupReads`, or the task's
  closures where the faces are tasks of one set) shared six handles, each a heap cell of its own:
  the mark of input, the members, the keyexpr asks, the stop, the end and the watchers' events.
  They are the fields of one `GroupShared`, made with the join, of which each side holds one
  `Rc`; the face notes that it read the end by a flag (`end_read`), where it let go of its
  handle. A group's row of the face table (R5) holds these fields as its own.
- The JOIN ask, the due and the counters stay handles of their own: they are the MCU loop's types
  (`JoinAsk`, `GroupDue`), which both shells read, or shared with the stage (`TransportStats`),
  whose cells F8b decides.
- Tests: no branch is new; `tests::group` (the mark of input,
  `a_burst_of_a_members_datagrams_moves_the_links_once`; the end and a join again,
  `a_member_whose_group_link_is_lost_joins_the_group_again`; the members, with `connectivity`,
  `each_member_is_a_transport_a_watcher_is_told_of_as_it_comes_and_goes`), `told_tests`.
- Bytes, expected: -600 to -1,500 (language, sessions); receive Ir: none.

### 8.5 The share section 2.1 left unplaced, placed

Read from the code of 2026-11-28 against the bodies section 2 names: by symbol, not by line, so
each part has a kind and an owner, not a figure.

| part (row) | kind | why | whose |
|---|---|---|---|
| the group's two sockets in larger bodies, `bind_joined` and `bind_sender` against `_z_listen_udp_multicast` and `_z_open_udp_multicast` (A) | contract in a larger form | the same sockets, memberships and egress pin (section 4.1, D1); the larger part is the plan over a generic socket (`Plan::resolve`, `MulticastSocket`) and the link's `multicast-link-requires-iface` policy, where zenoh-pico requires `iface` | T-LINK (`docs/win-budget/size.md` section 9) |
| `HostGroupReceive` against `_z_read_udp_multicast` (A) | contract | a datagram kept for the next walk (`keep`) and a read that waits in the group's receive (`await_input`) are the read slot's (`docs/c-abi-architecture.md` section 8.8): one read waits on every face and group, where zenoh-pico blocks a task in each transport; what the group's own sender sent is dropped by both | none |
| `find_by_src`, `JoinIn::read_into`, `walk_lent_payload`, the reassembly (B2) | contract | the same work: zenoh-pico finds a peer by its address (`_z_find_peer_entry`), reads a JOIN and a frame's messages and rejoins a chain; its JOIN decoder lies in its unicast build's codec | none |
| `session_duties`, `encode_join_into_slice`, `zp_send_join` (C) | contract | the release of the peer pool with its members' retractions (D3), and the JOIN zenoh-pico encodes in its base's codec | none |
| `Core::join_group` (D) | form, read by line first | section 8.2 | F5's rest, then R5 |
| `link_wait`, `open_links`, `end_links`, `read_groups`, `step_groups`, `step_group`, `seat_group` (D) | contract in a form R5 takes | the read waits on the groups beside the faces and steps each where it lies (the contract); the slot taken out of the session and put back around each step, and the groups a vector beside the face table, are the form a row of the face table replaces | R5 (`peer-rows.md`) |
| the executor's task memory, `Taking` and `TaskStore` (D) | not linked by the read form | the round's form alone runs a group as a task (section 7) | none |
| the kept cells and the group face's transport cells (D, G) | form | F9 (landed); the stage's cells are F8b's | F8b |
| the rest of the drop glue and the `RawVec` growth (G) | form, falling with the bodies they serve | read again after F7 and R5 | the group-link-writer lane, R5 |

What is left to this lane: F5's rest, once the line reading names it. F7, D2, F8b and T3 are the
group-link-writer lane's.

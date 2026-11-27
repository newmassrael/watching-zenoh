# The `peer` step in proportion: what it adds over the client, by owner, and the structure that brings it to zenoh-pico's order (peer-proportion)

`peer` costs wz an order of magnitude more than `Z_FEATURE_UNICAST_PEER` costs zenoh-pico
(`docs/c-abi-migration/feat-peer.md`, the table at its head: +104,075 against +3,792 on the API
chain, +158,099 against +8,642 on the peer chain). `feat-peer.md` paired the work and named the
behaviours zenoh-pico lacks; this note reads the same step body by body and owner by owner from the
explain report, separates what is a behaviour (a switch, off in the zenoh-pico preset) from what is
the form the code takes (a structural step), states the target in numbers, shows how far the steps
reach, says what is left and why, and lands the largest structural step of the case the owner's
ruling compares.

The owner's rulings this note keeps (2026-11-27, delegated): every behaviour zenoh-pico does not
have is a Kconfig capability, on in a build that names nothing and off in the zenoh-pico preset;
the release profiles (`host-peer-ext`, `host-peer`) keep wz's behaviours on, and a like-for-like
comparison is made on the zenoh-pico preset; the storage policy is a preset axis (the release D12,
the zenoh-pico preset `OnUse`, `heap-native.md` section 9); the receive's instructions a message
do not grow.

## 1. Readings

| what | source | how read |
|---|---|---|
| bytes by owner and by body, the client case and the peer case | the explain reports (`size_ledger_gate.py --explain`, JSON under the cost gate's `size-ledger/`) of `pico-client-coop-nostd`, `pico-peer-coop` and `pico-api-coop-nostd`, one run on tree `cded266a88`, whose crates are those of `0d94053525` (the commits between touch docs, scripts and CI only) | each area's `owners` (bytes by the source line's owner) and `symbols` (bytes by body) of the peer case less the client case's |
| the explain report of `0d94053525` for the two cases | the same gate on that tree | the area rows: `pico-peer-coop` sessions 108,808 against 30,392, driver 55,777 against 16,560, doors 48,678 against 19,616, transport 39,218 against 16,863; `pico-api-coop-nostd` sessions 298,875 against 55,128, driver 142,278 against 26,087 |
| zenoh-pico's bodies | the reference libraries of the same cases, in the same reports | the `pico` side's `symbols`, diffed the same way |

The peer chain's step read this way, client case to peer case: wz +124,333 (125,913 added by the
owners that grew, 1,580 given back by those that shrank), zenoh-pico +8,642. By area: sessions
+47,692 against +2,884, driver +29,931 against +511, language +17,134 against +1,646, transport
+13,044 against +2,912, doors +9,287 against +582, codec +7,264 against +107.

Two cautions on the figures:

- The peer chain turns on `scout` with `peer` (`wz-capi-pico`'s `peer = ["scout", ...]`;
  zenoh-pico's `Z_FEATURE_SCOUTING 0->1` beside `Z_FEATURE_UNICAST_PEER 0->1`). Its owners are
  read apart below (G0, 33,472 B); the `peer` step proper is the rest, **90,861 B**, against
  zenoh-pico's 3,792 (its API chain step, which has no scouting in it: 8,642 less its `scout`
  step's 4,850).
- The per-feature figures quoted at the head of `feat-peer.md` were read before the `udp/`
  listener and the answer to a peer's Interest became capabilities of their own (W3, W4) and before
  the lent-only udp port (S1). The case read here has neither (no `UdpPort` and no answering body
  in it), so its 90,861 is today's `peer`. The per-feature report wants a new reading
  (section 8).

The owner view counts each byte by its source line, so code inlined across owners counts where it
was written; the body view names the bodies. Groups below are owner groups; the bodies named in each
are the body view's, so a group's total and its bodies' bytes need not add up.

## 2. What the step adds, group by group

| group | wz, B | owners (owner view, B) | largest bodies (body view, peer case; "a -> b" where the client case has the body) | zenoh-pico for the same | kind |
|---|---:|---|---|---|---|
| G0 scout (the `scout` feature) | 33,472 | `scouting_host` 5,978, `capi_pico::scout` 4,802, `runtime_posix::interfaces` 4,094, `runtime_posix::multicast` 3,864, `text_out` 2,388, `runtime_posix::scouting` 1,984, `core::net::parser` 1,620, `scouting_message` 1,597 | `scout::window_hellos` 14,427, `z_scout` 3,148, `z_hello_clone` 1,752, `ipv6_text` 1,608 | `_z_scout_inner` +2,970, `z_scout` 533, `_z_scout_process_hello` 380: 4,850 | the scout step's own; not this note's |
| G1 faces: the read, the turn, the supervisor, the task table | 19,889 | `engine::direct` +8,248, `runtime_coop::faces` +6,077, `executor` +2,305, `cs` +655, `wz_host_sync` +575, `form::one_thread_lock` +346 | `CoopEngine::face_turn` 4,842 (the client's `link_turn` 4,656 goes), `read_direct` 352 -> 4,160, `put_on_links` 3,023 -> 5,209, `place_link_session` 2,980 -> 4,593, `open_links` 983 -> 3,091, `drive_link` 1,429 -> 2,798, `wait_on_faces` 1,947, `LinkSupervisor::read_node` 1,632, `ExecutorState::run_among` 1,209, `claim_among` 540, `drop_among` 341, `DirectFaces::taken_in` 859 | `_zp_unicast_read_task_fn` +1,197, the wait over the peers' sockets 124, `_zp_unicast_lease_task_fn` +247, `_zp_unicast_keep_alive_task_fn` +179 | work (N faces), with two forms in it: F1, F5 |
| G2 the open's plan and the faces' pools | 20,406 | `row_pool` +6,180, `capi_coop::arena` +5,428, `bounded` +3,144, `engine::registry` +2,332, `peer_tables` +1,037, `byte_cells` +960; `capi_coop::region` -358 | `RegistryOf<ManyHolders>::new` 4,925, `ArenaPlan::lay_out` 2,284, `lend_session` 4,290 -> 5,968, `assemble` 4,107 -> 5,843, `RemoteSubscriberTable::dispatch_iteration_event_with_local` 1,997, `registry::lend_set` 1,286, `arena::pool_rows` 616 | none: a heap block per peer (`vendor/zenoh-pico/src/transport/peer.c` @ `ztu->_peers = _z_transport_peer_unicast_slist_push_empty(ztu->_peers);`) | the storage axis (section 4, W5) and, on D12, a form: F3 |
| G3 the accepting cookie | 6,181 | `accept_state` +1,234, `accept_cookie` +1,013, `signing_key` +657, `sha2` +1,305, `block_buffer` +489, `hmac` +434, `subtle` +419, `digest` +373 | `decode_accept_cookie` 2,286, `send_init_ack_with_cookie` 1,880, `RegionAcceptState::encode` 1,133, `compute_hmac_sha256_full` 1,108, `NegotiatedExtensions::decode` 742, `sha256::compress256` 648 | an empty cookie (`vendor/zenoh-pico/src/transport/unicast/transport.c` @ `_z_t_msg_make_init_ack(mode, *local_zid, cookie)`) | behaviour: W1 |
| G4 the admission of crossing links | 1,478 | `link_admission` +1,377 | `rival_says` 751, `LinkRegistry::reserve` 595, `LinkBook::try_with_order` 286 | none: each link a peer of its own (`vendor/zenoh-pico/src/transport/peer.c` @ `z_result_t _z_transport_peer_unicast_add(`) | behaviour: W2 |
| G5 the accepting handshake and its machine | 8,998 | `session_actions` +2,672, `sce_rust_runtime::engine` +2,098, `transport::state` +930, `credential_identity` +812, `event_queue` +502 | `Turn::run` 664 -> 1,336, `Engine::lend_event` 408, `encode_init_into` 774, `send_open_lent` 496 | the accepting handshake is in zenoh-pico's client build already (`_z_unicast_handshake_listen`, exported): its step counts none of it | work; a counting difference (section 6); the machine's turn is F4 |
| G6 the listener and the links | 9,747 | `ip_stack` +1,649, `link_storage` +1,595, `capi_pico::os::no_std_host` +1,571 (about 800 of it the scout's host calls), `runtime_posix::net` +1,193, `capi_pico::session` +950 | `IpListener::accept` 591, `PosixTcpListener::accept` 400, `IpLinks::begin_initiator` +653 (owner view), `TxLender::acquire` 394, `poll_on` 350 | `_zp_unicast_accept_task_fn` 552, `_z_new_transport` +270, `_z_open` +314, `_z_add_peers` 380, `_z_add_peers_impl` 286, `_zp_add_peers_task_fn` 466 | mostly the same work; the links' form is lane T-LINK's (`docs/win-budget/size.md` section 9) |
| G7 the codec runtime | 6,081 | `sce_forge_runtime::codec` +2,148, `::storage` +1,168, `::reader` +1,124, `wz_codecs` +429 | the accepting states' encoders and decoders (in G3's bodies), `UnicastRx::dispatch_datagram` 2,297 -> 2,572 | in its client build | the accepting side's codecs: work, and W1's share |
| G8 what a new face is told | 4,114 | `session_tables` +924, `engine::replay` +797, `key_arena` +486, `wireexpr_resolve` +426 | `replay::announce_on` 737, `SessionTables::declare_keyexpr_where` 1,291 | `_z_interest_push_declarations_to_peer` (in the client build) | work |
| G9 the receive of each face | 2,158 | `reassembly_dispatch` +1,156, `drive` +776 | the fragment rejoin's Router per face (`fragment_in_place` 1,277 -> 2,106, owner view) | in its client build | work |
| G10 the engine, other | 5,352 | `capi_coop::engine` +5,415 | `next_peer` 193 -> 773, `fan_out_in` 545, the callers of the held operations | | work and W6's share |
| G11 language | 6,465 | `core::ptr` +2,522, `alloc::raw_vec` +1,275, `core::cmp` +402, `heapless::vec` +391 | drop glue of the faces' rows, the listeners' list growing (`RawVec<faces::Listening<..>>::grow_one` 99) | | falls with the bodies it is inlined in |

The operations held with every face's send place (`HeldOperation as UnderHeldFaces` `run`, 11
bodies, 8,745 B) are counted by the owner view in the operations' own groups (G8, G10); they are the
operations moved out of their callers, plus a wrapper each, read in section 5 (F2).

## 3. What zenoh-pico's step is

- The accept is a future on the runtime its client build already runs (its read and lease tasks
  are futures of the same executor): `vendor/zenoh-pico/src/transport/manager.c` @
  `f._fut_fn = _zp_unicast_accept_task_fn;`, which takes a TCP connection
  (`vendor/zenoh-pico/src/transport/unicast/accept.c` @
  `_z_tcp_accept(&listen_socket, &con_socket)`) up to the build's bound
  (`vendor/zenoh-pico/include/zenoh-pico/config.h.in` @ `#define Z_LISTEN_MAX_CONNECTION_NB 10`).
- The peers are a list on the heap, one transport for all of them, one transmit lock
  (`vendor/zenoh-pico/src/transport/common/tx.c` @ `_z_transport_tx_mutex_lock(`), one batch
  encoded once and written to every peer's socket (`vendor/zenoh-pico/src/transport/common/tx.c` @
  `static z_result_t _z_transport_tx_flush_buffer(`).
- The read task waits on every peer's socket
  (`vendor/zenoh-pico/src/transport/unicast/read.c` @
  `return _z_socket_wait_readable(&iter, Z_CONFIG_SOCKET_TIMEOUT);`); the lease task walks the list
  (`vendor/zenoh-pico/src/transport/unicast/lease.c` @
  `_z_transport_peer_unicast_slist_extract_all_filter(ztu->_peers, &dropped_peers,`).
- A new peer is pushed every declaration once and `DeclareFinal` of interest 0
  (`vendor/zenoh-pico/src/session/interest.c` @ `_z_interest_send_declare_final(zn, 0, peer)`);
  a unicast Interest is not answered (`vendor/zenoh-pico/src/session/interest.c` @
  `// Nothing to do on unicast`).

Each wz face is a link session of its own, read where it lies (`docs/c-abi-architecture.md`
section 8): its machine, lease, sequence numbers, reassembly Router, read slot and send place, and
the tables of its peer's declarations the routing reads. That is the architecture's contract, not a
form, and it is most of what is left in section 6.

## 4. Behaviours zenoh-pico lacks: switches

Each is a capability of `deploy/wz-config.toml` (`[[capability]]`, `upstream_off = ["zenoh-pico"]`,
`abis = ["core", "pico"]`), on in a build that names nothing, off in the zenoh-pico preset, on in the
release profiles. The bytes are the peer case's in the zenoh-pico preset; the release case
`pico-api-coop-nostd` keeps each, 0.

| | capability (Kconfig) | on: what wz does | off (zenoh-pico preset): what the peer does instead | bytes off, peer case | receive Ir | turns red |
|---|---|---|---|---:|---|---|
| W1 | `accept-cookie` (`WZ_CAP_ACCEPT_COOKIE`) | a stateless acceptor: the `InitAck` carries the negotiated state sealed (HMAC-SHA256) and read back from the `OpenSyn` | an empty cookie, the state held by the accepting link's session until its `OpenSyn`, a half-open link bounded by `MAX_ACCEPT_PENDING`, as `feat-peer.md` section 4.1 sets out | -7,000 to -9,000 (G3, and G3's lines in G5 and G7) | none: the handshake only | an `OpenSyn` on a link no `InitAck` state is held for is refused; a build without it holds no `decode_accept_cookie` (the cost gate's FORBIDDEN rule) |
| W2 | `link-admission` (`WZ_CAP_LINK_ADMISSION`) | one link to a remote node when both dial | each link a face of its own | -1,500 to -2,300 (G4) | none: at the handshake | two crossing dials make two faces without it, one with it |
| W6 | `face-send-places` (`WZ_CAP_FACE_SEND_PLACES`) | each face its own send place: a publish to one face does not wait behind a send on another, a droppable one passes a held face over; an operation holds every face's place (`CoopEngine::live_on_link`) | one send place for every face, as zenoh-pico's one transmit lock: an operation holds that place and the session's lock and runs in its caller (the dial form's `hold_dial`), a publish writes each face under it; `HeldOperation`, `hold_faces_from`, the per-face `try_leg` and `wait_leg` and the held chain (`HeldSend`) are not compiled | -3,000 to -5,000 (the held operations' wrappers 2,100 to 2,900, `hold_faces_from` 341, `fan_out_in` 545, the per-face legs) | none per message: the read's slots are each face's still | a publish to two faces takes one place (`Takes::place_tries`); the cost gate FORBIDS `HeldOperation` in `pico-peer-coop` |
| W3 | `udp-listen` (landed) | a `udp/` listener | refused by name | 0 here: already out of the case | | as landed |
| W4 | `interest-answer` (landed) | answers a peer's unicast Interest | answers none | 0 here: already out of the case | | as landed |

**W5 is not a capability.** `feat-peer.md` section 4.1 planned `runtime-plan` as a capability whose
off form needed its S3, a listening session laid out in a region the build fixes. The storage ruling
of 2026-11-27 decides the zenoh-pico preset's form instead: `OnUse`, each table's memory taken at
its first row, no plan, no region and no lender (`heap-native.md` sections 3.1, 9.1 and 11). A region
for a listening session would give that preset a form its ruling does not choose, so S3 is withdrawn.
The plan's bytes leave the like-for-like case when the on-use open covers `runtime-plan`
(`heap-native.md` section 10.2, the peer twin `pico-peer-coop-on-use`): each face's tables counted
at its attach, the registry made by value. Expected on that twin against today's peer case: -12,000
to -16,000 of G2 (the plan, the lend, `RegistryOf<ManyHolders>::new`, the lent pools); each face's
tables made at its attach stay. The release keeps D12 and the plan.

## 5. Form: structural steps

Ordered by the like-for-like case (the peer case in the zenoh-pico preset's form: on-use storage,
W1, W2 and W6 off), which is the comparison the owner's ruling names; the release case's column
says where a step is larger there.

| step | what changes | peer case, B | release case `pico-api-coop-nostd`, B | receive Ir, and why | turns red | owner |
|---|---|---:|---:|---|---|---|
| **F1 (landed with this note)** | the runtime's task table of a build whose read steps every face itself is no table (`RuntimeForm::Taskless`) whether it dials, listens or reads on a thread: chosen by the fact that no link runs as a task (`not(wz_round)`), not by the feature `listen` or `threads`; a build that joins groups keeps its cells | -2,500 to -2,700: `run_among` 1,209, `claim_among` 540, `drop_among` 341, `settle` 160, `classify` 147, the wakers 67, `TaskCell::write_owned` 53, `RuntimeTables::runtime`'s 240, less the no-cell table's 102 | 0: it joins groups, whose sessions are tasks | none: the direct form runs no pass (`Core::run_tasks` is `wz_round`'s), and the read never calls the executor | `tests::direct_runtime::a_listening_session_whose_read_steps_its_faces_opens_a_runtime_of_no_cell` | this lane |
| F4 | the accepting session machine of the reactive class: its eventless step from `SentOpenAck` to `Established` made an evented one in its SCXML source, so the reactive turn SCE is asked for (`docs/win-budget/size.md` section 10.3) covers the accepting build too | -1,500 to -2,500 (`Turn::run` 664 -> 1,336, `event_queue` +502, the general turn's other bodies) | -1,500 to -2,500 | per transport event fewer checks, never per sample | `machine_class_tests` with `session-unicast-accept`: the accepting machine of the class | the SCXML source here, the turn SCE's |
| F5 | the read of many faces: `read_faces`, `wait_on_faces` and `face_turn` hold 10,949 against the client's 5,008 for the same face's turn; the inlined attribution of the three bodies says which part is the walk and which a form | to be measured; at most -3,000 | as the peer case | to be held to none | the read's tests over several faces | this lane, after a measurement cell |
| F2 | the held operations as one hold and the operation in its caller where every face keeps its send place (W6 on): each face's hold kept by its site and let go of in reverse by one guard's drop, the held face found by a mark in the face rather than by the chain on the stack | 0 in the zenoh-pico preset (W6 off compiles none); today -2,100 to -2,900 (11 copies, 8,745 B: `declare_write_filter` 2,354, `undeclare_subscriber` 1,916, `declare_subscriber_on_wire` 1,126, `face_turn`'s replay 991; eight of them measured at 2,137 B over their client callers) | -4,500 to -6,000 (21 copies, 22,902 B) | none: an operation is a declaration, a query or a reply, never the read; `face_turn`'s replay hold is a turn's, not a message's | `direct::held_operation_tests`, the engine's declaration tests over faces | this lane; the send place's protocol is `wz-runtime-coop`'s `FaceSite` |
| F3 | the plan form's lend by a description walked once (as the region's `place_region` walks `RegionLines`), not each table's constructor inlined into the registry's | 0 on the on-use twin (no plan); today -4,000 to -7,000 (`RegistryOf<ManyHolders>::new` 4,925, `ArenaPlan::lay_out` 2,284, `lend_set` 1,286, `pool_rows` 616) | -4,000 to -7,000 | none: the open only | the arena's plan tests, and a description's lines test as the region's | the arena's owner (D12 form) |
| F6 | one UDP driver for a dialled socket and a port's peer (`feat-peer.md` S2) | 0 (`udp-listen` off) | -1,500 to -2,500 (`UdpDriver<PortPeer<..>>` 3,699 beside `UdpDriver<PosixUdpSocket>` 1,836) | none: `recv_with` an arm per socket kind | the driver's tests over both sockets | lane T-LINK |

No two forms of one thing are compiled side by side in the peer case: the client's region and the
peer's plan are one each (`capi_coop::region` leaves with `listen`), and the session tables are
over `Lent` alone (33 bodies, no `Region` instance). F1 is a form chosen by a feature where the fact
it stands for is another (over-generalization); F2 and F3 are per-type copies; F5 is to be read.

## 6. The target, and how far the steps reach

**Target: the like-for-like `peer` step at most 10 times zenoh-pico's**, one decimal order: at most
37,920 B against 3,792 on the API chain's step, read on the zenoh-pico preset's form (on-use
storage, wz's behaviours off), the scout step apart on both sides. Today: 90,861, 24.0 times.

| step | kind | B, expected | mid | step after it, B | times zenoh-pico |
|---|---|---:|---:|---:|---:|
| today | | | | 90,861 | 24.0 |
| storage on-use covering `runtime-plan` (`heap-native.md` N3c) | preset axis | 12,000 to 16,000 | 14,000 | 76,861 | 20.3 |
| W1 `accept-cookie` off | switch | 7,000 to 9,000 | 8,000 | 68,861 | 18.2 |
| W6 `face-send-places` off | switch | 3,000 to 5,000 | 4,000 | 64,861 | 17.1 |
| F1 (landed) | form | 2,500 to 2,700 | 2,650 | 62,211 | 16.4 |
| F4 the accepting machine's turn | form | 1,500 to 2,500 | 2,000 | 60,211 | 15.9 |
| W2 `link-admission` off | switch | 1,500 to 2,300 | 1,900 | 58,311 | 15.4 |
| F5 the read of many faces | form | 0 to 3,000 | 1,500 | 56,811 | 15.0 |

The steps reach about 15 times, not 10: about 18,900 B are left over the target. What is left, about
56,800 B, and why:

- **The acceptor's handshake and its codecs, about 10,000 (G5 and G7 less W1's and F4's shares):
  counting, a contract of the client build.** wz's client build links no acceptor (`wz-capi-coop`'s
  `listen` off: "the engine is the dial role alone and its text has no acceptor"), so the accepting
  handshake's states, its `InitSyn` and `OpenSyn` readers and its `InitAck` and `OpenAck` writers
  are the `peer` step's. zenoh-pico's client build compiles its accepting handshake
  (`_z_unicast_handshake_listen`, an exported function) and those codecs, so its step counts none of
  them. Read in the same column (the acceptor in both client cases, or out of both), the step is
  about 46,800, 12.3 times.
- **Each face a session of its own, about 22,000 (G1 less F1, F5 and W6's share, G2 less on-use's
  share, G9): contract of the architecture.** Each face keeps its machine, lease, sequence
  numbers, Router, read slot and send place, and the tables of its peer's declarations, made at its
  attach under on-use; zenoh-pico's peers are list entries of one transport. That is
  `docs/c-abi-architecture.md`'s P2 and section 8 (every face read where it lies), which a form
  step does not undo.
- **The listener and the links, about 9,000 (G6 less the scout's host calls): mostly the same work,
  its excess the link layer's form**, which lane T-LINK owns (`docs/win-budget/size.md` section 9,
  the closed set of links; section 3.4, the dial's open as one body).
- **What a new face is told, the engine's own and the language lines, about 15,000 (G8, G10 less
  W6's share, G11): the same work and the lines inlined in the bodies above**, which fall with them.

So the 10-times target needs, beyond these steps, the counting decision (an owner's: whether the
size ledger reads the acceptor in the client cases of both libraries; 12.3 times with it) and about
8,900 B more from F5's and lane T-LINK's residuals, which are measured before they are promised; the
per-face sessions are the architecture's and stay.

## 7. The step landed with this note: F1

`RuntimeTables::form` (`crates/wz-capi-coop/src/engine.rs` @
`pub(crate) const fn form(groups: usize) -> RuntimeForm`) chose the runtime's task table by the
features `listen` and `threads`. In the direct form
(`not(wz_round)`: a build without `threads`, or with `threads` where each value has a lock of its
own), no link runs as a task: the read steps every face where it lies (`place_wire` makes a link's
session in its read slot, `CoopEngine::accept_links` takes each connection off its ports in the
read), and `RuntimeTables::of` reserves no cell (`of_groups` holds 0 tasks). Yet a listening build
made its runtime `Reserved`, so the walks of a table of many cells (`ExecutorState::run_among`,
`claim_among`, `drop_among`, `settle`, `classify`, the waker table) were linked for a table of
none, and a `threads` build made it `ForOne` and linked the one-cell walks. The form is now
`Opening` for a build that joins groups, whose sessions are tasks; `Taskless` for the direct form;
and, where each link runs as a task, `Reserved` for a listener and `ForOne` for a dial role.

- A spawn on a `Taskless` runtime is refused, counted, as a reserved table of no cell refused it, so
  nothing a program or the engine sees changes; the runtime's span is the one-cell layout of no
  cell, laid out and placed by the same `form`.
- Expected: `pico-peer-coop` -2,500 to -2,700 in the driver area; `pico-client-coop-nostd` and
  `pico-api-coop-nostd` unchanged; a `threads` build of the direct form that joins no group (a
  pico library with `multi-thread` and without `multicast-transport`) loses the one-cell walks too.
- Receive Ir: unchanged. No pass of the runtime runs in the direct form (`Core::run_tasks` is
  `wz_round`'s); the read never reaches the executor.
- Tests: `tests::direct_runtime` is compiled in every build of the direct form that joins no group
  (`not(any(wz_round, feature = "group"))`), not only in a build without `threads` and `listen`.
  `a_listening_session_whose_read_steps_its_faces_opens_a_runtime_of_no_cell` asserts `form` is
  `Taskless` for a listening config and that its placed runtime refuses a spawn, counted: red on the
  old `form` in any `listen` build. `a_session_whose_read_steps_its_link_opens_a_runtime_of_no_cell`
  asserts the same of the client's config: red on the old `form` in a `threads` build. A `wz_round`
  build keeps its tables and their tests (`tests::runtime_tables`, `tests::admission_heap`).

## 8. Verification (the main session's)

- Build and clippy of `wz-capi-coop` with its defaults (`threads`, the direct form), with
  `--no-default-features --features std,key-matching-listener,listen,query,queryable`, with `listen`,
  with `group`,
  and with `listen` under `WZ_COOP_VALUE_LOCKS=off` (the `wz_round` form); of `wz-capi-pico` with
  `os-host,link-udp,peer` and with its defaults.
- `cargo test -p wz-capi-coop --lib direct_runtime`: 2 tests (the defaults).
- `cargo test -p wz-capi-coop --lib --features listen direct_runtime`: 2 tests.
- `cargo test -p wz-capi-coop --lib --no-default-features --features std,key-matching-listener,listen,query,queryable direct_runtime`: 2 tests.
- `cargo test -p wz-capi-coop --lib --features group direct_runtime`: 0 (not compiled).
- `WZ_COOP_VALUE_LOCKS=off cargo test -p wz-capi-coop --lib --features listen runtime_tables`: the
  task form's tests as before, and `admission_heap` in the same build.
- Layer C1cs: `pico-peer-coop` lower by 2,500 to 2,700 in the driver area, `nm -C` of its library
  holding `ExecutorState::claim_none` and no `run_among`, `claim_among` or `drop_among`;
  `pico-client-coop-nostd` and `pico-api-coop-nostd` unchanged.
- The perf matrix's receive arm on `pico-client-coop-nostd`: its receive Ir as its last reading.
- `python3 scripts/lib/size_ledger_gate.py --per-feature pico-api-coop-nostd pico-peer-coop` again,
  so the head of `feat-peer.md` reads the step without W3, W4 and S1.

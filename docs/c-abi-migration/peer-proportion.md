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
| **F4 (landed, section 9.1)** | the accepting session machine of the reactive class: its eventless step from `SentOpenAck` to `Established` made an evented one in its SCXML source, so the reactive turn SCE is asked for (`docs/win-budget/size.md` section 10.3) covers the accepting build too | -1,500 to -2,500 (`Turn::run` 664 -> 1,336, `event_queue` +502, the general turn's other bodies) | -1,500 to -2,500 | per transport event fewer checks, never per sample | `machine_class_tests` with `session-unicast-accept`: the accepting machine of the class | the SCXML source here, the turn SCE's |
| F5 | the read of many faces: `read_faces`, `wait_on_faces` and `face_turn` hold 10,949 against the client's 5,008 for the same face's turn; the inlined attribution of the three bodies says which part is the walk and which a form | to be measured; at most -3,000 | as the peer case | to be held to none | the read's tests over several faces | this lane, after a measurement cell |
| F2 | the held operations as one hold and the operation in its caller where every face keeps its send place (W6 on): each face's hold kept by its site and let go of in reverse by one guard's drop, the held face found by a mark in the face rather than by the chain on the stack | 0 in the zenoh-pico preset (W6 off compiles none); today -2,100 to -2,900 (11 copies, 8,745 B: `declare_write_filter` 2,354, `undeclare_subscriber` 1,916, `declare_subscriber_on_wire` 1,126, `face_turn`'s replay 991; eight of them measured at 2,137 B over their client callers) | -4,500 to -6,000 (21 copies, 22,902 B) | none: an operation is a declaration, a query or a reply, never the read; `face_turn`'s replay hold is a turn's, not a message's | `direct::held_operation_tests`, the engine's declaration tests over faces | this lane; the send place's protocol is `wz-runtime-coop`'s `FaceSite` |
| F3 (in steps: sections 9.3, 9.4) | the plan form's lend by a description walked once (as the region's `place_region` walks `RegionLines`), not each table's constructor inlined into the registry's | 0 on the on-use twin (no plan); today -4,000 to -7,000 (`RegistryOf<ManyHolders>::new` 4,925, `ArenaPlan::lay_out` 2,284, `lend_set` 1,286, `pool_rows` 616) | -4,000 to -7,000 | none: the open only | the arena's plan tests, and a description's lines test as the region's | the arena's owner (D12 form) |
| **F6 (landed, section 9.2)** | one UDP driver for a dialled socket and a port's peer (`feat-peer.md` S2) | 0 (`udp-listen` off) | -1,500 to -2,500 (`UdpDriver<PortPeer<..>>` 3,699 beside `UdpDriver<PosixUdpSocket>` 1,836) | none: `recv_with` an arm per socket kind | the driver's tests over both sockets | lane T-LINK |

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

## 9. The steps landed after F1, and where F3 stands

### 9.1 F4: the acceptor's OpenAck on the OpenSyn's own step

`sources/session/session_fsm_unicast.scxml` had `Accepting.SentOpenAck`, entered by the admitted
`open_syn.received` (its entry sending the OpenAck) and left at once by an eventless transition to
`Established`: `docs/session-fsm.md` section 2.2 gives that state an immediate exit, so no event
ever found it current (`drive.rs`'s `awaited_in` said so). It was the machine's only eventless
transition, and it kept the accepting build's session machine out of the reactive class. The state
is now the transition's effect: `SentInitAck` takes `open_syn.received` to `Established` with
`send_open_ack` on the transition. The order of effects is the same (the OpenAck, then
`Established`'s entry; neither `SentInitAck` nor `Accepting` has an exit action), the admission
of the OpenSyn is the dispatcher's as before, and the accepting deadline keys on the two
`Accepting` children left (`session_timeouts`). The generated machine
(`out/wz-session-core/session_fsm_unicast_sm.rs`) was regenerated with the pinned generator (the
store's build of `vendor/sce` at its pin, the xtask's arguments and strip); the regeneration also
carries three `compile_error!` guards the feature model gained since the file was last made, each
already implied by the crate's own features.

- What SCE provides at the pin, read from `vendor/sce`: the reactive turn of ADR 0148 is there.
  `DocumentTables::reactive_class` and `StatePolicy::REACTIVE_TURN` decide it, and
  `Turn::run(initial, reactive)` skips the macrostep completion for a reactive machine. With F4
  every machine the peer case links (session, link, reassembly slot, scouting) is of the class, so
  every call of the one out-of-line `Turn::run` hands it `true`; the general turn's
  `complete_macrostep` and the internal queue's drain have no caller left in the case when the
  compiler folds the constant through the shared body, which the runtime's own comment relies on.
- What SCE is still asked (SCE ADR 0155, an SCE session's): the reactive turn as a body of its own
  for a policy whose `REACTIVE_TURN` is `true` (the compiled reactive machine), so that the general
  turn's bodies leave the image by construction rather than by the compiler's constant
  propagation through an out-of-line function, and section 10.3 items 2 and 3 of
  `docs/win-budget/size.md`. Nothing on the wz side waits on it: the machines' sources are of the
  class and the tests hold them there.
- Expected: `pico-peer-coop` and `pico-api-coop-nostd` -1,500 to -2,500 in transport where the
  fold happens (`Turn::run` back towards its 664-byte client form, the `event_queue` internal
  half); 0 where it does not, until ADR 0155. Receive Ir: per transport event the eventless
  selection and the internal queue's check fewer; never per sample.
- Tests (`wz-session-core`'s `machine_class_tests`):
  `the_session_machine_is_of_the_reactive_class` now runs in every build (it replaced the accepting
  build's test that asserted the eventless step) and asserts the runtime's `reactive_class` beside
  the file's own reading: red, with `session-unicast-accept`, on any accepting state left without
  an event. `the_acceptors_open_syn_takes_it_to_established_sending_the_open_ack` reads the
  OpenSyn's candidate from `SentInitAck`: red on a target other than `Established` or a transition
  with no content. `the_scouting_machine_is_of_the_reactive_class` (`scouting-active`): red on an
  eventless or raising step in the scouting source. `session_timeouts` keeps its accepting tests
  over the two children; `wz-runtime-tokio`'s accepting-path tests assert the same traces as
  before (`send_open_ack` once, Established's entry actions once).

### 9.2 F6: one UDP driver for a dialled socket and a port's peer

`IpLinks` made `UdpDriver<U, ..>` for a dial and an acceptor bound to a port of its own, and
`UdpDriver<PortPeer<U, ..>, ..>` for each peer a `udp/` port took: two instances of the whole
driver and its two tables (`BoxedLinkDriver`, `SessionDatagramLink`). `udp_link::LinkSocket` is
now the one socket type of every datagram link of a stack that listens on `udp/`: `Own(U)` or
`Port(PortPeer<U, N>)`, each call a match on the kind that forwards to the kind's own answer
(the share's `times_out` and `set_receive_timeout` stay `false`, so a peer's link still waits the
tick and never arms the port's socket). `LinkPlace::own_datagram` wraps a socket of the stack's own
where the build listens on `udp/` and hands it on unchanged otherwise, so a build without
`udp-listen` compiles what it compiled before; `LINK_CELL_BYTES` reads the one driver type.

- Expected: `pico-api-coop-nostd` (and every case with `udp-listen`) -1,500 to -2,500 in the
  driver area: `UdpDriver<PortPeer<..>>`'s 3,699 less the matches added to the remaining instance;
  `pico-peer-coop` 0 (no `udp-listen`). Receive Ir: one match on the kind per socket call of a
  `udp/` link, no call added; none on `tcp/`.
- Test: `udp_link::tests::one_driver_reads_a_socket_of_its_own_and_a_ports_share_alike` makes both
  links through one function returning one type, reads a datagram over each, and asserts the share
  answers its own `times_out` and `set_receive_timeout` (`false`) and leaves the port's socket
  unarmed: red on a kind that forwards to the other's path. Compiled with `udp-listen`, with and
  without `udp-port-lent-only` (the port is made over lent rows and slots, which both have).

### 9.3 F3: what reading the plan form found, and the design

The premise holds for part of the bytes and not for the rest. `RegistryOf::new` (the plan form,
`runtime-plan`) builds each table by value through its type's `lent` (`App::lent`,
`PeerPools::lent`, `Gets::lent`, `FaceTables::lend` through `lend_set`), each `?` after a table
leaving a drop path for what was built before it, and moves them into the registry; the region form
(`placed.rs`) places the zeroed registry by one walk of `RegistryRegion::places`. But the plan
form's lends already go through one untyped, out-of-line body (`Arena::lend_rows`,
`TableLender::lend_stride`), and a share of the bodies named for F3 is not placement at all:
`ArenaPlan::lay_out` and `pool_rows` are the plan's own count, which a description of the lend does
not remove; the pools' hand-out (`keep_rows_in`), the spare sets reserved for faces to come
(`adding::SpareSets`) and the declaration watches are values built at the open, not rows placed.

The design that closes it is one description for both forms, not a second family beside the
region's: each table type's `places` gives, for each of its sequences, the sequence's offset, its
row's stride and alignment, and which count of the plan sets its room (a count slot), and its key
handles; the region form reads each room as its type's constant and its rows at the region's
offsets, as now, and the plan form lends each line's rows from the arena in order and reads its
room from the plan's counts, writing the sequences of a registry placed zeroed where it lies, as
`place_region` does. The plan's byte count is then the same lines summed (one fact in one layer:
`arena_bytes` of each type goes), and `RegistryOf::new` becomes `write_parts`, one walk and
`bind`, the form `placed.rs` has. It touches the fifteen `places` of `wz-session-core`'s tables
(`session_tables`, `slot_observer` twice, `peer_tables`, `reply`, `reply_stage` twice,
`reply_hold`, `slot_map`, `decl_sink`, `pubsub`, and the `declare` tables), `RegionLines` and
`place_seqs`, the arena plan's count of the registry's rows, and the registry's two forms. It is
the next step of this lane: it was not written blind in this run, because every line of it is a
layout the region's and the plan's tests must hold together, and the plan form is the release
case's (`pico-api-coop-nostd`); a description wrong in one offset writes a sequence over another.
Expected as section 5 says (-4,000 to -7,000 on the release case, 0 on the on-use twin, which has
no plan); receive Ir none.

### 9.4 F3: the steps landed, and the ones left

The description is now one: a line of it (`bounded::SeqPlace`) states where a table's sequence
lies, the bytes of one row (`stride`), the build's bound (`room`, which a region keeps and a plan
lends at most) and which count of a plan sets the rows it is lent (`count`, a `bounded::RowCount`
slot), beside the region's offset of the rows. A region walks it by `place_seqs` as before; a plan
walks the same lines by `lend_seqs`, each line lent the next span of the arena, and counts them by
`seq_bytes`, the lines summed, so the lend and the count of a table are one fact.
`key_arena::lend_region` is `place_region`'s plan form, the key handles joined by one body for
both. The fifteen descriptions are written over `bounded::LaidOut` (the two policies whose
sequences are `LentSeq`), so `Lent` and `Region` read one const fn each; a type's region rows
struct is generic over the policy with `Region` the default, standing only for the region's
offsets in the plan form.

| commit | what it did | what its tests hold |
|---|---|---|
| `abe9ff7cd4` | the line's `stride` and `count`, `lend_seqs`, `seq_bytes`, `seq_rows`; lines in 32 bits; `SessionTables::lent` and `arena_bytes` read `SessionTables::places` (the per-table `Presence::lent_from`, `LentTable` and `kept_bytes` go) | `bounded::tests::a_plan_lends_the_description_a_region_places` (each table at the offset the count says, a count past the room refused and every later table rowless); `session_tables::tests::lent_tables_lie_where_their_description_counts_them` (the lent and the region's lines agree but for offsets, every line held to a limit, no two sequences or row spans meet, the arena took `arena_bytes`) |
| `2b770ef192` | `Requesters::lent` and `arena_bytes` read `Requesters::places` through `lend_region`; `ReplyRegistry`'s and `LivelinessGetRegistry`'s own `lent` and `arena_bytes` go; counts `Queries` and `LivelinessGets` | `slot_observer::requester_region_tests::lent_requesters_lie_where_their_description_counts_them`, through the shared `bounded::assert_lent_as_described` |
| `90a32d53ae` | the observer's own lists: `DeclObserverPair`, the three watcher tables and `LocalTokenRegistry` describe themselves over `LaidOut` (`LocalTokenRows` and `ObserverRegionRows` generic over the policy), each watcher line counted `DeclWatchers`, the tokens' `LocalTokens`; `SlotObserverOf::lent` lends the application tables, then one `lend_region` over the observer's description; `SlotObserverOf::arena_bytes(watchers, local_tokens)` is the lines summed and replaces `decl_watcher_bytes`; the per-table `lent`/`arena_bytes` of the pair, the three tables and the token registry go | `slot_observer::lent_tests::lent_observer_lists_lie_where_their_description_counts_them` (offsets, counts, no overlap, `arena_bytes` equal to the lines laid, one key line with `liveliness-token`, a token count past the build's bound refused); `decl_sink::tests::a_lent_pair_refuses_an_observer_past_its_rows` now lends through `lend_seqs` and holds the lines' sum to the two lists' spans |
| `cda04a0c1a` | a face's peer tables: `SubscriberPeer`, `ReplyStage` (`ReplyStageRows` generic), `FinalStage` and `PeerTables` describe themselves over `LaidOut`, the key lines generic too; counts `PendingDeclares`, `Replies`, `ReplyBytes` (a line of one-byte rows) and `Finals` (`PeerRows::counts`); `PeerTables::lend_rows` keeps its keys and pools as before, walks `LINES` (its own lines, the reply stage's two, the Finals') by `lend_seqs`, then lends the side's compose row, which a region keeps inline and so is no line; `arena_bytes` is the lines summed and the compose row; `ReplyStage`'s and `FinalStage`'s `lent`/`arena_bytes` and `SubscriberPeer`'s `lent`/`lend_rows`/`arena_bytes` go (`lend_compose_row` and `compose_bytes` stay, public) | `peer_tables::lent_tests::lent_peer_tables_lie_where_their_description_counts_them` (line count by feature, the reply bytes a stride-1 line, offsets, counts, no overlap, lines plus compose row equal to `arena_bytes` and to the arena's high water); the existing in-place, refusal and over-the-build tests hold the order and the refusals |
| `1db0387513` | the coop plan's row of the observer's lists reads the engine's own observer (`engine::app_list_bytes`, `App::arena_bytes(watchers, 0)`) instead of `SlotObserverOf<HeapSinks, Lent>`: the part of step 4 that needs no step 3 | `tests::arena::the_plan_lays_out_the_watcher_lists_the_limits_state` compares the plan's row with `app_list_bytes` at the build's and a lowered limit |

Size: a line was 24 bytes on a 64-bit target and is 20 now (four `u32` and the count), so the
region's description statics shrink there; on a 32-bit target a line was 12 bytes and is 20, and a
`RegionLines<MAX>` holds `MAX` lines whether it uses them or not, so the region form's statics grow
by 8 bytes a line there (the registry region's description most). The text the two steps take out
is the per-table lends inlined into `SessionTables::lent` (nine `SlotMap::lent_from` and the held
replies' `lend_with`) and into `Requesters::lent` (three `arena.lend`); each `lent` now carries one
description static of its own. Receive Ir: none, the open only.

Size of the two steps after them: the text that goes is the per-table lends the two `lent` bodies
inlined (four `arena.lend` and the three tables' `lent` wrappers in the observer, four in a face's
peer tables), each `lent` now one walk over one description static of its own; the plan's counts
are the same bytes as before, in the same order for the observer and with the side's compose row
moved after the stagings for a face, which no count reads. The region form's lines now carry their
count; a region ignores it. Receive Ir: none, the open only. The coop plan still counts the
watchers by `HeapSinks`' row type, not the engine's own, which over-counts a build whose watcher
sink is a unit; `1db0387513` closes it (the row shrinks by `MAX_DECL_OBSERVERS` times the difference of
the two sinks' rows, per list, where the build installs no watch). What `peer-row-pools`
keeps in the session's pools is no line of a face's: the pools stay `PeerPools::lent`, and
`keep_rows_in` stays the hand-out.

Left, in order, each a step of its own over the same line:

3. Landed (section 9.5): the registry's plan form walks its own lines and the dial face's set at
   the open; the sets of the places no face took yet are walked when a face first takes each.
4. `ArenaPlan`'s count of the registry's rows read as the same lines summed (`seq_bytes` of
   `RegistryOf::LINES` and `FaceTables::arena_bytes`), so `app_list_bytes`, the per-set
   `PeerTables::arena_bytes` and `FaceGets::arena_bytes` and the `FACE_SET_BYTES` and
   `HELD_SET_BYTES` rows go from the plan, and with them the last run-time readers of the per-type
   description statics (`SlotObserverOf::LINES`, `PeerTables::LINES`, `Requesters::LINES`). The
   plan's rows by part (`ArenaPart`) are a report other readers use; they are kept, each counted
   from the lines of its part, so the step changes how they are counted and not what they say.
5. The description statics on a 32-bit target (section 9.6); measured before it is chosen.

What reading the registry for step 3 found, before any of it was written:

- Not every set is a line of the open. `SpareSets::reserved` splits one span for the sets of the
  places no face took yet and builds each when a face first takes its place (`build_to`), so the
  pages of sets for faces that never come stay unresident; one walk at the open would write them.
  The plan form's walk is therefore the registry's own lines (the application's tables and lists,
  the sets' table, the held index, the owed tokens' table, the session's own gets) and the dial
  face's set, and each later set is one walk of the set's description by `lend_set`, as now.
- Not everything the open lends is a line: `PeerPools::lent` (the pools, their directory and key
  ids), `H::lent` (the held index, a table of `FaceId`, which is a line) and `DeclWatches::under`
  are values or spans with a hand-out of their own; the pools stay a lend of their own beside the
  walk, as section 9.4 step 2 left them.
- The set's description differs by form: `placed.rs`'s `FaceTables::places` lays the reply stage no
  rows (the region stages replies outside the session's lock) and lives only in the region build.
  Section 9.5 settles it the other way from the one first read here: the plan lends that stage no
  row either (`arena::peer_rows` states `replies` and `reply_bytes` 0 for every build of this
  engine), so the one description has no reply line, rather than a line lent zero rows.
- Order: the open lent the application, the pools, the owed table, the sets' table, the held
  index, the dial set, the spare span, then the session's own gets. The plan's total does not move
  with the order (every span starts on the arena's alignment); section 9.5 gives the new one.

### 9.5 F3 step 3: the registry lent by one walk of its description

| commit | what it did | what its tests hold |
|---|---|---|
| `278ddeab46` | `engine/registry/described.rs` holds the descriptions both laid-out forms read. A set's (`FaceTables::places`): its peer's stagings, its Finals where the build answers queries, its gets where it asks them, and no reply stage. The registry's (`RegistryOf::places`): the application's lists (`SlotObserverOf::places::<0>`, the session's own tokens being rows of its table set) and tables (`SessionTables::places`), the sets' table (`RowCount::FaceSets`), the index of their holders where the form keeps one (`Holders::LINES`, counted `FaceSets`), the owed tokens' table where faces go (`RowCount::OwedTokens`) and the session's own gets. The region's description (`placed.rs`) is `RegistryOf::places` over its rows (`RegistryRowsAt`) and each set's `FaceTables::places`. `RegistryOf::new` lends the pools, the reserve of the sets to come, then the registry made of no rows (`SlotObserverOf::over(SessionTables::rowless())`, `Holders::rowless`) by one `lend_region` over `RegistryOf::LINES` under one `RowCounts` (the tables', the lists' by `SlotObserverOf::list_counts`, the gets', the sets', the owed tokens', joined by `RowCounts::and`), then holds the tables to the limits, names the index's rows (`Holders::hold_sets`) and lends the dial face's set. `FaceTables::lend` is one `lend_region` over the set's description and the row its peer's side composes keys in; `FaceTables::arena_bytes` is those summed, which `SpareSets::reserved` reads. `App::lent`, `Gets::lent`, the three `arena.lend` of the sets, the index and the owed table, `Holders::lent` and `PeerTables::lend_rows` leave the open. | `registry::tests::every_table_of_the_registry_lies_where_its_description_counts_it` (every line of the registry at the offset the count of the lines before it says, each table its count, no two sequences or row spans meet, `seq_bytes` of the lines what the walk took; the dial face's set from the first byte past the registry's rows; the reserve right before the registry's rows; a set built when a face comes laid as the dial face's). `a_registry_of_one_face_lies_where_its_description_counts_it` (the form of one face describes no index line, and lays out as described). `a_count_past_a_lines_room_refuses_the_open` (`liveliness`: one own token counted is `OverCeiling { rows: 1, ceiling: 0 }`, none is the CONTROL). `bounded::tests::joined_counts_state_each_parts_count`. The region's tests (`a_state_regions_lines_lie_inside_it_and_name_nothing_twice`, `placed::tests`) hold the region form over the shared functions. |

The lines whose change turns each new test red: in `RegistryOf::places`, the sets' line counted
other than `RowCount::FaceSets` or `.with(&H::LINES, ..)` left out (the first test: a table not at
its counted offset, the index's rows not lent); `App::places::<0>` made `::<{ MAX_LOCAL_TOKENS }>`
(the refusal test); the reserve split off after the walk in `RegistryOf::new` (the first test's
reserve assertion); a holder line in `OneHolder::LINES` (the second test); `RowCounts::and` adding
the two counts or keeping one side (its test).

What changes for the engine: nothing a session sees. The open's spans lie in another order
(pools, reserve, the registry's lines, the dial face's set and its compose row), the total the
same. A face's reply stage and, without `queryable`, its Finals stage are no line now where they
were lines lent zero rows; either is a stage of no room, which refuses and counts what it is handed
as before. The registry's own tests lent a face one reply and one Final in every build; they lend
no reply now, and `holds_one_final` asserts a stage of no room in a build that answers no query.

Size, expected on `pico-api-coop-nostd` and `pico-peer-coop`: text -1,500 to -3,500 (the
by-value observer `App::lent` built with a drop path after each table, the own gets' `Gets::lent`,
three `arena.lend` and `Holders::lent` out of `RegistryOf<ManyHolders>::new`; `Gets::lent` by
value and `PeerTables::lend_rows` out of `lend_set`), against +600 to +1,200 of read-only data
for the two description statics the walks read (`RegistryOf::LINES`, `FaceTables::LINES`, each a
`RegionLines<MAX>` of 20-byte lines and word-sized key offsets) while the per-type statics stay
read by the plan's count until step 4. 0 on the on-use twin, which has no plan. Receive Ir: none,
the open only.

### 9.6 Step 5: the description statics on a 32-bit target, prepared for both readings

A line (`SeqPlace`) is 20 bytes on every target, four `u32` and the count. A `RegionLines<MAX>`
holds `MAX` lines and `MAX` key offsets (`usize`) and two counts whatever it uses, so each
description static carries the unused tail of its bound; on a 32-bit target a line was 12 bytes
before the line took its stride and count. The reading asked of the main session: the i686 build of
`pico-api-coop-nostd`, the bytes of each `RegionLines` static (`nm -S --size-sort` on the
library, the symbols of the `LINES` and `DESCRIPTION` consts), and the library's read-only data
against the same build at `99c88e8372`.

- If the statics are material there (their growth over the 12-byte form more than the text step 3
  took out on that target): each description read at run time becomes a static of exactly the
  lines and key offsets it uses. `RegionLines` gains `const fn trimmed<const SEQS: usize, const
  KEYS: usize>(&self) -> Described<SEQS, KEYS>`, the counts read from the description itself
  (`DESC.seq_lines().len()`, `DESC.key_lines().len()`) in the item that names it, key offsets
  held as `u32` as the lines' are; `place_region` and `lend_region` take the trimmed form's
  slices. The unused tail goes on every target, the 64-bit one too. Its test: each trimmed static
  states the description's lines and key offsets in order, and a description of none is a static
  of none.
- If they are within the noise of that build: no change; the reading is recorded here and step 5
  closes. Trimming the tail is then a size step of its own only where a 64-bit reading shows it.

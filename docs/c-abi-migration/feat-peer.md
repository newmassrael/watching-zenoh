# Feature `peer`: what it costs wz and zenoh-pico, and where (feat-peer)

The size ledger's per-feature reading (`size_ledger_gate.py --per-feature`, branch
`size-per-feature`, 2026-11-27, zenoh-pico pin `6a881c21dad1`, its version 1.10.2) steps each
feature onto the minimal case `pico-client-coop-nostd` (`os-host`, `link-udp`). Turning on
`peer` costs wz far more than `Z_FEATURE_UNICAST_PEER` costs zenoh-pico:

| chain | step | wz | zenoh-pico |
|---|---|---:|---:|
| `pico-api-coop-nostd` (after `scout`) | `peer` | +104,075 | +3,792 |
| `pico-peer-coop` (from the client case, `scout` with it) | `peer` | +158,099 | +8,642 |

By area, the API chain's step: sessions +47,779 against +149, driver +29,340 against +507,
transport +9,167 against +2,912, language +9,408 against +224, codec +3,576 against 0,
unclassified +3,491. This note pairs what wz adds with what zenoh-pico does for the same job, says
which difference is the work itself (an owner's decision of contract or preset) and which is the
form the code takes (a structural step), and lands the first structural step.

## 1. Readings

| what | source | how read |
|---|---|---|
| bytes by area, each step | the per-feature report of both chains (`size-ledger/per-feature-pico-api-coop-nostd.json`, `per-feature-pico-peer-coop.json` under the cost gate's target directory) | as the ledger reads them: line tables, inline frames |
| bytes by body, the `peer` step of the API chain | the step libraries of the same run, `pico-client-coop-nostd+scout` and `pico-client-coop-nostd+peer` (the build of `os-host,link-udp,scout,peer`, read once for both chains) | `nm -C -S` of each, every text symbol's size, the two diffed by name: +104,075, the same total as the ledger's |
| zenoh-pico's own bodies | the reference libraries of the same steps | `nm -S`, diffed the same way: +3,792 |

The body view counts a body where it lies, so code inlined into a body counts with it; the area
view counts each byte by its source line. The groups below are the body view; a body is named by
its function, so a group's total is good to a few hundred bytes. Neither report names owners
per step: the explain report (`size_ledger_gate.py --explain`) of `pico-peer-coop` and
`pico-api-coop-nostd` is what splits the larger groups further (section 5, S5).

## 2. What zenoh-pico does for `Z_FEATURE_UNICAST_PEER`

- The accept task: `_zp_unicast_accept_task_fn` (552 bytes) takes a TCP connection
  (`vendor/zenoh-pico/src/transport/unicast/accept.c` @
  `_z_tcp_accept(&listen_socket, &con_socket)`), refuses past the build's bound
  (`vendor/zenoh-pico/src/transport/unicast/accept.c` @
  `_z_transport_peer_unicast_slist_len(ztu->_peers) >= Z_LISTEN_MAX_CONNECTION_NB`, 10 in
  `vendor/zenoh-pico/include/zenoh-pico/config.h.in` @ `#define Z_LISTEN_MAX_CONNECTION_NB 10`),
  runs the handshake on that socket to its end (`vendor/zenoh-pico/src/transport/unicast/accept.c` @
  `ret = _z_unicast_handshake_listen(&param, ztu->_common._link,`) and adds the peer to a list.
  The task exists only with TCP or TLS (`vendor/zenoh-pico/src/transport/unicast/accept.c` @
  `(Z_FEATURE_LINK_TCP == 1 || Z_FEATURE_LINK_TLS == 1)`).
- The handshake's accepting side, `_z_unicast_handshake_listen` (655 bytes), answers an
  `InitSyn` with an `InitAck` whose cookie is `_z_slice_null()`
  (`vendor/zenoh-pico/src/transport/unicast/transport.c` @
  `_z_t_msg_make_init_ack(mode, *local_zid, cookie)`): it waits for the `OpenSyn` on the same
  socket, the state in its frame. It is in the client build already (an exported function of
  the library), so the step does not count it.
- The peers are a list on the heap (`vendor/zenoh-pico/src/transport/peer.c` @
  `ztu->_peers = _z_transport_peer_unicast_slist_push_empty(ztu->_peers);`); a batch is encoded
  once and written to every peer's socket (`vendor/zenoh-pico/src/transport/common/tx.c` @
  `static z_result_t _z_transport_tx_flush_buffer(`).
- The read task waits on every peer's socket (`vendor/zenoh-pico/src/transport/unicast/read.c` @
  `return _z_socket_wait_readable(&iter, Z_CONFIG_SOCKET_TIMEOUT);`, +1,197 bytes to
  `_zp_unicast_read_task_fn`); the lease and keep-alive tasks walk the list
  (`vendor/zenoh-pico/src/transport/unicast/lease.c` @
  `_z_transport_peer_unicast_slist_extract_all_filter(ztu->_peers, &dropped_peers,` and
  `vendor/zenoh-pico/src/transport/unicast/lease.c` @
  `_z_transport_tx_send_t_msg(&ztu->_common, &t_msg, ztu->_peers)`); a second connect locator
  is retried by a task (`_zp_add_peers_task_fn`, `_z_add_peers`, 1,132 bytes).
- Declarations: a new peer is pushed every declaration once, with interest id 0 and a
  `DeclareFinal` (`vendor/zenoh-pico/src/session/interest.c` @
  `_z_interest_send_declare_final(zn, 0, peer)`, in `_z_interest_push_declarations_to_peer`);
  an `Interest` that arrives on a unicast transport is not answered
  (`vendor/zenoh-pico/src/session/interest.c` @ `// Nothing to do on unicast`).
- A `udp/` unicast listener does not exist on POSIX: `_z_udp_posix_listen` answers
  `_Z_ERR_GENERIC` (`vendor/zenoh-pico/src/link/transport/udp/udp_posix.c` @
  `static z_result_t _z_udp_posix_listen(`).
- No two links to one remote node are told apart: each accepted or dialled link is a peer of its
  own (`vendor/zenoh-pico/src/transport/peer.c` @ `z_result_t _z_transport_peer_unicast_add(`).

## 3. The pairing

wz's `peer` on the cooperative engine is `wz-capi-coop`'s `listen` and `runtime-plan`:
`listen` brings the runtime's `listen` (the session's accepting role and the `udp/` listener),
`interest-answer` and `peer-row-pools`.

| work | wz bytes | zenoh-pico bytes | verdict |
|---|---:|---:|---|
| accepting handshake: an `InitAck` with a sealed cookie (HMAC-SHA256 over the state the `OpenSyn` brings back), the extensions it negotiates | 7,800 | 655, in the client build | work differs: W1 |
| one link to a remote node when both dial (`link_admission`) | 2,300 | 0 | work differs: W2 |
| a `udp/` unicast listener: one socket, a face for each source | 16,000 | 0 (no listener on POSIX) | work differs: W3; inside it, form: S1, S2 |
| a `tcp/` listener and its accept | 2,100 | 552 and +270 in `_z_new_transport` | same work |
| answering a peer's `Interest` from the session's own declarations (`interest-answer`), and reconciling each face | 7,600 | 0 on unicast; 86 to push declarations once, in the client build | work differs: W4 |
| the session's arena laid out from the config at the open (`runtime-plan`): the plan, the lend of every table, the registry made over it, and the session's tables over lent rows (`bounded::Lent`) in place of the region's | 18,700 | 0 (a heap block per peer; the bound fixed at build) | form for this preset, its remedy a preset decision: W5, S3 |
| the faces' rows in the session's pools (`peer-row-pools`) | 2,700 | the heap | same work under the no-heap rule |
| each operation run with every face's send place held (`HeldOperation`, 11 operations in this step) | 7,100 | 0 (one peer lock around the list) | mostly the lock order a face set needs; residual form: S4 |
| the read of each face, its turn and the open's listeners | 15,700 | 1,197 + 426 + 1,132 | same work, form to split: S5 |
| supervisor, executor, cells, a face's coming and going | 8,000 | the list | same work, form to split: S5 |
| a publish's leg to each face | 4,800 | 0 (one batch to every socket) | partly work: each face names a key by its own declarations; the rest S5 |
| the receive per peer (reassembly per face, the control walk) | 6,300 | in the client build | mostly W1 and W4's lines in the walk |
| the stream link's accepted side, tx lending | 2,700 | in the client build | same work |
| **total** | **104,075** | **3,792** | |

The language area (+9,408) and the unclassified bytes (+3,491) are lines of these bodies (drop
glue, core and alloc bodies inlined into them); they fall with the bodies.

## 4. Owner decisions (the work itself differs)

| | what wz does | what zenoh-pico does | off in the pico preset, what is lost | bytes |
|---|---|---|---|---:|
| W1 | accepts statelessly: the `InitAck` carries the negotiated state sealed (HMAC-SHA256), read back from the `OpenSyn`, with the extensions (QoS, patch, multilink, auth) | an empty cookie; the handshake runs to its end on the accepted socket, its state in the task's frame | a listener that holds no row for a half-open handshake (a burst of `InitSyn` costs nothing) and the extensions zenoh negotiates; a stateful acceptor would hold a row per pending link, bounded by the faces | 7,800 |
| W2 | keeps one link to a remote node when both dial (`link_admission`) | keeps both | two wz peers that dial each other hold two faces and deliver each sample twice | 2,300 |
| W3 | listens on `udp/` (`wz-runtime-coop`'s `udp-listen`, brought by `listen`) | does not on POSIX | accepting a peer that dials `udp/`; the split is a feature of the pico ABI of its own (off in the preset) beside `peer` | 16,000 |
| W4 | answers a peer's `Interest` (current, future, restricted to a key) and keeps the answer current | pushes every declaration once at connect, answers no unicast `Interest` | a zenoh peer or router that asks with a restricted key, or for future declarations, gets them from wz; under pico's form it gets everything once and nothing after | 7,600 |
| W5 | reads the number of faces and every table's rows from the config at the open (`runtime-plan`) | fixes the number of connections at build (`Z_LISTEN_MAX_CONNECTION_NB`) and takes the rest from the heap | a config that raises the faces at the open; fixed at build, the region reserves the build's worst case instead of the config's | 18,700 |

W3 and W5 are preset decisions: wz keeps the capability either way, and the pico preset names it or
not. W1, W2 and W4 change what a peer of the session sees on the wire.

### 4.1 The owner's ruling (2026-11-27): a switch for each behaviour

Each behaviour zenoh-pico does not have is a capability of its own in `deploy/wz-config.toml`
(`[[capability]]`, `upstream_off = ["zenoh-pico"]`, `abis = ["core", "pico"]`), on in a build that
names nothing and off in the zenoh-pico preset, as the send's behaviours (`tx-probe`,
`tx-stream-owed` and their siblings) are. That holds for W1, W2 and W4 as well, though they change
the wire: the pico preset's contract is zenoh-pico's own, so its peer behaves as zenoh-pico's does.
The host profiles over the pico base that ship a library (`host-peer-ext`, its like-for-like
`host-peer`, and `host-peer-raweth`) keep each one as they had it, as they keep the send's: a
behaviour is no door, so `host-peer` holds the same ones as `host-peer-ext`, and
`pico-api-coop-nostd`, built from `host-peer`, keeps their bytes. The case that loses them is
`pico-peer-coop` (`os-host,link-udp,peer` and nothing else), the peer of zenoh-pico's own switches.

| | capability | the cooperative engine's feature | off: what the peer does instead | needs first | bytes off `pico-peer-coop`, expected |
|---|---|---|---|---|---:|
| W5 | `runtime-plan` (as a capability) | `wz-capi-coop`'s `runtime-plan`, no longer implied by `peer` | lays its arena out in the region the build fixes, the faces a build constant (`MAX_FACES`), a config that states another count refused by name (`ArenaLimit::ShapeDiffersFromBuild`), as zenoh-pico fixes `Z_LISTEN_MAX_CONNECTION_NB` | S3 | 10,000 to 18,000 |
| W3 | `udp-listen` | `wz-capi-coop`'s `udp-listen` over the runtime's `udp-listen` and `udp-port-lent-only`; `listen` no longer brings it | refuses a `udp/` endpoint to listen on by name, as a scheme its links do not carry, and accepts over `tcp/` alone | none | 11,000 to 13,000 (the 16,000 of section 3 less S1's) |
| W1 | `accept-cookie` | a session-core feature beside `session-unicast-accept` | answers an `InitSyn` with an empty cookie and keeps the negotiated state in the accepting link's own session until its `OpenSyn`, a half-open link bounded by `MAX_ACCEPT_PENDING`; no HMAC-SHA256 and no cookie codec is linked | the host's classification of an `OpenSyn` against the held state | 7,000 to 8,000 |
| W4 | `interest-answer` | `wz-capi-coop`'s `interest-answer`, no longer implied by `listen` | answers no `Interest` a peer sends on a unicast face, and ends the replay a new face is told with the `DeclareFinal` of interest 0, as zenoh-pico's push to a new peer does | the session core's `session-unicast-accept` without `interest-answer` | 7,000 to 7,600 |
| W6 | `face-send-places` | `wz-capi-coop`'s `face-send-places`, read by its build script | without `threads`, sends to every face under one send place, the session's lock, as zenoh-pico sends to every peer under one transmit lock: an operation runs in its caller and a put is one leg that reaches every face | none | 3,000 to 5,000 |
| W2 | `link-admission` | the engine's admission (`link_admission`, `admission_gate`) under a feature of its own | takes each link as a face of its own, a remote node that dials and is dialled holding two | none | 2,000 to 2,300 |

The order is by size, the largest first, each landed with `pico-peer-coop` lower and
`pico-client-coop-nostd` (bytes, and receive Ir near its W/P of 0.757) unchanged: the client case
compiles none of the six. W5 waits on S3, which is the form its off side takes, so W3 lands first.

**W3 (this branch).** `udp-listen` declared beside `peer`, which it implies; the runtime's `listen`
brings the accepting role alone, and the session's plan lays the udp ports' rows out only with
`udp-listen` (`TransportRows::port_rx`, `port_peers`, `port_rows`, `PlanShape::udp_listens`).
Without it a `udp/` endpoint to listen on reaches `IpLinks::open_listener`'s last arm and the open
is refused with `OpenError::Listen` naming the endpoint and `LinkOpenError::Unsupported`. Held by
`tests::a_build_without_the_udp_listener_refuses_a_udp_endpoint_to_listen_on` (`listen` without
`udp-listen`, with a `tcp/` CONTROL) and, with it, by the udp tests of `tests::listen::` and
`tests::arena::` as before.

**W4 (this branch).** The session core's `session-unicast-accept` stops implying `interest-answer`;
each crate that takes the session core without its defaults and accepts names `interest-answer`
beside the role (`wz-session-mcu`'s `listen` and `adminspace-write`, `wz-session-lwip`'s
`session-unicast-accept` and `adminspace-write`, and the facade's accepting role through the
runtime's new `interest-answer`; the tokio runtime names it already), so nothing but the pico peer
changes. `wz-capi-coop`'s `listen` drops it and `group` keeps it (zenoh-pico answers an
`Interest` on a multicast transport, `vendor/zenoh-pico/src/session/interest.c` @
`// Nothing to do on unicast` being the unicast arm alone). The `DeclareFinal` of the initial
interest, which zenoh-pico sends a new peer after the declarations it pushes
(`vendor/zenoh-pico/src/session/interest.c` @
`_Z_RETURN_IF_ERR(_z_interest_send_declare_final(zn, 0, peer));`), moves from `interest-answer` to
`any(interest-answer, listen)` in `engine/replay.rs`, so a peer without the answer still ends its
push as zenoh-pico's does.

**W2 (this branch).** The admission (`LinkAdmission`, `LinkBook`, `LinkRegistry` as the engine's
`Admission`, the arena's `LinkAdmissionState` row and `SessionLent::links`) and its place in each
link's handshake (`TransportState::admission` and `place_actions`' install, `wz-runtime-coop`'s
own `link-admission`) are gated by `link-admission` in place of `listen`; without it no link is
asked about, so every link that ends its handshake is a face, as each accepted or dialled link is
a peer of zenoh-pico's own (`vendor/zenoh-pico/src/transport/peer.c` @
`z_result_t _z_transport_peer_unicast_add(`). The work form's `admission_gate` stays with
`listen`: what it holds back is a taken link's input until its face is brought up, which a link
that was not asked about needs as much. The dial role's standing by for a node another face holds
(`LinkSupervisor::read_node`) stays too: it reads a handshake that ended at a held node, which
only a peer's own admission refuses, and keeps the dial role from dialling that node again. Held by
`tests::one_thread::listen::a_second_dial_to_a_node_of_one_thread_is_a_face_of_its_own_without_the_admission`
(two faces at each end, the first link the CONTROL) and, with it, by
`a_second_dial_to_a_node_of_one_thread_is_refused` and `tests::one_face::` as before; the arena's
row by `tests::arena::a_listening_session_lays_out_its_link_admission_only_where_the_build_has_one`.

**W1 (this branch).** `accept-cookie` is the session core's (a default), forwarded by
`wz-runtime-coop`'s and `wz-capi-coop`'s (a default of that crate's own build), and named beside
the accepting role by each crate that takes the session core without its defaults and accepts
(`wz-session-mcu`'s `listen` and `adminspace-write` and its tests' acceptor, `wz-session-lwip`'s
`session-unicast-accept` and `adminspace-write`, the facade's accepting role through the runtime;
the tokio runtime holds it through the session core's defaults), so nothing but the pico peer
changes. It gates the `accept_cookie` module, `CookieKey`'s key and its decode, and the stateless
half of the acceptor: the mint at the InitAck, the release of what the cookie carries, the rebuild
at the OpenSyn, and the runtime's draw before an accepted link's handshake. The session machine
is unchanged: its accept guard is an event the host classifies (`cookie_valid`), and without the
feature `SessionLinkActions::fixed_cookie` is always true, so every accept is held as the
`handshake-cookie` policy's `fixed` value holds it, whatever that policy states: the InitAck
carries the session's configured cookie, empty, as zenoh-pico's does
(`vendor/zenoh-pico/src/transport/unicast/transport.c` @
`_z_t_msg_make_init_ack(mode, *local_zid, cookie)`), the nonce slot marks the accept pending, the
negotiated state stays in the link's session, `cookie_valid` admits the OpenSyn that echoes the
configured cookie once, and nothing is drawn for a cookie or for its key. The binding keeps the
session's source only where its acceptor draws (the cookie, or a challenge of `session-extauth` or
`transport-multilink`). `signing_key`'s MAC and the `hmac` dependency stay: nothing calls them
in the off form, the release profiles' LTO keeps nothing no export reaches, and `sha2` is the
credential identity's as well. Held by
`session_actions::bundle_tests::an_acceptor_without_the_stateless_cookie_holds_its_accept` (both
builds: held and admitted without the feature, minted under a dry source and refused with it),
`session_init_params::cookie_key_tests::an_acceptor_that_mints_no_cookie_holds_and_draws_no_key`,
and `wz-capi-coop`'s `tests::an_open_whose_source_gives_nothing_opens_where_no_cookie_key_is_drawn`
beside its twin `an_open_whose_source_gives_no_cookie_key_is_refused_with_the_entropy_refusal`;
end to end, by `tests::one_thread::listen::` in the zenoh-pico preset's form (the engine against
itself, both ends holding their accepts).

**W6 (this branch).** `face-send-places` is `wz-capi-coop`'s (a default of that crate's own
build) and the pico ABI's capability of the same name, which `wz-capi-core` carries by name alone
(the tokio engine sends on each link through a writer of its own). It chooses how the
direct read's sends hold the faces they send on in a build whose read takes faces past the dial
role's (`listen`, `group`), as the crate's build script states it: each face's send place apart
(`wz_face_places`) where the feature is named or the build has `threads`, else one send place for
every face, the session's lock (`wz_one_send_place`). A build whose only face is the dial role's
keeps its own form either way, so the client case is unchanged. That form is not the off form: it
holds the dial role's place alone (`hold_dial`), so in a peer that only listens, whose dial role
holds no link, an operation would send to no face and a put would answer `Ok(0)` having reached
none. The off form is zenoh-pico's one transmit lock for all its peers
(`vendor/zenoh-pico/src/transport/common/tx.c` @ `_z_transport_tx_mutex_lock(`), in two arms.

- Without `threads`, the like-for-like case `pico-peer-coop`: no lock beside the session's. An
  operation runs in its caller under the session's lock alone (`CoopEngine::live_on_link`), each
  of its sends lends its face's link by a try of the face's place (`send_through`, `send_on`),
  and a put is one leg (`CoopEngine::on_faces`) that reaches every face that is up and every
  group the session joined (`FaceTx::reaches`, `FaceTx::reaches_groups`), each face's link lent
  by a try. On the one thread of the form no try finds a place held: the read steps a face's pump
  with that face's read slot held and not its place, hands its records out with the session free,
  and changes a face's place only between operations, so `found_held`'s debug assertion holds in
  this form too, and no put is held behind another send. Not compiled in it: `HeldSend`,
  `UnderHeldFaces`, `HeldOperation`, `hold_faces_from`, `on_face_legs`, `wait_leg`, `try_leg`,
  `on_publish_legs` and `on_groups_leg` with the groups' own legs (`publish_to_groups_on`,
  `put_plain_groups_leg`), `FaceTx`'s chain of holds and `DirectEnd::is_of`, and the answer to a
  held face's place (`behind_held_place`, `dropped_on_face`, `LinkRooms::for_held_place`).
- With `threads`, argued here and not compiled in this step, which keeps each face's place in
  every `threads` build whatever is named, so the multi-threaded library is unchanged: one send
  lock of the session, `S`, in place of each face's place as what a send waits on. The read of
  each face where it lies (`docs/c-abi-architecture.md` section 8) keeps its order: a face's read
  slot first, then the session's lock, under which a face's place is changed only by a try, the
  change it finds held owed to the read (`DirectSlot::pay_site`). The form adds one rule: whatever
  waits on a face's place takes `S` first. An operation and a put hold `S`, then the session's
  lock; the read carries out an owed change holding the face's slot, then `S`, then the place,
  with the session's lock let go of. Every wait is then in the order slot, `S`, session's lock: no
  holder of `S` waits on a read slot, since a send never waits on a read's step; no holder of the
  session's lock waits on `S` or on a face's place, each being a try under it; and a face's place
  is waited on only under `S`. With no wait against that order there is no cycle, and so no
  deadlock. A send's try of a face's place under `S` finds no other holder, as `found_held`
  asserts, and each face's read still steps its pump holding its own slot alone, never `S`: a put
  waits behind another send, as zenoh-pico's put waits for its transmit lock, and never behind a
  read. The form moves the read's own waits on a face's place under `S`, which is a step of its
  own with the threaded read's tests.

Receive Ir: unchanged. No message's receive reaches a send place in any form: the read's dispatch
and its hand-out of records hold none, the one operation the read runs is the replay turn of a face
that came up (`turn_replay`), once for each link, and the client case `pico-client-coop-nostd`
(neither `listen` nor `group`) compiles the dial role's form, which this step does not touch.
Held by `tests::one_thread::listen::a_put_of_a_listener_of_one_thread_reaches_every_face_it_took`
(both forms: a listener that dials nothing puts once and both clients it took hear it, one leg
reaching the two faces without the feature and one leg for each with it; red on an off form whose
put holds the dial role's place alone), and
`tests::direct_receive::an_operation_holds_no_face_place_where_the_faces_share_the_sessions_lock`
(off: the face is reached by a try and its place is free inside the operation) beside its twins
`an_operation_reaches_each_face_through_the_wire_it_holds` and
`an_operation_holds_the_place_of_every_face_with_a_link`; with each face's place, by
`engine::direct::held_operation_tests`, the place tries of
`tests::direct_receive::a_publish_hands_each_face_a_leg_of_its_own`,
`tests::congestion::a_held_face_place_answers_as_a_send_on_that_face` and
`tests::direct_receive::a_session_that_joined_no_group_hands_the_groups_no_leg` as before.

**W5.** The capability is `wz-capi-coop`'s `runtime-plan`, which `config-policy` and `group` keep
implying; `peer` stops implying it once S3 lands. Until then `peer` keeps it, and the capability is
not declared, since a pico build of `peer` without it has no form to compile.

## 5. Structural steps (the form)

| step | change | bytes, expected | receive Ir of `pico-client-coop-nostd` (about 3,066) | held by |
|---|---|---|---|---|
| **S1 (this branch)** | a udp port of the C engine keeps only what its session lent: `wz-runtime-coop`'s selector `udp-port-lent-only`, named by `wz-capi-coop`'s `listen`, compiles the port's rows and read buffers in their lent form alone; the heap form (`BookRows::Own`, `PortRx::Own`, `Held::Own`, `UdpPort::in_book`) is not compiled beside it, and links lent no rows or no slots refuse a `udp/` listener as exhausted | `pico-peer-coop` and `pico-api-coop-nostd` (and every step after `peer` of the API chain) -3,000 to -5,000, driver area: the second arm of every walk of the rows (the drop glues of a port and of a peer's share, 2,313 and 1,016; the read and sort, 3,354; the take and the look for a peer, 1,375 and 462), `PortRows<Heap>::enqueue` (336), the vectors' growth (3 x 99); the client case 0 | none: the client case compiles no port; a port's receive loses an arm and gains no call | `udp_link::a_lent_only_port_keeps_what_its_session_lent_and_nothing_of_its_own`, `ip_stack::a_lent_only_port_opens_over_the_rows_and_slots_its_session_lent_alone` |
| S2 (with `udp-listen` on) | one UDP link driver for a dialled socket and a port's peer: the driver is a copy per socket type (`UdpDriver<PosixUdpSocket>` and `UdpDriver<PortPeer<..>>`, about 3,600 bytes the second), and outside `recv_with` the two do the same | -1,500 to -2,500; client 0 | none: built only with `udp-listen`; a match on the socket kind, no call | the driver's tests over both sockets |
| S3 (W5's off form) | a listening session laid out in the region the build fixes (the face count a build constant, as zenoh-pico's), so neither the plan nor the lent row policy is compiled | -10,000 to -18,000; client 0 | none | the region's tests with faces |
| S4 | the residual of each held operation's frame (about 200 bytes an operation after `arch-mono` M1); measured on the explain report first | -1,000 to -2,500 | none: no operation is the read | `direct::held_operation_tests` |
| S5 | the read and turn of each face, the supervisor and the publish's leg split by owner with the explain report of the two cases, then designed | to be measured | to be held to none | |

S1 removes a form the C library had beside its one reachable form, so it stands whatever W3 comes
to: with `udp/` listening out of the pico preset the step still holds every build that listens on
`udp/`.

## 6. Verification (the main session's)

- Build and clippy of `wz-runtime-coop` with `alloc,session-unicast,udp-listen` and with
  `alloc,session-unicast,udp-listen,udp-port-lent-only` (the docs' sets `heap` and
  `heap-lent-ports`), and of `wz-capi-coop` with `listen`.
- With the selector, 2 tests:
  `cargo test -p wz-runtime-coop --lib --features alloc,session-unicast,udp-listen,udp-port-lent-only a_lent_only_port`;
  the same filter without the selector runs 0, and
  `cargo test -p wz-runtime-coop --lib --features alloc,session-unicast,udp-listen udp` runs the
  heap form's tests as before.
- `cargo test -p wz-capi-coop --lib --features listen`: the listening tests over `udp/`, whose
  ports the open lends.
- Layer C1cs: `pico-peer-coop` and `pico-api-coop-nostd` lower in the driver area;
  `pico-client-coop-nostd` unchanged; `nm -C` of the peer library holds no
  `PortRows<..Heap..>` body.
- The perf matrix's receive arm on `pico-client-coop-nostd`: receive Ir as its last reading.
- For S5: `python3 scripts/lib/size_ledger_gate.py --explain pico-api-coop-nostd pico-peer-coop`
  once `size-per-feature` lands.
- W3: `python3 scripts/lib/wz_config.py --write` (the statement vectors name the new capability),
  then `--check`; build and clippy of `wz-capi-coop` with `listen` and with `udp-listen`, of
  `wz-runtime-coop` with `alloc,session-unicast,listen`, and of `wz-capi-pico` with
  `os-host,link-udp,peer` and with its defaults.
- W3, the refused case, 1 test:
  `cargo test -p wz-capi-coop --lib --no-default-features --features std,key-matching-listener,listen,query,queryable a_build_without_the_udp_listener`;
  with `udp-listen` the same filter runs 0, and `cargo test -p wz-capi-coop --lib --features listen,query,queryable,udp-listen udp`
  runs the udp listener's tests as before.
- W4: build and clippy of `wz-session-core` with `session-unicast,session-unicast-accept,no_std`
  and no defaults (the accepting role without the answer, a combination no build had before), of
  `wz-capi-coop` with `listen` and with `listen,interest-answer`, of `wz-session-mcu` with
  `listen` and of `wz-session-lwip` with `session-unicast-accept`; `wz_config.py --write` and
  `--check` as for W3.
- W4, the refused case, 1 test:
  `cargo test -p wz-capi-coop --lib --no-default-features --features std,key-matching-listener,listen,query,queryable a_listening_build_without_the_answer`;
  the filter `initial_final` in the same build runs the tests of the initial interest's Final
  (`engine::replay`'s and `tests::replay`'s), which a build that listens keeps without the answer.
- W3, Layer C1cs: `pico-peer-coop` lower by 11,000 to 13,000, most in the driver area;
  `pico-client-coop-nostd` and `pico-api-coop-nostd` unchanged (`host-peer` keeps
  `udp-listen`); `nm -C` of the peer library holds no `IpUdpListener` and no `UdpPort` body.
- W2: `wz_config.py --write` and `--check` as for W3; build and clippy of `wz-runtime-coop` with
  `alloc,session-unicast,listen` and with `alloc,session-unicast,link-admission`, of
  `wz-capi-coop` with `listen` and with `link-admission`, the latter also under
  `WZ_COOP_VALUE_LOCKS=off` (the work form), and of `wz-capi-pico` with `os-host,link-udp,peer`
  and with its defaults.
- W2, off, 2 tests:
  `cargo test -p wz-capi-coop --lib --no-default-features --features std,key-matching-listener,listen,query,queryable admission`
  runs `a_second_dial_to_a_node_of_one_thread_is_a_face_of_its_own_without_the_admission` and
  `a_listening_session_lays_out_its_link_admission_only_where_the_build_has_one`.
- W2, on: the same filter with `link-admission` beside them runs the arena's test and
  `tests::admission_heap::`, the filter `a_second_dial_to_a_node_of_one_thread` the refused twin
  alone, and
  `cargo test -p wz-capi-coop --lib --features link-admission,query,queryable one_face` runs the
  three of `tests::one_face::`.
- W2, Layer C1cs: `pico-peer-coop` lower by 1,500 to 2,300 (`rival_says`, `LinkRegistry::reserve`,
  `LinkBook::try_with_order`); `pico-client-coop-nostd` and `pico-api-coop-nostd` unchanged.
- W1: `wz_config.py --write` and `--check`, and `sce_feature_model.py`'s check (the session
  core's model names `accept-cookie`); build and clippy of `wz-session-core` with its defaults,
  with `session-unicast,session-unicast-accept,codec-init-body,codec-open-body` and no defaults,
  and the same with `tx-lend-only` and with `session-fixed-storage`; of `wz-runtime-coop` with
  `alloc,session-unicast,listen` and with `accept-cookie` beside them; of `wz-capi-coop` with
  its defaults and with `--no-default-features --features std,key-matching-listener,listen,query,queryable`;
  of `wz-session-mcu` with `listen`, `wz-session-lwip` with `session-unicast-accept`, the
  facade with `runtime-coop,session-unicast-accept`, and `wz-capi-pico` with
  `os-host,link-udp,peer` and with its defaults.
- W1, off: the two filters of the session core's new rows (`nondefault-tests-gate.sh`, the
  lend-only rows' build), 1 test each, and
  `cargo test -p wz-capi-coop --lib --no-default-features --features std,key-matching-listener,listen,query,queryable no_cookie_key`,
  1 test (the twin without the key), then the same build's `one_thread::listen`, which holds
  every accept at both ends.
- W1, on: `cargo test -p wz-session-core --lib --features session-unicast,session-unicast-accept,codec-init-body,codec-open-body cookie`
  (the bundle test's minted side and the key tests), `cargo test -p wz-capi-coop --lib no_cookie_key`
  (1, the entropy refusal), and the tokio runtime's `handshake_cookie_fixed` and
  `session_fsm_accepting_path` files as before.
- W1, Layer C1cs: `pico-peer-coop` lower by 7,000 to 9,000 (`decode_accept_cookie`,
  `send_init_ack_with_cookie`'s mint, `RegionAcceptState::encode`, `compute_hmac_sha256_full`,
  `sha256::compress256`), `nm -C` of it holding none of them; `pico-client-coop-nostd` and
  `pico-api-coop-nostd` unchanged.
- W6: `wz_config.py --write` and `--check` as for W3; build and clippy of `wz-capi-coop` with its
  defaults, with `--no-default-features --features std,key-matching-listener,listen,query,queryable`
  (one send place for every face) and the same with `face-send-places` (each face's place on one
  thread), with `--no-default-features --features std,app-transport,group` and the same with
  `face-send-places`, with `listen` and with `group` (`threads`: each face's place), and with
  `listen` under `WZ_COOP_VALUE_LOCKS=off` (the round: neither); of `wz-capi-pico` with
  `os-host,link-udp,peer` (one thread, one send place), with
  `os-host,link-udp,peer,face-send-places`, with `os-host,link-udp,peer,multicast-transport` and
  with its defaults.
- W6, off, 1 test each:
  `cargo test -p wz-capi-coop --lib --no-default-features --features std,key-matching-listener,listen,query,queryable a_put_of_a_listener_of_one_thread`
  and the filter `an_operation_holds_no_face_place`; the filter `held_operation` runs 0 there, and
  the whole of that build runs as the gate's row of one thread runs it. The group's form:
  `cargo test -p wz-capi-coop --lib --no-default-features --features std,app-transport,group one_thread::group`.
- W6, on: the same two builds with `face-send-places` beside them run
  `a_put_of_a_listener_of_one_thread` (1, two legs), `an_operation_reaches_each_face_through_the_wire_it_holds` (1),
  `an_operation_holds_the_place_of_every_face_with_a_link` (1), `held_operation` (3) and
  `an_operation_holds_no_face_place` (0); with `threads`,
  `cargo test -p wz-capi-coop --lib --features listen,query,queryable held_operation` runs 3.
- W6, Layer C1cs: `pico-peer-coop` lower by 3,000 to 5,000 (the held operations' wrappers,
  `HeldOperation as UnderHeldFaces` `run`, and `hold_faces_from`, `try_leg`, `wait_leg`,
  `on_face_legs`, `behind_held_place`), `nm -C` of it holding none of them;
  `pico-client-coop-nostd` and `pico-api-coop-nostd` unchanged.

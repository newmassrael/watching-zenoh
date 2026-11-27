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

## 5. Structural steps (the form)

| step | change | bytes, expected | receive Ir of `pico-client-coop-nostd` (about 3,066) | held by |
|---|---|---|---|---|
| **S1 (this branch)** | a udp port of the C engine keeps only what its session lent: `wz-runtime-coop`'s selector `udp-port-lent-only`, named by `wz-capi-coop`'s `listen`, compiles the port's rows and read buffers in their lent form alone; the heap form (`BookRows::Own`, `PortRx::Own`, `Held::Own`, `UdpPort::in_book`) is not compiled beside it, and links lent no rows or no slots refuse a `udp/` listener as exhausted | `pico-peer-coop` and `pico-api-coop-nostd` (and every step after `peer` of the API chain) -3,000 to -5,000, driver area: the second arm of every walk of the rows (the drop glues of a port and of a peer's share, 2,313 and 1,016; the read and sort, 3,354; the take and the look for a peer, 1,375 and 462), `PortRows<Heap>::enqueue` (336), the vectors' growth (3 x 99); the client case 0 | none: the client case compiles no port; a port's receive loses an arm and gains no call | `udp_link::a_lent_only_port_keeps_what_its_session_lent_and_nothing_of_its_own`, `ip_stack::a_lent_only_port_opens_over_the_rows_and_slots_its_session_lent_alone` |
| S2 (with W3 kept) | one UDP link driver for a dialled socket and a port's peer: the driver is a copy per socket type (`UdpDriver<PosixUdpSocket>` and `UdpDriver<PortPeer<..>>`, about 3,600 bytes the second), and outside `recv_with` the two do the same | -1,500 to -2,500; client 0 | none: built only with `udp-listen`; a match on the socket kind, no call | the driver's tests over both sockets |
| S3 (with W5 decided at build) | a listening session laid out in the region the build fixes (the face count a build constant, as zenoh-pico's), so neither the plan nor the lent row policy is compiled | -10,000 to -18,000; client 0 | none | the region's tests with faces |
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

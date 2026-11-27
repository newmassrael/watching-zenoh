# Driver area of the minimal case against zenoh-pico (lane base-driver)

The driver area of the size ledger's case `pico-client-coop-nostd` (`wz-capi-pico-lib` with
`os-host,link-udp` and no default features, profile `capi-nostd`; `deploy/size_ledger.json`),
body by body against the zenoh-pico build of the same capabilities (`vendor/zenoh-pico`, 1.10.2),
and the steps that take its excess out, largest first. Read from the ledger's `--explain`
document of main measured on 2026-11-27 (schema 5): the case is 205,921 bytes against 170,500
(1.21), and four areas lose (sessions, doors, transport, driver). The driver area is 28,932 bytes
against 16,049 (+12,883, 1.80). `docs/win-budget/size.md` section 3.4 read the same area a day
earlier (30,060); its lock design has landed and is kept here.

Bytes are each side's in the area, as the ledger places them: an inlined function's bytes are its
own file's, so a body's row below counts only what of it lies in the driver area (`link_turn` is
4,743 bytes in all, 1,608 of them here). A pico function is named as `nm` reads the reference
build.

Verdicts: **shape** is the same job done in more bytes, of five kinds: overlapping layers (one
fact kept or recomputed in several rows), generic copy (one body instantiated per type), inline
copy (a body copied into each caller), over-generalization (code a case's build carries for
uses it never has), moved by value (a large value written field by field where it is placed).
**work** is a behaviour wz has and zenoh-pico does not. **same work** is a job both do, at
about pico's cost or less.

Under the owner's ruling of 2026-11-27 (Kconfig switches), each behaviour zenoh-pico does not
have becomes a capability of its own in `deploy/wz-config.toml` with `upstream_off =
["zenoh-pico"]`, on in a build that names nothing and off in the zenoh-pico preset, which is the
preset contract: a behaviour visible on the wire is pico's in that preset too.

## 1. The bodies and their counterparts

| job | wz bodies (bytes in the area) | zenoh-pico | wz B | pico B | verdict | step |
|---|---|---|---:|---:|---|---|
| dial: open a socket, claim its buffers, place its link | `IpLinks::begin_initiator` 2,411 | `_z_open_link`, `_z_open_socket`, `_z_new_link_udp_unicast`, `_z_f_link_open_udp_unicast`, `_z_udp_unicast_open`, `_z_new_link_tcp`, `_z_f_link_open_tcp`, `_z_tcp_open` | 2,411 | 2,352 | shape: moved by value (a datagram driver written field by field into its cell, 273 B of `MaybeUninit::write`) | S5 |
| dial: place a stream link in its cell | `LinkPlace::stream` 547 | (in `_z_new_link_tcp`, row above) | 547 | 0 | shape: moved by value (the stream driver written into its cell, 217 B) | S5 |
| dial: read the endpoint text | `dial::dial_step` 1,658 | `_z_endpoint_from_string`, `_z_locator_from_string`, `_z_endpoint_config_from_string`, `_z_endpoint_parse_port`, `_z_endpoint_parse_host`, `_z_locator_metadata_from_string`, `_z_locator_init`, `_z_endpoint_init`, `_z_udp_config_from_strn`, `_z_tcp_config_from_strn` | 1,658 | 1,911 | same work (pico larger) | - |
| dial: read a literal IP address and port | `locator_text::ipv6_groups` 470, `locator_text::socket_addr_v4` 313, `Text::number` 141, `Text::port` 70 | `_z_ip_port_to_endpoint`, `_z_tcp_address_valid`, `_z_udp_unicast_address_valid` (and the C library's `getaddrinfo` for every endpoint) | 994 | 476 | shape: overlapping layers (a literal is read by wz's parser on a host whose resolver reads it too) | S4 |
| dial: a connect under way, answered on a later turn | `Dial::answer_on` 1,084 | none: `_z_tcp_open` connects and waits in one call | 1,084 | 0 | work: wz only (a connect that does not hold the session, polled by the engine) | W2 |
| dial: pass a connect refused later to the host's next address | `HostWalk::pass_on` 221 | none: `_z_tcp_open` walks `ai_next` inside its one call | 221 | 0 | work: wz only (part of W2) | W2 |
| dial: resolve a name, begin at its first address | `dial::begin` 910 | `_z_tcp_endpoint_init`, `_z_udp_unicast_endpoint_init` (each a `getaddrinfo`) | 910 | 224 | shape: over-generalization (the ask/cursor machine and its shell over a walk resumed later, W2) | W2 |
| dial: socket calls and address forms | `net::name_of` 195, `RawAddr::of` 130, `net::socket_addr_at` 111, `net::set_nonblocking` 97, `net::call_at` 76, 2 more 111 | `_z_udp_unicast_endpoint_init_from_address`, `_z_tcp_endpoint_init_from_address`, `_z_socket_set_blocking` | 720 | 295 | same work | - |
| a socket's wait for room (stream room, a connect under way) | `net::poll_writable` 179 | none | 179 | 0 | work: wz only (W1 and W2 each call it) | W1, W2 |
| dial: the refusal names its endpoint | `EndpointRefusal::new` 151, `EndpointTexts::write` 75, `EndpointTexts::text` 25 | none: an error code | 251 | 0 | work: wz only (the refused endpoint's text) | L0 6b-4 |
| dial: the face's dial row | `DirectSlot::take_dial_answer` 291, `LinkSupervisor::new` 183, `z_open` 175, `LinkSupervisor::end_dial` 86, `LinkSupervisor::put_dial` 79, 5 more 140 | (transport area: `_z_new_transport_client`) | 954 | 0 | shape: overlapping layers (the dial held in three rows, arch-l0-driver section 2) | L0 6b-3 |
| stream: receive a batch | `StreamDriver::recv_with` 991 | `_z_tcp_read_exact`, `_z_tcp_read`, `_z_f_link_read_exact_tcp`, `_z_link_recv_exact_zbuf`, `_z_link_socket_recv_zbuf`, `_z_link_recv_zbuf` | 991 | 272 | shape: over-generalization (a framing trait, a batch kept where it lies across reads that do not wait); the receive path | - |
| stream: send a frame, owe its rest, answer room | `StreamDriver::tx_slot_send` 708, `StreamDriver::write_owed` 522, `StreamDriver::wait_for_room` 300, `StreamDriver::tx_slot_acquire` 296, `StreamDriver::service` 278, 5 more 325 | `_z_link_send_wbuf`, `_z_f_link_write_tcp` | 2,429 | 281 | work: wz only (frames owed and written later, room asked of the stream) | W1 (landed with this file) |
| stream: the two tables' other entries | `StreamDriver::link_ends` 71, `StreamDriver::link_mtu_for` 69, `StreamDriver::input_wait` 31, `StreamDriver::try_recv` 28, `StreamDriver::set_idle_flush` 25, 28 more 284 | `_z_f_link_close_tcp`, `_z_f_link_free_tcp`, `_z_f_link_read_tcp`, `_z_f_link_write_all_tcp`, `_z_f_link_tcp_read_socket`, `_z_get_link_mtu_tcp` | 508 | 81 | shape: over-generalization (two tables a driver) | S6 |
| udp: receive a datagram | `UdpDriver::recv_with` 393, `PosixUdpSocket::receive` 273, `UdpDriver::admit` 25 | `_z_udp_unicast_read_exact`, `_z_udp_unicast_read`, `_z_f_link_read_exact_udp_unicast` | 691 | 319 | same work; the receive path | - |
| udp: the link's own wait in its loop | `UdpDriver::service_within` 362, `UdpDriver::wait_for_datagram` 276, `UdpDriver::service` 149, `UdpDriver::uses_wake_budget` 11 | none in a client whose read task waits (`_z_socket_wait_readable`, below) | 798 | 0 | shape: over-generalization (the loop's own wait kept by the table in a build whose owner waits for every link) | S2 |
| udp: send a frame from a lent slot | `UdpDriver::tx_slot_send` 202, `link_storage::copied_send` 188, `UdpDriver::tx_slot_acquire` 121, `UdpDriver::tx_slot_storage` 50, `UdpDriver::send_blocking` 21, 3 more 56 | `_z_f_link_write_udp_unicast`, `_z_f_link_write_all_udp_unicast`, `_z_udp_unicast_write` | 638 | 93 | shape: overlapping layers (a slot lent a frame, and a copy for a frame handed as bytes) | - |
| udp: the two tables' other entries | `UdpDriver::link_mtu` 69, `UdpDriver::link_ends` 61, `UdpDriver::input_wait` 31, `UdpDriver::try_recv` 28, `UdpDriver::holds_input` 20, 12 more 97 | `_z_f_link_close_udp_unicast`, `_z_f_link_free_udp_unicast`, `_z_f_link_read_udp_unicast`, `_z_f_link_udp_read_socket`, `_z_get_link_mtu_udp_unicast` | 306 | 66 | shape: over-generalization (two tables a driver) | S6 |
| the link handle's forwarding entries | `CellRc::input_wait` 17, `CellRc::recv_with` 17, `CellRc::room_wait` 17, `CellRc::service_within` 17, `CellRc::try_recv` 17, 10 more 140 | none | 225 | 0 | shape: over-generalization (a third table over the drivers' own) | S6 |
| the copying receive (`try_recv`) | `link_storage::copied_receive` 96, its closure 92 and the closure's call shim 58 | none | 246 | 0 | shape: over-generalization (kept by the table; the build's receive lends) | S6 |
| the owner's wait on its links | `IdleWait::wait` 393 | `_z_socket_wait_readable` | 393 | 396 | same work | - |
| the link's turn (receive path) | `CoopEngine::link_turn` 1,608 | `_z_executor_spin`, `_z_executor_get_next_fut`, `_zp_unicast_read_task_fn` | 1,608 | 1,061 | shape: overlapping layers (arch-l0-driver section 2); the receive path | L0 6b-6 |
| placing a link's session | `CoopEngine::place_link_session` 1,603, `LinkSession::init_in` 254, `session_drive::place_session_with_router` 12 | `_z_session_init` (and the transport area) | 1,869 | 100 | shape: overlapping layers (the life, the link and the face kept in three rows) | L0 6b-6 |
| the engine's assembly and task table | `CoopEngine::assemble` 521, `RuntimeTables::runtime` 383, `ExecutorState::claim_none` 100, `engine::lend_session` 86, `engine::session_zid` 81, 5 more 142 | `_z_executor_null`, `_z_executor_spawn`, `_z_executor_get_status`, `_z_executor_cancel_fut`, `_z_executor_resume_suspended_fut`, `_z_executor_get_fut_status` | 1,313 | 778 | shape: overlapping layers (the sessions area's open; its lane) | sessions |
| the last holder's drop of a kept value | `Shared::last_placed` 469, `Shared::last_placed` 204, `Shared::last_placed` 105, `Shared::last_placed` 54, `kept::place_head` 43, 3 more 34 | none (`free`) | 909 | 0 | shape: generic copy (four types' drop paths of `Shared::last_placed`) | S3 |
| links placed in cells the session lent | `link_cells::head_in` 129, `link_cells::let_go` 59, `link_cells::heap_head` 54, `link_cells::hold` 40, `link_cells::give_back` 10, 2 more 10 | none (`z_malloc`) | 302 | 9 | work: wz only (no heap: the cells a session lends; kept, the no-heap contract) | - |
| a typed lock taken and let go of in line at a door | `handlers::push` 233, `matching::declare_on_filter` 228, `z_undeclare_matching_listener` 137, `WriteFilter::drop (Drop)` 131, `RawLock::lock_contended` 125, 47 more 1,732 | `_z_mutex_lock`, `_z_mutex_unlock`, `_z_mutex_try_lock` (calls, system.c) | 2,586 | 0 | shape: inline copy (kept: the receive's instruction count, size.md 3.4) | - |
| clock, entropy, sleep | `unix::sleep_us` 134, `RefCell::try_draw` 111, `PosixClock::now_us` 81, `platform::sleep_for` 16 | `z_clock_*`, `z_time_*`, `z_random_*`, `z_sleep_*` (system.c) | 342 | 1,849 | same work (pico larger) | - |
| the engine's face turn, rows and drops | `LinkSession::service_due` 451, `CoopEngine::drive_link` 303, `Core::end_links` 291, `drive::fragment_in_place` 255, `SiteSend::drop (Drop)` 146, 34 more 1,403 | `_zp_unicast_lease_task_fn`, `_zp_unicast_keep_alive_task_fn`, `_z_client_reopen_task_fn`, `_zp_unicast_failed_result`, `_z_session_clear` | 2,849 | 419 | shape: overlapping layers (arch-l0-driver section 2) | L0 6b-2..6b-5 |
| jobs only zenoh-pico's build links: a listener and its accept, an endpoint written back as text, the interface iterator, frees and clears | none in this client | `_z_socket_get_endpoints` 495, `_z_tcp_listen` 484, `_z_listen_link` 356, `_z_tcp_accept` 329, `_z_endpoint_to_string` 289, `_z_endpoint_config_to_string` 262, `_z_endpoint_config_strlen` 262, `_z_locator_to_string` 221, the UDP interface iterator 388, and the rest | 0 | 5,067 | pico's own | - |
| **total** | | | **28,932** | **16,049** | | |

## 2. The two shares

| share | wz | zenoh-pico | wz - pico |
|---|---:|---:|---:|
| shape (same job, more bytes) | 20,662 | 5,922 | +14,740 |
| work (wz only) | 4,466 | 290 | +4,176 |
| same work | 3,804 | 4,770 | -966 |
| zenoh-pico only | 0 | 5,067 | -5,067 |
| total | 28,932 | 16,049 | +12,883 |

Of the shape share, three rows are kept on purpose and are not steps: the typed lock taken in line
at a door (2,586: out of line it cost the receive 3,020 instructions a message against 2,759,
`docs/win-budget/size.md` section 3.4), the links' cells (302: the no-heap contract of the C
library) and the two receive bodies (stream 991, datagram 691), which are the receive path. The
work share is four behaviours: the stream link's owed frames (W1), the connect answered on a later
turn and its walk (W2), the refusal's endpoint text (arch-l0-driver 6b-4) and the socket's wait
for room both of the first two call.

## 3. Steps, by the bytes they take out

Estimates are bytes of the case's driver area. "Receive" is the instruction count a message of
`docs/win-budget/ir-receive.md` costs (about 3,066 on main, perf matrix arm W): a step that moves
it up is not landed.

| order | step | kind | change | rows (wz B now) | estimate | receive | lane |
|---:|---|---|---|---:|---:|---|---|
| - | L0 | shape: overlapping layers | the face's life, link and rows each kept once (`docs/c-abi-migration/arch-l0-driver.md` steps 6b-2 to 6b-6) | 7,531 | -1,300 to -2,750 | 6b-6 is on it; its own lane reads it | arch-l0-driver |
| 1 | **W1** (landed with this file) | work: switch `tx-stream-owed` | off: a stream link writes each frame whole, the send waiting for its stream (`StreamSocket::write_all`), as `_z_link_send_wbuf` waits in `send`; no owed ring, no question of room asked of the stream | 2,429 + 179 | -1,100 to -1,500 | 0: the datagram receive reaches none of it; a stream link's `service` per turn drops a `RefCell` borrow | base-driver |
| 2 | W2 | work: switch (a connect that does not hold the session) | off: a dial connects and waits in one call, walking the host's addresses there, as `_z_tcp_open` does; `Dial::answer_on`'s later answer and `HostWalk::pass_on` go | 2,215 (+ part of the dial row) | -800 to -1,200 | 0 (an open, never a message) | base-driver, with arch-l0-driver 6b-1 to 6b-3 (the life's `DialStage::Pending`) |
| 3 | S2 | shape: over-generalization | whether the owner waits for every link becomes the stack's type, so a driver of such a stack has no wait of its own (`size.md` 3.4, first item) | 798 + about 120 of the stream's `service` | -800 to -1,000 | 0 or less (the `owner_waits` load goes) | base-driver; touches every heap link family |
| 4 | S4 | shape: overlapping layers | on a stack that `RESOLVES`, a literal address goes to the host's resolver (one `getaddrinfo` asked for a numeric host) and wz's literal parser is not linked; a stack without a resolver keeps it | 994 | -600 to -850 | 0 | base-driver |
| 5 | S6 | shape: over-generalization | one table a link (the session's sends and the loop's pump through one `dyn` entry set), and `try_recv` out of the table of a build whose receive lends | 1,285 | -400 to -800 | must not rise: `recv_with` is reached through the table | base-driver |
| 6 | S3 | shape: generic copy | one out-of-line drop path for the last holder of a kept value, the type's drop handed as a function | 909 | -300 to -450 | 0 (no kept value is let go on a message) | base-driver |
| 7 | S5 | shape: moved by value | a link built where it lies: the driver's fields written once into the cell, not assembled and copied (273 B and 217 B of `MaybeUninit::write`) | 2,958 | -200 to -400 | 0 (an open) | base-driver |

Steps 1 to 7 together are about -4,200 to -6,200 of the area's +12,883, and with L0 about -5,500 to
-8,950. What is left is the kept rows of section 2 and the residue of the engine's face turn.

## 4. Step W1: the stream link's owed frames as a capability

`tx-stream-owed` is `wz-runtime-coop`'s feature (its one default), forwarded by
`wz-capi-coop`'s and named by the pico and core ABI manifests and `deploy/wz-config.toml`
(`WZ_CAP_TX_STREAM_OWED`, off in `configs/zenoh-pico_defconfig`, on in the host profiles).
`wz-session-lwip` names it (no pico library is built over it) and `wz-runtime-posix` names it
for its own tests only, so the pico library's build is the one that decides it.

| case | with `tx-stream-owed` (as before) | without it (the zenoh-pico preset) |
|---|---|---|
| a frame the stream takes whole | written, slot back, the next frame not asked for room | written, slot back |
| a frame the stream takes in part | the rest owed in the slot, written by the next step that finds room; the send returns at once | the send waits for room (`wait_writable` of the service tick) and writes the rest, then returns |
| a frame behind owed frames | owed whole behind them, in order | none can be behind: nothing is owed between calls |
| a question of room | written owed frames first; the stream asked within the message's wait; congested when it has none | room at once, also while every slot is with the session (its open batch takes the message, or is sent first and the slot lent again); while another send holds the link, a droppable message is congested at once and a blocking one waits for it; congested at once while a pool the session's links share has no slot; the stream is not asked |
| a slot asked while frames are owed | the owed frames written first, the freed slot lent | the slot or none: no write of the link's own frees one |
| a write the stream fails | the link ends, every owed frame's slot back | the link ends, the frame's slot back |
| an ended link | a send writes nothing, its slot back | the same |
| the framing's own units (a WebSocket's answers) | written between frames as now | written whole before the next frame |

Bodies that go or shrink in the case: `StreamDriver::write_owed` (522) and `drop_owed` (104) are
not linked; `tx_slot_send` (708) is the seal and one `write_all`; `wait_for_room` (300) and
`tx_slot_acquire` (296) no longer write or ask the stream; `OwedQueue` and the `room_known` cell
leave the driver, so each stream link's cell is smaller by the ring (`LENT_SLOTS` places).

Tests, in `crates/wz-runtime-coop/src/stream_link.rs`: the sixteen tests of the owed form are
gated on the feature; five run without it (`nondefault-tests-gate.sh`, the `-default` row of
`wz-runtime-coop` over `stream_link::`):
`a_send_without_owed_frames_waits_until_the_stream_took_the_whole_frame`,
`a_link_without_owed_frames_has_room_while_it_has_a_slot`,
`a_failed_write_without_owed_frames_ends_the_link_and_gives_back_its_slot`, and in
`session_room` `a_droppable_message_on_a_full_stream_is_written_by_a_send_that_waits` and
`a_blocking_message_on_a_full_stream_is_written_and_closes_nothing`.

Measured by the main session on the case's explain report: the driver row and the
`wz_runtime_coop::stream_link` owner line (2,755 now); the step is reverted if the area does not
fall by at least 1,000.

## 5. Step S2: who waits for a datagram link's input, as the stack's type

`IpLinks` takes a sixth parameter, `W: InputWaiter` (`wz_runtime_coop::session_drive`), which is
`WaitsInLoop` by default; `waited_by_owner` is the conversion to `WaitedByOwner`, and the stack
makes each datagram link a `UdpDriver<_, _, _, W>`. A socket type says whether every socket of it
names its owner's wait (`DatagramSocket::NAMES_INPUT_WAIT`: the POSIX, Windows and Zephyr
sockets do, a port's peer as its port's socket). A link of a `WaitedByOwner` stack over such a
socket answers `service` and `service_within` with nothing, so `UdpDriver::wait_for_datagram`
(276), `arm` and the waits of `service_within` (362) and `service` (149) are not in its build.
`recv_with` is the same body, called where it was.

| case | before | after |
|---|---|---|
| owner waits, socket names its wait (the pico library's host sockets) | a flag set at the open, read at each service | the type says so: no flag read, no wait of the loop's compiled |
| owner waits, socket names no wait (the tests' sockets, the program's transport) | the flag from `input_wait` at the open | the same |
| the links wait in their own loop | the tick, or the deadline the image allows | the same |

The pico library names the waited links in its chain of link types (`WaitedSocketLinks` in
`crates/wz-capi-pico/src/session.rs`, through `ComposedLinks::WaitedByOwner`), as the cooperative
engine's tests do (`PosixLinks` in `crates/wz-capi-coop/src/tests.rs`). Test:
`udp_link::tests::a_link_of_a_stack_its_owner_waits_for_has_no_wait_of_its_own`.

Left for a step of its own: the stream link's share (about 120 bytes of `StreamDriver::service`).
A stream link's type is its stream's (`StreamSocket::Link`), so carrying `W` there touches each
stream family and the secure channel's.

Measured on the case's explain report: the driver row and the `wz_runtime_coop::udp_link` owner
line; expected -700 to -790, the receive's instructions a message unchanged or fewer.

## 6. Step S5: a datagram link written where it lies

`UdpDriver::with_peer_in` writes the driver field by field in the place it is handed, and the
stack makes each datagram link with it in its cell (`LinkPlace::datagram`), so
`begin_initiator` builds no driver in its frame to move there (the 273 bytes of
`MaybeUninit::write`); `with_peer` is the same body over a place in its own frame. Test:
`udp_link::tests::a_link_written_where_it_lies_is_the_link_a_value_is`.

Left: the stream link's placement (217 bytes, `LinkPlace::stream`), whose link is the stream's
type (`StreamSocket::Link`), the same seam as S2's stream share.

Measured on the case's explain report: `begin_initiator` and the `wz_runtime_coop::ip_stack`
owner line; expected -150 to -270, the receive untouched (an open).

# Migration lane base-transport: the transport area against zenoh-pico, body by body

Status: the reading, the steps and the first step built (B1, commit `248c36d42d`). Nothing here
was built, run or measured by this lane: every byte and instruction figure of a step is an
**estimate** from the code, to be read on the size ledger's explain document of the case and on
the perf matrix's receive line.

The case is `pico-client-coop-nostd` (`wz-capi-pico` without its defaults, `os-host,link-udp`,
profile `capi-nostd`): one thread, the dial face alone, the four send behaviours beyond
zenoh-pico's transport off (`tx-probe`, `tx-expiry-run`, `tx-fragment-credit`, `tx-held-wait`),
`transport-qos` off. The reading is the size ledger's explain document of 2026-11-27 (main at the
arch-put landing, case total 205,921 against 170,500, 1.21): the transport area is 28,108 bytes in
146 bodies against zenoh-pico's 13,951 in 100, +14,157. A body's bytes are those of its lines the
area rule places here, so a body inlined across areas is counted in each by its lines.

## 1. The table

zenoh-pico's functions are its 1.10.2 build of the same capabilities (`vendor/zenoh-pico`), read
off the same document. "wz - pico" is the row's difference. The verdict names the kind of the
difference: **form** (overlapping layers, generic copies, inline copies, over-generalisation, a
value moved) or **work** (a behaviour wz has and zenoh-pico does not).

| row | job | wz bodies (bytes in the area) | wz | zenoh-pico functions | pico | wz - pico | verdict | step |
|-----|-----|-------------------------------|---:|----------------------|-----:|----------:|---------|------|
| T1 | the session, link and slot machines' runtime | `Turn::run` 1,269, `exit_states_from_rows` 643, `enter_states_from_rows` 544, `select_transition_from_rows` 447, `Turn::take_microstep` 379, `exit_interpreter` 254, `UnicastLink::input` 190, `Engine::run_turn` 468 in 3, `Engine::new_in_place` 353 in 3, the `EngineHost` hooks, queue and store | 5,777 | none as a body: the handshake is straight-line code in `_z_unicast_handshake_open` (T3) | 0 | +5,777 | form: over-generalisation (the general turn for three machines of the reactive class) and generic copies (793 bytes of per-machine monomorphs beyond each one's largest) | S-SCE |
| T2 | receive: a datagram's units and a frame's records | `UnicastRx::dispatch_datagram` 1,727, `drive::dispatch_copied` 466, `CoopEngine::link_turn` 398, `drive::walk_records_in_place` 289 and its record closure 59, `CoopEngine::drive_link` 88, `place_session_with_router` 35, `take_input` 8 | 3,070 | `_z_unicast_process_messages` 332, `_z_unicast_handle_frame` 329, `_z_unicast_recv_t_msg` 322, `_z_link_recv_t_msg` 281, `_zp_unicast_read` 277, `_z_unicast_client_read` 225, `_zp_unicast_read_task_fn` 206, `_z_unicast_handle_transport_message` 191, `_z_link_recv_t_msg_cap_flow_stream` 176, `_z_unicast_update_rx_buffer` 168, four more 83 | 2,590 | +480 | form: overlapping layers (the link's datagram reader, the unit's dispatch and the record walk are three bodies where pico's read and process are two) | none: the receive's hot path |
| T3 | receive: control messages and the handshake's answers | `drive::read_control_in_place` 2,034 (`decide_admitted` and `judge_handshake_step` inlined), `dispatch_control_in_place` 153, `credential_identity::zid_is_bound` 144, `LinkLease::reserve` 76, `ext_chain::read_walk` 53 | 2,460 | `_z_unicast_handshake_open` 873, which also builds and sends the InitSyn and the OpenSyn | 873 | +1,587 | work, about 600 to 1,000: what zenoh's establishment checks and pico's does not (the peer's region name and remote bound, read and refused when malformed; the node's admission of a link and the `MaxLinks` close; a dial's expected peer; the stray-message policy and its replay of a held answer); form, the rest: every role's and extension's decision compiled into one inlined body | W1 to W4 |
| T4 | receive: fragments | `drive::fragment_in_place` 2,152 (1,277 of it the rejoin router's lines), `ReassemblyDispatcher::init_in` 187, `Slot::end` 148, `turn_slot_engine` 127, `start_slot_engine` 77, `engine::lend_session`'s lines 64 | 2,755 | `_z_unicast_handle_fragment_inner` 825 | 825 | +1,930 | form: over-generalisation (a router of slots, each a machine of its own, over a lent staging area of two 4 KiB chains, for a session of one peer, where pico appends to one buffer per reliability); the behaviour is the same (sequence gaps, the start and drop markers of a negotiated patch, `vendor/zenoh-pico/src/transport/unicast/rx.c` @ `if (_Z_PATCH_HAS_FRAGMENT_MARKERS(peer->common._patch)) {`) | B4 |
| T5 | timers: lease, keep-alive, handshake deadlines | `LinkSession::service_due` 891, `UnicastTransport::due_ms` 712, `drive::keepalive_deadlines` 511, `drive::deliver_session_event` 164, `LinkSession::init_in` 105, `zp_send_keep_alive` 86, `stamp_rx_activity` 18 | 2,487 | `_zp_unicast_failed_result` 195, `_zp_unicast_keep_alive_task_fn` 192, `_zp_unicast_lease_task_fn` 167, `_zp_unicast_send_keep_alive` 93, `_z_send_keep_alive` 30 | 677 | +1,810 | form: the driver's write reports and the companion carriage compiled for a runtime none of whose drivers has them (B1); inline copies (the lease's deadlines read inline in both `fire_due` and `next_due_ms`); work, about 400 to 700: the watch of the peer's initial declarations (the `reliable-gap-reconnect` policy), the application layer's wake, a deadline per handshake state where pico has one connect deadline | B1 (built), B2, W5 |
| T6 | send: the dispatch | `dispatch_network_message_in::<false>` 1,599 and its closure 10 | 1,609 | `_z_transport_tx_send_n_msg_inner` 1,341, `_z_send_n_msg` 459 | 1,800 | -191 | won; the Control barrier is still compiled on one conduit (form) | B5 |
| T7 | send: the writer and the link's slot | `write_n_msg` 1,498, `emit_on_link` 216, `flush_conduit` 169, `send_lent_on` 168, `TxLease` 416 in 10 bodies, `batch_link` 107, `try_encoded_len` 93, `write_vle_u64` 91 in 2, `CountTxBuf` 72 in 6, `drain_conduits` 59, `batch_door` 24, six more 71 | 2,984 | `_z_link_send_t_msg` 300, `_z_send_n_batch` 260, `__unsafe_z_prepare_wbuf` 86, `__unsafe_z_finalize_wbuf` 72, `_z_transport_start_batching` 66, `_z_transport_stop_batching` 39 | 823 | +2,161 | form: overlapping layers (each frame a slot the link lends, `TxLease`, written through `&dyn TxBuf`, with a counting pass, `CountTxBuf` and `try_encoded_len`, before the writing one) where pico writes into the transport's one batch buffer | B3 |
| T8 | send: fragments | `emit_fragment_chain` 643, `send_fragment`'s writer 175, `emit_fragments_encoded` 145, `send_fragment` 123 | 1,086 | `_z_transport_tx_send_fragment` 433, `__unsafe_z_serialize_zenoh_fragment` 247 | 680 | +406 | form: the chain planned from the message's encoded length and each fragment lent a slot of its own (the credit and the stop fragment are off here) | with B3 |
| T9 | send: control messages | `send_control_lent`'s writer 376, `send_open_syn` 231, `send_init_syn` 151, `write_init` 102, `send_close_with_reason` 69, `send_control_lent` 68, `send_close_frame_with_reason` 53, `encode_open_head_into` 36, the close reasons 35 | 1,121 | `_z_transport_tx_send_t_msg` 408, `_z_unicast_send_close` 112, `_z_send_close` 60, `_z_send_t_msg` 54, `_z_transport_tx_send_t_msg_wrapper` 11 (and the sends inside `_z_unicast_handshake_open`, T3) | 645 | +476 | form: a lent writer per control message; work, about 50 to 100: the Open stages the remote bound the session decided | with B3, W1 |
| T10 | network messages written inside the transport's writers | `dispatch_declare_lent`'s writer 1,177, `send_push_at`'s writer 220, `lent_push::write_push` 171, `dispatch_interest_lent`'s writer 58, three codec writers 52 | 1,678 | none here: pico encodes them in its codec area | 0 | +1,678 | form: inline copies of codec and session work, placed here by the writer's file; moving them is an area move, not a cut | none |
| T11 | engine bodies that carry transport lines | `CoopEngine::place_link_session` 634, `replay::told` 393, `CoopEngine::send_on_links` 374, `Retract::tell` 178, `faces::pay_held` 62, `DirectSink::drain_pushes` 50, `RegistryOf::dispatch_to` 48, six more 104 | 1,843 | none here: pico's are in its sessions area | 0 | +1,843 | form: inline copies of `session_actions` lines in the cooperative engine's bodies | none in this lane |
| T12 | establishment | `record_established_at` 476, `init_core` 470, `derive_initial_sn::absorb` 182, `LinkState`'s drop 63, `release_link` 30, `link_driver_open` 17 | 1,238 | `_z_new_transport` 647, `_z_unicast_handshake_listen` 646, `_z_unicast_transport_create` 469, `_z_transport_peer_unicast_add` 326, `_z_new_peer` 311, `_z_unicast_open_peer` 156, `_z_unicast_open_client` 17 | 2,572 | -1,334 | won | none |
| T13 | pico's manager, peers, pending peers, SN helpers, multicast and raw-Ethernet entries | none here: wz holds them in its sessions and driver areas | 0 | 57 functions, the largest `_z_pending_peers_copy_from_locators` 301, `_z_conduit_sn_list_copy` 173, `_z_pending_peers_move` 167 | 2,466 | -2,466 | won | none |
| | **total** | | **28,108** | | **13,951** | **+14,157** | | |

### 1.1 The two shares

| share | rows | bytes |
|-------|------|------:|
| form, the losing rows | T1 to T5, T7 to T11 | about 16,350 to 17,100 |
| of which the statechart runtime (SCE's) | T1 | 5,777 |
| of which attribution, an area move only | T10, T11 | 3,521 |
| of which the receive's hot path, no step | T2 | 480 |
| of which wz's to walk | T3 to T5, T7 to T9 | about 6,550 to 7,300 |
| work, the losing rows | T3, T5, T9 | about 1,050 to 1,800 |
| the won rows | T6, T12, T13 | -3,991 |

## 2. What the earlier readings said, against this one

- The transport reading of 2026-11-25 (kept outside the repository) measured a build with `std`
  by symbol (40,839 against 14,742); its totals do not compare with this document's (by symbol
  here 32,964 against 14,742, pico's the same). Its items, against this build:
  - static descent of the machines: **landed in part** (the row walk of SCE ADR 0135:
    `select_transition_from_rows`, `enter_states_from_rows`, `exit_states_from_rows`); what is
    left is SCE's: `docs/win-budget/size.md` section 6.4 and the reactive turn that branch
    `sz-transport2` adds to it as its section 10.3 (`7d8239bfb5`, not on main) (S-SCE below);
  - the session's entity messages out of the transport: **not done, and not a cut**: T10 and T11
    are an area move, as that reading said;
  - one send frame path: **landed** (`write_n_msg`, `docs/win-budget/size.md` section 6.1); what
    is left of T7 is the slot lend under it (B3);
  - folding the receive's outcome layers: the receive of this build is in place (`rx-in-place`)
    and links none of the copying path's outcome report; what is left is T2 (hot path, no step)
    and T4's router (B4);
  - handshake data handed to the machine (SCE ADR 0124): **not in this build**: an OpenAck is
    still admitted against `awaiting_open_ack` in the session's facts (`admit_open_ack`);
  - single-thread forms of the runtime's words: **landed in part** (the send windows are
    `Cell<u64>`: `set_window::<Cell<u64>>`, `begin_drain::<Cell<u64>>`);
  - the client's fixed extension chain: what is left of it here is 105 bytes (`read_walk` 53,
    `extpatch` 52), nothing to walk.
- `docs/win-budget/size.md` section 6.3 (one body gives the session machine its events):
  **landed** (`deliver_session_event`, 164).
- No Control barrier on one conduit (branch `sz-transport2`, its `docs/win-budget/size.md`
  section 10.2 and commit `3c25c9e036`): **not on main**; this build has `transport-qos` off, so
  it compiles the barrier (B5).
- The four send behaviours beyond pico: **landed** (`2d08b9b104`, `d8ed7786a4`) and off in this
  build; the dispatch is now under pico's (T6).
- The timers rows were **too low**: `docs/win-budget/size.md` section 2.3 (`transport_timers`
  786 and `keepalive_deadlines` 511 against 626) and branch `sz-transport2`'s section 10 (786
  against 626, +160) counted owners' lines, which are part of three bodies; by bodies the timers
  are 2,487 against 677 (T5).

## 3. The steps, by expected bytes on this case's transport row

Work steps follow the owner's ruling of 2026-11-27: a behaviour zenoh-pico does not have is a
Kconfig capability of its own (`deploy/wz-config.toml`, `[[capability]]` with
`upstream_off = ["zenoh-pico"]`, as `tx-probe` and `tx-expiry-run` are), off in the zenoh-pico
preset, its key path refused by a build without it. That holds for a behaviour seen on the wire
too: the preset's contract is zenoh-pico's.

| step | rows | kind | what | expected | receive Ir | before it |
|------|------|------|------|---------:|------------|-----------|
| S-SCE | T1 | form, SCE's | the reactive turn, exit paths beside entry paths, `process_event` out of line and the per-machine halves folded (`docs/win-budget/size.md` section 6.4; the reactive turn of branch `sz-transport2`, section 10.3) | -2,000 to -2,900 | none per sample | an SCE session |
| B3 | T7, T8, T9 | form | for a single-threaded lend-only build, a frame written in place into the link's one batch slot held for the batch: no counting pass (`CountTxBuf`, `try_encoded_len`), no per-frame `TxLease`; a fragment written into the same slot | -800 to -1,300 | none (send only) | the send's Ir on the perf matrix, and which lines of `write_n_msg` the lease holds |
| B4 | T4 | form | for a session of one peer, the rejoin of a fragment chain into one lent chain per reliability, with the slot machine kept (P8) and the router's ingest folded into it | -600 to -1,000 | none per sample (a fragment is the cold path) | a reading of which of the router's lines hold the 1,277 (cell M13 of branch `sz-transport2`, section 10.4) |
| B1 | T5 (and T7's `emit_on_link`) | form | the four write facts of a link driver (whether it reports its writes, its last write, a class carried apart, that carriage's last write) compiled only with `link-wire-reports`, which only the tokio runtime names | -350 to -500 | lower: no clock read and four indirect calls fewer at each keep-alive deadline read; two fewer at each frame handed over | **built, `248c36d42d`** |
| W1 | T3, T9 | work | the handshake's regions: the peer's region name and remote bound read and refused when malformed, the bound the session decides and stages on its Open | -250 to -450 | none | owner's key path for the capability |
| W5 | T5 | work | the watch of the peer's initial declarations (its deadline in the lease, its expiry in `judge_lease`) | -250 to -400 | none | as W1 |
| W2 | T3 | work | the node's admission of a link (`LinkAdmission`, `LinkLease`) and the `MaxLinks` close | -200 to -400 | none | as W1 |
| B2 | T5 | form | the lease's deadlines read once, out of line, for `fire_due` and `next_due_ms` | -150 to -300 | must not rise: a call per turn is added, so only with a per-turn Ir reading | the perf matrix arm W |
| W4 | T3 | work | the stray-message policy's replay of a held answer | -100 to -200 | none | as W1 |
| B5 | T6 | form | no Control barrier on one conduit | -60 to -150 | none | merging `sz-transport2` |
| W3 | T3 | work | a dial's expected peer (the InitAck's zid against the node the dial was made for) | -80 to -150 | none | as W1 |

Together, the wz steps (B and W) are about -2,850 to -4,850 on the row, S-SCE another -2,000 to
-2,900; the rest of the gap is attribution (T10, T11) and the hot receive walk (T2).

**Why B1 is the step built first, though B3 and B4 are larger by estimate.** B3 and B4 each change
a send or a receive form, and their bytes lie in lines inlined into bodies this document does not
split (`write_n_msg`, `fragment_in_place`): their ranges are guesses until those lines are read
(the "before it" column), and B3 moves the send's instructions, which only the perf matrix reads.
B1 removes code that is named whole (the driver's four methods, their calls in
`keepalive_deadlines`, `judge_keepalive` and `emit_on_link`, the companion field), cannot reach
any driver of this build, and adds no instruction anywhere, so it is the largest step that could be
built without a measurement first. It is not the largest step; the order above is.

## 4. B1 as built

`link::BoxedLinkDriver`'s `reports_wire_writes`, `ms_since_wire_write`, `carries_apart` and
`ms_since_wire_write_for` exist only with `wz-session-core`'s `link-wire-reports` (a default of
the crate; `wz-runtime-tokio` names it, whose writer queues and QUIC companion implement them). A
build without it (every cooperative and MCU build, which take the crate without its defaults):

- `emit_on_link` marks the line at every frame handed over, as zenoh-pico sets its transmitted
  flag at every write it flushes (`vendor/zenoh-pico/src/transport/common/tx.c` @
  `static z_result_t _z_transport_tx_flush_buffer(`); before, it asked the driver
  twice per frame and got the same answer from every driver of the build;
- `keepalive_deadlines` counts the link's deadline from the establishment and the tick alone,
  reads no clock and asks the driver nothing; `KeepaliveDeadlines` has no companion, and
  `judge_keepalive` sends no companion keepalive;
- the reconnect seam's two forwarding drivers (`SwappableLink`, `LocalSwappableLink`) forward
  the four only where they exist;
- a driver of such a build cannot answer any of the four (the trait has none), so no write report
  can be given that the session would not read.

A build with it is unchanged. Tests (`session_actions::bundle_tests::link_stamps`):

- `every_frame_handed_to_a_link_that_writes_inline_marks_its_line` (both builds): a reliable
  data frame, a best-effort data frame and a best-effort control frame each mark the line, and the
  keep-alive deadline is one interval after the establishment. Red if the line's mark is compiled
  only with the feature, or the deadline reads anything but the two stamps. Run without the
  feature by the new leg of `scripts/lib/nondefault-tests-gate.sh`, the zenoh-pico preset's
  session core.
- `a_link_that_reports_its_writes_keeps_each_carriage_by_its_own_writes` (with the feature): on
  a driver that queues its writes and carries best-effort apart, a queued data frame and a frame
  carried apart mark nothing, a control frame marks, and one judge at the end of the first tick
  sends one keepalive on the link and one on the companion. Red if the feature's build loses the
  driver's answers or the companion's keepalive.

# Migration lane base-transport: the transport area against zenoh-pico, body by body

Status: the reading, the steps and the first step built (B1, commit `248c36d42d`). Nothing here
was built, run or measured by this lane: every byte and instruction figure of a step is an
**estimate** from the code, to be read on the size ledger's explain document of the case and on
the perf matrix's receive line. Section 5 reads B3's and B4's bodies line by line in a built
library, splits each step by what the lines hold, and records B3a, the first of them, as built.
Section 6 records the work steps as they were built against the code.

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
| B3 | T7, T8, T9 | form | for a single-threaded lend-only build, a frame written in place into the link's one batch slot held for the batch: no counting pass (`CountTxBuf`, `try_encoded_len`), no per-frame `TxLease`; a fragment written into the same slot. Split by its lines into B3a to B3d (section 5.3) | -640 to -1,105 | none (send only) | B3a built; B3b first, with a build loop (section 5.3) |
| B4 | T4 | form | for a session of one peer, the rejoin of a fragment chain into one lent chain per reliability, with the slot machine kept (P8) and the router's ingest folded into it. Split into B4a and B4b (section 5.3) | -350 to -650 | none per sample (a fragment is the cold path) | a line reading of the case's own Router, which the build read in section 5 cannot give (section 5.2) |
| B1 | T5 (and T7's `emit_on_link`) | form | the four write facts of a link driver (whether it reports its writes, its last write, a class carried apart, that carriage's last write) compiled only with `link-wire-reports`, which only the tokio runtime names | -350 to -500 | lower: no clock read and four indirect calls fewer at each keep-alive deadline read; two fewer at each frame handed over | **built, `248c36d42d`** |
| W1 | T3, T9 | work | the handshake's regions: the peer's region name and remote bound read and refused when malformed, the bound the session decides and stages on its Open | -250 to -450 | none | **built** (section 6.1) |
| W5 | T5 | work | the watch of the peer's initial declarations (its deadline in the lease, its expiry in `judge_lease`) | -250 to -400 | none | **built, changed** (section 6.2): form, not work; a feature only the tokio runtime names |
| W2 | T3 | work | the node's admission of a link (`LinkAdmission`, `LinkLease`) and the `MaxLinks` close | -200 to -400 | none | **built** (section 6.3), under the capability `link-admission` |
| B2 | T5 | form | the lease's deadlines read once, out of line, for `fire_due` and `next_due_ms` | -150 to -300 | must not rise: a call per turn is added, so only with a per-turn Ir reading | the perf matrix arm W |
| W4 | T3 | work | the stray-message policy's replay of a held answer | -100 to -200 | none | as W1 |
| B5 | T6 | form | no Control barrier on one conduit | -60 to -150 | none | merging `sz-transport2` |
| W3 | T3 | work | a dial's expected peer (the InitAck's zid against the node the dial was made for) | -80 to -150 | none | as W1 |

Together, the wz steps (B and W) are about -2,430 to -4,305 on the row with B3 and B4 as section
5.3 splits them (-2,850 to -4,850 before that reading), S-SCE another -2,000 to -2,900; the rest of
the gap is attribution (T10, T11) and the hot receive walk (T2).

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

## 5. B3 and B4 read line by line

The two steps' bytes lie in lines inlined into `write_n_msg` and `fragment_in_place`, which the
explain document places by body and owner but not by line. They are read here in a library with
line tables: the `capi-nostd` build of `wz-capi-pico` of 2026-11-27, disassembled with
`objdump -d -l --inlines`, each instruction's bytes given to the line of the read body that holds
it, the deepest such line of its inline stack. That build is not the case: it has threads (its
locks and SN counters are atomics), the accept side, `tx-fragment-credit`, the probe and a
`ManyPeers` Router, and its source is main before B1. Its figures are its own; what only it has
is said where it matters. The case's library carries no line tables, so no line of the case is
read here.

### 5.1 `write_n_msg` (1,557 bytes in that build; 1,498 in the case's transport area)

| part | bytes |
|------|------:|
| **join the frame the conduit holds open** (`batch.stage.lent`) | **514** |
| the window's test and the open slot taken out of the stage | 54 |
| its holder found (`with_batch_holder`, one record read) and the holder-gone arm | 42 |
| picked up as a lease (`TxLease::pick_up`) | 53 |
| the frame's reliability read off its first byte | 45 |
| the message written (`TxSink`, `write_body`) | 45 |
| joined: the count, and the slot put down again (`keep_open`) | 92 |
| not joined: the roll-back 26, the record and the count cleared 27, the frame sent (`send_lent_batch`, inlined) 130: of it 52 the lease copied whole into the callee's parameter, 37 the emit call, 41 the lease's drop test and give-back call | 183 |
| **the congestion ask** (`congested_within`) | **113** |
| **the lend's budget and band** | **29** |
| **lend a slot and write a frame** (the `with_conduit_link` closure) | **672** |
| the lend (`lease_on`, the `acquire` call, the `None` test) and a window slot's shortness | 55 |
| the SN minted (an atomic add in that build, a cell in the case) | 42 |
| held to the budget (`hold_to`) | 40 |
| the envelope and the message (`encode_frame_envelope_into`: the `begin_frame` call, `TxSink`, `write_body`) and its answer | 130 |
| a window's frame kept open: the window's test 11, the stale-record arm 41, the frame counter 3, `tx_slot_spare` and its test 22 (accept side only), `keep_open` and the record 70, the count 18 | 165 |
| a frame sent whole: the emit call | 38 |
| the lease's drop at the closure's end (the sent test and the give-back call) | 80 |
| the SN handed on, the frame counter, the closure's own lines | 122 |
| **the lend-only answer** (refusals, the chain's call, the SN given back) | **156** |
| **entry and exit** | **73** |

The lease is per-frame code in four places of this one body: picked up 53, put down 64 and 70,
copied 52, dropped 41 and 80, 360 bytes; the holder record that says which link lent the open
frame is 42, 19, 41 and 13 more, 115 bytes. Around the body, in the case: `TxLease::acquire` 149,
the lease's `TxBuf` table 267, its drop glue 33. The counting pass is the fragment chain's alone (a
lend-only frame asks for the whole budget and measures nothing): `emit_fragments_encoded` 145,
`try_encoded_len` 93, `CountTxBuf`'s table 72, 310 bytes in the case.

### 5.2 `fragment_in_place` (3,581 bytes in that build; 2,152 in the case's transport area)

| part | bytes |
|------|------:|
| **the Router's ingest** (`ingest_keeping`, `judge`) | **2,594** |
| the chain's machine driven and the chain delivered (`drive_open_chain`): `finish` 481 with the delivery closure 113, the stage's append 255, the rest 179 | 915 |
| a chain opened (`admit_chain_start`): the staging's `acquire` 237, the quota's count 228, the open chain written 111, a full pool's policy (`make_room`) 80, the chain's key 58, the bound 38, the rest 110 | 862 |
| a continuation admitted (`admit_continuation`) | 240 |
| the open chain found (`find_active`) | 185 |
| the chain markers | 100 |
| the rest of `judge` and the slot ended | 292 |
| **the facts read in one hold** (a lock in that build, a cell in the case) | **158** |
| **the head's gates, the events and the reports around the ingest** | **829** |

Of the Router's 2,594, about 360 are `ManyPeers`' own: the peer comparison in the quota's count
and in `find_active` (105 and 117), the peer key written into the open chain (58) and a full
pool's eviction (80), which a `OnePeer` Router refuses at once. The case's Router has none of
them, so this build cannot say which lines hold the case's 1,277 router bytes; it says where a
fold can cut. The search for the open chain, the free
slot and the quota's count are three walks of the same two slots; the `Judged` and `admitted`
answers carry a slot index and an outcome between `judge`, the two admissions and the drive; the
delivery is compiled once, but `finish` keeps two hand-up orders (released first for a kept or
lent chain, after for a borrowed one).

### 5.3 The steps, split by what the lines hold

| step | what | expected | send Ir | receive Ir | before it |
|------|------|---------:|---------|------------|-----------|
| B3a | **built** (commit "Borrow the open frame's lease into its send"): the open frame's lease lent to `send_lent_batch` by reference, so a message that does not join the open frame copies no lease whole (the 52 of 5.1) | -40 to -55 | lower: one 56-byte copy fewer on that message, no call added | none | built |
| B3b | the conduit's open frame written where it lies: one write cursor over the slot's memory, the one `TxBuf` table of a lent frame, which the lease holds as a field, so neither the pick-up nor the put-down copies the frame's state | -150 to -250 | lower | none | a build loop: the lease and its put-down forms are named on 115 lines of 9 other files |
| B3c | the slot held for the batch: a single-conduit lend-only link lends the batch one slot, and a frame that does not join leaves before the next opens in it, as zenoh-pico's batch does; no per-frame `acquire`, no holder record | -250 to -500 | lower: no lend per frame | none | B3b; the cooperative link's slot pool (driver area) |
| B3d | the chain's length read off its first fragment's run (`BodyWindow` counts the message's position already): no counting pass, so `emit_fragments_encoded`, `try_encoded_len` and `CountTxBuf`'s table leave the lend-only build | -200 to -300 | none (a chain only) | none | B3b; the cap's refusal moved between the first fragment's write and its emit |
| B4a | one open chain per reliability in a `OnePeer` Router: the slot is the reliability's index, so no search, no free-slot walk and no quota count | -150 to -250 | none | none per sample (a fragment is the cold path) | a line reading of the case's own Router |
| B4b | the ingest one body: the admissions and the drive without the `Judged` and `admitted` hand-offs, one hand-up order | -200 to -400 | none | none per sample | B4a |

B3 is -640 to -1,105 by these lines, below the earlier -800 to -1,300 at both ends; B4 is -350
to -650, below the earlier -600 to -1,000. None of the steps touches the receive's hot path (a
frame's records are walked as before), and none adds a call to the send path.

## 6. The work steps as built

Each work step follows the owner's ruling of section 3 and the shape of the send's four
(`tx-probe` and its siblings): the session core's feature, on by default, which the tokio engine's
runtime keeps whatever is named; the pico ABI's capability of the same name (`deploy/wz-config.toml`,
`upstream_off = ["zenoh-pico"]`), forwarded by `wz-capi-pico`, `wz-capi-core` and
`wz-capi-coop`; off in the zenoh-pico preset and on in the release profiles (`host-peer`,
`host-peer-ext`, `host-peer-raweth`). A step whose reading here did not match the code is
changed or stopped, and the reason is written under it. Nothing below was built or measured by this
lane.

### 6.1 W1, the handshake's regions (`handshake-regions`)

Without the feature neither region extension is read: each is one the build does not know, which
zenoh-pico's decoders skip as they skip any extension that is not mandatory
(`vendor/zenoh-pico/src/protocol/codec/transport.c` @ `z_result_t _z_init_decode_ext(`), and
neither is.

- the readers of a chain, held or read where it lies (`inbound::ExtChainRead`), answer the
  region and the bound as none whatever the entries hold, so an InitSyn or an InitAck with a
  malformed region name and an Open with a bound of neither value refuse nothing, and the session
  holds no region and no bound of its peer; the walk of a chain read in place keeps no answer for
  either (`ChainAnswers`), and the slot profile's keeper keeps neither entry;
- the acceptor's admission of the OpenSyn's bound and the decision of the bound announced on the
  Open (`decide_local_remote_bound`) are not compiled into the dispatch, so no bound is decided and
  none is announced, as zenoh-pico's Open carries none;
- a build that stages no handshake extension (`ext_chains_cfg`) writes its Open with no chain;
  a build that holds the chains keeps their staging of the bound, which shares the patch level's
  place in the chain machinery (`ext_chain::StagedExt`): with nothing decided it stages none.

`south-subregions` implies the feature, a bound decided by a rule being one announced. The receive's
hot path is untouched: every line removed reads a handshake message. The tests that hold it are the
readers' (`inbound::control_read_tests`) and the lent Open's
(`session_actions::bundle_tests::lent_handshake`), each stating what both builds read and write,
run without the feature by two legs of `scripts/lib/nondefault-tests-gate.sh`.

### 6.2 W5, the watch of the peer's initial declarations (`declaration-sync-watch`)

**Changed from the table.** The watch begins on the first event an engine notes of a session
(`SessionLinkActions::note_declare_finals_in`), and only the tokio runtime notes them
(`crates/wz-runtime-tokio/src/session_glue.rs` and `src/session/mod.rs`); the cooperative engine,
and so every build of the case and of the release libraries over it, never does, so its progress
stays at the "no engine notes" mark and the watch never runs there, whatever the policy and the
limit say (`DECLARATION_SYNC_RX_NO_PROGRESS_MS` already reads "Only the tokio engine reads it").
The row's bytes are code no driver of those builds can reach, which is B1's kind and not a
behaviour a capability would switch: a capability turned on in a release profile would compile a
watch that still never runs. So it takes B1's shape: the session core's feature, a default, named
by the tokio runtime alone.

Without it the session keeps no progress word, an event noted begins nothing, the lease's
deadlines are its expiry alone (`drive::LeaseDeadlines`), `judge_lease` judges no watch, and no
quiet window settles an accepted link's sync under `until-declarations-synced-when-begun`, as
with the window at 0. The test that holds it is
`session_actions::bundle_tests::link_stamps::a_build_without_the_declaration_watch_wakes_for_the_lease_alone`,
run without the feature beside the line-mark row of `scripts/lib/nondefault-tests-gate.sh`; the
watch's own tests are compiled with the feature only.

What is left: a statement of `DECLARATION_SYNC_RX_NO_PROGRESS_MS` is still taken by a build that
reads it nowhere. Its refusal by name is the limit's `read_by`, which names a capability, and this
is not one; it waits for an engine of the C library that notes the peer's declarations.

### 6.3 W2, the node's admission of a link (`link-admission`)

The capability is the one the peer lane declared (`deploy/wz-config.toml`, `link-admission`,
taken here by `git cherry-pick` of its commit and of its test fix, the same changes as on the
integration branch): it gates the cooperative engine's admission, the arena row and the install in
each link's handshake, and turned on nothing of the session core, whose half stayed compiled into
every build with an allocator, the dial-only case included. This step is that half: the session
core's feature of the same name, a default, which `wz-runtime-coop`'s `link-admission` and the
tokio runtime name. Without it:

- a link carries no lease (`SessionLinkActions::link_lease`), and the install, the three
  questions the handshake asks (`link_admitted`, `link_admitted_for_remote`, `link_confirmed`),
  the room check, the `MaxLinks` refusal and the release are not compiled; the node a link's
  admission was asked about (`link_admission_node`), which the engine reads of a listening
  session's faces either way, is none;
- the dispatch asks nothing, so every link that ends its handshake is a face of its own;
- a peer's `MaxLinks` Close before the establishment is a Close like any other, where a build with
  it reports the link refused (`DriverLoopOutcome::LinkRefused`).

The node's tables (`link_admission::LinkRegistry`, `LinkBook`) and the tie rule stay in
`link_admission`, ungated: they are the node's, which a build that links none of the session's
questions does not instantiate. The test is
`session_actions::bundle_tests::unicast_transport::a_peers_max_links_close_is_a_refused_link_only_where_links_are_admitted`,
which states both builds and runs without the feature in a leg of
`scripts/lib/nondefault-tests-gate.sh`; the engine's own tests of one face to a node and of a
face per link are the peer lane's (`tests::one_face`, `tests::one_thread::listen`).

// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2226 (open-debt item 575) — FOREIGN-INTEROP for a sender that ABANDONS a
//! fragment chain: a real `zenohd` is made to run out of batches
//! mid-fragmentation, and what it actually puts on the wire is MEASURED.
//!
//! ⛔⛔⛔ THE HEADLINE, BECAUSE IT REVERSES WHAT THIS LEG WAS COMMISSIONED FOR.
//!
//! Item 575 asked for a genuine witness that moves
//! `fragment_chains.aborted_sender_dropped` off zero, on the premise that
//! "zenoh (Rust) emits the `0x3 Drop` marker in production and is the only
//! implementation that does". The first half of that premise is FALSE ON THE
//! WIRE, and this leg is the measurement.
//!
//! Upstream has exactly one emit site — `pipeline.rs:403` at zenoh 1.5.0,
//! `fragment.ext_drop = Some(fragment::ext::Drop::new())`. Three lines around
//! it decide its fate:
//!
//! ```text
//!   let mut batch = WBatch::new_ephemeral(self.batch_config);
//!   self.fragbuf.clear();                       // <- the payload is emptied
//!   fragment.ext_drop = Some(..);
//!   let _ = batch.encode((&mut self.fragbuf.reader(), &mut fragment));
//!   self.s_out.move_batch(batch);               // <- sent regardless
//! ```
//!
//! The codec for `(&mut ZBufReader, &mut FragmentHeader)`
//! (`zenoh-codec/src/transport/batch.rs:198-232`) writes the header, then ends
//! with `r.siphon(&mut *writer)`. `ZBufReader::siphon` finishes
//! `NonZeroUsize::new(read).ok_or(DidntSiphon)` (`zenoh-buffers/src/zbuf.rs:343`),
//! so a reader with NOTHING IN IT — which `fragbuf.clear()` guarantees — cannot
//! return `Ok`. The codec rewinds, `encode` returns `Err`, THE RESULT IS
//! DISCARDED, and an EMPTY batch is moved out and written to the link.
//!
//! ⇒ **No implementation puts `0x3 Drop` on the wire.** wz's encoder has no
//! production caller, zenoh-pico's one call site passes `false`
//! (`src/transport/common/tx.c:466`), and zenoh (Rust) tries and fails. So
//! `aborted_sender_dropped` cannot be moved off zero by any genuine peer at
//! this pin, and a leg that claimed otherwise would have had to synthesise the
//! bytes — which is exactly the synthetic witness item 575 exists to replace.
//!
//! MEASURED, not deduced: on the arm below whose stall outlasts upstream's
//! budget, the router's direction carries EXACTLY ONE zero-length batch and it
//! is the last thing the router writes; wz then reports `ParseError(Empty)` and
//! `LinkLost(PeerClosed)`. On the twin, whose stall is shorter than the same
//! budget, there is none.
//!
//! ## What this leg therefore witnesses
//!
//! That the router REACHED its abandon path — the empty batch is the signature
//! — and that the marker did not survive the encode. Both halves are pinned, so
//! the day upstream repairs that `encode` this leg REDS and says so, at which
//! point item 575's genuine witness becomes buildable for the first time.
//!
//! ## R2227 — AND THAT THE ZERO IS ABOUT THE ROUTER, NOT ABOUT THE READER
//!
//! Everything above rests on `drop_marked == 0`, which is produced by ONE walk
//! over the recorded bytes (`fragment_ext_offset`). A walk that cannot reach
//! `0x3` returns exactly the same zero as a wire that does not carry one, and
//! as filed the leg had nothing that told the two apart — the class this tree
//! has recorded as "a dead probe and a negative result look the same".
//!
//! Two halves now do, and they answer different halves of the question:
//!
//!   * on the ROUTER'S OWN BYTES — `drop_reader_seen_on_router_bytes`, a
//!     precondition of BOTH arms: take a batch the router really wrote,
//!     re-label its `0x2` envelope `0x3`, and the walk must find it. One byte
//!     from what upstream would have sent had its encode survived, and it
//!     asserts about the reader only;
//!   * on UPSTREAM'S ENVELOPE SHAPES — the control group at the end of this
//!     file, which needs no zenohd and so runs in the DEFAULT lane, where the
//!     two arms above never do.
//!
//! MEASURED, and it corrected the guess that prompted it: the reader defect
//! that survives every pre-existing assertion is a narrowed ID MASK, not a
//! reordered chain walk. Under `EXT_MID_MASK = 0x1E` both arms keep
//! `first_marked` (1 and 7) and keep `drop_marked == 0`, every assertion this
//! leg was filed with passes, and only the new precondition reds.
//!
//! ## THREE conditions at once, and the third is the one that is easy to miss
//!
//! Reaching that emit site needs all of:
//!
//!   1. the pipeline runs out of batches mid-fragmentation, so `s_ref.pull()`
//!      yields `None` and the deadline arm is taken;
//!   2. the message is DROPPABLE. `pipeline.rs:823` takes the deadline arm only
//!      for `msg.is_droppable()`, which is `!is_reliable() ||
//!      congestion_control == Drop`
//!      (`commons/zenoh-protocol/src/network/mod.rs:162`). A **Block** message
//!      takes the `wait_before_close` arm instead: the session is TORN DOWN and
//!      no marker is written at all. That is why the publisher here names
//!      `congestion_control: "drop"` rather than inheriting a default;
//!   3. ⚠ **at least one fragment already emitted.** The marker sits in the
//!      `else` of `if fragment.ext_first.is_some()`. On the FIRST fragment
//!      upstream merely resets the sequence number and writes NOTHING; only
//!      once `ext_first` has been cleared — which happens after the first
//!      successful encode — does the restore arm build the ephemeral stop
//!      fragment.
//!
//! The third is why this leg asserts `begun >= 1` BEFORE it reads the drop
//! counter, and the two are one fact rather than a sanity check followed by the
//! real one: a chain that never started cannot be abandoned, and wz's own
//! reassembler agrees — `reassembly_dispatch.rs:553` reaches `SenderDropped`
//! only with a chain already active.
//!
//! ## Topology
//!
//! ```text
//!   zenoh z_pub ──tcp──> zenohd ──tcp──> [stalling relay] ──tcp──> wz
//!   (genuine, 56 KiB,      (splits to the      ^ stops READING       (subscriber)
//!    congestion=drop)       negotiated MTU)      inside the chain
//! ```
//!
//! ## Why the stall is on the READ, and why it is a legal thing for a wire to do
//!
//! A relay that stopped WRITING would still drain its upstream socket, so the
//! router would never block and never exhaust. Stopping the READ is what
//! propagates back-pressure — the ordinary behaviour of a slow consumer. A
//! receiver that stops reading for a moment violates nothing, and the sender's
//! reaction to it is the production path under witness. Nothing is dropped,
//! reordered or rewritten: every byte the router wrote is forwarded, in order,
//! after the hold.
//!
//! ## The option-atom PAIR, and it differs in ONE NUMBER
//!
//! Both legs run the SAME helper, the SAME router config and the SAME genuine
//! publisher. The only difference is how long the relay stalls:
//!
//!   1. the PROOF ([`OUTLASTING_HOLD`]): longer than upstream's own
//!      `max_wait_before_drop_fragments` budget, so the deadline expires and
//!      the router abandons the chain.
//!   2. the TWIN ([`BRIEF_HOLD`]): shorter than that budget, so the router
//!      WAITS THE STALL OUT and finishes the chain. Same fault, same
//!      back-pressure, same kernel buffers — and no marker.
//!
//! That is a sharper control than "fault versus no fault" would be. It isolates
//! upstream's DEADLINE as the thing that decides, which is the claim being
//! made: the marker is the router's own policy and not something the harness
//! manufactured. A fault-versus-none pair would leave "the relay caused it"
//! open.
//!
//! ## What each half reads
//!
//!   * the RECORDING, read by a parser that is not the census
//!     ([`fragment_ext_present`], walking the ext chain by hand), says whether
//!     the router put a Fragment carrying ext `0x3` on the wire, and how many
//!     zero-length batches it wrote. Without a reader outside the census the
//!     leg would be asking wz's counter to vouch for wz's counter.
//!   * the CENSUS over the same bytes says a chain had `begun`, and that no
//!     abort was misfiled — `aborted_out_of_order` is a lossy link and
//!     `aborted_superseded` is a restart, and a document reporting either would
//!     send a consumer to a diagnosis the wire does not support.
//!
//! ## ⚠ The wz-side consequence, recorded rather than asserted here
//!
//! wz meets that empty batch with `ParseError(Empty)` and drops the link. Whose
//! defect that is, and whether a receiver should survive a peer's malformed
//! zero-length batch, is a question about wz and not about this leg's subject;
//! it is filed as its own open-debt item rather than settled in an assertion
//! here.
//!
//! Opt-in (`#[ignore]`, run-ci Layer Z): zenohd and the core zenoh `z_pub`
//! example are external binaries. The test NAMES carry `zenohd` because Layer
//! E's skip filter is a name substring (R311y437).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use wz_capture::Dissection;
use wz_codecs::wire_const::T_MID_FRAGMENT;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, frag_payload, spawn_counting_relay,
    spawn_publishing_zenoh_zpub_dropping, spawn_zenohd_shallow_tx_queue_on_ephemeral_tcp,
    wz_ap_demo_binary, zenoh_core_example_binary, RelayFault,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, Side};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{SubscribeOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{initiate_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::zenohd_interop_session_init_params;
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 16384;
const SUB_KEYEXPR: &str = "demo/**";
const PUB_KEY: &str = "demo/chain-drop";

/// Upstream's OWN budget for a multi-fragment droppable message, in the units
/// its config uses: `max_wait_before_drop_fragments`, 50000 µs
/// (`DEFAULT_CONFIG.json5:626-632`).
///
/// LEFT AT ITS DEFAULT on the router, which is the point — see
/// `spawn_zenohd_shallow_tx_queue_on_ephemeral_tcp`. It is written here because
/// the two holds below are defined against it, and a reader has to be able to
/// see all three numbers at once.
const UPSTREAM_DROP_FRAGMENT_BUDGET: Duration = Duration::from_micros(50_000);

/// The PROOF arm's hold: comfortably longer than the budget, so the deadline
/// expires while the router still has fragments to send.
///
/// ⚠ SIZED FROM BOTH ENDS OF A WINDOW THIS LEG HAD TO MEASURE.
///
/// Below, it must outlast [`UPSTREAM_DROP_FRAGMENT_BUDGET`], which is what the
/// pair is about.
///
/// Above, it must NOT outlast WZ'S OWN TOLERANCE FOR SILENCE. MEASURED at
/// 2500 ms: the arm ran 4.5 s and ended with `drive_session_until_terminal`
/// returning `Terminated` — nothing reaches wz for the whole hold, its session
/// gives up, and the arm is over before the link can drain the marker out. A
/// hold that kills the session witnesses nothing, and it witnesses it while
/// looking exactly like a router that never abandoned.
///
/// So the window is roughly 50 ms … 2 s, and this sits an order of magnitude
/// inside both edges. What makes that possible is [`PAYLOAD_LEN`]: one message
/// larger than the bounded buffers blocks the router within its FIRST chain, so
/// the hold no longer has to wait for a republishing publisher to accumulate
/// volume.
const OUTLASTING_HOLD: Duration = Duration::from_millis(400);

/// The TWIN arm's hold: comfortably shorter, so the router waits it out.
const BRIEF_HOLD: Duration = Duration::from_millis(5);

// The relation is the whole design of the pair, so it is checked by the
// compiler rather than left to two numbers that happen to be ordered.
const _: () = assert!(BRIEF_HOLD.as_micros() < UPSTREAM_DROP_FRAGMENT_BUDGET.as_micros());
const _: () = assert!(OUTLASTING_HOLD.as_micros() > UPSTREAM_DROP_FRAGMENT_BUDGET.as_micros());

/// The MTU wz advertises, which zenohd min-negotiates to
/// (`accept.rs:220-224`), so the routed Put no longer fits one batch.
///
/// Small enough to guarantee a chain, large enough that the first fragments
/// clear the kernel buffers before the sender blocks — condition 3 above needs
/// at least one fragment out.
const NEGOTIATED_MTU: u16 = 2048;

/// How much the genuine publisher sends per message.
///
/// ⚠ BOUNDED ABOVE BY THE OBSERVER, and this is the constraint that is easy to
/// miss: the census reassembles with `PassiveSession`'s geometry, whose
/// `PASSIVE_CHAIN_CAP` is 65536 bytes (`wz-session-core/src/passive.rs:1129`) —
/// NOT the runtime's 1 MiB slot. MEASURED at 64 KiB: every chain came back
/// `aborted_capacity_overflow`, so the twin could never show a completed one
/// and the proof's counter would have been read off a document that gave up
/// for an unrelated reason.
///
/// ⚠ It also has to survive being an `argv` string: Linux caps a single
/// argument at `MAX_ARG_STRLEN` (128 KiB), and the payload is passed to
/// `z_pub -p`.
///
/// ⚠ BOUNDED BELOW BY THE KERNEL. ONE message has to exceed what the bounded
/// buffers hold — MEASURED at ~45 KB — so the router blocks inside its FIRST
/// chain. At 32 KiB it did not: the hold then had to wait for a publisher that
/// republishes about once a second to accumulate the volume, which pushed it
/// past what wz's session will sit through in silence.
///
/// The two bounds leave a narrow band, and this sits in it: above ~45 KB and
/// below 64 KiB, with room for `z_pub`'s 7-byte counter prefix and the
/// keyexpr.
const PAYLOAD_LEN: usize = 56 * 1024;

/// What one arm observed.
struct ArmOutcome {
    /// The census document over the bytes the RELAY recorded.
    census: String,
    /// Fragment batches the router wrote carrying ext `0x3`, counted by
    /// `wz_integration_tests::fragment_ext`'s walk rather than by the census.
    drop_marked: usize,
    /// Fragment batches the router wrote carrying ext `0x2`, the chain starts.
    first_marked: usize,
    /// Whether the reader that produced `drop_marked` CAN see a `0x3` in the
    /// bytes this very arm recorded — `fragment_ext::drop_reader_alive_on`,
    /// which takes one batch the router really wrote and re-labels its `0x2`
    /// envelope `0x3`.
    ///
    /// ⚠ WITHOUT THIS, `drop_marked == 0` HAS NO DISCRIMINATING POWER: a reader
    /// that structurally cannot reach `0x3` reports the same zero as a wire
    /// that does not carry it, and this leg's headline would rest on the reader
    /// rather than on the router. `first_marked` does not close it — see that
    /// module's own docs for the mutation that survives every other assertion
    /// here.
    drop_reader_seen_on_router_bytes: bool,
    /// Zero-length batches the router put on the wire — upstream's actual
    /// signature for reaching its abandon path. See the module docs.
    empty_batches: usize,
    /// Fragment-tagged batches the relay counted on the router's direction.
    fragment_batches: usize,
    /// How many times the stall fault actually held.
    stalls: usize,
    /// Whether wz delivered the whole payload byte-exact.
    delivered: bool,
}

/// The ext-chain walk, its two counters and its anti-vacuity probe live in
/// `wz_integration_tests::fragment_ext` rather than here, and that placement is
/// the point: Layer C0 requires `#[ignore]` of every `#[test]` in a binary-dep
/// fixture and Layer Z runs those with `-- --ignored`, so a control group
/// written in THIS file would run in no lane at all. In the lib it needs no
/// zenohd, no demo and no socket, and `cargo test --workspace` reaches it.
/// See that module's docs for what the control group is for and for the
/// mutation that survives every assertion in this file.
use wz_integration_tests::fragment_ext::{
    drop_reader_alive_on, ext_marked_batches, EXT_ID_DROP, EXT_ID_FIRST,
};

/// Drive one arm: a genuine publisher, a real zenohd whose tx path is shallow,
/// and a wz subscriber dialling THROUGH a relay that stalls inside the chain.
///
/// Shared by both legs so the ONLY difference between them is `hold`.
async fn subscribe_through_a_stalled_link(hold: Duration) -> ArmOutcome {
    let value = frag_payload(PAYLOAD_LEN);
    let z_pub = zenoh_core_example_binary("z_pub");

    // wz is IN-PROCESS here, so the demo binary enters only as the router's
    // handshake-readiness probe — and that is exactly where a stale one
    // misdirects: the probe fails to detect a router that IS up and the next
    // line then blames the session layer for a defect in the build.
    assert_demo_binary_newer_than_sources(&wz_ap_demo_binary());
    let (mut zenohd, zenohd_port) = spawn_zenohd_shallow_tx_queue_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    let relay = spawn_counting_relay(
        zenohd_port,
        T_MID_FRAGMENT,
        RelayFault::StallAcceptorToDialerInsideAChain { hold },
    );

    let mut params = zenohd_interop_session_init_params();
    params.batch_size = NEGOTIATED_MTU;
    let stream = TcpStream::connect(("127.0.0.1", relay.port()))
        .await
        .expect("wz dials the stalling relay");
    let opened = initiate_and_open_session(
        DialedLink::Tcp(stream),
        params,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await;
    let mut opened = match opened {
        Ok(opened) => opened,
        Err(e) => {
            let _ = zenohd.child_mut().kill();
            let _ = zenohd.child_mut().wait();
            panic!("wz did not reach Established against zenohd through the relay: {e:?}");
        }
    };

    let session = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );
    let delivered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _subscriber = {
        let delivered = Arc::clone(&delivered);
        let expected = value.clone().into_bytes();
        session
            .declare_subscriber(SUB_KEYEXPR, SubscribeOptions::default(), move |sample| {
                if sample.payload().ends_with(&expected[..]) {
                    delivered.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            })
            .expect("wz declares its routed subscriber")
    };

    // The publisher comes up AFTER the subscription so the route exists when it
    // starts; z_pub republishes on a cadence, so a first Put that raced the
    // declare is not the leg's only chance.
    let mut publisher = spawn_publishing_zenoh_zpub_dropping(
        &z_pub,
        PUB_KEY,
        &value,
        &format!("tcp/127.0.0.1:{zenohd_port}"),
        || tempfile::tempfile().expect("tempfile for z_pub stdout"),
    );

    let timeouts = SessionTimeouts::spec_defaults();
    let rx_reassembly_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let last_outcomes: Arc<std::sync::Mutex<Vec<String>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let outcome_tail = Arc::clone(&last_outcomes);
    let drive = {
        let last_outcomes = Arc::clone(&last_outcomes);
        // ⚠ THE SESSION'S OWN DISPATCH, not a standalone observer. MEASURED:
        // the first draft handed events to a fresh `ApplicationLayerObserver`,
        // so the subscriber callback never fired and BOTH arms reported
        // `delivered=false` while the census — reading the same wire —
        // reassembled twelve chains. A leg whose delivery witness is wired to
        // nothing reports the same thing whether or not delivery works.
        let session_drive = session.clone();
        let rx_reassembly_drops = Arc::clone(&rx_reassembly_drops);
        drive_session_until_terminal(
            &mut opened.inbound,
            &opened.actions,
            &mut opened.engine,
            None,
            &opened.clock,
            &timeouts,
            move |event| {
                if matches!(&event, IterationEvent::ReassemblyDropped(_)) {
                    rx_reassembly_drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                if let IterationEvent::Poll(outcome) = &event {
                    let mut tail = last_outcomes.lock().expect("outcome tail");
                    tail.push(format!("{outcome:?}"));
                    if tail.len() > 8 {
                        tail.remove(0);
                    }
                }
                session_drive.dispatch_iteration_event(event)
            },
        )
    };

    // Run long enough for the stall to elapse and for the router to write
    // whatever it is going to write afterwards. Both arms wait the SAME time,
    // so a difference in the readings is not a difference in observation.
    let scenario = async {
        let deadline = Instant::now() + OUTLASTING_HOLD + Duration::from_secs(6);
        while Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let started = Instant::now();
    let ended_by = tokio::select! {
        outcome = drive => format!("the drive loop returned ({outcome:?})"),
        () = scenario => String::from("the scenario's own clock"),
    };
    eprintln!(
        "  arm ran {:?} and was ended by {ended_by}; last poll outcomes: {:?}",
        started.elapsed(),
        outcome_tail.lock().expect("outcome tail").clone()
    );

    let recording = relay.recording();
    let fragment_batches = relay.acceptor_to_dialer_count();
    let stalls = relay.stalls();
    let _ = publisher.child_mut().kill();
    let _ = publisher.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    // ANTI-VACUITY: an empty recording satisfies every count below by having
    // nothing to count.
    assert!(
        !recording.is_empty(),
        "the relay recorded NOTHING, so every reading below is over an empty \
         wire"
    );
    let pcap = synthesise_pcap(&recording, relay.port(), zenohd_port);
    let dissection = Dissection::from_pcap(&pcap).expect("the recorded wire parses as a pcap");
    let census = wz_capture::census_json::census_json(&dissection);

    // Reported rather than asserted here: an arm is data, and every assertion
    // belongs in the `#[test]` that owns the claim. What is printed is what a
    // failure needs in order to be diagnosed in one run rather than three —
    // above all how many bytes the ROUTER got out during the hold, which is
    // what decides whether it ever blocked.
    let from_router: usize = recording
        .iter()
        .filter(|(side, _)| *side == Side::FromListener)
        .map(|(_, segment)| segment.len())
        .sum();
    let chains = census
        .split("\"fragment_chains\":")
        .nth(1)
        .and_then(|rest| rest.split_once("}}"))
        .map(|(head, _)| head.to_string())
        .unwrap_or_else(|| String::from("<no fragment_chains plane>"));
    // The LAST few transport MIDs the router wrote. A chain that stops because
    // the router CLOSED the session looks identical, in every count above, to
    // one that stops because it is still blocked — and the two want opposite
    // repairs.
    let tail: Vec<String> = recording
        .iter()
        .filter(|(side, _)| *side == Side::FromListener)
        .rev()
        .take(6)
        .filter_map(|(_, segment)| segment.get(2).map(|h| format!("{:#04x}", h & 0x1F)))
        .collect();
    let empty_batches = recording
        .iter()
        .filter(|(side, _)| *side == Side::FromListener)
        .filter(|(_, segment)| segment.len() <= 2)
        .count();
    let sizes: Vec<usize> = recording
        .iter()
        .filter(|(side, _)| *side == Side::FromListener)
        .rev()
        .take(6)
        .map(|(_, segment)| segment.len())
        .collect();
    eprintln!(
        "  last router MIDs (newest first): {tail:?}; empty_batches={empty_batches}; \
         last sizes (newest first): {sizes:?}"
    );
    eprintln!(
        "arm hold={hold:?}: stalls={stalls} fragment_batches={fragment_batches} \
         first_marked={} drop_marked={} router_bytes={from_router} \
         wz_reassembly_drops={} delivered={}\n  fragment_chains: {chains}",
        ext_marked_batches(&recording, T_MID_FRAGMENT, EXT_ID_FIRST),
        ext_marked_batches(&recording, T_MID_FRAGMENT, EXT_ID_DROP),
        rx_reassembly_drops.load(std::sync::atomic::Ordering::SeqCst),
        delivered.load(std::sync::atomic::Ordering::SeqCst),
    );

    ArmOutcome {
        census,
        drop_marked: ext_marked_batches(&recording, T_MID_FRAGMENT, EXT_ID_DROP),
        first_marked: ext_marked_batches(&recording, T_MID_FRAGMENT, EXT_ID_FIRST),
        drop_reader_seen_on_router_bytes: drop_reader_alive_on(&recording, T_MID_FRAGMENT)
            .unwrap_or(false),
        empty_batches,
        fragment_batches,
        stalls,
        delivered: delivered.load(std::sync::atomic::Ordering::SeqCst),
    }
}

/// The preconditions BOTH arms must reach before either one's drop reading
/// means anything.
///
/// Shared so the twin cannot quietly hold to a weaker standard than the proof:
/// a calibration arm that reported zero because nothing fragmented, or because
/// the fault never fired, is calibrating nothing.
#[track_caller]
fn assert_the_arm_reached_the_state_under_test(arm: &ArmOutcome, what: &str) {
    assert_eq!(
        arm.stalls, 1,
        "{what}: the stall fault held {} time(s). A reading taken without the \
         fault having fired says nothing about what the hold does",
        arm.stalls
    );
    assert!(
        arm.fragment_batches >= 2,
        "{what}: the router put {} fragment-tagged batch(es) on the wire; \
         without a chain there is nothing to abandon",
        arm.fragment_batches
    );
    assert!(
        arm.first_marked >= 1,
        "{what}: no batch carried the `0x2 First` marker, so no chain START \
         reached the wire"
    );
    // ── AND THE READER THAT WILL REPORT `drop_marked` IS ALIVE ────────────
    //
    // A precondition rather than a leg-local check, because BOTH arms read
    // `drop_marked == 0` and both would be vacuous the same way. The zero has
    // to mean "the router did not write `0x3`"; a walk that structurally
    // cannot reach `0x3` returns exactly the same zero, and `first_marked`
    // above does not exclude it — upstream writes `ext_drop` LAST, so the Drop
    // envelope is the one whose `Z` bit is clear, and a `Z`-before-id walk
    // keeps finding every `0x2` while never finding a `0x3`.
    assert!(
        arm.drop_reader_seen_on_router_bytes,
        "{what}: re-labelling a REAL recorded `0x2 First` envelope to `0x3` \
         did not make this file's ext walk find it, so `drop_marked` is read \
         by a walk that cannot see the marker and its zero means nothing"
    );
    // `begun` is asserted as NOT ZERO rather than as a literal: the publisher
    // republishes on a cadence, so how many chains a run contains is a
    // function of timing and pinning it would make the leg flake for a reason
    // that is not its subject.
    assert!(
        !arm.census.contains("\"begun\":0"),
        "{what}: the census counted no chain as begun\n--- census ---\n{}",
        arm.census
    );
}

/// Assert `key` reads `want` in a census document, naming the document when it
/// does not.
#[track_caller]
fn census_says(doc: &str, key: &str, want: &str, why: &str) {
    let needle = format!("\"{key}\":{want}");
    assert!(
        doc.contains(&needle),
        "the census does not say {needle}: {why}\n--- census ---\n{doc}"
    );
}

// wz-proves: transport-fragmentation zenohd->wz
// wz-proves: codec-fragment zenohd->wz
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router + the core zenoh z_pub example); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn wz_counts_a_chain_a_genuine_zenohd_abandoned() {
    let arm = subscribe_through_a_stalled_link(OUTLASTING_HOLD).await;

    // ── THE CHAIN STARTED, first and structurally ─────────────────────────
    //
    // Not a sanity check preceding the real one: upstream writes the marker
    // only once `ext_first` has been cleared, and wz raises `SenderDropped`
    // only with a chain already active. A leg that read the drop counter
    // without this would not know whether a zero meant "no abandon" or "no
    // chain".
    assert_the_arm_reached_the_state_under_test(&arm, "the proof arm");

    // ── UPSTREAM REACHED ITS ABANDON PATH, and this is its signature ──────
    //
    // A zero-length batch is not something a healthy router writes. It is what
    // `pipeline.rs:395-407` produces when the deadline expires mid-chain: the
    // ephemeral stop batch, whose encode failed, moved out anyway.
    assert_eq!(
        arm.empty_batches, 1,
        "the router wrote {} zero-length batch(es). Exactly one is the \
         signature of it taking the abandon path once; none means the stall \
         never made it run out of batches and the arm measured a healthy link",
        arm.empty_batches
    );

    // ── AND THE `0x3 Drop` MARKER DID NOT SURVIVE THE ENCODE ──────────────
    //
    // ⚠ THIS ASSERTION IS THE OPPOSITE OF WHAT THIS LEG WAS COMMISSIONED TO
    // MAKE, and the inversion is the round's finding rather than a concession.
    // See the module docs: upstream assigns `ext_drop`, then hands the codec an
    // EMPTY reader, and `siphon` refuses to produce a `NonZeroUsize` from zero
    // bytes — so `WBatch::encode` rewinds and the marker never reaches the
    // wire. The result is discarded (`let _ = batch.encode(..)`), which is why
    // an empty batch goes out in its place.
    //
    // A RED HERE IS GOOD NEWS: it means the pinned upstream started emitting
    // the marker, and open-debt item 575 — a genuine witness for
    // `aborted_sender_dropped` — becomes buildable. The repair is then to
    // invert this back and assert the census counter, not to widen the number.
    assert_eq!(
        arm.drop_marked, 0,
        "the router put the `0x3 Drop` ext on the wire. zenoh 1.5.0 cannot: \
         its one emit site clears the fragment buffer before encoding, and the \
         codec refuses a zero-byte fragment. If this reds, upstream has fixed \
         that and item 575's genuine witness is now buildable"
    );
    census_says(
        &arm.census,
        "aborted_sender_dropped",
        "0",
        "and the census agrees, because the marker it counts never crossed \
         the wire",
    );

    // ── NOR WAS THE ABANDON MISFILED AS SOMETHING ELSE ────────────────────
    //
    // The register's completion condition ④, and it still holds and still
    // matters: whatever the router did, the document must not report it as a
    // lossy link or as a restart. Both would send a consumer to a diagnosis
    // the wire does not support.
    census_says(
        &arm.census,
        "aborted_out_of_order",
        "0",
        "an abandoning sender is not a lossy link",
    );
    census_says(
        &arm.census,
        "aborted_superseded",
        "0",
        "nor a restart over an open chain",
    );
}

// wz-proves: none -- the CALIBRATION twin of the leg above.
//
// It witnesses that the SAME back-pressure, applied for LESS TIME than
// upstream's own `max_wait_before_drop_fragments`, leaves the chain intact:
// the router waits the stall out and finishes. That is what forbids reading
// the sibling's marker as something this harness manufactured, and it is why
// the pair differs in one number rather than in whether a fault ran at all.
//
// A chain that correctly completes proves no atom's cross-impl behaviour, so
// this leg claims none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router + the core zenoh z_pub example); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn wz_sees_no_abandon_when_a_genuine_zenohd_outwaits_the_stall() {
    let arm = subscribe_through_a_stalled_link(BRIEF_HOLD).await;

    // The SAME preconditions, through the SAME helper.
    assert_the_arm_reached_the_state_under_test(&arm, "the twin arm");

    // THE DISCRIMINATOR. The sibling's zero-length batch appears only when the
    // hold outlasts upstream's own budget; hold for less and the router waits
    // it out, finishes the chain, and writes nothing malformed. That is what
    // attributes the sibling's reading to the DEADLINE rather than to
    // back-pressure, to this relay, or to the bounded buffers — all three of
    // which are identical here.
    assert_eq!(
        arm.empty_batches, 0,
        "the router wrote a zero-length batch while being stalled for less \
         than its own drop-fragment budget, so the sibling's is not \
         attributable to the deadline"
    );
    assert_eq!(
        arm.drop_marked, 0,
        "the router put a `0x3 Drop` ext on a chain it completed"
    );
    census_says(
        &arm.census,
        "aborted_sender_dropped",
        "0",
        "a chain that completed was not abandoned",
    );

    // And the link WORKS: the payload arrives whole. Without this the twin's
    // zero could mean "the stall broke the session" rather than "the router
    // waited it out".
    assert!(
        arm.delivered,
        "the payload did not arrive intact through a briefly stalled link, so \
         this arm is not a healthy baseline"
    );
}

// The control group for the reader above is NOT here, and its absence is
// deliberate: see the `use` near the top of this file and
// `wz_integration_tests::fragment_ext`.

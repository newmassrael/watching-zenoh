// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2200 (open-debt item 558) — FOREIGN-INTEROP PER-CONDUIT reassembly: two
//! genuine publishers on DIFFERENT conduits fragment through a real `zenohd`
//! into watching-zenoh, their chains are made to OVERLAP on the wire, and wz
//! reassembles both into byte-exact `Sample`s.
//!
//! ## The gap this closes
//!
//! `transport-fragmentation` had two zenohd witnesses already
//! (`wz_fragment_tx_zenohd_interop.rs`, `wz_fragment_rx_zenohd_interop.rs`) and
//! neither says anything about CHANNELS: the words `priority`, `reliability`,
//! `conduit`, `channel` and `qos` appear in neither file. wz keys a reassembly
//! chain on `(peer, reliable, priority)`
//! (`wz-session-core/src/reassembly_dispatch.rs`), and the only thing measuring
//! that key was `C1bb`, a lane where wz grades wz. The consuming surface that
//! reported this gap judges answers by whether a GENUINE counterparty produced
//! them, so a unit lane could not fill it.
//!
//! ## Why an overlap has to be manufactured, and why that is honest
//!
//! MEASURED, R2200, against a live router: two publishers at priority 1 and
//! priority 6, both fragmenting to a 64-byte MTU on ONE link, arrive as
//!
//! ```text
//!   1 1 1 1 1 | 6 6 6 6 6 | 1 1 1 1 1 | 6 6 6 6 6 ...
//! ```
//!
//! strictly sequential — the genuine router flushes before it fragments and
//! holds one mutex for the whole chain
//! (`wz-integration-tests/src/lib.rs`, `spawn_counting_relay`'s docs, citing
//! `io/zenoh-transport/src/common/pipeline.rs:281`).
//!
//! **A sequential stream discriminates nothing.** An implementation that keyed
//! reassembly on the peer alone, ignoring the conduit entirely, reassembles it
//! correctly: each chain opens, completes and closes before the next begins.
//! Only an OVERLAP separates that implementation from wz's, and neither peer
//! will produce one, so the transport in between does —
//! [`RelayFault::InterleaveConduitsAcceptorToDialer`], which holds a whole
//! chain until a fragment on ANOTHER conduit has overtaken it.
//!
//! That is a legal thing for a wire to do, and the reason is the point of the
//! test: reordering ACROSS conduits is what a conduit IS, each carrying its own
//! sequence-number space. WITHIN one conduit the fault preserves order exactly.
//! Every byte in both chains is still the genuine router's; only their
//! interleaving is the harness's.
//!
//! ## What each half witnesses, and why no one of them is the proof
//!
//!   * the RELAY reports two distinct conduits, read off the wire by a parser
//!     that is not wz's ([`Conduit`] via `fragment_conduit`), plus how many
//!     batches it held and how many overtook them. Without the last two the leg
//!     could pass on a stream that never overlapped.
//!   * WZ's own drive loop reports the conduit of every fragment it decoded.
//!     The leg asserts this MATCHES the relay's reading: two independent
//!     parsers over the same bytes, so a leg whose only witness was wz's decode
//!     is not asking wz whether wz was right.
//!   * BOTH payloads arrive byte-exact under their own key. This is the
//!     completion witness and the only assertion that cannot hold unless two
//!     separate chains were tracked at once — a single-context reassembler
//!     splices the overtaking chain's chunks into the held one and delivers
//!     garbage, or nothing.
//!
//! ## Two AXES, and why one of them is not enough
//!
//! wz's chain key has TWO discriminating halves, `reliable` and `priority`, and
//! a leg that varied both at once would pass on an implementation that read
//! either one alone. So each axis holds the other half FIXED:
//!
//!   * [`PRIORITY_AXIS`] — priority 1 vs 6, both reliable. This half rides the
//!     `ext_qos` extension.
//!   * [`RELIABILITY_AXIS`] — reliable vs best-effort, both at priority 6. This
//!     half rides the Fragment header's `R` flag
//!     (`wz-session-core/src/inbound.rs:670`), which no amount of `ext_qos`
//!     parsing reaches.
//!
//! MEASURED, R2200 — the two are separately load-bearing, and the discriminator
//! is orthogonal. Dropping `priority` from `find_active` reds the priority
//! proof and NOTHING else; dropping `reliable` reds the reliability proof and
//! nothing else. Each mutation leaves three of the four arms green, so neither
//! arm is carrying the other.
//!
//! ## The option-atom TWIN, per axis
//!
//! All four legs run the SAME helper against the SAME router. Within an axis
//! the only difference is the relay fault:
//!
//!   1. the PROOF (`InterleaveConduitsAcceptorToDialer`): chains overlap,
//!      `held >= 1`, `overtaken >= 1`, both payloads byte-exact.
//!   2. the TWIN (`RelayFault::None`): the same two conduits, the same
//!      fragmentation, NO overlap — `held == 0` and `overtaken == 0` — and both
//!      payloads still arrive. It is what forbids reading either counter as a
//!      constant, and it isolates the overlap as the ONLY difference between a
//!      leg that discriminates and one that does not.
//!
//! Opt-in (`#[ignore]`, run-ci Layer Z): zenohd and the core zenoh `z_pub`
//! example are external binaries. The test NAME carries `zenohd` because Layer
//! E's skip filter is a name substring (R311y437).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use wz_codecs::wire_const::T_MID_FRAGMENT;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, frag_payload, spawn_counting_relay,
    spawn_publishing_zenoh_zpub, spawn_zenohd_on_ephemeral_tcp, wz_ap_demo_binary,
    zenoh_core_example_binary, Conduit, RelayFault,
};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{SubscribeOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    initiate_and_open_session_with_qos, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::zenohd_interop_session_init_params;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 8192;

/// The two keys the genuine publishers own. One key each, so a delivery can be
/// attributed to a publisher without reading its payload.
const HI_KEY: &str = "demo/chan-hi";
const LO_KEY: &str = "demo/chan-lo";
/// Deliberately NEITHER arm uses the DEFAULT priority (5, `Priority::Data`): a
/// chain at the default carries no `ext_qos` at all, so a leg using it could
/// not tell "the router chose this conduit" from "the router said nothing".
const DEFAULT_PRIORITY_WIRE: u8 = 5;

/// One genuine publisher's conduit: what to tell zenoh in its config spelling,
/// and what that must appear as on the wire.
///
/// Both are written down because they are two different authorities. The names
/// are the ones `qos/publication` accepts; the wire values are what zenoh's
/// codec encodes them to and what wz's chain key is built from. A leg asserts
/// the second, so a wrong name shows up as a conduit that never appeared rather
/// than as a silently collapsed pair.
#[derive(Clone, Copy)]
struct ChannelSpec {
    key: &'static str,
    priority_name: &'static str,
    reliability_name: &'static str,
    wire: Conduit,
}

/// Which half of wz's `(reliable, priority)` chain key an arm separates the two
/// publishers on.
///
/// The pair exists because a leg that varied BOTH halves at once would pass on
/// an implementation that keyed on either one alone. Each axis holds the other
/// half FIXED, so the only thing that can tell the two chains apart is the half
/// the axis names — which is what makes the mutation on `find_active` red the
/// matching arm and only it.
#[derive(Clone, Copy)]
struct ConduitAxis {
    label: &'static str,
    hi: ChannelSpec,
    lo: ChannelSpec,
}

/// Two priorities, both reliable. The half wz reads out of the `ext_qos`
/// extension.
const PRIORITY_AXIS: ConduitAxis = ConduitAxis {
    label: "priority",
    hi: ChannelSpec {
        key: HI_KEY,
        priority_name: "real_time",
        reliability_name: "reliable",
        wire: Conduit {
            priority: 1,
            reliable: true,
        },
    },
    lo: ChannelSpec {
        key: LO_KEY,
        priority_name: "data_low",
        reliability_name: "reliable",
        wire: Conduit {
            priority: 6,
            reliable: true,
        },
    },
};

/// Two reliabilities at ONE priority. The half wz reads out of the Fragment
/// header's `R` flag (`wz-session-core/src/inbound.rs:670`), which no amount of
/// `ext_qos` parsing would reach.
///
/// `data_low` for both rather than the default, for the same reason the
/// priority axis avoids 5: at the default there is no `ext_qos` on the wire, so
/// a mismatch between the two parsers' priority readings could not surface.
const RELIABILITY_AXIS: ConduitAxis = ConduitAxis {
    label: "reliability",
    hi: ChannelSpec {
        key: HI_KEY,
        priority_name: "data_low",
        reliability_name: "reliable",
        wire: Conduit {
            priority: 6,
            reliable: true,
        },
    },
    lo: ChannelSpec {
        key: LO_KEY,
        priority_name: "data_low",
        reliability_name: "best_effort",
        wire: Conduit {
            priority: 6,
            reliable: false,
        },
    },
};

const SUB_KEYEXPR: &str = "demo/**";
/// The tiny advertised batch. zenohd min-negotiates to it, so each routed Put
/// must fragment on its way to wz.
const TINY_BATCH: u16 = 64;
/// 200 B > 64 B MTU: five fragments per chain, MEASURED.
const PAYLOAD_LEN: usize = 200;
/// `"[%4d] "` — the counter the zenoh `z_pub` example prepends to every value.
/// Seven bytes while the index is under 10000, which the seconds this leg runs
/// for keep it well inside.
const ZPUB_PREFIX_LEN: usize = 7;

struct ArmOutcome {
    negotiated_mtu: usize,
    relay_held: usize,
    relay_overtaken: usize,
    /// Conduits the RELAY read off the fragment batches.
    relay_conduits: BTreeSet<Conduit>,
    /// Conduits WZ's own decoder reported for the fragments it took.
    wz_conduits: BTreeSet<Conduit>,
    /// Byte-exact deliveries per key.
    deliveries: BTreeMap<String, usize>,
    /// Every delivered Sample carried exactly prefix + its key's own value.
    byte_exact: bool,
    rx_reassembly_drops: usize,
    outcome: Result<(), String>,
}

/// Drive one arm: a stock zenohd, two genuine publishers on different
/// conduits, and a wz subscriber dialling THROUGH the relay with a tiny batch.
///
/// Shared by all four legs so that within an axis the ONLY difference is
/// `fault`, and across axes the ONLY difference is `axis` — each twin is a twin
/// by construction, not by parallel maintenance of copies.
async fn subscribe_across_two_conduits(axis: ConduitAxis, fault: RelayFault) -> ArmOutcome {
    let hi_value = frag_payload(PAYLOAD_LEN);
    // A DIFFERENT payload per key: identical ones would let a delivery under
    // the wrong key still satisfy the byte check, which is exactly the damage
    // a conduit-blind reassembler produces.
    let lo_value: String = frag_payload(PAYLOAD_LEN).chars().rev().collect::<String>();
    assert_ne!(
        hi_value, lo_value,
        "the two payloads must be tellable apart"
    );
    let z_pub = zenoh_core_example_binary("z_pub");

    // wz is IN-PROCESS here, so the demo binary enters only as
    // `spawn_zenohd_on_ephemeral_tcp`'s handshake readiness probe — and that is
    // exactly where a stale one misdirects. The probe would fail to detect a
    // router that is in fact up, and the next line then panics with "wz did not
    // reach Established against zenohd", pointing the investigation at the
    // session layer for a defect that is in the build.
    assert_demo_binary_newer_than_sources(&wz_ap_demo_binary());
    let (mut zenohd, zenohd_port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    let relay = spawn_counting_relay(zenohd_port, T_MID_FRAGMENT, fault);

    let mut params = zenohd_interop_session_init_params();
    params.batch_size = TINY_BATCH;
    let stream = TcpStream::connect(("127.0.0.1", relay.port()))
        .await
        .expect("wz dials the interleaving relay");
    // QoS is OFFERED, not assumed: without the ext negotiated, a non-DEFAULT
    // priority has no per-priority conduit to ride and this leg's whole subject
    // disappears. The assertion on `wz_conduits` below is what would catch a
    // build where the offer silently did not take.
    let opened = initiate_and_open_session_with_qos(
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
    let negotiated_mtu = opened.actions.negotiated_batch_mtu();

    let session = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );

    let deliveries = Arc::new(std::sync::Mutex::new(BTreeMap::<String, usize>::new()));
    let byte_exact = Arc::new(AtomicBool::new(true));
    // Bound to a named `_subscriber` (NOT `_`) so the RAII handle stays alive
    // through the drive; a `_`-drop would withdraw the route before the
    // publishers reach the router.
    let _subscriber = {
        let deliveries = Arc::clone(&deliveries);
        let byte_exact = Arc::clone(&byte_exact);
        let hi_expected = hi_value.clone().into_bytes();
        let lo_expected = lo_value.clone().into_bytes();
        session
            .declare_subscriber(SUB_KEYEXPR, SubscribeOptions::default(), move |sample| {
                let key = sample.keyexpr().to_string();
                let expected = match key.as_str() {
                    HI_KEY => &hi_expected,
                    LO_KEY => &lo_expected,
                    _ => {
                        // A Sample under neither key is not this leg's
                        // evidence, and silently ignoring it would let a
                        // mis-routed delivery go unremarked.
                        byte_exact.store(false, Ordering::SeqCst);
                        return;
                    }
                };
                let payload = sample.payload();
                let whole_value_in_order = payload.ends_with(&expected[..]);
                let nothing_extra = payload.len() == ZPUB_PREFIX_LEN + expected.len();
                // The prefix is checked too, or damage confined to the FIRST
                // chunk — which is exactly what an overtaking chain would
                // splice in — would pass the tail equality and the length pin
                // together.
                let prefix_intact = payload.first() == Some(&b'[')
                    && payload.get(ZPUB_PREFIX_LEN - 1) == Some(&b' ');
                if !(whole_value_in_order && nothing_extra && prefix_intact) {
                    byte_exact.store(false, Ordering::SeqCst);
                    return;
                }
                *deliveries
                    .lock()
                    .expect("delivery tally")
                    .entry(key)
                    .or_insert(0) += 1;
            })
            .expect("wz declares the routed subscriber")
    };

    // WZ's OWN reading of which conduit each fragment rode — the half the relay
    // structurally cannot make, and the one the relay's reading is checked
    // against.
    let wz_conduits = Arc::new(std::sync::Mutex::new(BTreeSet::<Conduit>::new()));
    let rx_reassembly_drops = Arc::new(AtomicUsize::new(0));
    let timeouts = SessionTimeouts::spec_defaults();
    let drive = {
        let wz_conduits = Arc::clone(&wz_conduits);
        let rx_reassembly_drops = Arc::clone(&rx_reassembly_drops);
        let session_drive = session.clone();
        drive_session_until_terminal(
            &mut opened.inbound,
            &opened.actions,
            &mut opened.engine,
            None,
            &opened.clock,
            &timeouts,
            move |event| {
                match &event {
                    IterationEvent::Poll(DriverLoopOutcome::Fragment {
                        priority,
                        reliable,
                        ..
                    }) => {
                        // BOTH halves, read off the same event wz builds its
                        // chain key from. Recording the priority alone would
                        // make the reliability axis's two conduits look like
                        // one here, and the cross-check against the relay would
                        // then be satisfied by a decoder that had dropped the
                        // very bit that arm exists to witness.
                        wz_conduits.lock().expect("wz conduit set").insert(Conduit {
                            priority: priority.wire_byte(),
                            reliable: *reliable,
                        });
                    }
                    IterationEvent::ReassemblyDropped(_) => {
                        rx_reassembly_drops.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => {}
                }
                session_drive.dispatch_iteration_event(event)
            },
        )
    };

    let endpoint = format!("tcp/127.0.0.1:{zenohd_port}");
    let scenario = async {
        // The publishers are spawned only AFTER wz's subscriber is declared, so
        // zenohd installs the route first. The spawn helper BLOCKS until the
        // child reports it is publishing, so it runs on a blocking thread:
        // holding the async executor there would stall the drive loop and let
        // the session's lease expire.
        let hi_endpoint = endpoint.clone();
        let hi_payload = hi_value.clone();
        let hi_bin = z_pub.clone();
        let hi_spec = axis.hi;
        let hi_child = tokio::task::spawn_blocking(move || {
            spawn_publishing_zenoh_zpub(
                &hi_bin,
                hi_spec.key,
                &hi_payload,
                &hi_endpoint,
                hi_spec.priority_name,
                hi_spec.reliability_name,
                || tempfile::tempfile().expect("tempfile for z_pub stdout"),
            )
        })
        .await
        .expect("hi z_pub spawn task");

        let lo_payload = lo_value.clone();
        let lo_spec = axis.lo;
        let lo_child = tokio::task::spawn_blocking(move || {
            spawn_publishing_zenoh_zpub(
                &z_pub,
                lo_spec.key,
                &lo_payload,
                &endpoint,
                lo_spec.priority_name,
                lo_spec.reliability_name,
                || tempfile::tempfile().expect("tempfile for z_pub stdout"),
            )
        })
        .await
        .expect("lo z_pub spawn task");

        // Both publishers repeat on a 1s cadence with byte-identical values, so
        // one landing per key after the routes settle suffices — deterministic,
        // not flaky-masking retry.
        let deadline = Instant::now() + Duration::from_secs(25);
        let outcome = loop {
            {
                let tally = deliveries.lock().expect("delivery tally");
                if tally.get(axis.hi.key).copied().unwrap_or(0) >= 1
                    && tally.get(axis.lo.key).copied().unwrap_or(0) >= 1
                {
                    break Ok(());
                }
            }
            if Instant::now() >= deadline {
                let tally = deliveries.lock().expect("delivery tally").clone();
                break Err(format!(
                    "both conduits did not deliver within 25s (MTU {negotiated_mtu}, \
                     relay conduits {:?}, wz conduits {:?}, held {}, overtaken {}, \
                     deliveries {tally:?})",
                    relay.conduits_seen(),
                    wz_conduits.lock().expect("wz conduit set").clone(),
                    relay.held_count(),
                    relay.overtaken_count(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        (outcome, hi_child, lo_child)
    };

    let (outcome, children) = tokio::select! {
        _ = drive => (
            Err("wz drive loop reached a terminal state before both Samples arrived".to_string()),
            None,
        ),
        (r, hi, lo) = scenario => (r, Some((hi, lo))),
    };

    if let Some((mut hi, mut lo)) = children {
        let _ = hi.child_mut().kill();
        let _ = hi.child_mut().wait();
        let _ = lo.child_mut().kill();
        let _ = lo.child_mut().wait();
    }
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    // Both shared readings are taken into locals BEFORE the struct literal. A
    // `MutexGuard` created inside a tail expression is a temporary OF THAT
    // EXPRESSION, so it is dropped after the block's own locals -- including
    // the `Arc`s it borrows from -- which the borrow checker refuses (E0597).
    // Naming them ends each guard at its own statement.
    let wz_conduits = wz_conduits.lock().expect("wz conduit set").clone();
    let deliveries = deliveries.lock().expect("delivery tally").clone();

    ArmOutcome {
        negotiated_mtu,
        relay_held: relay.held_count(),
        relay_overtaken: relay.overtaken_count(),
        relay_conduits: relay.conduits_seen(),
        wz_conduits,
        deliveries,
        byte_exact: byte_exact.load(Ordering::SeqCst),
        rx_reassembly_drops: rx_reassembly_drops.load(Ordering::SeqCst),
        outcome,
    }
}

/// Assertions every arm owes, whatever the relay did to the ordering: the
/// preconditions that make the arm the arm it claims to be.
fn assert_shared_preconditions(arm: &ArmOutcome, axis: ConduitAxis, label: &str) {
    assert!(arm.outcome.is_ok(), "{label}: {:?}", arm.outcome);
    assert_eq!(
        arm.negotiated_mtu, TINY_BATCH as usize,
        "{label}: the arm must be the small-MTU one, or nothing fragments"
    );
    // The two specs must be TELLABLE APART, on both the wire and the key. An
    // axis whose halves collided would be one publisher measured against
    // itself, and every assertion below would still pass. Compared as VALUES,
    // not by counting the literal pair: a `[a, b].len() == 2` moves only when
    // the pair itself is edited, so it can never catch the thing it is for.
    assert_ne!(
        axis.hi.wire, axis.lo.wire,
        "{label}: the axis's two specs must name DIFFERENT conduits"
    );
    assert_ne!(
        axis.hi.key, axis.lo.key,
        "{label}: the axis's two specs must publish under DIFFERENT keys, or a \
         delivery cannot be attributed to a publisher"
    );
    let expected: BTreeSet<Conduit> = [axis.hi.wire, axis.lo.wire].into_iter().collect();
    assert!(
        arm.relay_conduits.is_superset(&expected),
        "{label}: the genuine router must put BOTH configured conduits on the \
         link; expected {expected:?}, the relay read {:?}",
        arm.relay_conduits
    );
    assert!(
        !arm.relay_conduits
            .iter()
            .any(|c| c.priority == DEFAULT_PRIORITY_WIRE),
        "{label}: a DEFAULT-priority fragment means the qos overwrite did not \
         take for one publisher, and the leg would then be measuring one \
         conduit against the absence of an ext; the relay read {:?}",
        arm.relay_conduits
    );
    // The two readings must AGREE. This is what stops the leg from being wz
    // asking wz: the relay's parser and wz's decoder are separate code over the
    // same bytes, and a leg that accepted either alone would pass with one of
    // them wrong.
    assert_eq!(
        arm.wz_conduits, arm.relay_conduits,
        "{label}: wz's decoder and the relay's parser must read the SAME \
         conduits off the same wire"
    );
    assert_eq!(
        arm.rx_reassembly_drops, 0,
        "{label}: no chain may be aborted or refused by the reassembly dispatcher"
    );
    assert!(
        arm.byte_exact,
        "{label}: every delivered Sample must carry exactly its own key's value"
    );
    for key in [axis.hi.key, axis.lo.key] {
        assert!(
            arm.deliveries.get(key).copied().unwrap_or(0) >= 1,
            "{label}: {key} delivered nothing; tally {:?}",
            arm.deliveries
        );
    }
}

/// The PROOF's own assertions: the two counters that make an arm a proof rather
/// than a slower twin.
///
/// Without them the leg passes on a stream that never overlapped, which every
/// reassembler handles — including the conduit-blind one this exists to refuse.
fn assert_overlap_happened(arm: &ArmOutcome, label: &str) {
    assert!(
        arm.relay_held >= 1,
        "{label}: the relay must have HELD a chain; held {}",
        arm.relay_held
    );
    assert!(
        arm.relay_overtaken >= 1,
        "{label}: a fragment on the other conduit must have OVERTAKEN the held \
         chain; held {} overtaken {}",
        arm.relay_held,
        arm.relay_overtaken
    );
}

/// The TWIN's own assertions: the same two counters, at zero.
fn assert_no_overlap_happened(arm: &ArmOutcome, label: &str) {
    assert_eq!(
        arm.relay_held, 0,
        "{label}: a verbatim relay holds nothing; held {}",
        arm.relay_held
    );
    assert_eq!(
        arm.relay_overtaken, 0,
        "{label}: and nothing overtakes; overtaken {}",
        arm.relay_overtaken
    );
}

// wz-proves: transport-fragmentation zenohd->wz
// wz-proves: transport-qos zenohd->wz
// wz-proves: pubsub-sample zenohd->wz
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binary-dep e2e (zenohd router + zenoh core z_pub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn zenohd_chains_on_two_priorities_reassemble_while_interleaved() {
    let arm = subscribe_across_two_conduits(
        PRIORITY_AXIS,
        RelayFault::InterleaveConduitsAcceptorToDialer,
    )
    .await;
    // The label is composed FROM the axis rather than written out beside it, so
    // a failure can never name an axis the arm did not run.
    let label = format!("{}/interleaved", PRIORITY_AXIS.label);
    assert_shared_preconditions(&arm, PRIORITY_AXIS, &label);
    assert_overlap_happened(&arm, &label);
}

// wz-proves: none -- the CALIBRATION twin of the leg above. It differs in ONE
// argument (the relay forwards verbatim instead of interleaving) and exists to
// forbid reading the held/overtaken counters as constants: they are non-zero
// there and MUST be zero here, over the same router, the same publishers and
// the same fragmentation. It witnesses no atom the proof does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binary-dep e2e (zenohd router + zenoh core z_pub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn zenohd_chains_on_two_priorities_reassemble_without_interleaving() {
    let arm = subscribe_across_two_conduits(PRIORITY_AXIS, RelayFault::None).await;
    let label = format!("{}/verbatim", PRIORITY_AXIS.label);
    assert_shared_preconditions(&arm, PRIORITY_AXIS, &label);
    assert_no_overlap_happened(&arm, &label);
}

// wz-proves: transport-fragmentation zenohd->wz
// wz-proves: transport-qos zenohd->wz
// wz-proves: pubsub-sample zenohd->wz
//
// The SAME three atoms as the priority proof, and a separate witness for each
// rather than a duplicate. wz keys on `(peer, reliable, priority)`; the
// priority arm holds `reliable` fixed at `true`, so an implementation that
// dropped the reliability bit passes it. Here the two chains ride ONE priority
// and differ only in the header's `R` flag, which no `ext_qos` parsing reaches
// — so that bit is the only thing that can separate them.
//
// There is no `transport-reliability` atom to claim: the reliable /
// best-effort split IS the conduit, and the conduit is what `transport-qos`
// names in this catalogue.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binary-dep e2e (zenohd router + zenoh core z_pub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn zenohd_chains_on_two_reliabilities_reassemble_while_interleaved() {
    let arm = subscribe_across_two_conduits(
        RELIABILITY_AXIS,
        RelayFault::InterleaveConduitsAcceptorToDialer,
    )
    .await;
    let label = format!("{}/interleaved", RELIABILITY_AXIS.label);
    assert_shared_preconditions(&arm, RELIABILITY_AXIS, &label);
    assert_overlap_happened(&arm, &label);
}

// wz-proves: none -- the CALIBRATION twin of the reliability leg, on the same
// terms as the priority twin above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "binary-dep e2e (zenohd router + zenoh core z_pub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn zenohd_chains_on_two_reliabilities_reassemble_without_interleaving() {
    let arm = subscribe_across_two_conduits(RELIABILITY_AXIS, RelayFault::None).await;
    let label = format!("{}/verbatim", RELIABILITY_AXIS.label);
    assert_shared_preconditions(&arm, RELIABILITY_AXIS, &label);
    assert_no_overlap_happened(&arm, &label);
}

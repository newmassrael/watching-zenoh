// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-qos",
    feature = "transport-unicast",
    feature = "transport-link-tcp"
))]

//! wz<->wz QoS transport end to end — the negotiated per-priority data path.
//!
//! The wz mirror of zenoh's QoS unicast transport (`init.rs:146 zextunit!(0x1,
//! false)`): both peers OFFER the `ext_qos` unit ext on InitSyn / InitAck, the
//! symmetric `&=` merge agrees, and the established session carries a non-DEFAULT
//! priority on its OWN per-(priority, reliability) SN conduit, stamping the
//! Frame's `ext_qos` extension (id 0x1, z64). y215 built the wire + conduits;
//! R311y216(a) wires the `set_qos_offer` production caller (the `*_with_qos`
//! entrypoints) so `is_qos` can flip true — until then the wire was DEFAULT-inert.
//!
//! Three complementary proofs:
//!
//!   1. `qos_negotiates_and_delivers_prioritized_put_over_real_tcp` — the
//!      end-to-end proof over a real TCP loopback. Both sides reach Established
//!      with `is_qos()` true, and a `Put` published at a NON-DEFAULT priority
//!      (`InteractiveHigh`) is delivered byte-exact to a subscriber on the
//!      acceptor. A prioritized Frame that the peer failed to admit on its
//!      per-priority conduit (F5 drop / SN gate) would never deliver — so a
//!      successful delivery with the flag asserted proves the negotiated
//!      conduit admitted the prioritized frame (the composed activation path).
//!   2. `qos_prioritized_put_rides_ext_qos_and_negotiates_by_and` — the
//!      deterministic, socket-free distinguishing proof: drive the handshake over
//!      recording drivers, publish at `InteractiveHigh`, and inspect the captured
//!      wire. With QoS negotiated the Frame sets `FLAG_T_Z` and carries the
//!      `ext_qos` extension; the no-offer CONTROL (and the one-sided offer, which
//!      the `&=` leaves NoQoS) TX-clamps the priority to DEFAULT, so the Frame is
//!      byte-identical to a pre-QoS Frame (no Z flag, no ext_qos).
//!   3. `qos_config_field_selects_offer` — the `WzConfig.qos` config surface a
//!      caller reads to pick a qos open entrypoint (the demo `--qos` reader landed
//!      in R311y218, bridging `WzConfig.qos -> FaceSources.qos` over the multilink
//!      path; per-face priority segregation is R311y219).
//!
//! ## Non-flakiness
//!
//! Test 1 is a handful of in-order, loss-free datagrams on 127.0.0.1 (TCP
//! retransmits); both sides drive continuously until the delivery is observed,
//! bounded by a ~3s probe budget. Test 2 touches no socket and no clock — it is a
//! deterministic feed of each side's captured bytes into the other.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use wz_codecs::wire_const;
use wz_runtime_tokio::config::WzConfig;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, SessionLinkActions};
use wz_runtime_tokio::session_open::{
    accept_and_open_session_with_qos, connect_and_open_session_with_qos, DialConfig, DialedLink,
    DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::{establish_capability_pair, fixture_params_with_zid};
use wz_session_core::locator::parse_any_locator;
use wz_session_core::qos::Priority;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/qos";

/// Publish a `Put` at `priority` on `actions` and return the captured outbound
/// wire bytes (the most recent recording-driver send). The express API
/// (`send_push_literal_qos`) is the non-DEFAULT send path; a QoS session stamps
/// `ext_qos`, a non-QoS session clamps to DEFAULT.
fn send_qos_and_capture(
    actions: &Arc<SessionLinkActions>,
    driver: &wz_runtime_tokio_test_support::LifecycleRecordingDriver,
    priority: Priority,
) -> Vec<u8> {
    actions
        .send_push_literal_qos(KEYEXPR, b"payload", true, priority)
        .expect("send on an established session");
    driver
        .snapshot()
        .sends
        .last()
        .expect("a send was recorded")
        .0
        .clone()
}

/// Test 1 — two wz nodes handshake over a loopback TCP link, BOTH offering QoS,
/// reach Established with `is_qos` negotiated on, and a `Put` published at a
/// NON-DEFAULT priority (`InteractiveHigh`) on the initiator is delivered
/// byte-exact to a subscriber on the acceptor — the prioritized frame admitted on
/// the negotiated per-priority conduit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn qos_negotiates_and_delivers_prioritized_put_over_real_tcp() {
    let payload = b"prioritized-hello".to_vec();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // ── Open BOTH sessions concurrently, each offering QoS.
    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept tcp peer");
        accept_and_open_session_with_qos(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(0x02),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established with qos offered")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        let cfg = DialConfig::default();
        connect_and_open_session_with_qos(
            locator,
            fixture_params_with_zid(0x01),
            &cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established with qos offered")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    // The negotiation succeeded on BOTH sides (the `&=` of two true offers).
    assert!(opened_init.actions.is_qos(), "initiator negotiated qos on");
    assert!(opened_acc.actions.is_qos(), "acceptor negotiated qos on");

    // ── Subscriber on the acceptor; asserts the delivered payload byte-exact.
    let fired = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    {
        let fired = fired.clone();
        let expect = payload.clone();
        observer.subscribers.register(KEYEXPR, move |sample| {
            assert_eq!(sample.keyexpr(), KEYEXPR);
            assert_eq!(
                sample.payload(),
                &expect[..],
                "the payload delivered over the prioritized conduit matches the Put byte-for-byte"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    let timeouts = SessionTimeouts::spec_defaults();
    let drive_acc = drive_session_until_terminal(
        &mut opened_acc.inbound,
        &opened_acc.actions,
        &mut opened_acc.engine,
        None,
        &opened_acc.clock,
        &timeouts,
        |event| observer.dispatch_event(event),
    );
    let init_actions = opened_init.actions.clone();
    let drive_init = drive_session_until_terminal(
        &mut opened_init.inbound,
        &opened_init.actions,
        &mut opened_init.engine,
        None,
        &opened_init.clock,
        &timeouts,
        |_| {},
    );

    let fired_probe = fired.clone();
    let scenario = async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        init_actions
            .send_push_literal_qos(
                KEYEXPR,
                &payload,
                /*reliable=*/ true,
                Priority::InteractiveHigh,
            )
            .expect("prioritized publish builds and routes through the QoS send seam");
        for _ in 0..100 {
            if fired_probe.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("subscriber did not fire within the ~3s budget");
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "exactly one delivery from the prioritized Put over the negotiated QoS conduit"
    );
}

/// Test 2 — the distinguishing wire-form proof. With QoS negotiated, a
/// non-DEFAULT-priority Put's Frame sets `FLAG_T_Z` and carries the `ext_qos`
/// extension; without the offer (or with a one-sided offer the `&=` leaves
/// NoQoS), the TX seam clamps the priority to DEFAULT and the Frame is
/// byte-identical to a pre-QoS Frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn qos_prioritized_put_rides_ext_qos_and_negotiates_by_and() {
    let offer = |a: &Arc<SessionLinkActions>| {
        a.set_qos_offer(true);
    };

    // Both offer -> negotiated on -> the prioritized Put's Frame carries ext_qos.
    let both = establish_capability_pair(true, true, offer).await;
    assert!(both.init_actions.is_qos(), "initiator negotiated qos on");
    assert!(both.resp_actions.is_qos(), "acceptor negotiated qos on");
    let framed_qos = send_qos_and_capture(
        &both.init_actions,
        &both.init_driver,
        Priority::InteractiveHigh,
    );
    assert_eq!(
        framed_qos[0] & 0x1F,
        wire_const::T_MID_FRAME,
        "the prioritized Put rides a Frame"
    );
    assert_ne!(
        framed_qos[0] & wire_const::FLAG_T_Z,
        0,
        "the QoS Frame sets the ext-chain Z flag (it carries the ext_qos extension)"
    );

    // CONTROL: neither offers -> universal -> the priority is clamped to DEFAULT,
    // so the Frame carries NO ext_qos (Z clear, byte-identical to pre-QoS).
    let none = establish_capability_pair(false, false, offer).await;
    assert!(!none.init_actions.is_qos(), "initiator stays non-qos");
    assert!(!none.resp_actions.is_qos(), "acceptor stays non-qos");
    let framed_plain = send_qos_and_capture(
        &none.init_actions,
        &none.init_driver,
        Priority::InteractiveHigh,
    );
    assert_eq!(
        framed_plain[0] & 0x1F,
        wire_const::T_MID_FRAME,
        "without qos the Put still rides a Frame"
    );
    assert_eq!(
        framed_plain[0] & wire_const::FLAG_T_Z,
        0,
        "a non-qos session clamps the priority to DEFAULT: no ext_qos, no Z flag (pre-QoS wire)"
    );

    // NEGOTIATION `&=`: only the initiator offers -> the responder never reflects,
    // so BOTH finalize NoQoS (zenoh `recv_init_ack` else-NoQoS), and the
    // initiator's prioritized Put is likewise clamped.
    let one = establish_capability_pair(true, false, offer).await;
    assert!(
        !one.init_actions.is_qos(),
        "a one-sided offer leaves the initiator non-qos (peer did not reflect)"
    );
    assert!(
        !one.resp_actions.is_qos(),
        "the responder never offered, so it stays non-qos"
    );
    let framed_one = send_qos_and_capture(
        &one.init_actions,
        &one.init_driver,
        Priority::InteractiveHigh,
    );
    assert_eq!(
        framed_one[0] & wire_const::FLAG_T_Z,
        0,
        "the one-sided-offer session clamps to DEFAULT: no ext_qos rides the wire"
    );
}

/// Test 3 — the `WzConfig.qos` config surface round-trips: a config-driven caller
/// reads `cfg.qos` to select a qos open entrypoint. Default is off (byte-identical
/// to pre-QoS); the demo `--qos` reader (R311y218) bridges this field `WzConfig.qos
/// -> FaceSources.qos -> the *_with_multilink entrypoints` (the `max_links ->
/// FaceSources` bridge precedent); per-face priority segregation is R311y219.
#[test]
fn qos_config_field_selects_offer() {
    let on = WzConfig::new().with_qos(true);
    let off = WzConfig::new();
    assert!(on.qos, "with_qos(true) sets the QoS offer surface");
    assert!(
        !off.qos,
        "the default is off (byte-identical to a pre-QoS session)"
    );
}

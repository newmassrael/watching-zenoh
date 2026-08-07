// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "reassembly")]

//! R311im — reassembly RX seam integration: a `T_MID_FRAGMENT` (0x06)
//! wire frame is decoded by `parse_inbound` into `InboundFrame::Fragment`,
//! and a multi-fragment chain reassembles through the
//! `ReassemblyDispatcher` exactly as the drive loop wires it
//! (`wz_runtime_tokio::session_glue::report_outcome_reassembling`).
//!
//! Proves the full RX path `wire bytes -> parse_inbound -> Fragment ->
//! ReassemblyDispatcher::ingest -> reassembled message` against the real
//! transport-header decode (R/M flags, VLE sn, tail payload), not a
//! hand-rolled fragment struct.

use wz_runtime_tokio::session_glue::{parse_inbound, InboundFrame};
use wz_session_core::reassembly_dispatch::{Fragment, ReassemblyConfig, ReassemblyDispatcher};
// The `T_MID_FRAGMENT` wire crafter is the shared no_std SSOT (R311it
// sibling), byte-identical with the MCU reassembly e2e so both profiles
// inspect the same fragment bytes.
use wz_session_wire_fixtures::craft_fragment_wire as fragment_frame;

/// `parse_inbound` decodes the transport-header R/M bits, the VLE sn, and
/// the tail payload into `InboundFrame::Fragment`.
#[test]
fn fragment_frame_decodes_r_m_sn_payload() {
    let wire = fragment_frame(true, true, 7, b"chunk0");
    let frame = parse_inbound(&wire).expect("parse fragment frame");
    let InboundFrame::Fragment {
        reliable,
        more,
        sn,
        payload,
        ..
    } = frame
    else {
        panic!("expected InboundFrame::Fragment");
    };
    assert!(reliable);
    assert!(more);
    assert_eq!(sn, 7);
    assert_eq!(payload, b"chunk0");
}

/// A best-effort fragment clears the R bit; a final fragment clears the M
/// bit — the two header discriminators are independent.
#[test]
fn best_effort_final_fragment_clears_r_and_m() {
    let wire = fragment_frame(false, false, 3, b"end");
    let frame = parse_inbound(&wire).expect("parse fragment frame");
    let InboundFrame::Fragment {
        reliable,
        more,
        sn,
        payload,
        ..
    } = frame
    else {
        panic!("expected InboundFrame::Fragment");
    };
    assert!(!reliable);
    assert!(!more);
    assert_eq!(sn, 3);
    assert_eq!(payload, b"end");
}

/// A two-fragment chain reassembles end-to-end through the real
/// `parse_inbound` decode + the dispatcher, concatenating the bodies in
/// SN order. This is the data path `report_outcome_reassembling` drives in
/// the steady-state session loop.
#[test]
fn two_fragment_chain_reassembles_through_parse_inbound() {
    let mut d: ReassemblyDispatcher<4, 256> =
        ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));
    let zid: &[u8] = &[0x01; 16];

    let f0 = fragment_frame(true, true, 10, b"hello ");
    let f1 = fragment_frame(true, false, 11, b"world");

    let mut reassembled: Option<Vec<u8>> = None;
    for wire in [&f0, &f1] {
        let frame = parse_inbound(wire).expect("parse fragment frame");
        let InboundFrame::Fragment {
            reliable,
            sn,
            more,
            payload,
            markers,
            ..
        } = frame
        else {
            panic!("expected InboundFrame::Fragment");
        };
        // R311y578 — `fragment_frame` builds a bare `VLE(sn) + tail` wire with
        // no ext chain, so neither chain-boundary marker is on it. The
        // dispatcher runs with markers OFF here (the patch-0 contract), which
        // is why a marker-less chain still starts. The armed contract is
        // exercised in `reassembly_dispatch`'s own suite and in
        // `session_glue`'s round trip over wz's REAL emitted wire.
        assert_eq!(markers, wz_session_core::extfragment::FragmentMarkers::NONE);
        d.ingest(
            Fragment {
                peer_key: zid,
                reliable,
                sn,
                more: u8::from(more),
                payload: &payload,
                priority: wz_session_core::qos::Priority::DEFAULT,
                markers,
            },
            wz_session_core::sn::mask_from_res(0x02),
            0,
            |msg| reassembled = Some(msg.to_vec()),
        );
    }

    assert_eq!(reassembled.as_deref(), Some(&b"hello world"[..]));
}

/// R311y221 — the reassembly-completion synthesizer (`reassembled_frame_outcome`,
/// the SSOT the unicast `drive.rs:756` and the multicast
/// `multicast_dispatch.rs` completion closures share) threads the chain's band
/// onto the delivered `FramePayload`. The unicast caller passes the chain's real
/// decoded `priority` (keyed on `(peer, reliable, priority)` at ingest), so a
/// FRAGMENTED prioritized Put delivers on the SAME band a single-frame Put would;
/// the multicast caller passes DEFAULT (its per-priority conduits stay deferred,
/// R311y215 step 8). Guards the trap where a reassembled frame silently loses its
/// band while a whole frame keeps it.
#[test]
fn reassembled_outcome_carries_the_chain_band() {
    use wz_session_core::driver_loop::{reassembled_frame_outcome, DriverLoopOutcome};
    use wz_session_core::qos::Priority;

    // An empty payload reassembles to an empty (Ok) message batch — enough to
    // observe the synthesized outcome's band without a codec fixture (the R74
    // empty-tail FramePayload precedent).
    let unicast = reassembled_frame_outcome(true, 5, Priority::InteractiveHigh, b"");
    match unicast {
        DriverLoopOutcome::FramePayload {
            priority,
            reliable,
            sn,
            ..
        } => {
            assert_eq!(
                priority,
                Priority::InteractiveHigh,
                "the reassembled whole-frame keeps the chain's band, not DEFAULT"
            );
            assert!(reliable);
            assert_eq!(sn, 5);
        }
        other => panic!("expected FramePayload, got {other:?}"),
    }

    // The multicast-style DEFAULT caller stays DEFAULT (deferred conduits).
    let multicast = reassembled_frame_outcome(false, 0, Priority::DEFAULT, b"");
    assert!(matches!(
        multicast,
        DriverLoopOutcome::FramePayload { priority, .. } if priority == Priority::DEFAULT
    ));
}

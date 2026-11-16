// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The headers of a Frame and a Fragment as this crate writes them
//! (`frame_encode`) and reads them (`inbound`, owned and in place), held to the
//! documents that state each header (`sources/codecs/transport_frame_header.scxml`,
//! `transport_fragment_header.scxml`).
//!
//! For every header written here the document's view reads it whole, leaves the
//! payload after it, writes the same bytes back, and reads the SN, the flags and
//! the chain the readers here read; and a header laid out as upstream lays it out
//! (`commons/zenoh-codec/src/transport/frame.rs` @
//! `impl<W> WCodec<&FrameHeader, &mut W> for Zenoh080`, and `fragment.rs`
//! beside it) is what the writers here write for the same values.

use alloc::vec;
use alloc::vec::Vec;

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::transport_fragment_header::TransportFragmentHeaderView;
use wz_codecs::transport_frame_header::TransportFrameHeaderView;
use wz_codecs::wire_const;

use crate::frame_encode::{begin_frame, frame_flags, write_fragment_head};
use crate::inbound::{parse_fragment_in_place, parse_frame_in_place, parse_inbound, InboundFrame};
use crate::qos::Priority;

/// Payload bytes after a header: two network-message ids.
const PAYLOAD: [u8; 2] = [0x1D, 0x1E];

/// The Frame header of `wz-codecs`' `transport_headers` test: best effort, SN
/// 300, the QoS extension of priority 2.
const UPSTREAM_FRAME_QOS: [u8; 5] = [0x85, 0xAC, 0x02, 0x31, 0x02];

/// The Fragment header of the same test: reliable, more to follow, SN 300,
/// the chain QoS priority 2, First, Drop.
const UPSTREAM_FRAGMENT_FIRST: [u8; 7] = [0xE6, 0xAC, 0x02, 0xB1, 0x02, 0x82, 0x03];

/// SNs at each VLE width the session's rings reach, the widest below `2^63`.
const SNS: [u64; 7] = [0, 5, 127, 128, 300, 1 << 35, (1 << 63) - 1];

/// The QoS a header is written with: none, the default priority asked for, and
/// one that is not the default.
fn qos_cases() -> [Option<Priority>; 3] {
    [None, Some(Priority::DEFAULT), Some(Priority::from_wire(2))]
}

/// The headers of the entries a view's chain yields, none when Z is clear.
macro_rules! view_chain_headers {
    ($view:expr) => {
        $view
            .extensions
            .as_ref()
            .map(|list| list.inner().iter())
            .into_iter()
            .flatten()
            .map(|entry| entry.header)
            .collect::<Vec<u8>>()
    };
}

/// The view of the Frame header at the front of `unit`, with the payload left;
/// it writes the header back as `unit` holds it.
fn frame_header_view(unit: &[u8]) -> TransportFrameHeaderView<'_> {
    let mut cursor = SceCursor::new(unit);
    let view = TransportFrameHeaderView::decode(&mut cursor).expect("the header decodes");
    assert_eq!(cursor.remaining(), PAYLOAD.len(), "the payload is left");
    assert_eq!(view.encode_to_vec(), &unit[..unit.len() - PAYLOAD.len()]);
    view
}

/// [`frame_header_view`] for a Fragment.
fn fragment_header_view(unit: &[u8]) -> TransportFragmentHeaderView<'_> {
    let mut cursor = SceCursor::new(unit);
    let view = TransportFragmentHeaderView::decode(&mut cursor).expect("the header decodes");
    assert_eq!(cursor.remaining(), PAYLOAD.len(), "the payload is left");
    assert_eq!(view.encode_to_vec(), &unit[..unit.len() - PAYLOAD.len()]);
    view
}

/// The readers here and the view read the Frame `unit` alike.
fn assert_frame_read_alike(unit: &[u8]) {
    let view = frame_header_view(unit);
    match parse_inbound(unit) {
        Ok(InboundFrame::Frame {
            reliable,
            sn,
            payload,
            has_ext,
            extensions,
            ..
        }) => {
            assert_eq!(reliable, view.header & wire_const::FLAG_T_FRAME_R != 0);
            assert_eq!(sn, view.sn);
            assert_eq!(payload.as_slice(), PAYLOAD);
            assert_eq!(has_ext, view.extensions.is_some());
            assert_eq!(
                extensions.iter().map(|e| e.header).collect::<Vec<u8>>(),
                view_chain_headers!(view)
            );
        }
        Ok(_) => panic!("the decoder here read another message"),
        Err(refused) => panic!("the decoder here refused the frame: {refused:?}"),
    }
    let (head, payload_at) = parse_frame_in_place(unit)
        .expect("a Frame")
        .expect("the in-place reader reads it");
    assert_eq!(head.sn, view.sn);
    assert_eq!(head.reliable, view.header & wire_const::FLAG_T_FRAME_R != 0);
    assert_eq!(payload_at, unit.len() - PAYLOAD.len());
}

/// The readers here and the view read the Fragment `unit` alike.
fn assert_fragment_read_alike(unit: &[u8]) {
    let view = fragment_header_view(unit);
    let view_markers = crate::extfragment::FragmentMarkers::from_headers(view_chain_headers!(view));
    match parse_inbound(unit) {
        Ok(InboundFrame::Fragment {
            reliable,
            sn,
            more,
            payload,
            has_ext,
            extensions,
            markers,
            ..
        }) => {
            assert_eq!(reliable, view.header & wire_const::FLAG_T_FRAGMENT_R != 0);
            assert_eq!(more, view.header & wire_const::FLAG_T_FRAGMENT_M != 0);
            assert_eq!(sn, view.sn);
            assert_eq!(payload, PAYLOAD);
            assert_eq!(has_ext, view.extensions.is_some());
            assert_eq!(
                extensions.iter().map(|e| e.header).collect::<Vec<u8>>(),
                view_chain_headers!(view)
            );
            assert_eq!(markers, view_markers);
        }
        Ok(_) => panic!("the decoder here read another message"),
        Err(refused) => panic!("the decoder here refused the fragment: {refused:?}"),
    }
    let (head, payload_at) = parse_fragment_in_place(unit)
        .expect("a Fragment")
        .expect("the in-place reader reads it");
    assert_eq!(head.sn, view.sn);
    assert_eq!(head.more, view.header & wire_const::FLAG_T_FRAGMENT_M != 0);
    assert_eq!(head.markers(), view_markers);
    assert_eq!(payload_at, unit.len() - PAYLOAD.len());
}

#[test]
fn every_frame_header_written_here_is_the_header_the_document_reads() {
    for sn in SNS {
        for reliable in [false, true] {
            for qos in qos_cases() {
                let mut unit = Vec::new();
                begin_frame(&mut unit, sn, frame_flags(reliable), qos).expect("a Vec grows");
                unit.extend_from_slice(&PAYLOAD);
                assert_frame_read_alike(&unit);
            }
        }
    }
}

#[test]
fn the_frame_header_written_here_for_upstreams_values_is_upstreams() {
    let mut header = Vec::new();
    begin_frame(
        &mut header,
        300,
        frame_flags(false),
        Some(Priority::from_wire(2)),
    )
    .expect("a Vec grows");
    assert_eq!(header, UPSTREAM_FRAME_QOS);
    let mut unit = header;
    unit.extend_from_slice(&PAYLOAD);
    assert_frame_read_alike(&unit);
}

#[test]
fn every_fragment_header_written_here_is_the_header_the_document_reads() {
    for sn in SNS {
        for reliable in [false, true] {
            for more in [false, true] {
                for (first, drop_marker) in
                    [(false, false), (true, false), (false, true), (true, true)]
                {
                    for qos in qos_cases() {
                        let mut unit = Vec::new();
                        write_fragment_head(&mut unit, sn, reliable, more, first, drop_marker, qos)
                            .expect("a Vec grows");
                        unit.extend_from_slice(&PAYLOAD);
                        assert_fragment_read_alike(&unit);
                    }
                }
            }
        }
    }
}

#[test]
fn the_fragment_header_written_here_for_upstreams_values_is_upstreams() {
    let mut header = Vec::new();
    write_fragment_head(
        &mut header,
        300,
        true,
        true,
        true,
        true,
        Some(Priority::from_wire(2)),
    )
    .expect("a Vec grows");
    assert_eq!(header, UPSTREAM_FRAGMENT_FIRST);
    let mut unit = header;
    unit.extend_from_slice(&PAYLOAD);
    assert_fragment_read_alike(&unit);
}

/// Nine entries no reader acts on (id 0xC, not mandatory), each announcing a
/// next: the run a chain carries before the entries that matter, past the eight
/// a reader here once stopped at.
const NINE_UNREAD: [u8; 9] = [0x8C; 9];

/// A Frame with nine unread entries before its QoS extension, and a Fragment
/// with them before its QoS, First and Drop, are read whole by every reader
/// here, the one that keeps no list included: upstream reads the chain to its
/// end (`commons/zenoh-codec/src/transport/frame.rs` @ `while has_ext {`).
#[test]
fn the_entries_after_a_long_chain_prefix_are_read_in_place() {
    let mut frame = vec![0x85, 0xAC, 0x02];
    frame.extend_from_slice(&NINE_UNREAD);
    frame.extend_from_slice(&[0x31, 0x02]);
    frame.extend_from_slice(&PAYLOAD);
    assert_frame_read_alike(&frame);
    let (head, _) = parse_frame_in_place(&frame)
        .expect("a Frame")
        .expect("the in-place reader reads it");
    assert_eq!(head.priority(), Priority::from_wire(2));
    #[cfg(feature = "session-unicast")]
    assert_eq!(
        head.ext_admission(),
        crate::ext_admit::ExtAdmission::Admissible
    );

    let mut fragment = vec![0xE6, 0xAC, 0x02];
    fragment.extend_from_slice(&NINE_UNREAD);
    fragment.extend_from_slice(&[0xB1, 0x02, 0x82, 0x03]);
    fragment.extend_from_slice(&PAYLOAD);
    assert_fragment_read_alike(&fragment);
    let (head, _) = parse_fragment_in_place(&fragment)
        .expect("a Fragment")
        .expect("the in-place reader reads it");
    assert_eq!(head.priority(), Priority::from_wire(2));
    assert_eq!(
        head.markers(),
        crate::extfragment::FragmentMarkers {
            first: true,
            dropped: true
        }
    );
    #[cfg(feature = "session-unicast")]
    assert_eq!(
        head.ext_admission(),
        crate::ext_admit::ExtAdmission::Admissible
    );
}

/// The in-place reader keeps no list of a chain's headers, so the entry the
/// admission rule refuses is found wherever it lies: a mandatory entry of an id
/// a Frame does not declare, tenth in the chain, refuses the Frame as the owned
/// decode's verdict does.
#[cfg(feature = "session-unicast")]
#[test]
fn a_refused_entry_after_a_long_chain_prefix_refuses_the_frame_in_place() {
    use crate::ext_admit::ExtAdmission;
    let mut frame = vec![0x85, 0xAC, 0x02];
    frame.extend_from_slice(&NINE_UNREAD);
    frame.push(0x1C);
    frame.extend_from_slice(&PAYLOAD);
    let (head, _) = parse_frame_in_place(&frame)
        .expect("a Frame")
        .expect("the in-place reader reads it");
    assert_eq!(
        head.ext_admission(),
        ExtAdmission::UnknownMandatory { eid: 0x1C }
    );
    let owned = parse_inbound(&frame).expect("the owned decode reads it");
    assert_eq!(owned.ext_admission(), head.ext_admission());

    // CONTROL: the same entry without the mandatory bit is admissible.
    let last_entry = frame.len() - PAYLOAD.len() - 1;
    frame[last_entry] = 0x0C;
    let (head, _) = parse_frame_in_place(&frame)
        .expect("a Frame")
        .expect("the in-place reader reads it");
    assert_eq!(head.ext_admission(), ExtAdmission::Admissible);
}

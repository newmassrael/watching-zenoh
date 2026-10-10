// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! OAM carrier for the linkstate-peer topology exchange (P4 routing,
//! linkstate port step c1).
//!
//! zenoh floods peer topology as a `LinkStateList` wrapped in an OAM
//! (Operations & Maintenance) network message: `Network::make_msg`
//! (`zenoh/src/net/protocol/network.rs:350-365`) encodes the list with
//! the routing codec into a `ZBuf`, then builds
//! `Oam { id: OAM_LINKSTATE, body: ZBuf(bytes), ext_qos: QoSType::OAM }`.
//!
//! This module is the wz carrier between the `wz-codecs` LinkStateList
//! codec (step b) and the `NetworkMessage::Oam` envelope:
//!
//! * [`build_linkstate_oam`] — LinkStateList -> OAM message wire bytes.
//! * [`try_parse_linkstate_oam`] — a decoded OAM -> a [`LinkstateOam`]
//!   outcome (not-mine / decoded / malformed).
//!
//! The carrier is built but NOT yet attached to the RX/TX path: the
//! inbound `parse_frame_payload` OAM arm (`network_message.rs:199`) still
//! surfaces a generic `NetworkMessage::Oam`; wiring it to call
//! [`try_parse_linkstate_oam`], and the graph-driven send path, is step
//! c3. The in-memory topology graph that consumes a parsed LinkStateList
//! is step c2. `codec-linkstate`-gated (AP/full-node routing; absent from
//! the MCU footprint); owned `Vec` output (alloc-gated).
//!
//! The list itself is walked an entry at a time in both directions, never
//! through the generated bounded `LinkstateList` view, whose every slot sits
//! on the calling task's stack (see "The list walk" below).

use alloc::vec;
use alloc::vec::Vec;

use sce_forge_runtime::codec::{CodecError, SceCursor, SceSink, VecSink};
use sce_forge_runtime::heapless::Vec as HeaplessVec;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_zbuf::ExtZbufOwned;
use wz_codecs::ext_zint::ExtZint;
use wz_codecs::linkstate::{Linkstate, LinkstateOwned};
use wz_codecs::linkstate_list::{LinkstateList, LinkstateListOwned};
use wz_codecs::oam::{OamOwned, OamOwnedVariant};
use wz_codecs::wire_const;

/// Raw 2-bit body-encoding selectors (the value before it is shifted into
/// an `enc` field at bits 5..6). ZBuf = `0b10`, Z64/ZInt = `0b01` (zenoh
/// `common/extension.rs` ENC_*). The OAM/ext header builders below shift
/// these into position so a header byte reads as `mid | (enc << 5) | ...`
/// rather than an opaque packed literal.
const ENC_ZBUF: u8 = 0b10;
const ENC_ZINT: u8 = 0b01;

/// The linkstate qos extension's id — zenoh `oam::ext::QoS::ID` = 0x1
/// (`commons/zenoh-protocol/src/network/oam.rs:67`).
const OAM_QOS_EXT_ID: u8 = 0x01;

/// `QoSType::OAM.inner` projected to a ZExtZ64 value: `Priority::Control`
/// (0) | `D_FLAG` (0x08, since `CongestionControl::DEFAULT_OAM` is
/// `Block`) = 8 (zenoh `network/mod.rs:425,408,434,520`). zenoh's OAM
/// codec serialises the qos ext whenever it differs from
/// `QoSType::DEFAULT` (`network/oam.rs` codec:56-69), and `QoSType::OAM`
/// always does — so a linkstate OAM always carries exactly this one
/// extension. Pinned by the byte-parity test.
const OAM_QOS_EXT_VALUE: u64 = 0x08;

/// Outcome of [`try_parse_linkstate_oam`] — a deliberate trichotomy so a
/// malformed topology message is never silently indistinguishable from a
/// routine non-linkstate OAM (which would drop a corrupt flood on the
/// forwarding plane without a trace).
#[derive(Debug)]
pub enum LinkstateOam {
    /// The OAM id is not `OAM_LINKSTATE` — not a topology carrier; the
    /// caller leaves it to the generic `NetworkMessage::Oam` path.
    NotLinkstate,
    /// An `OAM_LINKSTATE`-addressed message whose ZBuf body decoded into a
    /// topology `LinkStateList`.
    Decoded(LinkstateListOwned),
    /// An `OAM_LINKSTATE`-addressed message that is unusable: the body was
    /// not a ZBuf (`None` — a wire-protocol violation, since zenoh always
    /// uses ENC_ZBUF for linkstate), or the ZBuf bytes failed to decode as
    /// a `LinkStateList` (`Some(err)`). The message is for us but corrupt;
    /// the caller should drop + count it, not treat it as non-linkstate.
    Malformed(Option<CodecError>),
}

/// How many entries a LinkStateList may hold: the bound of the generated
/// borrowed view's `link_states` field, read off its type so this module
/// enforces exactly the cap the codec's own `decode` and `try_as_borrowed`
/// enforce, and follows it if the codec's source changes it.
const LINK_STATES_CAP: usize = bound_of(|list: &LinkstateList<'static>| &list.link_states);

const fn bound_of<T, const N: usize>(
    _field: for<'v> fn(&'v LinkstateList<'static>) -> &'v HeaplessVec<T, N>,
) -> usize {
    N
}

// ── The list walk ────────────────────────────────────────────────────
//
// The generated `LinkstateList` view holds its entries in a bounded inline
// list, `HeaplessVec<Linkstate, LINK_STATES_CAP>`, so a value of it is every
// slot at once: ~171 KB whether the list carries one entry or the bound
// (`the_borrowed_linkstate_lists_stack_footprint_is_bounded`). Encoding an
// owned list goes through that view (`try_as_borrowed`, then `encode`), and
// decoding one produces it before projecting to owned. The value lives on the
// stack and moves by value through each of those calls, which in a debug
// build kept ~1.58 MiB of stack for one flood of a one-entry list.
//
// Both directions run inside whatever task polls the routing plane: a router
// floods its link state from `FaceForwarder::register`, inside the accept
// loop's poll, and parses an inbound advertisement there too. That task's
// stack is a tokio worker's or a test thread's 2 MiB, and the loop's own
// frames already take part of it; the router e2e in the widest feature leg
// overflowed exactly there.
//
// So the carrier walks the list an entry at a time and never materialises the
// bounded view. The wire is the codec's, unchanged: a VLE count, then each
// entry by the generated `Linkstate` codec. What the list codec checks is
// checked here in its order (each entry projected, then the bound), so a list
// the codec refuses is refused here with the same error and no byte written.
// The parity tests below pin both directions against the generated list codec.

/// Encode `list` as the LinkStateList wire, entry by entry.
///
/// The bytes the generated `LinkstateList::encode` writes for
/// `list.try_as_borrowed()?`, and the same refusals: every entry is projected
/// first, in order, and an entry past [`LINK_STATES_CAP`] is
/// `TooManyElements` (`sce_forge_runtime::codec::try_project_bounded`). An
/// entry the generated encode refuses is an `Err` here, where the generated
/// `encode_to_vec` panics.
fn encode_linkstate_list(list: &LinkstateListOwned) -> Result<Vec<u8>, CodecError> {
    for (index, entry) in list.link_states.iter().enumerate() {
        entry.try_as_borrowed()?;
        if index >= LINK_STATES_CAP {
            return Err(CodecError::TooManyElements);
        }
    }
    let mut bytes = Vec::new();
    let mut sink = VecSink::new(&mut bytes);
    sink.write_vle_u64(list.num_link_states)?;
    for entry in list.link_states.iter() {
        entry.try_as_borrowed()?.encode(&mut sink)?;
    }
    Ok(bytes)
}

/// Decode a LinkStateList from `cursor` into its owned form, entry by entry.
///
/// What the generated `LinkstateList::decode` then `try_into_owned` produce
/// and refuse, in their order: every entry is decoded, an entry past
/// [`LINK_STATES_CAP`] is `TooManyElements` once it has decoded, and only
/// then is each entry projected to owned. The decoded entries wait on the heap,
/// not in a bounded inline list.
fn decode_linkstate_list_owned(
    cursor: &mut SceCursor<'_>,
) -> Result<LinkstateListOwned, CodecError> {
    let num_link_states = cursor.read_vle_u64()?;
    let mut entries: Vec<Linkstate<'_>> = Vec::new();
    for _ in 0..num_link_states {
        let entry = Linkstate::decode(cursor)?;
        if entries.len() >= LINK_STATES_CAP {
            return Err(CodecError::TooManyElements);
        }
        entries.push(entry);
    }
    let link_states = entries
        .into_iter()
        .map(Linkstate::try_into_owned)
        .collect::<Result<Vec<LinkstateOwned>, CodecError>>()?;
    Ok(LinkstateListOwned {
        num_link_states,
        link_states,
    })
}

/// Build the OAM network-message wire bytes carrying `list`. Mirrors
/// zenoh `Network::make_msg`: encode the LinkStateList with the routing
/// codec, wrap it as `Oam { id: OAM_LINKSTATE, body: ZBuf(bytes),
/// ext_qos: QoSType::OAM }`. The transport `Frame` envelope is applied
/// separately. Owned input (the topology graph in step c2 holds owned
/// link-state records); `alloc`-only, like the sibling builders.
pub fn build_linkstate_oam(list: &LinkstateListOwned) -> Result<Vec<u8>, CodecError> {
    Ok(build_linkstate_oam_owned(list)?
        .try_as_borrowed()?
        .encode_to_vec())
}

/// Build the OAM-LINKSTATE carrier as an OWNED message — the send-path form.
/// The driver wraps this in `NetworkMessage::Oam` and floods it on its faces
/// via `send_network_message` (c3d). [`build_linkstate_oam`] is the same
/// message rendered to wire bytes (for inspection / byte-parity tests).
pub fn build_linkstate_oam_owned(list: &LinkstateListOwned) -> Result<OamOwned, CodecError> {
    let list_bytes = encode_linkstate_list(list)?;
    let value_len = list_bytes.len() as u64;

    // The qos extension (QoSType::OAM). Its header is composed from named
    // constants in `id | (enc << 5) | more` arithmetic form (the ext
    // setters are borrowed-form-only, not on the owned ExtEntryOwned), so
    // the byte is self-documenting rather than an opaque packed literal —
    // the same composite style push_build uses for its ext headers. more=0
    // because it is the only / last extension, so the chain terminates.
    let qos_ext = ExtEntryOwned {
        header: OAM_QOS_EXT_ID | (ENC_ZINT << 5),
        body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint {
            value: OAM_QOS_EXT_VALUE,
        }),
    };
    let extensions = vec![qos_ext];

    // The header's ext-chain Z bit is DERIVED from whether an extension
    // chain follows (mirrors push_build's `z_flag`), so it cannot desync
    // from the `extensions` field if a future edit drops the qos ext. The
    // enc bits are ENC_ZBUF to match the ZBuf body constructed below.
    let z = if extensions.is_empty() {
        0
    } else {
        wire_const::FLAG_N_Z
    };
    let header = wire_const::N_MID_OAM | (ENC_ZBUF << 5) | z;

    let oam = OamOwned {
        header,
        // The generated field is the WIRE width (a zint read into `u64`); the
        // constant is the VALUE width. Widening a `u16` constant is always
        // sound — it is the reverse direction, narrowing a decoded id, that
        // needs `oam_id_from_wire` and is done below.
        id: wire_const::OAM_LINKSTATE_ID as u64,
        extensions: Some(extensions),
        body: OamOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
            value_len,
            // `owned_bytes` is the wz SSOT for the borrowed->owned bytes
            // copy. Under `alloc` it is an infallible heap copy — the
            // `ExtZbufOwned` `<32>` cap is the no_std heapless bound, and
            // the linkstate carrier is alloc-only, so a multi-node payload
            // larger than 32 bytes rides the heap copy without truncation
            // (exercised by `round_trips_multinode_payload_over_32_bytes`).
            value: crate::codec_owned::owned_bytes(&list_bytes)?,
        }),
    };
    Ok(oam)
}

/// Classify a decoded OAM message as a topology carrier. See
/// [`LinkstateOam`] for the three outcomes. Decoding walks the list an entry
/// at a time through the generated `Linkstate` codec, projecting each to
/// owned (`decode_linkstate_list_owned`), so a payload
/// exceeding the generic ext-ZBuf `<32>` owned cap is fine (the structured
/// link-state records carry their own appropriately-bounded fields).
pub fn try_parse_linkstate_oam(oam: &OamOwned) -> LinkstateOam {
    // Truncate BEFORE comparing: the decoded field holds the whole zint, and a
    // sender that wrote a wide encoding of `0x1_0001` addressed every
    // conforming peer's linkstate handler (`oam_id_from_wire`). Comparing the
    // wide value answers `NotLinkstate` for a message the rest of the network
    // is acting on.
    if wire_const::oam_id_from_wire(oam.id) != wire_const::OAM_LINKSTATE_ID {
        return LinkstateOam::NotLinkstate;
    }
    let body_bytes = match &oam.body {
        OamOwnedVariant::CodecZenohExtZbuf(zbuf) => zbuf.value.as_slice(),
        // OAM_LINKSTATE addressee, but the body is not a ZBuf: a
        // wire-protocol violation, not a different OAM.
        _ => return LinkstateOam::Malformed(None),
    };
    let mut cursor = SceCursor::new(body_bytes);
    match decode_linkstate_list_owned(&mut cursor) {
        Ok(list) => LinkstateOam::Decoded(list),
        Err(e) => LinkstateOam::Malformed(Some(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_codecs::ext_unit::ExtUnit;
    use wz_codecs::oam::Oam;

    /// A LinkStateList wire of one minimal LinkState entry (the `MIN`
    /// oracle from the wz-codecs linkstate byte-parity test): count=1,
    /// then options=0 / psid=1 / sn=0 / links_len=0.
    const LIST_WIRE: [u8; 5] = [0x01, 0x00, 0x01, 0x00, 0x00];

    /// The OAM message wrapping `LIST_WIRE`, byte-derived from the zenoh
    /// OAM codec:
    ///   DF        header (N_MID_OAM 0x1F | ENC_ZBUF 0x40 | Z 0x80)
    ///   01        id = OAM_LINKSTATE (VLE)
    ///   21 08     qos ext (header id 0x1|Z64, value 8), more=0 -> chain ends
    ///   05        ZBuf length (VLE) = 5
    ///   01 00 01 00 00   the LinkStateList bytes
    const OAM_WIRE: [u8; 10] = [0xDF, 0x01, 0x21, 0x08, 0x05, 0x01, 0x00, 0x01, 0x00, 0x00];

    /// A LinkStateList wire of one WGT-bearing LinkState entry (the
    /// `WEIGHTED` oracle): count=1, then options=WGT / psid=3 / sn=0 /
    /// links_len=2 / links=[5,9] / weights=[100, 300] (300 = VLE 0xAC 0x02).
    const WEIGHTED_LIST_WIRE: [u8; 10] =
        [0x01, 0x08, 0x03, 0x00, 0x02, 0x05, 0x09, 0x64, 0xAC, 0x02];

    fn decode_list_owned(wire: &[u8]) -> LinkstateListOwned {
        let mut cursor = SceCursor::new(wire);
        LinkstateList::decode(&mut cursor)
            .expect("decode list")
            .try_into_owned()
            .expect("list to owned")
    }

    fn decode_oam_owned(wire: &[u8]) -> OamOwned {
        let mut cursor = SceCursor::new(wire);
        Oam::decode(&mut cursor)
            .expect("decode oam")
            .try_into_owned()
            .expect("oam to owned")
    }

    /// The stack the full round-trip needs in a DEBUG build, stated here rather
    /// than left to `RUST_MIN_STACK`.
    ///
    /// The chain crosses the owned/borrowed boundary six times
    /// (`decode` -> `try_into_owned` -> `try_as_borrowed` -> encode -> `decode`
    /// -> `try_into_owned`), and the borrowed form is a HEAPLESS
    /// [`the_borrowed_linkstate_lists_stack_footprint_is_bounded`]-sized value
    /// that moves by value at every one of them, with no slot reuse at `-O0`.
    ///
    /// R311y880 MEASURED the requirement on the build machine after the
    /// `link_weights` retype: 2 MiB (libtest's default) and 2.5 MiB abort,
    /// 4 MiB passes. The margin before that round was never measured at all,
    /// which is why a 24 KiB growth surfaced as `SIGABRT` in three tests rather
    /// than as a number. 8 MiB is that measured floor with room, and it is a
    /// TEST-thread figure.
    ///
    /// That figure once also read "the library's own parse path fits inside
    /// 2 MiB", which was measured, while the BUILD path went unmeasured and
    /// took ~1.58 MiB of a router's poll stack per flood. The carrier now
    /// crosses no borrowed list in either direction (the list walk above, held
    /// by `the_carrier_runs_in_less_stack_than_one_borrowed_list`); the
    /// crossings left here are this test's own oracle, `decode_list_owned` and
    /// the final `try_as_borrowed`, which is why the figure stays.
    const ROUND_TRIP_STACK: usize = 8 * 1024 * 1024;

    /// build an OAM from a list wire, decode+parse it back, and return the
    /// decoded list (asserting the round-trip reproduces the list bytes).
    ///
    /// Runs on its own thread so [`ROUND_TRIP_STACK`] is the stack it actually
    /// gets. An env var would put the requirement somewhere a plain
    /// `cargo test` never reads.
    fn round_trip(list_wire: &[u8]) -> LinkstateListOwned {
        let wire = list_wire.to_vec();
        std::thread::Builder::new()
            .stack_size(ROUND_TRIP_STACK)
            .spawn(move || round_trip_inner(&wire))
            .expect("spawn the round-trip thread")
            .join()
            .expect("the round-trip must fit in ROUND_TRIP_STACK")
    }

    fn round_trip_inner(list_wire: &[u8]) -> LinkstateListOwned {
        let list = decode_list_owned(list_wire);
        let oam_wire = build_linkstate_oam(&list).expect("build oam");
        let oam = decode_oam_owned(&oam_wire);
        match try_parse_linkstate_oam(&oam) {
            LinkstateOam::Decoded(parsed) => {
                assert_eq!(
                    parsed.try_as_borrowed().unwrap().encode_to_vec(),
                    list_wire,
                    "round-trip must reproduce the inner list bytes"
                );
                parsed
            }
            LinkstateOam::NotLinkstate => panic!("expected Decoded, got NotLinkstate"),
            LinkstateOam::Malformed(e) => panic!("expected Decoded, got Malformed({e:?})"),
        }
    }

    #[test]
    fn build_matches_zenoh_oam_wire() {
        let list = decode_list_owned(&LIST_WIRE);
        let wire = build_linkstate_oam(&list).expect("build oam");
        assert_eq!(wire, OAM_WIRE, "OAM-LINKSTATE wire must match zenoh");
    }

    #[test]
    fn parse_extracts_linkstate_list() {
        let oam = decode_oam_owned(&OAM_WIRE);
        match try_parse_linkstate_oam(&oam) {
            LinkstateOam::Decoded(list) => {
                assert_eq!(list.try_as_borrowed().unwrap().encode_to_vec(), LIST_WIRE);
                assert_eq!(list.num_link_states, 1);
                assert_eq!(list.link_states.len(), 1);
                assert_eq!(list.link_states[0].psid, 1);
            }
            other => panic!("expected Decoded, got {other:?}"),
        }
    }

    #[test]
    fn parse_returns_not_linkstate_for_other_id() {
        // A well-formed OAM with a different id is not a topology carrier.
        let oam = OamOwned {
            header: wire_const::N_MID_OAM | (ENC_ZBUF << 5),
            id: 0x0002,
            extensions: None,
            body: OamOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: 0,
                value: crate::codec_owned::owned_bytes(&[]).unwrap(),
            }),
        };
        assert!(matches!(
            try_parse_linkstate_oam(&oam),
            LinkstateOam::NotLinkstate
        ));
    }

    /// And the CONTROL for the control: an id whose LOW 16 BITS are the
    /// linkstate id IS the linkstate id, because `OamId = u16`
    /// (`zenoh-protocol/src/network/oam.rs:16`) and upstream's reader keeps
    /// only those bits (`zenoh-codec/src/core/zint.rs`, `uint_impl!(u16)`).
    ///
    /// This is not a rendering question. Answering `NotLinkstate` here means
    /// wz drops a topology advertisement that every conforming peer in the
    /// same network folded into its routing table — the two would then
    /// disagree about who is reachable, which is the failure a replacement
    /// cannot have. R311y879.
    #[test]
    fn an_id_that_aliases_onto_linkstate_is_the_linkstate_id() {
        let oam = OamOwned {
            header: wire_const::N_MID_OAM | (ENC_ZBUF << 5),
            id: wire_const::OAM_LINKSTATE_ID as u64 + 0x1_0000,
            extensions: None,
            body: OamOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: LIST_WIRE.len() as u64,
                value: crate::codec_owned::owned_bytes(&LIST_WIRE).unwrap(),
            }),
        };
        match try_parse_linkstate_oam(&oam) {
            LinkstateOam::Decoded(list) => assert_eq!(list.num_link_states, 1),
            other => panic!("a conforming peer walks this body: {other:?}"),
        }
    }

    #[test]
    fn parse_returns_malformed_for_non_zbuf_body() {
        // OAM_LINKSTATE id but a Unit body — a wire-protocol violation,
        // distinct from a non-linkstate OAM.
        let oam = OamOwned {
            header: wire_const::N_MID_OAM,
            id: wire_const::OAM_LINKSTATE_ID as u64,
            extensions: None,
            body: OamOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
        };
        assert!(matches!(
            try_parse_linkstate_oam(&oam),
            LinkstateOam::Malformed(None)
        ));
    }

    #[test]
    fn round_trips_empty_list() {
        // A zero-entry LinkStateList ("I know of no peers"): count byte 0x00.
        let list = round_trip(&[0x00]);
        assert_eq!(list.num_link_states, 0);
        assert_eq!(list.link_states.len(), 0);
    }

    /// The BORROWED `LinkstateList` is a heapless value moved by value through
    /// every owned/borrowed crossing, and this pins how big it is allowed to
    /// get.
    ///
    /// R311y880 measured it at 171_536 B (`Linkstate` 2_680 x the codec's
    /// `HeaplessVec<_, 64>` cap), up 24_576 B from the round before, because
    /// retyping `link_weights` to the WIRE's width grew each element from 2 to
    /// 8 bytes. That growth was correct and stays, but it turned three
    /// round-trip tests into a bare `SIGABRT` with no number attached — the
    /// margin had never been measured, so nothing could say how close they
    /// already were.
    ///
    /// A CEILING rather than an equality on purpose: padding can shift the
    /// exact figure, and a pin that reds on padding teaches its readers to edit
    /// the pin. What must not pass silently is another field-width change.
    /// When this reds, re-measure [`ROUND_TRIP_STACK`] before raising it.
    #[test]
    fn the_borrowed_linkstate_lists_stack_footprint_is_bounded() {
        let size = core::mem::size_of::<LinkstateList<'_>>();
        assert!(
            size <= 192 * 1024,
            "the borrowed LinkstateList is {size} B, past the 192 KiB ceiling; \
             re-measure ROUND_TRIP_STACK before raising this"
        );
    }

    /// A LinkStateList wire of `n` minimal entries with distinct psids, each
    /// `options=0 / psid / sn=0 / links_len=0` (psid < 128, so one VLE byte).
    fn minimal_list_wire(n: u8) -> Vec<u8> {
        let mut wire = vec![n];
        for psid in 0..n {
            wire.extend_from_slice(&[0x00, psid, 0x00, 0x00]);
        }
        wire
    }

    /// An `OAM_LINKSTATE` message carrying `list_wire`, assembled as an owned
    /// value so building it crosses no borrowed list.
    fn linkstate_oam_of(list_wire: &[u8]) -> OamOwned {
        OamOwned {
            header: wire_const::N_MID_OAM | (ENC_ZBUF << 5),
            id: wire_const::OAM_LINKSTATE_ID as u64,
            extensions: None,
            body: OamOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: list_wire.len() as u64,
                value: crate::codec_owned::owned_bytes(list_wire).unwrap(),
            }),
        }
    }

    /// The carrier's stack cost does not grow with the codec's list bound.
    ///
    /// Both directions run on whatever task polls the routing plane: a router
    /// floods its link state from `FaceForwarder::register`, inside the accept
    /// loop's poll, on a tokio worker's 2 MiB or a test thread's 2 MiB. Built
    /// through the borrowed `LinkstateList`, one flood cost ~1.58 MiB of stack
    /// in a debug build (measured under gdb: `try_project_bounded` 204_808 B,
    /// `LinkstateListOwned::try_as_borrowed` 686_176 B, this module's builder
    /// 686_752 B) for a list of ONE entry, because the view reserves all 64
    /// slots inline and moves by value. The accept loop's own frames took the
    /// rest, and the router e2e in the 82-feature leg aborted.
    ///
    /// The budget is one borrowed list's own size: an implementation that
    /// materialises the bounded view cannot fit in it, whatever its frames,
    /// and one that walks the list an entry at a time needs a few entries'
    /// worth. A full list (the bound, 64 entries) is parsed and rebuilt.
    #[test]
    fn the_carrier_runs_in_less_stack_than_one_borrowed_list() {
        let budget = core::mem::size_of::<LinkstateList<'_>>();
        let list_wire = minimal_list_wire(64);
        let oam = linkstate_oam_of(&list_wire);
        let rebuilt = std::thread::Builder::new()
            .stack_size(budget)
            .spawn(move || {
                let LinkstateOam::Decoded(list) = try_parse_linkstate_oam(&oam) else {
                    panic!("a full list is a linkstate advertisement");
                };
                assert_eq!(list.link_states.len(), 64);
                build_linkstate_oam_owned(&list).expect("rebuild the full list")
            })
            .expect("spawn the carrier thread")
            .join()
            .expect("the carrier must run inside one borrowed list's stack");
        match rebuilt.body {
            OamOwnedVariant::CodecZenohExtZbuf(zbuf) => {
                assert_eq!(zbuf.value.as_slice(), list_wire.as_slice());
            }
            other => panic!("a linkstate OAM carries a ZBuf body: {other:?}"),
        }
    }

    /// Run `body` on a thread with [`ROUND_TRIP_STACK`]: the parity tests
    /// below call the generated list codec as their oracle, and it needs it.
    fn with_oracle_stack(body: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(ROUND_TRIP_STACK)
            .spawn(body)
            .expect("spawn the oracle thread")
            .join()
            .expect("the oracle must fit in ROUND_TRIP_STACK");
    }

    /// The list walk writes the generated list codec's bytes: an empty list,
    /// one entry, a weighted entry, and a full list at the bound.
    #[test]
    fn the_list_walk_encodes_what_the_list_codec_encodes() {
        with_oracle_stack(|| {
            for wire in [
                vec![0x00],
                LIST_WIRE.to_vec(),
                WEIGHTED_LIST_WIRE.to_vec(),
                minimal_list_wire(64),
            ] {
                let list = decode_list_owned(&wire);
                let by_codec = list.try_as_borrowed().expect("in bound").encode_to_vec();
                assert_eq!(encode_linkstate_list(&list), Ok(by_codec.clone()));
                assert_eq!(by_codec, wire);
            }
        });
    }

    /// The list walk refuses what the list codec refuses: an owned list one
    /// entry past the bound is `TooManyElements` on both, and the bound is the
    /// codec's own.
    #[test]
    fn the_list_walk_refuses_a_list_past_the_bound_as_the_codec_does() {
        assert_eq!(LINK_STATES_CAP, 64);
        with_oracle_stack(|| {
            let mut list = decode_list_owned(&minimal_list_wire(64));
            let extra = list.link_states[0].clone();
            list.link_states.push(extra);
            list.num_link_states = 65;
            assert_eq!(
                list.try_as_borrowed().err(),
                Some(CodecError::TooManyElements)
            );
            assert_eq!(
                encode_linkstate_list(&list),
                Err(CodecError::TooManyElements)
            );
            assert!(matches!(
                build_linkstate_oam_owned(&list),
                Err(CodecError::TooManyElements)
            ));
        });
    }

    /// The list walk decodes what the list codec decodes, and refuses an
    /// advertisement past the bound, or one cut short, with the codec's error.
    #[test]
    fn the_list_walk_decodes_what_the_list_codec_decodes() {
        with_oracle_stack(|| {
            let mut past_bound = minimal_list_wire(64);
            past_bound[0] = 65;
            past_bound.extend_from_slice(&[0x00, 0x40, 0x00, 0x00]);
            let mut cut_short = minimal_list_wire(3);
            cut_short.pop();
            for wire in [
                vec![0x00],
                LIST_WIRE.to_vec(),
                WEIGHTED_LIST_WIRE.to_vec(),
                minimal_list_wire(64),
                past_bound,
                cut_short,
            ] {
                let by_codec = LinkstateList::decode(&mut SceCursor::new(&wire))
                    .and_then(|list| list.try_into_owned());
                let by_walk = decode_linkstate_list_owned(&mut SceCursor::new(&wire));
                assert_eq!(by_walk, by_codec, "wire {wire:02x?}");
                match try_parse_linkstate_oam(&linkstate_oam_of(&wire)) {
                    LinkstateOam::Decoded(list) => assert_eq!(Ok(list), by_codec),
                    LinkstateOam::Malformed(Some(e)) => assert_eq!(Err(e), by_codec),
                    other => panic!("a ZBuf linkstate body is decoded or malformed: {other:?}"),
                }
            }
        });
    }

    #[test]
    fn round_trips_weighted_list() {
        let list = round_trip(&WEIGHTED_LIST_WIRE);
        assert_eq!(list.link_states.len(), 1);
        let weights = list.link_states[0]
            .weights
            .as_ref()
            .expect("WGT set => weights present through the OAM carrier");
        assert_eq!(weights.len(), 2);
        assert_eq!(weights[1].weight, 300);
    }

    #[test]
    fn round_trips_multinode_payload_over_32_bytes() {
        // 10 minimal entries => list wire = 1 (count) + 10*4 = 41 bytes,
        // well over the generic ext-ZBuf <32> owned cap. Proves the
        // alloc-unbounded SceBytes path carries a multi-node payload
        // without truncation.
        let mut list_wire: Vec<u8> = vec![0x0A]; // count = 10
        for _ in 0..10 {
            list_wire.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        }
        assert!(list_wire.len() > 32, "payload must exceed the <32> cap");
        let list = round_trip(&list_wire);
        assert_eq!(list.num_link_states, 10);
        assert_eq!(list.link_states.len(), 10);
    }
}

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! OAM carrier for the linkstate-peer topology exchange (P4 routing,
//! linkstate port step c1).
//!
//! zenoh floods peer topology as a `LinkStateList` wrapped in an OAM
//! (Operations & Maintenance) network message: `Network::make_msg`
//! (`zenoh/src/net/protocol/network.rs:350-365`) encodes the list with
//! the routing codec into a `ZBuf`, then builds
//! `Oam { id: OAM_LINKSTATE, body: ZBuf(bytes), ext_qos: QoSType::OAM }`.
//! This module is the wz bridge between the `wz-codecs` LinkStateList
//! codec (step b) and the `NetworkMessage::Oam` envelope:
//!
//! * [`build_linkstate_oam`] — LinkStateList -> OAM message wire bytes.
//! * [`try_parse_linkstate_oam`] — a decoded OAM -> LinkStateList iff the
//!   OAM id is `OAM_LINKSTATE` and the body is a ZBuf.
//!
//! The carrier is `codec-linkstate`-gated (AP/full-node routing; absent
//! from the MCU footprint). The transport `Frame` envelope is applied
//! separately (`frame_encode`), same as the other network-message
//! builders. The in-memory topology graph that consumes the parsed
//! LinkStateList is step c2.

use alloc::vec;
use alloc::vec::Vec;

use sce_forge_runtime::codec::{CodecError, SceCursor};
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_zbuf::ExtZbufOwned;
use wz_codecs::ext_zint::ExtZint;
use wz_codecs::linkstate_list::{LinkstateList, LinkstateListOwned};
use wz_codecs::oam::{OamOwned, OamOwnedVariant};
use wz_codecs::wire_const;

/// zenoh `oam::id::OAM_LINKSTATE` (`commons/zenoh-protocol/src/network/
/// oam.rs:27`) — the OAM message id carrying a topology `LinkStateList`.
/// Carried as the OAM `id:z16` (a VLE u16); the wz OAM codec models the
/// id field as a VLE `u64`, of which the OAM ids are a subset.
pub const OAM_ID_LINKSTATE: u64 = 0x0001;

/// OAM header byte for a linkstate message: `N_MID_OAM` (0x1F) in bits
/// 0..4, `ENC_ZBUF` (0b10) in the enc bits 5..6 (= 0x40), and the
/// extensions flag `Z` (0x80). Z is always set because the qos extension
/// is always present (see [`OAM_QOS_EXT_HEADER`]).
const OAM_LINKSTATE_HEADER: u8 = wire_const::N_MID_OAM | 0x40 | 0x80; // 0xDF

/// The qos extension every linkstate OAM carries. zenoh's `make_msg` sets
/// `ext_qos: QoSType::OAM`, which is NOT `QoSType::DEFAULT`, so the OAM
/// codec always serialises it (`commons/zenoh-codec/src/network/oam.rs:
/// 56-69`). The ext header `0x21` = ext id `0x1` | enc `Z64` (0x20) |
/// more-flag 0 (it is the only/last extension). The ext value 8 is
/// `QoSType::OAM.inner` = `Priority::Control` (0) | `D_FLAG` (0x08, since
/// `CongestionControl::DEFAULT_OAM` is `Block`), projected to a ZExtZ64
/// value (`network/mod.rs:425,408,520`). Constant for every linkstate OAM.
const OAM_QOS_EXT_HEADER: u8 = 0x21;
const OAM_QOS_EXT_VALUE: u64 = 0x08;

/// Build the OAM network-message wire bytes carrying `list`. Mirrors
/// zenoh `Network::make_msg`: encode the LinkStateList with the routing
/// codec, wrap it as `Oam { id: OAM_LINKSTATE, body: ZBuf(bytes),
/// ext_qos: QoSType::OAM }`. The transport `Frame` envelope is applied
/// separately. Owned input (the topology graph in step c2 holds owned
/// link-state records); `alloc`-only, like the sibling builders.
pub fn build_linkstate_oam(list: &LinkstateListOwned) -> Result<Vec<u8>, CodecError> {
    let list_bytes = list.try_as_borrowed()?.encode_to_vec();
    let value_len = list_bytes.len() as u64;
    let oam = OamOwned {
        header: OAM_LINKSTATE_HEADER,
        id: OAM_ID_LINKSTATE,
        extensions: Some(vec![ExtEntryOwned {
            header: OAM_QOS_EXT_HEADER,
            body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint {
                value: OAM_QOS_EXT_VALUE,
            }),
        }]),
        body: OamOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
            value_len,
            // `owned_bytes` is the wz SSOT for the borrowed->owned bytes
            // copy (the same helper the push source_info ext uses). Under
            // `alloc` it is an infallible heap copy — the `ExtZbufOwned`
            // `<32>` cap is the no_std heapless bound, and the linkstate
            // carrier is alloc-only, so a multi-node payload larger than
            // 32 bytes rides the heap copy without truncation.
            value: crate::codec_owned::owned_bytes(&list_bytes)?,
        }),
    };
    let wire = oam.try_as_borrowed()?.encode_to_vec();
    Ok(wire)
}

/// Decode the topology payload out of a received OAM message. Returns
/// `None` when the OAM is not a linkstate carrier (a different `id`, or a
/// non-ZBuf body — both leave the message to the generic
/// `NetworkMessage::Oam` path); `Some(Ok(list))` / `Some(Err(..))` for an
/// `OAM_LINKSTATE` ZBuf body that decodes / fails to decode as a
/// `LinkStateList`. Decoding goes through the borrowed `LinkstateList`
/// codec then projects to owned, so a payload exceeding the generic
/// ext-ZBuf `<32>` owned cap is fine (the structured link-state records
/// carry their own appropriately-bounded fields).
pub fn try_parse_linkstate_oam(oam: &OamOwned) -> Option<Result<LinkstateListOwned, CodecError>> {
    if oam.id != OAM_ID_LINKSTATE {
        return None;
    }
    let body_bytes = match &oam.body {
        OamOwnedVariant::CodecZenohExtZbuf(zbuf) => zbuf.value.as_slice(),
        _ => return None,
    };
    let mut cursor = SceCursor::new(body_bytes);
    Some(LinkstateList::decode(&mut cursor).and_then(|list| list.try_into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn decode_list_owned(wire: &[u8]) -> LinkstateListOwned {
        let mut cursor = SceCursor::new(wire);
        LinkstateList::decode(&mut cursor)
            .expect("decode list")
            .try_into_owned()
            .expect("list to owned")
    }

    #[test]
    fn build_matches_zenoh_oam_wire() {
        let list = decode_list_owned(&LIST_WIRE);
        let wire = build_linkstate_oam(&list).expect("build oam");
        assert_eq!(wire, OAM_WIRE, "OAM-LINKSTATE wire must match zenoh");
    }

    #[test]
    fn parse_extracts_linkstate_list() {
        let mut cursor = SceCursor::new(&OAM_WIRE);
        let oam = Oam::decode(&mut cursor)
            .expect("decode oam")
            .try_into_owned()
            .expect("oam to owned");
        let list = try_parse_linkstate_oam(&oam)
            .expect("OAM_LINKSTATE id recognised")
            .expect("body decodes as LinkStateList");
        // Re-encode the parsed list; it must reproduce the inner wire.
        assert_eq!(list.try_as_borrowed().unwrap().encode_to_vec(), LIST_WIRE);
        assert_eq!(list.num_link_states, 1);
        assert_eq!(list.link_states.len(), 1);
        assert_eq!(list.link_states[0].psid, 1);
    }

    #[test]
    fn parse_ignores_non_linkstate_oam() {
        // An OAM with a different id is not a linkstate carrier.
        let oam = OamOwned {
            header: OAM_LINKSTATE_HEADER,
            id: 0x0002,
            extensions: None,
            body: OamOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: 0,
                value: crate::codec_owned::owned_bytes(&[]).unwrap(),
            }),
        };
        assert!(try_parse_linkstate_oam(&oam).is_none());
    }

    #[test]
    fn build_parse_round_trips() {
        let list = decode_list_owned(&LIST_WIRE);
        let wire = build_linkstate_oam(&list).unwrap();
        let mut cursor = SceCursor::new(&wire);
        let oam = Oam::decode(&mut cursor).unwrap().try_into_owned().unwrap();
        let parsed = try_parse_linkstate_oam(&oam).unwrap().unwrap();
        assert_eq!(parsed.try_as_borrowed().unwrap().encode_to_vec(), LIST_WIRE);
    }
}

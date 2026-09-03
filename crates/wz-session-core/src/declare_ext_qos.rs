// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Declare-envelope `ext_qos` — the QoS class zenoh stamps on the Declare
//! network message, and the SSOT for the one extension every
//! `declare_build` envelope now carries.
//!
//! zenoh types the field as `pub type QoS = zextz64!(0x1, false)`
//! (`commons/zenoh-protocol/src/network/declare.rs:67`) — extension id `0x1`,
//! `Z64`-bodied, and NOT mandatory (no `M` flag), so the header byte is
//! `id (0x01) | ENC_Z64 (0x20) = 0x21` for a terminal entry. The encoder writes
//! it exactly when the value differs from `QoSType::DEFAULT`
//! (`commons/zenoh-codec/src/network/declare.rs:105,118`), and a Declare is
//! constructed with `QoSType::DECLARE` — `Priority::Control` (0) plus
//! `CongestionControl::DEFAULT_DECLARE`, which is `Block`
//! (`network/mod.rs:410-411`, `core/mod.rs:599`) — so the ext is written on
//! effectively every Declare zenoh emits.
//!
//! "Effectively" is measured rather than assumed: across
//! `zenoh/src/net/routing/` the pinned 1.5.0 tree (`49c8a53`) constructs a
//! Declare with `ext_qos: ext::QoSType::DECLARE` at 127 sites and with
//! `ext_qos: ext::QoSType::default()` at 3 — `hat/client/token.rs:135` and
//! `:371`, `hat/p2p_peer/token.rs:215`, all of them token declares whose
//! siblings in the same file use `DECLARE`. wz stamps `DECLARE` on every
//! envelope: it is upstream's rule, the three outliers read as upstream drift
//! against itself rather than a second class, and a Declare that says
//! "Control priority, do not drop" is the one that survives a congested link.
//!
//! ## Why this is a gap and not a divergence
//!
//! zenoh-pico does NOT write this ext: `_z_n_msg_make_declare` sets
//! `_ext_qos = _Z_N_QOS_DEFAULT` unconditionally
//! (`vendor/zenoh-pico/src/protocol/definitions/network.c:178`), so its encoder's
//! `has_qos_ext` gate (`src/protocol/codec/network.c:390`) is never taken. wz's
//! previous `extensions: None` therefore matched pico exactly while diverging
//! from zenoh — and pico's DECODER accepts the ext regardless
//! (`_z_declare_decode_extensions`, `network.c:422-425`), so stamping it costs
//! nothing on the pico leg and buys the zenoh one.
//!
//! ## Why the Interest arm lives in a module named for the Declare
//!
//! `Interest` carries the same extension — `pub type QoS = zextz64!(0x1,
//! false)` again (`network/interest.rs:187`) — and upstream's own Interest
//! CODEC compares it against `declare::ext::QoSType::DEFAULT`
//! (`zenoh-codec/src/network/interest.rs:59,77`), i.e. zenoh itself reaches
//! into the declare module for the Interest's QoS type. One module for both is
//! that fact rather than a convenience.
//!
//! What is NOT shared is the VALUE, and the difference is measured, not
//! assumed. zenoh stamps `DECLARE` on effectively every Declare, but on exactly
//! ONE of its six api-level Interests: the liveliness-subscriber
//! (`api/session.rs:1812`). The SUBSCRIBERS (`:1376`) and QUERYABLES (`:1434`)
//! interests, all three `Final`s (`:1405`, `:1462`, `:1600`) and the liveliness
//! GET (`:2400`, which reaches for `request::ext::QoSType` for an Interest) all
//! use DEFAULT and therefore write nothing. Only the routing-layer HATs use
//! `DECLARE` uniformly. So the Interest arm is a SETTER
//! (`set_interest_qos`) applied at the one builder that earns it, and there
//! is deliberately no `interest_envelope_extensions` twin of
//! `declare_envelope_extensions` — a chain constructor invites every Interest
//! builder to call it, which would be a divergence dressed as parity.
//!
//! ## Chain order
//!
//! zenoh writes the Declare extensions in id order — qos, then tstamp, then
//! nodeid (`zenoh-codec/src/network/declare.rs:118-129`). The builders stamp
//! qos at construction and `declare_routing_context`
//! appends `ext_nodeid` afterwards, so the production order is `[qos, nodeid]`
//! by construction. `set_declare_qos` re-appends (the shared
//! [`ext_nodeid::set_z64_ext`] chain edit is retain-then-push), so calling it on
//! a Declare that already carries an `ext_nodeid` reorders the chain; that
//! costs nothing to either decoder — both scan the chain by id — but it does
//! cost byte-parity, which is why the builders and not this setter are the
//! production path.

use alloc::vec::Vec;

#[cfg(feature = "codec-declare")]
use wz_codecs::declare::DeclareOwned;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_zint::ExtZint;
use wz_codecs::interest::InterestOwned;

use crate::ext_nodeid::{self, EXT_ENC_Z64};
use crate::qos::{CongestionControl, Priority};
use crate::sample::QosLevel;

/// The Declare `ext_qos` extension id — zenoh `declare::ext::QoS`,
/// `zextz64!(0x1, false)`.
pub const QOS_EXT_ID: u8 = 0x01;

/// The `ext_qos` header with no further extension following:
/// `id (0x01) | ENC_Z64 (0x20)` = `0x21`. NO `M` flag — upstream declares the
/// extension non-mandatory (`zextz64!(0x1, false)`), unlike `ext_nodeid`'s
/// `zextz64!(0x3, true)`. The chain-continuation `FLAG_Z` (0x80) is layered on
/// by [`ext_nodeid::apply_chain_z_bits`] when the entry is not last.
pub const QOS_EXT_HEADER: u8 = QOS_EXT_ID | EXT_ENC_Z64;

/// zenoh `QoSType::DECLARE` projected onto wz's own packed-byte type:
/// `Priority::Control` (0) in the low three bits, `CongestionControl::Block`
/// (`CongestionControl::DEFAULT_DECLARE`) in the `nodrop` bit 3, no express —
/// raw `0x08`. Built from the typed enums through the single packer
/// (`QosLevel::from_parts`) rather than written as a literal, so the layout
/// stays owned by one place; the byte itself is pinned by a test.
pub const QOS_DECLARE: QosLevel =
    QosLevel::from_parts(Priority::Control, CongestionControl::Block, false);

/// Build the `ext_qos` extension entry carrying `qos`. Terminal header (the
/// caller's chain normalisation via [`ext_nodeid::apply_chain_z_bits`] sets the
/// continuation bit if another entry follows).
pub fn qos_ext(qos: QosLevel) -> ExtEntryOwned {
    ExtEntryOwned {
        header: QOS_EXT_HEADER,
        body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint {
            value: qos.raw as u64,
        }),
    }
}

/// The Declare envelope's extension chain as every
/// `declare_build` builder emits it: exactly one entry,
/// the `ext_qos` carrying [`QOS_DECLARE`]. The single place the "what does a
/// freshly built Declare carry" question is answered, so a new builder cannot
/// forget it by copying a stale literal.
///
/// R311y802 — `#[inline(never)]` is load-bearing, and it is a FOOTPRINT
/// decision rather than a style one. R311y801 shipped this function inlinable
/// and Layer F redded on the codec-close lane, whose elision collapsed from
/// +1776B to -192B; bisecting to this one file restored it, and the attribute
/// fixes it while keeping the feature.
///
/// The MECHANISM is not the obvious one and was measured rather than assumed.
/// Inlining fifteen copies of a one-element `Vec` is not what cost the bytes:
/// with the attribute the BASELINE binary shrinks only 152B (2711088 ->
/// 2710936). What it costs is CONFIGURATION-DEPENDENCE — the `minus-codec-close`
/// build shrinks 2184B (2711296 -> 2709112), because in that feature set (which
/// also drops `transport-multicast` and the `domain-*` umbrellas) LLVM chose to
/// inline at all fifteen sites and in the baseline it did not. A codec's
/// measured elision is a DIFFERENCE between two builds, so a function whose
/// inlining decision flips between them is charged to whichever feature the
/// lane is measuring. Out-of-line, the decision cannot flip: codec-close's
/// elision reads +1824B, against +1792B for a tree with this whole envelope
/// change reverted.
#[inline(never)]
pub fn declare_envelope_extensions() -> Vec<ExtEntryOwned> {
    alloc::vec![qos_ext(QOS_DECLARE)]
}

/// Read the `ext_qos` out of a message's extension chain. `QosLevel::DEFAULT`
/// when absent — zenoh's omit-on-DEFAULT convention read back the way its
/// decoder does (the field simply keeps its default), which is also what every
/// Declare from a pico peer means.
///
/// Carrier-agnostic because the chain is: the two public readers below differ
/// only in which struct's field they hand over.
fn read_qos_chain(exts: Option<&Vec<ExtEntryOwned>>) -> QosLevel {
    ext_nodeid::read_z64_ext(exts, QOS_EXT_ID)
        .map(|v| QosLevel::from_raw(v as u8))
        .unwrap_or(QosLevel::DEFAULT)
}

/// Set the `ext_qos` in a message's extension chain and sync that message's
/// header `Z` bit. `QosLevel::DEFAULT` REMOVES the entry — zenoh's
/// omit-on-DEFAULT encode gate expressed as a chain edit, so a round-trip
/// through the wire and back is idempotent.
///
/// The header byte is passed in rather than the message, because WHICH header
/// carries the bit is the only thing the Declare and Interest arms do not
/// share; everything above it does, which is why it is one function.
fn set_qos_chain(exts: &mut Option<Vec<ExtEntryOwned>>, header: &mut u8, qos: QosLevel) {
    let value = if qos == QosLevel::DEFAULT {
        None
    } else {
        Some(qos.raw as u64)
    };
    let present = ext_nodeid::set_z64_ext(exts, QOS_EXT_ID, QOS_EXT_HEADER, value);
    ext_nodeid::sync_header_z(header, present);
}

/// Read an `Interest`'s `ext_qos`. Absent means `QosLevel::DEFAULT`, which is
/// what six of upstream's seven api-level Interests mean on the wire — and what
/// NONE of its six routing-hat propagation sites mean, every one of which
/// stamps `QoSType::INTEREST` (R2316 re-measured both populations against the
/// pinned 1.10.0 reference; the earlier "five of six" was the 1.5.0-era count).
pub fn read_interest_qos(interest: &InterestOwned) -> QosLevel {
    read_qos_chain(interest.extensions.as_ref())
}

/// Set an `Interest`'s `ext_qos` (`QosLevel::DEFAULT` removes it).
pub fn set_interest_qos(interest: &mut InterestOwned, qos: QosLevel) {
    set_qos_chain(&mut interest.extensions, &mut interest.header, qos);
}

/// Read a Declare's `ext_qos`. Absent means `QosLevel::DEFAULT` — the state
/// every Declare wz emitted before R311y801, and every Declare a pico peer
/// emits at all.
#[cfg(feature = "codec-declare")]
pub fn read_declare_qos(declare: &DeclareOwned) -> QosLevel {
    read_qos_chain(declare.extensions.as_ref())
}

/// Set a Declare's `ext_qos` (`QosLevel::DEFAULT` REMOVES it).
#[cfg(feature = "codec-declare")]
pub fn set_declare_qos(declare: &mut DeclareOwned, qos: QosLevel) {
    set_qos_chain(&mut declare.extensions, &mut declare.header, qos);
}

/// The Interest arm's own tests — separate from the Declare module below
/// because that one needs `codec-declare` and `wz_codecs::interest` does not.
/// The PAIR is the arm here: the liveliness SUBSCRIBER carries the ext and the
/// liveliness GET does not, and a test that only asserted the first would pass
/// just as well against a build that stamped every Interest.
#[cfg(test)]
mod interest_tests {
    use super::*;
    use crate::ext_nodeid::MESSAGE_FLAG_Z;
    use crate::interest_build::{
        build_interest_final, build_interest_liveliness_get, build_interest_liveliness_subscriber,
        build_interest_subscribers,
    };

    #[test]
    fn the_liveliness_subscriber_interest_carries_the_declare_qos() {
        let i = build_interest_liveliness_subscriber(4, true, 0, Some("live/**")).expect("build");
        assert_eq!(read_interest_qos(&i), QOS_DECLARE);
        assert_eq!(i.header & MESSAGE_FLAG_Z, MESSAGE_FLAG_Z);
        assert_eq!(i.extensions.as_ref().map(|e| e.len()), Some(1));
    }

    /// The discriminating half. Upstream's liveliness GET
    /// (`api/session.rs:2400`) leaves the field at DEFAULT — it even reaches
    /// for `request::ext::QoSType` to say so — so wz must write nothing here
    /// even though the GET shares its whole body with the subscriber above.
    #[test]
    fn the_liveliness_get_interest_carries_no_qos() {
        let i = build_interest_liveliness_get(4, 0, Some("live/**")).expect("build");
        assert_eq!(read_interest_qos(&i), QosLevel::DEFAULT);
        assert!(i.extensions.is_none());
        assert_eq!(i.header & MESSAGE_FLAG_Z, 0);
    }

    /// The subscribers interest (`api/session.rs:1376`) and the Final
    /// (`:1405`) are the other two shapes wz emits, and upstream leaves both at
    /// DEFAULT.
    #[test]
    fn the_subscribers_and_final_interests_carry_no_qos() {
        let subs = build_interest_subscribers(7, true, true, 0, Some("demo/**")).expect("build");
        assert!(subs.extensions.is_none());
        assert_eq!(subs.header & MESSAGE_FLAG_Z, 0);

        let fin = build_interest_final(7);
        assert!(fin.extensions.is_none());
        assert_eq!(fin.header & MESSAGE_FLAG_Z, 0);
    }

    /// The Interest codec writes its extensions AFTER the body (id, options,
    /// wire_expr) — the opposite of the Declare, where they precede it
    /// (`zenoh-codec/src/network/interest.rs:65-88` vs `declare.rs:111-132`).
    /// The wz generated field order is the same, and this pins that the ext
    /// lands at the TAIL rather than being spliced into the body.
    ///
    /// `codec-declare`-gated for the same reason `interest_build`'s own wire
    /// vectors are: `TestWire for InterestOwned` is emitted under that feature
    /// in `wz-codecs-test-support` (lib.rs:64-68), not under an interest one.
    #[cfg(feature = "codec-declare")]
    #[test]
    fn the_interest_qos_ext_trails_the_body_on_the_wire() {
        use wz_codecs_test_support::TestWire;

        let i = build_interest_liveliness_subscriber(4, true, 0, Some("live")).expect("build");
        let wire = i.wire();
        // LITERAL bytes, not the constants: every other Interest vector in this
        // tree derives its tail from `QOS_EXT_HEADER`, so without one literal
        // pin on this plane a wrong constant would move the Interest wire with
        // nothing to catch it (measured — falsify probe 3 redded only the
        // Declare-side literal goldens).
        assert_eq!(
            &wire[wire.len() - 2..],
            &[0x21, 0x08],
            "the ext_qos entry (id 0x01 | ENC_Z64, QoSType::DECLARE) is the \
             last thing on an Interest's wire"
        );
        assert_eq!(wire[0] & MESSAGE_FLAG_Z, MESSAGE_FLAG_Z, "header Z set");
    }
}

#[cfg(all(test, feature = "codec-declare"))]
mod tests {
    use super::*;
    use crate::declare_build::{build_declare_kexpr, build_declare_subscriber};
    use crate::declare_routing_context::set_declare_source;
    use crate::ext_nodeid::{EXT_FLAG_M, EXT_FLAG_Z, MESSAGE_FLAG_Z};

    /// The packed byte is `Priority::Control | nodrop` = 8, the same value
    /// `linkstate_oam` pins for `QoSType::OAM` (identical components) and the
    /// value zenoh's `QoSType::DECLARE` carries. Stated as a literal HERE and
    /// derived from the typed enums in the const, so a change to either side
    /// has to face the other.
    #[test]
    fn declare_qos_packs_to_control_plus_nodrop() {
        assert_eq!(QOS_DECLARE.raw, 0x08);
        assert_eq!(QOS_DECLARE.priority(), Priority::Control);
        assert_eq!(QOS_DECLARE.congestion(), CongestionControl::Block);
        assert!(!QOS_DECLARE.is_express());
        // ... and it is NOT the DEFAULT, which is what makes zenoh write it.
        assert_ne!(QOS_DECLARE, QosLevel::DEFAULT);
    }

    /// The header byte is non-mandatory, unlike ext_nodeid's. Getting the `M`
    /// flag wrong is invisible on the happy path and only surfaces when a peer
    /// does not understand the extension: with `M` set, zenoh-pico's
    /// `_z_msg_ext_unknown_error` REJECTS the whole message
    /// (`src/protocol/codec/network.c:431-432`) instead of skipping the entry.
    #[test]
    fn qos_ext_header_is_optional_z64_not_mandatory() {
        assert_eq!(QOS_EXT_HEADER, 0x21);
        assert_eq!(QOS_EXT_HEADER & EXT_FLAG_M, 0, "ext_qos is not mandatory");
        assert_eq!(QOS_EXT_HEADER & EXT_FLAG_Z, 0, "terminal entry");
    }

    #[test]
    fn a_built_declare_carries_the_declare_qos() {
        let d = build_declare_kexpr(3, "demo/example").expect("build");
        assert_eq!(read_declare_qos(&d), QOS_DECLARE);
        assert_eq!(
            d.header & MESSAGE_FLAG_Z,
            MESSAGE_FLAG_Z,
            "the envelope header must flag the chain"
        );
    }

    #[test]
    fn setting_the_default_removes_the_ext_and_clears_the_header_bit() {
        let mut d = build_declare_kexpr(3, "demo/example").expect("build");
        set_declare_qos(&mut d, QosLevel::DEFAULT);
        assert!(d.extensions.is_none(), "omit-on-DEFAULT drops the sole ext");
        assert_eq!(d.header & MESSAGE_FLAG_Z, 0);
        // Reading it back still answers DEFAULT — the encode gate and the read
        // are two halves of the same convention.
        assert_eq!(read_declare_qos(&d), QosLevel::DEFAULT);
    }

    /// The production chain order: qos is stamped by the builder, nodeid is
    /// appended by the forward seam, and zenoh writes them in that order.
    #[test]
    fn qos_precedes_nodeid_in_the_production_chain() {
        let mut d = build_declare_subscriber(0, 0, Some("demo/sub")).expect("build");
        set_declare_source(&mut d, 7);
        let exts = d.extensions.as_ref().expect("chain present");
        assert_eq!(exts.len(), 2);
        assert_eq!(exts[0].header, QOS_EXT_HEADER | EXT_FLAG_Z, "qos leads");
        assert_eq!(exts[1].header, 0x33, "nodeid terminates");
        assert_eq!(read_declare_qos(&d), QOS_DECLARE);
        assert_eq!(crate::declare_routing_context::read_declare_source(&d), 7);
    }

    /// Byte-parity against the zenoh wire for the simplest Declare wz emits.
    /// Derived from `zenoh-codec/src/network/declare.rs` (header, then exts,
    /// then body) and `zenoh-pico`'s `_z_msg_ext_encode_zint` (header byte then
    /// a VLE value) — the same derivation the ext_nodeid golden uses.
    #[test]
    fn declare_kexpr_with_qos_matches_the_zenoh_golden_bytes() {
        use wz_codecs_test_support::TestWire;

        let d = build_declare_kexpr(3, "demo/example").expect("build");
        let mut expected = alloc::vec![
            0x9E, // Declare header: N_MID_DECLARE 0x1E | Z 0x80 (ext chain)
            0x21, // ext_qos header: id 0x01 | ENC_Z64 0x20 (terminal, no M)
            0x08, // QoSType::DECLARE -> Control | nodrop -> VLE(8)
            0x20, // DeclKexpr header: MID 0x00 | N 0x20
            0x03, // mapping id 3 -> VLE
            0x00, // wireexpr mapping id 0 -> VLE (literal sentinel)
            0x0C, // suffix_len 12 -> VLE
        ];
        expected.extend_from_slice(b"demo/example");
        assert_eq!(d.wire(), expected);
    }

    /// The ext survives the wz codec round-trip, which is the property a peer
    /// actually depends on: the decoder must not silently swallow the chain and
    /// hand the body back as if the Declare had carried nothing.
    #[test]
    fn the_qos_ext_survives_the_wire_round_trip() {
        use sce_forge_runtime::codec::SceCursor;
        use wz_codecs::declare::Declare;
        use wz_codecs_test_support::TestWire;

        let d = build_declare_subscriber(9, 0, Some("demo/sub")).expect("build");
        let bytes = d.wire();
        let mut cursor = SceCursor::new(&bytes);
        let decoded = Declare::decode(&mut cursor)
            .and_then(|x| x.try_into_owned())
            .expect("decode declare");
        assert_eq!(read_declare_qos(&decoded), QOS_DECLARE);
        assert!(matches!(
            decoded.body,
            wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclSubscriber(_)
        ));
    }
}

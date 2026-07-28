// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y435 — the handshake-negotiated capability SET as one value, with the
//! qos/lowlatency exclusivity made unrepresentable.
//!
//! ## Why this type exists
//!
//! zenoh models the negotiable transport surface as independent booleans spread
//! over two structs — `TransportConfigUnicast::{is_qos, shm, is_lowlatency}` and
//! `TransportLinkUnicastConfig::batch.is_compression`, all four landing
//! independently at `io/zenoh-transport/src/unicast/establishment/open.rs:681`,
//! `:685`, `:689`, `:701`. Three of the four genuinely compose. The fourth pair
//! does not: `io/zenoh-transport/src/unicast/manager.rs:264-265` bails with
//! `'qos' and 'lowlatency' options are incompatible` when both are set, and
//! upstream has a dedicated test for that failure
//! (`io/zenoh-transport/tests/unicast_transport.rs:1534`).
//!
//! So upstream the constraint is real but only enforced at RUNTIME, at manager
//! build, as a string error. zenoh-pico is narrower still: it negotiates no
//! `ext_qos` on unicast at all, so the pair cannot arise there for lack of one
//! half rather than by design.
//!
//! wz enforces the same constraint one layer earlier and one degree harder: the
//! exclusive pair is ONE field with three states, so the both-on configuration
//! cannot be constructed — there is no value of [`TransportMode`] that means
//! "qos and lowlatency". A misconfiguration zenoh discovers by running, wz
//! rejects by not compiling. That is the wz superset direction (a stricter
//! encoding of the SAME upstream rule), not a behavioural divergence: for every
//! configuration zenoh accepts, [`SessionOffer`] has exactly one representation.
//!
//! ## Why the orthogonal capabilities stay booleans
//!
//! `compression` and `shm` are NOT part of the exclusive choice, because
//! upstream composes them freely and its own test matrix proves it — the lean
//! transport maps SHM on both directions
//! (`unicast/lowlatency/tx.rs:31-36`, `unicast/lowlatency/rx.rs:37-45`) and
//! zenoh's SHM suite runs the lowlatency arm explicitly
//! (`io/zenoh-transport/tests/unicast_shm.rs:170`). Folding them into the enum
//! would forbid compositions zenoh supports, which is the opposite failure from
//! the one this module fixes. R311y435's audit read all four pairs against the
//! upstream composed data path; only qos x lowlatency diverged.
//!
//! ## What this replaces
//!
//! The granular `SessionLinkActions::set_qos_offer` /
//! `set_lowlatency_offer` setters remain (signature stability), and they keep
//! their refuse-the-second-offer guards for callers that stage one capability at
//! a time. But those guards are ORDER-DEPENDENT — first-staged wins — where
//! zenoh's check is symmetric and total. Routing every deploy-facing open
//! through [`SessionOffer`] means no production path can observe that order
//! dependence, because no production path can express the both-on input.

/// The EXCLUSIVE transport-mode choice for one session.
///
/// Exactly one of the three states holds at a time, which is what makes the
/// zenoh `manager.rs:264` conflict unrepresentable rather than merely rejected.
/// [`Universal`](Self::Universal) is the default and is byte-identical on the
/// wire to a session that never heard of either capability: it offers neither
/// establishment ext.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TransportMode {
    /// Neither ext offered — zenoh's default unicast transport, one conduit,
    /// Frame(sn)-wrapped data. The only mode every wz build can provide.
    #[default]
    Universal,
    /// Offer `ext_qos` (unit ext 0x1) — per-(priority, reliability) SN conduits
    /// and a Frame `ext_qos` on non-DEFAULT traffic. zenoh
    /// `TransportConfigUnicast::is_qos` (`open.rs:681`). Needs `transport-qos`.
    Qos,
    /// Offer `Z_EXT_LOWLATENCY` (unit ext 0x5) — the lean data path with no
    /// Frame envelope, no SN, no fragmentation and no batching. zenoh
    /// `TransportConfigUnicast::is_lowlatency` (`open.rs:689`). Needs
    /// `transport-lowlatency`.
    LowLatency,
}

impl TransportMode {
    /// The cargo feature this mode needs, or `None` for
    /// [`Universal`](Self::Universal) which every build provides.
    #[must_use]
    pub const fn required_feature(self) -> Option<&'static str> {
        match self {
            Self::Universal => None,
            Self::Qos => Some("transport-qos"),
            Self::LowLatency => Some("transport-lowlatency"),
        }
    }
}

/// A requested capability whose cargo feature this build does not carry.
///
/// Returned rather than silently dropped, and it covers the ORTHOGONAL
/// capabilities as well as the mode. Dropping either kind would be the same
/// defect: a caller that asked for the lean path, or for compression, and got a
/// session without it has shipped a wire form it did not configure and will find
/// out by packet capture. zenoh has no equivalent error because its capabilities
/// are always compiled in — this is the honest half of wz's compile-time feature
/// elision, which is what buys the slim MCU builds zenoh cannot produce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedCapability {
    /// What was asked for, e.g. `"TransportMode::Qos"` or `"compression"`.
    pub capability: &'static str,
    /// The cargo feature that would provide it, e.g. `"transport-qos"`.
    pub feature: &'static str,
}

impl core::fmt::Display for UnsupportedCapability {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} needs the `{}` cargo feature, which this build does not carry",
            self.capability, self.feature
        )
    }
}

/// The complete set of capabilities one session OFFERS at the handshake.
///
/// Scope is deliberately the handshake-negotiated surface only. Namespace, auth
/// dispatch and multilink are excluded because they are not negotiated the same
/// way: namespace is a unilateral local decorator on the post-Established data
/// plane, auth is a dispatch install, multilink carries its own 0x4 ext chain.
/// Mixing them in would make this type a grab bag rather than the SSOT for
/// "which capability exts does the InitSyn carry".
///
/// Construct with [`Self::universal`] and the `with_*` builders; every
/// combination that type-checks is one zenoh also accepts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SessionOffer {
    /// The exclusive mode. See [`TransportMode`].
    pub mode: TransportMode,
    /// Offer `Z_EXT_COMPRESSION` (unit ext 0x6). Composes with every mode: on
    /// [`TransportMode::LowLatency`] the ext is still negotiated but the lz4
    /// wrap is suppressed, because upstream's lean tx never touches `WBatch`
    /// (`unicast/lowlatency/link.rs:33-73`) — R311y434.
    pub compression: bool,
    /// Offer the SHM establishment ext (0x2). Composes with every mode:
    /// upstream maps SHM on the lean path in both directions
    /// (`unicast/lowlatency/tx.rs:33`, `rx.rs:40`).
    pub shm: bool,
}

impl SessionOffer {
    /// The zero offer: universal transport, no capability ext. Byte-identical
    /// on the wire to a pre-capability wz session.
    #[must_use]
    pub const fn universal() -> Self {
        Self {
            mode: TransportMode::Universal,
            compression: false,
            shm: false,
        }
    }

    /// Select the exclusive transport mode. Replacing rather than accumulating
    /// is the point: this is the call that cannot express the zenoh
    /// `manager.rs:264` conflict.
    #[must_use]
    pub const fn with_mode(mut self, mode: TransportMode) -> Self {
        self.mode = mode;
        self
    }

    /// Offer the lz4 batch compression ext.
    #[must_use]
    pub const fn with_compression(mut self, compression: bool) -> Self {
        self.compression = compression;
        self
    }

    /// Offer the SHM establishment ext.
    #[must_use]
    pub const fn with_shm(mut self, shm: bool) -> Self {
        self.shm = shm;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_offer_is_the_zero_offer() {
        assert_eq!(SessionOffer::default(), SessionOffer::universal());
        assert_eq!(TransportMode::default(), TransportMode::Universal);
    }

    /// The whole point of the type: selecting a mode REPLACES, so no builder
    /// chain reaches a state carrying both Qos and LowLatency. This is the
    /// compile-time analogue of zenoh's runtime `manager.rs:264` bail.
    #[test]
    fn selecting_a_mode_replaces_rather_than_accumulates() {
        let offer = SessionOffer::universal()
            .with_mode(TransportMode::Qos)
            .with_mode(TransportMode::LowLatency);
        assert_eq!(offer.mode, TransportMode::LowLatency);

        let offer = SessionOffer::universal()
            .with_mode(TransportMode::LowLatency)
            .with_mode(TransportMode::Qos);
        assert_eq!(offer.mode, TransportMode::Qos);
    }

    /// The orthogonal capabilities compose with EVERY mode — the audit result
    /// this type must not accidentally forbid.
    #[test]
    fn the_orthogonal_capabilities_compose_with_every_mode() {
        for mode in [
            TransportMode::Universal,
            TransportMode::Qos,
            TransportMode::LowLatency,
        ] {
            let offer = SessionOffer::universal()
                .with_mode(mode)
                .with_compression(true)
                .with_shm(true);
            assert_eq!(offer.mode, mode);
            assert!(offer.compression && offer.shm);
        }
    }

    #[test]
    fn every_non_universal_mode_names_a_cargo_feature() {
        assert_eq!(TransportMode::Universal.required_feature(), None);
        assert_eq!(TransportMode::Qos.required_feature(), Some("transport-qos"));
        assert_eq!(
            TransportMode::LowLatency.required_feature(),
            Some("transport-lowlatency")
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn the_unsupported_capability_error_names_the_missing_feature() {
        use alloc::string::ToString;

        let msg = UnsupportedCapability {
            capability: "TransportMode::Qos",
            feature: "transport-qos",
        }
        .to_string();
        assert!(msg.contains("transport-qos"), "{msg}");
        assert!(msg.contains("TransportMode::Qos"), "{msg}");
    }
}

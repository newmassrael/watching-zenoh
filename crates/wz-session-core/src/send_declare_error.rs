// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Typed reject surface for the outbound DECLARE-side gate
//! ([`SessionLinkActions::send_declare_keyexpr`] /
//! `_subscriber` / `_queryable` / `_token`).
//!
//! R300 — guards against (a) malformed keyexprs (structural canon
//! violations) and (b) zenoh-pico bug #3 SIGABRT patterns (R299
//! fixture). The gate runs BEFORE any wire bytes are produced or any
//! outbound-mapping-table side effect — every variant is a no-emit
//! reject (the session-link state is unchanged on Err).
//!
//! Lives in wz-session-core because both the SessionLinkActions
//! method signatures (in wz-runtime-tokio session_glue.rs) and the
//! application-level error projection (Session::declare_* error
//! types) need to reference the same enum without dragging tokio.

use core::fmt;

use sce_forge_runtime::codec::CodecError;

use crate::keyexpr_canon::OutboundKeyexprError;

/// R300 — typed reject from the outbound DECLARE-side gate that
/// guards against (a) malformed keyexprs and (b) zenoh-pico bug #3
/// SIGABRT patterns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendDeclareError {
    /// The reconstructed keyexpr (resolved from `(mapping_id,
    /// suffix)` via the outbound mapping table) failed the
    /// pico-safety check.
    Keyexpr(OutboundKeyexprError),
    /// `send_declare_keyexpr(mapping_id = 0, ..)` — the keyexpr
    /// mapping id space reserves `0` for "literal" indication on
    /// the subscriber / queryable / token side, so registering a
    /// new mapping AT id 0 has no wire interpretation.
    ReservedMappingIdZero,
    /// `send_declare_subscriber` / `_queryable` / `_token` was
    /// called with a `mapping_id != 0` that has no entry in the
    /// outbound mapping table.
    UnknownMappingId(u64),
    /// `send_declare_subscriber` / `_queryable` / `_token` was
    /// called with `mapping_id == 0` AND `keyexpr_suffix == None`
    /// — no keyexpr at all.
    MissingKeyexpr,
    /// W3 (SCE pin 7a94d084a) — the keyexpr suffix exceeded the
    /// declared bounded-codec capacity (`MAX_KEYEXPR_BYTES`) while
    /// copying the caller string into the no-alloc owned mirror, so
    /// the DECLARE could not be assembled. Same bound the decode
    /// path enforces; a no-emit reject (no wire bytes left).
    Codec(CodecError),
    /// R311g1 — the matching `declare-*` Cargo feature is OFF in
    /// this build, so the wire emit path is elided. The
    /// `SessionLinkActions` method signature stays stable
    /// regardless of feature configuration (per
    /// `feedback_signature_stability`); the caller observes the
    /// build-time choice as an honest runtime reject.
    ///
    /// Variant ordering: appended at end so existing match arms
    /// in downstream crates surface a non-exhaustive-match
    /// warning (when applicable) rather than silently rebind a
    /// prior variant.
    FeatureDisabled,
}

impl fmt::Display for SendDeclareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keyexpr(e) => write!(f, "send_declare: {e}"),
            Self::ReservedMappingIdZero => f.write_str(
                "send_declare_keyexpr: mapping_id 0 is reserved \
                 (cannot register a new keyexpr mapping at id 0)",
            ),
            Self::UnknownMappingId(id) => write!(
                f,
                "send_declare: mapping_id {id} has no outbound entry \
                 (no preceding send_declare_keyexpr for this id, \
                 or it was undeclared before this call)"
            ),
            Self::MissingKeyexpr => f.write_str(
                "send_declare: mapping_id 0 requires a literal keyexpr \
                 suffix (received None)",
            ),
            Self::Codec(e) => write!(
                f,
                "send_declare: keyexpr suffix exceeded bounded-codec \
                 capacity while building owned mirror: {e:?}"
            ),
            Self::FeatureDisabled => f.write_str(
                "send_declare: matching declare-* Cargo feature is OFF \
                 in this build; wire emit elided (signature-stability \
                 contract — caller observes build-time choice as \
                 runtime reject)",
            ),
        }
    }
}

impl core::error::Error for SendDeclareError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Keyexpr(e) => Some(e),
            _ => None,
        }
    }
}

impl From<OutboundKeyexprError> for SendDeclareError {
    fn from(e: OutboundKeyexprError) -> Self {
        Self::Keyexpr(e)
    }
}

impl From<CodecError> for SendDeclareError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

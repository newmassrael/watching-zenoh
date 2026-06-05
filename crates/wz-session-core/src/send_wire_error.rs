// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Typed reject surface for the outbound payload / keyexpr-carrying
//! wire-emit actions that are NOT the DECLARE family —
//! [`SessionLinkActions::send_push_literal`] / `_aliased` /
//! `send_push_del_*` / `send_push_with_meta_*` (publish),
//! `send_request_query` / `_with_meta` (query), and
//! `send_interest_liveliness_subscriber` (interest).
//!
//! These three families share exactly one failure model — a build
//! that elides the codec (`FeatureDisabled`) or caller data that
//! overflows the declared bounded-codec capacity (`Codec`) — so they
//! share one error type rather than three identical ones. The DECLARE
//! family keeps its own richer [`crate::send_declare_error::SendDeclareError`]
//! because it additionally pre-checks the outbound mapping table and
//! keyexpr pico-safety (failure modes these actions do not have).
//!
//! Distinct from `SendDeclareError` (ISP): a publish/query/interest
//! caller never observes `Keyexpr` / `ReservedMappingIdZero` /
//! `UnknownMappingId` / `MissingKeyexpr`, so those variants are not in
//! scope here.

use core::fmt;

use sce_forge_runtime::codec::CodecError;

/// W3 (SCE pin 7a94d084a) — typed reject from an outbound
/// payload/keyexpr-carrying wire-emit action. Every variant is a
/// no-emit reject (no wire bytes leave on `Err`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendWireError {
    /// The caller data (payload / keyexpr suffix) exceeded the
    /// declared bounded-codec capacity while copying into the
    /// no-alloc owned mirror — the same bound the decode path
    /// enforces. The wrapped [`CodecError`] is the codec-level cause.
    Codec(CodecError),
    /// R311g1 signature-stability — the matching `codec-*` /
    /// `declare-*` Cargo feature is OFF in this build, so the wire
    /// emit path is elided. The `SessionLinkActions` method signature
    /// stays stable regardless of feature configuration (per
    /// `feedback_signature_stability`); the caller observes the
    /// build-time choice as an honest runtime reject rather than a
    /// missing symbol or a falsely-`Ok` no-op.
    ///
    /// Variant ordering: appended at end so existing match arms in
    /// downstream crates surface a non-exhaustive-match warning rather
    /// than silently rebind a prior variant.
    FeatureDisabled,
}

impl fmt::Display for SendWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(e) => write!(
                f,
                "send_wire: caller data exceeded bounded-codec capacity \
                 while building owned mirror: {e:?}"
            ),
            Self::FeatureDisabled => f.write_str(
                "send_wire: matching codec-* Cargo feature is OFF in this \
                 build; wire emit elided (signature-stability contract — \
                 caller observes build-time choice as runtime reject)",
            ),
        }
    }
}

impl core::error::Error for SendWireError {}

impl From<CodecError> for SendWireError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

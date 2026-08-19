// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Inbound-parse error surface and the ext-chain depth ceiling.
//!
//! Both are precursor types for the session_glue dispatch cluster
//! (NetworkMessage / DriverLoopOutcome / IterationEvent), which will
//! land in subsequent rounds. Extracted first because InboundParseError
//! is the smallest type with the most external coupling
//! (`sce_forge_runtime::CodecError`), so isolating it validates the
//! dep wiring before the bigger cluster moves.

use core::fmt;

use sce_forge_runtime::codec::CodecError;

/// Error surface for `parse_inbound`. Distinct from `CodecError` so
/// callers can react to "empty wire" (link delivered a zero-byte
/// frame, programming error) without conflating it with codec-level
/// `NeedMoreBytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundParseError {
    /// The frame was zero bytes — no transport-message header to
    /// dispatch on.
    Empty,
    /// The body codec rejected the wire (truncated, VLE overflow,
    /// etc.).
    Codec(CodecError),
    /// R68c — the transport header set the Z flag but the trailing
    /// ext chain exceeded `MAX_EXT_CHAIN_DEPTH` without surfacing a
    /// chain-terminator entry (Z bit clear). Mirrors
    /// `ext_envelope.scxml::on-overflow="reject"` so a malformed
    /// peer cannot pin the decoder into an unbounded loop.
    ExtChainOverflow,
    /// The header selected a body encoding the wire spec RESERVES, so the
    /// message has no shape to read and no length to skip.
    ///
    /// Raised by `parse_inbound`'s transport-OAM arm for `iext::ENC_MASK ==
    /// 0b11`, which zenoh's own decoder answers with `DidntRead`
    /// (`zenoh-codec/src/transport/oam.rs`). Distinct from [`Self::Codec`]
    /// because nothing about the wire is TRUNCATED or malformed at the byte
    /// level — the bytes are well-formed and the SPEC declines to say what
    /// they mean, which is a different thing for a reader to report.
    ReservedEncoding,
    /// transport-compression — a compression-negotiated batch could not be
    /// lz4-decompressed (empty wire, a corrupt lz4 block, or a blob that would
    /// expand past the negotiated mtu bound — the decompression-bomb guard).
    /// The session tears down (framing error) rather than trusting the peer.
    #[cfg(feature = "transport-compression")]
    CompressionFailed,
}

impl fmt::Display for InboundParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "inbound frame was empty (no transport header)"),
            Self::Codec(e) => write!(f, "inbound body codec rejected wire: {:?}", e),
            Self::ExtChainOverflow => write!(
                f,
                "inbound ext chain exceeded MAX_EXT_CHAIN_DEPTH={} without terminator",
                MAX_EXT_CHAIN_DEPTH
            ),
            Self::ReservedEncoding => {
                write!(f, "inbound header selected a reserved body encoding")
            }
            #[cfg(feature = "transport-compression")]
            Self::CompressionFailed => {
                write!(f, "inbound compressed batch failed lz4 decompression")
            }
        }
    }
}

/// R68c — upper bound on ext-chain entries decoded per inbound
/// frame. Mirrors `ext_envelope.scxml::max-depth="8"` so the wz
/// inbound decoder fails closed on the same chain length zenoh-pico
/// would already reject. Production deploys with a higher ceiling
/// would have to bump this AND `ext_envelope.scxml` together.
pub const MAX_EXT_CHAIN_DEPTH: usize = 8;

impl core::error::Error for InboundParseError {}

impl From<CodecError> for InboundParseError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

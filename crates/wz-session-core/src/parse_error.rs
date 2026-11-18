// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Inbound-parse error surface.
//!
//! A precursor type for the session_glue dispatch cluster
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
    /// A received handshake chain repeats an extension a `session-slot`
    /// build reads, past the one entry per extension such a build holds.
    ///
    /// The length of a chain is not refused: a chain is read to the entry
    /// whose `Z` flag is clear, as zenoh's reader
    /// (`commons/zenoh-codec/src/transport/init.rs` @ `while has_ext {`) and
    /// zenoh-pico's (`vendor/zenoh-pico/src/protocol/codec/ext.c` @
    /// `while (has_next && ret == _Z_RES_OK) {`) both read it, and an entry no
    /// build reads is judged by its header and not kept. A chain that never
    /// terminates runs into the end of its frame and is refused as a
    /// truncated wire ([`Self::Codec`]).
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
    // Ungated: the passive observer reports an lz4 batch it could
    // not open in EVERY build, including one with no lz4 at all.
    CompressionFailed,
    /// R2437 — an ext chain carried an extension wz does not recognise on that
    /// message with the M (mandatory) bit SET.
    ///
    /// The wire spec's whole point in giving each extension an M bit is that
    /// the sender declares whether a receiver may proceed without understanding
    /// it, and upstream enforces exactly that: its unknown-extension reader logs
    /// and continues for M clear, and returns `DidntRead` for M set
    /// (`commons/zenoh-codec/src/common/extension.rs` @ `if u.is_mandatory()`).
    /// Until this round wz read the M bit nowhere in production — measured, the
    /// only three readers in the tree were assertions inside one integration
    /// test — so wz completed a handshake on terms it had not understood, which
    /// is the one outcome the bit exists to prevent.
    ///
    /// Distinct from [`Self::Codec`] for the reason [`Self::ReservedEncoding`]
    /// is: nothing here is truncated or malformed. The bytes parse, and the
    /// SENDER has said they may not be ignored.
    UnknownMandatoryExt {
        /// The unrecognised extension's IDENTITY (its header without the chain
        /// flag), so a refusal names what it refused: the id alone could not tell
        /// the unknown mandatory `0x58` from the region name `0x48`.
        eid: u8,
    },
    /// An ext chain carried an entry whose encoding is the reserved `0b11`.
    ///
    /// zenoh 1.10.2 refuses the whole message on it, mandatory or not: the
    /// reader of an undeclared extension fails on the encoding before it asks
    /// the `M` bit (`commons/zenoh-codec/src/common/extension.rs` @
    /// `let body = match self.header & iext::ENC_MASK {`). The chain decode
    /// reads it as a unit so that an analyzer still sees it; this is the
    /// participant's refusal (`crate::ext_admit::ExtAdmission::ReservedEncoding`).
    /// Distinct from [`Self::ReservedEncoding`], which is a MESSAGE body's
    /// encoding and carries no extension identity.
    ReservedExtEncoding {
        /// The entry's identity (its header without the chain flag).
        eid: u8,
    },
    /// The message announced a protocol version other than
    /// [`wz_codecs::wire_const::PROTOCOL_VERSION`], so the rest of its body is
    /// laid out by a protocol this reader does not implement.
    ///
    /// Raised by the passive reader alone, for the four messages that carry a
    /// version (Init, Join, Scout, Hello). A participant's own decode keeps
    /// upstream's order, which decodes the body and leaves the refusal to the
    /// handshake. An observer has no handshake to leave it to, and a body read
    /// past a foreign version byte is the reading that turns arbitrary bytes into
    /// a node with a zid and a role.
    ForeignVersion {
        /// The version byte the message announced.
        version: u8,
    },
    /// The message names a zid that is no zid: its bytes are all zero, or its
    /// length is outside `1..=16`.
    ///
    /// zenoh's decoder reads a zid's bytes and then refuses the id they spell
    /// when it is not a non-zero `u128` of at most sixteen bytes
    /// (`commons/zenoh-codec/src/core/zenohid.rs` @
    /// `ZenohIdProto::try_from(&id[..size]).map_err(|_| DidntRead)`), so the
    /// message is refused whole, as a malformed one is. Distinct from
    /// [`Self::Codec`]: the bytes are well-formed and the value they spell is
    /// the one no node has.
    InvalidZid(crate::session_zid::ZidError),
}

impl fmt::Display for InboundParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "inbound frame was empty (no transport header)"),
            Self::Codec(e) => write!(f, "inbound body codec rejected wire: {:?}", e),
            Self::ExtChainOverflow => write!(
                f,
                "inbound handshake ext chain repeats an extension past the one entry held for it"
            ),
            Self::ReservedEncoding => {
                write!(f, "inbound header selected a reserved body encoding")
            }
            Self::CompressionFailed => {
                write!(f, "inbound compressed batch failed lz4 decompression")
            }
            Self::UnknownMandatoryExt { eid } => write!(
                f,
                "inbound ext {:#04x} is unknown and MANDATORY (M bit set)",
                eid
            ),
            Self::ReservedExtEncoding { eid } => {
                write!(f, "inbound ext {:#04x} has the reserved encoding 0b11", eid)
            }
            Self::ForeignVersion { version } => write!(
                f,
                "inbound message announces protocol version {:#04x}; this reader reads {:#04x}",
                version,
                wz_codecs::wire_const::PROTOCOL_VERSION
            ),
            Self::InvalidZid(why) => write!(f, "inbound message names no zid: {why}"),
        }
    }
}

impl core::error::Error for InboundParseError {}

impl From<CodecError> for InboundParseError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

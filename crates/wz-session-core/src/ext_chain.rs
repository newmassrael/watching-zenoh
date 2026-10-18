// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the transport-message extension CHAIN codec — the Z-flag-gated list
//! of `ExtEntry` records that trails an Init / Open / Close / KeepAlive / Frame
//! body, and (nested) the per-method sub-ext chain INSIDE the Z_EXT_AUTH ext.
//!
//! One encode / decode pair so the outbound establishment path
//! (`handshake_encode`), the inbound parser (`inbound`), and the extauth
//! dispatch (`auth_dispatch`, the auth ext's inner method chain) share one
//! definition of the Z-bit continuation loop rather than each re-deriving it.
//! Each function is gated on the union of its consumers' features so a subset
//! that needs only one half does not drag the other in (and never trips
//! dead-code under `-D warnings`).

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use wz_codecs::ext_entry::ExtEntryOwned;

/// How many extension entries a session can have staged on ONE of its four
/// handshake chains at once, derived from what this build can stage.
///
/// Every stager replaces an entry by its extension id before it adds one (the
/// `retain` then `push` of `stage_capability`, the replace-in-place of the patch
/// stager), so a chain holds at most one entry per kind of extension the build
/// can stage. The kinds are counted from the features that stage them: the patch
/// level, the region name and the remote bound are staged by every build that
/// has the handshake; the rest each by the feature that owns them. Capacity for
/// one more than the count is not kept: an entry that would not fit is a
/// stager that skipped its replace, and `ExtChainBuf::push` says so.
#[cfg(all(feature = "session-slot", feature = "session-unicast"))]
pub const STAGED_EXT_KINDS: usize = 3
    + cfg!(feature = "transport-qos") as usize
    + cfg!(feature = "transport-lowlatency") as usize
    + cfg!(feature = "session-extcompression") as usize
    + cfg!(feature = "session-extshm") as usize
    + cfg!(feature = "session-extauth") as usize
    + cfg!(feature = "transport-multilink") as usize;

/// One handshake ext chain as a session stages it: the growable `Vec` of every
/// profile but `session-slot`, and under it an array of `STAGED_EXT_KINDS`
/// entries held in the session's own storage (fixed-memory step S5).
///
/// The fixed form has exactly the operations the stagers use on the vector
/// (`push`, `retain`, indexing, iteration, `Default` for the take-and-put-back
/// of the lend-only handshake), so a stager is written once.
#[cfg(all(not(feature = "session-slot"), feature = "session-unicast"))]
pub type ExtChainBuf = Vec<ExtEntryOwned>;

/// See the growable form of this alias.
#[cfg(all(feature = "session-slot", feature = "session-unicast"))]
#[derive(Debug, Clone, Default)]
pub struct ExtChainBuf(heapless::Vec<ExtEntryOwned, STAGED_EXT_KINDS>);

// Which of these a build uses depends on which extensions it can stage.
#[cfg(all(feature = "session-slot", feature = "session-unicast"))]
#[allow(dead_code)]
impl ExtChainBuf {
    /// A chain of exactly `entry`.
    pub fn one(entry: ExtEntryOwned) -> Self {
        let mut chain = Self::default();
        chain.push(entry);
        chain
    }

    /// Append `entry`. The chain holds one entry per kind of extension the
    /// build stages (`STAGED_EXT_KINDS`), so this fits whenever the stager
    /// replaced the entry of its own id first, as every stager does; one that
    /// did not is a defect in the stager, and failing here names it rather than
    /// dropping an entry the peer was owed.
    pub fn push(&mut self, entry: ExtEntryOwned) {
        if self.0.push(entry).is_err() {
            panic!("a handshake ext chain holds one entry per staged extension kind");
        }
    }

    /// Keep only the entries `keep` accepts, in order.
    pub fn retain<F: FnMut(&ExtEntryOwned) -> bool>(&mut self, keep: F) {
        self.0.retain(keep);
    }

    /// Remove and return the entry at `at`, keeping the order of the rest.
    pub fn remove(&mut self, at: usize) -> ExtEntryOwned {
        self.0.remove(at)
    }
}

#[cfg(all(feature = "session-slot", feature = "session-unicast"))]
impl core::ops::Deref for ExtChainBuf {
    type Target = [ExtEntryOwned];

    fn deref(&self) -> &[ExtEntryOwned] {
        self.0.as_slice()
    }
}

#[cfg(all(feature = "session-slot", feature = "session-unicast"))]
impl core::ops::DerefMut for ExtChainBuf {
    fn deref_mut(&mut self) -> &mut [ExtEntryOwned] {
        self.0.as_mut_slice()
    }
}

/// The extension chain a received handshake message (INIT, OPEN, CLOSE,
/// KEEP_ALIVE) carries, as the decoder hands it over: a growable `Vec` on every
/// profile but `session-slot`, and under it an array of the decoder's own bound
/// (`MAX_EXT_CHAIN_DEPTH` entries), so reading a chain allocates nothing for
/// the chain itself. Both are read as `[ExtEntryOwned]`.
#[cfg(not(feature = "session-slot"))]
pub type ExtChainOwned = Vec<ExtEntryOwned>;
/// See the growable form of this alias.
#[cfg(feature = "session-slot")]
pub type ExtChainOwned = heapless::Vec<ExtEntryOwned, { crate::parse_error::MAX_EXT_CHAIN_DEPTH }>;

/// [`decode_ext_chain`] into the form a received handshake message holds its
/// chain in ([`ExtChainOwned`]).
///
/// An entry's own body is a separate matter: an owned entry carries its bytes
/// in the SCE default storage, so an extension whose body is a byte string (the
/// region name, an auth or SHM challenge) still owns a heap copy of it; the
/// entries a wz peer's handshake carries (the patch level, the unit and integer
/// capability offers) own nothing.
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive"
))]
pub(crate) fn decode_handshake_ext_chain(
    cursor: &mut sce_forge_runtime::codec::SceCursor<'_>,
) -> Result<ExtChainOwned, crate::parse_error::InboundParseError> {
    #[cfg(not(feature = "session-slot"))]
    {
        decode_ext_chain(cursor)
    }
    #[cfg(feature = "session-slot")]
    {
        use crate::parse_error::{InboundParseError, MAX_EXT_CHAIN_DEPTH};
        use wz_codecs::ext_entry::ExtEntry;

        let mut entries = ExtChainOwned::new();
        for _ in 0..MAX_EXT_CHAIN_DEPTH {
            let entry = ExtEntry::decode(cursor).map_err(InboundParseError::Codec)?;
            let z = entry.z();
            let owned = entry.try_into_owned().map_err(InboundParseError::Codec)?;
            // Cannot overflow: the loop's bound is the array's.
            if entries.push(owned).is_err() {
                return Err(InboundParseError::ExtChainOverflow);
            }
            if !z {
                return Ok(entries);
            }
        }
        Err(InboundParseError::ExtChainOverflow)
    }
}

/// A chain of exactly `entry`, in whichever form this profile stages it.
#[cfg(feature = "session-unicast")]
pub(crate) fn ext_chain_of(entry: ExtEntryOwned) -> ExtChainBuf {
    #[cfg(not(feature = "session-slot"))]
    {
        alloc::vec![entry]
    }
    #[cfg(feature = "session-slot")]
    {
        ExtChainBuf::one(entry)
    }
}

/// The `max-depth` every entry-flag ext chain in the network and zenoh-payload
/// layers is generated with (`sources/codecs/*.scxml`).
///
/// R311y582 — this constant exists because the hand-written walker in
/// [`crate::dissect`] has to be told the bound the generated decode gets from
/// its container type, and it was told fourteen times, as the literal `4`. One
/// fact reachable by two paths always drifts (this workspace has paid for that
/// four times in one session before), and here the drift would be silent in the
/// worst way: a walker whose bound is LOWER than the codec's rejects wire the
/// codec accepts, and one whose bound is HIGHER walks into bytes the codec
/// never read.
///
/// It is not derived from the generated type because a const generic parameter
/// has no name to import. What closes the loop instead is
/// `the_generated_chain_capacities_match_the_constants` in [`crate::dissect`],
/// which asks each generated container for its own `capacity()` — so a
/// regenerated codec with a different depth reds a test rather than silently
/// disagreeing with the walker.
// Callers, exactly: the `dissect` walkers, and this crate's own
// chain-saturation tests — which live in `network_message` behind
// `all(test, codec-frame, codec-push)`.
//
// R311y588 — the gate was `any(dissect, test)`, and a full local sweep found
// the hole in SEVEN lanes: a `--lib` TEST build without `dissect` makes `test`
// true, so the constant compiles, while its only test-side consumer needs
// `codec-push` and is absent. Dead code under `-D warnings`. Third instance of
// the R311y579 (G7) class in one session, and the first one no per-crate check
// could have seen — every arm run by hand had either `dissect` or `codec-push`
// in it.
#[cfg(any(
    feature = "dissect",
    all(test, feature = "codec-frame", feature = "codec-push")
))]
pub const NETWORK_EXT_CHAIN_DEPTH: usize = 8;

/// `Query`'s chain has a depth of its own, a number the SCXML declares apart from
/// the network messages'. Separate constant rather than a second use of
/// [`NETWORK_EXT_CHAIN_DEPTH`]: they are declared in different documents for
/// different reasons, and collapsing them would make a future divergence
/// invisible. Until R3046 the chain also read to the end of the frame where the
/// others stop at the entry whose Z flag is clear; it stops there now.
#[cfg(feature = "dissect")]
pub const QUERY_EXT_CHAIN_DEPTH: usize = 8;

/// Encode an ext chain to bytes: each entry's `ExtEntry` encoding with the
/// chain-continuation Z bit (`0x80`) set on every entry but the last (Z clear =
/// terminator). An empty slice encodes to no bytes (the "no extensions" case).
/// The non-Z header bits (`ext_id`, `M`, `enc`) stay author-set; the helper
/// only patches the Z bit per chain position (`ExtEntry::encode` pushes the
/// header byte first).
///
/// The vector form: its consumers are the ones that want the chain as bytes of
/// their own (the auth ext's inner method chain, which is then wrapped in an
/// outer ext; the transport composer). The handshake encoders write their chain
/// straight after the body through [`encode_ext_chain_into`] and do not call
/// this.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "session-extauth",
        feature = "transport-compose",
        // The unit tests of `passive` (which builds the same wire from the same
        // entries) and of the lend-only chain writer below, under the feature sets
        // their own modules are compiled at.
        all(
            test,
            feature = "codec-init-body",
            feature = "codec-open-body",
            feature = "codec-close",
            feature = "codec-frame"
        ),
        all(
            test,
            feature = "tx-lend-only",
            any(feature = "codec-init-body", feature = "codec-open-body")
        )
    )
))]
pub(crate) fn encode_ext_chain(entries: &[ExtEntryOwned]) -> Vec<u8> {
    if entries.is_empty() {
        return Vec::new();
    }
    let mut buf = Vec::with_capacity(entries.len() * 4);
    encode_ext_chain_into(&mut buf, entries).expect("a Vec grows, so its sink is infallible");
    buf
}

/// [`encode_ext_chain`] into a buffer the caller chose: a heap `Vec` (what the
/// function above passes) or a link's lent slot, so a handshake message's chain
/// is written once, where the message is, and not into a vector of its own that
/// is then copied after the body.
///
/// The same bytes as the vector form, by construction: each entry is encoded
/// from its borrowed view with the chain-continuation bit set on its header
/// first, which is the byte the vector form patched after encoding it. A fixed
/// buffer that cannot hold the chain refuses with `BufferOverflow`; the bytes
/// already written stay, so the caller rolls back with
/// [`TxBuf::truncate`](crate::tx_buf::TxBuf::truncate) to the length it saw.
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "session-extauth"
))]
pub(crate) fn encode_ext_chain_into(
    buf: &mut crate::tx_buf::EncodeBuf<'_>,
    entries: &[ExtEntryOwned],
) -> Result<(), sce_forge_runtime::codec::CodecError> {
    let last = entries.len().wrapping_sub(1);
    for (i, entry) in entries.iter().enumerate() {
        let mut view = entry.as_borrowed();
        if i == last {
            view.header &= !0x80;
        } else {
            view.header |= 0x80;
        }
        view.encode(&mut crate::tx_buf::TxSink::new(&mut *buf))?;
    }
    Ok(())
}

/// Decode the Z-flag-gated ext chain into the lifetime-free owned mirror,
/// bounded by [`MAX_EXT_CHAIN_DEPTH`](crate::parse_error::MAX_EXT_CHAIN_DEPTH)
/// so a malformed peer cannot pin the decoder into an unbounded loop.
///
/// UNCONDITIONAL within this `alloc`-gated module since transport OAM joined
/// `parse_inbound`: that arm carries no `codec-*` gate, so every build that
/// compiles this module calls this function. The `any(codec-*)` union it used
/// to carry had to be grown twice by feature-SUBSET builds (R311y605,
/// R311y607) and each growth was a defect until it was found; there is no
/// longer a list to be short of.
///
/// The heap profile's form: it returns a growable `Vec`. The slot profile reads
/// its chain through [`decode_handshake_ext_chain`], into an array.
#[cfg(feature = "alloc")]
pub(crate) fn decode_ext_chain(
    cursor: &mut sce_forge_runtime::codec::SceCursor<'_>,
) -> Result<Vec<ExtEntryOwned>, crate::parse_error::InboundParseError> {
    use crate::parse_error::{InboundParseError, MAX_EXT_CHAIN_DEPTH};
    use wz_codecs::ext_entry::ExtEntry;

    let mut entries = Vec::new();
    for _ in 0..MAX_EXT_CHAIN_DEPTH {
        let entry = ExtEntry::decode(cursor).map_err(InboundParseError::Codec)?;
        let z = entry.z();
        // Deep-copy the borrowed decode view into the lifetime-free owned mirror
        // so the parsed chain can outlive the input buffer.
        entries.push(entry.try_into_owned().map_err(InboundParseError::Codec)?);
        if !z {
            return Ok(entries);
        }
    }
    Err(InboundParseError::ExtChainOverflow)
}

// Compiled only under the lend-only profile, whose handshake is the one that
// writes its chain through the `_into` form: the profile's own lib leg runs it.
#[cfg(all(
    test,
    feature = "alloc",
    feature = "tx-lend-only",
    any(feature = "codec-init-body", feature = "codec-open-body")
))]
mod tests {
    use super::*;
    use alloc::vec;

    /// Three entries with distinct headers and bodies, the first two with Z set
    /// by the encoder and the last with it cleared.
    fn chain() -> Vec<ExtEntryOwned> {
        use wz_codecs::ext_entry::ExtEntryOwnedVariant;
        let unit = |id: u8| ExtEntryOwned {
            header: id,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(wz_codecs::ext_unit::ExtUnit {}),
        };
        vec![crate::extpatch::encode_patch_ext(), unit(0x05), unit(0x01)]
    }

    /// The chain written straight into a buffer is the chain the vector form
    /// builds: each entry's header carries the continuation bit on all but the
    /// last, and the bytes are the entries' own. The lend-only handshake writes
    /// its chain through the `_into` form, and every other builder of a
    /// handshake message is held to this equality.
    #[test]
    fn a_chain_written_into_a_buffer_is_the_chain_the_vector_form_builds() {
        let entries = chain();
        let expected = encode_ext_chain(&entries);
        assert!(!expected.is_empty(), "three entries make bytes");

        // The fixed form needs a buffer type that is not the vector, which is
        // what the writers take only where a link can lend a slot.
        #[cfg(any(feature = "transport-tx-lend", not(feature = "alloc")))]
        {
            use crate::tx_buf::{SliceTxBuf, TxBuf};
            let mut storage = [0u8; 64];
            let mut fixed = SliceTxBuf::new(&mut storage);
            encode_ext_chain_into(&mut fixed, &entries).expect("the chain fits 64 bytes");
            assert_eq!(fixed.as_slice(), expected.as_slice());
        }

        let mut grown: Vec<u8> = Vec::new();
        encode_ext_chain_into(&mut grown, &entries).expect("a vector grows");
        assert_eq!(grown, expected);

        // The empty chain writes nothing, in both forms.
        assert!(encode_ext_chain(&[]).is_empty());
        let mut empty: Vec<u8> = Vec::new();
        encode_ext_chain_into(&mut empty, &[]).expect("nothing to write");
        assert!(empty.is_empty());
    }

    /// A buffer too short for the chain refuses it.
    #[cfg(any(feature = "transport-tx-lend", not(feature = "alloc")))]
    #[test]
    fn a_buffer_too_short_for_the_chain_refuses_it() {
        use crate::tx_buf::SliceTxBuf;
        let entries = chain();
        let mut storage = [0u8; 3];
        let mut fixed = SliceTxBuf::new(&mut storage);
        assert_eq!(
            encode_ext_chain_into(&mut fixed, &entries),
            Err(sce_forge_runtime::codec::CodecError::BufferOverflow)
        );
    }
}

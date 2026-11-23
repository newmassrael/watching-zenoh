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

use crate::transport_profile::ExtEntryOwned;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// How many extension entries a session can have staged on ONE of its four
/// handshake chains at once, derived from what this build can stage.
///
/// Every stager replaces an entry by its extension id before it adds one
/// (`stage_in_canonical_order`), so a chain holds at most one entry per kind
/// of extension the build can stage. The kinds are counted from the features that stage them: the patch
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

    /// Insert `entry` at `at`, shifting the rest up. The capacity argument is
    /// `push`'s: a stager that removed its own id first always has room.
    pub fn insert(&mut self, at: usize, entry: ExtEntryOwned) {
        if self.0.insert(at, entry).is_err() {
            panic!("a handshake ext chain holds one entry per staged extension kind");
        }
    }
}

/// Make `entry` the one entry of extension id `id` on a staged handshake chain,
/// or, for `None`, take every entry of that id off it.
///
/// The entry goes where upstream's encoder writes it. zenoh writes the Init and
/// Open chains field by field in ascending id order (qos / qos_link 0x1, shm
/// 0x2, auth 0x3, mlink 0x4, lowlatency 0x5, compression 0x6, patch or remote
/// bound 0x7, region name 0x8:
/// `commons/zenoh-codec/src/transport/init.rs` @ `// Extensions` and
/// `commons/zenoh-codec/src/transport/open.rs` @ `// Extensions`), so keeping
/// the chain sorted by id is what makes every wz encoder of it emit that order,
/// whichever stager ran first. Equal ids keep their arrival order; a chain has
/// at most one, since each id names one field of the message.
///
/// Removal keys on the 4-bit id field rather than the identity: the unit `QoS`
/// and the z64 `QoSLink` share id 0x1 and zenoh refuses to emit both, so a
/// re-stage of either form must replace the other.
#[cfg(feature = "session-unicast")]
pub(crate) fn stage_in_canonical_order(
    chain: &mut ExtChainBuf,
    id: u8,
    entry: Option<ExtEntryOwned>,
) {
    chain.retain(|e| e.ext_id() != id);
    if let Some(entry) = entry {
        debug_assert_eq!(entry.ext_id(), id, "a stager staged another id's entry");
        let at = canonical_position(chain, id);
        chain.insert(at, entry);
    }
}

/// Where an entry of id `id` belongs in `chain`: after every entry whose id is
/// not greater, so a stable insert leaves a sorted chain sorted.
#[cfg(feature = "session-unicast")]
fn canonical_position(chain: &[ExtEntryOwned], id: u8) -> usize {
    chain
        .iter()
        .position(|e| e.ext_id() > id)
        .unwrap_or(chain.len())
}

/// Put a chain handed over whole into the order
/// [`stage_in_canonical_order`] keeps, so a seeded chain and a staged one are
/// written alike. Stable, so entries of one id keep the order they came in.
#[cfg(all(not(feature = "session-slot"), feature = "session-unicast"))]
pub(crate) fn sort_into_canonical_order(chain: &mut ExtChainBuf) {
    chain.sort_by_key(|e| e.ext_id());
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
/// profile but `session-slot`, and under it `ReceivedExtChain`. Both are read as
/// `[ExtEntryOwned]` and judged through the crate's `ChainHeaders`.
#[cfg(not(feature = "session-slot"))]
pub type ExtChainOwned = Vec<ExtEntryOwned>;
/// See the growable form of this alias.
#[cfg(feature = "session-slot")]
pub type ExtChainOwned = ReceivedExtChain;

/// The header bytes the admission rule judges a message's extensions by
/// ([`crate::ext_admit::judge_ext_chain`]), in the chain's order: every entry's, where the chain
/// is kept whole, and the first entry the rule refuses, where it is not. The rule answers with
/// the first entry it refuses, so both judge alike.
// Named by `InboundFrame::ext_admission`'s `judge`, which the arms of the messages that carry a
// chain call: the handshake's four, and the heap profile's three more.
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive",
    all(feature = "alloc", feature = "codec-frame"),
    all(feature = "alloc", feature = "reassembly"),
    all(feature = "alloc", feature = "codec-join")
))]
pub(crate) trait ChainHeaders {
    /// The headers, the chain's last entry last.
    fn chain_headers(&self) -> impl Iterator<Item = u8> + '_;
}

#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-keep-alive",
        feature = "codec-frame",
        feature = "reassembly",
        feature = "codec-join"
    )
))]
impl ChainHeaders for [ExtEntryOwned] {
    fn chain_headers(&self) -> impl Iterator<Item = u8> + '_ {
        self.iter().map(|entry| entry.header)
    }
}

#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-keep-alive",
        feature = "codec-frame",
        feature = "reassembly",
        feature = "codec-join"
    )
))]
impl ChainHeaders for Vec<ExtEntryOwned> {
    fn chain_headers(&self) -> impl Iterator<Item = u8> + '_ {
        self.as_slice().chain_headers()
    }
}

/// How many entries of ONE received handshake message a `session-slot` build keeps: those of
/// the extensions it reads, which are the patch level, the region name and the remote bound, and
/// one for each extension a feature of the build reads.
#[cfg(feature = "session-slot")]
pub const RECEIVED_EXT_KINDS: usize = 3
    + (cfg!(feature = "transport-qos") || PASSIVE_READS_EVERY_OFFER) as usize
    + (cfg!(feature = "transport-lowlatency") || PASSIVE_READS_EVERY_OFFER) as usize
    + (cfg!(feature = "session-extcompression") || PASSIVE_READS_EVERY_OFFER) as usize
    + (cfg!(feature = "transport-shm") || PASSIVE_READS_EVERY_OFFER) as usize
    + (cfg!(feature = "session-extauth") || PASSIVE_READS_EVERY_OFFER) as usize
    + (cfg!(feature = "transport-multilink") || PASSIVE_READS_EVERY_OFFER) as usize;

/// Whether the build carries the passive tracker (`crate::passive`), which folds BOTH sides'
/// offers of every capability (qos, shm, auth, multilink, lowlatency, compression) whatever the
/// build negotiates itself, so it reads each of those extensions off a received chain. Its gate
/// is the module's.
#[cfg(feature = "session-slot")]
const PASSIVE_READS_EVERY_OFFER: bool = cfg!(all(
    feature = "alloc",
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-frame"
));

/// Whether this build reads the establishment extension `id` off a message a peer sent: the
/// extensions of the modules it compiles (`extpatch`, `extregion` and `extbound` always, the
/// others each behind the feature of its module, and all of them where the passive tracker is
/// built). An entry of any other id is not kept; it is judged by its header like the rest.
#[cfg(all(
    feature = "session-slot",
    any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-keep-alive"
    )
))]
const fn reads_received_ext(id: u8) -> bool {
    use crate::ext_header::establishment_ext_id as known;
    // `extbound`'s remote bound is the patch level's id (0x7), on the OPEN messages.
    id == known::PATCH
        || id == known::REGION_NAME
        || ((cfg!(feature = "transport-qos") || PASSIVE_READS_EVERY_OFFER) && id == known::QOS)
        || ((cfg!(feature = "transport-shm") || PASSIVE_READS_EVERY_OFFER) && id == known::SHM)
        || ((cfg!(feature = "session-extauth") || PASSIVE_READS_EVERY_OFFER) && id == known::AUTH)
        || ((cfg!(feature = "transport-multilink") || PASSIVE_READS_EVERY_OFFER)
            && id == known::MULTILINK)
        || ((cfg!(feature = "transport-lowlatency") || PASSIVE_READS_EVERY_OFFER)
            && id == known::LOWLATENCY)
        || ((cfg!(feature = "session-extcompression") || PASSIVE_READS_EVERY_OFFER)
            && id == known::COMPRESSION)
}

/// The extension chain of a received handshake message on `session-slot`: the entries of the
/// extensions this build reads ([`reads_received_ext`]), for the readers, which look an
/// extension up by its id, and the header of the first entry the admission rule refuses for the
/// message, which is all the rule's verdict depends on.
///
/// Its size does not depend on the chain's length, which the protocol does not bound: a chain
/// keeps one entry for each extension a build reads (three in the smallest) and one header.
#[cfg(feature = "session-slot")]
#[derive(Debug, Default)]
pub struct ReceivedExtChain {
    entries: heapless::Vec<ExtEntryOwned, RECEIVED_EXT_KINDS>,
    // Read by `ChainHeaders`, which a build with no message that carries a chain does not have.
    #[cfg(any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-keep-alive"
    ))]
    refused_header: Option<u8>,
}

#[cfg(feature = "session-slot")]
impl ReceivedExtChain {
    /// A chain with no entry.
    pub const fn new() -> Self {
        Self {
            entries: heapless::Vec::new(),
            #[cfg(any(
                feature = "codec-init-body",
                feature = "codec-open-body",
                feature = "codec-close",
                feature = "codec-keep-alive"
            ))]
            refused_header: None,
        }
    }
}

#[cfg(feature = "session-slot")]
impl core::ops::Deref for ReceivedExtChain {
    type Target = [ExtEntryOwned];

    fn deref(&self) -> &[ExtEntryOwned] {
        self.entries.as_slice()
    }
}

// Only a handshake message holds its chain in this form (the heap profile's three keep a `Vec`),
// so the refused header is kept, and read, where a handshake decoder is built.
#[cfg(all(
    feature = "session-slot",
    any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "codec-keep-alive"
    )
))]
impl ChainHeaders for ReceivedExtChain {
    fn chain_headers(&self) -> impl Iterator<Item = u8> + '_ {
        self.refused_header.into_iter()
    }
}

/// The chain of a received handshake message as its document read it
/// (`sources/codecs/transport_{init,open,close,keep_alive}.scxml`), into the form the
/// message holds it in ([`ExtChainOwned`]), and into a chain the caller already holds (empty,
/// as [`ExtChainOwned::new`] makes it): the caller builds the message the chain belongs to
/// first, so that the chain is filled where it will stay and is not a value of its own on the
/// way there. On an error the chain holds the entries taken so far, which the caller discards
/// with the message.
///
/// `walked` yields the entries of the document's view, in order, to the entry whose `Z` flag is
/// clear, and every one of them is taken: the protocol bounds a chain by nothing, and zenoh
/// reads a handshake chain to its end (`commons/zenoh-codec/src/transport/init.rs` @
/// `while has_ext {`). On `session-slot` an entry of an extension the build does not read is
/// judged by its header for the message `mid` names and not kept, so the chain's storage does
/// not grow with its length.
///
/// The loop is generic over the walk, which is a type of its own for each message's document; what
/// it does with an entry is one function out of line (`keep_handshake_entry`), so that the four
/// messages' decodes share one copy of it and each holds only its own walk.
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
pub(crate) fn collect_handshake_ext_chain<'a>(
    mid: u8,
    walked: impl Iterator<Item = wz_codecs::ext_entry::ExtEntryView<'a>>,
    entries: &mut ExtChainOwned,
) -> Result<(), crate::parse_error::InboundParseError> {
    for entry in walked {
        // On `session-slot` only the entries of an extension the build reads are kept, one each:
        // a peer that repeats one fills the chain and is refused. Every other build keeps them all.
        #[cfg(feature = "session-slot")]
        let read = reads_received_ext(entry.ext_id());
        #[cfg(not(feature = "session-slot"))]
        let read = true;
        keep_handshake_entry(mid, &entry, read, entries)?;
    }
    Ok(())
}

/// One entry of a received handshake chain into the chain the message holds
/// (`collect_handshake_ext_chain`), kept when `read` says the build reads its extension. On
/// `session-slot` every entry is judged by its header for the message `mid` names, kept or not,
/// and the first refused header is what the chain holds of the rest; every other build keeps the
/// whole chain, which the rule judges entry by entry later.
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive"
))]
#[inline(never)]
fn keep_handshake_entry(
    mid: u8,
    entry: &wz_codecs::ext_entry::ExtEntryView<'_>,
    read: bool,
    entries: &mut ExtChainOwned,
) -> Result<(), crate::parse_error::InboundParseError> {
    #[cfg(not(feature = "session-slot"))]
    {
        let _ = (mid, read);
        entries.push(received_entry(entry)?);
    }
    #[cfg(feature = "session-slot")]
    {
        if entries.refused_header.is_none()
            && crate::ext_admit::judge_ext_chain(
                crate::ext_admit::ExtCarrier::Transport(mid),
                [entry.header],
            )
            .is_refusal()
        {
            entries.refused_header = Some(entry.header);
        }
        if read && entries.entries.push(received_entry(entry)?).is_err() {
            return Err(crate::parse_error::InboundParseError::ExtChainOverflow);
        }
    }
    Ok(())
}

/// The chain of a received Frame, Fragment, Join, transport OAM, Scout or Hello as its document
/// read it, owned: the heap profile's form of the chain those messages report. The document's
/// view reads a chain to the entry whose `Z` flag is clear, whatever its length, and every entry
/// is kept, as `collect_handshake_ext_chain` keeps a handshake's.
///
/// Gated on `alloc` alone: the transport OAM is read by every build with an allocator, under no
/// `codec-*` feature, so every such build has a reader of this.
#[cfg(feature = "alloc")]
pub(crate) fn collect_ext_chain<'a>(
    walked: impl Iterator<Item = wz_codecs::ext_entry::ExtEntryView<'a>>,
) -> Result<Vec<ExtEntryOwned>, crate::parse_error::InboundParseError> {
    walked.map(|entry| received_entry(&entry)).collect()
}

/// The verdict [`collect_ext_chain`] gives the chain `walked` yields, entry by entry, with
/// nothing kept and nothing copied: for a reader that refuses the message whatever its chain
/// says and needs only the refusals the decoder would have answered with (the in-place reader of
/// a JOIN and of a transport OAM).
///
/// Each entry is lent where it lies, which is the step of `received_entry` that can refuse:
/// its second step stores the lent entry at the transport profile, which is the heap in every
/// build this is compiled in, and the heap refuses no body. So a ZBuf extension's body is judged
/// without the copy of it the stored entry would make. The walk of a group datagram reads a
/// transport OAM's chain through it too, to step past the OAM (`inbound::control_extent`).
#[cfg(all(
    feature = "alloc",
    feature = "codec-frame",
    any(
        feature = "session-unicast",
        all(
            feature = "session-multicast",
            feature = "codec-join",
            feature = "codec-close"
        )
    )
))]
pub(crate) fn check_ext_chain<'a>(
    walked: impl Iterator<Item = wz_codecs::ext_entry::ExtEntryView<'a>>,
) -> Result<(), crate::parse_error::InboundParseError> {
    for entry in walked {
        let mut lent = wz_codecs::lent::ExtEntry::default();
        entry
            .into_builder(&mut lent)
            .map_err(crate::parse_error::InboundParseError::Codec)?;
    }
    Ok(())
}

/// One entry of a received transport chain, from the view the document read it as to the
/// lifetime-free owned form the message keeps.
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive",
    feature = "alloc"
))]
pub(crate) fn received_entry(
    entry: &wz_codecs::ext_entry::ExtEntryView<'_>,
) -> Result<ExtEntryOwned, crate::parse_error::InboundParseError> {
    use crate::parse_error::InboundParseError;

    let mut lent = wz_codecs::lent::ExtEntry::default();
    entry
        .into_builder(&mut lent)
        .map_err(InboundParseError::Codec)?;
    lent.try_into_owned_in::<crate::transport_profile::TransportStorage>()
        .map_err(InboundParseError::Codec)
}

/// How many entries a wz node stores of every entry-flag ext chain in the
/// network and zenoh-payload layers: the capacity `deploy/codec_node.yaml` gives
/// the `Node` profile. The protocol bounds a chain by nothing; this is a fact of
/// the storing decode at `Node`, which refuses an entry past it as
/// `CapacityExceeded`, and not of the wire, which the dissector reads to the
/// entry whose `Z` flag is clear.
///
/// It is not derived from the generated type because a const generic parameter
/// has no name to import. What closes the loop instead is
/// `the_node_chain_capacities_match_the_constant` in [`crate::dissect`], which
/// reads each lent form's list capacity back out of its type, so a deploy file
/// with a different capacity reds a test rather than silently disagreeing with
/// the tests that build a chain one entry past it.
// Readers, exactly: the `dissect` tests, and this crate's own chain-saturation
// tests, which live in `network_message` behind `all(test, codec-frame,
// codec-push)`.
//
// R311y588 — the gate was `any(dissect, test)`, and a full local sweep found
// the hole in SEVEN lanes: a `--lib` TEST build without `dissect` makes `test`
// true, so the constant compiles, while its only test-side consumer needs
// `codec-push` and is absent. Dead code under `-D warnings`. Third instance of
// the R311y579 (G7) class in one session, and the first one no per-crate check
// could have seen — every arm run by hand had either `dissect` or `codec-push`
// in it.
//
// The dissector itself no longer reads it, since it walks a chain as the wire
// says, so the constant is test-only.
#[cfg(all(
    test,
    any(
        feature = "dissect",
        all(feature = "codec-frame", feature = "codec-push")
    )
))]
pub const NETWORK_EXT_CHAIN_DEPTH: usize = 8;

/// Encode an ext chain to bytes: each entry's `ExtEntry` encoding with the
/// chain-continuation Z bit (`0x80`) set on every entry but the last (Z clear =
/// terminator). An empty slice encodes to no bytes (the "no extensions" case).
/// The non-Z header bits (`ext_id`, `M`, `enc`) stay author-set; the helper
/// only patches the Z bit per chain position (`ExtEntry::encode` pushes the
/// header byte first).
///
/// The vector form: its consumers are the ones that want the chain as bytes of
/// their own (the auth ext's inner method chain, which is then wrapped in an
/// outer ext; the tests that build a message's chain by hand). The handshake
/// messages, the transport composer's included, are written whole
/// by their documents, and the lend-only Open writes its chain straight after
/// its head through [`encode_ext_chain_into`]; none of them calls this.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "session-extauth",
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
// The Init is written whole by its document, so the chain is written here for
// the vector form above, for the lend-only Open, which writes its chain after
// the head where the chain is staged, and for the tests that hold that Open's
// two halves to the whole one.
#[cfg(any(
    all(
        feature = "tx-lend-only",
        feature = "session-unicast",
        feature = "codec-open-body",
        any(feature = "session-unicast-open", feature = "session-unicast-accept")
    ),
    all(
        feature = "alloc",
        any(
            feature = "session-extauth",
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
    ),
    all(test, feature = "codec-init-body", feature = "codec-open-body")
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

/// The bytes [`encode_ext_chain_into`] writes for `entries`, as each entry's codec
/// counts it. The continuation bit that encode sets or clears on each header
/// changes no length.
// Its reader is the lend-only Open's sizer, the Init being counted whole by its
// document, so the gate is that send's in `session_actions`.
#[cfg(all(
    feature = "tx-lend-only",
    feature = "session-unicast",
    feature = "codec-open-body",
    any(feature = "session-unicast-open", feature = "session-unicast-accept")
))]
pub(crate) fn ext_chain_len(entries: &[ExtEntryOwned]) -> usize {
    // Counted by the writer itself, so the count and the write are one compiled encoder.
    let mut count = crate::tx_buf::CountTxBuf::new();
    match encode_ext_chain_into(&mut count, entries) {
        Ok(()) => crate::tx_buf::TxBuf::len(&count),
        Err(_) => 0,
    }
}

/// Decode the Z-flag-gated ext chain into the lifetime-free owned mirror, to
/// the entry whose `Z` flag is clear. Each entry consumes at least its header
/// byte, so a chain that never terminates ends at the cursor's end as a
/// truncated wire rather than in a loop.
///
/// The chain no message's document holds: the authentication extension's inner
/// list of method entries, which travels inside a ZBuf body (`auth_dispatch`'s
/// demultiplex). Every message chain is read by its message's document and kept
/// through [`collect_ext_chain`] or `collect_handshake_ext_chain`.
#[cfg(feature = "session-extauth")]
pub(crate) fn decode_ext_chain(
    cursor: &mut sce_forge_runtime::codec::SceCursor<'_>,
) -> Result<Vec<ExtEntryOwned>, crate::parse_error::InboundParseError> {
    use crate::parse_error::InboundParseError;
    use wz_codecs::lent::ExtEntry;

    let mut entries = Vec::new();
    loop {
        let entry = ExtEntry::decode(cursor).map_err(InboundParseError::Codec)?;
        let z = entry.z();
        // Deep-copy the borrowed decode view into the lifetime-free owned mirror
        // so the parsed chain can outlive the input buffer.
        entries.push(
            entry
                .try_into_owned_in::<crate::transport_profile::TransportStorage>()
                .map_err(InboundParseError::Codec)?,
        );
        if !z {
            return Ok(entries);
        }
    }
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
        use crate::transport_profile::ExtEntryOwnedVariant;
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

// Every staged chain, on both forms. The fixed form holds as few as three
// entries, so the tests that run on it stage no more than three.
#[cfg(all(test, feature = "session-unicast"))]
mod canonical_order_tests {
    use super::*;
    use crate::transport_profile::ExtEntryOwnedVariant;

    /// A unit entry whose header is its id: the order rule reads the id only,
    /// so the body is immaterial.
    fn unit(id: u8) -> ExtEntryOwned {
        ExtEntryOwned {
            header: id,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(wz_codecs::ext_unit::ExtUnit {}),
        }
    }

    /// The z64 form of an id, as `QoSLink` is beside the unit `QoS` on 0x1.
    fn z64(id: u8, value: u64) -> ExtEntryOwned {
        ExtEntryOwned {
            header: id | crate::ext_header::EXT_ENC_Z64,
            body: ExtEntryOwnedVariant::CodecZenohExtZint(wz_codecs::ext_zint::ExtZint { value }),
        }
    }

    fn stage(chain: &mut ExtChainBuf, entry: ExtEntryOwned) {
        let id = entry.ext_id();
        stage_in_canonical_order(chain, id, Some(entry));
    }

    /// The InitSyn send stages its entries in this order onto a chain seeded
    /// with the patch entry: auth, multilink, lowlatency, QoS, compression,
    /// SHM, region name. zenoh writes them qos, shm, auth, mlink, lowlatency,
    /// compression, patch, region (`commons/zenoh-codec/src/transport/init.rs`
    /// @ `// Extensions`), which is ascending id.
    #[cfg(not(feature = "session-slot"))]
    #[test]
    fn entries_staged_in_send_order_sit_in_upstreams_encode_order() {
        let mut chain: ExtChainBuf = alloc::vec![crate::extpatch::encode_patch_ext()];
        for id in [0x03, 0x04, 0x05, 0x01, 0x06, 0x02, 0x08] {
            stage(&mut chain, unit(id));
        }
        assert!(
            chain
                .iter()
                .map(|e| e.ext_id())
                .eq([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            "the staged chain is in zenoh's field order: {chain:?}"
        );
    }

    /// Re-staging an id replaces whatever form it had, in its place: the unit
    /// QoS and the z64 QoSLink share 0x1, and zenoh never emits both.
    #[test]
    fn restaging_an_id_replaces_its_entry_in_place() {
        let mut chain = ExtChainBuf::default();
        stage(&mut chain, unit(0x08));
        stage(&mut chain, crate::extpatch::encode_patch_ext_at(1));
        stage(&mut chain, unit(0x01));
        stage(&mut chain, z64(0x01, 9));
        assert!(
            chain.iter().map(|e| e.ext_id()).eq([0x01, 0x07, 0x08]),
            "one entry per id, ascending: {chain:?}"
        );
        assert_eq!(
            chain[0].header,
            0x01 | crate::ext_header::EXT_ENC_Z64,
            "the z64 form replaced the unit one"
        );
    }

    /// `None` takes the id off and leaves the rest in order; an id the chain
    /// does not hold leaves it untouched.
    #[test]
    fn staging_none_takes_the_id_off() {
        let mut chain = ExtChainBuf::default();
        stage(&mut chain, unit(0x08));
        stage(&mut chain, unit(0x01));
        stage(&mut chain, crate::extpatch::encode_patch_ext_at(1));
        stage_in_canonical_order(&mut chain, 0x07, None);
        assert!(chain.iter().map(|e| e.ext_id()).eq([0x01, 0x08]));
        stage_in_canonical_order(&mut chain, 0x05, None);
        assert!(chain.iter().map(|e| e.ext_id()).eq([0x01, 0x08]));
    }

    /// A chain handed over whole is ordered by the 4-bit id, not the header
    /// byte, and stably: two entries of one id keep the order they came in.
    #[cfg(not(feature = "session-slot"))]
    #[test]
    fn a_chain_handed_over_whole_is_sorted_by_id_stably() {
        let mut chain: ExtChainBuf = alloc::vec![unit(0x08), z64(0x01, 3), unit(0x07), unit(0x01)];
        sort_into_canonical_order(&mut chain);
        assert!(
            chain.iter().map(|e| e.header).eq([
                0x01 | crate::ext_header::EXT_ENC_Z64,
                0x01,
                0x07,
                0x08
            ]),
            "{chain:?}"
        );
    }
}

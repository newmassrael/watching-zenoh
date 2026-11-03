// SCE-MAP: reply:74 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="codec")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.

use sce_forge_runtime::codec::{CodecError, SceCursor, SceSink};
// RFC §synth-5-B: `VecSink` and the heap-backed `encode_to_vec` facade
// are gated on the `alloc` feature (see
// `backends/rust/forge-runtime/src/codec.rs`). MCU / `no_std` consumers see
// only the sink-based primary `encode` + `SliceSink` paths.
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use sce_forge_runtime::codec::VecSink;

use sce_forge_runtime::codec::{Bounded, ListView, ListWalk};
use super::ext_entry::ExtEntryView;
use super::msg_put::MsgPutView;
use super::msg_del::MsgDelView;

/// A tag `Reply` names no arm for, which its default arm holds: a
/// value inside the 5 bits the tag is read from and outside
/// every arm's tag (docs/adr/0065 §6 R3). A default arm is written with the tag
/// it holds and read back as the default arm, so no tag it holds is refused.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplyUnknownTag(u8);

#[allow(dead_code)]
impl ReplyUnknownTag {
    /// `tag` as a tag no arm names, or `None` when it is past the tag's bits or
    /// is an arm's.
    pub const fn new(tag: u8) -> Option<Self> {
        match tag {
            1..=2 => None,
            _ if tag > 31 => None,
            _ => Some(Self(tag)),
        }
    }

    /// The tag.
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl ::sce_forge_runtime::codec::UnknownTag for ReplyUnknownTag {
    const SPACE: ::sce_forge_runtime::codec::TagSpace =
        ::sce_forge_runtime::codec::TagSpace::new(31, &[(1, 2)]);

    fn widened(self) -> u64 {
        u64::from(self.0)
    }

    fn from_admitted(tag: u64, _proof: ::sce_forge_runtime::codec::Admitted) -> Self {
        Self(tag as u8)
    }
}

// pub API: codecs are intended for cross-crate consumption (SCE_FORGE.md
// §6 codec). The kind-agnostic conformance harness only references a
// subset of fixtures, so unused-but-pub fields/methods would otherwise
// trigger dead_code on every codec build.
use super::ext_entry::ExtEntryOwned;
use super::msg_put::MsgPutOwned;
use super::msg_del::MsgDelOwned;
/// The field `extensions` of `Reply`, which a storage profile
/// answers for by this type.
#[allow(dead_code)]
pub struct ReplyExtensionsField;

// `Inline` does not answer for `extensions`: the protocol states no bound of
// it, so it is held only by a profile whose container grows, or by a deployment
// that gives it a capacity (docs/adr/0077 §7).

/// What `ReplyIn` and the codecs it holds ask of a storage profile.
#[allow(dead_code)]
pub trait ReplyStorage: ::core::fmt::Debug + Clone + PartialEq + ::sce_forge_runtime::codec::HoldsList<ReplyExtensionsField> + super::ext_entry::ExtEntryStorage + super::msg_put::MsgPutStorage + super::msg_del::MsgDelStorage {}

impl<S: ::core::fmt::Debug + Clone + PartialEq + ::sce_forge_runtime::codec::HoldsList<ReplyExtensionsField> + super::ext_entry::ExtEntryStorage + super::msg_put::MsgPutStorage + super::msg_del::MsgDelStorage> ReplyStorage for S {}

/// What `ReplyIn<Lent<'a, D>>` asks of the profile `D`: how it holds
/// the lists of `Reply` and of the codecs it holds, since the lent
/// form borrows every byte string and text from the frame (docs/adr/0077 §7).
#[allow(dead_code)]
pub trait ReplyLentStorage: ::core::fmt::Debug + Clone + PartialEq + ::sce_forge_runtime::codec::HoldsList<ReplyExtensionsField> + super::ext_entry::ExtEntryLentStorage + super::msg_put::MsgPutLentStorage + super::msg_del::MsgDelLentStorage {}

impl<D: ::core::fmt::Debug + Clone + PartialEq + ::sce_forge_runtime::codec::HoldsList<ReplyExtensionsField> + super::ext_entry::ExtEntryLentStorage + super::msg_put::MsgPutLentStorage + super::msg_del::MsgDelLentStorage> ReplyLentStorage for D {}

/// What a decode of a frame of the lifetime `'f` asks of a storage profile
/// beside ReplyStorage: how it stores each field of that frame.
#[allow(dead_code)]
pub trait ReplyFrom<'f>: ReplyStorage + super::ext_entry::ExtEntryFrom<'f> + super::msg_put::MsgPutFrom<'f> + super::msg_del::MsgDelFrom<'f> {}

impl<'f, S: ReplyStorage + super::ext_entry::ExtEntryFrom<'f> + super::msg_put::MsgPutFrom<'f> + super::msg_del::MsgDelFrom<'f>> ReplyFrom<'f> for S {}

// `ReplyIn<S>` is the one value this codec has, at the storage
// profile `S` (docs/adr/0077 §7). `Reply<'a>` is it on `Lent`, which
// borrows bytes and text from the frame, and `ReplyOwned<S>` names it
// at a profile that holds them.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct ReplyIn<S: ReplyStorage> {
    pub header: u8,
    pub consolidation: Option<u8>,
    pub extensions: Option<::sce_forge_runtime::codec::Bounded<<S as ::sce_forge_runtime::codec::HoldsList<ReplyExtensionsField>>::List<ExtEntryOwned<S>>, { usize::MAX }, 1>>,
    pub body: ReplyVariantIn<S>,
}

/// The eager form: bytes and text borrowed from the frame, lists held inline.
#[allow(dead_code)]
pub type Reply<'a> = ReplyIn<::sce_forge_runtime::codec::Lent<'a>>;

/// The value at a profile that holds its bytes and text, named
/// with the profile: the build's default on the heap-free tier is `Inline`, which
/// holds no field whose protocol states no bound (docs/adr/0077 §7).
#[allow(dead_code)]
pub type ReplyOwned<S> = ReplyIn<S>;

impl<S: ReplyStorage> Default for ReplyIn<S> {
    fn default() -> Self {
        Self {
            header: 0x04u8,
            consolidation: Default::default(),
            extensions: Default::default(),
            body: Default::default(),
        }
    }
}

// RFC §synth-5-B variant primitive: discriminated-union body for the
// codec's tag-field suffix. Each arm wraps an imported codec's decoded
// value; the optional Default arm preserves the runtime tag value
// alongside its catch-all body.
//
// Variant arms wrap distinct body codecs whose stored forms differ in
// field count and size, so the tagged union is inherently size-disparate.
// The lint's only remedy is boxing the large arm, which adds an
// indirection (and allocation) the generated decode path does not need —
// and which the non-allocating storage profile could not take at all.
// The size spread is the deliberate tagged-union trade-off.
#[allow(clippy::large_enum_variant)]
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum ReplyVariantIn<S: ReplyStorage> {
    CodecZenohMsgPut(MsgPutOwned<S>),
    CodecZenohMsgDel(MsgDelOwned<S>),
    Default {
        tag: ReplyUnknownTag,
        body: MsgPutOwned<S>,
    },
}

#[allow(dead_code)]
pub type ReplyVariant<'a> = ReplyVariantIn<::sce_forge_runtime::codec::Lent<'a>>;

#[allow(dead_code)]
pub type ReplyOwnedVariant<S> = ReplyVariantIn<S>;

impl<S: ReplyStorage> Default for ReplyVariantIn<S> {
    fn default() -> Self {
        // RFC variant-default-uniformity: pick the declared default
        // arm (`<sce:arm default="true"/>`) so a freshly-constructed
        // envelope round-trips byte-exactly through `encode() ->
        // decode()` — pairs with the inner codec's `<sce:flag value=>`
        // -baked `Default::default()` to close the dispatch loop.
        Self::CodecZenohMsgPut(MsgPutOwned::<S>::default())
    }
}

#[allow(dead_code)]
impl<S: ReplyStorage> ReplyIn<S> {
    /// Construct an instance with every field at its own type's
    /// [`Default`]. Generated procedure_l2 code stores codec instances
    /// as owned members and needs an infallible constructor to
    /// initialize them before any `encode()` or `decode()` call. An
    /// enum-typed field starts at the first variant its document
    /// declares, not at the carrier's zero: a closed set does not hold
    /// a value it never declared.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode the next frame from `cursor`. On success the cursor
    /// advances past the consumed bytes; on `NeedMoreBytes` the cursor
    /// is left untouched so the caller can resume after appending more
    /// bytes (RFC §synth-5-B L494-519).
    pub fn decode<'f>(cursor: &mut SceCursor<'f>) -> Result<Self, CodecError> where S: ReplyFrom<'f> {
        let mut _out = Self::default();
        Self::decode_into(cursor, &mut _out)?;
        Ok(_out)
    }

    /// Decode the next frame from `cursor` into `_out`: the bytes, the bounds
    /// and the errors of [`Self::decode`], with each bounded list and embedded
    /// body built in the field where it will live.
    ///
    /// `decode` returns its value, and a `heapless::Vec` moves by copying its
    /// whole declared capacity, so every hop a decoded list takes on the way
    /// up (the struct literal, `Ok(..)`, a variant wrapper, the caller's own
    /// binding) copies the declared maximum however few entries the wire held.
    /// A caller on a path where that shows decodes into a destination it owns.
    /// On `Err`, `_out` holds the fields decoded so far and is not to be read.
    pub fn decode_into<'f>(cursor: &mut SceCursor<'f>, _out: &mut Self) -> Result<(), CodecError> where S: ReplyFrom<'f> {
        // A form past its capacity stopped where it could not store, so the
        // frame is judged by what cannot run out, and only a frame that parses
        // is one this node cannot hold (docs/adr/0077 §7). Any profile may hold
        // less than a bound, so this stands on every codec that takes one.
        let mut _frame = *cursor;
        match Self::store_into(cursor, _out) {
            Err(CodecError::CapacityExceeded) => {
                ReplyView::decode(&mut _frame)?;
                Err(CodecError::CapacityExceeded)
            }
            stored => stored,
        }
    }

    /// The reading of [`Self::decode_into`], which stops where a field is past
    /// its capacity.
    fn store_into<'f>(cursor: &mut SceCursor<'f>, _out: &mut Self) -> Result<(), CodecError> where S: ReplyFrom<'f> {
        // RFC §synth-5-B peek-byte / streaming-prefix:
        // streaming prefix decode (variable-length fields supported via
        // per-field present_if/tlv-chain/embed/repeat helpers). Peek-byte
        // mode additionally peeks the cursor's next byte for the variant
        // tag without advancing — the arm body decoder reads the peeked
        // byte as its own header byte (Zenoh response/request body MID
        // dispatch shape per network.c:347-364 + 220-235).
        let header = {
            let raw = cursor.peek_slice(1)?;
            let _v = raw[0];
            cursor.advance(1)?;
            _v
        };
        let consolidation = if (header & 0x20u8) != 0 {
            let raw = cursor.peek_slice(1)?;
            let _v = raw[0];
            cursor.advance(1)?;
            Some(_v)
        } else {
            None
        };
        if (header & 0x80u8) != 0 {
            _out.extensions.insert(Default::default()).refill(|_vec| {
                let mut _more = false;
                loop {
                    let _entry = ExtEntryOwned::<S>::decode(cursor)?;
                    _more = _entry.z();
                    // The loop walks the chain's depth and `_vec` holds the capacity, so
                // this push fails only where the deployment holds fewer entries than
                // the frame says. An over-long chain is refused after the loop.
                ::sce_forge_runtime::codec::SceList::try_push(_vec, _entry)?;
                    if !_more { break; }
                }
                if _more && cursor.remaining() == 0 {
                    return Err(CodecError::NeedMoreBytes);
                }
                Ok(())
            })?;
        } else {
            _out.extensions = None;
        }
        let _peek = cursor.peek_slice(1)?[0];
        // Dispatch on the tag field; each arm decodes its body codec
        // from the cursor. The default arm (when declared) carries the
        // runtime tag value so encode can round-trip it back onto the
        // wire.
        // Each arm is installed in `_out.body` holding its body's default and
        // that body is decoded where it sits, so no arm body is returned up
        // through the variant wrapper.
        match _peek & 0x1F {
            1u8 => {
                _out.body = ReplyVariantIn::CodecZenohMsgPut(MsgPutOwned::<S>::default());
                if let ReplyVariantIn::CodecZenohMsgPut(_b) = &mut _out.body {
                    MsgPutOwned::<S>::decode_into(cursor, _b)?;
                }
            }
            2u8 => {
                _out.body = ReplyVariantIn::CodecZenohMsgDel(MsgDelOwned::<S>::default());
                if let ReplyVariantIn::CodecZenohMsgDel(_b) = &mut _out.body {
                    MsgDelOwned::<S>::decode_into(cursor, _b)?;
                }
            }
            other => {
                _out.body = ReplyVariantIn::Default {
                    tag: ReplyUnknownTag(other),
                    body: MsgPutOwned::<S>::default(),
                };
                if let ReplyVariantIn::Default { body: _b, .. } = &mut _out.body {
                    MsgPutOwned::<S>::decode_into(cursor, _b)?;
                }
            }
        }
        _out.header = header;
        _out.consolidation = consolidation;
        Ok(())
    }

    // RFC §synth-5-B flags primitive: per-bit-range accessors over
    // the carrier field. Single-bit (width=1) reads as bool; multi-bit
    // (width>=2) reads as the smallest unsigned integer that fits the
    // range. Setters mask + shift on the way in so out-of-range
    // callers can't corrupt sibling bits. Wire layout is unchanged —
    // the carrier still occupies its declared bytes.
    pub fn mid(&self) -> u8 {
        self.header & 0x1F
    }

    pub fn set_mid(&mut self, v: u8) {
        self.header = (self.header & !0x1F) | (v & 0x1F);
    }

    pub fn c(&self) -> bool {
        (self.header & 0x20) != 0
    }

    pub fn set_c(&mut self, v: bool) {
        if v {
            self.header |= 0x20;
        } else {
            self.header &= !0x20;
        }
    }

    pub fn z(&self) -> bool {
        (self.header & 0x80) != 0
    }

    pub fn set_z(&mut self, v: bool) {
        if v {
            self.header |= 0x80;
        } else {
            self.header &= !0x80;
        }
    }


    /// Encode `self` into the caller-owned sink. Every value has a frame
    /// (docs/adr/0065), so the only error is the sink's own:
    /// `CodecError::BufferOverflow` from a bounded sink when the destination
    /// has insufficient remaining capacity, and none from a sink that cannot
    /// refuse (`VecSink`, `CountSink`).
    pub fn encode<K: SceSink>(&self, w: &mut K) -> Result<(), K::Error> {
        ReplyWire::encode_source(self, w)
    }

    /// Heap-backed convenience facade. It reserves nothing, since the
    /// largest frame passes `u32` (docs/adr/0077 §7), and delegates to
    /// `encode` over a
    /// `VecSink`, and returns the freshly-encoded bytes: the encode refuses
    /// no value and the vector cannot run out of room. Callers targeting
    /// zero-alloc hot paths should call `encode` directly against a
    /// caller-owned sink.
    ///
    /// Gated on the `alloc` feature — `VecSink` lives behind the
    /// same gate (see `backends/rust/forge-runtime/src/codec.rs`). MCU /
    /// `no_std` builds without `alloc` only see the sink-based
    /// primary `encode`.
    #[cfg(feature = "alloc")]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut _sce_v: Vec<u8> = Vec::new();
        let Ok(()) = self.encode(&mut VecSink::new(&mut _sce_v));
        _sce_v
    }
}

/// The arm of `Reply`'s variant a value holds, each arm's body as the
/// source it says. The tag is not among them: `Reply` derives it from
/// the arm, as it derives a length, and a default arm presents the tag
/// it could not name.
// A default arm's tag is read by the codec that embeds this one and
// derives its own carrier bits from the arm, which not every build uses.
#[allow(dead_code)]
pub enum ReplyVariantSource<'s, A0: ?Sized, A1: ?Sized, D: ?Sized> {
    CodecZenohMsgPut(&'s A0),
    CodecZenohMsgDel(&'s A1),
    Default { tag: ReplyUnknownTag, body: &'s D },
}

impl<'s, A0: ?Sized, A1: ?Sized, D: ?Sized> ReplyVariantSource<'s, A0, A1, D> {
    /// The tag of the arm this is: the value the document gives a known
    /// arm, and the tag a default arm holds. It is the tag the encode
    /// writes, or the one a caller hands the decode for a variant whose
    /// wire form carries none.
    pub fn tag(&self) -> u8 {
        match self {
            Self::CodecZenohMsgPut(_) => 1,
            Self::CodecZenohMsgDel(_) => 2,
            Self::Default { tag, .. } => tag.get(),
        }
    }
}

// ── Source (ADR 0058) ────────────────────────────────────────────────
/// What a value of `Reply` says: its presented fields. A length, a count
/// or the flag a gated field is announced by is not among them; the
/// encode computes those from what is ([`ReplyWire::encode_source`]).
pub trait ReplySource {
    /// The `header` field.
    fn header(&self) -> u8;
    /// The `consolidation` field.
    fn consolidation(&self) -> Option<u8>;
    /// The `extensions` field.
    fn extensions(&self) -> Option<::sce_forge_runtime::codec::BoundedIter<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone, { usize::MAX }, 1>>;
    /// The arm of the variant this value holds.
    fn body(&self) -> ReplyVariantSource<'_, impl super::msg_put::MsgPutSource, impl super::msg_del::MsgDelSource, impl super::msg_put::MsgPutSource>;
}

impl<T: ReplySource + ?Sized> ReplySource for &T {
    fn header(&self) -> u8 {
        (**self).header()
    }
    fn consolidation(&self) -> Option<u8> {
        (**self).consolidation()
    }
    fn extensions(&self) -> Option<::sce_forge_runtime::codec::BoundedIter<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone, { usize::MAX }, 1>> {
        (**self).extensions()
    }
    fn body(&self) -> ReplyVariantSource<'_, impl super::msg_put::MsgPutSource, impl super::msg_del::MsgDelSource, impl super::msg_put::MsgPutSource> {
        (**self).body()
    }
}

/// The arm of `Reply`'s variant that ReplyParts holds.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum ReplyPartsBody<'a> {
    CodecZenohMsgPut(&'a super::msg_put::MsgPutParts<'a>),
    CodecZenohMsgDel(&'a super::msg_del::MsgDelParts<'a>),
    /// The tag the grammar could not name, and the body it holds.
    Default { tag: ReplyUnknownTag, body: &'a super::msg_put::MsgPutParts<'a> },
}

/// A value of `Reply` held in the types a caller already has: a source
/// ([`ReplySource`]) whose lists are slices within their bounds and whose
/// bodies are references.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct ReplyParts<'a> {
    /// The `header` field.
    pub header: u8,
    /// The `consolidation` field.
    pub consolidation: Option<u8>,
    /// The `extensions` field.
    pub extensions: Option<::sce_forge_runtime::codec::Bounded<&'a [super::ext_entry::ExtEntryParts<'a>], { usize::MAX }, 1>>,
    /// The arm of the variant this value holds.
    pub body: ReplyPartsBody<'a>,
}

impl<'a> ReplySource for ReplyParts<'a> {
    fn header(&self) -> u8 {
        self.header
    }
    fn consolidation(&self) -> Option<u8> {
        self.consolidation
    }
    fn extensions(&self) -> Option<::sce_forge_runtime::codec::BoundedIter<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone, { usize::MAX }, 1>> {
        self.extensions.as_ref().map(|_l| _l.iter())
    }
    fn body(&self) -> ReplyVariantSource<'_, impl super::msg_put::MsgPutSource, impl super::msg_del::MsgDelSource, impl super::msg_put::MsgPutSource> {
        match &self.body {
            ReplyPartsBody::CodecZenohMsgPut(_b) => ReplyVariantSource::CodecZenohMsgPut(*_b),
            ReplyPartsBody::CodecZenohMsgDel(_b) => ReplyVariantSource::CodecZenohMsgDel(*_b),
            ReplyPartsBody::Default { tag, body } => ReplyVariantSource::Default { tag: *tag, body: *body },
        }
    }
}

impl<S: ReplyStorage> ReplySource for ReplyOwned<S> {
    fn header(&self) -> u8 {
        self.header
    }
    fn consolidation(&self) -> Option<u8> {
        self.consolidation
    }
    fn extensions(&self) -> Option<::sce_forge_runtime::codec::BoundedIter<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone, { usize::MAX }, 1>> {
        self.extensions.as_ref().map(|_l| _l.list_iter())
    }
    fn body(&self) -> ReplyVariantSource<'_, impl super::msg_put::MsgPutSource, impl super::msg_del::MsgDelSource, impl super::msg_put::MsgPutSource> {
        match &self.body {
            ReplyOwnedVariant::CodecZenohMsgPut(_b) => ReplyVariantSource::CodecZenohMsgPut(_b),
            ReplyOwnedVariant::CodecZenohMsgDel(_b) => ReplyVariantSource::CodecZenohMsgDel(_b),
            ReplyOwnedVariant::Default { tag, body } => ReplyVariantSource::Default { tag: *tag, body },
        }
    }
}

impl<'a> ReplySource for ReplyView<'a> {
    fn header(&self) -> u8 {
        self.header
    }
    fn consolidation(&self) -> Option<u8> {
        self.consolidation
    }
    fn extensions(&self) -> Option<::sce_forge_runtime::codec::BoundedIter<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone, { usize::MAX }, 1>> {
        self.extensions.as_ref().map(|_l| _l.iter())
    }
    fn body(&self) -> ReplyVariantSource<'_, impl super::msg_put::MsgPutSource, impl super::msg_del::MsgDelSource, impl super::msg_put::MsgPutSource> {
        match &self.body {
            ReplyViewVariant::CodecZenohMsgPut(_b) => ReplyVariantSource::CodecZenohMsgPut(_b),
            ReplyViewVariant::CodecZenohMsgDel(_b) => ReplyVariantSource::CodecZenohMsgDel(_b),
            ReplyViewVariant::Default { tag, body } => ReplyVariantSource::Default { tag: *tag, body },
        }
    }
}

/// The codec `Reply` itself: what writes a value read through
/// [`ReplySource`], holding no value and naming no storage profile. Every
/// form of the value, a parent and a view write through it, so a profile
/// that cannot hold some field is never asked for here (docs/adr/0077 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReplyWire;

#[allow(dead_code)]
impl ReplyWire {
    /// Encode what `src` says into the caller-owned sink: the bytes
    /// `Reply::encode` writes for the value it holds, read through
    /// [`ReplySource`]. A length, a count or a gate flag is computed from what
    /// `src` presents. Every value `src` can present has a frame, so the
    /// only error is the sink's (docs/adr/0065).
    pub fn encode_source<S: ReplySource + ?Sized, K: SceSink>(src: &S, w: &mut K) -> Result<(), K::Error> {
        Self::write_source(src, w)
    }

    /// The tag of the arm `src` holds ([`ReplyVariantSource::tag`]).
    pub fn tag_of<S: ReplySource + ?Sized>(src: &S) -> u8 {
        src.body().tag()
    }

    /// [`Self::encode_source`] without the guard a parent has already made.
    #[doc(hidden)]
    pub fn write_source<S: ReplySource + ?Sized, K: SceSink>(src: &S, w: &mut K) -> Result<(), K::Error> {
        let _k_extensions: usize = src.extensions().map_or(0, |_l| _l.len());
        let _p_header_c_0: bool = src.consolidation().is_some();
        let _p_header_z_0: bool = src.extensions().is_some();
        let _c_header: u8 = (((src.header() & !0x20) | (u8::from(_p_header_c_0) << 5)) & !0x80) | (u8::from(_p_header_z_0) << 7);
        w.write_u8(_c_header)?;
        if let Some(_v) = src.consolidation() {
            w.write_u8(_v)?;
        }
        if let Some(_v) = src.extensions() {
            for (_i, _e) in _v.enumerate() {
                super::ext_entry::ExtEntryWire::write_source_in(&_e, w, &super::ext_entry::ExtEntryOverrides::header_z(_i + 1 < _k_extensions))?;
            }
        }
        match src.body() {
            ReplyVariantSource::CodecZenohMsgPut(_b) => super::msg_put::MsgPutWire::write_source(_b, w)?,
            ReplyVariantSource::CodecZenohMsgDel(_b) => super::msg_del::MsgDelWire::write_source(_b, w)?,
            ReplyVariantSource::Default { body: _b, .. } => super::msg_put::MsgPutWire::write_source(_b, w)?,
        }
        Ok(())
    }

    /// The bytes [`Self::write_source`] writes for `src`, counted with
    /// nothing written.
    #[doc(hidden)]
    pub fn count_source<S: ReplySource + ?Sized>(src: &S) -> usize {
        let mut _c = ::sce_forge_runtime::codec::CountSink::new();
        let Ok(()) = Self::write_source(src, &mut _c);
        _c.len()
    }
}

impl<S: ReplySource + ?Sized> ::sce_forge_runtime::codec::SourceWrite<S> for ReplyWire {
    type Error<E> = E;

    fn write<K: SceSink>(src: &S, w: &mut K) -> Result<(), K::Error> where CodecError: From<K::Error> {
        Self::write_source(src, w)
    }
}

#[allow(dead_code)]
impl ReplyWire {
    /// The size of the frame [`Self::encode_source`] writes for `src`, found
    /// with nothing written: the encode refuses no value, so neither does
    /// this. The result writes the frame into a window of exactly that size
    /// and cannot fail.
    pub fn measure<S: ReplySource + ?Sized>(src: &S) -> ::sce_forge_runtime::codec::Measured<'_, Self, S> {
        let Ok(measured) = ::sce_forge_runtime::codec::measure(src);
        measured
    }

    /// Write `src` into `window` in one pass and return the bytes it is, for a
    /// window as large as the caller can spare. On an error the window holds a
    /// prefix to discard; see [`::sce_forge_runtime::codec::write_window`].
    pub fn write_window<S: ReplySource + ?Sized>(src: &S, window: &mut [u8]) -> Result<usize, CodecError> {
        let mut sink = ::sce_forge_runtime::codec::SliceSink::new(window);
        Self::write_source(src, &mut sink)?;
        Ok(sink.position())
    }
}


// ── View (ADR 0049) ──────────────────────────────────────────────────
// `ReplyView` is what a decode of `Reply` learned, not a
// copy of what the wire repeated: a scalar, a string or a bytes field is held
// as `Reply` holds it, an embedded body or a variant arm as its
// own view, and a bounded list as the frame it was read from, how many entries
// it holds and what a walk needs to read them again (`ListView`). Its size
// depends on the number of fields and not on any `sce:max-count`, so moving
// one copies a few words however long its lists may be. `decode` refuses the
// frames `Reply::decode` refuses, with the same error: the entries
// are decoded once to check them, and a walk afterwards cannot fail.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum ReplyViewVariant<'a> {
    CodecZenohMsgPut(MsgPutView<'a>),
    CodecZenohMsgDel(MsgDelView<'a>),
    Default {
        tag: ReplyUnknownTag,
        body: MsgPutView<'a>,
    },
}

impl<'a> Default for ReplyViewVariant<'a> {
    fn default() -> Self {
        Self::CodecZenohMsgPut(MsgPutView::default())
    }
}

#[allow(dead_code)]
pub struct ReplyExtensionsWalk;

impl ListWalk<0> for ReplyExtensionsWalk {
    type Entry<'b> = ExtEntryView<'b>;

    fn decode<'b>(_c: &mut SceCursor<'b>, _a: &[u8; 0]) -> Result<Self::Entry<'b>, CodecError> {
        ExtEntryView::decode(_c)
    }

    fn advance(_e: &Self::Entry<'_>, _s: &mut [u8; 0]) {  }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct ReplyView<'a> {
    pub header: u8,
    pub consolidation: Option<u8>,
    pub extensions: Option<Bounded<ListView<'a, ReplyExtensionsWalk, 0>, { usize::MAX }, 1>>,
    pub body: ReplyViewVariant<'a>,
}

impl<'a> Default for ReplyView<'a> {
    fn default() -> Self {
        Self {
            header: 0x04u8,
            consolidation: Default::default(),
            extensions: Default::default(),
            body: ReplyViewVariant::default(),
        }
    }
}

#[allow(dead_code)]
impl<'a> ReplyView<'a> {
    /// A view with every field at its own type's [`Default`]: the destination
    /// [`Self::decode_into`] fills.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode the next frame from `cursor`: the bytes, the bounds and the
    /// errors of [`Reply::decode`], held as a view. On success the
    /// cursor advances past the consumed bytes.
    pub fn decode(cursor: &mut SceCursor<'a>) -> Result<Self, CodecError> {
        let mut _out = Self::default();
        Self::decode_into(cursor, &mut _out)?;
        Ok(_out)
    }

    /// [`Self::decode`] into a destination the caller owns, so a view that
    /// embeds or dispatches to this one is filled where it will live. On
    /// `Err`, `_out` holds the fields decoded so far and is not to be read.
    pub fn decode_into(cursor: &mut SceCursor<'a>, _out: &mut Self) -> Result<(), CodecError> {
        // RFC §synth-5-B peek-byte / streaming-prefix:
        // streaming prefix decode (variable-length fields supported via
        // per-field present_if/tlv-chain/embed/repeat helpers). Peek-byte
        // mode additionally peeks the cursor's next byte for the variant
        // tag without advancing — the arm body decoder reads the peeked
        // byte as its own header byte (Zenoh response/request body MID
        // dispatch shape per network.c:347-364 + 220-235).
        let header = {
            let raw = cursor.peek_slice(1)?;
            let _v = raw[0];
            cursor.advance(1)?;
            _v
        };
        let consolidation = if (header & 0x20u8) != 0 {
            let raw = cursor.peek_slice(1)?;
            let _v = raw[0];
            cursor.advance(1)?;
            Some(_v)
        } else {
            None
        };
        if (header & 0x80u8) != 0 {
            let _rest = cursor.peek_slice(cursor.remaining())?;
            let mut _count: u32 = 0;
            let mut _more = false;
            loop {
                let _entry = ExtEntryView::decode(cursor)?;
                _more = _entry.z();
                _count += 1;
                if !_more { break; }
            }
            if _more && cursor.remaining() == 0 {
                return Err(CodecError::NeedMoreBytes);
            }
            _out.extensions = Some(Bounded::new(ListView::new(_rest, _count, [])).ok_or(CodecError::TooManyElements)?);
        } else {
            _out.extensions = None;
        }
        let _peek = cursor.peek_slice(1)?[0];
        // Dispatch on the tag field; each arm decodes its body codec
        // from the cursor. The default arm (when declared) carries the
        // runtime tag value so encode can round-trip it back onto the
        // wire.
        // Each arm is installed in `_out.body` holding its body's default and
        // that body is decoded where it sits, so no arm body is returned up
        // through the variant wrapper.
        match _peek & 0x1F {
            1u8 => {
                _out.body = ReplyViewVariant::CodecZenohMsgPut(MsgPutView::default());
                if let ReplyViewVariant::CodecZenohMsgPut(_b) = &mut _out.body {
                    MsgPutView::decode_into(cursor, _b)?;
                }
            }
            2u8 => {
                _out.body = ReplyViewVariant::CodecZenohMsgDel(MsgDelView::default());
                if let ReplyViewVariant::CodecZenohMsgDel(_b) = &mut _out.body {
                    MsgDelView::decode_into(cursor, _b)?;
                }
            }
            other => {
                _out.body = ReplyViewVariant::Default {
                    tag: ReplyUnknownTag(other),
                    body: MsgPutView::default(),
                };
                if let ReplyViewVariant::Default { body: _b, .. } = &mut _out.body {
                    MsgPutView::decode_into(cursor, _b)?;
                }
            }
        }
        _out.header = header;
        _out.consolidation = consolidation;
        Ok(())
    }

    /// Fill `_out`, the builder form [`Reply`] a sender fills and
    /// encodes, with what this view says: every field, each embedded body, the
    /// variant arm, and each list entry as the walk yields it, built in the
    /// destination where it will live. Fails only where the destination cannot
    /// hold it, which a destination of the same declared bounds does.
    // The name every view's method has (ADR 0049), which borrows because a
    // view is read, not consumed. Clippy leaves an exported method's name
    // alone; a crate that includes this module privately is asked to rename
    // it, and the one name is what lets a codec reach every view it holds.
    #[allow(clippy::wrong_self_convention)]
    pub fn into_builder<D>(&self, _out: &mut ReplyIn<::sce_forge_runtime::codec::Lent<'a, D>>) -> Result<(), CodecError> where D: ReplyLentStorage {
        _out.header = self.header;
        _out.consolidation = self.consolidation;
        match &self.extensions {
            Some(_l) => _out.extensions.insert(Default::default()).refill(|_vec| {
                    for _e in _l.iter() {
                        ::sce_forge_runtime::codec::SceList::try_push(_vec, Default::default())?;
                        if let Some(_slot) = ::sce_forge_runtime::codec::SceList::last_mut(_vec) {
                            _e.into_builder(_slot)?;
                        }
                    }
                    Ok(())
                })?,
            None => _out.extensions = None,
        }
        match &self.body {
            ReplyViewVariant::CodecZenohMsgPut(_b) => {
                _out.body = ReplyVariantIn::CodecZenohMsgPut(Default::default());
                if let ReplyVariantIn::CodecZenohMsgPut(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
            ReplyViewVariant::CodecZenohMsgDel(_b) => {
                _out.body = ReplyVariantIn::CodecZenohMsgDel(Default::default());
                if let ReplyVariantIn::CodecZenohMsgDel(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
            ReplyViewVariant::Default { tag, body } => {
                _out.body = ReplyVariantIn::Default {
                    tag: *tag,
                    body: Default::default(),
                };
                if let ReplyVariantIn::Default { body: _o, .. } = &mut _out.body {
                    body.into_builder(_o)?;
                }
            }
        }
        Ok(())
    }


    /// Encode what this view says into the caller-owned sink: the bytes
    /// [`Reply::encode`] writes for the value [`Self::into_builder`]
    /// fills, written straight from the view, walking each list, without the
    /// builder. It writes the canonical wire, not the frame the view was decoded
    /// from, so a frame `decode` accepted in a form that is not canonical is
    /// not passed on as it came.
    pub fn encode<S: SceSink>(&self, w: &mut S) -> Result<(), S::Error> {
        ReplyWire::encode_source(self, w)
    }

    /// Heap-backed convenience facade over [`Self::encode`], which refuses no
    /// value (docs/adr/0065).
    #[cfg(feature = "alloc")]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut _sce_v: Vec<u8> = Vec::new();
        let Ok(()) = self.encode(&mut VecSink::new(&mut _sce_v));
        _sce_v
    }

    pub fn mid(&self) -> u8 {
        self.header & 0x1F
    }

    pub fn c(&self) -> bool {
        (self.header & 0x20) != 0
    }

    pub fn z(&self) -> bool {
        (self.header & 0x80) != 0
    }

}

// ── Owned projection (storage-parameterised native form) ─────────────
// `Reply<'a>` above is a zero-copy view borrowing the decode
// buffer. Consumers that persist a decoded value beyond the buffer's
// lifetime — including the self-contained bounded-collection that stores
// elements by value — call `.try_into_owned()` for this lifetime-free
// `ReplyOwned`. The rkyv-style Archived(borrowed) ↔ native
// (owned) split, both generated from the one SCXML source (SSOT).
//
// The owned form is parameterised by a storage profile rather than fixed at
// build-configuration time: `ReplyOwned<Heap>` holds growable
// containers with the declared capacities advisory, `ReplyOwned<Inline>`
// holds every field inline at its declared capacity and never allocates, and
// both exist in the same binary. `ReplyOwned` alone is the build's
// default profile. Because the non-allocating profile is a *type*, this mirror
// carries no `alloc` gate at all — a list- or embed-bearing codec has an owned
// form on the heap-free tier too, and a heap-capable consumer can still pin a
// value to storage that is guaranteed not to allocate.
//
// `try_into_owned` is the fallible direction (one `?` per profile: on the
// growable profile the copy cannot fail, on the inline profile it enforces
// each declared bound); `try_as_borrowed` re-borrows any profile back
// into the single borrowed view that owns `encode`; `transcode_in` moves a
// value between profiles as a checked projection rather than a re-decode.
//
// Decoding picks the profile from the call (`try_into_owned_in::<Inline>()`).
// Hand-assembling one instead names it on the value or its binding —
// `let v: ReplyOwned = ReplyOwned { .. };`
// — because the fields reach the profile through its associated container
// types, which cannot be run backwards to recover the profile from a value.
// Naming it once is also what lets each field's container infer, so no call
// site repeats a capacity. A capacity is not in this file at all except as
// what `Inline` holds: a deployment answers for the same tags from its own.

#[allow(dead_code)]
impl<'a, D> ReplyVariantIn<::sce_forge_runtime::codec::Lent<'a, D>> where D: ReplyLentStorage {
    /// Deep-copy this borrowed variant body into its owned mirror at the
    /// given storage profile. Fallible because a borrowed arm body's own
    /// projection re-checks its declared capacities (the same bounds decode
    /// enforces) — on the growable profile no check can fire.
    pub fn try_into_owned_in<S: ReplyFrom<'a>>(self) -> Result<ReplyOwnedVariant<S>, CodecError> {
        Ok(match self {
            Self::CodecZenohMsgPut(_b) => ReplyOwnedVariant::CodecZenohMsgPut(_b.try_into_owned_in::<S>()?),
            Self::CodecZenohMsgDel(_b) => ReplyOwnedVariant::CodecZenohMsgDel(_b.try_into_owned_in::<S>()?),
            Self::Default { tag, body } => ReplyOwnedVariant::Default { tag, body: body.try_into_owned_in::<S>()? },
        })
    }
}

#[allow(dead_code)]
impl<S: ReplyStorage> ReplyOwnedVariant<S> {
    /// Re-borrow this owned variant body back into its borrowed mirror —
    /// the inverse of the projection above. Reuses the borrowed view's
    /// single `encode`; the owned form deliberately carries no encode of
    /// its own.
    pub fn try_as_borrowed(&self) -> Result<ReplyVariantIn<::sce_forge_runtime::codec::Lent<'_, S>>, CodecError> {
        let mut _out = Default::default();
        self.try_as_borrowed_into(&mut _out)?;
        Ok(_out)
    }

    /// [`Self::try_as_borrowed`] into a destination the caller
    /// owns: the active arm is installed in `_out` holding its body's default
    /// and that body is projected where it sits, so the arm body is never
    /// returned up through the variant wrapper.
    ///
    /// A bounded list moves by copying its whole declared capacity, so a
    /// projection that returns one copies the declared maximum at every layer
    /// it passes through. A caller on a path where that shows projects into a
    /// destination it owns. On `Err`, `_out` holds what was projected so far.
    pub fn try_as_borrowed_into<'o>(&'o self, _out: &mut ReplyVariantIn<::sce_forge_runtime::codec::Lent<'o, S>>) -> Result<(), CodecError> {
        match self {
            ReplyOwnedVariant::CodecZenohMsgPut(_b) => {
                *_out = ReplyVariantIn::CodecZenohMsgPut(Default::default());
                if let ReplyVariantIn::CodecZenohMsgPut(_o) = _out {
                    _b.try_as_borrowed_into(_o)?;
                }
            }
            ReplyOwnedVariant::CodecZenohMsgDel(_b) => {
                *_out = ReplyVariantIn::CodecZenohMsgDel(Default::default());
                if let ReplyVariantIn::CodecZenohMsgDel(_o) = _out {
                    _b.try_as_borrowed_into(_o)?;
                }
            }
            ReplyOwnedVariant::Default { tag, body } => {
                *_out = ReplyVariantIn::Default { tag: *tag, body: Default::default() };
                if let ReplyVariantIn::Default { body: _o, .. } = _out {
                    body.try_as_borrowed_into(_o)?;
                }
            }
        }
        Ok(())
    }
}

// The lent value at any profile `D` that holds its lists: what a decode of a
// frame gives where bytes and text borrow it, `Reply<'a>` being it
// at `Inline` (docs/adr/0077 §7).
#[allow(dead_code)]
impl<'a, D> ReplyIn<::sce_forge_runtime::codec::Lent<'a, D>> where D: ReplyLentStorage {
    /// Deep-copy this borrowed zero-copy view into an owned, lifetime-free
    /// [`ReplyOwned`] held in the given storage profile. Call at
    /// a decode boundary when the decoded value must outlive the input
    /// buffer — stored in a long-lived enum, moved across an async task, or
    /// inserted by value into a bounded-collection.
    ///
    /// Fallible for profile uniformity. Every value of this type is within
    /// each declared bound, since its lists, bytes and text hold their bounds
    /// in their types (docs/adr/0077 §3), and the inline and growable profiles
    /// hold each field at its bound, so the projection does not fail on them.
    /// A profile whose capacity is below a bound raises
    /// `CodecError::CapacityExceeded` for a value it cannot hold.
    pub fn try_into_owned_in<S: ReplyFrom<'a>>(self) -> Result<ReplyOwned<S>, CodecError> {
        Ok(ReplyOwned {
            header: self.header,
            consolidation: self.consolidation,
            extensions: self.extensions.map(|_v| ::sce_forge_runtime::codec::try_collect_bounded(_v, |_e| _e.try_into_owned_in::<S>())).transpose()?,
            body: self.body.try_into_owned_in::<S>()?,
        })
    }

    // No projection at the build's default profile: on the heap-free tier
    // that is `Inline`, which holds no field whose protocol states no bound
    // (docs/adr/0077 §7). Name the profile, `try_into_owned_in::<S>()`.
}

#[allow(dead_code)]
impl<S: ReplyStorage> ReplyOwned<S> {
    /// Re-borrow this owned value back into the zero-copy borrowed view —
    /// the inverse of `try_into_owned_in`. `encode` lives only on the
    /// borrowed view (the owned form is read-only), so an owned consumer
    /// reaches it via `try_as_borrowed` then `encode` / `encode_to_vec`.
    /// Each field is projected by reference — a cheap re-borrow, not a copy.
    /// Fallible: a bounded `<sce:repeat>` / `<sce:tlv-chain>` list holding
    /// more than its declared `N` raises `CodecError::TooManyElements` — the
    /// same bound decode enforces. Only a growable profile can hold such a
    /// list; on the inline profile the source is already within bounds.
    pub fn try_as_borrowed(&self) -> Result<ReplyIn<::sce_forge_runtime::codec::Lent<'_, S>>, CodecError> {
        let mut _out = Default::default();
        self.try_as_borrowed_into(&mut _out)?;
        Ok(_out)
    }

    /// [`Self::try_as_borrowed`] into a destination the caller owns, each
    /// bounded list and embedded body projected in the field where it sits.
    ///
    /// A bounded list moves by copying its whole declared capacity, so a
    /// projection that returns one copies the declared maximum at every layer
    /// it passes through (the optional wrapper, the borrowed struct, the
    /// variant, the caller's binding), however few entries the list holds. A
    /// caller on a path where that shows projects into a destination it owns,
    /// then encodes from it. On `Err`, `_out` holds what was projected so far
    /// and is not to be read.
    pub fn try_as_borrowed_into<'o>(&'o self, _out: &mut ReplyIn<::sce_forge_runtime::codec::Lent<'o, S>>) -> Result<(), CodecError> {
        _out.header = self.header;
        _out.consolidation = self.consolidation;
        match &self.extensions {
            Some(_l) => _out.extensions.insert(Default::default()).refill(|_d| ::sce_forge_runtime::codec::try_project_bounded_into(_d, _l.inner(), |_e| Ok(_e.as_borrowed())))?,
            None => _out.extensions = None,
        }
        self.body.try_as_borrowed_into(&mut _out.body)?;
        Ok(())
    }

    /// Move this value to a different storage profile — growable to inline
    /// when handing it to a path that must not allocate, or inline to
    /// growable when it is leaving that path.
    ///
    /// A checked projection through the borrowed view, not a re-decode: the
    /// bytes are copied once and every destination capacity is enforced, so
    /// a value that cannot fit the target profile is rejected here rather
    /// than truncated.
    pub fn transcode_in<D: for<'x> ReplyFrom<'x>>(&self) -> Result<ReplyOwned<D>, CodecError> {
        self.try_as_borrowed()?.try_into_owned_in::<D>()
    }
}

#[allow(dead_code)]
impl<'a, D> ReplyVariantIn<::sce_forge_runtime::codec::Lent<'a, D>> where D: ReplyLentStorage {
    /// The projection above, with the profile's byte and text containers made
    /// from `origin` — what the decoded bytes were taken from.
    pub fn try_into_owned_in_origin<S: ReplyStorage + ::sce_forge_runtime::codec::OriginStorage>(self, origin: &<S as ::sce_forge_runtime::codec::OriginStorage>::Origin) -> Result<ReplyOwnedVariant<S>, CodecError> {
        Ok(match self {
            Self::CodecZenohMsgPut(_b) => ReplyOwnedVariant::CodecZenohMsgPut(_b.try_into_owned_in_origin::<S>(origin)?),
            Self::CodecZenohMsgDel(_b) => ReplyOwnedVariant::CodecZenohMsgDel(_b.try_into_owned_in_origin::<S>(origin)?),
            Self::Default { tag, body } => ReplyOwnedVariant::Default { tag, body: body.try_into_owned_in_origin::<S>(origin)? },
        })
    }
}

#[allow(dead_code)]
impl<'a, D> ReplyIn<::sce_forge_runtime::codec::Lent<'a, D>> where D: ReplyLentStorage {
    /// Project this borrowed view into an owned [`ReplyOwned`]
    /// whose byte and text containers are made by the profile's
    /// `OriginStorage` from each slice AND `origin`, the buffer the
    /// view was decoded from. A profile that shares that buffer builds
    /// containers that refer back to it instead of copying out of it; what the
    /// origin is, and what to do with a slice that does not come from it, is
    /// the profile's to say.
    ///
    /// `try_into_owned_in` stays the copying projection. Every codec this one
    /// embeds, repeats or dispatches to must have been generated with
    /// `--owned-origin` as well.
    pub fn try_into_owned_in_origin<S: ReplyStorage + ::sce_forge_runtime::codec::OriginStorage>(self, origin: &<S as ::sce_forge_runtime::codec::OriginStorage>::Origin) -> Result<ReplyOwned<S>, CodecError> {
        Ok(ReplyOwned {
            header: self.header,
            consolidation: self.consolidation,
            extensions: self.extensions.map(|_v| ::sce_forge_runtime::codec::try_collect_bounded(_v, |_e| _e.try_into_owned_in_origin::<S>(origin))).transpose()?,
            body: self.body.try_into_owned_in_origin::<S>(origin)?,
        })
    }
}
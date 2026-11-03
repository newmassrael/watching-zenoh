// SCE-MAP: oam:50 :: _forge_body

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

use super::ext_unit::ExtUnit;
use super::ext_zint::ExtZint;

use sce_forge_runtime::codec::{Bounded, ListView, ListWalk};
use super::ext_entry::ExtEntryView;
use super::ext_unit::ExtUnitView;
use super::ext_zint::ExtZintView;
use super::ext_zbuf::ExtZbufView;

/// A tag `Oam` names no arm for, which its default arm holds: a
/// value inside the 2 bits the tag is read from and outside
/// every arm's tag (docs/adr/0065 §6 R3). A default arm is written with the tag
/// it holds and read back as the default arm, so no tag it holds is refused.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OamUnknownTag(u8);

#[allow(dead_code)]
impl OamUnknownTag {
    /// `tag` as a tag no arm names, or `None` when it is past the tag's bits or
    /// is an arm's.
    pub const fn new(tag: u8) -> Option<Self> {
        match tag {
            0..=2 => None,
            _ if tag > 3 => None,
            _ => Some(Self(tag)),
        }
    }

    /// The tag.
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl ::sce_forge_runtime::codec::UnknownTag for OamUnknownTag {
    const SPACE: ::sce_forge_runtime::codec::TagSpace =
        ::sce_forge_runtime::codec::TagSpace::new(3, &[(0, 2)]);

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
use super::ext_zbuf::ExtZbufOwned;
/// The field `extensions` of `Oam`, which a storage profile
/// answers for by this type.
#[allow(dead_code)]
pub struct OamExtensionsField;

// `Inline` does not answer for `extensions`: the protocol states no bound of
// it, so it is held only by a profile whose container grows, or by a deployment
// that gives it a capacity (docs/adr/0077 §7).

/// What `OamIn` and the codecs it holds ask of a storage profile.
#[allow(dead_code)]
pub trait OamStorage: ::core::fmt::Debug + Clone + PartialEq + ::sce_forge_runtime::codec::HoldsList<OamExtensionsField> + super::ext_entry::ExtEntryStorage + super::ext_zbuf::ExtZbufStorage {}

impl<S: ::core::fmt::Debug + Clone + PartialEq + ::sce_forge_runtime::codec::HoldsList<OamExtensionsField> + super::ext_entry::ExtEntryStorage + super::ext_zbuf::ExtZbufStorage> OamStorage for S {}

/// What `OamIn<Lent<'a, D>>` asks of the profile `D`: how it holds
/// the lists of `Oam` and of the codecs it holds, since the lent
/// form borrows every byte string and text from the frame (docs/adr/0077 §7).
#[allow(dead_code)]
pub trait OamLentStorage: ::core::fmt::Debug + Clone + PartialEq + ::sce_forge_runtime::codec::HoldsList<OamExtensionsField> + super::ext_entry::ExtEntryLentStorage + super::ext_zbuf::ExtZbufLentStorage {}

impl<D: ::core::fmt::Debug + Clone + PartialEq + ::sce_forge_runtime::codec::HoldsList<OamExtensionsField> + super::ext_entry::ExtEntryLentStorage + super::ext_zbuf::ExtZbufLentStorage> OamLentStorage for D {}

/// What a decode of a frame of the lifetime `'f` asks of a storage profile
/// beside OamStorage: how it stores each field of that frame.
#[allow(dead_code)]
pub trait OamFrom<'f>: OamStorage + super::ext_entry::ExtEntryFrom<'f> + super::ext_zbuf::ExtZbufFrom<'f> {}

impl<'f, S: OamStorage + super::ext_entry::ExtEntryFrom<'f> + super::ext_zbuf::ExtZbufFrom<'f>> OamFrom<'f> for S {}

// `OamIn<S>` is the one value this codec has, at the storage
// profile `S` (docs/adr/0077 §7). `Oam<'a>` is it on `Lent`, which
// borrows bytes and text from the frame, and `OamOwned<S>` names it
// at a profile that holds them.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct OamIn<S: OamStorage> {
    pub header: u8,
    pub id: u64,
    pub extensions: Option<::sce_forge_runtime::codec::Bounded<<S as ::sce_forge_runtime::codec::HoldsList<OamExtensionsField>>::List<ExtEntryOwned<S>>, { usize::MAX }, 1>>,
    pub body: OamVariantIn<S>,
}

/// The eager form: bytes and text borrowed from the frame, lists held inline.
#[allow(dead_code)]
pub type Oam<'a> = OamIn<::sce_forge_runtime::codec::Lent<'a>>;

/// The value at a profile that holds its bytes and text, named
/// with the profile: the build's default on the heap-free tier is `Inline`, which
/// holds no field whose protocol states no bound (docs/adr/0077 §7).
#[allow(dead_code)]
pub type OamOwned<S> = OamIn<S>;

impl<S: OamStorage> Default for OamIn<S> {
    fn default() -> Self {
        Self {
            header: 0x1fu8,
            id: Default::default(),
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
pub enum OamVariantIn<S: OamStorage> {
    CodecZenohExtUnit(ExtUnit),
    CodecZenohExtZint(ExtZint),
    CodecZenohExtZbuf(ExtZbufOwned<S>),
    Default {
        tag: OamUnknownTag,
        body: ExtUnit,
    },
}

#[allow(dead_code)]
pub type OamVariant<'a> = OamVariantIn<::sce_forge_runtime::codec::Lent<'a>>;

#[allow(dead_code)]
pub type OamOwnedVariant<S> = OamVariantIn<S>;

impl<S: OamStorage> Default for OamVariantIn<S> {
    fn default() -> Self {
        // RFC variant-default-uniformity: pick the declared default
        // arm (`<sce:arm default="true"/>`) so a freshly-constructed
        // envelope round-trips byte-exactly through `encode() ->
        // decode()` — pairs with the inner codec's `<sce:flag value=>`
        // -baked `Default::default()` to close the dispatch loop.
        Self::CodecZenohExtUnit(ExtUnit::default())
    }
}

#[allow(dead_code)]
impl<S: OamStorage> OamIn<S> {
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
    pub fn decode<'f>(cursor: &mut SceCursor<'f>) -> Result<Self, CodecError> where S: OamFrom<'f> {
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
    pub fn decode_into<'f>(cursor: &mut SceCursor<'f>, _out: &mut Self) -> Result<(), CodecError> where S: OamFrom<'f> {
        // A form past its capacity stopped where it could not store, so the
        // frame is judged by what cannot run out, and only a frame that parses
        // is one this node cannot hold (docs/adr/0077 §7). Any profile may hold
        // less than a bound, so this stands on every codec that takes one.
        let mut _frame = *cursor;
        match Self::store_into(cursor, _out) {
            Err(CodecError::CapacityExceeded) => {
                OamView::decode(&mut _frame)?;
                Err(CodecError::CapacityExceeded)
            }
            stored => stored,
        }
    }

    /// The reading of [`Self::decode_into`], which stops where a field is past
    /// its capacity.
    fn store_into<'f>(cursor: &mut SceCursor<'f>, _out: &mut Self) -> Result<(), CodecError> where S: OamFrom<'f> {
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
        let id = cursor.read_vle_u64()?;
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
        // Dispatch on the tag field; each arm decodes its body codec
        // from the cursor. The default arm (when declared) carries the
        // runtime tag value so encode can round-trip it back onto the
        // wire.
        // Each arm is installed in `_out.body` holding its body's default and
        // that body is decoded where it sits, so no arm body is returned up
        // through the variant wrapper.
        match (header >> 5) & 0x03 {
            0u8 => {
                _out.body = OamVariantIn::CodecZenohExtUnit(ExtUnit::default());
                if let OamVariantIn::CodecZenohExtUnit(_b) = &mut _out.body {
                    ExtUnit::decode_into(cursor, _b)?;
                }
            }
            1u8 => {
                _out.body = OamVariantIn::CodecZenohExtZint(ExtZint::default());
                if let OamVariantIn::CodecZenohExtZint(_b) = &mut _out.body {
                    ExtZint::decode_into(cursor, _b)?;
                }
            }
            2u8 => {
                _out.body = OamVariantIn::CodecZenohExtZbuf(ExtZbufOwned::<S>::default());
                if let OamVariantIn::CodecZenohExtZbuf(_b) = &mut _out.body {
                    ExtZbufOwned::<S>::decode_into(cursor, _b)?;
                }
            }
            other => {
                _out.body = OamVariantIn::Default {
                    tag: OamUnknownTag(other),
                    body: ExtUnit::default(),
                };
                if let OamVariantIn::Default { body: _b, .. } = &mut _out.body {
                    ExtUnit::decode_into(cursor, _b)?;
                }
            }
        }
        _out.header = header;
        _out.id = id;
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

    pub fn enc(&self) -> u8 {
        (self.header >> 5) & 0x03
    }

    pub fn set_enc(&mut self, v: u8) {
        self.header = (self.header & !0x60) | ((v & 0x03) << 5);
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
        OamWire::encode_source(self, w)
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

/// The arm of `Oam`'s variant a value holds, each arm's body as the
/// source it says. The tag is not among them: `Oam` derives it from
/// the arm, as it derives a length, and a default arm presents the tag
/// it could not name.
// A default arm's tag is read by the codec that embeds this one and
// derives its own carrier bits from the arm, which not every build uses.
#[allow(dead_code)]
pub enum OamVariantSource<'s, A0: ?Sized, A1: ?Sized, A2: ?Sized, D: ?Sized> {
    CodecZenohExtUnit(&'s A0),
    CodecZenohExtZint(&'s A1),
    CodecZenohExtZbuf(&'s A2),
    Default { tag: OamUnknownTag, body: &'s D },
}

impl<'s, A0: ?Sized, A1: ?Sized, A2: ?Sized, D: ?Sized> OamVariantSource<'s, A0, A1, A2, D> {
    /// The tag of the arm this is: the value the document gives a known
    /// arm, and the tag a default arm holds. It is the tag the encode
    /// writes, or the one a caller hands the decode for a variant whose
    /// wire form carries none.
    pub fn tag(&self) -> u8 {
        match self {
            Self::CodecZenohExtUnit(_) => 0,
            Self::CodecZenohExtZint(_) => 1,
            Self::CodecZenohExtZbuf(_) => 2,
            Self::Default { tag, .. } => tag.get(),
        }
    }
}

// ── Source (ADR 0058) ────────────────────────────────────────────────
/// What a value of `Oam` says: its presented fields. A length, a count
/// or the flag a gated field is announced by is not among them; the
/// encode computes those from what is ([`OamWire::encode_source`]).
pub trait OamSource {
    /// The `header` field.
    fn header(&self) -> u8;
    /// The `id` field.
    fn id(&self) -> u64;
    /// The `extensions` field.
    fn extensions(&self) -> Option<::sce_forge_runtime::codec::BoundedIter<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone, { usize::MAX }, 1>>;
    /// The arm of the variant this value holds.
    fn body(&self) -> OamVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::ext_zbuf::ExtZbufSource, impl super::ext_unit::ExtUnitSource>;
}

impl<T: OamSource + ?Sized> OamSource for &T {
    fn header(&self) -> u8 {
        (**self).header()
    }
    fn id(&self) -> u64 {
        (**self).id()
    }
    fn extensions(&self) -> Option<::sce_forge_runtime::codec::BoundedIter<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone, { usize::MAX }, 1>> {
        (**self).extensions()
    }
    fn body(&self) -> OamVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::ext_zbuf::ExtZbufSource, impl super::ext_unit::ExtUnitSource> {
        (**self).body()
    }
}

/// The arm of `Oam`'s variant that OamParts holds.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum OamPartsBody<'a> {
    CodecZenohExtUnit(&'a super::ext_unit::ExtUnitParts),
    CodecZenohExtZint(&'a super::ext_zint::ExtZintParts),
    CodecZenohExtZbuf(&'a super::ext_zbuf::ExtZbufParts<'a>),
    /// The tag the grammar could not name, and the body it holds.
    Default { tag: OamUnknownTag, body: &'a super::ext_unit::ExtUnitParts },
}

/// A value of `Oam` held in the types a caller already has: a source
/// ([`OamSource`]) whose lists are slices within their bounds and whose
/// bodies are references.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct OamParts<'a> {
    /// The `header` field.
    pub header: u8,
    /// The `id` field.
    pub id: u64,
    /// The `extensions` field.
    pub extensions: Option<::sce_forge_runtime::codec::Bounded<&'a [super::ext_entry::ExtEntryParts<'a>], { usize::MAX }, 1>>,
    /// The arm of the variant this value holds.
    pub body: OamPartsBody<'a>,
}

impl<'a> OamSource for OamParts<'a> {
    fn header(&self) -> u8 {
        self.header
    }
    fn id(&self) -> u64 {
        self.id
    }
    fn extensions(&self) -> Option<::sce_forge_runtime::codec::BoundedIter<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone, { usize::MAX }, 1>> {
        self.extensions.as_ref().map(|_l| _l.iter())
    }
    fn body(&self) -> OamVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::ext_zbuf::ExtZbufSource, impl super::ext_unit::ExtUnitSource> {
        match &self.body {
            OamPartsBody::CodecZenohExtUnit(_b) => OamVariantSource::CodecZenohExtUnit(*_b),
            OamPartsBody::CodecZenohExtZint(_b) => OamVariantSource::CodecZenohExtZint(*_b),
            OamPartsBody::CodecZenohExtZbuf(_b) => OamVariantSource::CodecZenohExtZbuf(*_b),
            OamPartsBody::Default { tag, body } => OamVariantSource::Default { tag: *tag, body: *body },
        }
    }
}

impl<S: OamStorage> OamSource for OamOwned<S> {
    fn header(&self) -> u8 {
        self.header
    }
    fn id(&self) -> u64 {
        self.id
    }
    fn extensions(&self) -> Option<::sce_forge_runtime::codec::BoundedIter<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone, { usize::MAX }, 1>> {
        self.extensions.as_ref().map(|_l| _l.list_iter())
    }
    fn body(&self) -> OamVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::ext_zbuf::ExtZbufSource, impl super::ext_unit::ExtUnitSource> {
        match &self.body {
            OamOwnedVariant::CodecZenohExtUnit(_b) => OamVariantSource::CodecZenohExtUnit(_b),
            OamOwnedVariant::CodecZenohExtZint(_b) => OamVariantSource::CodecZenohExtZint(_b),
            OamOwnedVariant::CodecZenohExtZbuf(_b) => OamVariantSource::CodecZenohExtZbuf(_b),
            OamOwnedVariant::Default { tag, body } => OamVariantSource::Default { tag: *tag, body },
        }
    }
}

impl<'a> OamSource for OamView<'a> {
    fn header(&self) -> u8 {
        self.header
    }
    fn id(&self) -> u64 {
        self.id
    }
    fn extensions(&self) -> Option<::sce_forge_runtime::codec::BoundedIter<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone, { usize::MAX }, 1>> {
        self.extensions.as_ref().map(|_l| _l.iter())
    }
    fn body(&self) -> OamVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::ext_zbuf::ExtZbufSource, impl super::ext_unit::ExtUnitSource> {
        match &self.body {
            OamViewVariant::CodecZenohExtUnit(_b) => OamVariantSource::CodecZenohExtUnit(_b),
            OamViewVariant::CodecZenohExtZint(_b) => OamVariantSource::CodecZenohExtZint(_b),
            OamViewVariant::CodecZenohExtZbuf(_b) => OamVariantSource::CodecZenohExtZbuf(_b),
            OamViewVariant::Default { tag, body } => OamVariantSource::Default { tag: *tag, body },
        }
    }
}

/// The codec `Oam` itself: what writes a value read through
/// [`OamSource`], holding no value and naming no storage profile. Every
/// form of the value, a parent and a view write through it, so a profile
/// that cannot hold some field is never asked for here (docs/adr/0077 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OamWire;

#[allow(dead_code)]
impl OamWire {
    /// Encode what `src` says into the caller-owned sink: the bytes
    /// `Oam::encode` writes for the value it holds, read through
    /// [`OamSource`]. A length, a count or a gate flag is computed from what
    /// `src` presents. Every value `src` can present has a frame, so the
    /// only error is the sink's (docs/adr/0065).
    pub fn encode_source<S: OamSource + ?Sized, K: SceSink>(src: &S, w: &mut K) -> Result<(), K::Error> {
        Self::write_source(src, w)
    }

    /// The tag of the arm `src` holds ([`OamVariantSource::tag`]).
    pub fn tag_of<S: OamSource + ?Sized>(src: &S) -> u8 {
        src.body().tag()
    }

    /// [`Self::encode_source`] without the guard a parent has already made.
    #[doc(hidden)]
    pub fn write_source<S: OamSource + ?Sized, K: SceSink>(src: &S, w: &mut K) -> Result<(), K::Error> {
        let _k_extensions: usize = src.extensions().map_or(0, |_l| _l.len());
        let _d_header_enc: u8 = src.body().tag();
        let _p_header_z_0: bool = src.extensions().is_some();
        let _c_header: u8 = (((src.header() & !0x60) | (_d_header_enc << 5)) & !0x80) | (u8::from(_p_header_z_0) << 7);
        w.write_u8(_c_header)?;
        w.write_vle_u64(src.id())?;
        if let Some(_v) = src.extensions() {
            for (_i, _e) in _v.enumerate() {
                super::ext_entry::ExtEntryWire::write_source_in(&_e, w, &super::ext_entry::ExtEntryOverrides::header_z(_i + 1 < _k_extensions))?;
            }
        }
        match src.body() {
            OamVariantSource::CodecZenohExtUnit(_b) => super::ext_unit::ExtUnitWire::write_source(_b, w)?,
            OamVariantSource::CodecZenohExtZint(_b) => super::ext_zint::ExtZintWire::write_source(_b, w)?,
            OamVariantSource::CodecZenohExtZbuf(_b) => super::ext_zbuf::ExtZbufWire::write_source(_b, w)?,
            OamVariantSource::Default { body: _b, .. } => super::ext_unit::ExtUnitWire::write_source(_b, w)?,
        }
        Ok(())
    }

    /// The bytes [`Self::write_source`] writes for `src`, counted with
    /// nothing written.
    #[doc(hidden)]
    pub fn count_source<S: OamSource + ?Sized>(src: &S) -> usize {
        let mut _c = ::sce_forge_runtime::codec::CountSink::new();
        let Ok(()) = Self::write_source(src, &mut _c);
        _c.len()
    }
}

impl<S: OamSource + ?Sized> ::sce_forge_runtime::codec::SourceWrite<S> for OamWire {
    type Error<E> = E;

    fn write<K: SceSink>(src: &S, w: &mut K) -> Result<(), K::Error> where CodecError: From<K::Error> {
        Self::write_source(src, w)
    }
}

#[allow(dead_code)]
impl OamWire {
    /// The size of the frame [`Self::encode_source`] writes for `src`, found
    /// with nothing written: the encode refuses no value, so neither does
    /// this. The result writes the frame into a window of exactly that size
    /// and cannot fail.
    pub fn measure<S: OamSource + ?Sized>(src: &S) -> ::sce_forge_runtime::codec::Measured<'_, Self, S> {
        let Ok(measured) = ::sce_forge_runtime::codec::measure(src);
        measured
    }

    /// Write `src` into `window` in one pass and return the bytes it is, for a
    /// window as large as the caller can spare. On an error the window holds a
    /// prefix to discard; see [`::sce_forge_runtime::codec::write_window`].
    pub fn write_window<S: OamSource + ?Sized>(src: &S, window: &mut [u8]) -> Result<usize, CodecError> {
        let mut sink = ::sce_forge_runtime::codec::SliceSink::new(window);
        Self::write_source(src, &mut sink)?;
        Ok(sink.position())
    }
}


// ── View (ADR 0049) ──────────────────────────────────────────────────
// `OamView` is what a decode of `Oam` learned, not a
// copy of what the wire repeated: a scalar, a string or a bytes field is held
// as `Oam` holds it, an embedded body or a variant arm as its
// own view, and a bounded list as the frame it was read from, how many entries
// it holds and what a walk needs to read them again (`ListView`). Its size
// depends on the number of fields and not on any `sce:max-count`, so moving
// one copies a few words however long its lists may be. `decode` refuses the
// frames `Oam::decode` refuses, with the same error: the entries
// are decoded once to check them, and a walk afterwards cannot fail.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum OamViewVariant<'a> {
    CodecZenohExtUnit(ExtUnitView),
    CodecZenohExtZint(ExtZintView),
    CodecZenohExtZbuf(ExtZbufView<'a>),
    Default {
        tag: OamUnknownTag,
        body: ExtUnitView,
    },
}

impl<'a> Default for OamViewVariant<'a> {
    fn default() -> Self {
        Self::CodecZenohExtUnit(ExtUnitView::default())
    }
}

#[allow(dead_code)]
pub struct OamExtensionsWalk;

impl ListWalk<0> for OamExtensionsWalk {
    type Entry<'b> = ExtEntryView<'b>;

    fn decode<'b>(_c: &mut SceCursor<'b>, _a: &[u8; 0]) -> Result<Self::Entry<'b>, CodecError> {
        ExtEntryView::decode(_c)
    }

    fn advance(_e: &Self::Entry<'_>, _s: &mut [u8; 0]) {  }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct OamView<'a> {
    pub header: u8,
    pub id: u64,
    pub extensions: Option<Bounded<ListView<'a, OamExtensionsWalk, 0>, { usize::MAX }, 1>>,
    pub body: OamViewVariant<'a>,
}

impl<'a> Default for OamView<'a> {
    fn default() -> Self {
        Self {
            header: 0x1fu8,
            id: Default::default(),
            extensions: Default::default(),
            body: OamViewVariant::default(),
        }
    }
}

#[allow(dead_code)]
impl<'a> OamView<'a> {
    /// A view with every field at its own type's [`Default`]: the destination
    /// [`Self::decode_into`] fills.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode the next frame from `cursor`: the bytes, the bounds and the
    /// errors of [`Oam::decode`], held as a view. On success the
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
        let id = cursor.read_vle_u64()?;
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
        // Dispatch on the tag field; each arm decodes its body codec
        // from the cursor. The default arm (when declared) carries the
        // runtime tag value so encode can round-trip it back onto the
        // wire.
        // Each arm is installed in `_out.body` holding its body's default and
        // that body is decoded where it sits, so no arm body is returned up
        // through the variant wrapper.
        match (header >> 5) & 0x03 {
            0u8 => {
                _out.body = OamViewVariant::CodecZenohExtUnit(ExtUnitView::default());
                if let OamViewVariant::CodecZenohExtUnit(_b) = &mut _out.body {
                    ExtUnitView::decode_into(cursor, _b)?;
                }
            }
            1u8 => {
                _out.body = OamViewVariant::CodecZenohExtZint(ExtZintView::default());
                if let OamViewVariant::CodecZenohExtZint(_b) = &mut _out.body {
                    ExtZintView::decode_into(cursor, _b)?;
                }
            }
            2u8 => {
                _out.body = OamViewVariant::CodecZenohExtZbuf(ExtZbufView::default());
                if let OamViewVariant::CodecZenohExtZbuf(_b) = &mut _out.body {
                    ExtZbufView::decode_into(cursor, _b)?;
                }
            }
            other => {
                _out.body = OamViewVariant::Default {
                    tag: OamUnknownTag(other),
                    body: ExtUnitView::default(),
                };
                if let OamViewVariant::Default { body: _b, .. } = &mut _out.body {
                    ExtUnitView::decode_into(cursor, _b)?;
                }
            }
        }
        _out.header = header;
        _out.id = id;
        Ok(())
    }

    /// Fill `_out`, the builder form [`Oam`] a sender fills and
    /// encodes, with what this view says: every field, each embedded body, the
    /// variant arm, and each list entry as the walk yields it, built in the
    /// destination where it will live. Fails only where the destination cannot
    /// hold it, which a destination of the same declared bounds does.
    // The name every view's method has (ADR 0049), which borrows because a
    // view is read, not consumed. Clippy leaves an exported method's name
    // alone; a crate that includes this module privately is asked to rename
    // it, and the one name is what lets a codec reach every view it holds.
    #[allow(clippy::wrong_self_convention)]
    pub fn into_builder<D>(&self, _out: &mut OamIn<::sce_forge_runtime::codec::Lent<'a, D>>) -> Result<(), CodecError> where D: OamLentStorage {
        _out.header = self.header;
        _out.id = self.id;
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
            OamViewVariant::CodecZenohExtUnit(_b) => {
                _out.body = OamVariantIn::CodecZenohExtUnit(Default::default());
                if let OamVariantIn::CodecZenohExtUnit(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
            OamViewVariant::CodecZenohExtZint(_b) => {
                _out.body = OamVariantIn::CodecZenohExtZint(Default::default());
                if let OamVariantIn::CodecZenohExtZint(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
            OamViewVariant::CodecZenohExtZbuf(_b) => {
                _out.body = OamVariantIn::CodecZenohExtZbuf(Default::default());
                if let OamVariantIn::CodecZenohExtZbuf(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
            OamViewVariant::Default { tag, body } => {
                _out.body = OamVariantIn::Default {
                    tag: *tag,
                    body: Default::default(),
                };
                if let OamVariantIn::Default { body: _o, .. } = &mut _out.body {
                    body.into_builder(_o)?;
                }
            }
        }
        Ok(())
    }


    /// Encode what this view says into the caller-owned sink: the bytes
    /// [`Oam::encode`] writes for the value [`Self::into_builder`]
    /// fills, written straight from the view, walking each list, without the
    /// builder. It writes the canonical wire, not the frame the view was decoded
    /// from, so a frame `decode` accepted in a form that is not canonical is
    /// not passed on as it came.
    pub fn encode<S: SceSink>(&self, w: &mut S) -> Result<(), S::Error> {
        OamWire::encode_source(self, w)
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

    pub fn enc(&self) -> u8 {
        (self.header >> 5) & 0x03
    }

    pub fn z(&self) -> bool {
        (self.header & 0x80) != 0
    }

}

// ── Owned projection (storage-parameterised native form) ─────────────
// `Oam<'a>` above is a zero-copy view borrowing the decode
// buffer. Consumers that persist a decoded value beyond the buffer's
// lifetime — including the self-contained bounded-collection that stores
// elements by value — call `.try_into_owned()` for this lifetime-free
// `OamOwned`. The rkyv-style Archived(borrowed) ↔ native
// (owned) split, both generated from the one SCXML source (SSOT).
//
// The owned form is parameterised by a storage profile rather than fixed at
// build-configuration time: `OamOwned<Heap>` holds growable
// containers with the declared capacities advisory, `OamOwned<Inline>`
// holds every field inline at its declared capacity and never allocates, and
// both exist in the same binary. `OamOwned` alone is the build's
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
// `let v: OamOwned = OamOwned { .. };`
// — because the fields reach the profile through its associated container
// types, which cannot be run backwards to recover the profile from a value.
// Naming it once is also what lets each field's container infer, so no call
// site repeats a capacity. A capacity is not in this file at all except as
// what `Inline` holds: a deployment answers for the same tags from its own.

#[allow(dead_code)]
impl<'a, D> OamVariantIn<::sce_forge_runtime::codec::Lent<'a, D>> where D: OamLentStorage {
    /// Deep-copy this borrowed variant body into its owned mirror at the
    /// given storage profile. Fallible because a borrowed arm body's own
    /// projection re-checks its declared capacities (the same bounds decode
    /// enforces) — on the growable profile no check can fire.
    pub fn try_into_owned_in<S: OamFrom<'a>>(self) -> Result<OamOwnedVariant<S>, CodecError> {
        Ok(match self {
            Self::CodecZenohExtUnit(_b) => OamOwnedVariant::CodecZenohExtUnit(_b),
            Self::CodecZenohExtZint(_b) => OamOwnedVariant::CodecZenohExtZint(_b),
            Self::CodecZenohExtZbuf(_b) => OamOwnedVariant::CodecZenohExtZbuf(_b.try_into_owned_in::<S>()?),
            Self::Default { tag, body } => OamOwnedVariant::Default { tag, body },
        })
    }
}

#[allow(dead_code)]
impl<S: OamStorage> OamOwnedVariant<S> {
    /// Re-borrow this owned variant body back into its borrowed mirror —
    /// the inverse of the projection above. Reuses the borrowed view's
    /// single `encode`; the owned form deliberately carries no encode of
    /// its own.
    pub fn as_borrowed(&self) -> OamVariantIn<::sce_forge_runtime::codec::Lent<'_, S>> {
        let mut _out = Default::default();
        self.as_borrowed_into(&mut _out);
        _out
    }

    /// [`Self::as_borrowed`] into a destination the caller
    /// owns: the active arm is installed in `_out` holding its body's default
    /// and that body is projected where it sits, so the arm body is never
    /// returned up through the variant wrapper.
    ///
    /// A bounded list moves by copying its whole declared capacity, so a
    /// projection that returns one copies the declared maximum at every layer
    /// it passes through. A caller on a path where that shows projects into a
    /// destination it owns. On `Err`, `_out` holds what was projected so far.
    pub fn as_borrowed_into<'o>(&'o self, _out: &mut OamVariantIn<::sce_forge_runtime::codec::Lent<'o, S>>) {
        match self {
            OamOwnedVariant::CodecZenohExtUnit(_b) => {
                *_out = OamVariantIn::CodecZenohExtUnit(Default::default());
                if let OamVariantIn::CodecZenohExtUnit(_o) = _out {
                    *_o = _b.clone();
                }
            }
            OamOwnedVariant::CodecZenohExtZint(_b) => {
                *_out = OamVariantIn::CodecZenohExtZint(Default::default());
                if let OamVariantIn::CodecZenohExtZint(_o) = _out {
                    *_o = _b.clone();
                }
            }
            OamOwnedVariant::CodecZenohExtZbuf(_b) => {
                *_out = OamVariantIn::CodecZenohExtZbuf(Default::default());
                if let OamVariantIn::CodecZenohExtZbuf(_o) = _out {
                    _b.as_borrowed_into(_o);
                }
            }
            OamOwnedVariant::Default { tag, body } => {
                *_out = OamVariantIn::Default { tag: *tag, body: Default::default() };
                if let OamVariantIn::Default { body: _o, .. } = _out {
                    *_o = body.clone();
                }
            }
        }
        
    }
}

// The lent value at any profile `D` that holds its lists: what a decode of a
// frame gives where bytes and text borrow it, `Oam<'a>` being it
// at `Inline` (docs/adr/0077 §7).
#[allow(dead_code)]
impl<'a, D> OamIn<::sce_forge_runtime::codec::Lent<'a, D>> where D: OamLentStorage {
    /// Deep-copy this borrowed zero-copy view into an owned, lifetime-free
    /// [`OamOwned`] held in the given storage profile. Call at
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
    pub fn try_into_owned_in<S: OamFrom<'a>>(self) -> Result<OamOwned<S>, CodecError> {
        Ok(OamOwned {
            header: self.header,
            id: self.id,
            extensions: self.extensions.map(|_v| ::sce_forge_runtime::codec::try_collect_bounded(_v, |_e| _e.try_into_owned_in::<S>())).transpose()?,
            body: self.body.try_into_owned_in::<S>()?,
        })
    }

    // No projection at the build's default profile: on the heap-free tier
    // that is `Inline`, which holds no field whose protocol states no bound
    // (docs/adr/0077 §7). Name the profile, `try_into_owned_in::<S>()`.
}

#[allow(dead_code)]
impl<S: OamStorage> OamOwned<S> {
    /// Re-borrow this owned value back into the zero-copy borrowed view —
    /// the inverse of `try_into_owned_in`. `encode` lives only on the
    /// borrowed view (the owned form is read-only), so an owned consumer
    /// reaches it via `try_as_borrowed` then `encode` / `encode_to_vec`.
    /// Each field is projected by reference — a cheap re-borrow, not a copy.
    /// Fallible: a bounded `<sce:repeat>` / `<sce:tlv-chain>` list holding
    /// more than its declared `N` raises `CodecError::TooManyElements` — the
    /// same bound decode enforces. Only a growable profile can hold such a
    /// list; on the inline profile the source is already within bounds.
    pub fn try_as_borrowed(&self) -> Result<OamIn<::sce_forge_runtime::codec::Lent<'_, S>>, CodecError> {
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
    pub fn try_as_borrowed_into<'o>(&'o self, _out: &mut OamIn<::sce_forge_runtime::codec::Lent<'o, S>>) -> Result<(), CodecError> {
        _out.header = self.header;
        _out.id = self.id;
        match &self.extensions {
            Some(_l) => _out.extensions.insert(Default::default()).refill(|_d| ::sce_forge_runtime::codec::try_project_bounded_into(_d, _l.inner(), |_e| Ok(_e.as_borrowed())))?,
            None => _out.extensions = None,
        }
        self.body.as_borrowed_into(&mut _out.body);
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
    pub fn transcode_in<D: for<'x> OamFrom<'x>>(&self) -> Result<OamOwned<D>, CodecError> {
        self.try_as_borrowed()?.try_into_owned_in::<D>()
    }
}

#[allow(dead_code)]
impl<'a, D> OamVariantIn<::sce_forge_runtime::codec::Lent<'a, D>> where D: OamLentStorage {
    /// The projection above, with the profile's byte and text containers made
    /// from `origin` — what the decoded bytes were taken from.
    pub fn try_into_owned_in_origin<S: OamStorage + ::sce_forge_runtime::codec::OriginStorage>(self, origin: &<S as ::sce_forge_runtime::codec::OriginStorage>::Origin) -> Result<OamOwnedVariant<S>, CodecError> {
        Ok(match self {
            Self::CodecZenohExtUnit(_b) => OamOwnedVariant::CodecZenohExtUnit(_b),
            Self::CodecZenohExtZint(_b) => OamOwnedVariant::CodecZenohExtZint(_b),
            Self::CodecZenohExtZbuf(_b) => OamOwnedVariant::CodecZenohExtZbuf(_b.try_into_owned_in_origin::<S>(origin)?),
            Self::Default { tag, body } => OamOwnedVariant::Default { tag, body },
        })
    }
}

#[allow(dead_code)]
impl<'a, D> OamIn<::sce_forge_runtime::codec::Lent<'a, D>> where D: OamLentStorage {
    /// Project this borrowed view into an owned [`OamOwned`]
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
    pub fn try_into_owned_in_origin<S: OamStorage + ::sce_forge_runtime::codec::OriginStorage>(self, origin: &<S as ::sce_forge_runtime::codec::OriginStorage>::Origin) -> Result<OamOwned<S>, CodecError> {
        Ok(OamOwned {
            header: self.header,
            id: self.id,
            extensions: self.extensions.map(|_v| ::sce_forge_runtime::codec::try_collect_bounded(_v, |_e| _e.try_into_owned_in_origin::<S>(origin))).transpose()?,
            body: self.body.try_into_owned_in_origin::<S>(origin)?,
        })
    }
}
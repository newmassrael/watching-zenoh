// SCE-MAP: ext_entry:60 :: _forge_body

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
use super::ext_zbuf::ExtZbuf;

use super::ext_unit::ExtUnitView;
use super::ext_zint::ExtZintView;
use super::ext_zbuf::ExtZbufView;

/// A tag `ExtEntry` names no arm for, which its default arm holds: a
/// value inside the 2 bits the tag is read from and outside
/// every arm's tag (docs/adr/0065 §6 R3). A default arm is written with the tag
/// it holds and read back as the default arm, so no tag it holds is refused.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtEntryUnknownTag(u8);

#[allow(dead_code)]
impl ExtEntryUnknownTag {
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

impl ::sce_forge_runtime::codec::UnknownTag for ExtEntryUnknownTag {
    const SPACE: ::sce_forge_runtime::codec::TagSpace =
        ::sce_forge_runtime::codec::TagSpace::new(3, &[(0, 2)]);

    fn widened(self) -> u64 {
        u64::from(self.0)
    }

    fn from_admitted(tag: u64, _proof: ::sce_forge_runtime::codec::Admitted) -> Self {
        Self(tag as u8)
    }
}

// RFC §synth-5-B variant primitive: discriminated-union body for the
// codec's tag-field suffix. Each arm wraps an imported codec's decoded
// value; the optional Default arm preserves the runtime tag value
// alongside its catch-all body.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum ExtEntryVariant<'a> {
    CodecZenohExtUnit(ExtUnit),
    CodecZenohExtZint(ExtZint),
    CodecZenohExtZbuf(ExtZbuf<'a>),
    Default {
        tag: ExtEntryUnknownTag,
        body: ExtUnit,
    },
}

impl<'a> Default for ExtEntryVariant<'a> {
    fn default() -> Self {
        // RFC variant-default-uniformity: pick the declared default
        // arm (`<sce:arm default="true"/>`) so a freshly-constructed
        // envelope round-trips byte-exactly through `encode() ->
        // decode()` — pairs with the inner codec's `<sce:flag value=>`
        // -baked `Default::default()` to close the dispatch loop.
        Self::CodecZenohExtUnit(ExtUnit::default())
    }
}

// pub API: codecs are intended for cross-crate consumption (SCE_FORGE.md
// §6 codec). The kind-agnostic conformance harness only references a
// subset of fixtures, so unused-but-pub fields/methods would otherwise
// trigger dead_code on every codec build.
#[allow(dead_code)]
#[derive(Default, Debug, Clone, PartialEq)]
pub struct ExtEntry<'a> {
    pub header: u8,
    pub body: ExtEntryVariant<'a>,
}

#[allow(dead_code)]
impl<'a> ExtEntry<'a> {
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
    pub fn decode(cursor: &mut SceCursor<'a>) -> Result<Self, CodecError> {
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
    pub fn decode_into(cursor: &mut SceCursor<'a>, _out: &mut Self) -> Result<(), CodecError> {
        // Decode fixed prefix (RFC §synth-5-B variant primitive: fields
        // sit before the variant suffix on the wire).
        let raw = cursor.peek_slice(1)?;
        let header = raw[0];
        cursor.advance(1)?;
        // Dispatch on the tag field; each arm decodes its body codec
        // from the cursor. The default arm (when declared) carries the
        // runtime tag value so encode can round-trip it back onto the
        // wire.
        // Each arm is installed in `_out.body` holding its body's default and
        // that body is decoded where it sits, so no arm body is returned up
        // through the variant wrapper.
        match (header >> 5) & 0x03 {
            0u8 => {
                _out.body = ExtEntryVariant::CodecZenohExtUnit(ExtUnit::default());
                if let ExtEntryVariant::CodecZenohExtUnit(_b) = &mut _out.body {
                    ExtUnit::decode_into(cursor, _b)?;
                }
            }
            1u8 => {
                _out.body = ExtEntryVariant::CodecZenohExtZint(ExtZint::default());
                if let ExtEntryVariant::CodecZenohExtZint(_b) = &mut _out.body {
                    ExtZint::decode_into(cursor, _b)?;
                }
            }
            2u8 => {
                _out.body = ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf::default());
                if let ExtEntryVariant::CodecZenohExtZbuf(_b) = &mut _out.body {
                    ExtZbuf::decode_into(cursor, _b)?;
                }
            }
            other => {
                _out.body = ExtEntryVariant::Default {
                    tag: ExtEntryUnknownTag(other),
                    body: ExtUnit::default(),
                };
                if let ExtEntryVariant::Default { body: _b, .. } = &mut _out.body {
                    ExtUnit::decode_into(cursor, _b)?;
                }
            }
        }
        _out.header = header;
        Ok(())
    }

    // RFC §synth-5-B flags primitive: per-bit-range accessors over
    // the carrier field. Single-bit (width=1) reads as bool; multi-bit
    // (width>=2) reads as the smallest unsigned integer that fits the
    // range. Setters mask + shift on the way in so out-of-range
    // callers can't corrupt sibling bits. Wire layout is unchanged —
    // the carrier still occupies its declared bytes.
    pub fn ext_id(&self) -> u8 {
        self.header & 0x0F
    }

    pub fn set_ext_id(&mut self, v: u8) {
        self.header = (self.header & !0x0F) | (v & 0x0F);
    }

    pub fn m(&self) -> bool {
        (self.header & 0x10) != 0
    }

    pub fn set_m(&mut self, v: bool) {
        if v {
            self.header |= 0x10;
        } else {
            self.header &= !0x10;
        }
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

    /// Worst-case encoded byte count for this codec — the upper bound
    /// against which `VecSink::new` reserves capacity in the
    /// `encode_to_vec` facade, and the natural reserve hint for
    /// caller-owned `SliceSink` allocations.
    pub const MAX_ENCODED_BYTES: usize = 42;

    /// Encode `self` into the caller-owned sink. Every value has a frame
    /// (docs/adr/0065), so the only error is the sink's own:
    /// `CodecError::BufferOverflow` from a bounded sink when the destination
    /// has insufficient remaining capacity, and none from a sink that cannot
    /// refuse (`VecSink`, `CountSink`).
    pub fn encode<S: SceSink>(&self, w: &mut S) -> Result<(), S::Error> {
        Self::encode_source(self, w)
    }

    /// Heap-backed convenience facade. Pre-reserves
    /// `MAX_ENCODED_BYTES` so the worst-case write path performs at
    /// most one allocation, then delegates to `encode` over a
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
        let mut _sce_v: Vec<u8> = Vec::with_capacity(Self::MAX_ENCODED_BYTES);
        let Ok(()) = self.encode(&mut VecSink::new(&mut _sce_v));
        _sce_v
    }
}

/// The arm of `ExtEntry`'s variant a value holds, each arm's body as the
/// source it says. The tag is not among them: `ExtEntry` derives it from
/// the arm, as it derives a length, and a default arm presents the tag
/// it could not name.
// A default arm's tag is read by the codec that embeds this one and
// derives its own carrier bits from the arm, which not every build uses.
#[allow(dead_code)]
pub enum ExtEntryVariantSource<'s, A0: ?Sized, A1: ?Sized, A2: ?Sized, D: ?Sized> {
    CodecZenohExtUnit(&'s A0),
    CodecZenohExtZint(&'s A1),
    CodecZenohExtZbuf(&'s A2),
    Default { tag: ExtEntryUnknownTag, body: &'s D },
}

/// Flags of `ExtEntry` a parent sets in place of the ones a value presents:
/// the end flag of a chain whose entries are `ExtEntry`, which the chain
/// derives from where an entry stands.
#[doc(hidden)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ExtEntryOverrides {
    /// The `M` flag of `header`, when a parent sets it.
    pub header_m: Option<bool>,
    /// The `Z` flag of `header`, when a parent sets it.
    pub header_z: Option<bool>,
}

#[allow(dead_code)]
impl ExtEntryOverrides {
    /// Sets `M` of `header` and nothing else.
    #[allow(clippy::needless_update)]
    pub fn header_m(value: bool) -> Self {
        Self { header_m: Some(value), ..Self::default() }
    }

    /// Sets `Z` of `header` and nothing else.
    #[allow(clippy::needless_update)]
    pub fn header_z(value: bool) -> Self {
        Self { header_z: Some(value), ..Self::default() }
    }
}

// ── Source (ADR 0058) ────────────────────────────────────────────────
/// What a value of `ExtEntry` says: its presented fields. A length, a count
/// or the flag a gated field is announced by is not among them; `ExtEntry`
/// computes those from what is ([`ExtEntry::encode_source`]).
pub trait ExtEntrySource {
    /// The `header` field.
    fn header(&self) -> u8;
    /// The arm of the variant this value holds.
    fn body(&self) -> ExtEntryVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::ext_zbuf::ExtZbufSource, impl super::ext_unit::ExtUnitSource>;
}

impl<T: ExtEntrySource + ?Sized> ExtEntrySource for &T {
    fn header(&self) -> u8 {
        (**self).header()
    }
    fn body(&self) -> ExtEntryVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::ext_zbuf::ExtZbufSource, impl super::ext_unit::ExtUnitSource> {
        (**self).body()
    }
}

/// The arm of `ExtEntry`'s variant that ExtEntryParts holds.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum ExtEntryPartsBody<'a> {
    CodecZenohExtUnit(&'a super::ext_unit::ExtUnitParts),
    CodecZenohExtZint(&'a super::ext_zint::ExtZintParts),
    CodecZenohExtZbuf(&'a super::ext_zbuf::ExtZbufParts<'a>),
    /// The tag the grammar could not name, and the body it holds.
    Default { tag: ExtEntryUnknownTag, body: &'a super::ext_unit::ExtUnitParts },
}

/// A value of `ExtEntry` held in the types a caller already has: a source
/// ([`ExtEntrySource`]) whose lists are slices and whose bodies are references.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct ExtEntryParts<'a> {
    /// The `header` field.
    pub header: u8,
    /// The arm of the variant this value holds.
    pub body: ExtEntryPartsBody<'a>,
}

impl<'a> ExtEntrySource for ExtEntryParts<'a> {
    fn header(&self) -> u8 {
        self.header
    }
    fn body(&self) -> ExtEntryVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::ext_zbuf::ExtZbufSource, impl super::ext_unit::ExtUnitSource> {
        match &self.body {
            ExtEntryPartsBody::CodecZenohExtUnit(_b) => ExtEntryVariantSource::CodecZenohExtUnit(*_b),
            ExtEntryPartsBody::CodecZenohExtZint(_b) => ExtEntryVariantSource::CodecZenohExtZint(*_b),
            ExtEntryPartsBody::CodecZenohExtZbuf(_b) => ExtEntryVariantSource::CodecZenohExtZbuf(*_b),
            ExtEntryPartsBody::Default { tag, body } => ExtEntryVariantSource::Default { tag: *tag, body: *body },
        }
    }
}

impl<'a> ExtEntrySource for ExtEntry<'a> {
    fn header(&self) -> u8 {
        self.header
    }
    fn body(&self) -> ExtEntryVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::ext_zbuf::ExtZbufSource, impl super::ext_unit::ExtUnitSource> {
        match &self.body {
            ExtEntryVariant::CodecZenohExtUnit(_b) => ExtEntryVariantSource::CodecZenohExtUnit(_b),
            ExtEntryVariant::CodecZenohExtZint(_b) => ExtEntryVariantSource::CodecZenohExtZint(_b),
            ExtEntryVariant::CodecZenohExtZbuf(_b) => ExtEntryVariantSource::CodecZenohExtZbuf(_b),
            ExtEntryVariant::Default { tag, body } => ExtEntryVariantSource::Default { tag: *tag, body },
        }
    }
}

impl<'a> ExtEntrySource for ExtEntryView<'a> {
    fn header(&self) -> u8 {
        self.header
    }
    fn body(&self) -> ExtEntryVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::ext_zbuf::ExtZbufSource, impl super::ext_unit::ExtUnitSource> {
        match &self.body {
            ExtEntryViewVariant::CodecZenohExtUnit(_b) => ExtEntryVariantSource::CodecZenohExtUnit(_b),
            ExtEntryViewVariant::CodecZenohExtZint(_b) => ExtEntryVariantSource::CodecZenohExtZint(_b),
            ExtEntryViewVariant::CodecZenohExtZbuf(_b) => ExtEntryVariantSource::CodecZenohExtZbuf(_b),
            ExtEntryViewVariant::Default { tag, body } => ExtEntryVariantSource::Default { tag: *tag, body },
        }
    }
}

impl<S: ::sce_forge_runtime::codec::CodecStorage> ExtEntrySource for ExtEntryOwned<S> {
    fn header(&self) -> u8 {
        self.header
    }
    fn body(&self) -> ExtEntryVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::ext_zbuf::ExtZbufSource, impl super::ext_unit::ExtUnitSource> {
        match &self.body {
            ExtEntryOwnedVariant::CodecZenohExtUnit(_b) => ExtEntryVariantSource::CodecZenohExtUnit(_b),
            ExtEntryOwnedVariant::CodecZenohExtZint(_b) => ExtEntryVariantSource::CodecZenohExtZint(_b),
            ExtEntryOwnedVariant::CodecZenohExtZbuf(_b) => ExtEntryVariantSource::CodecZenohExtZbuf(_b),
            ExtEntryOwnedVariant::Default { tag, body } => ExtEntryVariantSource::Default { tag: *tag, body },
        }
    }
}

#[allow(dead_code)]
impl<'a> ExtEntry<'a> {
    /// Encode what `src` says into the caller-owned sink: the bytes
    /// [`Self::encode`] writes for the value it holds, read through
    /// [`ExtEntrySource`]. A length, a count or a gate flag is computed from what
    /// `src` presents. Every value `src` can present has a frame, so the
    /// only error is the sink's (docs/adr/0065).
    pub fn encode_source<S: ExtEntrySource + ?Sized, K: SceSink>(src: &S, w: &mut K) -> Result<(), K::Error> {
        Self::write_source(src, w)
    }

    /// [`Self::encode_source`] without the guard a parent has already made.
    #[doc(hidden)]
    pub fn write_source<S: ExtEntrySource + ?Sized, K: SceSink>(src: &S, w: &mut K) -> Result<(), K::Error> {
        Self::write_source_in(src, w, &ExtEntryOverrides::default())
    }

    /// [`Self::write_source`] with the flags a parent sets in place of the
    /// ones `src` presents.
    #[doc(hidden)]
    pub fn write_source_in<S: ExtEntrySource + ?Sized, K: SceSink>(src: &S, w: &mut K, over: &ExtEntryOverrides) -> Result<(), K::Error> {
        let _d_header_enc: u8 = match src.body() {
            ExtEntryVariantSource::CodecZenohExtUnit(_) => 0,
            ExtEntryVariantSource::CodecZenohExtZint(_) => 1,
            ExtEntryVariantSource::CodecZenohExtZbuf(_) => 2,
            ExtEntryVariantSource::Default { tag, .. } => tag.get(),
        };
        let mut _c_header: u8 = (src.header() & !0x60) | (_d_header_enc << 5);
        if let Some(_o) = over.header_m {
            _c_header = (_c_header & !0x10) | (u8::from(_o) << 4);
        }
        if let Some(_o) = over.header_z {
            _c_header = (_c_header & !0x80) | (u8::from(_o) << 7);
        }
        w.write_u8(_c_header)?;
        match src.body() {
            ExtEntryVariantSource::CodecZenohExtUnit(_b) => ExtUnit::write_source(_b, w)?,
            ExtEntryVariantSource::CodecZenohExtZint(_b) => ExtZint::write_source(_b, w)?,
            ExtEntryVariantSource::CodecZenohExtZbuf(_b) => ExtZbuf::write_source(_b, w)?,
            ExtEntryVariantSource::Default { body: _b, .. } => ExtUnit::write_source(_b, w)?,
        }
        Ok(())
    }

    /// The bytes [`Self::write_source`] writes for `src`, counted with
    /// nothing written.
    #[doc(hidden)]
    pub fn count_source<S: ExtEntrySource + ?Sized>(src: &S) -> usize {
        let mut _c = ::sce_forge_runtime::codec::CountSink::new();
        let Ok(()) = Self::write_source(src, &mut _c);
        _c.len()
    }
}

impl<'a, S: ExtEntrySource + ?Sized> ::sce_forge_runtime::codec::SourceWrite<S> for ExtEntry<'a> {
    type Error<E> = E;

    fn write<K: SceSink>(src: &S, w: &mut K) -> Result<(), K::Error> where CodecError: From<K::Error> {
        Self::write_source(src, w)
    }
}

#[allow(dead_code)]
impl<'a> ExtEntry<'a> {
    /// The size of the frame [`Self::encode_source`] writes for `src`, found
    /// with nothing written: the encode refuses no value, so neither does
    /// this. The result writes the frame into a window of exactly that size
    /// and cannot fail.
    pub fn measure<S: ExtEntrySource + ?Sized>(src: &S) -> ::sce_forge_runtime::codec::Measured<'_, Self, S> {
        let Ok(measured) = ::sce_forge_runtime::codec::measure(src);
        measured
    }

    /// Write `src` into `window` in one pass and return the bytes it is, for a
    /// window as large as the caller can spare. On an error the window holds a
    /// prefix to discard; see [`::sce_forge_runtime::codec::write_window`].
    pub fn write_window<S: ExtEntrySource + ?Sized>(src: &S, window: &mut [u8]) -> Result<usize, CodecError> {
        let mut sink = ::sce_forge_runtime::codec::SliceSink::new(window);
        Self::write_source(src, &mut sink)?;
        Ok(sink.position())
    }
}


// ── View (ADR 0049) ──────────────────────────────────────────────────
// `ExtEntryView` is what a decode of `ExtEntry` learned, not a
// copy of what the wire repeated: a scalar, a string or a bytes field is held
// as `ExtEntry` holds it, an embedded body or a variant arm as its
// own view, and a bounded list as the frame it was read from, how many entries
// it holds and what a walk needs to read them again (`ListView`). Its size
// depends on the number of fields and not on any `sce:max-count`, so moving
// one copies a few words however long its lists may be. `decode` refuses the
// frames `ExtEntry::decode` refuses, with the same error: the entries
// are decoded once to check them, and a walk afterwards cannot fail.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum ExtEntryViewVariant<'a> {
    CodecZenohExtUnit(ExtUnitView),
    CodecZenohExtZint(ExtZintView),
    CodecZenohExtZbuf(ExtZbufView<'a>),
    Default {
        tag: ExtEntryUnknownTag,
        body: ExtUnitView,
    },
}

impl<'a> Default for ExtEntryViewVariant<'a> {
    fn default() -> Self {
        Self::CodecZenohExtUnit(ExtUnitView::default())
    }
}

#[allow(dead_code)]
#[derive(Default, Debug, Clone, PartialEq)]
pub struct ExtEntryView<'a> {
    pub header: u8,
    pub body: ExtEntryViewVariant<'a>,
}

#[allow(dead_code)]
impl<'a> ExtEntryView<'a> {
    /// A view with every field at its own type's [`Default`]: the destination
    /// [`Self::decode_into`] fills.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode the next frame from `cursor`: the bytes, the bounds and the
    /// errors of [`ExtEntry::decode`], held as a view. On success the
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
        // Decode fixed prefix (RFC §synth-5-B variant primitive: fields
        // sit before the variant suffix on the wire).
        let raw = cursor.peek_slice(1)?;
        let header = raw[0];
        cursor.advance(1)?;
        // Dispatch on the tag field; each arm decodes its body codec
        // from the cursor. The default arm (when declared) carries the
        // runtime tag value so encode can round-trip it back onto the
        // wire.
        // Each arm is installed in `_out.body` holding its body's default and
        // that body is decoded where it sits, so no arm body is returned up
        // through the variant wrapper.
        match (header >> 5) & 0x03 {
            0u8 => {
                _out.body = ExtEntryViewVariant::CodecZenohExtUnit(ExtUnitView::default());
                if let ExtEntryViewVariant::CodecZenohExtUnit(_b) = &mut _out.body {
                    ExtUnitView::decode_into(cursor, _b)?;
                }
            }
            1u8 => {
                _out.body = ExtEntryViewVariant::CodecZenohExtZint(ExtZintView::default());
                if let ExtEntryViewVariant::CodecZenohExtZint(_b) = &mut _out.body {
                    ExtZintView::decode_into(cursor, _b)?;
                }
            }
            2u8 => {
                _out.body = ExtEntryViewVariant::CodecZenohExtZbuf(ExtZbufView::default());
                if let ExtEntryViewVariant::CodecZenohExtZbuf(_b) = &mut _out.body {
                    ExtZbufView::decode_into(cursor, _b)?;
                }
            }
            other => {
                _out.body = ExtEntryViewVariant::Default {
                    tag: ExtEntryUnknownTag(other),
                    body: ExtUnitView::default(),
                };
                if let ExtEntryViewVariant::Default { body: _b, .. } = &mut _out.body {
                    ExtUnitView::decode_into(cursor, _b)?;
                }
            }
        }
        _out.header = header;
        Ok(())
    }

    /// Fill `_out`, the builder form [`ExtEntry`] a sender fills and
    /// encodes, with what this view says: every field, each embedded body, the
    /// variant arm, and each list entry as the walk yields it, built in the
    /// destination where it will live. Fails only where the destination cannot
    /// hold it, which a destination of the same declared bounds does.
    // The name every view's method has (ADR 0049), which borrows because a
    // view is read, not consumed. Clippy leaves an exported method's name
    // alone; a crate that includes this module privately is asked to rename
    // it, and the one name is what lets a codec reach every view it holds.
    #[allow(clippy::wrong_self_convention)]
    pub fn into_builder(&self, _out: &mut ExtEntry<'a>) -> Result<(), CodecError> {
        _out.header = self.header;
        match &self.body {
            ExtEntryViewVariant::CodecZenohExtUnit(_b) => {
                _out.body = ExtEntryVariant::CodecZenohExtUnit(ExtUnit::default());
                if let ExtEntryVariant::CodecZenohExtUnit(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
            ExtEntryViewVariant::CodecZenohExtZint(_b) => {
                _out.body = ExtEntryVariant::CodecZenohExtZint(ExtZint::default());
                if let ExtEntryVariant::CodecZenohExtZint(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
            ExtEntryViewVariant::CodecZenohExtZbuf(_b) => {
                _out.body = ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf::default());
                if let ExtEntryVariant::CodecZenohExtZbuf(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
            ExtEntryViewVariant::Default { tag, body } => {
                _out.body = ExtEntryVariant::Default {
                    tag: *tag,
                    body: ExtUnit::default(),
                };
                if let ExtEntryVariant::Default { body: _o, .. } = &mut _out.body {
                    body.into_builder(_o)?;
                }
            }
        }
        Ok(())
    }

    /// Worst-case encoded byte count for this codec, as
    /// [`ExtEntry::MAX_ENCODED_BYTES`].
    pub const MAX_ENCODED_BYTES: usize = 42;

    /// Encode what this view says into the caller-owned sink: the bytes
    /// [`ExtEntry::encode`] writes for the value [`Self::into_builder`]
    /// fills, written straight from the view, walking each list, without the
    /// builder. It writes the canonical wire, not the frame the view was decoded
    /// from, so a frame `decode` accepted in a form that is not canonical is
    /// not passed on as it came.
    pub fn encode<S: SceSink>(&self, w: &mut S) -> Result<(), S::Error> {
        ExtEntry::encode_source(self, w)
    }

    /// Heap-backed convenience facade over [`Self::encode`], which refuses no
    /// value (docs/adr/0065).
    #[cfg(feature = "alloc")]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut _sce_v: Vec<u8> = Vec::with_capacity(Self::MAX_ENCODED_BYTES);
        let Ok(()) = self.encode(&mut VecSink::new(&mut _sce_v));
        _sce_v
    }

    pub fn ext_id(&self) -> u8 {
        self.header & 0x0F
    }

    pub fn m(&self) -> bool {
        (self.header & 0x10) != 0
    }

    pub fn enc(&self) -> u8 {
        (self.header >> 5) & 0x03
    }

    pub fn z(&self) -> bool {
        (self.header & 0x80) != 0
    }

}

// ── Owned projection (storage-parameterised native form) ─────────────
// `ExtEntry<'a>` above is a zero-copy view borrowing the decode
// buffer. Consumers that persist a decoded value beyond the buffer's
// lifetime — including the self-contained bounded-collection that stores
// elements by value — call `.try_into_owned()` for this lifetime-free
// `ExtEntryOwned`. The rkyv-style Archived(borrowed) ↔ native
// (owned) split, both generated from the one SCXML source (SSOT).
//
// The owned form is parameterised by a storage profile rather than fixed at
// build-configuration time: `ExtEntryOwned<Heap>` holds growable
// containers with the declared capacities advisory, `ExtEntryOwned<Inline>`
// holds every field inline at its declared capacity and never allocates, and
// both exist in the same binary. `ExtEntryOwned` alone is the build's
// default profile. Because the non-allocating profile is a *type*, this mirror
// carries no `alloc` gate at all — a list- or embed-bearing codec has an owned
// form on the heap-free tier too, and a heap-capable consumer can still pin a
// value to storage that is guaranteed not to allocate.
//
// `try_into_owned` is the fallible direction (one `?` per profile: on the
// growable profile the copy cannot fail, on the inline profile it enforces
// each declared bound); `as_borrowed` re-borrows any profile back
// into the single borrowed view that owns `encode`; `transcode_in` moves a
// value between profiles as a checked projection rather than a re-decode.
//
// Decoding picks the profile from the call (`try_into_owned_in::<Inline>()`).
// Hand-assembling one instead names it on the value or its binding —
// `let v: ExtEntryOwned = ExtEntryOwned { .. };`
// — because the fields reach the profile through its associated container
// types, which cannot be run backwards to recover the profile from a value.
// Naming it once is also what lets each field's declared capacity infer,
// so no call site repeats a `sce:max-size` / `sce:max-count` constant.
use super::ext_zbuf::ExtZbufOwned;
// Same pub-API policy as the borrowed view above: the owned mirror and its
// projections are cross-crate surface, and which of them a given in-repo
// fixture happens to call says nothing about their value.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct ExtEntryOwned<S: ::sce_forge_runtime::codec::CodecStorage = ::sce_forge_runtime::codec::DefaultStorage> {
    pub header: u8,
    pub body: ExtEntryOwnedVariant<S>,
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> ExtEntryOwned<S> {
    // RFC §synth-5-B read-accessor parity with the borrowed view: pure
    // bit getters over the copied carrier (rkyv Archived↔native getter
    // parity), so owned consumers read `{Codec}Owned` with the same API as
    // the borrowed view and never re-derive the SCE wire bit layout (SSOT).
    // Read-only — write accessors belong with an owned-encode path, which
    // does not exist yet.
    pub fn ext_id(&self) -> u8 {
        self.header & 0x0F
    }

    pub fn m(&self) -> bool {
        (self.header & 0x10) != 0
    }

    pub fn enc(&self) -> u8 {
        (self.header >> 5) & 0x03
    }

    pub fn z(&self) -> bool {
        (self.header & 0x80) != 0
    }
}

// Variant arms wrap distinct body codecs whose owned mirrors differ in
// field count and size, so the tagged union is inherently size-disparate.
// The lint's only remedy is boxing the large arm, which adds an
// indirection (and allocation) the generated decode path does not need —
// and which the non-allocating storage profile could not take at all.
// The size spread is the deliberate tagged-union trade-off.
#[allow(clippy::large_enum_variant)]
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum ExtEntryOwnedVariant<S: ::sce_forge_runtime::codec::CodecStorage = ::sce_forge_runtime::codec::DefaultStorage> {
    CodecZenohExtUnit(ExtUnit),
    CodecZenohExtZint(ExtZint),
    CodecZenohExtZbuf(ExtZbufOwned<S>),
    Default {
        tag: ExtEntryUnknownTag,
        body: ExtUnit,
    },
}

#[allow(dead_code)]
impl<'a> ExtEntryVariant<'a> {
    /// Deep-copy this borrowed variant body into its owned mirror at the
    /// given storage profile. Fallible because a borrowed arm body's own
    /// projection re-checks its declared capacities (the same bounds decode
    /// enforces) — on the growable profile no check can fire.
    pub fn try_into_owned_in<S: ::sce_forge_runtime::codec::CodecStorage>(self) -> Result<ExtEntryOwnedVariant<S>, CodecError> {
        Ok(match self {
            ExtEntryVariant::CodecZenohExtUnit(_b) => ExtEntryOwnedVariant::CodecZenohExtUnit(_b),
            ExtEntryVariant::CodecZenohExtZint(_b) => ExtEntryOwnedVariant::CodecZenohExtZint(_b),
            ExtEntryVariant::CodecZenohExtZbuf(_b) => ExtEntryOwnedVariant::CodecZenohExtZbuf(_b.try_into_owned_in::<S>()?),
            ExtEntryVariant::Default { tag, body } => ExtEntryOwnedVariant::Default { tag, body },
        })
    }

    /// The same projection at the build's default storage profile.
    pub fn try_into_owned(self) -> Result<ExtEntryOwnedVariant, CodecError> {
        self.try_into_owned_in()
    }
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> ExtEntryOwnedVariant<S> {
    /// Re-borrow this owned variant body back into its borrowed mirror —
    /// the inverse of the projection above. Reuses the borrowed view's
    /// single `encode`; the owned form deliberately carries no encode of
    /// its own.
    pub fn as_borrowed(&self) -> ExtEntryVariant<'_> {
        let mut _out = ExtEntryVariant::default();
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
    pub fn as_borrowed_into<'o>(&'o self, _out: &mut ExtEntryVariant<'o>) {
        match self {
            ExtEntryOwnedVariant::CodecZenohExtUnit(_b) => {
                *_out = ExtEntryVariant::CodecZenohExtUnit(Default::default());
                if let ExtEntryVariant::CodecZenohExtUnit(_o) = _out {
                    *_o = _b.clone();
                }
            }
            ExtEntryOwnedVariant::CodecZenohExtZint(_b) => {
                *_out = ExtEntryVariant::CodecZenohExtZint(Default::default());
                if let ExtEntryVariant::CodecZenohExtZint(_o) = _out {
                    *_o = _b.clone();
                }
            }
            ExtEntryOwnedVariant::CodecZenohExtZbuf(_b) => {
                *_out = ExtEntryVariant::CodecZenohExtZbuf(Default::default());
                if let ExtEntryVariant::CodecZenohExtZbuf(_o) = _out {
                    _b.as_borrowed_into(_o);
                }
            }
            ExtEntryOwnedVariant::Default { tag, body } => {
                *_out = ExtEntryVariant::Default { tag: *tag, body: Default::default() };
                if let ExtEntryVariant::Default { body: _o, .. } = _out {
                    *_o = body.clone();
                }
            }
        }
        
    }
}

#[allow(dead_code)]
impl<'a> ExtEntry<'a> {
    /// Deep-copy this borrowed zero-copy view into an owned, lifetime-free
    /// [`ExtEntryOwned`] held in the given storage profile. Call at
    /// a decode boundary when the decoded value must outlive the input
    /// buffer — stored in a long-lived enum, moved across an async task, or
    /// inserted by value into a bounded-collection.
    ///
    /// Fallible for profile uniformity: on the inline profile a field longer
    /// than its declared capacity raises `CodecError::TooManyElements` (the
    /// same bound and error decode enforces), on the growable profile the
    /// copy cannot fail. The borrowed zero-copy path is unaffected either
    /// way.
    pub fn try_into_owned_in<S: ::sce_forge_runtime::codec::CodecStorage>(self) -> Result<ExtEntryOwned<S>, CodecError> {
        Ok(ExtEntryOwned {
            header: self.header,
            body: self.body.try_into_owned_in::<S>()?,
        })
    }

    /// The same projection at the build's default storage profile — growable
    /// where an allocator exists, inline on the heap-free tier.
    pub fn try_into_owned(self) -> Result<ExtEntryOwned, CodecError> {
        self.try_into_owned_in()
    }
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> ExtEntryOwned<S> {
    /// Re-borrow this owned value back into the zero-copy borrowed view —
    /// the inverse of `try_into_owned_in`. `encode` lives only on the
    /// borrowed view (the owned form is read-only), so an owned consumer
    /// reaches it via `as_borrowed` then `encode` / `encode_to_vec`.
    /// Each field is projected by reference — a cheap re-borrow, not a copy.
    pub fn as_borrowed(&self) -> ExtEntry<'_> {
        let mut _out = ExtEntry::default();
        self.as_borrowed_into(&mut _out);
        _out
    }

    /// [`Self::as_borrowed`] into a destination the caller owns, each
    /// bounded list and embedded body projected in the field where it sits.
    ///
    /// A bounded list moves by copying its whole declared capacity, so a
    /// projection that returns one copies the declared maximum at every layer
    /// it passes through (the optional wrapper, the borrowed struct, the
    /// variant, the caller's binding), however few entries the list holds. A
    /// caller on a path where that shows projects into a destination it owns,
    /// then encodes from it. On `Err`, `_out` holds what was projected so far
    /// and is not to be read.
    pub fn as_borrowed_into<'o>(&'o self, _out: &mut ExtEntry<'o>) {
        _out.header = self.header;
        self.body.as_borrowed_into(&mut _out.body);
        
    }

    /// Move this value to a different storage profile — growable to inline
    /// when handing it to a path that must not allocate, or inline to
    /// growable when it is leaving that path.
    ///
    /// A checked projection through the borrowed view, not a re-decode: the
    /// bytes are copied once and every destination capacity is enforced, so
    /// a value that cannot fit the target profile is rejected here rather
    /// than truncated.
    pub fn transcode_in<D: ::sce_forge_runtime::codec::CodecStorage>(&self) -> Result<ExtEntryOwned<D>, CodecError> {
        self.as_borrowed().try_into_owned_in::<D>()
    }
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> ExtEntryOwned<S> {
    /// Encode `self` into the caller-owned sink, straight from the owned
    /// fields: the bytes `as_borrowed` followed by
    /// [`ExtEntry::encode`] writes, without the projection.
    ///
    /// The projection builds the whole borrowed record (every list and
    /// embedded body in it, by value) only for `encode` to read it once. A
    /// sender that holds an owned value encodes it from here.
    /// Every value has a frame (docs/adr/0065), so the only error is the
    /// sink's own.
    pub fn encode<K: SceSink>(&self, w: &mut K) -> Result<(), K::Error> {
        ExtEntry::encode_source(self, w)
    }

    /// Heap-backed convenience facade over [`Self::encode`], which refuses no
    /// value.
    #[cfg(feature = "alloc")]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut _sce_v: Vec<u8> = Vec::with_capacity(ExtEntry::MAX_ENCODED_BYTES);
        let Ok(()) = self.encode(&mut VecSink::new(&mut _sce_v));
        _sce_v
    }
}

#[allow(dead_code)]
impl<'a> ExtEntryVariant<'a> {
    /// The projection above, with the profile's byte and text containers made
    /// from `origin` — what the decoded bytes were taken from.
    pub fn try_into_owned_in_origin<S: ::sce_forge_runtime::codec::OriginStorage>(self, origin: &<S as ::sce_forge_runtime::codec::OriginStorage>::Origin) -> Result<ExtEntryOwnedVariant<S>, CodecError> {
        Ok(match self {
            ExtEntryVariant::CodecZenohExtUnit(_b) => ExtEntryOwnedVariant::CodecZenohExtUnit(_b),
            ExtEntryVariant::CodecZenohExtZint(_b) => ExtEntryOwnedVariant::CodecZenohExtZint(_b),
            ExtEntryVariant::CodecZenohExtZbuf(_b) => ExtEntryOwnedVariant::CodecZenohExtZbuf(_b.try_into_owned_in_origin::<S>(origin)?),
            ExtEntryVariant::Default { tag, body } => ExtEntryOwnedVariant::Default { tag, body },
        })
    }
}

#[allow(dead_code)]
impl<'a> ExtEntry<'a> {
    /// Project this borrowed view into an owned [`ExtEntryOwned`]
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
    pub fn try_into_owned_in_origin<S: ::sce_forge_runtime::codec::OriginStorage>(self, origin: &<S as ::sce_forge_runtime::codec::OriginStorage>::Origin) -> Result<ExtEntryOwned<S>, CodecError> {
        Ok(ExtEntryOwned {
            header: self.header,
            body: self.body.try_into_owned_in_origin::<S>(origin)?,
        })
    }
}
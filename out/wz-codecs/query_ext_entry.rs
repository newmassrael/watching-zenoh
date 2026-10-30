// SCE-MAP: query_ext_entry:26 :: _forge_body

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
use super::query_value_zbuf::QueryValueZbuf;

use super::ext_unit::ExtUnitView;
use super::ext_zint::ExtZintView;
use super::query_value_zbuf::QueryValueZbufView;

/// A tag `QueryExtEntry` names no arm for, which its default arm holds: a
/// value inside the 2 bits the tag is read from and outside
/// every arm's tag (docs/adr/0065 §6 R3). A default arm is written with the tag
/// it holds and read back as the default arm, so no tag it holds is refused.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueryExtEntryUnknownTag(u8);

#[allow(dead_code)]
impl QueryExtEntryUnknownTag {
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

// RFC §synth-5-B variant primitive: discriminated-union body for the
// codec's tag-field suffix. Each arm wraps an imported codec's decoded
// value; the optional Default arm preserves the runtime tag value
// alongside its catch-all body.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum QueryExtEntryVariant<'a> {
    CodecZenohExtUnit(ExtUnit),
    CodecZenohExtZint(ExtZint),
    CodecZenohQueryValueZbuf(QueryValueZbuf<'a>),
    Default {
        tag: QueryExtEntryUnknownTag,
        body: ExtUnit,
    },
}

impl<'a> Default for QueryExtEntryVariant<'a> {
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
pub struct QueryExtEntry<'a> {
    pub header: u8,
    pub body: QueryExtEntryVariant<'a>,
}

#[allow(dead_code)]
impl<'a> QueryExtEntry<'a> {
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
    pub fn decode(cursor: &mut SceCursor<'a>, after_shm: u8) -> Result<Self, CodecError> {
        let mut _out = Self::default();
        Self::decode_into(cursor, &mut _out, after_shm)?;
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
    pub fn decode_into(cursor: &mut SceCursor<'a>, _out: &mut Self, after_shm: u8) -> Result<(), CodecError> {
        // Declared-but-unconsumed flag inputs: defensive suppress per declared
        // `<sce:flag-input>` so codecs that haven't (yet) consumed an
        // input via `present-if` compile cleanly. The validator enforces
        // declaration; consumption is a per-codec design choice.
        let _ = after_shm;
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
                _out.body = QueryExtEntryVariant::CodecZenohExtUnit(ExtUnit::default());
                if let QueryExtEntryVariant::CodecZenohExtUnit(_b) = &mut _out.body {
                    ExtUnit::decode_into(cursor, _b)?;
                }
            }
            1u8 => {
                _out.body = QueryExtEntryVariant::CodecZenohExtZint(ExtZint::default());
                if let QueryExtEntryVariant::CodecZenohExtZint(_b) = &mut _out.body {
                    ExtZint::decode_into(cursor, _b)?;
                }
            }
            2u8 => {
                _out.body = QueryExtEntryVariant::CodecZenohQueryValueZbuf(QueryValueZbuf::default());
                if let QueryExtEntryVariant::CodecZenohQueryValueZbuf(_b) = &mut _out.body {
                    QueryValueZbuf::decode_into(cursor, _b, after_shm)?;
                }
            }
            other => {
                _out.body = QueryExtEntryVariant::Default {
                    tag: QueryExtEntryUnknownTag(other),
                    body: ExtUnit::default(),
                };
                if let QueryExtEntryVariant::Default { body: _b, .. } = &mut _out.body {
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
    pub const MAX_ENCODED_BYTES: usize = 1383;

    /// Encode `self` into the caller-owned sink. Returns the value's refusal
    /// when the encoding cannot carry it (a length past its type, a list past
    /// its bound, a gate that disagrees with a presence; the document declares
    /// `sce:encode-may-fail`), or the sink's own error:
    /// `CodecError::BufferOverflow` from a bounded sink when the destination
    /// has insufficient remaining capacity.
    pub fn encode<S: SceSink>(&self, w: &mut S, after_shm: u8) -> Result<(), CodecError> where CodecError: From<S::Error> {
        Self::encode_source(self, w, after_shm)
    }

    /// Heap-backed convenience facade. Pre-reserves
    /// `MAX_ENCODED_BYTES` so the worst-case write path performs at
    /// most one allocation, then delegates to `encode` over a
    /// `VecSink`. Returns the freshly-encoded byte vector, or the error
    /// `encode` refuses a value with: one the encoding cannot carry (a
    /// length past its type, a list past its bound) or one a gate
    /// disagrees with. Callers targeting zero-alloc hot paths should call
    /// `encode` directly against a caller-owned sink.
    ///
    /// Gated on the `alloc` feature — `VecSink` lives behind the
    /// same gate (see `backends/rust/forge-runtime/src/codec.rs`). MCU /
    /// `no_std` builds without `alloc` only see the sink-based
    /// primary `encode`.
    #[cfg(feature = "alloc")]
    pub fn encode_to_vec(&self, after_shm: u8) -> Result<Vec<u8>, CodecError> {
        let mut _sce_v: Vec<u8> = Vec::with_capacity(Self::MAX_ENCODED_BYTES);
        let mut _sce_sink = VecSink::new(&mut _sce_v);
        self.encode(&mut _sce_sink, after_shm)?;
        Ok(_sce_v)
    }
}

/// The arm of `QueryExtEntry`'s variant a value holds, each arm's body as the
/// source it says. The tag is not among them: `QueryExtEntry` derives it from
/// the arm, as it derives a length, and a default arm presents the tag
/// it could not name.
// A default arm's tag is read by the codec that embeds this one and
// derives its own carrier bits from the arm, which not every build uses.
#[allow(dead_code)]
pub enum QueryExtEntryVariantSource<'s, A0: ?Sized, A1: ?Sized, A2: ?Sized, D: ?Sized> {
    CodecZenohExtUnit(&'s A0),
    CodecZenohExtZint(&'s A1),
    CodecZenohQueryValueZbuf(&'s A2),
    Default { tag: QueryExtEntryUnknownTag, body: &'s D },
}

/// Flags of `QueryExtEntry` a parent sets in place of the ones a value presents:
/// the end flag of a chain whose entries are `QueryExtEntry`, which the chain
/// derives from where an entry stands.
#[doc(hidden)]
#[derive(Debug, Default, Clone, Copy)]
pub struct QueryExtEntryOverrides {
    /// The `M` flag of `header`, when a parent sets it.
    pub header_m: Option<bool>,
    /// The `Z` flag of `header`, when a parent sets it.
    pub header_z: Option<bool>,
}

#[allow(dead_code)]
impl QueryExtEntryOverrides {
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
/// What a value of `QueryExtEntry` says: its presented fields. A length, a count
/// or the flag a gated field is announced by is not among them; `QueryExtEntry`
/// computes those from what is ([`QueryExtEntry::encode_source`]).
pub trait QueryExtEntrySource {
    /// The `header` field.
    fn header(&self) -> u8;
    /// The arm of the variant this value holds.
    fn body(&self) -> QueryExtEntryVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::query_value_zbuf::QueryValueZbufSource, impl super::ext_unit::ExtUnitSource>;
}

impl<T: QueryExtEntrySource + ?Sized> QueryExtEntrySource for &T {
    fn header(&self) -> u8 {
        (**self).header()
    }
    fn body(&self) -> QueryExtEntryVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::query_value_zbuf::QueryValueZbufSource, impl super::ext_unit::ExtUnitSource> {
        (**self).body()
    }
}

/// The arm of `QueryExtEntry`'s variant that QueryExtEntryParts holds.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum QueryExtEntryPartsBody<'a> {
    CodecZenohExtUnit(&'a super::ext_unit::ExtUnitParts),
    CodecZenohExtZint(&'a super::ext_zint::ExtZintParts),
    CodecZenohQueryValueZbuf(&'a super::query_value_zbuf::QueryValueZbufParts<'a>),
    /// The tag the grammar could not name, and the body it holds.
    Default { tag: QueryExtEntryUnknownTag, body: &'a super::ext_unit::ExtUnitParts },
}

/// A value of `QueryExtEntry` held in the types a caller already has: a source
/// ([`QueryExtEntrySource`]) whose lists are slices and whose bodies are references.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct QueryExtEntryParts<'a> {
    /// The `header` field.
    pub header: u8,
    /// The arm of the variant this value holds.
    pub body: QueryExtEntryPartsBody<'a>,
}

impl<'a> QueryExtEntrySource for QueryExtEntryParts<'a> {
    fn header(&self) -> u8 {
        self.header
    }
    fn body(&self) -> QueryExtEntryVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::query_value_zbuf::QueryValueZbufSource, impl super::ext_unit::ExtUnitSource> {
        match &self.body {
            QueryExtEntryPartsBody::CodecZenohExtUnit(_b) => QueryExtEntryVariantSource::CodecZenohExtUnit(*_b),
            QueryExtEntryPartsBody::CodecZenohExtZint(_b) => QueryExtEntryVariantSource::CodecZenohExtZint(*_b),
            QueryExtEntryPartsBody::CodecZenohQueryValueZbuf(_b) => QueryExtEntryVariantSource::CodecZenohQueryValueZbuf(*_b),
            QueryExtEntryPartsBody::Default { tag, body } => QueryExtEntryVariantSource::Default { tag: *tag, body: *body },
        }
    }
}

impl<'a> QueryExtEntrySource for QueryExtEntry<'a> {
    fn header(&self) -> u8 {
        self.header
    }
    fn body(&self) -> QueryExtEntryVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::query_value_zbuf::QueryValueZbufSource, impl super::ext_unit::ExtUnitSource> {
        match &self.body {
            QueryExtEntryVariant::CodecZenohExtUnit(_b) => QueryExtEntryVariantSource::CodecZenohExtUnit(_b),
            QueryExtEntryVariant::CodecZenohExtZint(_b) => QueryExtEntryVariantSource::CodecZenohExtZint(_b),
            QueryExtEntryVariant::CodecZenohQueryValueZbuf(_b) => QueryExtEntryVariantSource::CodecZenohQueryValueZbuf(_b),
            QueryExtEntryVariant::Default { tag, body } => QueryExtEntryVariantSource::Default { tag: *tag, body },
        }
    }
}

impl<'a> QueryExtEntrySource for QueryExtEntryView<'a> {
    fn header(&self) -> u8 {
        self.header
    }
    fn body(&self) -> QueryExtEntryVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::query_value_zbuf::QueryValueZbufSource, impl super::ext_unit::ExtUnitSource> {
        match &self.body {
            QueryExtEntryViewVariant::CodecZenohExtUnit(_b) => QueryExtEntryVariantSource::CodecZenohExtUnit(_b),
            QueryExtEntryViewVariant::CodecZenohExtZint(_b) => QueryExtEntryVariantSource::CodecZenohExtZint(_b),
            QueryExtEntryViewVariant::CodecZenohQueryValueZbuf(_b) => QueryExtEntryVariantSource::CodecZenohQueryValueZbuf(_b),
            QueryExtEntryViewVariant::Default { tag, body } => QueryExtEntryVariantSource::Default { tag: *tag, body },
        }
    }
}

impl<S: ::sce_forge_runtime::codec::CodecStorage> QueryExtEntrySource for QueryExtEntryOwned<S> {
    fn header(&self) -> u8 {
        self.header
    }
    fn body(&self) -> QueryExtEntryVariantSource<'_, impl super::ext_unit::ExtUnitSource, impl super::ext_zint::ExtZintSource, impl super::query_value_zbuf::QueryValueZbufSource, impl super::ext_unit::ExtUnitSource> {
        match &self.body {
            QueryExtEntryOwnedVariant::CodecZenohExtUnit(_b) => QueryExtEntryVariantSource::CodecZenohExtUnit(_b),
            QueryExtEntryOwnedVariant::CodecZenohExtZint(_b) => QueryExtEntryVariantSource::CodecZenohExtZint(_b),
            QueryExtEntryOwnedVariant::CodecZenohQueryValueZbuf(_b) => QueryExtEntryVariantSource::CodecZenohQueryValueZbuf(_b),
            QueryExtEntryOwnedVariant::Default { tag, body } => QueryExtEntryVariantSource::Default { tag: *tag, body },
        }
    }
}

#[allow(dead_code)]
impl<'a> QueryExtEntry<'a> {
    /// Encode what `src` says into the caller-owned sink: the bytes
    /// [`Self::encode`] writes for the value it holds, read through
    /// [`QueryExtEntrySource`]. A length, a count or a gate flag is computed from what
    /// `src` presents, and a value the encoding cannot carry is refused
    /// before the first byte is written.
    pub fn encode_source<S: QueryExtEntrySource + ?Sized, K: SceSink>(src: &S, w: &mut K, after_shm: u8) -> Result<(), CodecError> where CodecError: From<K::Error> {
        Self::count_source(src, after_shm)?;
        Self::write_source(src, w, after_shm)
    }

    /// [`Self::encode_source`] without the guard a parent has already made.
    #[doc(hidden)]
    pub fn write_source<S: QueryExtEntrySource + ?Sized, K: SceSink>(src: &S, w: &mut K, after_shm: u8) -> Result<(), CodecError> where CodecError: From<K::Error> {
        Self::write_source_in(src, w, after_shm, &QueryExtEntryOverrides::default())
    }

    /// [`Self::write_source`] with the flags a parent sets in place of the
    /// ones `src` presents.
    #[doc(hidden)]
    pub fn write_source_in<S: QueryExtEntrySource + ?Sized, K: SceSink>(src: &S, w: &mut K, after_shm: u8, over: &QueryExtEntryOverrides) -> Result<(), CodecError> where CodecError: From<K::Error> {
        let _d_header_enc: u8 = match src.body() {
            QueryExtEntryVariantSource::CodecZenohExtUnit(_) => 0,
            QueryExtEntryVariantSource::CodecZenohExtZint(_) => 1,
            QueryExtEntryVariantSource::CodecZenohQueryValueZbuf(_) => 2,
            QueryExtEntryVariantSource::Default { tag, .. } => tag.get(),
        };
        let mut _c_header: u8 = (src.header() & !0x60) | (_d_header_enc << 5);
        if let Some(_o) = over.header_m {
            _c_header = (_c_header & !0x10) | (u8::from(_o) << 4);
        }
        if let Some(_o) = over.header_z {
            _c_header = (_c_header & !0x80) | (u8::from(_o) << 7);
        }
        let _ = after_shm;
        w.write_u8(_c_header)?;
        match src.body() {
            QueryExtEntryVariantSource::CodecZenohExtUnit(_b) => ExtUnit::write_source(_b, w)?,
            QueryExtEntryVariantSource::CodecZenohExtZint(_b) => ExtZint::write_source(_b, w)?,
            QueryExtEntryVariantSource::CodecZenohQueryValueZbuf(_b) => QueryValueZbuf::write_source(_b, w, after_shm)?,
            QueryExtEntryVariantSource::Default { body: _b, .. } => ExtUnit::write_source(_b, w)?,
        }
        Ok(())
    }

    /// The bytes [`Self::write_source`] writes for `src`, counted with
    /// nothing written.
    #[doc(hidden)]
    pub fn count_source<S: QueryExtEntrySource + ?Sized>(src: &S, after_shm: u8) -> Result<usize, CodecError> {
        let mut _c = ::sce_forge_runtime::codec::CountSink::new();
        Self::write_source(src, &mut _c, after_shm)?;
        Ok(_c.len())
    }
}


// ── View (ADR 0049) ──────────────────────────────────────────────────
// `QueryExtEntryView` is what a decode of `QueryExtEntry` learned, not a
// copy of what the wire repeated: a scalar, a string or a bytes field is held
// as `QueryExtEntry` holds it, an embedded body or a variant arm as its
// own view, and a bounded list as the frame it was read from, how many entries
// it holds and what a walk needs to read them again (`ListView`). Its size
// depends on the number of fields and not on any `sce:max-count`, so moving
// one copies a few words however long its lists may be. `decode` refuses the
// frames `QueryExtEntry::decode` refuses, with the same error: the entries
// are decoded once to check them, and a walk afterwards cannot fail.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum QueryExtEntryViewVariant<'a> {
    CodecZenohExtUnit(ExtUnitView),
    CodecZenohExtZint(ExtZintView),
    CodecZenohQueryValueZbuf(QueryValueZbufView<'a>),
    Default {
        tag: QueryExtEntryUnknownTag,
        body: ExtUnitView,
    },
}

impl<'a> Default for QueryExtEntryViewVariant<'a> {
    fn default() -> Self {
        Self::CodecZenohExtUnit(ExtUnitView::default())
    }
}

#[allow(dead_code)]
#[derive(Default, Debug, Clone, PartialEq)]
pub struct QueryExtEntryView<'a> {
    pub header: u8,
    pub body: QueryExtEntryViewVariant<'a>,
}

#[allow(dead_code)]
impl<'a> QueryExtEntryView<'a> {
    /// A view with every field at its own type's [`Default`]: the destination
    /// [`Self::decode_into`] fills.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode the next frame from `cursor`: the bytes, the bounds and the
    /// errors of [`QueryExtEntry::decode`], held as a view. On success the
    /// cursor advances past the consumed bytes.
    pub fn decode(cursor: &mut SceCursor<'a>, after_shm: u8) -> Result<Self, CodecError> {
        let mut _out = Self::default();
        Self::decode_into(cursor, &mut _out, after_shm)?;
        Ok(_out)
    }

    /// [`Self::decode`] into a destination the caller owns, so a view that
    /// embeds or dispatches to this one is filled where it will live. On
    /// `Err`, `_out` holds the fields decoded so far and is not to be read.
    pub fn decode_into(cursor: &mut SceCursor<'a>, _out: &mut Self, after_shm: u8) -> Result<(), CodecError> {
        // Declared-but-unconsumed flag inputs: defensive suppress per declared
        // `<sce:flag-input>` so codecs that haven't (yet) consumed an
        // input via `present-if` compile cleanly. The validator enforces
        // declaration; consumption is a per-codec design choice.
        let _ = after_shm;
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
                _out.body = QueryExtEntryViewVariant::CodecZenohExtUnit(ExtUnitView::default());
                if let QueryExtEntryViewVariant::CodecZenohExtUnit(_b) = &mut _out.body {
                    ExtUnitView::decode_into(cursor, _b)?;
                }
            }
            1u8 => {
                _out.body = QueryExtEntryViewVariant::CodecZenohExtZint(ExtZintView::default());
                if let QueryExtEntryViewVariant::CodecZenohExtZint(_b) = &mut _out.body {
                    ExtZintView::decode_into(cursor, _b)?;
                }
            }
            2u8 => {
                _out.body = QueryExtEntryViewVariant::CodecZenohQueryValueZbuf(QueryValueZbufView::default());
                if let QueryExtEntryViewVariant::CodecZenohQueryValueZbuf(_b) = &mut _out.body {
                    QueryValueZbufView::decode_into(cursor, _b, after_shm)?;
                }
            }
            other => {
                _out.body = QueryExtEntryViewVariant::Default {
                    tag: QueryExtEntryUnknownTag(other),
                    body: ExtUnitView::default(),
                };
                if let QueryExtEntryViewVariant::Default { body: _b, .. } = &mut _out.body {
                    ExtUnitView::decode_into(cursor, _b)?;
                }
            }
        }
        _out.header = header;
        Ok(())
    }

    /// Fill `_out`, the builder form [`QueryExtEntry`] a sender fills and
    /// encodes, with what this view says: every field, each embedded body, the
    /// variant arm, and each list entry as the walk yields it, built in the
    /// destination where it will live. Fails only where the destination cannot
    /// hold it, which a destination of the same declared bounds does.
    // The name every view's method has (ADR 0049), which borrows because a
    // view is read, not consumed. Clippy leaves an exported method's name
    // alone; a crate that includes this module privately is asked to rename
    // it, and the one name is what lets a codec reach every view it holds.
    #[allow(clippy::wrong_self_convention)]
    pub fn into_builder(&self, _out: &mut QueryExtEntry<'a>) -> Result<(), CodecError> {
        _out.header = self.header;
        match &self.body {
            QueryExtEntryViewVariant::CodecZenohExtUnit(_b) => {
                _out.body = QueryExtEntryVariant::CodecZenohExtUnit(ExtUnit::default());
                if let QueryExtEntryVariant::CodecZenohExtUnit(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
            QueryExtEntryViewVariant::CodecZenohExtZint(_b) => {
                _out.body = QueryExtEntryVariant::CodecZenohExtZint(ExtZint::default());
                if let QueryExtEntryVariant::CodecZenohExtZint(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
            QueryExtEntryViewVariant::CodecZenohQueryValueZbuf(_b) => {
                _out.body = QueryExtEntryVariant::CodecZenohQueryValueZbuf(QueryValueZbuf::default());
                if let QueryExtEntryVariant::CodecZenohQueryValueZbuf(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
            QueryExtEntryViewVariant::Default { tag, body } => {
                _out.body = QueryExtEntryVariant::Default {
                    tag: *tag,
                    body: ExtUnit::default(),
                };
                if let QueryExtEntryVariant::Default { body: _o, .. } = &mut _out.body {
                    body.into_builder(_o)?;
                }
            }
        }
        Ok(())
    }

    /// Worst-case encoded byte count for this codec, as
    /// [`QueryExtEntry::MAX_ENCODED_BYTES`].
    pub const MAX_ENCODED_BYTES: usize = 1383;

    /// Encode what this view says into the caller-owned sink: the bytes
    /// [`QueryExtEntry::encode`] writes for the value [`Self::into_builder`]
    /// fills, written straight from the view, walking each list, without the
    /// builder. It writes the canonical wire, not the frame the view was decoded
    /// from, so a frame `decode` accepted in a form that is not canonical is
    /// not passed on as it came.
    pub fn encode<S: SceSink>(&self, w: &mut S, after_shm: u8) -> Result<(), CodecError> where CodecError: From<S::Error> {
        QueryExtEntry::encode_source(self, w, after_shm)
    }

    /// Heap-backed convenience facade over [`Self::encode`], which refuses a
    /// value it cannot carry.
    #[cfg(feature = "alloc")]
    pub fn encode_to_vec(&self, after_shm: u8) -> Result<Vec<u8>, CodecError> {
        let mut _sce_v: Vec<u8> = Vec::with_capacity(Self::MAX_ENCODED_BYTES);
        let mut _sce_sink = VecSink::new(&mut _sce_v);
        self.encode(&mut _sce_sink, after_shm)?;
        Ok(_sce_v)
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
// `QueryExtEntry<'a>` above is a zero-copy view borrowing the decode
// buffer. Consumers that persist a decoded value beyond the buffer's
// lifetime — including the self-contained bounded-collection that stores
// elements by value — call `.try_into_owned()` for this lifetime-free
// `QueryExtEntryOwned`. The rkyv-style Archived(borrowed) ↔ native
// (owned) split, both generated from the one SCXML source (SSOT).
//
// The owned form is parameterised by a storage profile rather than fixed at
// build-configuration time: `QueryExtEntryOwned<Heap>` holds growable
// containers with the declared capacities advisory, `QueryExtEntryOwned<Inline>`
// holds every field inline at its declared capacity and never allocates, and
// both exist in the same binary. `QueryExtEntryOwned` alone is the build's
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
// `let v: QueryExtEntryOwned = QueryExtEntryOwned { .. };`
// — because the fields reach the profile through its associated container
// types, which cannot be run backwards to recover the profile from a value.
// Naming it once is also what lets each field's declared capacity infer,
// so no call site repeats a `sce:max-size` / `sce:max-count` constant.
use super::query_value_zbuf::QueryValueZbufOwned;
// Same pub-API policy as the borrowed view above: the owned mirror and its
// projections are cross-crate surface, and which of them a given in-repo
// fixture happens to call says nothing about their value.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct QueryExtEntryOwned<S: ::sce_forge_runtime::codec::CodecStorage = ::sce_forge_runtime::codec::DefaultStorage> {
    pub header: u8,
    pub body: QueryExtEntryOwnedVariant<S>,
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> QueryExtEntryOwned<S> {
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
pub enum QueryExtEntryOwnedVariant<S: ::sce_forge_runtime::codec::CodecStorage = ::sce_forge_runtime::codec::DefaultStorage> {
    CodecZenohExtUnit(ExtUnit),
    CodecZenohExtZint(ExtZint),
    CodecZenohQueryValueZbuf(QueryValueZbufOwned<S>),
    Default {
        tag: QueryExtEntryUnknownTag,
        body: ExtUnit,
    },
}

#[allow(dead_code)]
impl<'a> QueryExtEntryVariant<'a> {
    /// Deep-copy this borrowed variant body into its owned mirror at the
    /// given storage profile. Fallible because a borrowed arm body's own
    /// projection re-checks its declared capacities (the same bounds decode
    /// enforces) — on the growable profile no check can fire.
    pub fn try_into_owned_in<S: ::sce_forge_runtime::codec::CodecStorage>(self) -> Result<QueryExtEntryOwnedVariant<S>, CodecError> {
        Ok(match self {
            QueryExtEntryVariant::CodecZenohExtUnit(_b) => QueryExtEntryOwnedVariant::CodecZenohExtUnit(_b),
            QueryExtEntryVariant::CodecZenohExtZint(_b) => QueryExtEntryOwnedVariant::CodecZenohExtZint(_b),
            QueryExtEntryVariant::CodecZenohQueryValueZbuf(_b) => QueryExtEntryOwnedVariant::CodecZenohQueryValueZbuf(_b.try_into_owned_in::<S>()?),
            QueryExtEntryVariant::Default { tag, body } => QueryExtEntryOwnedVariant::Default { tag, body },
        })
    }

    /// The same projection at the build's default storage profile.
    pub fn try_into_owned(self) -> Result<QueryExtEntryOwnedVariant, CodecError> {
        self.try_into_owned_in()
    }
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> QueryExtEntryOwnedVariant<S> {
    /// Re-borrow this owned variant body back into its borrowed mirror —
    /// the inverse of the projection above. Reuses the borrowed view's
    /// single `encode`; the owned form deliberately carries no encode of
    /// its own.
    pub fn try_as_borrowed(&self) -> Result<QueryExtEntryVariant<'_>, CodecError> {
        let mut _out = QueryExtEntryVariant::default();
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
    pub fn try_as_borrowed_into<'o>(&'o self, _out: &mut QueryExtEntryVariant<'o>) -> Result<(), CodecError> {
        match self {
            QueryExtEntryOwnedVariant::CodecZenohExtUnit(_b) => {
                *_out = QueryExtEntryVariant::CodecZenohExtUnit(Default::default());
                if let QueryExtEntryVariant::CodecZenohExtUnit(_o) = _out {
                    *_o = _b.clone();
                }
            }
            QueryExtEntryOwnedVariant::CodecZenohExtZint(_b) => {
                *_out = QueryExtEntryVariant::CodecZenohExtZint(Default::default());
                if let QueryExtEntryVariant::CodecZenohExtZint(_o) = _out {
                    *_o = _b.clone();
                }
            }
            QueryExtEntryOwnedVariant::CodecZenohQueryValueZbuf(_b) => {
                *_out = QueryExtEntryVariant::CodecZenohQueryValueZbuf(Default::default());
                if let QueryExtEntryVariant::CodecZenohQueryValueZbuf(_o) = _out {
                    _b.try_as_borrowed_into(_o)?;
                }
            }
            QueryExtEntryOwnedVariant::Default { tag, body } => {
                *_out = QueryExtEntryVariant::Default { tag: *tag, body: Default::default() };
                if let QueryExtEntryVariant::Default { body: _o, .. } = _out {
                    *_o = body.clone();
                }
            }
        }
        Ok(())
    }
}

#[allow(dead_code)]
impl<'a> QueryExtEntry<'a> {
    /// Deep-copy this borrowed zero-copy view into an owned, lifetime-free
    /// [`QueryExtEntryOwned`] held in the given storage profile. Call at
    /// a decode boundary when the decoded value must outlive the input
    /// buffer — stored in a long-lived enum, moved across an async task, or
    /// inserted by value into a bounded-collection.
    ///
    /// Fallible for profile uniformity: on the inline profile a field longer
    /// than its declared capacity raises `CodecError::TooManyElements` (the
    /// same bound and error decode enforces), on the growable profile the
    /// copy cannot fail. The borrowed zero-copy path is unaffected either
    /// way.
    pub fn try_into_owned_in<S: ::sce_forge_runtime::codec::CodecStorage>(self) -> Result<QueryExtEntryOwned<S>, CodecError> {
        Ok(QueryExtEntryOwned {
            header: self.header,
            body: self.body.try_into_owned_in::<S>()?,
        })
    }

    /// The same projection at the build's default storage profile — growable
    /// where an allocator exists, inline on the heap-free tier.
    pub fn try_into_owned(self) -> Result<QueryExtEntryOwned, CodecError> {
        self.try_into_owned_in()
    }
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> QueryExtEntryOwned<S> {
    /// Re-borrow this owned value back into the zero-copy borrowed view —
    /// the inverse of `try_into_owned_in`. `encode` lives only on the
    /// borrowed view (the owned form is read-only), so an owned consumer
    /// reaches it via `try_as_borrowed` then `encode` / `encode_to_vec`.
    /// Each field is projected by reference — a cheap re-borrow, not a copy.
    /// Fallible: a bounded `<sce:repeat>` / `<sce:tlv-chain>` list holding
    /// more than its declared `N` raises `CodecError::TooManyElements` — the
    /// same bound decode enforces. Only a growable profile can hold such a
    /// list; on the inline profile the source is already within bounds.
    pub fn try_as_borrowed(&self) -> Result<QueryExtEntry<'_>, CodecError> {
        let mut _out = QueryExtEntry::default();
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
    pub fn try_as_borrowed_into<'o>(&'o self, _out: &mut QueryExtEntry<'o>) -> Result<(), CodecError> {
        _out.header = self.header;
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
    pub fn transcode_in<D: ::sce_forge_runtime::codec::CodecStorage>(&self) -> Result<QueryExtEntryOwned<D>, CodecError> {
        self.try_as_borrowed()?.try_into_owned_in::<D>()
    }
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> QueryExtEntryOwned<S> {
    /// Encode `self` into the caller-owned sink, straight from the owned
    /// fields: the bytes `try_as_borrowed` followed by
    /// [`QueryExtEntry::encode`] writes, without the projection.
    ///
    /// The projection builds the whole borrowed record (every list and
    /// embedded body in it, by value) only for `encode` to read it once. A
    /// sender that holds an owned value encodes it from here.
    /// The same refusals as the projection's: a list longer than the borrowed
    /// view declares raises `CodecError::TooManyElements`, so an owned value the
    /// borrowed form could not carry is an error and never a frame its own
    /// decoder would reject.
    pub fn encode<K: SceSink>(&self, w: &mut K, after_shm: u8) -> Result<(), CodecError> where CodecError: From<K::Error> {
        QueryExtEntry::encode_source(self, w, after_shm)
    }

    /// Heap-backed convenience facade over [`Self::encode`]. Fallible: a list
    /// past the bound the borrowed view declares is refused, as is any value
    /// the encoding cannot carry.
    #[cfg(feature = "alloc")]
    pub fn encode_to_vec(&self, after_shm: u8) -> Result<Vec<u8>, CodecError> {
        let mut _sce_v: Vec<u8> = Vec::with_capacity(QueryExtEntry::MAX_ENCODED_BYTES);
        let mut _sce_sink = VecSink::new(&mut _sce_v);
        self.encode(&mut _sce_sink, after_shm)?;
        Ok(_sce_v)
    }
}

#[allow(dead_code)]
impl<'a> QueryExtEntryVariant<'a> {
    /// The projection above, with the profile's byte and text containers made
    /// from `origin` — what the decoded bytes were taken from.
    pub fn try_into_owned_in_origin<S: ::sce_forge_runtime::codec::OriginStorage>(self, origin: &<S as ::sce_forge_runtime::codec::OriginStorage>::Origin) -> Result<QueryExtEntryOwnedVariant<S>, CodecError> {
        Ok(match self {
            QueryExtEntryVariant::CodecZenohExtUnit(_b) => QueryExtEntryOwnedVariant::CodecZenohExtUnit(_b),
            QueryExtEntryVariant::CodecZenohExtZint(_b) => QueryExtEntryOwnedVariant::CodecZenohExtZint(_b),
            QueryExtEntryVariant::CodecZenohQueryValueZbuf(_b) => QueryExtEntryOwnedVariant::CodecZenohQueryValueZbuf(_b.try_into_owned_in_origin::<S>(origin)?),
            QueryExtEntryVariant::Default { tag, body } => QueryExtEntryOwnedVariant::Default { tag, body },
        })
    }
}

#[allow(dead_code)]
impl<'a> QueryExtEntry<'a> {
    /// Project this borrowed view into an owned [`QueryExtEntryOwned`]
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
    pub fn try_into_owned_in_origin<S: ::sce_forge_runtime::codec::OriginStorage>(self, origin: &<S as ::sce_forge_runtime::codec::OriginStorage>::Origin) -> Result<QueryExtEntryOwned<S>, CodecError> {
        Ok(QueryExtEntryOwned {
            header: self.header,
            body: self.body.try_into_owned_in_origin::<S>(origin)?,
        })
    }
}
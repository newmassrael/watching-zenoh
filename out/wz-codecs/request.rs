// SCE-MAP: request:119 :: _forge_body

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
// RFC §synth-5-B B2/B3: bounded inline list storage for repeat / tlv-chain
// fields — heap-free `heapless::Vec<T, N>` (re-exported by the runtime),
// the Rust mirror of the C11 `T elems[MAX]; len` representation. Always
// available (no `alloc` gate) so list-bearing codecs compile on the
// pure no_std no-alloc MCU tier.
use sce_forge_runtime::heapless::Vec as HeaplessVec;

use super::wireexpr::Wireexpr;
use super::ext_entry::ExtEntry;
#[cfg(feature = "request-put-del")]
use super::msg_put::MsgPut;
#[cfg(feature = "request-put-del")]
use super::msg_del::MsgDel;
use super::query::Query;

use sce_forge_runtime::codec::{ListView, ListWalk};
use super::wireexpr::WireexprView;
use super::ext_entry::ExtEntryView;
#[cfg(feature = "request-put-del")]
use super::msg_put::MsgPutView;
#[cfg(feature = "request-put-del")]
use super::msg_del::MsgDelView;
use super::query::QueryView;

// RFC §synth-5-B variant primitive: discriminated-union body for the
// codec's tag-field suffix. Each arm wraps an imported codec's decoded
// value; the optional Default arm preserves the runtime tag value
// alongside its catch-all body.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum RequestVariant<'a> {
    #[cfg(feature = "request-put-del")]
    CodecZenohMsgPut(MsgPut<'a>),
    #[cfg(feature = "request-put-del")]
    CodecZenohMsgDel(MsgDel<'a>),
    CodecZenohQuery(Query<'a>),
    Default {
        tag: u8,
        body: Query<'a>,
    },
}

impl<'a> Default for RequestVariant<'a> {
    fn default() -> Self {
        // RFC variant-default-uniformity: pick the declared default
        // arm (`<sce:arm default="true"/>`) so a freshly-constructed
        // envelope round-trips byte-exactly through `encode() ->
        // decode()` — pairs with the inner codec's `<sce:flag value=>`
        // -baked `Default::default()` to close the dispatch loop.
        Self::CodecZenohQuery(Query::default())
    }
}

// pub API: codecs are intended for cross-crate consumption (SCE_FORGE.md
// §6 codec). The kind-agnostic conformance harness only references a
// subset of fixtures, so unused-but-pub fields/methods would otherwise
// trigger dead_code on every codec build.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct Request<'a> {
    pub header: u8,
    pub rid: u64,
    pub keyexpr: Wireexpr<'a>,
    pub extensions: Option<HeaplessVec<ExtEntry<'a>, 8>>,
    pub body: RequestVariant<'a>,
}

// RFC variant-default-uniformity: at least one field's
// `<sce:flags>` carrier declares a wire-MID constant via
// `<sce:flag value="N"/>`. Manual `impl Default` bakes the OR of
// every declared `(value & mask) << bit` into that carrier so a
// freshly-constructed instance carries the wire-MID for its own
// dispatch tag. Fields without declared values fall through to
// `Default::default()` (preserving derive(Default) semantics).
impl<'a> Default for Request<'a> {
    fn default() -> Self {
        Self {
            header: 0x1cu8,
            rid: Default::default(),
            keyexpr: Default::default(),
            extensions: Default::default(),
            body: RequestVariant::default(),
        }
    }
}

#[allow(dead_code)]
impl<'a> Request<'a> {
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
        let rid = cursor.read_vle_u64()?;
        Wireexpr::decode_into(cursor, &mut _out.keyexpr, (header >> 5) & 0x1, (header >> 6) & 0x1)?;
        if (header & 0x80u8) != 0 {
            let _vec = _out.extensions.insert(HeaplessVec::<ExtEntry<'a>, 8>::new());
            let mut _more = false;
            for _ in 0..8u32 {
                if cursor.remaining() == 0 { break; }
                let _entry = ExtEntry::decode(cursor)?;
                _more = _entry.z();
                // Bounded by max-depth on both sides — loop count and `_vec`
                // capacity are the same literal — so this push cannot fail. An
                // over-long chain is refused by the guard after the loop.
                _vec.push(_entry).map_err(|_| CodecError::TooManyElements)?;
                if !_more { break; }
            }
            if _more && cursor.remaining() == 0 {
                return Err(CodecError::NeedMoreBytes);
            }
            if _more {
                return Err(CodecError::TlvChainOverflow);
            }
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
            #[cfg(feature = "request-put-del")]
            1u8 => {
                _out.body = RequestVariant::CodecZenohMsgPut(MsgPut::default());
                #[allow(irrefutable_let_patterns)]
                if let RequestVariant::CodecZenohMsgPut(_b) = &mut _out.body {
                    MsgPut::decode_into(cursor, _b)?;
                }
            }
            #[cfg(not(feature = "request-put-del"))]
            1u8 => return Err(CodecError::VariantArmNotBuilt),
            #[cfg(feature = "request-put-del")]
            2u8 => {
                _out.body = RequestVariant::CodecZenohMsgDel(MsgDel::default());
                #[allow(irrefutable_let_patterns)]
                if let RequestVariant::CodecZenohMsgDel(_b) = &mut _out.body {
                    MsgDel::decode_into(cursor, _b)?;
                }
            }
            #[cfg(not(feature = "request-put-del"))]
            2u8 => return Err(CodecError::VariantArmNotBuilt),
            3u8 => {
                _out.body = RequestVariant::CodecZenohQuery(Query::default());
                #[allow(irrefutable_let_patterns)]
                if let RequestVariant::CodecZenohQuery(_b) = &mut _out.body {
                    Query::decode_into(cursor, _b)?;
                }
            }
            other => {
                _out.body = RequestVariant::Default {
                    tag: other,
                    body: Query::default(),
                };
                #[allow(irrefutable_let_patterns)]
                if let RequestVariant::Default { body: _b, .. } = &mut _out.body {
                    Query::decode_into(cursor, _b)?;
                }
            }
        }
        _out.header = header;
        _out.rid = rid;
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

    pub fn n(&self) -> bool {
        (self.header & 0x20) != 0
    }

    pub fn set_n(&mut self, v: bool) {
        if v {
            self.header |= 0x20;
        } else {
            self.header &= !0x20;
        }
    }

    pub fn m(&self) -> bool {
        (self.header & 0x40) != 0
    }

    pub fn set_m(&mut self, v: bool) {
        if v {
            self.header |= 0x40;
        } else {
            self.header &= !0x40;
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

    /// Worst-case encoded byte count for this codec — the upper bound
    /// against which `VecSink::new` reserves capacity in the
    /// `encode_to_vec` facade, and the natural reserve hint for
    /// caller-owned `SliceSink` allocations.
    pub const MAX_ENCODED_BYTES: usize = 11597;

    /// Encode `self` into the caller-owned sink. Returns the value's refusal
    /// when the encoding cannot carry it (a length past its type, a list past
    /// its bound, a gate that disagrees with a presence; the document declares
    /// `sce:encode-may-fail`), or the sink's own error:
    /// `CodecError::BufferOverflow` from a bounded sink when the destination
    /// has insufficient remaining capacity.
    pub fn encode<S: SceSink>(&self, w: &mut S) -> Result<(), CodecError> where CodecError: From<S::Error> {
        Self::encode_source(self, w)
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
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, CodecError> {
        let mut _sce_v: Vec<u8> = Vec::with_capacity(Self::MAX_ENCODED_BYTES);
        let mut _sce_sink = VecSink::new(&mut _sce_v);
        self.encode(&mut _sce_sink)?;
        Ok(_sce_v)
    }
}

/// The arm of `Request`'s variant a value holds, each arm's body as the
/// source it says. The tag is not among them: `Request` derives it from
/// the arm, as it derives a length, and a default arm presents the tag
/// it could not name.
// A default arm's tag is read by the codec that embeds this one and
// derives its own carrier bits from the arm, which not every build uses.
#[allow(dead_code)]
pub enum RequestVariantSource<'s, #[cfg(feature = "request-put-del")] A0: ?Sized, #[cfg(feature = "request-put-del")] A1: ?Sized, A2: ?Sized, D: ?Sized> {
    #[cfg(feature = "request-put-del")]
    CodecZenohMsgPut(&'s A0),
    #[cfg(feature = "request-put-del")]
    CodecZenohMsgDel(&'s A1),
    CodecZenohQuery(&'s A2),
    Default { tag: u8, body: &'s D },
}

/// Flags of `Request` a parent sets in place of the ones a value presents:
/// the end flag of a chain whose entries are `Request`, which the chain
/// derives from where an entry stands.
#[doc(hidden)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RequestOverrides {
    /// The `N` flag of `header`, when a parent sets it.
    pub header_n: Option<bool>,
}

#[allow(dead_code)]
impl RequestOverrides {
    /// Sets `N` of `header` and nothing else.
    #[allow(clippy::needless_update)]
    pub fn header_n(value: bool) -> Self {
        Self { header_n: Some(value), ..Self::default() }
    }
}

// ── Source (ADR 0058) ────────────────────────────────────────────────
/// What a value of `Request` says: its presented fields. A length, a count
/// or the flag a gated field is announced by is not among them; `Request`
/// computes those from what is ([`Request::encode_source`]).
pub trait RequestSource {
    /// The `header` field.
    fn header(&self) -> u8;
    /// The `rid` field.
    fn rid(&self) -> u64;
    /// The `keyexpr` field.
    fn keyexpr(&self) -> &impl super::wireexpr::WireexprSource;
    /// The `extensions` field.
    fn extensions(&self) -> Option<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone>;
    #[cfg(not(feature = "request-put-del"))]
    /// The arm of the variant this value holds.
    fn body(&self) -> RequestVariantSource<'_, impl super::query::QuerySource, impl super::query::QuerySource>;
    #[cfg(feature = "request-put-del")]
    /// The arm of the variant this value holds.
    fn body(&self) -> RequestVariantSource<'_, impl super::msg_put::MsgPutSource, impl super::msg_del::MsgDelSource, impl super::query::QuerySource, impl super::query::QuerySource>;
}

impl<T: RequestSource + ?Sized> RequestSource for &T {
    fn header(&self) -> u8 {
        (**self).header()
    }
    fn rid(&self) -> u64 {
        (**self).rid()
    }
    fn keyexpr(&self) -> &impl super::wireexpr::WireexprSource {
        (**self).keyexpr()
    }
    fn extensions(&self) -> Option<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone> {
        (**self).extensions()
    }
    #[cfg(not(feature = "request-put-del"))]
    fn body(&self) -> RequestVariantSource<'_, impl super::query::QuerySource, impl super::query::QuerySource> {
        (**self).body()
    }
    #[cfg(feature = "request-put-del")]
    fn body(&self) -> RequestVariantSource<'_, impl super::msg_put::MsgPutSource, impl super::msg_del::MsgDelSource, impl super::query::QuerySource, impl super::query::QuerySource> {
        (**self).body()
    }
}

/// The arm of `Request`'s variant that RequestParts holds.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum RequestPartsBody<'a> {
    #[cfg(feature = "request-put-del")]
    CodecZenohMsgPut(&'a super::msg_put::MsgPutParts<'a>),
    #[cfg(feature = "request-put-del")]
    CodecZenohMsgDel(&'a super::msg_del::MsgDelParts<'a>),
    CodecZenohQuery(&'a super::query::QueryParts<'a>),
    /// The tag the grammar could not name, and the body it holds.
    Default { tag: u8, body: &'a super::query::QueryParts<'a> },
}

/// A value of `Request` held in the types a caller already has: a source
/// ([`RequestSource`]) whose lists are slices and whose bodies are references.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct RequestParts<'a> {
    /// The `header` field.
    pub header: u8,
    /// The `rid` field.
    pub rid: u64,
    /// The `keyexpr` field.
    pub keyexpr: &'a super::wireexpr::WireexprParts<'a>,
    /// The `extensions` field.
    pub extensions: Option<&'a [super::ext_entry::ExtEntryParts<'a>]>,
    /// The arm of the variant this value holds.
    pub body: RequestPartsBody<'a>,
}

impl<'a> RequestSource for RequestParts<'a> {
    fn header(&self) -> u8 {
        self.header
    }
    fn rid(&self) -> u64 {
        self.rid
    }
    fn keyexpr(&self) -> &impl super::wireexpr::WireexprSource {
        self.keyexpr
    }
    fn extensions(&self) -> Option<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone> {
        self.extensions.map(<[_]>::iter)
    }
    #[cfg(not(feature = "request-put-del"))]
    fn body(&self) -> RequestVariantSource<'_, impl super::query::QuerySource, impl super::query::QuerySource> {
        match &self.body {
            #[cfg(feature = "request-put-del")]
            RequestPartsBody::CodecZenohMsgPut(_b) => RequestVariantSource::CodecZenohMsgPut(*_b),
            #[cfg(feature = "request-put-del")]
            RequestPartsBody::CodecZenohMsgDel(_b) => RequestVariantSource::CodecZenohMsgDel(*_b),
            RequestPartsBody::CodecZenohQuery(_b) => RequestVariantSource::CodecZenohQuery(*_b),
            RequestPartsBody::Default { tag, body } => RequestVariantSource::Default { tag: *tag, body: *body },
        }
    }
    #[cfg(feature = "request-put-del")]
    fn body(&self) -> RequestVariantSource<'_, impl super::msg_put::MsgPutSource, impl super::msg_del::MsgDelSource, impl super::query::QuerySource, impl super::query::QuerySource> {
        match &self.body {
            #[cfg(feature = "request-put-del")]
            RequestPartsBody::CodecZenohMsgPut(_b) => RequestVariantSource::CodecZenohMsgPut(*_b),
            #[cfg(feature = "request-put-del")]
            RequestPartsBody::CodecZenohMsgDel(_b) => RequestVariantSource::CodecZenohMsgDel(*_b),
            RequestPartsBody::CodecZenohQuery(_b) => RequestVariantSource::CodecZenohQuery(*_b),
            RequestPartsBody::Default { tag, body } => RequestVariantSource::Default { tag: *tag, body: *body },
        }
    }
}

impl<'a> RequestSource for Request<'a> {
    fn header(&self) -> u8 {
        self.header
    }
    fn rid(&self) -> u64 {
        self.rid
    }
    fn keyexpr(&self) -> &impl super::wireexpr::WireexprSource {
        &self.keyexpr
    }
    fn extensions(&self) -> Option<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone> {
        self.extensions.as_ref().map(|_l| _l.iter())
    }
    #[cfg(not(feature = "request-put-del"))]
    fn body(&self) -> RequestVariantSource<'_, impl super::query::QuerySource, impl super::query::QuerySource> {
        match &self.body {
            #[cfg(feature = "request-put-del")]
            RequestVariant::CodecZenohMsgPut(_b) => RequestVariantSource::CodecZenohMsgPut(_b),
            #[cfg(feature = "request-put-del")]
            RequestVariant::CodecZenohMsgDel(_b) => RequestVariantSource::CodecZenohMsgDel(_b),
            RequestVariant::CodecZenohQuery(_b) => RequestVariantSource::CodecZenohQuery(_b),
            RequestVariant::Default { tag, body } => RequestVariantSource::Default { tag: *tag, body },
        }
    }
    #[cfg(feature = "request-put-del")]
    fn body(&self) -> RequestVariantSource<'_, impl super::msg_put::MsgPutSource, impl super::msg_del::MsgDelSource, impl super::query::QuerySource, impl super::query::QuerySource> {
        match &self.body {
            #[cfg(feature = "request-put-del")]
            RequestVariant::CodecZenohMsgPut(_b) => RequestVariantSource::CodecZenohMsgPut(_b),
            #[cfg(feature = "request-put-del")]
            RequestVariant::CodecZenohMsgDel(_b) => RequestVariantSource::CodecZenohMsgDel(_b),
            RequestVariant::CodecZenohQuery(_b) => RequestVariantSource::CodecZenohQuery(_b),
            RequestVariant::Default { tag, body } => RequestVariantSource::Default { tag: *tag, body },
        }
    }
}

impl<'a> RequestSource for RequestView<'a> {
    fn header(&self) -> u8 {
        self.header
    }
    fn rid(&self) -> u64 {
        self.rid
    }
    fn keyexpr(&self) -> &impl super::wireexpr::WireexprSource {
        &self.keyexpr
    }
    fn extensions(&self) -> Option<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone> {
        self.extensions.as_ref().map(|_l| _l.iter())
    }
    #[cfg(not(feature = "request-put-del"))]
    fn body(&self) -> RequestVariantSource<'_, impl super::query::QuerySource, impl super::query::QuerySource> {
        match &self.body {
            #[cfg(feature = "request-put-del")]
            RequestViewVariant::CodecZenohMsgPut(_b) => RequestVariantSource::CodecZenohMsgPut(_b),
            #[cfg(feature = "request-put-del")]
            RequestViewVariant::CodecZenohMsgDel(_b) => RequestVariantSource::CodecZenohMsgDel(_b),
            RequestViewVariant::CodecZenohQuery(_b) => RequestVariantSource::CodecZenohQuery(_b),
            RequestViewVariant::Default { tag, body } => RequestVariantSource::Default { tag: *tag, body },
        }
    }
    #[cfg(feature = "request-put-del")]
    fn body(&self) -> RequestVariantSource<'_, impl super::msg_put::MsgPutSource, impl super::msg_del::MsgDelSource, impl super::query::QuerySource, impl super::query::QuerySource> {
        match &self.body {
            #[cfg(feature = "request-put-del")]
            RequestViewVariant::CodecZenohMsgPut(_b) => RequestVariantSource::CodecZenohMsgPut(_b),
            #[cfg(feature = "request-put-del")]
            RequestViewVariant::CodecZenohMsgDel(_b) => RequestVariantSource::CodecZenohMsgDel(_b),
            RequestViewVariant::CodecZenohQuery(_b) => RequestVariantSource::CodecZenohQuery(_b),
            RequestViewVariant::Default { tag, body } => RequestVariantSource::Default { tag: *tag, body },
        }
    }
}

impl<S: ::sce_forge_runtime::codec::CodecStorage> RequestSource for RequestOwned<S> {
    fn header(&self) -> u8 {
        self.header
    }
    fn rid(&self) -> u64 {
        self.rid
    }
    fn keyexpr(&self) -> &impl super::wireexpr::WireexprSource {
        &self.keyexpr
    }
    fn extensions(&self) -> Option<impl Iterator<Item = impl super::ext_entry::ExtEntrySource> + Clone> {
        self.extensions.as_ref().map(|_l| ::sce_forge_runtime::codec::SceList::as_slice(_l).iter())
    }
    #[cfg(not(feature = "request-put-del"))]
    fn body(&self) -> RequestVariantSource<'_, impl super::query::QuerySource, impl super::query::QuerySource> {
        match &self.body {
            #[cfg(feature = "request-put-del")]
            RequestOwnedVariant::CodecZenohMsgPut(_b) => RequestVariantSource::CodecZenohMsgPut(_b),
            #[cfg(feature = "request-put-del")]
            RequestOwnedVariant::CodecZenohMsgDel(_b) => RequestVariantSource::CodecZenohMsgDel(_b),
            RequestOwnedVariant::CodecZenohQuery(_b) => RequestVariantSource::CodecZenohQuery(_b),
            RequestOwnedVariant::Default { tag, body } => RequestVariantSource::Default { tag: *tag, body },
        }
    }
    #[cfg(feature = "request-put-del")]
    fn body(&self) -> RequestVariantSource<'_, impl super::msg_put::MsgPutSource, impl super::msg_del::MsgDelSource, impl super::query::QuerySource, impl super::query::QuerySource> {
        match &self.body {
            #[cfg(feature = "request-put-del")]
            RequestOwnedVariant::CodecZenohMsgPut(_b) => RequestVariantSource::CodecZenohMsgPut(_b),
            #[cfg(feature = "request-put-del")]
            RequestOwnedVariant::CodecZenohMsgDel(_b) => RequestVariantSource::CodecZenohMsgDel(_b),
            RequestOwnedVariant::CodecZenohQuery(_b) => RequestVariantSource::CodecZenohQuery(_b),
            RequestOwnedVariant::Default { tag, body } => RequestVariantSource::Default { tag: *tag, body },
        }
    }
}

#[allow(dead_code)]
impl<'a> Request<'a> {
    /// Encode what `src` says into the caller-owned sink: the bytes
    /// [`Self::encode`] writes for the value it holds, read through
    /// [`RequestSource`]. A length, a count or a gate flag is computed from what
    /// `src` presents, and a value the encoding cannot carry is refused
    /// before the first byte is written.
    pub fn encode_source<S: RequestSource + ?Sized, K: SceSink>(src: &S, w: &mut K) -> Result<(), CodecError> where CodecError: From<K::Error> {
        Self::count_source(src)?;
        Self::write_source(src, w)
    }

    /// [`Self::encode_source`] without the guard a parent has already made.
    #[doc(hidden)]
    pub fn write_source<S: RequestSource + ?Sized, K: SceSink>(src: &S, w: &mut K) -> Result<(), CodecError> where CodecError: From<K::Error> {
        Self::write_source_in(src, w, &RequestOverrides::default())
    }

    /// [`Self::write_source`] with the flags a parent sets in place of the
    /// ones `src` presents.
    #[doc(hidden)]
    pub fn write_source_in<S: RequestSource + ?Sized, K: SceSink>(src: &S, w: &mut K, over: &RequestOverrides) -> Result<(), CodecError> where CodecError: From<K::Error> {
        let _k_extensions: usize = src.extensions().map_or(0, |_l| _l.count());
        if _k_extensions > 8 {
            return Err(CodecError::TlvChainOverflow);
        }
        let _d_header_m: u8 = match super::wireexpr::WireexprSource::body(src.keyexpr()) { super::wireexpr::WireexprVariantSource::WireexprNonlocal(_) => 0, super::wireexpr::WireexprVariantSource::WireexprLocal(_) => 1 };
        let _p_header_z_0: bool = src.extensions().is_some();
        let mut _c_header: u8 = (((src.header() & !0x40) | (_d_header_m << 6)) & !0x80) | (u8::from(_p_header_z_0) << 7);
        if let Some(_o) = over.header_n {
            _c_header = (_c_header & !0x20) | (u8::from(_o) << 5);
        }
        w.write_u8(_c_header)?;
        w.write_vle_u64(src.rid())?;
        Wireexpr::write_source(src.keyexpr(), w, (_c_header >> 5) & 0x1)?;
        if let Some(_v) = src.extensions() {
            for (_i, _e) in _v.enumerate() {
                ExtEntry::write_source_in(&_e, w, &super::ext_entry::ExtEntryOverrides::header_z(_i + 1 < _k_extensions))?;
            }
        }
        match src.body() {
            #[cfg(feature = "request-put-del")]
            RequestVariantSource::CodecZenohMsgPut(_b) => MsgPut::write_source(_b, w)?,
            #[cfg(feature = "request-put-del")]
            RequestVariantSource::CodecZenohMsgDel(_b) => MsgDel::write_source(_b, w)?,
            RequestVariantSource::CodecZenohQuery(_b) => Query::write_source(_b, w)?,
            RequestVariantSource::Default { body: _b, .. } => Query::write_source(_b, w)?,
        }
        Ok(())
    }

    /// The bytes [`Self::write_source`] writes for `src`, counted with
    /// nothing written.
    #[doc(hidden)]
    pub fn count_source<S: RequestSource + ?Sized>(src: &S) -> Result<usize, CodecError> {
        let mut _c = ::sce_forge_runtime::codec::CountSink::new();
        Self::write_source(src, &mut _c)?;
        Ok(_c.len())
    }
}

impl<'a, S: RequestSource + ?Sized> ::sce_forge_runtime::codec::SourceWrite<S> for Request<'a> {
    type Error<E> = CodecError;

    fn write<K: SceSink>(src: &S, w: &mut K) -> Result<(), CodecError> where CodecError: From<K::Error> {
        Self::write_source(src, w)
    }
}

#[allow(dead_code)]
impl<'a> Request<'a> {
    /// The size of the frame [`Self::encode_source`] writes for `src`, found
    /// with nothing written, or the refusal that encode would give. The result
    /// writes the frame into a window of exactly that size and cannot fail.
    pub fn measure<S: RequestSource + ?Sized>(src: &S) -> Result<::sce_forge_runtime::codec::Measured<'_, Self, S>, CodecError> {
        ::sce_forge_runtime::codec::measure(src)
    }

    /// Write `src` into `window` in one pass and return the bytes it is, for a
    /// window as large as the caller can spare. On an error the window holds a
    /// prefix to discard; see [`::sce_forge_runtime::codec::write_window`].
    pub fn write_window<S: RequestSource + ?Sized>(src: &S, window: &mut [u8]) -> Result<usize, CodecError> {
        let mut sink = ::sce_forge_runtime::codec::SliceSink::new(window);
        Self::write_source(src, &mut sink)?;
        Ok(sink.position())
    }
}


// ── View (ADR 0049) ──────────────────────────────────────────────────
// `RequestView` is what a decode of `Request` learned, not a
// copy of what the wire repeated: a scalar, a string or a bytes field is held
// as `Request` holds it, an embedded body or a variant arm as its
// own view, and a bounded list as the frame it was read from, how many entries
// it holds and what a walk needs to read them again (`ListView`). Its size
// depends on the number of fields and not on any `sce:max-count`, so moving
// one copies a few words however long its lists may be. `decode` refuses the
// frames `Request::decode` refuses, with the same error: the entries
// are decoded once to check them, and a walk afterwards cannot fail.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum RequestViewVariant<'a> {
    #[cfg(feature = "request-put-del")]
    CodecZenohMsgPut(MsgPutView<'a>),
    #[cfg(feature = "request-put-del")]
    CodecZenohMsgDel(MsgDelView<'a>),
    CodecZenohQuery(QueryView<'a>),
    Default {
        tag: u8,
        body: QueryView<'a>,
    },
}

impl<'a> Default for RequestViewVariant<'a> {
    fn default() -> Self {
        Self::CodecZenohQuery(QueryView::default())
    }
}

#[allow(dead_code)]
pub struct RequestExtensionsWalk;

impl ListWalk<0> for RequestExtensionsWalk {
    type Entry<'b> = ExtEntryView<'b>;

    fn decode<'b>(_c: &mut SceCursor<'b>, _a: &[u8; 0]) -> Result<Self::Entry<'b>, CodecError> {
        ExtEntryView::decode(_c)
    }

    fn advance(_e: &Self::Entry<'_>, _s: &mut [u8; 0]) {  }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct RequestView<'a> {
    pub header: u8,
    pub rid: u64,
    pub keyexpr: WireexprView<'a>,
    pub extensions: Option<ListView<'a, RequestExtensionsWalk, 0>>,
    pub body: RequestViewVariant<'a>,
}

impl<'a> Default for RequestView<'a> {
    fn default() -> Self {
        Self {
            header: 0x1cu8,
            rid: Default::default(),
            keyexpr: Default::default(),
            extensions: Default::default(),
            body: RequestViewVariant::default(),
        }
    }
}

#[allow(dead_code)]
impl<'a> RequestView<'a> {
    /// A view with every field at its own type's [`Default`]: the destination
    /// [`Self::decode_into`] fills.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode the next frame from `cursor`: the bytes, the bounds and the
    /// errors of [`Request::decode`], held as a view. On success the
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
        let rid = cursor.read_vle_u64()?;
        WireexprView::decode_into(cursor, &mut _out.keyexpr, (header >> 5) & 0x1, (header >> 6) & 0x1)?;
        if (header & 0x80u8) != 0 {
            let _rest = cursor.peek_slice(cursor.remaining())?;
            let mut _count: u32 = 0;
            let mut _more = false;
            for _ in 0..8u32 {
                if cursor.remaining() == 0 { break; }
                let _entry = ExtEntryView::decode(cursor)?;
                _more = _entry.z();
                _count += 1;
                if !_more { break; }
            }
            if _more && cursor.remaining() == 0 {
                return Err(CodecError::NeedMoreBytes);
            }
            if _more {
                return Err(CodecError::TlvChainOverflow);
            }
            _out.extensions = Some(ListView::new(_rest, _count, []));
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
            #[cfg(feature = "request-put-del")]
            1u8 => {
                _out.body = RequestViewVariant::CodecZenohMsgPut(MsgPutView::default());
                #[allow(irrefutable_let_patterns)]
                if let RequestViewVariant::CodecZenohMsgPut(_b) = &mut _out.body {
                    MsgPutView::decode_into(cursor, _b)?;
                }
            }
            #[cfg(not(feature = "request-put-del"))]
            1u8 => return Err(CodecError::VariantArmNotBuilt),
            #[cfg(feature = "request-put-del")]
            2u8 => {
                _out.body = RequestViewVariant::CodecZenohMsgDel(MsgDelView::default());
                #[allow(irrefutable_let_patterns)]
                if let RequestViewVariant::CodecZenohMsgDel(_b) = &mut _out.body {
                    MsgDelView::decode_into(cursor, _b)?;
                }
            }
            #[cfg(not(feature = "request-put-del"))]
            2u8 => return Err(CodecError::VariantArmNotBuilt),
            3u8 => {
                _out.body = RequestViewVariant::CodecZenohQuery(QueryView::default());
                #[allow(irrefutable_let_patterns)]
                if let RequestViewVariant::CodecZenohQuery(_b) = &mut _out.body {
                    QueryView::decode_into(cursor, _b)?;
                }
            }
            other => {
                _out.body = RequestViewVariant::Default {
                    tag: other,
                    body: QueryView::default(),
                };
                #[allow(irrefutable_let_patterns)]
                if let RequestViewVariant::Default { body: _b, .. } = &mut _out.body {
                    QueryView::decode_into(cursor, _b)?;
                }
            }
        }
        _out.header = header;
        _out.rid = rid;
        Ok(())
    }

    /// Fill `_out`, the builder form [`Request`] a sender fills and
    /// encodes, with what this view says: every field, each embedded body, the
    /// variant arm, and each list entry as the walk yields it, built in the
    /// destination where it will live. Fails only where the destination cannot
    /// hold it, which a destination of the same declared bounds does.
    pub fn into_builder(&self, _out: &mut Request<'a>) -> Result<(), CodecError> {
        _out.header = self.header;
        _out.rid = self.rid;
        self.keyexpr.into_builder(&mut _out.keyexpr)?;
        match &self.extensions {
            Some(_l) => {
                let _vec = _out.extensions.insert(HeaplessVec::new());
                _vec.clear();
                for _e in _l.iter() {
                    _vec.push(ExtEntry::default()).map_err(|_| CodecError::TooManyElements)?;
                    if let Some(_slot) = _vec.last_mut() {
                        _e.into_builder(_slot)?;
                    }
                }
            }
            None => _out.extensions = None,
        }
        match &self.body {
            #[cfg(feature = "request-put-del")]
            RequestViewVariant::CodecZenohMsgPut(_b) => {
                _out.body = RequestVariant::CodecZenohMsgPut(MsgPut::default());
                #[allow(irrefutable_let_patterns)]
                if let RequestVariant::CodecZenohMsgPut(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
            #[cfg(feature = "request-put-del")]
            RequestViewVariant::CodecZenohMsgDel(_b) => {
                _out.body = RequestVariant::CodecZenohMsgDel(MsgDel::default());
                #[allow(irrefutable_let_patterns)]
                if let RequestVariant::CodecZenohMsgDel(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
            RequestViewVariant::CodecZenohQuery(_b) => {
                _out.body = RequestVariant::CodecZenohQuery(Query::default());
                #[allow(irrefutable_let_patterns)]
                if let RequestVariant::CodecZenohQuery(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
            RequestViewVariant::Default { tag, body } => {
                _out.body = RequestVariant::Default {
                    tag: *tag,
                    body: Query::default(),
                };
                #[allow(irrefutable_let_patterns)]
                if let RequestVariant::Default { body: _o, .. } = &mut _out.body {
                    body.into_builder(_o)?;
                }
            }
        }
        Ok(())
    }

    /// Worst-case encoded byte count for this codec, as
    /// [`Request::MAX_ENCODED_BYTES`].
    pub const MAX_ENCODED_BYTES: usize = 11597;

    /// Encode what this view says into the caller-owned sink: the bytes
    /// [`Request::encode`] writes for the value [`Self::into_builder`]
    /// fills, written straight from the view, walking each list, without the
    /// builder. It writes the canonical wire, not the frame the view was decoded
    /// from, so a frame `decode` accepted in a form that is not canonical is
    /// not passed on as it came.
    pub fn encode<S: SceSink>(&self, w: &mut S) -> Result<(), CodecError> where CodecError: From<S::Error> {
        Request::encode_source(self, w)
    }

    /// Heap-backed convenience facade over [`Self::encode`], which refuses a
    /// value it cannot carry.
    #[cfg(feature = "alloc")]
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, CodecError> {
        let mut _sce_v: Vec<u8> = Vec::with_capacity(Self::MAX_ENCODED_BYTES);
        let mut _sce_sink = VecSink::new(&mut _sce_v);
        self.encode(&mut _sce_sink)?;
        Ok(_sce_v)
    }

    pub fn mid(&self) -> u8 {
        self.header & 0x1F
    }

    pub fn n(&self) -> bool {
        (self.header & 0x20) != 0
    }

    pub fn m(&self) -> bool {
        (self.header & 0x40) != 0
    }

    pub fn z(&self) -> bool {
        (self.header & 0x80) != 0
    }

}

// ── Owned projection (storage-parameterised native form) ─────────────
// `Request<'a>` above is a zero-copy view borrowing the decode
// buffer. Consumers that persist a decoded value beyond the buffer's
// lifetime — including the self-contained bounded-collection that stores
// elements by value — call `.try_into_owned()` for this lifetime-free
// `RequestOwned`. The rkyv-style Archived(borrowed) ↔ native
// (owned) split, both generated from the one SCXML source (SSOT).
//
// The owned form is parameterised by a storage profile rather than fixed at
// build-configuration time: `RequestOwned<Heap>` holds growable
// containers with the declared capacities advisory, `RequestOwned<Inline>`
// holds every field inline at its declared capacity and never allocates, and
// both exist in the same binary. `RequestOwned` alone is the build's
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
// `let v: RequestOwned = RequestOwned { .. };`
// — because the fields reach the profile through its associated container
// types, which cannot be run backwards to recover the profile from a value.
// Naming it once is also what lets each field's declared capacity infer,
// so no call site repeats a `sce:max-size` / `sce:max-count` constant.
use super::wireexpr::WireexprOwned;
use super::ext_entry::ExtEntryOwned;
#[cfg(feature = "request-put-del")]
use super::msg_put::MsgPutOwned;
#[cfg(feature = "request-put-del")]
use super::msg_del::MsgDelOwned;
use super::query::QueryOwned;
// Same pub-API policy as the borrowed view above: the owned mirror and its
// projections are cross-crate surface, and which of them a given in-repo
// fixture happens to call says nothing about their value.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct RequestOwned<S: ::sce_forge_runtime::codec::CodecStorage = ::sce_forge_runtime::codec::DefaultStorage> {
    pub header: u8,
    pub rid: u64,
    pub keyexpr: WireexprOwned<S>,
    pub extensions: Option<S::List<ExtEntryOwned<S>, 16>>,
    pub body: RequestOwnedVariant<S>,
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> RequestOwned<S> {
    // RFC §synth-5-B read-accessor parity with the borrowed view: pure
    // bit getters over the copied carrier (rkyv Archived↔native getter
    // parity), so owned consumers read `{Codec}Owned` with the same API as
    // the borrowed view and never re-derive the SCE wire bit layout (SSOT).
    // Read-only — write accessors belong with an owned-encode path, which
    // does not exist yet.
    pub fn mid(&self) -> u8 {
        self.header & 0x1F
    }

    pub fn n(&self) -> bool {
        (self.header & 0x20) != 0
    }

    pub fn m(&self) -> bool {
        (self.header & 0x40) != 0
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
pub enum RequestOwnedVariant<S: ::sce_forge_runtime::codec::CodecStorage = ::sce_forge_runtime::codec::DefaultStorage> {
    #[cfg(feature = "request-put-del")]
    CodecZenohMsgPut(MsgPutOwned<S>),
    #[cfg(feature = "request-put-del")]
    CodecZenohMsgDel(MsgDelOwned<S>),
    CodecZenohQuery(QueryOwned<S>),
    Default {
        tag: u8,
        body: QueryOwned<S>,
    },
}

#[allow(dead_code)]
impl<'a> RequestVariant<'a> {
    /// Deep-copy this borrowed variant body into its owned mirror at the
    /// given storage profile. Fallible because a borrowed arm body's own
    /// projection re-checks its declared capacities (the same bounds decode
    /// enforces) — on the growable profile no check can fire.
    pub fn try_into_owned_in<S: ::sce_forge_runtime::codec::CodecStorage>(self) -> Result<RequestOwnedVariant<S>, CodecError> {
        Ok(match self {
            #[cfg(feature = "request-put-del")]
            RequestVariant::CodecZenohMsgPut(_b) => RequestOwnedVariant::CodecZenohMsgPut(_b.try_into_owned_in::<S>()?),
            #[cfg(feature = "request-put-del")]
            RequestVariant::CodecZenohMsgDel(_b) => RequestOwnedVariant::CodecZenohMsgDel(_b.try_into_owned_in::<S>()?),
            RequestVariant::CodecZenohQuery(_b) => RequestOwnedVariant::CodecZenohQuery(_b.try_into_owned_in::<S>()?),
            RequestVariant::Default { tag, body } => RequestOwnedVariant::Default { tag, body: body.try_into_owned_in::<S>()? },
        })
    }

    /// The same projection at the build's default storage profile.
    pub fn try_into_owned(self) -> Result<RequestOwnedVariant, CodecError> {
        self.try_into_owned_in()
    }
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> RequestOwnedVariant<S> {
    /// Re-borrow this owned variant body back into its borrowed mirror —
    /// the inverse of the projection above. Reuses the borrowed view's
    /// single `encode`; the owned form deliberately carries no encode of
    /// its own.
    pub fn try_as_borrowed(&self) -> Result<RequestVariant<'_>, CodecError> {
        let mut _out = RequestVariant::default();
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
    pub fn try_as_borrowed_into<'o>(&'o self, _out: &mut RequestVariant<'o>) -> Result<(), CodecError> {
        match self {
            #[cfg(feature = "request-put-del")]
            RequestOwnedVariant::CodecZenohMsgPut(_b) => {
                *_out = RequestVariant::CodecZenohMsgPut(Default::default());
                #[allow(irrefutable_let_patterns)]
                if let RequestVariant::CodecZenohMsgPut(_o) = _out {
                    _b.try_as_borrowed_into(_o)?;
                }
            }
            #[cfg(feature = "request-put-del")]
            RequestOwnedVariant::CodecZenohMsgDel(_b) => {
                *_out = RequestVariant::CodecZenohMsgDel(Default::default());
                #[allow(irrefutable_let_patterns)]
                if let RequestVariant::CodecZenohMsgDel(_o) = _out {
                    _b.try_as_borrowed_into(_o)?;
                }
            }
            RequestOwnedVariant::CodecZenohQuery(_b) => {
                *_out = RequestVariant::CodecZenohQuery(Default::default());
                #[allow(irrefutable_let_patterns)]
                if let RequestVariant::CodecZenohQuery(_o) = _out {
                    _b.try_as_borrowed_into(_o)?;
                }
            }
            RequestOwnedVariant::Default { tag, body } => {
                *_out = RequestVariant::Default { tag: *tag, body: Default::default() };
                #[allow(irrefutable_let_patterns)]
                if let RequestVariant::Default { body: _o, .. } = _out {
                    body.try_as_borrowed_into(_o)?;
                }
            }
        }
        Ok(())
    }
}

#[allow(dead_code)]
impl<'a> Request<'a> {
    /// Deep-copy this borrowed zero-copy view into an owned, lifetime-free
    /// [`RequestOwned`] held in the given storage profile. Call at
    /// a decode boundary when the decoded value must outlive the input
    /// buffer — stored in a long-lived enum, moved across an async task, or
    /// inserted by value into a bounded-collection.
    ///
    /// Fallible for profile uniformity: on the inline profile a field longer
    /// than its declared capacity raises `CodecError::TooManyElements` (the
    /// same bound and error decode enforces), on the growable profile the
    /// copy cannot fail. The borrowed zero-copy path is unaffected either
    /// way.
    pub fn try_into_owned_in<S: ::sce_forge_runtime::codec::CodecStorage>(self) -> Result<RequestOwned<S>, CodecError> {
        Ok(RequestOwned {
            header: self.header,
            rid: self.rid,
            keyexpr: self.keyexpr.try_into_owned_in::<S>()?,
            extensions: self.extensions.map(|_v| ::sce_forge_runtime::codec::try_collect_list(_v, |_e| _e.try_into_owned_in::<S>())).transpose()?,
            body: self.body.try_into_owned_in::<S>()?,
        })
    }

    /// The same projection at the build's default storage profile — growable
    /// where an allocator exists, inline on the heap-free tier.
    pub fn try_into_owned(self) -> Result<RequestOwned, CodecError> {
        self.try_into_owned_in()
    }
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> RequestOwned<S> {
    /// Re-borrow this owned value back into the zero-copy borrowed view —
    /// the inverse of `try_into_owned_in`. `encode` lives only on the
    /// borrowed view (the owned form is read-only), so an owned consumer
    /// reaches it via `try_as_borrowed` then `encode` / `encode_to_vec`.
    /// Each field is projected by reference — a cheap re-borrow, not a copy.
    /// Fallible: a bounded `<sce:repeat>` / `<sce:tlv-chain>` list holding
    /// more than its declared `N` raises `CodecError::TooManyElements` — the
    /// same bound decode enforces. Only a growable profile can hold such a
    /// list; on the inline profile the source is already within bounds.
    pub fn try_as_borrowed(&self) -> Result<Request<'_>, CodecError> {
        let mut _out = Request::default();
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
    pub fn try_as_borrowed_into<'o>(&'o self, _out: &mut Request<'o>) -> Result<(), CodecError> {
        _out.header = self.header;
        _out.rid = self.rid;
        self.keyexpr.as_borrowed_into(&mut _out.keyexpr);
        match &self.extensions {
            Some(_l) => ::sce_forge_runtime::codec::try_project_bounded_into(_out.extensions.insert(Default::default()), _l, |_e| Ok(_e.as_borrowed()))?,
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
    pub fn transcode_in<D: ::sce_forge_runtime::codec::CodecStorage>(&self) -> Result<RequestOwned<D>, CodecError> {
        self.try_as_borrowed()?.try_into_owned_in::<D>()
    }
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> RequestOwned<S> {
    /// Encode `self` into the caller-owned sink, straight from the owned
    /// fields: the bytes `try_as_borrowed` followed by
    /// [`Request::encode`] writes, without the projection.
    ///
    /// The projection builds the whole borrowed record (every list and
    /// embedded body in it, by value) only for `encode` to read it once. A
    /// sender that holds an owned value encodes it from here.
    /// The same refusals as the projection's: a list longer than the borrowed
    /// view declares raises `CodecError::TooManyElements`, so an owned value the
    /// borrowed form could not carry is an error and never a frame its own
    /// decoder would reject.
    pub fn encode<K: SceSink>(&self, w: &mut K) -> Result<(), CodecError> where CodecError: From<K::Error> {
        Request::encode_source(self, w)
    }

    /// Heap-backed convenience facade over [`Self::encode`]. Fallible: a list
    /// past the bound the borrowed view declares is refused, as is any value
    /// the encoding cannot carry.
    #[cfg(feature = "alloc")]
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, CodecError> {
        let mut _sce_v: Vec<u8> = Vec::with_capacity(Request::MAX_ENCODED_BYTES);
        let mut _sce_sink = VecSink::new(&mut _sce_v);
        self.encode(&mut _sce_sink)?;
        Ok(_sce_v)
    }
}

#[allow(dead_code)]
impl<'a> RequestVariant<'a> {
    /// The projection above, with the profile's byte and text containers made
    /// from `origin` — what the decoded bytes were taken from.
    pub fn try_into_owned_in_origin<S: ::sce_forge_runtime::codec::OriginStorage>(self, origin: &<S as ::sce_forge_runtime::codec::OriginStorage>::Origin) -> Result<RequestOwnedVariant<S>, CodecError> {
        Ok(match self {
            #[cfg(feature = "request-put-del")]
            RequestVariant::CodecZenohMsgPut(_b) => RequestOwnedVariant::CodecZenohMsgPut(_b.try_into_owned_in_origin::<S>(origin)?),
            #[cfg(feature = "request-put-del")]
            RequestVariant::CodecZenohMsgDel(_b) => RequestOwnedVariant::CodecZenohMsgDel(_b.try_into_owned_in_origin::<S>(origin)?),
            RequestVariant::CodecZenohQuery(_b) => RequestOwnedVariant::CodecZenohQuery(_b.try_into_owned_in_origin::<S>(origin)?),
            RequestVariant::Default { tag, body } => RequestOwnedVariant::Default { tag, body: body.try_into_owned_in_origin::<S>(origin)? },
        })
    }
}

#[allow(dead_code)]
impl<'a> Request<'a> {
    /// Project this borrowed view into an owned [`RequestOwned`]
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
    pub fn try_into_owned_in_origin<S: ::sce_forge_runtime::codec::OriginStorage>(self, origin: &<S as ::sce_forge_runtime::codec::OriginStorage>::Origin) -> Result<RequestOwned<S>, CodecError> {
        Ok(RequestOwned {
            header: self.header,
            rid: self.rid,
            keyexpr: self.keyexpr.try_into_owned_in_origin::<S>(origin)?,
            extensions: self.extensions.map(|_v| ::sce_forge_runtime::codec::try_collect_list(_v, |_e| _e.try_into_owned_in_origin::<S>(origin))).transpose()?,
            body: self.body.try_into_owned_in_origin::<S>(origin)?,
        })
    }
}
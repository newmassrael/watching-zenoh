// SCE-MAP: declare:50

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="codec")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.

use sce_forge_runtime::codec::{CodecError, SceCursor, SceSink};
// RFC §synth-5-B: `VecSink` and the heap-backed `encode_to_vec` facade
// are gated on the `alloc` feature (see
// `sce-forge-runtime/rust/src/codec.rs`). MCU / `no_std` consumers see
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

use super::ext_entry::ExtEntry;
use super::decl_final::DeclFinal;
use super::decl_kexpr::DeclKexpr;
use super::undecl_kexpr::UndeclKexpr;
use super::decl_subscriber::DeclSubscriber;
use super::decl_queryable::DeclQueryable;
use super::decl_token::DeclToken;
use super::undecl_subscriber::UndeclSubscriber;
use super::undecl_queryable::UndeclQueryable;
use super::undecl_token::UndeclToken;

// RFC §synth-5-B variant primitive: discriminated-union body for the
// codec's tag-field suffix. Each arm wraps an imported codec's decoded
// value; the optional Default arm preserves the runtime tag value
// alongside its catch-all body.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum DeclareVariant<'a> {
    CodecZenohDeclKexpr(DeclKexpr<'a>),
    CodecZenohUndeclKexpr(UndeclKexpr),
    CodecZenohDeclSubscriber(DeclSubscriber<'a>),
    CodecZenohUndeclSubscriber(UndeclSubscriber<'a>),
    CodecZenohDeclQueryable(DeclQueryable<'a>),
    CodecZenohUndeclQueryable(UndeclQueryable<'a>),
    CodecZenohDeclToken(DeclToken<'a>),
    CodecZenohUndeclToken(UndeclToken<'a>),
    CodecZenohDeclFinal(DeclFinal),
    Default {
        tag: u8,
        body: DeclFinal,
    },
}

impl<'a> Default for DeclareVariant<'a> {
    fn default() -> Self {
        // RFC variant-default-uniformity: pick the declared default
        // arm (`<sce:arm default="true"/>`) so a freshly-constructed
        // envelope round-trips byte-exactly through `encode() ->
        // decode()` — pairs with the inner codec's `<sce:flag value=>`
        // -baked `Default::default()` to close the dispatch loop.
        Self::CodecZenohDeclFinal(DeclFinal::default())
    }
}

// pub API: codecs are intended for cross-crate consumption (SCE_FORGE.md
// §6 codec). The kind-agnostic conformance harness only references a
// subset of fixtures, so unused-but-pub fields/methods would otherwise
// trigger dead_code on every codec build.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct Declare<'a> {
    pub header: u8,
    pub interest_id: Option<u64>,
    pub extensions: Option<HeaplessVec<ExtEntry<'a>, 4>>,
    pub body: DeclareVariant<'a>,
}

// RFC variant-default-uniformity: at least one field's
// `<sce:flags>` carrier declares a wire-MID constant via
// `<sce:flag value="N"/>`. Manual `impl Default` bakes the OR of
// every declared `(value & mask) << bit` into that carrier so a
// freshly-constructed instance carries the wire-MID for its own
// dispatch tag. Fields without declared values fall through to
// `Default::default()` (preserving derive(Default) semantics).
impl<'a> Default for Declare<'a> {
    fn default() -> Self {
        Self {
            header: 0x1eu8,
            interest_id: Default::default(),
            extensions: Default::default(),
            body: DeclareVariant::default(),
        }
    }
}

#[allow(dead_code)]
impl<'a> Declare<'a> {
    /// Construct an instance with every field zero-initialized via
    /// [`Default`]. Generated procedure_l2 code stores codec instances
    /// as owned members and needs an infallible constructor to
    /// initialize them before any `encode()` or `decode()` call.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode the next frame from `cursor`. On success the cursor
    /// advances past the consumed bytes; on `NeedMoreBytes` the cursor
    /// is left untouched so the caller can resume after appending more
    /// bytes (RFC §synth-5-B L494-519).
    pub fn decode(cursor: &mut SceCursor<'a>) -> Result<Self, CodecError> {
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
        let interest_id = if (header & 0x20u8) != 0 {
            let _v = cursor.read_vle_u64()?;
            Some(_v)
        } else {
            None
        };
        let extensions = if (header & 0x80u8) != 0 {
            let mut _vec: HeaplessVec<ExtEntry<'a>, 4> = HeaplessVec::new();
            for _ in 0..4u32 {
                    if cursor.remaining() == 0 { break; }
                    let _entry = ExtEntry::decode(cursor)?;
                    let _continue = _entry.z();
                    _vec.push(_entry).map_err(|_| CodecError::TooManyElements)?;
                    if !_continue { break; }
                }
            Some(_vec)
        } else {
            None
        };
        let _peek = cursor.peek_slice(1)?[0];
        // Dispatch on the tag field; each arm decodes its body codec
        // from the cursor. The default arm (when declared) carries the
        // runtime tag value so encode can round-trip it back onto the
        // wire.
        let body = match _peek & 0x1F {
            0u8 => DeclareVariant::CodecZenohDeclKexpr(DeclKexpr::decode(cursor)?),
            1u8 => DeclareVariant::CodecZenohUndeclKexpr(UndeclKexpr::decode(cursor)?),
            2u8 => DeclareVariant::CodecZenohDeclSubscriber(DeclSubscriber::decode(cursor)?),
            3u8 => DeclareVariant::CodecZenohUndeclSubscriber(UndeclSubscriber::decode(cursor)?),
            4u8 => DeclareVariant::CodecZenohDeclQueryable(DeclQueryable::decode(cursor)?),
            5u8 => DeclareVariant::CodecZenohUndeclQueryable(UndeclQueryable::decode(cursor)?),
            6u8 => DeclareVariant::CodecZenohDeclToken(DeclToken::decode(cursor)?),
            7u8 => DeclareVariant::CodecZenohUndeclToken(UndeclToken::decode(cursor)?),
            26u8 => DeclareVariant::CodecZenohDeclFinal(DeclFinal::decode(cursor)?),
            other => DeclareVariant::Default {
                tag: other,
                body: DeclFinal::decode(cursor)?,
            },
        };
        Ok(Self {
            header,
            interest_id,
            extensions,
            body,
        })
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

    pub fn i(&self) -> bool {
        (self.header & 0x20) != 0
    }

    pub fn set_i(&mut self, v: bool) {
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

    /// Worst-case encoded byte count for this codec — the upper bound
    /// against which `VecSink::new` reserves capacity in the
    /// `encode_to_vec` facade, and the natural reserve hint for
    /// caller-owned `SliceSink` allocations.
    pub const MAX_ENCODED_BYTES: usize = 444;

    /// Encode `self` into the caller-owned sink. Returns
    /// `CodecError::BufferOverflow` from a bounded sink when the
    /// destination has insufficient remaining capacity; growable
    /// sinks (e.g. `VecSink`) are effectively infallible.
    pub fn encode<S: SceSink>(&self, w: &mut S) -> Result<(), CodecError> {
        // RFC §synth-5-B peek-byte / streaming-prefix:
        // streaming prefix encode (per-field present_if/tlv-chain/embed/
        // repeat helpers). Peek-byte mode: the arm body's encode prepends
        // its own header byte (which the decoder peeked); no separate
        // tag byte is emitted here. Streaming-prefix mode (own-field
        // variant): the carrier is part of the prefix fields and emits
        // through the same per-field path.
        w.write_u8(self.header)?;
        if let Some(_v) = self.interest_id {
        w.write_vle_u64(_v)?;
        }
        if let Some(_list) = &self.extensions {
            for _e in _list {
                _e.encode(w)?;
            }
        }
        // Append the active arm's encoded bytes.
        match &self.body {
            DeclareVariant::CodecZenohDeclKexpr(b) => {
                b.encode(w)?;
            }
            DeclareVariant::CodecZenohUndeclKexpr(b) => {
                b.encode(w)?;
            }
            DeclareVariant::CodecZenohDeclSubscriber(b) => {
                b.encode(w)?;
            }
            DeclareVariant::CodecZenohUndeclSubscriber(b) => {
                b.encode(w)?;
            }
            DeclareVariant::CodecZenohDeclQueryable(b) => {
                b.encode(w)?;
            }
            DeclareVariant::CodecZenohUndeclQueryable(b) => {
                b.encode(w)?;
            }
            DeclareVariant::CodecZenohDeclToken(b) => {
                b.encode(w)?;
            }
            DeclareVariant::CodecZenohUndeclToken(b) => {
                b.encode(w)?;
            }
            DeclareVariant::CodecZenohDeclFinal(b) => {
                b.encode(w)?;
            }
            DeclareVariant::Default { body, .. } => {
                body.encode(w)?;
            }
        }
        Ok(())
    }

    /// Heap-backed convenience facade. Pre-reserves
    /// `MAX_ENCODED_BYTES` so the worst-case write path performs at
    /// most one allocation, then delegates to `encode` over a
    /// `VecSink`. Returns the freshly-encoded byte vector. Callers
    /// targeting zero-alloc hot paths should call `encode` directly
    /// against a caller-owned sink.
    ///
    /// Gated on the `alloc` feature — `VecSink` lives behind the
    /// same gate (see `sce-forge-runtime/rust/src/codec.rs`). MCU /
    /// `no_std` builds without `alloc` only see the sink-based
    /// primary `encode`.
    #[cfg(feature = "alloc")]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut _sce_v: Vec<u8> = Vec::with_capacity(Self::MAX_ENCODED_BYTES);
        let mut _sce_sink = VecSink::new(&mut _sce_v);
        self.encode(&mut _sce_sink)
            .expect("VecSink is infallible");
        _sce_v
    }
}

// ── Owned projection (portable native form) ───────────────────────────
// `Declare<'a>` above is a zero-copy view borrowing the decode
// buffer. Consumers that persist a decoded value beyond the buffer's
// lifetime — including the self-contained bounded-collection that stores
// elements by value — call `.try_into_owned()` for this lifetime-free
// `DeclareOwned`. The rkyv-style Archived(borrowed) ↔ native
// (owned) split, both generated from the one SCXML source (SSOT).
// `String` / `Bytes` fields project to the portable runtime newtypes
// `SceString<N>` / `SceBytes<N>`: an unbounded `String` / `Vec<u8>` under
// `alloc` (the on-wire protocol caps no payload, so the AP profile must
// not either — `N` is advisory) and the heap-free `heapless::String<N>` /
// `heapless::Vec<u8, N>` (the C11 `char[N]` analog) without it, where `N`
// is the hard capacity. A leaf codec's owned form therefore still compiles
// on a no-alloc MCU; only an unbounded owned `Vec` (list / embed / variant
// body) keeps the `alloc` gate. `try_into_owned` stays the fallible
// direction (one `?` per profile: the `alloc` copy cannot fail, the
// no-alloc copy enforces `N`); `try_as_borrowed` re-borrows either
// form infallibly via `.as_slice()` / `.as_str()`.
#[cfg(feature = "alloc")]
use super::ext_entry::ExtEntryOwned;
#[cfg(feature = "alloc")]
use super::decl_kexpr::DeclKexprOwned;
#[cfg(feature = "alloc")]
use super::decl_subscriber::DeclSubscriberOwned;
#[cfg(feature = "alloc")]
use super::decl_queryable::DeclQueryableOwned;
#[cfg(feature = "alloc")]
use super::decl_token::DeclTokenOwned;
#[cfg(feature = "alloc")]
use super::undecl_subscriber::UndeclSubscriberOwned;
#[cfg(feature = "alloc")]
use super::undecl_queryable::UndeclQueryableOwned;
#[cfg(feature = "alloc")]
use super::undecl_token::UndeclTokenOwned;
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq)]
pub struct DeclareOwned {
    pub header: u8,
    pub interest_id: Option<u64>,
    pub extensions: Option<Vec<ExtEntryOwned>>,
    pub body: DeclareOwnedVariant,
}

#[cfg(feature = "alloc")]
#[allow(dead_code)]
impl DeclareOwned {
    // RFC §synth-5-B read-accessor parity with the borrowed view: pure
    // bit getters over the copied carrier (rkyv Archived↔native getter
    // parity), so alloc consumers read `{Codec}Owned` with the same API as
    // the borrowed view and never re-derive the SCE wire bit layout (SSOT).
    // Read-only — write accessors belong with an owned-encode path, which
    // does not exist yet.
    pub fn mid(&self) -> u8 {
        self.header & 0x1F
    }

    pub fn i(&self) -> bool {
        (self.header & 0x20) != 0
    }

    pub fn z(&self) -> bool {
        (self.header & 0x80) != 0
    }
}

#[cfg(feature = "alloc")]
// Variant arms wrap distinct body codecs whose owned mirrors differ in
// field count and size, so the tagged union is inherently size-disparate.
// The lint's only remedy is boxing the large arm, which adds an
// indirection (and allocation) the generated decode path does not need.
// The size spread is the deliberate tagged-union trade-off.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum DeclareOwnedVariant {
    CodecZenohDeclKexpr(DeclKexprOwned),
    CodecZenohUndeclKexpr(UndeclKexpr),
    CodecZenohDeclSubscriber(DeclSubscriberOwned),
    CodecZenohUndeclSubscriber(UndeclSubscriberOwned),
    CodecZenohDeclQueryable(DeclQueryableOwned),
    CodecZenohUndeclQueryable(UndeclQueryableOwned),
    CodecZenohDeclToken(DeclTokenOwned),
    CodecZenohUndeclToken(UndeclTokenOwned),
    CodecZenohDeclFinal(DeclFinal),
    Default {
        tag: u8,
        body: DeclFinal,
    },
}

#[cfg(feature = "alloc")]
impl<'a> DeclareVariant<'a> {
    /// Deep-copy this borrowed variant body into its owned mirror. Fallible
    /// because a borrowed arm body's `try_into_owned` re-checks its bounded
    /// fields against their inline capacity (the same bound decode enforces).
    pub fn try_into_owned(self) -> Result<DeclareOwnedVariant, CodecError> {
        Ok(match self {
            DeclareVariant::CodecZenohDeclKexpr(_b) => DeclareOwnedVariant::CodecZenohDeclKexpr(_b.try_into_owned()?),
            DeclareVariant::CodecZenohUndeclKexpr(_b) => DeclareOwnedVariant::CodecZenohUndeclKexpr(_b),
            DeclareVariant::CodecZenohDeclSubscriber(_b) => DeclareOwnedVariant::CodecZenohDeclSubscriber(_b.try_into_owned()?),
            DeclareVariant::CodecZenohUndeclSubscriber(_b) => DeclareOwnedVariant::CodecZenohUndeclSubscriber(_b.try_into_owned()?),
            DeclareVariant::CodecZenohDeclQueryable(_b) => DeclareOwnedVariant::CodecZenohDeclQueryable(_b.try_into_owned()?),
            DeclareVariant::CodecZenohUndeclQueryable(_b) => DeclareOwnedVariant::CodecZenohUndeclQueryable(_b.try_into_owned()?),
            DeclareVariant::CodecZenohDeclToken(_b) => DeclareOwnedVariant::CodecZenohDeclToken(_b.try_into_owned()?),
            DeclareVariant::CodecZenohUndeclToken(_b) => DeclareOwnedVariant::CodecZenohUndeclToken(_b.try_into_owned()?),
            DeclareVariant::CodecZenohDeclFinal(_b) => DeclareOwnedVariant::CodecZenohDeclFinal(_b),
            DeclareVariant::Default { tag, body } => DeclareOwnedVariant::Default { tag, body },
        })
    }
}

#[cfg(feature = "alloc")]
impl DeclareOwnedVariant {
    /// Re-borrow this owned variant body back into its borrowed mirror —
    /// the inverse of `into_owned`. Reuses the borrowed view's single
    /// `encode`; the owned form deliberately carries no encode of its own.
    pub fn try_as_borrowed(&self) -> Result<DeclareVariant<'_>, CodecError> {
        Ok(match self {
            DeclareOwnedVariant::CodecZenohDeclKexpr(_b) => DeclareVariant::CodecZenohDeclKexpr(_b.as_borrowed()),
            DeclareOwnedVariant::CodecZenohUndeclKexpr(_b) => DeclareVariant::CodecZenohUndeclKexpr(_b.clone()),
            DeclareOwnedVariant::CodecZenohDeclSubscriber(_b) => DeclareVariant::CodecZenohDeclSubscriber(_b.as_borrowed()),
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(_b) => DeclareVariant::CodecZenohUndeclSubscriber(_b.try_as_borrowed()?),
            DeclareOwnedVariant::CodecZenohDeclQueryable(_b) => DeclareVariant::CodecZenohDeclQueryable(_b.try_as_borrowed()?),
            DeclareOwnedVariant::CodecZenohUndeclQueryable(_b) => DeclareVariant::CodecZenohUndeclQueryable(_b.try_as_borrowed()?),
            DeclareOwnedVariant::CodecZenohDeclToken(_b) => DeclareVariant::CodecZenohDeclToken(_b.as_borrowed()),
            DeclareOwnedVariant::CodecZenohUndeclToken(_b) => DeclareVariant::CodecZenohUndeclToken(_b.try_as_borrowed()?),
            DeclareOwnedVariant::CodecZenohDeclFinal(_b) => DeclareVariant::CodecZenohDeclFinal(_b.clone()),
            DeclareOwnedVariant::Default { tag, body } => DeclareVariant::Default { tag: *tag, body: body.clone() },
        })
    }
}

#[cfg(feature = "alloc")]
impl<'a> Declare<'a> {
    /// Deep-copy this borrowed zero-copy view into an owned, lifetime-free
    /// [`DeclareOwned`]. Call at a decode boundary when the
    /// decoded value must outlive the input buffer — stored in a long-lived
    /// enum, moved across an async task, or inserted by value into a
    /// bounded-collection. `String` / `Bytes` fields copy into the portable
    /// `SceString<N>` / `SceBytes<N>`: an unbounded heap copy under `alloc`
    /// (`N` advisory), else a fixed `heapless` copy capped at `N`. The
    /// method is fallible for profile uniformity — without `alloc` an
    /// over-`N` view raises `CodecError::TooManyElements` (the same bound
    /// and error decode enforces); under `alloc` the copy never fails. The
    /// borrowed zero-copy path is unaffected.
    pub fn try_into_owned(self) -> Result<DeclareOwned, CodecError> {
        Ok(DeclareOwned {
            header: self.header,
            interest_id: self.interest_id,
            extensions: self.extensions.map(|_v| _v.into_iter().map(|_e| _e.try_into_owned()).collect::<Result<_, _>>()).transpose()?,
            body: self.body.try_into_owned()?,
        })
    }
}

#[cfg(feature = "alloc")]
impl DeclareOwned {
    /// Re-borrow this owned value back into the zero-copy borrowed view —
    /// the inverse of `try_into_owned`. `encode` lives only on the borrowed
    /// view (the owned form is read-only), so an owned consumer reaches it
    /// via `try_as_borrowed` then `encode` / `encode_to_vec`. Each
    /// field is projected by reference — a cheap re-borrow, not a copy.
    /// Fallible: a bounded `<sce:repeat>` / `<sce:tlv-chain>` list whose
    /// owned `Vec` holds more than its declared `N` raises
    /// `CodecError::TooManyElements` — the same bound decode enforces.
    pub fn try_as_borrowed(&self) -> Result<Declare<'_>, CodecError> {
        Ok(Declare {
            header: self.header,
            interest_id: self.interest_id,
            extensions: self.extensions.as_ref().map(|_l| sce_forge_runtime::codec::try_project_bounded(_l, |_e| Ok(_e.as_borrowed()))).transpose()?,
            body: self.body.try_as_borrowed()?,
        })
    }
}
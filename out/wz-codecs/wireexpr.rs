// SCE-MAP: wireexpr:127 :: _forge_body

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

use super::wireexpr_local::WireexprLocal;
use super::wireexpr_nonlocal::WireexprNonlocal;

use super::wireexpr_local::WireexprLocalView;
use super::wireexpr_nonlocal::WireexprNonlocalView;

// RFC §synth-5-B variant primitive: discriminated-union body for the
// codec's tag-field suffix. Each arm wraps an imported codec's decoded
// value; the optional Default arm preserves the runtime tag value
// alongside its catch-all body.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum WireexprVariant<'a> {
    WireexprNonlocal(WireexprNonlocal<'a>),
    WireexprLocal(WireexprLocal<'a>),
}

impl<'a> Default for WireexprVariant<'a> {
    fn default() -> Self {
        // RFC variant-default-uniformity: pick the declared default
        // arm (`<sce:arm default="true"/>`) so a freshly-constructed
        // envelope round-trips byte-exactly through `encode() ->
        // decode()` — pairs with the inner codec's `<sce:flag value=>`
        // -baked `Default::default()` to close the dispatch loop.
        Self::WireexprLocal(WireexprLocal::default())
    }
}

// pub API: codecs are intended for cross-crate consumption (SCE_FORGE.md
// §6 codec). The kind-agnostic conformance harness only references a
// subset of fixtures, so unused-but-pub fields/methods would otherwise
// trigger dead_code on every codec build.
#[allow(dead_code)]
#[derive(Default, Debug, Clone, PartialEq)]
pub struct Wireexpr<'a> {
    pub body: WireexprVariant<'a>,
}

#[allow(dead_code)]
impl<'a> Wireexpr<'a> {
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
    pub fn decode(cursor: &mut SceCursor<'a>, n: u8, tag: u8) -> Result<Self, CodecError> {
        let mut _out = Self::default();
        Self::decode_into(cursor, &mut _out, n, tag)?;
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
    pub fn decode_into(cursor: &mut SceCursor<'a>, _out: &mut Self, n: u8, tag: u8) -> Result<(), CodecError> {
        // Declared-but-unconsumed flag inputs: defensive suppress per declared
        // `<sce:flag-input>` so codecs that haven't (yet) consumed an
        // input via `present-if` compile cleanly. The validator enforces
        // declaration; consumption is a per-codec design choice.
        let _ = n;
        // Parent-tag dispatch: `tag` is the dispatch value the
        // caller (parent codec) extracted from its own flag carrier
        // and passed in. The type is fixed at u8 — matches the parent's
        // `<sce:flag>` width upper bound.
        // Dispatch on the tag field; each arm decodes its body codec
        // from the cursor. The default arm (when declared) carries the
        // runtime tag value so encode can round-trip it back onto the
        // wire.
        // Each arm is installed in `_out.body` holding its body's default and
        // that body is decoded where it sits, so no arm body is returned up
        // through the variant wrapper.
        match tag {
            0u8 => {
                _out.body = WireexprVariant::WireexprNonlocal(WireexprNonlocal::default());
                if let WireexprVariant::WireexprNonlocal(_b) = &mut _out.body {
                    WireexprNonlocal::decode_into(cursor, _b, n)?;
                }
            }
            1u8 => {
                _out.body = WireexprVariant::WireexprLocal(WireexprLocal::default());
                if let WireexprVariant::WireexprLocal(_b) = &mut _out.body {
                    WireexprLocal::decode_into(cursor, _b, n)?;
                }
            }
            // Build-time `codec/variant-arm-unreachable` proves the
            // arm set covers the tag domain without a default.
            _ => unreachable!("variant exhaustiveness gated by codec/variant-arm-unreachable at parse time"),
        }
        Ok(())
    }

    /// Worst-case encoded byte count for this codec — the upper bound
    /// against which `VecSink::new` reserves capacity in the
    /// `encode_to_vec` facade, and the natural reserve hint for
    /// caller-owned `SliceSink` allocations.
    pub const MAX_ENCODED_BYTES: usize = 146;

    /// Encode `self` into the caller-owned sink. Returns the value's refusal
    /// when the encoding cannot carry it (a length past its type, a list past
    /// its bound, a gate that disagrees with a presence; the document declares
    /// `sce:encode-may-fail`), or the sink's own error:
    /// `CodecError::BufferOverflow` from a bounded sink when the destination
    /// has insufficient remaining capacity.
    pub fn encode<S: SceSink>(&self, w: &mut S, n: u8) -> Result<(), CodecError> where CodecError: From<S::Error> {
        Self::encode_source(self, w, n)
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
    pub fn encode_to_vec(&self, n: u8) -> Result<Vec<u8>, CodecError> {
        let mut _sce_v: Vec<u8> = Vec::with_capacity(Self::MAX_ENCODED_BYTES);
        let mut _sce_sink = VecSink::new(&mut _sce_v);
        self.encode(&mut _sce_sink, n)?;
        Ok(_sce_v)
    }
}

/// The arm of `Wireexpr`'s variant a value holds, each arm's body as the
/// source it says. The tag is not among them: `Wireexpr` derives it from
/// the arm, as it derives a length, and a default arm presents the tag
/// it could not name.
// A default arm's tag is read by the codec that embeds this one and
// derives its own carrier bits from the arm, which not every build uses.
#[allow(dead_code)]
pub enum WireexprVariantSource<'s, A0: ?Sized, A1: ?Sized> {
    WireexprNonlocal(&'s A0),
    WireexprLocal(&'s A1),
}

// ── Source (ADR 0058) ────────────────────────────────────────────────
/// What a value of `Wireexpr` says: its presented fields. A length, a count
/// or the flag a gated field is announced by is not among them; `Wireexpr`
/// computes those from what is ([`Wireexpr::encode_source`]).
pub trait WireexprSource {
    /// The arm of the variant this value holds.
    fn body(&self) -> WireexprVariantSource<'_, impl super::wireexpr_nonlocal::WireexprNonlocalSource, impl super::wireexpr_local::WireexprLocalSource>;
}

impl<T: WireexprSource + ?Sized> WireexprSource for &T {
    fn body(&self) -> WireexprVariantSource<'_, impl super::wireexpr_nonlocal::WireexprNonlocalSource, impl super::wireexpr_local::WireexprLocalSource> {
        (**self).body()
    }
}

/// The arm of `Wireexpr`'s variant that WireexprParts holds.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum WireexprPartsBody<'a> {
    WireexprNonlocal(&'a super::wireexpr_nonlocal::WireexprNonlocalParts<'a>),
    WireexprLocal(&'a super::wireexpr_local::WireexprLocalParts<'a>),
}

/// A value of `Wireexpr` held in the types a caller already has: a source
/// ([`WireexprSource`]) whose lists are slices and whose bodies are references.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct WireexprParts<'a> {
    /// The arm of the variant this value holds.
    pub body: WireexprPartsBody<'a>,
}

impl<'a> WireexprSource for WireexprParts<'a> {
    fn body(&self) -> WireexprVariantSource<'_, impl super::wireexpr_nonlocal::WireexprNonlocalSource, impl super::wireexpr_local::WireexprLocalSource> {
        match &self.body {
            WireexprPartsBody::WireexprNonlocal(_b) => WireexprVariantSource::WireexprNonlocal(*_b),
            WireexprPartsBody::WireexprLocal(_b) => WireexprVariantSource::WireexprLocal(*_b),
        }
    }
}

impl<'a> WireexprSource for Wireexpr<'a> {
    fn body(&self) -> WireexprVariantSource<'_, impl super::wireexpr_nonlocal::WireexprNonlocalSource, impl super::wireexpr_local::WireexprLocalSource> {
        match &self.body {
            WireexprVariant::WireexprNonlocal(_b) => WireexprVariantSource::WireexprNonlocal(_b),
            WireexprVariant::WireexprLocal(_b) => WireexprVariantSource::WireexprLocal(_b),
        }
    }
}

impl<'a> WireexprSource for WireexprView<'a> {
    fn body(&self) -> WireexprVariantSource<'_, impl super::wireexpr_nonlocal::WireexprNonlocalSource, impl super::wireexpr_local::WireexprLocalSource> {
        match &self.body {
            WireexprViewVariant::WireexprNonlocal(_b) => WireexprVariantSource::WireexprNonlocal(_b),
            WireexprViewVariant::WireexprLocal(_b) => WireexprVariantSource::WireexprLocal(_b),
        }
    }
}

impl<S: ::sce_forge_runtime::codec::CodecStorage> WireexprSource for WireexprOwned<S> {
    fn body(&self) -> WireexprVariantSource<'_, impl super::wireexpr_nonlocal::WireexprNonlocalSource, impl super::wireexpr_local::WireexprLocalSource> {
        match &self.body {
            WireexprOwnedVariant::WireexprNonlocal(_b) => WireexprVariantSource::WireexprNonlocal(_b),
            WireexprOwnedVariant::WireexprLocal(_b) => WireexprVariantSource::WireexprLocal(_b),
        }
    }
}

#[allow(dead_code)]
impl<'a> Wireexpr<'a> {
    /// Encode what `src` says into the caller-owned sink: the bytes
    /// [`Self::encode`] writes for the value it holds, read through
    /// [`WireexprSource`]. A length, a count or a gate flag is computed from what
    /// `src` presents, and a value the encoding cannot carry is refused
    /// before the first byte is written.
    pub fn encode_source<S: WireexprSource + ?Sized, K: SceSink>(src: &S, w: &mut K, n: u8) -> Result<(), CodecError> where CodecError: From<K::Error> {
        Self::count_source(src, n)?;
        Self::write_source(src, w, n)
    }

    /// [`Self::encode_source`] without the guard a parent has already made.
    #[doc(hidden)]
    pub fn write_source<S: WireexprSource + ?Sized, K: SceSink>(src: &S, w: &mut K, n: u8) -> Result<(), CodecError> where CodecError: From<K::Error> {
        let _ = n;
        match src.body() {
            WireexprVariantSource::WireexprNonlocal(_b) => WireexprNonlocal::write_source(_b, w, n)?,
            WireexprVariantSource::WireexprLocal(_b) => WireexprLocal::write_source(_b, w, n)?,
        }
        Ok(())
    }

    /// The bytes [`Self::write_source`] writes for `src`, counted with
    /// nothing written.
    #[doc(hidden)]
    pub fn count_source<S: WireexprSource + ?Sized>(src: &S, n: u8) -> Result<usize, CodecError> {
        let mut _c = ::sce_forge_runtime::codec::CountSink::new();
        Self::write_source(src, &mut _c, n)?;
        Ok(_c.len())
    }
}


// ── View (ADR 0049) ──────────────────────────────────────────────────
// `WireexprView` is what a decode of `Wireexpr` learned, not a
// copy of what the wire repeated: a scalar, a string or a bytes field is held
// as `Wireexpr` holds it, an embedded body or a variant arm as its
// own view, and a bounded list as the frame it was read from, how many entries
// it holds and what a walk needs to read them again (`ListView`). Its size
// depends on the number of fields and not on any `sce:max-count`, so moving
// one copies a few words however long its lists may be. `decode` refuses the
// frames `Wireexpr::decode` refuses, with the same error: the entries
// are decoded once to check them, and a walk afterwards cannot fail.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum WireexprViewVariant<'a> {
    WireexprNonlocal(WireexprNonlocalView<'a>),
    WireexprLocal(WireexprLocalView<'a>),
}

impl<'a> Default for WireexprViewVariant<'a> {
    fn default() -> Self {
        Self::WireexprLocal(WireexprLocalView::default())
    }
}

#[allow(dead_code)]
#[derive(Default, Debug, Clone, PartialEq)]
pub struct WireexprView<'a> {
    pub body: WireexprViewVariant<'a>,
}

#[allow(dead_code)]
impl<'a> WireexprView<'a> {
    /// A view with every field at its own type's [`Default`]: the destination
    /// [`Self::decode_into`] fills.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode the next frame from `cursor`: the bytes, the bounds and the
    /// errors of [`Wireexpr::decode`], held as a view. On success the
    /// cursor advances past the consumed bytes.
    pub fn decode(cursor: &mut SceCursor<'a>, n: u8, tag: u8) -> Result<Self, CodecError> {
        let mut _out = Self::default();
        Self::decode_into(cursor, &mut _out, n, tag)?;
        Ok(_out)
    }

    /// [`Self::decode`] into a destination the caller owns, so a view that
    /// embeds or dispatches to this one is filled where it will live. On
    /// `Err`, `_out` holds the fields decoded so far and is not to be read.
    pub fn decode_into(cursor: &mut SceCursor<'a>, _out: &mut Self, n: u8, tag: u8) -> Result<(), CodecError> {
        // Declared-but-unconsumed flag inputs: defensive suppress per declared
        // `<sce:flag-input>` so codecs that haven't (yet) consumed an
        // input via `present-if` compile cleanly. The validator enforces
        // declaration; consumption is a per-codec design choice.
        let _ = n;
        // Parent-tag dispatch: `tag` is the dispatch value the
        // caller (parent codec) extracted from its own flag carrier
        // and passed in. The type is fixed at u8 — matches the parent's
        // `<sce:flag>` width upper bound.
        // Dispatch on the tag field; each arm decodes its body codec
        // from the cursor. The default arm (when declared) carries the
        // runtime tag value so encode can round-trip it back onto the
        // wire.
        // Each arm is installed in `_out.body` holding its body's default and
        // that body is decoded where it sits, so no arm body is returned up
        // through the variant wrapper.
        match tag {
            0u8 => {
                _out.body = WireexprViewVariant::WireexprNonlocal(WireexprNonlocalView::default());
                if let WireexprViewVariant::WireexprNonlocal(_b) = &mut _out.body {
                    WireexprNonlocalView::decode_into(cursor, _b, n)?;
                }
            }
            1u8 => {
                _out.body = WireexprViewVariant::WireexprLocal(WireexprLocalView::default());
                if let WireexprViewVariant::WireexprLocal(_b) = &mut _out.body {
                    WireexprLocalView::decode_into(cursor, _b, n)?;
                }
            }
            // Build-time `codec/variant-arm-unreachable` proves the
            // arm set covers the tag domain without a default.
            _ => unreachable!("variant exhaustiveness gated by codec/variant-arm-unreachable at parse time"),
        }
        Ok(())
    }

    /// Fill `_out`, the builder form [`Wireexpr`] a sender fills and
    /// encodes, with what this view says: every field, each embedded body, the
    /// variant arm, and each list entry as the walk yields it, built in the
    /// destination where it will live. Fails only where the destination cannot
    /// hold it, which a destination of the same declared bounds does.
    pub fn into_builder(&self, _out: &mut Wireexpr<'a>) -> Result<(), CodecError> {
        match &self.body {
            WireexprViewVariant::WireexprNonlocal(_b) => {
                _out.body = WireexprVariant::WireexprNonlocal(WireexprNonlocal::default());
                if let WireexprVariant::WireexprNonlocal(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
            WireexprViewVariant::WireexprLocal(_b) => {
                _out.body = WireexprVariant::WireexprLocal(WireexprLocal::default());
                if let WireexprVariant::WireexprLocal(_o) = &mut _out.body {
                    _b.into_builder(_o)?;
                }
            }
        }
        Ok(())
    }

    /// Worst-case encoded byte count for this codec, as
    /// [`Wireexpr::MAX_ENCODED_BYTES`].
    pub const MAX_ENCODED_BYTES: usize = 146;

    /// Encode what this view says into the caller-owned sink: the bytes
    /// [`Wireexpr::encode`] writes for the value [`Self::into_builder`]
    /// fills, written straight from the view, walking each list, without the
    /// builder. It writes the canonical wire, not the frame the view was decoded
    /// from, so a frame `decode` accepted in a form that is not canonical is
    /// not passed on as it came.
    pub fn encode<S: SceSink>(&self, w: &mut S, n: u8) -> Result<(), CodecError> where CodecError: From<S::Error> {
        Wireexpr::encode_source(self, w, n)
    }

    /// Heap-backed convenience facade over [`Self::encode`], which refuses a
    /// value it cannot carry.
    #[cfg(feature = "alloc")]
    pub fn encode_to_vec(&self, n: u8) -> Result<Vec<u8>, CodecError> {
        let mut _sce_v: Vec<u8> = Vec::with_capacity(Self::MAX_ENCODED_BYTES);
        let mut _sce_sink = VecSink::new(&mut _sce_v);
        self.encode(&mut _sce_sink, n)?;
        Ok(_sce_v)
    }
}

// ── Owned projection (storage-parameterised native form) ─────────────
// `Wireexpr<'a>` above is a zero-copy view borrowing the decode
// buffer. Consumers that persist a decoded value beyond the buffer's
// lifetime — including the self-contained bounded-collection that stores
// elements by value — call `.try_into_owned()` for this lifetime-free
// `WireexprOwned`. The rkyv-style Archived(borrowed) ↔ native
// (owned) split, both generated from the one SCXML source (SSOT).
//
// The owned form is parameterised by a storage profile rather than fixed at
// build-configuration time: `WireexprOwned<Heap>` holds growable
// containers with the declared capacities advisory, `WireexprOwned<Inline>`
// holds every field inline at its declared capacity and never allocates, and
// both exist in the same binary. `WireexprOwned` alone is the build's
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
// `let v: WireexprOwned = WireexprOwned { .. };`
// — because the fields reach the profile through its associated container
// types, which cannot be run backwards to recover the profile from a value.
// Naming it once is also what lets each field's declared capacity infer,
// so no call site repeats a `sce:max-size` / `sce:max-count` constant.
use super::wireexpr_local::WireexprLocalOwned;
use super::wireexpr_nonlocal::WireexprNonlocalOwned;
// Same pub-API policy as the borrowed view above: the owned mirror and its
// projections are cross-crate surface, and which of them a given in-repo
// fixture happens to call says nothing about their value.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct WireexprOwned<S: ::sce_forge_runtime::codec::CodecStorage = ::sce_forge_runtime::codec::DefaultStorage> {
    pub body: WireexprOwnedVariant<S>,
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
pub enum WireexprOwnedVariant<S: ::sce_forge_runtime::codec::CodecStorage = ::sce_forge_runtime::codec::DefaultStorage> {
    WireexprNonlocal(WireexprNonlocalOwned<S>),
    WireexprLocal(WireexprLocalOwned<S>),
}

#[allow(dead_code)]
impl<'a> WireexprVariant<'a> {
    /// Deep-copy this borrowed variant body into its owned mirror at the
    /// given storage profile. Fallible because a borrowed arm body's own
    /// projection re-checks its declared capacities (the same bounds decode
    /// enforces) — on the growable profile no check can fire.
    pub fn try_into_owned_in<S: ::sce_forge_runtime::codec::CodecStorage>(self) -> Result<WireexprOwnedVariant<S>, CodecError> {
        Ok(match self {
            WireexprVariant::WireexprNonlocal(_b) => WireexprOwnedVariant::WireexprNonlocal(_b.try_into_owned_in::<S>()?),
            WireexprVariant::WireexprLocal(_b) => WireexprOwnedVariant::WireexprLocal(_b.try_into_owned_in::<S>()?),
        })
    }

    /// The same projection at the build's default storage profile.
    pub fn try_into_owned(self) -> Result<WireexprOwnedVariant, CodecError> {
        self.try_into_owned_in()
    }
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> WireexprOwnedVariant<S> {
    /// Re-borrow this owned variant body back into its borrowed mirror —
    /// the inverse of the projection above. Reuses the borrowed view's
    /// single `encode`; the owned form deliberately carries no encode of
    /// its own.
    pub fn as_borrowed(&self) -> WireexprVariant<'_> {
        let mut _out = WireexprVariant::default();
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
    pub fn as_borrowed_into<'o>(&'o self, _out: &mut WireexprVariant<'o>) {
        match self {
            WireexprOwnedVariant::WireexprNonlocal(_b) => {
                *_out = WireexprVariant::WireexprNonlocal(Default::default());
                if let WireexprVariant::WireexprNonlocal(_o) = _out {
                    _b.as_borrowed_into(_o);
                }
            }
            WireexprOwnedVariant::WireexprLocal(_b) => {
                *_out = WireexprVariant::WireexprLocal(Default::default());
                if let WireexprVariant::WireexprLocal(_o) = _out {
                    _b.as_borrowed_into(_o);
                }
            }
        }
        
    }
}

#[allow(dead_code)]
impl<'a> Wireexpr<'a> {
    /// Deep-copy this borrowed zero-copy view into an owned, lifetime-free
    /// [`WireexprOwned`] held in the given storage profile. Call at
    /// a decode boundary when the decoded value must outlive the input
    /// buffer — stored in a long-lived enum, moved across an async task, or
    /// inserted by value into a bounded-collection.
    ///
    /// Fallible for profile uniformity: on the inline profile a field longer
    /// than its declared capacity raises `CodecError::TooManyElements` (the
    /// same bound and error decode enforces), on the growable profile the
    /// copy cannot fail. The borrowed zero-copy path is unaffected either
    /// way.
    pub fn try_into_owned_in<S: ::sce_forge_runtime::codec::CodecStorage>(self) -> Result<WireexprOwned<S>, CodecError> {
        Ok(WireexprOwned {
            body: self.body.try_into_owned_in::<S>()?,
        })
    }

    /// The same projection at the build's default storage profile — growable
    /// where an allocator exists, inline on the heap-free tier.
    pub fn try_into_owned(self) -> Result<WireexprOwned, CodecError> {
        self.try_into_owned_in()
    }
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> WireexprOwned<S> {
    /// Re-borrow this owned value back into the zero-copy borrowed view —
    /// the inverse of `try_into_owned_in`. `encode` lives only on the
    /// borrowed view (the owned form is read-only), so an owned consumer
    /// reaches it via `as_borrowed` then `encode` / `encode_to_vec`.
    /// Each field is projected by reference — a cheap re-borrow, not a copy.
    pub fn as_borrowed(&self) -> Wireexpr<'_> {
        let mut _out = Wireexpr::default();
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
    pub fn as_borrowed_into<'o>(&'o self, _out: &mut Wireexpr<'o>) {
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
    pub fn transcode_in<D: ::sce_forge_runtime::codec::CodecStorage>(&self) -> Result<WireexprOwned<D>, CodecError> {
        self.as_borrowed().try_into_owned_in::<D>()
    }
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> WireexprOwned<S> {
    /// Encode `self` into the caller-owned sink, straight from the owned
    /// fields: the bytes `as_borrowed` followed by
    /// [`Wireexpr::encode`] writes, without the projection.
    ///
    /// The projection builds the whole borrowed record (every list and
    /// embedded body in it, by value) only for `encode` to read it once. A
    /// sender that holds an owned value encodes it from here.
    /// The same refusals as the projection's: a list longer than the borrowed
    /// view declares raises `CodecError::TooManyElements`, so an owned value the
    /// borrowed form could not carry is an error and never a frame its own
    /// decoder would reject.
    pub fn encode<K: SceSink>(&self, w: &mut K, n: u8) -> Result<(), CodecError> where CodecError: From<K::Error> {
        Wireexpr::encode_source(self, w, n)
    }

    /// Heap-backed convenience facade over [`Self::encode`]. Fallible: a list
    /// past the bound the borrowed view declares is refused, as is any value
    /// the encoding cannot carry.
    #[cfg(feature = "alloc")]
    pub fn encode_to_vec(&self, n: u8) -> Result<Vec<u8>, CodecError> {
        let mut _sce_v: Vec<u8> = Vec::with_capacity(Wireexpr::MAX_ENCODED_BYTES);
        let mut _sce_sink = VecSink::new(&mut _sce_v);
        self.encode(&mut _sce_sink, n)?;
        Ok(_sce_v)
    }
}

#[allow(dead_code)]
impl<'a> WireexprVariant<'a> {
    /// The projection above, with the profile's byte and text containers made
    /// from `origin` — what the decoded bytes were taken from.
    pub fn try_into_owned_in_origin<S: ::sce_forge_runtime::codec::OriginStorage>(self, origin: &<S as ::sce_forge_runtime::codec::OriginStorage>::Origin) -> Result<WireexprOwnedVariant<S>, CodecError> {
        Ok(match self {
            WireexprVariant::WireexprNonlocal(_b) => WireexprOwnedVariant::WireexprNonlocal(_b.try_into_owned_in_origin::<S>(origin)?),
            WireexprVariant::WireexprLocal(_b) => WireexprOwnedVariant::WireexprLocal(_b.try_into_owned_in_origin::<S>(origin)?),
        })
    }
}

#[allow(dead_code)]
impl<'a> Wireexpr<'a> {
    /// Project this borrowed view into an owned [`WireexprOwned`]
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
    pub fn try_into_owned_in_origin<S: ::sce_forge_runtime::codec::OriginStorage>(self, origin: &<S as ::sce_forge_runtime::codec::OriginStorage>::Origin) -> Result<WireexprOwned<S>, CodecError> {
        Ok(WireexprOwned {
            body: self.body.try_into_owned_in_origin::<S>(origin)?,
        })
    }
}
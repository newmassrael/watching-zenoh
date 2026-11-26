// SCE-MAP: compressed_batch:26 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="codec")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.

use sce_forge_runtime::codec::{CodecError, SceCursor, SceReader, SceSink};
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


// pub API: codecs are intended for cross-crate consumption (SCE_FORGE.md
// §6 codec). The kind-agnostic conformance harness only references a
// subset of fixtures, so unused-but-pub fields/methods would otherwise
// trigger dead_code on every codec build.
/// The field `payload` of `CompressedBatch`, which a storage profile
/// answers for by this type.
#[allow(dead_code)]
pub struct CompressedBatchPayloadField;

impl ::sce_forge_runtime::codec::HoldsBytes<CompressedBatchPayloadField> for ::sce_forge_runtime::codec::Inline {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<65535>;
}

/// What `CompressedBatchIn` and the codecs it holds ask of a storage profile.
#[allow(dead_code)]
pub trait CompressedBatchStorage: ::core::fmt::Debug + Clone + PartialEq + ::sce_forge_runtime::codec::HoldsBytes<CompressedBatchPayloadField> {}

impl<S: ::core::fmt::Debug + Clone + PartialEq + ::sce_forge_runtime::codec::HoldsBytes<CompressedBatchPayloadField>> CompressedBatchStorage for S {}

/// What `CompressedBatchIn<Lent<'a, D>>` asks of the profile `D`: how it holds
/// the lists of `CompressedBatch` and of the codecs it holds, since the lent
/// form borrows every byte string and text from the frame (docs/adr/0077 §7).
#[allow(dead_code)]
pub trait CompressedBatchLentStorage: ::core::fmt::Debug + Clone + PartialEq {}

impl<D: ::core::fmt::Debug + Clone + PartialEq> CompressedBatchLentStorage for D {}

/// What a decode of a frame of the lifetime `'f` asks of a storage profile
/// beside CompressedBatchStorage: how it stores each field of that frame.
#[allow(dead_code)]
pub trait CompressedBatchFrom<'f>: CompressedBatchStorage + ::sce_forge_runtime::codec::StoresBytes<'f, CompressedBatchPayloadField> {}

impl<'f, S: CompressedBatchStorage + ::sce_forge_runtime::codec::StoresBytes<'f, CompressedBatchPayloadField>> CompressedBatchFrom<'f> for S {}

// `CompressedBatchIn<S>` is the one value this codec has, at the storage
// profile `S` (docs/adr/0077 §7). `CompressedBatch<'a>` is it on `Lent`, which
// borrows bytes and text from the frame, and `CompressedBatchOwned<S>` names it
// at a profile that holds them.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct CompressedBatchIn<S: CompressedBatchStorage> {
    pub header: u8,
    pub payload: ::sce_forge_runtime::codec::Bounded<<S as ::sce_forge_runtime::codec::HoldsBytes<CompressedBatchPayloadField>>::Bytes, 65535>,
}

/// The eager form: bytes and text borrowed from the frame, lists held inline.
#[allow(dead_code)]
pub type CompressedBatch<'a> = CompressedBatchIn<::sce_forge_runtime::codec::Lent<'a>>;

/// The value at a profile that holds its bytes and text.
#[allow(dead_code)]
pub type CompressedBatchOwned<S = ::sce_forge_runtime::codec::DefaultStorage> = CompressedBatchIn<S>;

impl<S: CompressedBatchStorage> Default for CompressedBatchIn<S> {
    fn default() -> Self {
        Self {
            header: Default::default(),
            payload: Default::default(),
        }
    }
}

#[allow(dead_code)]
impl<S: CompressedBatchStorage> CompressedBatchIn<S> {
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

    /// Decode the next frame from `cursor`. On success the cursor advances
    /// past the consumed bytes; on a refusal it does not move, so a caller that
    /// receives `NeedMoreBytes` reads the frame again from the same place once
    /// more bytes have arrived (RFC §synth-5-B L494-519, docs/adr/0128).
    pub fn decode<'f>(cursor: &mut SceCursor<'f>) -> Result<Self, CodecError> where S: CompressedBatchFrom<'f> {
        cursor.read_frame(Self::read)
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
    ///
    /// A field past what the profile holds is read on and not held, and the
    /// frame is refused with `CapacityExceeded` only once it is read whole and
    /// every refusal of its own has had its turn (docs/adr/0077 §7), so this
    /// node and one that holds more refuse a malformed frame alike. On `Err`,
    /// `_out` holds the fields decoded so far and is not to be read; each of
    /// them holds what its type says.
    pub fn decode_into<'f>(cursor: &mut SceCursor<'f>, _out: &mut Self) -> Result<(), CodecError> where S: CompressedBatchFrom<'f> {
        cursor.read_frame(|cursor| Self::read_into(cursor, _out))
    }

    /// Read the frame through `cursor`, the frame's reader, as a value built
    /// once from its fields: every read total, each refusal recorded in the
    /// reader and the first of them the frame's verdict, which the reader says
    /// once the frame is read (docs/adr/0128). A codec that embeds or
    /// dispatches to this one reads it through this one function, out of line
    /// where the set reads it from two sites or more so that no site holds a
    /// copy (docs/adr/0136, docs/adr/0137).
    pub fn read<'f>(cursor: &mut SceReader<'f>) -> Self where S: CompressedBatchFrom<'f> {
        // Variable-length codec. RFC §synth-5-B B3 stream-correct shape:
        // a codec without `<sce:field sce:bit-size="tail">` consumes
        // only `min_bytes + length_value` rather than the entire
        // remaining input. Codecs WITH a tail field still consume
        // to end (tail's definition forces it). The TLV chain is the
        // multi-frame consumer, so length-ref entry codecs decode
        // iterably from a shared reader without each entry eating the
        // next entry's bytes. The fixed head is at least `min_bytes`
        // bytes, zeros once the frame has failed (docs/adr/0128), so
        // its reads by constant offsets below it hold on either.
        let raw = cursor.peek_at_least::<1>();
        let _frame_len = raw.len();
        let header = raw[0];
        if (_frame_len - 1) > 65535 {
            cursor.fail(CodecError::LengthOutOfRange);
        }
        let payload = &raw[1..];
        let payload = cursor.settle(::sce_forge_runtime::codec::Bounded::new(payload).ok_or(CodecError::LengthOutOfRange));
        let payload = cursor.hold(payload.store::<S, CompressedBatchPayloadField>());
        let value = Self {
            header,
            payload,
        };
        cursor.advance(_frame_len);
        value
    }

    /// [`Self::read`] into a destination the caller owns, so a codec that
    /// embeds or dispatches to this one reads it where it will live.
    pub fn read_into<'f>(cursor: &mut SceReader<'f>, _out: &mut Self) where S: CompressedBatchFrom<'f> {
        *_out = Self::read(cursor);
    }

    /// [`Self::read`], under the name every view reads with a chain hook
    /// (docs/adr/0130): `CompressedBatch` is its own view and holds no chain,
    /// so `_hook` is shown nothing.
    #[inline(always)]
    pub fn read_with<'f, H: ::sce_forge_runtime::codec::ChainHook>(cursor: &mut SceReader<'f>, _hook: &mut H) -> Self where S: CompressedBatchFrom<'f> {
        Self::read(cursor)
    }

    // RFC §synth-5-B flags primitive: per-bit-range accessors over
    // the carrier field. Single-bit (width=1) reads as bool; multi-bit
    // (width>=2) reads as the smallest unsigned integer that fits the
    // range. Setters mask + shift on the way in so out-of-range
    // callers can't corrupt sibling bits. Wire layout is unchanged —
    // the carrier still occupies its declared bytes.
    pub fn compression(&self) -> bool {
        (self.header & 0x01) != 0
    }

    pub fn set_compression(&mut self, v: bool) {
        if v {
            self.header |= 0x01;
        } else {
            self.header &= !0x01;
        }
    }

    /// Worst-case encoded byte count for this codec — the upper bound
    /// against which `VecSink::new` reserves capacity in the
    /// `encode_to_vec` facade, and the natural reserve hint for
    /// caller-owned `SliceSink` allocations.
    pub const MAX_ENCODED_BYTES: usize = 65536;

    /// Encode `self` into the caller-owned sink. Every value has a frame
    /// (docs/adr/0065), so the only error is the sink's own:
    /// `CodecError::BufferOverflow` from a bounded sink when the destination
    /// has insufficient remaining capacity, and none from a sink that cannot
    /// refuse (`VecSink`, `CountSink`).
    pub fn encode<K: SceSink>(&self, w: &mut K) -> Result<(), K::Error> {
        CompressedBatchWire::encode_source(self, w)
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

/// Flags of `CompressedBatch` a parent sets in place of the ones a value presents:
/// the end flag of a chain whose entries are `CompressedBatch`, which the chain
/// derives from where an entry stands.
#[doc(hidden)]
#[derive(Debug, Default, Clone, Copy)]
pub struct CompressedBatchOverrides {
    /// The `compression` flag of `header`, when a parent sets it.
    pub header_compression: Option<bool>,
}

#[allow(dead_code)]
impl CompressedBatchOverrides {
    /// Sets `compression` of `header` and nothing else.
    #[allow(clippy::needless_update)]
    pub fn header_compression(value: bool) -> Self {
        Self { header_compression: Some(value), ..Self::default() }
    }
}

// ── Source (ADR 0058) ────────────────────────────────────────────────
/// What a value of `CompressedBatch` says: its presented fields. A length, a count
/// or the flag a gated field is announced by is not among them; the
/// encode computes those from what is ([`CompressedBatchWire::encode_source`]).
pub trait CompressedBatchSource {
    /// The `header` field.
    fn header(&self) -> u8;
    /// The `payload` field.
    fn payload(&self) -> ::sce_forge_runtime::codec::Bytes<'_, 65535>;
}

impl<T: CompressedBatchSource + ?Sized> CompressedBatchSource for &T {
    fn header(&self) -> u8 {
        (**self).header()
    }
    fn payload(&self) -> ::sce_forge_runtime::codec::Bytes<'_, 65535> {
        (**self).payload()
    }
}

/// A value of `CompressedBatch` held in the types a caller already has: a source
/// ([`CompressedBatchSource`]) whose lists are slices within their bounds and whose
/// bodies are references.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct CompressedBatchParts<'a> {
    /// The `header` field.
    pub header: u8,
    /// The `payload` field.
    pub payload: ::sce_forge_runtime::codec::Bytes<'a, 65535>,
}

impl<'a> CompressedBatchSource for CompressedBatchParts<'a> {
    fn header(&self) -> u8 {
        self.header
    }
    fn payload(&self) -> ::sce_forge_runtime::codec::Bytes<'_, 65535> {
        self.payload
    }
}

#[allow(dead_code)]
impl<'a> CompressedBatchParts<'a> {
    /// The parts of what `src` says, each accessor of [`CompressedBatchSource`] read
    /// once: the one form a codec that holds this one writes it from,
    /// whatever form the value it is handed is in (docs/adr/0058).
    #[doc(hidden)]
    pub fn of<S: CompressedBatchSource + ?Sized>(src: &'a S) -> Self {
        Self {
            header: src.header(),
            payload: src.payload(),
        }
    }
}

impl<S: CompressedBatchStorage> CompressedBatchSource for CompressedBatchOwned<S> {
    fn header(&self) -> u8 {
        self.header
    }
    fn payload(&self) -> ::sce_forge_runtime::codec::Bytes<'_, 65535> {
        self.payload.as_bytes()
    }
}

/// The codec `CompressedBatch` itself: what writes a value read through
/// [`CompressedBatchSource`], holding no value and naming no storage profile. Every
/// form of the value, a parent and a view write through it, so a profile
/// that cannot hold some field is never asked for here (docs/adr/0077 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CompressedBatchWire;

#[allow(dead_code)]
impl CompressedBatchWire {
    /// Encode what `src` says into the caller-owned sink: the bytes
    /// `CompressedBatch::encode` writes for the value it holds, read through
    /// [`CompressedBatchSource`]. A length, a count or a gate flag is computed from what
    /// `src` presents. Every value `src` can present has a frame, so the
    /// only error is the sink's (docs/adr/0065).
    pub fn encode_source<S: CompressedBatchSource + ?Sized, K: SceSink>(src: &S, w: &mut K) -> Result<(), K::Error> {
        Self::write_source(src, w)
    }

    /// [`Self::encode_source`] without the guard a parent has already made.
    #[doc(hidden)]
    pub fn write_source<S: CompressedBatchSource + ?Sized, K: SceSink>(src: &S, w: &mut K) -> Result<(), K::Error> {
        Self::write_source_in(src, w, &CompressedBatchOverrides::default())
    }

    /// [`Self::write_source`] with the flags a parent sets in place of the
    /// ones `src` presents. `src` is read once into `CompressedBatchParts`, whatever form
    /// it is in, and the wire is written from that one form (`write_parts_in`).
    #[doc(hidden)]
    pub fn write_source_in<S: CompressedBatchSource + ?Sized, K: SceSink>(src: &S, w: &mut K, over: &CompressedBatchOverrides) -> Result<(), K::Error> {
        Self::write_parts_in(&CompressedBatchParts::of(src), w, over)
    }

    /// The wire of `src`, the one form every source of this codec is read
    /// into: one writer for each sink, however many forms are written. It is
    /// out of line unless every write is asked inlined (`--inline-encode`):
    /// inlined into `write_source_in`, it is copied into each form.
    #[inline(never)]
    fn write_parts_in<K: SceSink>(src: &CompressedBatchParts<'_>, w: &mut K, over: &CompressedBatchOverrides) -> Result<(), K::Error> {
        let mut _c_header: u8 = src.header();
        if let Some(_o) = over.header_compression {
            _c_header = (_c_header & !0x1) | u8::from(_o);
        }
        w.write_u8(_c_header)?;
        w.write_bytes(src.payload().into_inner())?;
        Ok(())
    }

    /// The bytes [`Self::write_source`] writes for `src`, counted with
    /// nothing written.
    #[doc(hidden)]
    pub fn count_source<S: CompressedBatchSource + ?Sized>(src: &S) -> usize {
        let mut _c = ::sce_forge_runtime::codec::CountSink::new();
        let Ok(()) = Self::write_source(src, &mut _c);
        _c.len()
    }
}

impl<S: CompressedBatchSource + ?Sized> ::sce_forge_runtime::codec::SourceWrite<S> for CompressedBatchWire {
    type Error<E> = E;

    fn write<K: SceSink>(src: &S, w: &mut K) -> Result<(), K::Error> where CodecError: From<K::Error> {
        Self::write_source(src, w)
    }
}

#[allow(dead_code)]
impl CompressedBatchWire {
    /// The size of the frame [`Self::encode_source`] writes for `src`, found
    /// with nothing written: the encode refuses no value, so neither does
    /// this. The result writes the frame into a window of exactly that size
    /// and cannot fail.
    pub fn measure<S: CompressedBatchSource + ?Sized>(src: &S) -> ::sce_forge_runtime::codec::Measured<'_, Self, S> {
        let Ok(measured) = ::sce_forge_runtime::codec::measure(src);
        measured
    }

    /// Write `src` into `window` in one pass and return the bytes it is, for a
    /// window as large as the caller can spare. On an error the window holds a
    /// prefix to discard; see [`::sce_forge_runtime::codec::write_window`].
    pub fn write_window<S: CompressedBatchSource + ?Sized>(src: &S, window: &mut [u8]) -> Result<usize, CodecError> {
        let mut sink = ::sce_forge_runtime::codec::SliceSink::new(window);
        Self::write_source(src, &mut sink)?;
        Ok(sink.position())
    }
}


// ── View (ADR 0049) ──────────────────────────────────────────────────
/// How a list of `CompressedBatch` reads its entries when it carries nothing from one
/// entry to the next: one walk for every such list of every codec.
#[allow(dead_code)]
pub struct CompressedBatchWalk;

impl ::sce_forge_runtime::codec::ListWalk<0> for CompressedBatchWalk {
    type Entry<'b> = CompressedBatchView<'b>;

    #[inline(always)]
    fn read_with<'b, H: ::sce_forge_runtime::codec::ChainHook>(_r: &mut SceReader<'b>, _a: &[u8; 0], _h: &mut H) -> Self::Entry<'b> {
        CompressedBatchView::read_with(_r, _h)
    }

    fn advance(_e: &Self::Entry<'_>, _s: &mut [u8; 0]) {  }
}

// `CompressedBatch` holds no bounded list, embedded body or variant, so a
// view of it would hold what it holds. Its view is the codec itself under the
// name every codec's view has, which lets a codec that embeds, lists or
// dispatches to it name `CompressedBatchView` whatever kind of codec it is.
#[allow(dead_code)]
pub type CompressedBatchView<'a> = CompressedBatch<'a>;

#[allow(dead_code)]
impl<'a> CompressedBatch<'a> {
    /// Fill `_out` with what this value says, as the view of any other codec
    /// does (`CompressedBatchView` is this type, so it takes part in the same
    /// call).
    // The name every view's method has (ADR 0049), which borrows because a
    // view is read, not consumed. Clippy leaves an exported method's name
    // alone; a crate that includes this module privately is asked to rename
    // it, and the one name is what lets a codec reach every view it holds.
    #[allow(clippy::wrong_self_convention)]
    // A codec with no list holds every field alike at every profile, so the
    // value at any `D` is filled field by field (docs/adr/0077 §7).
    pub fn into_builder<D>(&self, _out: &mut CompressedBatchIn<::sce_forge_runtime::codec::Lent<'a, D>>) -> Result<(), CodecError> where D: CompressedBatchLentStorage {
        _out.header = self.header;
        _out.payload = self.payload;
        Ok(())
    }
}

// ── Owned projection (storage-parameterised native form) ─────────────
// `CompressedBatch<'a>` above is a zero-copy view borrowing the decode
// buffer. Consumers that persist a decoded value beyond the buffer's
// lifetime — including the self-contained bounded-collection that stores
// elements by value — call `.try_into_owned()` for this lifetime-free
// `CompressedBatchOwned`. The rkyv-style Archived(borrowed) ↔ native
// (owned) split, both generated from the one SCXML source (SSOT).
//
// The owned form is parameterised by a storage profile rather than fixed at
// build-configuration time: `CompressedBatchOwned<Heap>` holds growable
// containers with the declared capacities advisory, `CompressedBatchOwned<Inline>`
// holds every field inline at its declared capacity and never allocates, and
// both exist in the same binary. `CompressedBatchOwned` alone is the build's
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
// `let v: CompressedBatchOwned = CompressedBatchOwned { .. };`
// — because the fields reach the profile through its associated container
// types, which cannot be run backwards to recover the profile from a value.
// Naming it once is also what lets each field's container infer, so no call
// site repeats a capacity. A capacity is not in this file at all except as
// what `Inline` holds: a deployment answers for the same tags from its own.

// The lent value at any profile `D` that holds its lists: what a decode of a
// frame gives where bytes and text borrow it, `CompressedBatch<'a>` being it
// at `Inline` (docs/adr/0077 §7).
#[allow(dead_code)]
impl<'a, D> CompressedBatchIn<::sce_forge_runtime::codec::Lent<'a, D>> where D: CompressedBatchLentStorage {
    /// Deep-copy this borrowed zero-copy view into an owned, lifetime-free
    /// [`CompressedBatchOwned`] held in the given storage profile. Call at
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
    pub fn try_into_owned_in<S: CompressedBatchFrom<'a>>(self) -> Result<CompressedBatchOwned<S>, CodecError> {
        Ok(CompressedBatchOwned {
            header: self.header,
            payload: self.payload.store::<S, CompressedBatchPayloadField>()?,
        })
    }

    /// The same projection at the build's default storage profile — growable
    /// where an allocator exists, inline on the heap-free tier.
    pub fn try_into_owned(self) -> Result<CompressedBatchOwned, CodecError> {
        self.try_into_owned_in()
    }
}

#[allow(dead_code)]
impl<S: CompressedBatchStorage> CompressedBatchOwned<S> {
    /// Re-borrow this owned value back into the zero-copy borrowed view —
    /// the inverse of `try_into_owned_in`. `encode` lives only on the
    /// borrowed view (the owned form is read-only), so an owned consumer
    /// reaches it via `as_borrowed` then `encode` / `encode_to_vec`.
    /// Each field is projected by reference — a cheap re-borrow, not a copy.
    pub fn as_borrowed(&self) -> CompressedBatchIn<::sce_forge_runtime::codec::Lent<'_, S>> {
        let mut _out = Default::default();
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
    pub fn as_borrowed_into<'o>(&'o self, _out: &mut CompressedBatchIn<::sce_forge_runtime::codec::Lent<'o, S>>) {
        _out.header = self.header;
        _out.payload = self.payload.as_bytes();
        
    }

    /// Move this value to a different storage profile — growable to inline
    /// when handing it to a path that must not allocate, or inline to
    /// growable when it is leaving that path.
    ///
    /// A checked projection through the borrowed view, not a re-decode: the
    /// bytes are copied once and every destination capacity is enforced, so
    /// a value that cannot fit the target profile is rejected here rather
    /// than truncated.
    pub fn transcode_in<D: for<'x> CompressedBatchFrom<'x>>(&self) -> Result<CompressedBatchOwned<D>, CodecError> {
        self.as_borrowed().try_into_owned_in::<D>()
    }
}

/// What the origin projection of `CompressedBatch` asks of a storage profile
/// beside CompressedBatchStorage: that it is an origin profile, and
/// that each byte string and text of `CompressedBatch` and of the codecs it
/// holds is built from the origin by the container the profile holds it in.
#[allow(dead_code)]
pub trait CompressedBatchOrigin: CompressedBatchStorage + ::sce_forge_runtime::codec::OriginStorage + ::sce_forge_runtime::codec::OriginBytes<CompressedBatchPayloadField> {}

impl<S: CompressedBatchStorage + ::sce_forge_runtime::codec::OriginStorage + ::sce_forge_runtime::codec::OriginBytes<CompressedBatchPayloadField>> CompressedBatchOrigin for S {}

#[allow(dead_code)]
impl<'a, D> CompressedBatchIn<::sce_forge_runtime::codec::Lent<'a, D>> where D: CompressedBatchLentStorage {
    /// Project this borrowed view into an owned [`CompressedBatchOwned`]
    /// whose byte and text containers are each built from the slice AND
    /// `origin`, the buffer the view was decoded from, by the
    /// container the profile holds that field in. A container that shares
    /// that buffer refers back to it instead of copying out of it; what the
    /// origin is, and what to do with a slice that does not come from it, is
    /// the profile's to say, field by field.
    ///
    /// `try_into_owned_in` stays the copying projection. Every codec this one
    /// embeds, repeats or dispatches to must have been generated with
    /// `--owned-origin` as well.
    pub fn try_into_owned_in_origin<S: CompressedBatchOrigin>(self, origin: &<S as ::sce_forge_runtime::codec::OriginStorage>::Origin) -> Result<CompressedBatchOwned<S>, CodecError> {
        Ok(CompressedBatchOwned {
            header: self.header,
            payload: ::sce_forge_runtime::codec::Bounded::from_built(<S as ::sce_forge_runtime::codec::OriginBytes<CompressedBatchPayloadField>>::bytes_from(origin, self.payload.into_inner()))?,
        })
    }
}
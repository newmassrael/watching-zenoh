// SCE-MAP: query_value_zbuf:56 :: _forge_body

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
use super::encoding::EncodingView;
use super::zbuf_slice::ZbufSliceView;

// pub API: codecs are intended for cross-crate consumption (SCE_FORGE.md
// §6 codec). The kind-agnostic conformance harness only references a
// subset of fixtures, so unused-but-pub fields/methods would otherwise
// trigger dead_code on every codec build.
use super::encoding::EncodingOwned;
use super::zbuf_slice::ZbufSliceOwned;
/// The field `value` of `QueryValueZbuf`, which a storage profile
/// answers for by this type.
#[allow(dead_code)]
pub struct QueryValueZbufValueField;

impl ::sce_forge_runtime::codec::HoldsBytes<QueryValueZbufValueField> for ::sce_forge_runtime::codec::Inline {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<4294967295>;
}

/// The field `slices` of `QueryValueZbuf`, which a storage profile
/// answers for by this type.
#[allow(dead_code)]
pub struct QueryValueZbufSlicesField;

impl ::sce_forge_runtime::codec::HoldsList<QueryValueZbufSlicesField> for ::sce_forge_runtime::codec::Inline {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 4294967295> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

/// What `QueryValueZbufIn` and the codecs it holds ask of a storage profile.
#[allow(dead_code)]
pub trait QueryValueZbufStorage: ::core::fmt::Debug + Clone + PartialEq + ::sce_forge_runtime::codec::HoldsBytes<QueryValueZbufValueField> + ::sce_forge_runtime::codec::HoldsList<QueryValueZbufSlicesField> + super::encoding::EncodingStorage + super::zbuf_slice::ZbufSliceStorage {}

impl<S: ::core::fmt::Debug + Clone + PartialEq + ::sce_forge_runtime::codec::HoldsBytes<QueryValueZbufValueField> + ::sce_forge_runtime::codec::HoldsList<QueryValueZbufSlicesField> + super::encoding::EncodingStorage + super::zbuf_slice::ZbufSliceStorage> QueryValueZbufStorage for S {}

/// What `QueryValueZbufIn<Lent<'a, D>>` asks of the profile `D`: how it holds
/// the lists of `QueryValueZbuf` and of the codecs it holds, since the lent
/// form borrows every byte string and text from the frame (docs/adr/0077 §7).
#[allow(dead_code)]
pub trait QueryValueZbufLentStorage: ::core::fmt::Debug + Clone + PartialEq + ::sce_forge_runtime::codec::HoldsList<QueryValueZbufSlicesField> + super::encoding::EncodingLentStorage + super::zbuf_slice::ZbufSliceLentStorage {}

impl<D: ::core::fmt::Debug + Clone + PartialEq + ::sce_forge_runtime::codec::HoldsList<QueryValueZbufSlicesField> + super::encoding::EncodingLentStorage + super::zbuf_slice::ZbufSliceLentStorage> QueryValueZbufLentStorage for D {}

/// What a decode of a frame of the lifetime `'f` asks of a storage profile
/// beside QueryValueZbufStorage: how it stores each field of that frame.
#[allow(dead_code)]
pub trait QueryValueZbufFrom<'f>: QueryValueZbufStorage + ::sce_forge_runtime::codec::StoresBytes<'f, QueryValueZbufValueField> + super::encoding::EncodingFrom<'f> + super::zbuf_slice::ZbufSliceFrom<'f> {}

impl<'f, S: QueryValueZbufStorage + ::sce_forge_runtime::codec::StoresBytes<'f, QueryValueZbufValueField> + super::encoding::EncodingFrom<'f> + super::zbuf_slice::ZbufSliceFrom<'f>> QueryValueZbufFrom<'f> for S {}

/// The group `QueryValueZbufAfterShm` as `QueryValueZbufOwned` holds it, in the storage
/// profile `S`.
#[allow(dead_code)]
pub type QueryValueZbufAfterShmOwned<S> = QueryValueZbufAfterShm<EncodingOwned<S>, ::sce_forge_runtime::codec::Bounded<<S as ::sce_forge_runtime::codec::HoldsList<QueryValueZbufSlicesField>>::List<ZbufSliceOwned<S>>, 4294967295>, ::sce_forge_runtime::codec::Bounded<<S as ::sce_forge_runtime::codec::HoldsBytes<QueryValueZbufValueField>>::Bytes, 4294967295>>;

// `QueryValueZbufIn<S>` is the one value this codec has, at the storage
// profile `S` (docs/adr/0077 §7). `QueryValueZbuf<'a>` is it on `Lent`, which
// borrows bytes and text from the frame, and `QueryValueZbufOwned<S>` names it
// at a profile that holds them.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct QueryValueZbufIn<S: QueryValueZbufStorage> {
    pub after_shm: QueryValueZbufAfterShmOwned<S>,
    pub slice_count: Option<u32>,
}

/// The eager form: bytes and text borrowed from the frame, lists held inline.
#[allow(dead_code)]
pub type QueryValueZbuf<'a> = QueryValueZbufIn<::sce_forge_runtime::codec::Lent<'a>>;

/// The value at a profile that holds its bytes and text.
#[allow(dead_code)]
pub type QueryValueZbufOwned<S = ::sce_forge_runtime::codec::DefaultStorage> = QueryValueZbufIn<S>;

impl<S: QueryValueZbufStorage> Default for QueryValueZbufIn<S> {
    fn default() -> Self {
        Self {
            after_shm: Default::default(),
            slice_count: Default::default(),
        }
    }
}

#[allow(dead_code)]
impl<S: QueryValueZbufStorage> QueryValueZbufIn<S> {
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
    pub fn decode<'f>(cursor: &mut SceCursor<'f>, after_shm: u8) -> Result<Self, CodecError> where S: QueryValueZbufFrom<'f> {
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
    pub fn decode_into<'f>(cursor: &mut SceCursor<'f>, _out: &mut Self, after_shm: u8) -> Result<(), CodecError> where S: QueryValueZbufFrom<'f> {
        // A form past its capacity stopped where it could not store, so the
        // frame is judged by what cannot run out, and only a frame that parses
        // is one this node cannot hold (docs/adr/0077 §7). Any profile may hold
        // less than a bound, so this stands on every codec that takes one.
        let mut _frame = *cursor;
        match Self::store_into(cursor, _out, after_shm) {
            Err(CodecError::CapacityExceeded) => {
                QueryValueZbufView::decode(&mut _frame, after_shm)?;
                Err(CodecError::CapacityExceeded)
            }
            stored => stored,
        }
    }

    /// The reading of [`Self::decode_into`], which stops where a field is past
    /// its capacity.
    fn store_into<'f>(cursor: &mut SceCursor<'f>, _out: &mut Self, after_shm: u8) -> Result<(), CodecError> where S: QueryValueZbufFrom<'f> {
        // Declared-but-unconsumed flag inputs: defensive suppress per declared
        // `<sce:flag-input>` so codecs that haven't (yet) consumed an
        // input via `present-if` compile cleanly. The validator enforces
        // declaration; consumption is a per-codec design choice.
        let _ = after_shm;
        // Streaming cursor decode (SSOT selection: `needs_streaming`).
        // The positional `raw[byte_off]` path is valid only when every
        // field's absolute offset is fixed at codegen time; this branch
        // handles every codec where it is not — present-if-gated fields
        // (runtime presence), VLE / repeat / TLV-chain / embed fields
        // (runtime width), string fields (UTF-8 decode), and a fixed field
        // after a variable-length payload (offset depends on the payload
        // length). Each field reads its own bytes from the cursor and
        // advances past exactly what it consumed. Per-field `is_repeat` /
        // `is_tlv_chain` / `is_embed` route to their dedicated helpers;
        // every other field flows through `present_if_decode_stmt`, whose
        // non-gated arm covers plain fixed / tail / length-ref / VLE reads.
        let value_len = cursor.read_vle_u64()?;
        let value = if (after_shm & 0x01u8) == 0 {
            let _len = value_len;
            if _len > 4294967295 {
                return Err(CodecError::LengthOutOfRange);
            }
            let _n = usize::try_from(_len).map_err(|_| CodecError::NeedMoreBytes)?;
            let raw = cursor.peek_slice(_n)?;
            let _v = raw;
            cursor.advance(_n)?;
            Some(_v)
        } else {
            None
        };
        let value = value.map(|_v| ::sce_forge_runtime::codec::Bounded::new(_v).ok_or(CodecError::LengthOutOfRange)).transpose()?;
        let value = value.map(|_v| _v.store::<S, QueryValueZbufValueField>()).transpose()?;
        let mut encoding: Option<EncodingOwned<S>> = None;
        if (after_shm & 0x01u8) != 0 {
            EncodingOwned::<S>::decode_into(cursor, encoding.insert(EncodingOwned::<S>::default()))?;
        } else {
            encoding = None;
        }
        let slice_count = if (after_shm & 0x01u8) != 0 {
            let _v = cursor.read_vle_u32()?;
            Some(_v)
        } else {
            None
        };
        let mut slices: Option<::sce_forge_runtime::codec::Bounded<<S as ::sce_forge_runtime::codec::HoldsList<QueryValueZbufSlicesField>>::List<ZbufSliceOwned<S>>, 4294967295>> = None;
        if (after_shm & 0x01u8) != 0 {
            let _n = slice_count.expect("co-gating: count present-if matches repeat");
            slices.insert(Default::default()).refill(|_vec| {
                for _ in 0.._n {
                    ::sce_forge_runtime::codec::SceList::try_push(_vec, ZbufSliceOwned::<S>::decode(cursor)?)?;
                }
                Ok(())
            })?;
        } else {
            slices = None;
        }
        _out.after_shm = if (after_shm & 0x01u8) != 0 { QueryValueZbufAfterShm::AfterShm { encoding: encoding.unwrap_or_default(), slices: slices.unwrap_or_default(), value_len } } else { QueryValueZbufAfterShm::NotAfterShm { value: value.unwrap_or_default() } };
        _out.slice_count = slice_count;
        Ok(())
    }


    /// Encode `self` into the caller-owned sink. Every value has a frame
    /// (docs/adr/0065), so the only error is the sink's own:
    /// `CodecError::BufferOverflow` from a bounded sink when the destination
    /// has insufficient remaining capacity, and none from a sink that cannot
    /// refuse (`VecSink`, `CountSink`).
    pub fn encode<K: SceSink>(&self, w: &mut K) -> Result<(), K::Error> {
        QueryValueZbufWire::encode_source(self, w)
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

/// The fields `after_shm` decide (docs/adr/0065 §6 R4b, R4c): a value holds the
/// ones of one arm, and `QueryValueZbuf` derives the gates from which.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QueryValueZbufAfterShm<Encoding, Slices, Value> {
    /// While `after_shm` holds.
    AfterShm {
        /// The `encoding` field.
        encoding: Encoding,
        /// The `slices` field.
        slices: Slices,
        /// The `value_len` field.
        value_len: u64,
    },
    /// While `after_shm` does not hold.
    NotAfterShm {
        /// The `value` field.
        value: Value,
    },
}

impl<Encoding: Default, Slices: Default, Value: Default> Default for QueryValueZbufAfterShm<Encoding, Slices, Value> {
    /// The arm held while `after_shm` does not hold, each field at its type's default.
    fn default() -> Self {
        Self::NotAfterShm { value: Default::default(), }
    }
}

// ── Source (ADR 0058) ────────────────────────────────────────────────
/// What a value of `QueryValueZbuf` says: its presented fields. A length, a count
/// or the flag a gated field is announced by is not among them; the
/// encode computes those from what is ([`QueryValueZbufWire::encode_source`]).
pub trait QueryValueZbufSource {
    /// The fields `after_shm` decides, held together (docs/adr/0065 §6 R4).
    fn after_shm(&self) -> QueryValueZbufAfterShm<&impl super::encoding::EncodingSource, ::sce_forge_runtime::codec::BoundedIter<impl Iterator<Item = impl super::zbuf_slice::ZbufSliceSource> + Clone, 4294967295>, ::sce_forge_runtime::codec::Bytes<'_, 4294967295>>;
}

impl<T: QueryValueZbufSource + ?Sized> QueryValueZbufSource for &T {
    fn after_shm(&self) -> QueryValueZbufAfterShm<&impl super::encoding::EncodingSource, ::sce_forge_runtime::codec::BoundedIter<impl Iterator<Item = impl super::zbuf_slice::ZbufSliceSource> + Clone, 4294967295>, ::sce_forge_runtime::codec::Bytes<'_, 4294967295>> {
        (**self).after_shm()
    }
}

/// A value of `QueryValueZbuf` held in the types a caller already has: a source
/// ([`QueryValueZbufSource`]) whose lists are slices within their bounds and whose
/// bodies are references.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct QueryValueZbufParts<'a> {
    /// The fields `after_shm` decides, held together (docs/adr/0065 §6 R4).
    pub after_shm: QueryValueZbufAfterShm<&'a super::encoding::EncodingParts<'a>, ::sce_forge_runtime::codec::Bounded<&'a [super::zbuf_slice::ZbufSliceParts<'a>], 4294967295>, ::sce_forge_runtime::codec::Bytes<'a, 4294967295>>,
}

impl<'a> QueryValueZbufSource for QueryValueZbufParts<'a> {
    fn after_shm(&self) -> QueryValueZbufAfterShm<&impl super::encoding::EncodingSource, ::sce_forge_runtime::codec::BoundedIter<impl Iterator<Item = impl super::zbuf_slice::ZbufSliceSource> + Clone, 4294967295>, ::sce_forge_runtime::codec::Bytes<'_, 4294967295>> {
        match &self.after_shm {
            QueryValueZbufAfterShm::AfterShm { encoding, slices, value_len } => QueryValueZbufAfterShm::AfterShm { encoding: *encoding, slices: slices.iter(), value_len: *value_len },
            QueryValueZbufAfterShm::NotAfterShm { value } => QueryValueZbufAfterShm::NotAfterShm { value: *value },
        }
    }
}

impl<S: QueryValueZbufStorage> QueryValueZbufSource for QueryValueZbufOwned<S> {
    fn after_shm(&self) -> QueryValueZbufAfterShm<&impl super::encoding::EncodingSource, ::sce_forge_runtime::codec::BoundedIter<impl Iterator<Item = impl super::zbuf_slice::ZbufSliceSource> + Clone, 4294967295>, ::sce_forge_runtime::codec::Bytes<'_, 4294967295>> {
        match &self.after_shm {
            QueryValueZbufAfterShm::AfterShm { encoding, slices, value_len } => QueryValueZbufAfterShm::AfterShm { encoding, slices: slices.list_iter(), value_len: *value_len },
            QueryValueZbufAfterShm::NotAfterShm { value } => QueryValueZbufAfterShm::NotAfterShm { value: value.as_bytes() },
        }
    }
}

impl<'a> QueryValueZbufSource for QueryValueZbufView<'a> {
    fn after_shm(&self) -> QueryValueZbufAfterShm<&impl super::encoding::EncodingSource, ::sce_forge_runtime::codec::BoundedIter<impl Iterator<Item = impl super::zbuf_slice::ZbufSliceSource> + Clone, 4294967295>, ::sce_forge_runtime::codec::Bytes<'_, 4294967295>> {
        match &self.after_shm {
            QueryValueZbufAfterShm::AfterShm { encoding, slices, value_len } => QueryValueZbufAfterShm::AfterShm { encoding, slices: slices.iter(), value_len: *value_len },
            QueryValueZbufAfterShm::NotAfterShm { value } => QueryValueZbufAfterShm::NotAfterShm { value: *value },
        }
    }
}

/// The codec `QueryValueZbuf` itself: what writes a value read through
/// [`QueryValueZbufSource`], holding no value and naming no storage profile. Every
/// form of the value, a parent and a view write through it, so a profile
/// that cannot hold some field is never asked for here (docs/adr/0077 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueryValueZbufWire;

#[allow(dead_code)]
impl QueryValueZbufWire {
    /// Encode what `src` says into the caller-owned sink: the bytes
    /// `QueryValueZbuf::encode` writes for the value it holds, read through
    /// [`QueryValueZbufSource`]. A length, a count or a gate flag is computed from what
    /// `src` presents. Every value `src` can present has a frame, so the
    /// only error is the sink's (docs/adr/0065).
    pub fn encode_source<S: QueryValueZbufSource + ?Sized, K: SceSink>(src: &S, w: &mut K) -> Result<(), K::Error> {
        Self::write_source(src, w)
    }

    /// The flag-input `after_shm` that `src` says: set exactly when the value holds the side of `after_shm` present while it holds.
    /// A parent hands the decode this bit and derives it from here for the
    /// encode.
    pub fn input_after_shm<S: QueryValueZbufSource + ?Sized>(src: &S) -> bool {
        matches!(QueryValueZbufSource::after_shm(src), QueryValueZbufAfterShm::AfterShm { .. })
    }

    /// [`Self::encode_source`] without the guard a parent has already made.
    #[doc(hidden)]
    pub fn write_source<S: QueryValueZbufSource + ?Sized, K: SceSink>(src: &S, w: &mut K) -> Result<(), K::Error> {
        let (_m_encoding, _m_slices, _m_value_len, _m_value) = match src.after_shm() {
            QueryValueZbufAfterShm::AfterShm { encoding, slices, value_len } => (Some(encoding), Some(slices), Some(value_len), None),
            QueryValueZbufAfterShm::NotAfterShm { value } => (None, None, None, Some(value)),
        };
        let after_shm: u8 = u8::from(matches!(QueryValueZbufSource::after_shm(src), QueryValueZbufAfterShm::AfterShm { .. }));
        let _k_slices: usize = _m_slices.clone().map_or(0, |_l| _l.len());
        let _n_d_value_len_0: usize = match _m_value {
            Some(_v) => _v.len(),
            None => 0,
        };
        let _f_d_value_len: Option<usize> = if _m_value.is_some() { Some(_n_d_value_len_0) } else { None };
        let _d_value_len: u64 = match _f_d_value_len {
            Some(_n) => ::sce_forge_runtime::codec::widen_usize(_n),
            None => _m_value_len.unwrap_or_default(),
        };
        let _f_d_slice_count: Option<usize> = if _m_slices.clone().is_some() { Some(_k_slices) } else { None };
        let _d_slice_count: u32 = _f_d_slice_count.unwrap_or(0) as u32;
        w.write_vle_u64(_d_value_len)?;
        if let Some(_v) = _m_value {
            w.write_bytes(_v.into_inner())?;
        }
        if let Some(_v) = _m_encoding {
            super::encoding::EncodingWire::write_source(_v, w)?;
        }
        if (after_shm & 0x1) != 0 {
            w.write_vle_u32(_d_slice_count)?;
        }
        if let Some(_v) = _m_slices.clone() {
            for _e in _v {
                super::zbuf_slice::ZbufSliceWire::write_source(&_e, w)?;
            }
        }
        Ok(())
    }

    /// The bytes [`Self::write_source`] writes for `src`, counted with
    /// nothing written.
    #[doc(hidden)]
    pub fn count_source<S: QueryValueZbufSource + ?Sized>(src: &S) -> usize {
        let mut _c = ::sce_forge_runtime::codec::CountSink::new();
        let Ok(()) = Self::write_source(src, &mut _c);
        _c.len()
    }
}

impl<S: QueryValueZbufSource + ?Sized> ::sce_forge_runtime::codec::SourceWrite<S> for QueryValueZbufWire {
    type Error<E> = E;

    fn write<K: SceSink>(src: &S, w: &mut K) -> Result<(), K::Error> where CodecError: From<K::Error> {
        Self::write_source(src, w)
    }
}

#[allow(dead_code)]
impl QueryValueZbufWire {
    /// The size of the frame [`Self::encode_source`] writes for `src`, found
    /// with nothing written: the encode refuses no value, so neither does
    /// this. The result writes the frame into a window of exactly that size
    /// and cannot fail.
    pub fn measure<S: QueryValueZbufSource + ?Sized>(src: &S) -> ::sce_forge_runtime::codec::Measured<'_, Self, S> {
        let Ok(measured) = ::sce_forge_runtime::codec::measure(src);
        measured
    }

    /// Write `src` into `window` in one pass and return the bytes it is, for a
    /// window as large as the caller can spare. On an error the window holds a
    /// prefix to discard; see [`::sce_forge_runtime::codec::write_window`].
    pub fn write_window<S: QueryValueZbufSource + ?Sized>(src: &S, window: &mut [u8]) -> Result<usize, CodecError> {
        let mut sink = ::sce_forge_runtime::codec::SliceSink::new(window);
        Self::write_source(src, &mut sink)?;
        Ok(sink.position())
    }
}


// ── View (ADR 0049) ──────────────────────────────────────────────────
// `QueryValueZbufView` is what a decode of `QueryValueZbuf` learned, not a
// copy of what the wire repeated: a scalar, a string or a bytes field is held
// as `QueryValueZbuf` holds it, an embedded body or a variant arm as its
// own view, and a bounded list as the frame it was read from, how many entries
// it holds and what a walk needs to read them again (`ListView`). Its size
// depends on the number of fields and not on any `sce:max-count`, so moving
// one copies a few words however long its lists may be. `decode` refuses the
// frames `QueryValueZbuf::decode` refuses, with the same error: the entries
// are decoded once to check them, and a walk afterwards cannot fail.
#[allow(dead_code)]
pub struct QueryValueZbufSlicesWalk;

impl ListWalk<0> for QueryValueZbufSlicesWalk {
    type Entry<'b> = ZbufSliceView<'b>;

    fn decode<'b>(_c: &mut SceCursor<'b>, _a: &[u8; 0]) -> Result<Self::Entry<'b>, CodecError> {
        ZbufSliceView::decode(_c)
    }

    fn advance(_e: &Self::Entry<'_>, _s: &mut [u8; 0]) {  }
}

#[allow(dead_code)]
#[derive(Default, Debug, Clone, PartialEq)]
pub struct QueryValueZbufView<'a> {
    pub after_shm: QueryValueZbufAfterShm<EncodingView<'a>, Bounded<ListView<'a, QueryValueZbufSlicesWalk, 0>, 4294967295>, ::sce_forge_runtime::codec::Bytes<'a, 4294967295>>,
    pub slice_count: Option<u32>,
}

#[allow(dead_code)]
impl<'a> QueryValueZbufView<'a> {
    /// A view with every field at its own type's [`Default`]: the destination
    /// [`Self::decode_into`] fills.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode the next frame from `cursor`: the bytes, the bounds and the
    /// errors of [`QueryValueZbuf::decode`], held as a view. On success the
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
        // Streaming cursor decode (SSOT selection: `needs_streaming`).
        // The positional `raw[byte_off]` path is valid only when every
        // field's absolute offset is fixed at codegen time; this branch
        // handles every codec where it is not — present-if-gated fields
        // (runtime presence), VLE / repeat / TLV-chain / embed fields
        // (runtime width), string fields (UTF-8 decode), and a fixed field
        // after a variable-length payload (offset depends on the payload
        // length). Each field reads its own bytes from the cursor and
        // advances past exactly what it consumed. Per-field `is_repeat` /
        // `is_tlv_chain` / `is_embed` route to their dedicated helpers;
        // every other field flows through `present_if_decode_stmt`, whose
        // non-gated arm covers plain fixed / tail / length-ref / VLE reads.
        let value_len = cursor.read_vle_u64()?;
        let value = if (after_shm & 0x01u8) == 0 {
            let _len = value_len;
            if _len > 4294967295 {
                return Err(CodecError::LengthOutOfRange);
            }
            let _n = usize::try_from(_len).map_err(|_| CodecError::NeedMoreBytes)?;
            let raw = cursor.peek_slice(_n)?;
            let _v = raw;
            cursor.advance(_n)?;
            Some(_v)
        } else {
            None
        };
        let value = value.map(|_v| ::sce_forge_runtime::codec::Bounded::new(_v).ok_or(CodecError::LengthOutOfRange)).transpose()?;
        let mut encoding: Option<EncodingView<'a>> = None;
        if (after_shm & 0x01u8) != 0 {
            EncodingView::decode_into(cursor, encoding.insert(EncodingView::default()))?;
        } else {
            encoding = None;
        }
        let slice_count = if (after_shm & 0x01u8) != 0 {
            let _v = cursor.read_vle_u32()?;
            Some(_v)
        } else {
            None
        };
        #[allow(clippy::needless_late_init)]
        let slices: Option<Bounded<ListView<'a, QueryValueZbufSlicesWalk, 0>, 4294967295>>;
        if (after_shm & 0x01u8) != 0 {
            let _n = slice_count.expect("co-gating: count present-if matches repeat");
            let _rest = cursor.peek_slice(cursor.remaining())?;
            let mut _count: u32 = 0;
            for _ in 0.._n {
                if _count == 4294967295 {
                    return Err(CodecError::TooManyElements);
                }
                ZbufSliceView::decode(cursor)?;
                _count += 1;
            }
            slices = Some(Bounded::new(ListView::new(_rest, _count, [])).ok_or(CodecError::TooManyElements)?);
        } else {
            slices = None;
        }
        _out.after_shm = if (after_shm & 0x01u8) != 0 { QueryValueZbufAfterShm::AfterShm { encoding: encoding.unwrap_or_default(), slices: slices.unwrap_or_default(), value_len } } else { QueryValueZbufAfterShm::NotAfterShm { value: value.unwrap_or_default() } };
        _out.slice_count = slice_count;
        Ok(())
    }

    /// Fill `_out`, the builder form [`QueryValueZbuf`] a sender fills and
    /// encodes, with what this view says: every field, each embedded body, the
    /// variant arm, and each list entry as the walk yields it, built in the
    /// destination where it will live. Fails only where the destination cannot
    /// hold it, which a destination of the same declared bounds does.
    // The name every view's method has (ADR 0049), which borrows because a
    // view is read, not consumed. Clippy leaves an exported method's name
    // alone; a crate that includes this module privately is asked to rename
    // it, and the one name is what lets a codec reach every view it holds.
    #[allow(clippy::wrong_self_convention)]
    pub fn into_builder<D>(&self, _out: &mut QueryValueZbufIn<::sce_forge_runtime::codec::Lent<'a, D>>) -> Result<(), CodecError> where D: QueryValueZbufLentStorage {
        match &self.after_shm {
            QueryValueZbufAfterShm::AfterShm { encoding, slices, value_len } => {
                let mut _o_encoding: EncodingOwned<::sce_forge_runtime::codec::Lent<'a, D>> = Default::default();
                encoding.into_builder(&mut _o_encoding)?;
                let mut _o_slices: ::sce_forge_runtime::codec::Bounded<<::sce_forge_runtime::codec::Lent<'a, D> as ::sce_forge_runtime::codec::HoldsList<QueryValueZbufSlicesField>>::List<ZbufSliceOwned<::sce_forge_runtime::codec::Lent<'a, D>>>, 4294967295> = Default::default();
                _o_slices.refill(|_vec| {
                    for _e in slices.iter() {
                        ::sce_forge_runtime::codec::SceList::try_push(_vec, Default::default())?;
                        if let Some(_slot) = ::sce_forge_runtime::codec::SceList::last_mut(_vec) {
                            _e.into_builder(_slot)?;
                        }
                    }
                    Ok(())
                })?;
                let mut _o_value_len: u64 = Default::default();
                _o_value_len = *value_len;
                _out.after_shm = QueryValueZbufAfterShm::AfterShm { encoding: _o_encoding, slices: _o_slices, value_len: _o_value_len };
            }
            QueryValueZbufAfterShm::NotAfterShm { value } => {
                let mut _o_value: ::sce_forge_runtime::codec::Bounded<<::sce_forge_runtime::codec::Lent<'a, D> as ::sce_forge_runtime::codec::HoldsBytes<QueryValueZbufValueField>>::Bytes, 4294967295> = Default::default();
                _o_value = *value;
                _out.after_shm = QueryValueZbufAfterShm::NotAfterShm { value: _o_value };
            }
        }
        _out.slice_count = self.slice_count;
        Ok(())
    }


    /// Encode what this view says into the caller-owned sink: the bytes
    /// [`QueryValueZbuf::encode`] writes for the value [`Self::into_builder`]
    /// fills, written straight from the view, walking each list, without the
    /// builder. It writes the canonical wire, not the frame the view was decoded
    /// from, so a frame `decode` accepted in a form that is not canonical is
    /// not passed on as it came.
    pub fn encode<S: SceSink>(&self, w: &mut S) -> Result<(), S::Error> {
        QueryValueZbufWire::encode_source(self, w)
    }

    /// Heap-backed convenience facade over [`Self::encode`], which refuses no
    /// value (docs/adr/0065).
    #[cfg(feature = "alloc")]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut _sce_v: Vec<u8> = Vec::new();
        let Ok(()) = self.encode(&mut VecSink::new(&mut _sce_v));
        _sce_v
    }
}

// ── Owned projection (storage-parameterised native form) ─────────────
// `QueryValueZbuf<'a>` above is a zero-copy view borrowing the decode
// buffer. Consumers that persist a decoded value beyond the buffer's
// lifetime — including the self-contained bounded-collection that stores
// elements by value — call `.try_into_owned()` for this lifetime-free
// `QueryValueZbufOwned`. The rkyv-style Archived(borrowed) ↔ native
// (owned) split, both generated from the one SCXML source (SSOT).
//
// The owned form is parameterised by a storage profile rather than fixed at
// build-configuration time: `QueryValueZbufOwned<Heap>` holds growable
// containers with the declared capacities advisory, `QueryValueZbufOwned<Inline>`
// holds every field inline at its declared capacity and never allocates, and
// both exist in the same binary. `QueryValueZbufOwned` alone is the build's
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
// `let v: QueryValueZbufOwned = QueryValueZbufOwned { .. };`
// — because the fields reach the profile through its associated container
// types, which cannot be run backwards to recover the profile from a value.
// Naming it once is also what lets each field's container infer, so no call
// site repeats a capacity. A capacity is not in this file at all except as
// what `Inline` holds: a deployment answers for the same tags from its own.

// The lent value at any profile `D` that holds its lists: what a decode of a
// frame gives where bytes and text borrow it, `QueryValueZbuf<'a>` being it
// at `Inline` (docs/adr/0077 §7).
#[allow(dead_code)]
impl<'a, D> QueryValueZbufIn<::sce_forge_runtime::codec::Lent<'a, D>> where D: QueryValueZbufLentStorage {
    /// Deep-copy this borrowed zero-copy view into an owned, lifetime-free
    /// [`QueryValueZbufOwned`] held in the given storage profile. Call at
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
    pub fn try_into_owned_in<S: QueryValueZbufFrom<'a>>(self) -> Result<QueryValueZbufOwned<S>, CodecError> {
        Ok(QueryValueZbufOwned {
            after_shm: match self.after_shm { QueryValueZbufAfterShm::AfterShm { encoding, slices, value_len } => QueryValueZbufAfterShm::AfterShm { encoding: encoding.try_into_owned_in::<S>()?, slices: ::sce_forge_runtime::codec::try_collect_bounded(slices, |_e| _e.try_into_owned_in::<S>())?, value_len }, QueryValueZbufAfterShm::NotAfterShm { value } => QueryValueZbufAfterShm::NotAfterShm { value: value.store::<S, QueryValueZbufValueField>()? }, },
            slice_count: self.slice_count,
        })
    }

    /// The same projection at the build's default storage profile — growable
    /// where an allocator exists, inline on the heap-free tier.
    pub fn try_into_owned(self) -> Result<QueryValueZbufOwned, CodecError> {
        self.try_into_owned_in()
    }
}

#[allow(dead_code)]
impl<S: QueryValueZbufStorage> QueryValueZbufOwned<S> {
    /// Re-borrow this owned value back into the zero-copy borrowed view —
    /// the inverse of `try_into_owned_in`. `encode` lives only on the
    /// borrowed view (the owned form is read-only), so an owned consumer
    /// reaches it via `try_as_borrowed` then `encode` / `encode_to_vec`.
    /// Each field is projected by reference — a cheap re-borrow, not a copy.
    /// Fallible: a bounded `<sce:repeat>` / `<sce:tlv-chain>` list holding
    /// more than its declared `N` raises `CodecError::TooManyElements` — the
    /// same bound decode enforces. Only a growable profile can hold such a
    /// list; on the inline profile the source is already within bounds.
    pub fn try_as_borrowed(&self) -> Result<QueryValueZbufIn<::sce_forge_runtime::codec::Lent<'_, S>>, CodecError> {
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
    pub fn try_as_borrowed_into<'o>(&'o self, _out: &mut QueryValueZbufIn<::sce_forge_runtime::codec::Lent<'o, S>>) -> Result<(), CodecError> {
        match &self.after_shm {
            QueryValueZbufAfterShm::AfterShm { encoding, slices, value_len } => {
                let mut _o_encoding: EncodingOwned<::sce_forge_runtime::codec::Lent<'o, S>> = Default::default();
                encoding.as_borrowed_into(&mut _o_encoding);
                let mut _o_slices: ::sce_forge_runtime::codec::Bounded<<::sce_forge_runtime::codec::Lent<'o, S> as ::sce_forge_runtime::codec::HoldsList<QueryValueZbufSlicesField>>::List<ZbufSliceOwned<::sce_forge_runtime::codec::Lent<'o, S>>>, 4294967295> = Default::default();
                _o_slices.refill(|_d| ::sce_forge_runtime::codec::try_project_bounded_into(_d, slices.inner(), |_e| Ok(_e.as_borrowed())))?;
                let mut _o_value_len: u64 = Default::default();
                _o_value_len = *value_len;
                _out.after_shm = QueryValueZbufAfterShm::AfterShm { encoding: _o_encoding, slices: _o_slices, value_len: _o_value_len };
            }
            QueryValueZbufAfterShm::NotAfterShm { value } => {
                let mut _o_value: ::sce_forge_runtime::codec::Bounded<<::sce_forge_runtime::codec::Lent<'o, S> as ::sce_forge_runtime::codec::HoldsBytes<QueryValueZbufValueField>>::Bytes, 4294967295> = Default::default();
                _o_value = value.as_bytes();
                _out.after_shm = QueryValueZbufAfterShm::NotAfterShm { value: _o_value };
            }
        }
        _out.slice_count = self.slice_count;
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
    pub fn transcode_in<D: for<'x> QueryValueZbufFrom<'x>>(&self) -> Result<QueryValueZbufOwned<D>, CodecError> {
        self.try_as_borrowed()?.try_into_owned_in::<D>()
    }
}

#[allow(dead_code)]
impl<'a, D> QueryValueZbufIn<::sce_forge_runtime::codec::Lent<'a, D>> where D: QueryValueZbufLentStorage {
    /// Project this borrowed view into an owned [`QueryValueZbufOwned`]
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
    pub fn try_into_owned_in_origin<S: QueryValueZbufStorage + ::sce_forge_runtime::codec::OriginStorage>(self, origin: &<S as ::sce_forge_runtime::codec::OriginStorage>::Origin) -> Result<QueryValueZbufOwned<S>, CodecError> {
        Ok(QueryValueZbufOwned {
            after_shm: match self.after_shm { QueryValueZbufAfterShm::AfterShm { encoding, slices, value_len } => QueryValueZbufAfterShm::AfterShm { encoding: encoding.try_into_owned_in_origin::<S>(origin)?, slices: ::sce_forge_runtime::codec::try_collect_bounded(slices, |_e| _e.try_into_owned_in_origin::<S>(origin))?, value_len }, QueryValueZbufAfterShm::NotAfterShm { value } => QueryValueZbufAfterShm::NotAfterShm { value: ::sce_forge_runtime::codec::Bounded::from_built(<S as ::sce_forge_runtime::codec::OriginStorage>::bytes_from::<QueryValueZbufValueField>(origin, value.into_inner()))? }, },
            slice_count: self.slice_count,
        })
    }
}
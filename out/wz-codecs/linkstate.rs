// SCE-MAP: linkstate:109 :: _forge_body

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

use super::linkstate_link::LinkstateLink;
use super::linkstate_weight::LinkstateWeight;
use super::locator::Locator;

use sce_forge_runtime::codec::{ListView, ListWalk};
use super::linkstate_link::LinkstateLinkView;
use super::linkstate_weight::LinkstateWeightView;
use super::locator::LocatorView;

// pub API: codecs are intended for cross-crate consumption (SCE_FORGE.md
// §6 codec). The kind-agnostic conformance harness only references a
// subset of fixtures, so unused-but-pub fields/methods would otherwise
// trigger dead_code on every codec build.
#[allow(dead_code)]
#[derive(Default, Debug, Clone, PartialEq)]
pub struct Linkstate<'a> {
    pub options: u8,
    pub psid: u64,
    pub sn: u64,
    pub zid_len: Option<u64>,
    pub zid: Option<&'a [u8]>,
    pub whatami: Option<u8>,
    pub num_locators: Option<u64>,
    pub locators: Option<HeaplessVec<Locator<'a>, 64>>,
    pub links_len: u64,
    pub links: HeaplessVec<LinkstateLink, 64>,
    pub weights: Option<HeaplessVec<LinkstateWeight, 64>>,
}

#[allow(dead_code)]
impl<'a> Linkstate<'a> {
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
        let options = {
            let raw = cursor.peek_slice(1)?;
            let _v = raw[0];
            cursor.advance(1)?;
            _v
        };
        let psid = cursor.read_vle_u64()?;
        let sn = cursor.read_vle_u64()?;
        let zid_len = if (options & 0x01u8) != 0 {
            let _v = cursor.read_vle_u64()?;
            Some(_v)
        } else {
            None
        };
        let zid = if (options & 0x01u8) != 0 {
            let _n = zid_len.unwrap() as usize;
            let raw = cursor.peek_slice(_n)?;
            let _v = raw;
            cursor.advance(_n)?;
            Some(_v)
        } else {
            None
        };
        let whatami = if (options & 0x02u8) != 0 {
            let raw = cursor.peek_slice(1)?;
            let _v = raw[0];
            cursor.advance(1)?;
            Some(_v)
        } else {
            None
        };
        let num_locators = if (options & 0x04u8) != 0 {
            let _v = cursor.read_vle_u64()?;
            Some(_v)
        } else {
            None
        };
        if (options & 0x04u8) != 0 {
            let _n = num_locators.expect("co-gating: count present-if matches repeat");
            let _vec = _out.locators.insert(HeaplessVec::<Locator<'a>, 64>::new());
            for _ in 0.._n {
                _vec.push(Locator::decode(cursor)?)
                    .map_err(|_| CodecError::TooManyElements)?;
            }
        } else {
            _out.locators = None;
        }
        let links_len = cursor.read_vle_u64()?;
        {
            let _vec = &mut _out.links;
            _vec.clear();
            for _ in 0..links_len {
                _vec.push(LinkstateLink::decode(cursor)?)
                    .map_err(|_| CodecError::TooManyElements)?;
            }
        }
        if (options & 0x08u8) != 0 {
            let _n = links_len;
            let _vec = _out.weights.insert(HeaplessVec::<LinkstateWeight, 64>::new());
            for _ in 0.._n {
                _vec.push(LinkstateWeight::decode(cursor)?)
                    .map_err(|_| CodecError::TooManyElements)?;
            }
        } else {
            _out.weights = None;
        }
        _out.options = options;
        _out.psid = psid;
        _out.sn = sn;
        _out.zid_len = zid_len;
        _out.zid = zid;
        _out.whatami = whatami;
        _out.num_locators = num_locators;
        _out.links_len = links_len;
        Ok(())
    }

    // RFC §synth-5-B flags primitive: per-bit-range accessors over
    // the carrier field. Single-bit (width=1) reads as bool; multi-bit
    // (width>=2) reads as the smallest unsigned integer that fits the
    // range. Setters mask + shift on the way in so out-of-range
    // callers can't corrupt sibling bits. Wire layout is unchanged —
    // the carrier still occupies its declared bytes.
    pub fn p(&self) -> bool {
        (self.options & 0x01) != 0
    }

    pub fn set_p(&mut self, v: bool) {
        if v {
            self.options |= 0x01;
        } else {
            self.options &= !0x01;
        }
    }

    pub fn w(&self) -> bool {
        (self.options & 0x02) != 0
    }

    pub fn set_w(&mut self, v: bool) {
        if v {
            self.options |= 0x02;
        } else {
            self.options &= !0x02;
        }
    }

    pub fn l(&self) -> bool {
        (self.options & 0x04) != 0
    }

    pub fn set_l(&mut self, v: bool) {
        if v {
            self.options |= 0x04;
        } else {
            self.options &= !0x04;
        }
    }

    pub fn h(&self) -> bool {
        (self.options & 0x08) != 0
    }

    pub fn set_h(&mut self, v: bool) {
        if v {
            self.options |= 0x08;
        } else {
            self.options &= !0x08;
        }
    }

    pub fn g(&self) -> bool {
        (self.options & 0x10) != 0
    }

    pub fn set_g(&mut self, v: bool) {
        if v {
            self.options |= 0x10;
        } else {
            self.options &= !0x10;
        }
    }

    /// Worst-case encoded byte count for this codec — the upper bound
    /// against which `VecSink::new` reserves capacity in the
    /// `encode_to_vec` facade, and the natural reserve hint for
    /// caller-owned `SliceSink` allocations.
    pub const MAX_ENCODED_BYTES: usize = 9987;

    /// Encode `self` into the caller-owned sink. Returns
    /// `CodecError::BufferOverflow` from a bounded sink when the
    /// destination has insufficient remaining capacity; growable
    /// sinks (e.g. `VecSink`) are effectively infallible.
    pub fn encode<S: SceSink>(&self, w: &mut S) -> Result<(), CodecError> {
        // Streaming cursor encode (SSOT selection: `needs_streaming`).
        // Mirrors the streaming decode: every field appends its own bytes
        // in declaration order through the per-field encode blocks, so a
        // gated field skips its append when absent, and a fixed field after
        // a variable-length payload lands after the payload (the positional
        // path appends variable fields last, placing it ahead on the wire).
        // Per-field `is_repeat` / `is_tlv_chain` / `is_embed` route to their
        // dedicated helpers; everything else uses `present_if_encode_block`
        // (its non-gated arm covers plain fixed / tail / length-ref / VLE).
        w.write_u8(self.options)?;
        w.write_vle_u64(self.psid)?;
        w.write_vle_u64(self.sn)?;
        if let Some(_v) = self.zid_len {
        w.write_vle_u64(_v)?;
        }
        if let Some(_v) = &self.zid {
            w.write_bytes(_v)?;
        }
        if let Some(_v) = self.whatami {
            w.write_u8(_v)?;
        }
        if let Some(_v) = self.num_locators {
        w.write_vle_u64(_v)?;
        }
        if let Some(_list) = &self.locators {
            for _e in _list {
                _e.encode(w)?;
            }
        }
        w.write_vle_u64(self.links_len)?;
        for _e in &self.links {
            _e.encode(w)?;
        }
        if let Some(_list) = &self.weights {
            for _e in _list {
                _e.encode(w)?;
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
    /// same gate (see `backends/rust/forge-runtime/src/codec.rs`). MCU /
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

// ── View (ADR 0049) ──────────────────────────────────────────────────
// `LinkstateView` is what a decode of `Linkstate` learned, not a
// copy of what the wire repeated: a scalar, a string or a bytes field is held
// as `Linkstate` holds it, an embedded body or a variant arm as its
// own view, and a bounded list as the frame it was read from, how many entries
// it holds and what a walk needs to read them again (`ListView`). Its size
// depends on the number of fields and not on any `sce:max-count`, so moving
// one copies a few words however long its lists may be. `decode` refuses the
// frames `Linkstate::decode` refuses, with the same error: the entries
// are decoded once to check them, and a walk afterwards cannot fail.
#[allow(dead_code)]
pub struct LinkstateLocatorsWalk;

impl ListWalk<0> for LinkstateLocatorsWalk {
    type Entry<'b> = LocatorView<'b>;

    fn decode<'b>(_c: &mut SceCursor<'b>, _a: &[u8; 0]) -> Result<Self::Entry<'b>, CodecError> {
        LocatorView::decode(_c)
    }

    fn advance(_e: &Self::Entry<'_>, _s: &mut [u8; 0]) {  }
}

#[allow(dead_code)]
pub struct LinkstateLinksWalk;

impl ListWalk<0> for LinkstateLinksWalk {
    type Entry<'b> = LinkstateLinkView;

    fn decode<'b>(_c: &mut SceCursor<'b>, _a: &[u8; 0]) -> Result<Self::Entry<'b>, CodecError> {
        LinkstateLinkView::decode(_c)
    }

    fn advance(_e: &Self::Entry<'_>, _s: &mut [u8; 0]) {  }
}

#[allow(dead_code)]
pub struct LinkstateWeightsWalk;

impl ListWalk<0> for LinkstateWeightsWalk {
    type Entry<'b> = LinkstateWeightView;

    fn decode<'b>(_c: &mut SceCursor<'b>, _a: &[u8; 0]) -> Result<Self::Entry<'b>, CodecError> {
        LinkstateWeightView::decode(_c)
    }

    fn advance(_e: &Self::Entry<'_>, _s: &mut [u8; 0]) {  }
}

#[allow(dead_code)]
#[derive(Default, Debug, Clone, PartialEq)]
pub struct LinkstateView<'a> {
    pub options: u8,
    pub psid: u64,
    pub sn: u64,
    pub zid_len: Option<u64>,
    pub zid: Option<&'a [u8]>,
    pub whatami: Option<u8>,
    pub num_locators: Option<u64>,
    pub locators: Option<ListView<'a, LinkstateLocatorsWalk, 0>>,
    pub links_len: u64,
    pub links: ListView<'a, LinkstateLinksWalk, 0>,
    pub weights: Option<ListView<'a, LinkstateWeightsWalk, 0>>,
}

#[allow(dead_code)]
impl<'a> LinkstateView<'a> {
    /// A view with every field at its own type's [`Default`]: the destination
    /// [`Self::decode_into`] fills.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode the next frame from `cursor`: the bytes, the bounds and the
    /// errors of [`Linkstate::decode`], held as a view. On success the
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
        let options = {
            let raw = cursor.peek_slice(1)?;
            let _v = raw[0];
            cursor.advance(1)?;
            _v
        };
        let psid = cursor.read_vle_u64()?;
        let sn = cursor.read_vle_u64()?;
        let zid_len = if (options & 0x01u8) != 0 {
            let _v = cursor.read_vle_u64()?;
            Some(_v)
        } else {
            None
        };
        let zid = if (options & 0x01u8) != 0 {
            let _n = zid_len.unwrap() as usize;
            let raw = cursor.peek_slice(_n)?;
            let _v = raw;
            cursor.advance(_n)?;
            Some(_v)
        } else {
            None
        };
        let whatami = if (options & 0x02u8) != 0 {
            let raw = cursor.peek_slice(1)?;
            let _v = raw[0];
            cursor.advance(1)?;
            Some(_v)
        } else {
            None
        };
        let num_locators = if (options & 0x04u8) != 0 {
            let _v = cursor.read_vle_u64()?;
            Some(_v)
        } else {
            None
        };
        if (options & 0x04u8) != 0 {
            let _n = num_locators.expect("co-gating: count present-if matches repeat");
            let _rest = cursor.peek_slice(cursor.remaining())?;
            let mut _count: u32 = 0;
            for _ in 0.._n {
                LocatorView::decode(cursor)?;
                if _count == 64 {
                    return Err(CodecError::TooManyElements);
                }
                _count += 1;
            }
            _out.locators = Some(ListView::new(_rest, _count, []));
        } else {
            _out.locators = None;
        }
        let links_len = cursor.read_vle_u64()?;
        {
            let _rest = cursor.peek_slice(cursor.remaining())?;
            let mut _count: u32 = 0;
            for _ in 0..links_len {
                LinkstateLinkView::decode(cursor)?;
                if _count == 64 {
                    return Err(CodecError::TooManyElements);
                }
                _count += 1;
            }
            _out.links = ListView::new(_rest, _count, []);
        }
        if (options & 0x08u8) != 0 {
            let _n = links_len;
            let _rest = cursor.peek_slice(cursor.remaining())?;
            let mut _count: u32 = 0;
            for _ in 0.._n {
                LinkstateWeightView::decode(cursor)?;
                if _count == 64 {
                    return Err(CodecError::TooManyElements);
                }
                _count += 1;
            }
            _out.weights = Some(ListView::new(_rest, _count, []));
        } else {
            _out.weights = None;
        }
        _out.options = options;
        _out.psid = psid;
        _out.sn = sn;
        _out.zid_len = zid_len;
        _out.zid = zid;
        _out.whatami = whatami;
        _out.num_locators = num_locators;
        _out.links_len = links_len;
        Ok(())
    }

    /// Fill `_out`, the builder form [`Linkstate`] a sender fills and
    /// encodes, with what this view says: every field, each embedded body, the
    /// variant arm, and each list entry as the walk yields it, built in the
    /// destination where it will live. Fails only where the destination cannot
    /// hold it, which a destination of the same declared bounds does.
    pub fn into_builder(&self, _out: &mut Linkstate<'a>) -> Result<(), CodecError> {
        _out.options = self.options;
        _out.psid = self.psid;
        _out.sn = self.sn;
        _out.zid_len = self.zid_len;
        _out.zid = self.zid;
        _out.whatami = self.whatami;
        _out.num_locators = self.num_locators;
        match &self.locators {
            Some(_l) => {
                let _vec = _out.locators.insert(HeaplessVec::new());
                _vec.clear();
                for _e in _l.iter() {
                    _vec.push(Locator::default()).map_err(|_| CodecError::TooManyElements)?;
                    if let Some(_slot) = _vec.last_mut() {
                        _e.into_builder(_slot)?;
                    }
                }
            }
            None => _out.locators = None,
        }
        _out.links_len = self.links_len;
        _out.links.clear();
        for _e in self.links.iter() {
            _out.links.push(LinkstateLink::default()).map_err(|_| CodecError::TooManyElements)?;
            if let Some(_slot) = _out.links.last_mut() {
                _e.into_builder(_slot)?;
            }
        }
        match &self.weights {
            Some(_l) => {
                let _vec = _out.weights.insert(HeaplessVec::new());
                _vec.clear();
                for _e in _l.iter() {
                    _vec.push(LinkstateWeight::default()).map_err(|_| CodecError::TooManyElements)?;
                    if let Some(_slot) = _vec.last_mut() {
                        _e.into_builder(_slot)?;
                    }
                }
            }
            None => _out.weights = None,
        }
        Ok(())
    }

    /// Worst-case encoded byte count for this codec, as
    /// [`Linkstate::MAX_ENCODED_BYTES`].
    pub const MAX_ENCODED_BYTES: usize = 9987;

    /// Encode what this view says into the caller-owned sink: the bytes
    /// [`Linkstate::encode`] writes for the value [`Self::into_builder`]
    /// fills, written straight from the view, walking each list, without the
    /// builder. It writes the canonical wire, not the frame the view was decoded
    /// from, so a frame `decode` accepted in a form that is not canonical is
    /// not passed on as it came.
    pub fn encode<S: SceSink>(&self, w: &mut S) -> Result<(), CodecError> {
        // Streaming cursor encode (SSOT selection: `needs_streaming`).
        // Mirrors the streaming decode: every field appends its own bytes
        // in declaration order through the per-field encode blocks, so a
        // gated field skips its append when absent, and a fixed field after
        // a variable-length payload lands after the payload (the positional
        // path appends variable fields last, placing it ahead on the wire).
        // Per-field `is_repeat` / `is_tlv_chain` / `is_embed` route to their
        // dedicated helpers; everything else uses `present_if_encode_block`
        // (its non-gated arm covers plain fixed / tail / length-ref / VLE).
        w.write_u8(self.options)?;
        w.write_vle_u64(self.psid)?;
        w.write_vle_u64(self.sn)?;
        if let Some(_v) = self.zid_len {
        w.write_vle_u64(_v)?;
        }
        if let Some(_v) = &self.zid {
            w.write_bytes(_v)?;
        }
        if let Some(_v) = self.whatami {
            w.write_u8(_v)?;
        }
        if let Some(_v) = self.num_locators {
        w.write_vle_u64(_v)?;
        }
        if let Some(_list) = &self.locators {
            for _e in _list.iter() {
                _e.encode(w)?;
            }
        }
        w.write_vle_u64(self.links_len)?;
        for _e in self.links.iter() {
            _e.encode(w)?;
        }
        if let Some(_list) = &self.weights {
            for _e in _list.iter() {
                _e.encode(w)?;
            }
        }
        Ok(())
    }

    /// Heap-backed convenience facade over [`Self::encode`].
    #[cfg(feature = "alloc")]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut _sce_v: Vec<u8> = Vec::with_capacity(Self::MAX_ENCODED_BYTES);
        let mut _sce_sink = VecSink::new(&mut _sce_v);
        self.encode(&mut _sce_sink)
            .expect("VecSink is infallible");
        _sce_v
    }

    pub fn p(&self) -> bool {
        (self.options & 0x01) != 0
    }

    pub fn w(&self) -> bool {
        (self.options & 0x02) != 0
    }

    pub fn l(&self) -> bool {
        (self.options & 0x04) != 0
    }

    pub fn h(&self) -> bool {
        (self.options & 0x08) != 0
    }

    pub fn g(&self) -> bool {
        (self.options & 0x10) != 0
    }

}

// ── Owned projection (storage-parameterised native form) ─────────────
// `Linkstate<'a>` above is a zero-copy view borrowing the decode
// buffer. Consumers that persist a decoded value beyond the buffer's
// lifetime — including the self-contained bounded-collection that stores
// elements by value — call `.try_into_owned()` for this lifetime-free
// `LinkstateOwned`. The rkyv-style Archived(borrowed) ↔ native
// (owned) split, both generated from the one SCXML source (SSOT).
//
// The owned form is parameterised by a storage profile rather than fixed at
// build-configuration time: `LinkstateOwned<Heap>` holds growable
// containers with the declared capacities advisory, `LinkstateOwned<Inline>`
// holds every field inline at its declared capacity and never allocates, and
// both exist in the same binary. `LinkstateOwned` alone is the build's
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
// `let v: LinkstateOwned = LinkstateOwned { .. };`
// — because the fields reach the profile through its associated container
// types, which cannot be run backwards to recover the profile from a value.
// Naming it once is also what lets each field's declared capacity infer,
// so no call site repeats a `sce:max-size` / `sce:max-count` constant.
use super::locator::LocatorOwned;
// Same pub-API policy as the borrowed view above: the owned mirror and its
// projections are cross-crate surface, and which of them a given in-repo
// fixture happens to call says nothing about their value.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct LinkstateOwned<S: ::sce_forge_runtime::codec::CodecStorage = ::sce_forge_runtime::codec::DefaultStorage> {
    pub options: u8,
    pub psid: u64,
    pub sn: u64,
    pub zid_len: Option<u64>,
    pub zid: Option<S::Bytes<16>>,
    pub whatami: Option<u8>,
    pub num_locators: Option<u64>,
    pub locators: Option<S::List<LocatorOwned<S>, 64>>,
    pub links_len: u64,
    pub links: S::List<LinkstateLink, 64>,
    pub weights: Option<S::List<LinkstateWeight, 64>>,
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> LinkstateOwned<S> {
    // RFC §synth-5-B read-accessor parity with the borrowed view: pure
    // bit getters over the copied carrier (rkyv Archived↔native getter
    // parity), so owned consumers read `{Codec}Owned` with the same API as
    // the borrowed view and never re-derive the SCE wire bit layout (SSOT).
    // Read-only — write accessors belong with an owned-encode path, which
    // does not exist yet.
    pub fn p(&self) -> bool {
        (self.options & 0x01) != 0
    }

    pub fn w(&self) -> bool {
        (self.options & 0x02) != 0
    }

    pub fn l(&self) -> bool {
        (self.options & 0x04) != 0
    }

    pub fn h(&self) -> bool {
        (self.options & 0x08) != 0
    }

    pub fn g(&self) -> bool {
        (self.options & 0x10) != 0
    }
}

#[allow(dead_code)]
impl<'a> Linkstate<'a> {
    /// Deep-copy this borrowed zero-copy view into an owned, lifetime-free
    /// [`LinkstateOwned`] held in the given storage profile. Call at
    /// a decode boundary when the decoded value must outlive the input
    /// buffer — stored in a long-lived enum, moved across an async task, or
    /// inserted by value into a bounded-collection.
    ///
    /// Fallible for profile uniformity: on the inline profile a field longer
    /// than its declared capacity raises `CodecError::TooManyElements` (the
    /// same bound and error decode enforces), on the growable profile the
    /// copy cannot fail. The borrowed zero-copy path is unaffected either
    /// way.
    pub fn try_into_owned_in<S: ::sce_forge_runtime::codec::CodecStorage>(self) -> Result<LinkstateOwned<S>, CodecError> {
        Ok(LinkstateOwned {
            options: self.options,
            psid: self.psid,
            sn: self.sn,
            zid_len: self.zid_len,
            zid: self.zid.map(<S::Bytes<16> as ::sce_forge_runtime::codec::SceByteBuf>::from_slice).transpose()?,
            whatami: self.whatami,
            num_locators: self.num_locators,
            locators: self.locators.map(|_v| ::sce_forge_runtime::codec::try_collect_list(_v, |_e| _e.try_into_owned_in::<S>())).transpose()?,
            links_len: self.links_len,
            links: ::sce_forge_runtime::codec::try_collect_list(self.links, Ok)?,
            weights: self.weights.map(|_v| ::sce_forge_runtime::codec::try_collect_list(_v, Ok)).transpose()?,
        })
    }

    /// The same projection at the build's default storage profile — growable
    /// where an allocator exists, inline on the heap-free tier.
    pub fn try_into_owned(self) -> Result<LinkstateOwned, CodecError> {
        self.try_into_owned_in()
    }
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> LinkstateOwned<S> {
    /// Re-borrow this owned value back into the zero-copy borrowed view —
    /// the inverse of `try_into_owned_in`. `encode` lives only on the
    /// borrowed view (the owned form is read-only), so an owned consumer
    /// reaches it via `try_as_borrowed` then `encode` / `encode_to_vec`.
    /// Each field is projected by reference — a cheap re-borrow, not a copy.
    /// Fallible: a bounded `<sce:repeat>` / `<sce:tlv-chain>` list holding
    /// more than its declared `N` raises `CodecError::TooManyElements` — the
    /// same bound decode enforces. Only a growable profile can hold such a
    /// list; on the inline profile the source is already within bounds.
    pub fn try_as_borrowed(&self) -> Result<Linkstate<'_>, CodecError> {
        let mut _out = Linkstate::default();
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
    pub fn try_as_borrowed_into<'o>(&'o self, _out: &mut Linkstate<'o>) -> Result<(), CodecError> {
        _out.options = self.options;
        _out.psid = self.psid;
        _out.sn = self.sn;
        _out.zid_len = self.zid_len;
        _out.zid = self.zid.as_ref().map(::sce_forge_runtime::codec::SceByteBuf::as_slice);
        _out.whatami = self.whatami;
        _out.num_locators = self.num_locators;
        match &self.locators {
            Some(_l) => ::sce_forge_runtime::codec::try_project_bounded_into(_out.locators.insert(Default::default()), _l, |_e| Ok(_e.as_borrowed()))?,
            None => _out.locators = None,
        }
        _out.links_len = self.links_len;
        ::sce_forge_runtime::codec::try_project_bounded_into(&mut _out.links, &self.links, |_e| Ok(_e.clone()))?;
        match &self.weights {
            Some(_l) => ::sce_forge_runtime::codec::try_project_bounded_into(_out.weights.insert(Default::default()), _l, |_e| Ok(_e.clone()))?,
            None => _out.weights = None,
        }
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
    pub fn transcode_in<D: ::sce_forge_runtime::codec::CodecStorage>(&self) -> Result<LinkstateOwned<D>, CodecError> {
        self.try_as_borrowed()?.try_into_owned_in::<D>()
    }
}

#[allow(dead_code)]
impl<S: ::sce_forge_runtime::codec::CodecStorage> LinkstateOwned<S> {
    /// Encode `self` into the caller-owned sink, straight from the owned
    /// fields: the bytes `try_as_borrowed` followed by
    /// [`Linkstate::encode`] writes, without the projection.
    ///
    /// The projection builds the whole borrowed record (every list and
    /// embedded body in it, by value) only for `encode` to read it once. A
    /// sender that holds an owned value encodes it from here. The same
    /// refusals as the projection's: a list longer than the borrowed view
    /// declares raises `CodecError::TooManyElements`, so an owned value the
    /// borrowed form could not carry is an error and never a frame its own
    /// decoder would reject.
    pub fn encode<K: SceSink>(&self, w: &mut K) -> Result<(), CodecError> {
        // Streaming cursor encode (SSOT selection: `needs_streaming`).
        // Mirrors the streaming decode: every field appends its own bytes
        // in declaration order through the per-field encode blocks, so a
        // gated field skips its append when absent, and a fixed field after
        // a variable-length payload lands after the payload (the positional
        // path appends variable fields last, placing it ahead on the wire).
        // Per-field `is_repeat` / `is_tlv_chain` / `is_embed` route to their
        // dedicated helpers; everything else uses `present_if_encode_block`
        // (its non-gated arm covers plain fixed / tail / length-ref / VLE).
        w.write_u8(self.options)?;
        w.write_vle_u64(self.psid)?;
        w.write_vle_u64(self.sn)?;
        if let Some(_v) = self.zid_len {
        w.write_vle_u64(_v)?;
        }
        if let Some(_v) = &self.zid {
            w.write_bytes(::sce_forge_runtime::codec::SceByteBuf::as_slice(_v))?;
        }
        if let Some(_v) = self.whatami {
            w.write_u8(_v)?;
        }
        if let Some(_v) = self.num_locators {
        w.write_vle_u64(_v)?;
        }
        if let Some(_list) = &self.locators {
            for _e in ::sce_forge_runtime::codec::bounded_entries::<_, _, 64>(_list)? {
                _e.encode(w)?;
            }
        }
        w.write_vle_u64(self.links_len)?;
        for _e in ::sce_forge_runtime::codec::bounded_entries::<_, _, 64>(&self.links)? {
            _e.encode(w)?;
        }
        if let Some(_list) = &self.weights {
            for _e in ::sce_forge_runtime::codec::bounded_entries::<_, _, 64>(_list)? {
                _e.encode(w)?;
            }
        }
        Ok(())
    }

    /// Heap-backed convenience facade over [`Self::encode`]. Fallible: a list
    /// past the bound the borrowed view declares is refused, and so is a
    /// presence the chain predicates disagree with.
    #[cfg(feature = "alloc")]
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, CodecError> {
        let mut _sce_v: Vec<u8> = Vec::with_capacity(Linkstate::MAX_ENCODED_BYTES);
        let mut _sce_sink = VecSink::new(&mut _sce_v);
        self.encode(&mut _sce_sink)?;
        Ok(_sce_v)
    }
}

#[allow(dead_code)]
impl<'a> Linkstate<'a> {
    /// Project this borrowed view into an owned [`LinkstateOwned`]
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
    pub fn try_into_owned_in_origin<S: ::sce_forge_runtime::codec::OriginStorage>(self, origin: &<S as ::sce_forge_runtime::codec::OriginStorage>::Origin) -> Result<LinkstateOwned<S>, CodecError> {
        Ok(LinkstateOwned {
            options: self.options,
            psid: self.psid,
            sn: self.sn,
            zid_len: self.zid_len,
            zid: self.zid.map(|_v| <S as ::sce_forge_runtime::codec::OriginStorage>::bytes_from::<16>(origin, _v)).transpose()?,
            whatami: self.whatami,
            num_locators: self.num_locators,
            locators: self.locators.map(|_v| ::sce_forge_runtime::codec::try_collect_list(_v, |_e| _e.try_into_owned_in_origin::<S>(origin))).transpose()?,
            links_len: self.links_len,
            links: ::sce_forge_runtime::codec::try_collect_list(self.links, Ok)?,
            weights: self.weights.map(|_v| ::sce_forge_runtime::codec::try_collect_list(_v, Ok)).transpose()?,
        })
    }
}
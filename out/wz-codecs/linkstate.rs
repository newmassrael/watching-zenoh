// SCE-MAP: linkstate:105

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

use super::linkstate_link::LinkstateLink;
use super::linkstate_weight::LinkstateWeight;
use super::locator::Locator;

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
        let locators = if (options & 0x04u8) != 0 {
            let _n = num_locators.expect("co-gating: count present-if matches repeat");
            let mut _vec: HeaplessVec<Locator<'a>, 64> = HeaplessVec::new();
            for _ in 0.._n {
                _vec.push(Locator::decode(cursor)?)
                    .map_err(|_| CodecError::TooManyElements)?;
            }
            Some(_vec)
        } else {
            None
        };
        let links_len = cursor.read_vle_u64()?;
        let links = {
            let mut _vec: HeaplessVec<LinkstateLink, 64> = HeaplessVec::new();
            for _ in 0..links_len {
                _vec.push(LinkstateLink::decode(cursor)?)
                    .map_err(|_| CodecError::TooManyElements)?;
            }
            _vec
        };
        let weights = if (options & 0x08u8) != 0 {
            let _n = links_len;
            let mut _vec: HeaplessVec<LinkstateWeight, 64> = HeaplessVec::new();
            for _ in 0.._n {
                _vec.push(LinkstateWeight::decode(cursor)?)
                    .map_err(|_| CodecError::TooManyElements)?;
            }
            Some(_vec)
        } else {
            None
        };
        Ok(Self {
            options,
            psid,
            sn,
            zid_len,
            zid,
            whatami,
            num_locators,
            locators,
            links_len,
            links,
            weights,
        })
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

    /// Worst-case encoded byte count for this codec — the upper bound
    /// against which `VecSink::new` reserves capacity in the
    /// `encode_to_vec` facade, and the natural reserve hint for
    /// caller-owned `SliceSink` allocations.
    pub const MAX_ENCODED_BYTES: usize = 9603;

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
// `Linkstate<'a>` above is a zero-copy view borrowing the decode
// buffer. Consumers that persist a decoded value beyond the buffer's
// lifetime — including the self-contained bounded-collection that stores
// elements by value — call `.try_into_owned()` for this lifetime-free
// `LinkstateOwned`. The rkyv-style Archived(borrowed) ↔ native
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
use super::locator::LocatorOwned;
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq)]
pub struct LinkstateOwned {
    pub options: u8,
    pub psid: u64,
    pub sn: u64,
    pub zid_len: Option<u64>,
    pub zid: Option<::sce_forge_runtime::codec::SceBytes<16>>,
    pub whatami: Option<u8>,
    pub num_locators: Option<u64>,
    pub locators: Option<Vec<LocatorOwned>>,
    pub links_len: u64,
    pub links: Vec<LinkstateLink>,
    pub weights: Option<Vec<LinkstateWeight>>,
}

#[cfg(feature = "alloc")]
#[allow(dead_code)]
impl LinkstateOwned {
    // RFC §synth-5-B read-accessor parity with the borrowed view: pure
    // bit getters over the copied carrier (rkyv Archived↔native getter
    // parity), so alloc consumers read `{Codec}Owned` with the same API as
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
}

#[cfg(feature = "alloc")]
impl<'a> Linkstate<'a> {
    /// Deep-copy this borrowed zero-copy view into an owned, lifetime-free
    /// [`LinkstateOwned`]. Call at a decode boundary when the
    /// decoded value must outlive the input buffer — stored in a long-lived
    /// enum, moved across an async task, or inserted by value into a
    /// bounded-collection. `String` / `Bytes` fields copy into the portable
    /// `SceString<N>` / `SceBytes<N>`: an unbounded heap copy under `alloc`
    /// (`N` advisory), else a fixed `heapless` copy capped at `N`. The
    /// method is fallible for profile uniformity — without `alloc` an
    /// over-`N` view raises `CodecError::TooManyElements` (the same bound
    /// and error decode enforces); under `alloc` the copy never fails. The
    /// borrowed zero-copy path is unaffected.
    pub fn try_into_owned(self) -> Result<LinkstateOwned, CodecError> {
        Ok(LinkstateOwned {
            options: self.options,
            psid: self.psid,
            sn: self.sn,
            zid_len: self.zid_len,
            zid: self.zid.map(::sce_forge_runtime::codec::SceBytes::from_slice).transpose()?,
            whatami: self.whatami,
            num_locators: self.num_locators,
            locators: self.locators.map(|_v| _v.into_iter().map(|_e| _e.try_into_owned()).collect::<Result<_, _>>()).transpose()?,
            links_len: self.links_len,
            links: self.links.into_iter().collect(),
            weights: self.weights.map(|_v| _v.into_iter().collect()),
        })
    }
}

#[cfg(feature = "alloc")]
impl LinkstateOwned {
    /// Re-borrow this owned value back into the zero-copy borrowed view —
    /// the inverse of `try_into_owned`. `encode` lives only on the borrowed
    /// view (the owned form is read-only), so an owned consumer reaches it
    /// via `try_as_borrowed` then `encode` / `encode_to_vec`. Each
    /// field is projected by reference — a cheap re-borrow, not a copy.
    /// Fallible: a bounded `<sce:repeat>` / `<sce:tlv-chain>` list whose
    /// owned `Vec` holds more than its declared `N` raises
    /// `CodecError::TooManyElements` — the same bound decode enforces.
    pub fn try_as_borrowed(&self) -> Result<Linkstate<'_>, CodecError> {
        Ok(Linkstate {
            options: self.options,
            psid: self.psid,
            sn: self.sn,
            zid_len: self.zid_len,
            zid: self.zid.as_deref(),
            whatami: self.whatami,
            num_locators: self.num_locators,
            locators: self.locators.as_ref().map(|_l| sce_forge_runtime::codec::try_project_bounded(_l, |_e| Ok(_e.as_borrowed()))).transpose()?,
            links_len: self.links_len,
            links: sce_forge_runtime::codec::try_project_bounded(&self.links, |_e| Ok(_e.clone()))?,
            weights: self.weights.as_ref().map(|_l| sce_forge_runtime::codec::try_project_bounded(_l, |_e| Ok(_e.clone()))).transpose()?,
        })
    }
}
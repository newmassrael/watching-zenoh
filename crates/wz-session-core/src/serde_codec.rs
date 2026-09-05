// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y68 — `ext-pubsub-serde-codec`: the Zenoh Serialization Format codec.
//!
//! A faithful, no_std + alloc re-implementation of zenoh-ext's
//! `serialization.rs` (`z_serialize` / `z_deserialize` and the
//! `Serialize` / `Deserialize` traits) — the typed application-payload
//! codec defined by the [Zenoh Serialization RFC]. It is a standalone
//! public atom (apps serialize typed payloads the zenoh way) and the
//! leaf prerequisite for the §5.25 advanced pub/sub track: the
//! sample-miss-detection heartbeat carries `z_serialize::<u32>(last_sn)`
//! and the recovery path decodes it with `z_deserialize::<u32>`
//! (zenoh advanced_publisher.rs:394/413, advanced_subscriber.rs:1075 —
//! the SOLE serde consumers; the cache/recovery/history replies carry
//! raw samples, not serde payloads).
//!
//! [Zenoh Serialization RFC]: https://github.com/eclipse-zenoh/roadmap/blob/main/rfcs/ALL/Serialization.md
//!
//! ## Wire format (byte-identical to zenoh-ext)
//!
//! - Integers (`i8..i128`, `u8..u128`, `f32`, `f64`): little-endian
//!   fixed-width, two's-complement for signed (NOT zigzag) — mirror of
//!   `impl_num!` (serialization.rs:309-356).
//! - `bool`: one byte `0` / `1` (serialization.rs:358-371).
//! - Sequences (`[T]`, `Vec<T>`): a `VarInt` length prefix then the
//!   elements (serialization.rs:373-441).
//! - `str` / `String`: serialized as the `&[u8]` of their UTF-8
//!   (length-prefixed) (serialization.rs:482-501).
//! - Tuples: the fields concatenated with NO framing
//!   (serialization.rs:503-546).
//! - `BTreeMap` / `BTreeSet`: a `VarInt` count then the elements
//!   (each map entry as a `(k, v)` pair) — mirror of zenoh's
//!   `serialize_iter` path (serialization.rs:442-481).
//!
//! ## Deliberate divergences from zenoh-ext (superset-not-mirror)
//!
//! - **Container is `Vec<u8>` / `&[u8]`, not `ZBytes`.** wz's
//!   `Sample.payload` is a `Vec<u8>` (sample.rs:304), so the codec
//!   serializes into a `Vec<u8>` and reads from a `&[u8]` cursor. The
//!   emitted bytes are identical to `ZBytes::to_bytes()` — the golden
//!   vectors below lock that.
//!   Upstream's `impl Serialize for ZBytes`
//!   (`zenoh-ext/src/serialization.rs` @ `impl Serialize for ZBytes`)
//!   writes a `VarInt` length then the raw bytes, which is exactly what
//!   wz's `impl Serialize for Vec<u8>` writes — the type is renamed, the
//!   format is not, and `zbytes_container_shape_is_the_vec_u8_impl`
//!   pins the equality.
//! - **`HashMap` / `HashSet` are the `hashbrown` ones**, not
//!   `std::collections`'. This crate is `#![no_std]`, and it already
//!   carries `hashbrown` for the peer-keyexpr table, so the hash
//!   containers cost no new dependency. They are generic over the hasher
//!   `S` where upstream fixes `RandomState`; the serialized form is a
//!   `VarInt` count then the entries in iteration order, which is what
//!   upstream emits and what upstream's own hash containers cannot make
//!   deterministic either.
//! - **The `serialize_n` / `deserialize_n` bulk hooks keep upstream's
//!   ROLE, not upstream's signature.** Upstream reads through
//!   `std::io::Read`, which can only fill ALREADY-INITIALIZED memory, so
//!   its bulk read takes `&mut [Self]` and carries a second
//!   `deserialize_n_uninit` over `MaybeUninit` to dodge the double
//!   initialization — its own comment at `default_deserialize_n_uninit`
//!   says exactly that. wz's deserializer reads from a BORROWED SLICE,
//!   so the bulk path constructs the `Vec` directly and needs neither
//!   the out-parameter nor the `MaybeUninit` twin:
//!   `Deserialize::deserialize_n` subsumes both upstream methods. (Plain
//!   code, not an intra-doc link: both hooks are `#[doc(hidden)]`, so a link
//!   to one is unresolvable and would spend a Layer C1bz doc-link budget.)
//!
//! ## The two varints, and why this module carries its own
//!
//! zenoh has TWO variable-length integer encodings and they are not the
//! same encoding:
//!
//! - The PROTOCOL `ZInt` (base-128 VLE) every wire field uses. Its 9th
//!   byte carries a full 8 data bits, the continuation bit reused as
//!   data, so a `u64` caps at 9 bytes. That is [`crate::vle`], the SSOT
//!   shared with every SCE-generated codec.
//! - The SERIALIZATION-FORMAT `VarInt`, which zenoh-ext encodes with the
//!   `leb128` crate (`zenoh-ext/Cargo.toml` @ `leb128`) — canonical
//!   LEB128, seven data bits per byte, so a `u64` takes up to ten.
//!
//! They agree for every value `< 2^63` and diverge above it, and
//! `VarInt` is a PUBLIC `Serialize` type, so the divergence is reachable
//! through the API and not only through length prefixes. Until R2362 this
//! module routed `VarInt` through the protocol VLE and called the
//! difference unreachable; it now carries the LEB128 the format actually
//! specifies, module-private, so the protocol SSOT keeps its own subject.

use alloc::{
    borrow::Cow,
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use core::{
    hash::{BuildHasher, Hash},
    marker::PhantomData,
};

use hashbrown::{HashMap, HashSet};

/// Append `v` to `out` as canonical LEB128 — the encoding zenoh-ext's
/// `VarInt<usize>` uses (`leb128::write::unsigned`). Seven data bits per
/// byte, the high bit marking continuation, so `u64::MAX` takes ten
/// bytes where the protocol VLE ([`crate::vle`]) would take nine.
fn write_leb128(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut byte = (v as u8) & 0x7f;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            return;
        }
    }
}

/// Error returned when deserialization fails (truncated input, an
/// invalid `bool` byte, a non-UTF-8 `String`, or trailing bytes after a
/// top-level [`z_deserialize`]). Mirror of zenoh-ext's `ZDeserializeError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZDeserializeError;

impl core::fmt::Display for ZDeserializeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("deserialization error")
    }
}

/// The element-at-a-time fallback behind [`Serialize::serialize_n`] —
/// the twin of zenoh-ext's `default_serialize_n`.
fn default_serialize_n<T: Serialize>(slice: &[T], serializer: &mut ZSerializer) {
    for t in slice {
        t.serialize(serializer);
    }
}

/// The element-at-a-time fallback behind [`Deserialize::deserialize_n`] —
/// the twin of zenoh-ext's `default_deserialize_n`. Pushes in a loop with
/// no `with_capacity(len)`, so a malformed length cannot drive an
/// unbounded allocation before the truncation check fails.
fn default_deserialize_n<T: Deserialize>(
    len: usize,
    deserializer: &mut ZDeserializer<'_>,
) -> Result<Vec<T>, ZDeserializeError> {
    let mut out = Vec::new();
    for _ in 0..len {
        out.push(T::deserialize(deserializer)?);
    }
    Ok(out)
}

/// A type that can be serialized into the Zenoh Serialization Format.
pub trait Serialize {
    /// Append the serialized form of `self` to `serializer`.
    fn serialize(&self, serializer: &mut ZSerializer);

    /// Bulk-serialize a run of `Self` — the hook every sequence body goes
    /// through, so an implementor can replace `len` calls to
    /// [`Serialize::serialize`] with one pass. The default is exactly
    /// that loop, and an override MUST emit the same bytes it would.
    ///
    /// The wz twin of zenoh-ext's `Serialize::serialize_n`.
    #[doc(hidden)]
    fn serialize_n(slice: &[Self], serializer: &mut ZSerializer)
    where
        Self: Sized,
    {
        default_serialize_n(slice, serializer);
    }
}

impl<T: Serialize + ?Sized> Serialize for &T {
    fn serialize(&self, serializer: &mut ZSerializer) {
        T::serialize(*self, serializer);
    }
}

/// A type that can be deserialized from the Zenoh Serialization Format.
pub trait Deserialize: Sized {
    /// Read one value of `Self` from `deserializer`, advancing its cursor.
    fn deserialize(deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError>;

    /// Bulk-deserialize a run of `len` values — the read twin of
    /// [`Serialize::serialize_n`], and the hook every sequence body goes
    /// through once the `VarInt` count has been read.
    ///
    /// This subsumes BOTH of upstream's read hooks. `deserialize_n` and
    /// `deserialize_n_uninit` are two methods there only because a
    /// `std::io::Read` can fill nothing but initialized memory; wz reads
    /// from a borrowed slice, so the run is built straight into a `Vec`
    /// and there is no uninitialized half to dodge.
    #[doc(hidden)]
    fn deserialize_n(
        len: usize,
        deserializer: &mut ZDeserializer<'_>,
    ) -> Result<Vec<Self>, ZDeserializeError> {
        default_deserialize_n(len, deserializer)
    }
}

/// Serializer accumulating bytes into a `Vec<u8>` (the wz analogue of
/// zenoh-ext's `ZSerializer(ZBytesWriter)`).
#[derive(Debug, Default)]
pub struct ZSerializer(Vec<u8>);

impl ZSerializer {
    /// Create an empty serializer.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Serialize one object into the buffer.
    pub fn serialize<T: Serialize>(&mut self, t: T) {
        t.serialize(self);
    }

    /// Serialize an exact-size iterator as a `VarInt` count followed by
    /// each element — the format `BTreeSet` / `BTreeMap` use, and the
    /// twin of zenoh-ext `ZSerializer::serialize_iter`.
    pub fn serialize_iter<T: Serialize, I: IntoIterator<Item = T>>(&mut self, iter: I)
    where
        I::IntoIter: ExactSizeIterator,
    {
        let iter = iter.into_iter();
        VarInt(iter.len()).serialize(self);
        for t in iter {
            t.serialize(self);
        }
    }

    /// Finish serialization, returning the accumulated bytes.
    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Deserializer reading from a borrowed byte slice with a position
/// cursor (the wz analogue of zenoh-ext's `ZDeserializer(ZBytesReader)`).
#[derive(Debug)]
pub struct ZDeserializer<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ZDeserializer<'a> {
    /// Create a deserializer over `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Return true when every byte has been consumed.
    pub fn done(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    /// Read one value of `T`, advancing the cursor.
    pub fn deserialize<T: Deserialize>(&mut self) -> Result<T, ZDeserializeError> {
        T::deserialize(self)
    }

    /// Read a `VarInt` count and return an iterator over that many `T` —
    /// the streaming read half, and the twin of zenoh-ext's
    /// `ZDeserializer::deserialize_iter`. It reads what
    /// [`ZSerializer::serialize_iter`] wrote, which is the same framing
    /// every sequence body uses.
    ///
    /// Dropping the iterator early drains the rest of the run, so the
    /// cursor is left where a full read would have left it and the value
    /// after the sequence still parses.
    pub fn deserialize_iter<'b, T: Deserialize>(
        &'b mut self,
    ) -> Result<ZReadIter<'a, 'b, T>, ZDeserializeError> {
        let len = VarInt::<usize>::deserialize(self)?.0;
        Ok(ZReadIter {
            deserializer: self,
            len,
            _phantom: PhantomData,
        })
    }

    /// `read_exact` over the borrowed slice: take `n` bytes or fail.
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], ZDeserializeError> {
        let end = self.pos.checked_add(n).ok_or(ZDeserializeError)?;
        if end > self.bytes.len() {
            return Err(ZDeserializeError);
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Read one canonical-LEB128 `u64` (the `VarInt` reader), advancing
    /// the cursor by the consumed byte count. Rejects an encoding whose
    /// value does not fit a `u64`, the same overflow rule
    /// `leb128::read::unsigned` applies at `shift == 63`.
    fn read_leb128(&mut self) -> Result<u64, ZDeserializeError> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.read_bytes(1)?[0];
            if shift == 63 && byte != 0x00 && byte != 0x01 {
                return Err(ZDeserializeError);
            }
            if shift > 63 {
                return Err(ZDeserializeError);
            }
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
    }
}

/// Iterator returned by [`ZDeserializer::deserialize_iter`] — the wz twin
/// of zenoh-ext's `ZReadIter`.
#[derive(Debug)]
pub struct ZReadIter<'a, 'b, T: Deserialize> {
    deserializer: &'b mut ZDeserializer<'a>,
    len: usize,
    _phantom: PhantomData<T>,
}

impl<T: Deserialize> Iterator for ZReadIter<'_, '_, T> {
    type Item = Result<T, ZDeserializeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        Some(T::deserialize(self.deserializer))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len, Some(self.len))
    }
}

impl<T: Deserialize> ExactSizeIterator for ZReadIter<'_, '_, T> {}

impl<T: Deserialize> Drop for ZReadIter<'_, '_, T> {
    fn drop(&mut self) {
        self.by_ref().for_each(drop);
    }
}

/// Serialize `t` into a fresh `Vec<u8>` per the Zenoh Serialization
/// Format. Byte-identical to zenoh-ext `z_serialize(t).to_bytes()`.
pub fn z_serialize<T: Serialize + ?Sized>(t: &T) -> Vec<u8> {
    let mut serializer = ZSerializer::new();
    serializer.serialize(t);
    serializer.finish()
}

/// Deserialize one `T` from `bytes`. Fails if `bytes` is malformed, too
/// short, or carries trailing bytes after `T` (the zenoh-ext
/// `!done()` trailing-byte reject, serialization.rs:146-148).
pub fn z_deserialize<T: Deserialize>(bytes: &[u8]) -> Result<T, ZDeserializeError> {
    let mut deserializer = ZDeserializer::new(bytes);
    let t = T::deserialize(&mut deserializer)?;
    if !deserializer.done() {
        return Err(ZDeserializeError);
    }
    Ok(t)
}

/// LEB128-style variable-length wrapper used for length prefixes. Only
/// `VarInt<usize>` is serializable, matching zenoh-ext (serialization.rs:550).
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarInt<T>(pub T);

impl Serialize for VarInt<usize> {
    fn serialize(&self, serializer: &mut ZSerializer) {
        write_leb128(&mut serializer.0, self.0 as u64);
    }
}

impl Deserialize for VarInt<usize> {
    fn deserialize(deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError> {
        let n = deserializer.read_leb128()?;
        Ok(VarInt(usize::try_from(n).map_err(|_| ZDeserializeError)?))
    }
}

macro_rules! impl_num {
    ($($ty:ty),* $(,)?) => {$(
        impl Serialize for $ty {
            #[inline]
            fn serialize(&self, serializer: &mut ZSerializer) {
                serializer.0.extend_from_slice(&self.to_le_bytes());
            }

            /// The bulk write: one `reserve` for the whole run instead of
            /// `len` growth checks. Upstream reaches the same place by
            /// transmuting the slice to its little-endian bytes
            /// (`unsafe { slice.align_to().1 }`); wz declines the
            /// transmute and keeps the loop, because the hook's contract
            /// is the BYTES and those are identical either way.
            #[inline]
            fn serialize_n(slice: &[Self], serializer: &mut ZSerializer) {
                const N: usize = core::mem::size_of::<$ty>();
                serializer.0.reserve(slice.len().saturating_mul(N));
                for t in slice {
                    serializer.0.extend_from_slice(&t.to_le_bytes());
                }
            }
        }
        impl Deserialize for $ty {
            #[inline]
            fn deserialize(
                deserializer: &mut ZDeserializer<'_>,
            ) -> Result<Self, ZDeserializeError> {
                const N: usize = core::mem::size_of::<$ty>();
                let mut buf = [0u8; N];
                buf.copy_from_slice(deserializer.read_bytes(N)?);
                Ok(<$ty>::from_le_bytes(buf))
            }

            /// The bulk read: the run's whole byte span is bounds-checked
            /// ONCE, which is also what makes `with_capacity(len)` safe
            /// here — a malformed length fails `read_bytes` before a
            /// single element is allocated, so the reservation can never
            /// outrun the input the way it could in the generic path.
            #[inline]
            fn deserialize_n(
                len: usize,
                deserializer: &mut ZDeserializer<'_>,
            ) -> Result<Vec<Self>, ZDeserializeError> {
                const N: usize = core::mem::size_of::<$ty>();
                let span = len.checked_mul(N).ok_or(ZDeserializeError)?;
                let bytes = deserializer.read_bytes(span)?;
                let mut out = Vec::with_capacity(len);
                for chunk in bytes.chunks_exact(N) {
                    let mut buf = [0u8; N];
                    buf.copy_from_slice(chunk);
                    out.push(<$ty>::from_le_bytes(buf));
                }
                Ok(out)
            }
        }
    )*};
}
impl_num!(i8, i16, i32, i64, i128, u8, u16, u32, u64, u128, f32, f64);

impl Serialize for bool {
    fn serialize(&self, serializer: &mut ZSerializer) {
        (*self as u8).serialize(serializer);
    }
}
impl Deserialize for bool {
    fn deserialize(deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError> {
        match u8::deserialize(deserializer)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ZDeserializeError),
        }
    }
}

fn serialize_slice<T: Serialize>(slice: &[T], serializer: &mut ZSerializer) {
    VarInt(slice.len()).serialize(serializer);
    T::serialize_n(slice, serializer);
}

fn deserialize_slice<T: Deserialize>(
    deserializer: &mut ZDeserializer<'_>,
) -> Result<Vec<T>, ZDeserializeError> {
    let len = VarInt::<usize>::deserialize(deserializer)?.0;
    T::deserialize_n(len, deserializer)
}

impl<T: Serialize> Serialize for [T] {
    fn serialize(&self, serializer: &mut ZSerializer) {
        serialize_slice(self, serializer);
    }
}
impl<T: Serialize, const N: usize> Serialize for [T; N] {
    fn serialize(&self, serializer: &mut ZSerializer) {
        serialize_slice(self.as_slice(), serializer);
    }
}
impl<T: Deserialize, const N: usize> Deserialize for [T; N] {
    fn deserialize(deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError> {
        // The length prefix must name EXACTLY N, the same reject upstream
        // makes before it reads a single element.
        if VarInt::<usize>::deserialize(deserializer)?.0 != N {
            return Err(ZDeserializeError);
        }
        let elems = T::deserialize_n(N, deserializer)?;
        // `deserialize_n` returned N elements or errored, so the convert
        // cannot fail; `map_err` rather than `unwrap` keeps the `T: Debug`
        // bound upstream's `MaybeUninit` route also avoids.
        <[T; N]>::try_from(elems).map_err(|_| ZDeserializeError)
    }
}
impl<'a, T: Serialize + 'a> Serialize for Cow<'a, [T]>
where
    [T]: alloc::borrow::ToOwned,
{
    fn serialize(&self, serializer: &mut ZSerializer) {
        serialize_slice(self, serializer);
    }
}
impl<T: Serialize> Serialize for Box<[T]> {
    fn serialize(&self, serializer: &mut ZSerializer) {
        serialize_slice(self, serializer);
    }
}
impl<T: Deserialize> Deserialize for Box<[T]> {
    fn deserialize(deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError> {
        Ok(deserialize_slice(deserializer)?.into_boxed_slice())
    }
}
impl<T: Serialize> Serialize for Vec<T> {
    fn serialize(&self, serializer: &mut ZSerializer) {
        serialize_slice(self, serializer);
    }
}
impl<T: Deserialize> Deserialize for Vec<T> {
    fn deserialize(deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError> {
        deserialize_slice(deserializer)
    }
}

impl Serialize for str {
    fn serialize(&self, serializer: &mut ZSerializer) {
        self.as_bytes().serialize(serializer);
    }
}
impl Serialize for Cow<'_, str> {
    fn serialize(&self, serializer: &mut ZSerializer) {
        self.as_bytes().serialize(serializer);
    }
}
impl Serialize for String {
    fn serialize(&self, serializer: &mut ZSerializer) {
        self.as_bytes().serialize(serializer);
    }
}
impl Deserialize for String {
    fn deserialize(deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError> {
        String::from_utf8(Vec::<u8>::deserialize(deserializer)?).map_err(|_| ZDeserializeError)
    }
}

impl<T: Serialize + Eq + Hash, S> Serialize for HashSet<T, S> {
    fn serialize(&self, serializer: &mut ZSerializer) {
        serializer.serialize_iter(self);
    }
}
impl<T: Deserialize + Eq + Hash, S: BuildHasher + Default> Deserialize for HashSet<T, S> {
    fn deserialize(deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError> {
        deserializer.deserialize_iter()?.collect()
    }
}
impl<T: Serialize + Ord> Serialize for BTreeSet<T> {
    fn serialize(&self, serializer: &mut ZSerializer) {
        serializer.serialize_iter(self);
    }
}
impl<T: Deserialize + Ord> Deserialize for BTreeSet<T> {
    fn deserialize(deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError> {
        deserializer.deserialize_iter()?.collect()
    }
}
impl<K: Serialize + Eq + Hash, V: Serialize, S> Serialize for HashMap<K, V, S> {
    fn serialize(&self, serializer: &mut ZSerializer) {
        serializer.serialize_iter(self);
    }
}
impl<K: Deserialize + Eq + Hash, V: Deserialize, S: BuildHasher + Default> Deserialize
    for HashMap<K, V, S>
{
    fn deserialize(deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError> {
        deserializer.deserialize_iter()?.collect()
    }
}
impl<K: Serialize + Ord, V: Serialize> Serialize for BTreeMap<K, V> {
    fn serialize(&self, serializer: &mut ZSerializer) {
        serializer.serialize_iter(self);
    }
}
impl<K: Deserialize + Ord, V: Deserialize> Deserialize for BTreeMap<K, V> {
    fn deserialize(deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError> {
        deserializer.deserialize_iter()?.collect()
    }
}

macro_rules! impl_tuple {
    ($($ty:ident $idx:tt),+) => {
        impl<$($ty: Serialize),+> Serialize for ($($ty,)+) {
            fn serialize(&self, serializer: &mut ZSerializer) {
                $(self.$idx.serialize(serializer);)+
            }
        }
        impl<$($ty: Deserialize),+> Deserialize for ($($ty,)+) {
            fn deserialize(
                deserializer: &mut ZDeserializer<'_>,
            ) -> Result<Self, ZDeserializeError> {
                Ok(($($ty::deserialize(deserializer)?,)+))
            }
        }
    };
}
/// The empty tuple: zero fields concatenated is zero bytes. Upstream's
/// `impl_tuple!` recursion emits this arity first (its `@@` arm with an
/// empty type list), so `z_serialize(&())` is an empty payload there too.
impl Serialize for () {
    fn serialize(&self, _serializer: &mut ZSerializer) {}
}
impl Deserialize for () {
    fn deserialize(_deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError> {
        Ok(())
    }
}

impl_tuple!(T0 0);
impl_tuple!(T0 0, T1 1);
impl_tuple!(T0 0, T1 1, T2 2);
impl_tuple!(T0 0, T1 1, T2 2, T3 3);
impl_tuple!(T0 0, T1 1, T2 2, T3 3, T4 4);
impl_tuple!(T0 0, T1 1, T2 2, T3 3, T4 4, T5 5);
impl_tuple!(T0 0, T1 1, T2 2, T3 3, T4 4, T5 5, T6 6);
impl_tuple!(T0 0, T1 1, T2 2, T3 3, T4 4, T5 5, T6 6, T7 7);
impl_tuple!(T0 0, T1 1, T2 2, T3 3, T4 4, T5 5, T6 6, T7 7, T8 8);
impl_tuple!(T0 0, T1 1, T2 2, T3 3, T4 4, T5 5, T6 6, T7 7, T8 8, T9 9);
impl_tuple!(T0 0, T1 1, T2 2, T3 3, T4 4, T5 5, T6 6, T7 7, T8 8, T9 9, T10 10);
impl_tuple!(T0 0, T1 1, T2 2, T3 3, T4 4, T5 5, T6 6, T7 7, T8 8, T9 9, T10 10, T11 11);
impl_tuple!(
    T0 0, T1 1, T2 2, T3 3, T4 4, T5 5, T6 6, T7 7, T8 8, T9 9, T10 10, T11 11, T12 12
);
impl_tuple!(
    T0 0, T1 1, T2 2, T3 3, T4 4, T5 5, T6 6, T7 7, T8 8, T9 9, T10 10, T11 11, T12 12,
    T13 13
);
impl_tuple!(
    T0 0, T1 1, T2 2, T3 3, T4 4, T5 5, T6 6, T7 7, T8 8, T9 9, T10 10, T11 11, T12 12,
    T13 13, T14 14
);
impl_tuple!(
    T0 0, T1 1, T2 2, T3 3, T4 4, T5 5, T6 6, T7 7, T8 8, T9 9, T10 10, T11 11, T12 12,
    T13 13, T14 14, T15 15
);

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};

    /// The exact byte vectors from zenoh-ext serialization.rs:653-673
    /// (`binary_format` test). Locks wz's emit to zenoh's wire bytes.
    #[test]
    fn binary_format_matches_zenoh_golden_vectors() {
        let i1: i32 = 1234566;
        assert_eq!(z_serialize(&i1), vec![134, 214, 18, 0]);
        let i2: i32 = -49245;
        assert_eq!(z_serialize(&i2), vec![163, 63, 255, 255]);
        let s: &str = "test";
        assert_eq!(z_serialize(s), vec![4, 116, 101, 115, 116]);
        let t: (u16, f32, &str) = (500, 1234.0, "test");
        assert_eq!(
            z_serialize(&t),
            vec![244, 1, 0, 64, 154, 68, 4, 116, 101, 115, 116]
        );
        let v: Vec<i64> = vec![-100, 500, 100000, -20000000];
        assert_eq!(
            z_serialize(&v),
            vec![
                4, 156, 255, 255, 255, 255, 255, 255, 255, 244, 1, 0, 0, 0, 0, 0, 0, 160, 134, 1,
                0, 0, 0, 0, 0, 0, 211, 206, 254, 255, 255, 255, 255
            ]
        );
        let vp: Vec<(&str, i16)> = vec![("s1", 10), ("s2", -10000)];
        assert_eq!(
            z_serialize(&vp),
            vec![2, 2, 115, 49, 10, 0, 2, 115, 50, 240, 216]
        );
    }

    /// The §5.25 heartbeat path: `z_serialize::<u32>(last_sn)` is a bare
    /// 4-byte little-endian u32 (no length prefix), decoded back by
    /// `z_deserialize::<u32>` (zenoh advanced_publisher.rs:394,
    /// advanced_subscriber.rs:1075).
    #[test]
    fn heartbeat_u32_roundtrips_as_4_le_bytes() {
        let last_sn: u32 = 0x4000;
        let bytes = z_serialize(&last_sn);
        assert_eq!(bytes, vec![0x00, 0x40, 0x00, 0x00]);
        assert_eq!(z_deserialize::<u32>(&bytes).unwrap(), 0x4000);
        assert_eq!(
            z_deserialize::<u32>(&z_serialize(&u32::MAX)).unwrap(),
            u32::MAX
        );
        assert_eq!(z_deserialize::<u32>(&z_serialize(&0u32)).unwrap(), 0);
    }

    #[test]
    fn scalar_and_collection_roundtrips() {
        assert!(z_deserialize::<bool>(&z_serialize(&true)).unwrap());
        assert!(!z_deserialize::<bool>(&z_serialize(&false)).unwrap());
        assert_eq!(
            z_deserialize::<i128>(&z_serialize(&i128::MIN)).unwrap(),
            i128::MIN
        );
        assert_eq!(
            z_deserialize::<String>(&z_serialize(&"héllo".to_string())).unwrap(),
            "héllo"
        );
        let v: Vec<u32> = vec![1, 2, 3, 100000];
        assert_eq!(z_deserialize::<Vec<u32>>(&z_serialize(&v)).unwrap(), v);
        let tup: (u8, String, bool) = (7, "x".to_string(), true);
        assert_eq!(
            z_deserialize::<(u8, String, bool)>(&z_serialize(&tup)).unwrap(),
            tup
        );
    }

    /// `BTreeMap` / `BTreeSet` carry a `VarInt` count then elements —
    /// the deterministic-ordered replacement for zenoh's `HashMap`.
    #[test]
    fn btree_roundtrips_deterministically() {
        let mut map = BTreeMap::new();
        map.insert(2u32, "two".to_string());
        map.insert(1u32, "one".to_string());
        let bytes = z_serialize(&map);
        // VarInt(2) then ascending keys (BTreeMap order): 1, "one", 2, "two".
        assert_eq!(bytes[0], 2);
        assert_eq!(z_deserialize::<BTreeMap<u32, String>>(&bytes).unwrap(), map);

        let set: BTreeSet<u16> = [5u16, 1, 3].into_iter().collect();
        assert_eq!(
            z_deserialize::<BTreeSet<u16>>(&z_serialize(&set)).unwrap(),
            set
        );
    }

    #[test]
    fn varint_roundtrips_to_usize_max() {
        for v in [0usize, 1, 127, 128, 16384, usize::MAX] {
            let bytes = z_serialize(&VarInt(v));
            assert_eq!(z_deserialize::<VarInt<usize>>(&bytes).unwrap(), VarInt(v));
        }
    }

    /// R2362 — `VarInt` is CANONICAL LEB128, not the protocol `ZInt` VLE.
    ///
    /// The two agree below `2^63` and part above it: LEB128 spends seven
    /// data bits per byte, so `u64::MAX` is TEN bytes of `0xff` capped by
    /// a `0x01`, where [`crate::vle`] packs the ninth byte with eight data
    /// bits and stops at NINE. `VarInt` is public `Serialize` surface, so
    /// that difference is reachable through the API and not only through
    /// length prefixes. Routing this back through `crate::vle` reds here.
    #[test]
    fn varint_is_leb128_not_the_protocol_vle() {
        // usize::MAX == u64::MAX on this target, the value that separates
        // the two encodings.
        let bytes = z_serialize(&VarInt(usize::MAX));
        assert_eq!(
            bytes,
            vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
            "VarInt(u64::MAX) is ten LEB128 bytes; the protocol VLE would emit nine",
        );
        // The protocol VLE's nine-byte form must NOT decode as this value:
        // it is a different encoding, and reading it as LEB128 is a short,
        // wrong number followed by trailing bytes.
        let mut vle_form = alloc::vec::Vec::new();
        crate::vle::encode_vle_u64_into(&mut vle_form, u64::MAX);
        assert_eq!(
            vle_form.len(),
            9,
            "the protocol VLE caps a u64 at nine bytes"
        );
        assert_ne!(vle_form, bytes);
        assert!(z_deserialize::<VarInt<usize>>(&vle_form).is_err());

        // Below the split the two agree, which is why every length prefix
        // in the golden vectors is unchanged.
        for v in [0u64, 1, 127, 128, 300, 16384, (1u64 << 63) - 1] {
            let mut vle = alloc::vec::Vec::new();
            crate::vle::encode_vle_u64_into(&mut vle, v);
            assert_eq!(z_serialize(&VarInt(v as usize)), vle, "value {v}");
        }

        // The overflow reject `leb128::read::unsigned` makes at shift 63.
        assert!(z_deserialize::<VarInt<usize>>(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02
        ])
        .is_err());
    }

    /// R2362 — the arities upstream's `impl_tuple!` recursion covers:
    /// zero through sixteen. wz stopped at eight, so a nine-field tuple
    /// was not serializable at all.
    #[test]
    fn tuple_arities_zero_and_nine_through_sixteen() {
        // The element type is spelled out: an empty `vec![]` is ambiguous once
        // the crate's feature union pulls a second `PartialEq<_>` for `u8`
        // into scope (`serde_json::Value`), and the narrower single-feature
        // build this test was first run under could not see that.
        let empty: Vec<u8> = Vec::new();
        assert_eq!(z_serialize(&()), empty);
        assert_eq!(z_deserialize::<()>(&[]).unwrap(), ());

        type Nine = (u8, u8, u8, u8, u8, u8, u8, u8, u8);
        let nine: Nine = (1, 2, 3, 4, 5, 6, 7, 8, 9);
        assert_eq!(z_serialize(&nine), vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(z_deserialize::<Nine>(&z_serialize(&nine)).unwrap(), nine);

        #[rustfmt::skip]
        type Sixteen = (
            u8, u8, u8, u8, u8, u8, u8, u8,
            u8, u8, u8, u8, u8, u8, u8, u16,
        );
        let sixteen: Sixteen = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x0102);
        assert_eq!(
            z_serialize(&sixteen),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x02, 0x01],
            "tuple fields concatenate with no framing, the last one little-endian",
        );
        // `core` stops implementing `Debug` / `PartialEq` for tuples at
        // arity twelve, so the read back is compared by re-serializing it
        // rather than by `assert_eq!` on the tuple itself.
        let Ok(back) = z_deserialize::<Sixteen>(&z_serialize(&sixteen)) else {
            panic!("a sixteen-field tuple must deserialize");
        };
        assert_eq!(z_serialize(&back), z_serialize(&sixteen));
    }

    /// R2362 — the four sequence carriers upstream serializes and wz did
    /// not: `[T; N]`, `Box<[T]>`, `Cow<[T]>` and `Cow<str>`. All four
    /// share `Vec`'s framing, so the assertion is byte equality with the
    /// `Vec` form plus the round trip for the two readable ones.
    #[test]
    fn array_box_and_cow_carriers_share_the_vec_framing() {
        let arr: [u16; 3] = [1, 2, 3];
        let as_vec: Vec<u16> = vec![1, 2, 3];
        assert_eq!(z_serialize(&arr), z_serialize(&as_vec));
        assert_eq!(z_deserialize::<[u16; 3]>(&z_serialize(&arr)).unwrap(), arr);
        // A length prefix that does not name N is refused before any
        // element is read (upstream's own N-mismatch reject).
        assert!(z_deserialize::<[u16; 4]>(&z_serialize(&arr)).is_err());
        assert!(z_deserialize::<[u16; 2]>(&z_serialize(&arr)).is_err());

        let boxed: Box<[u16]> = as_vec.clone().into_boxed_slice();
        assert_eq!(z_serialize(&boxed), z_serialize(&as_vec));
        assert_eq!(
            z_deserialize::<Box<[u16]>>(&z_serialize(&boxed)).unwrap(),
            boxed
        );

        let borrowed: Cow<'_, [u16]> = Cow::Borrowed(&as_vec);
        let owned: Cow<'_, [u16]> = Cow::Owned(as_vec.clone());
        assert_eq!(z_serialize(&borrowed), z_serialize(&as_vec));
        assert_eq!(z_serialize(&owned), z_serialize(&as_vec));

        let cow_str: Cow<'_, str> = Cow::Borrowed("test");
        assert_eq!(z_serialize(&cow_str), vec![4, 116, 101, 115, 116]);
        assert_eq!(z_serialize(&cow_str), z_serialize(&"test".to_string()));
    }

    /// R2362 — the hash containers. wz's are `hashbrown`'s (this crate is
    /// `no_std` and already carries the dependency), and their wire form
    /// is the same `VarInt` count plus entries every collection uses, so a
    /// `HashMap` and the `BTreeMap` holding the same single entry emit the
    /// same bytes.
    #[test]
    fn hash_containers_share_the_collection_framing() {
        let mut hset: HashSet<u16> = HashSet::new();
        hset.insert(7);
        let bset: BTreeSet<u16> = [7u16].into_iter().collect();
        assert_eq!(z_serialize(&hset), z_serialize(&bset));
        assert_eq!(
            z_deserialize::<HashSet<u16>>(&z_serialize(&hset)).unwrap(),
            hset
        );

        let mut hmap: HashMap<u16, String> = HashMap::new();
        hmap.insert(1, "one".to_string());
        let mut bmap: BTreeMap<u16, String> = BTreeMap::new();
        bmap.insert(1, "one".to_string());
        assert_eq!(z_serialize(&hmap), z_serialize(&bmap));
        assert_eq!(
            z_deserialize::<HashMap<u16, String>>(&z_serialize(&hmap)).unwrap(),
            hmap
        );

        // Multi-entry: iteration order is the hasher's, so the assertion
        // is the round trip rather than the bytes.
        let many: HashMap<u32, u32> = (0u32..8).map(|k| (k, k * 3)).collect();
        assert_eq!(
            z_deserialize::<HashMap<u32, u32>>(&z_serialize(&many)).unwrap(),
            many
        );
    }

    /// R2362 — the streaming read half. `deserialize_iter` reads what
    /// `serialize_iter` wrote, and dropping it early DRAINS the rest of
    /// the run so the value after the sequence still parses.
    #[test]
    fn deserialize_iter_streams_and_drains_on_drop() {
        let mut s = ZSerializer::new();
        s.serialize_iter([10u16, 20, 30]);
        s.serialize(0xabcdu16);
        let bytes = s.finish();

        let mut d = ZDeserializer::new(&bytes);
        let it = d.deserialize_iter::<u16>().unwrap();
        assert_eq!(it.len(), 3);
        let read: Result<Vec<u16>, _> = it.collect();
        assert_eq!(read.unwrap(), vec![10, 20, 30]);
        assert_eq!(d.deserialize::<u16>().unwrap(), 0xabcd);
        assert!(d.done());

        // Early drop: take one element, drop the iterator, and the tail
        // value must still be where it was.
        let mut d = ZDeserializer::new(&bytes);
        {
            let mut it = d.deserialize_iter::<u16>().unwrap();
            assert_eq!(it.next().unwrap().unwrap(), 10);
        }
        assert_eq!(d.deserialize::<u16>().unwrap(), 0xabcd);
        assert!(d.done());
    }

    /// R2362 — the bulk hooks are WIRED, not merely declared. The proof
    /// is a type whose overrides emit and consume a different shape than
    /// `len` calls to the single-value methods: if `serialize_slice` /
    /// `deserialize_slice` went back to a plain loop, the run would carry
    /// the single-value bytes and this reds.
    #[test]
    fn sequence_bodies_go_through_the_bulk_hooks() {
        #[derive(Debug, PartialEq, Eq)]
        struct Marked(u8);

        impl Serialize for Marked {
            fn serialize(&self, serializer: &mut ZSerializer) {
                // Single-value form: the byte, tagged 0xA0.
                0xa0u8.serialize(serializer);
                self.0.serialize(serializer);
            }
            fn serialize_n(slice: &[Self], serializer: &mut ZSerializer) {
                // Bulk form: one 0xB0 marker, then the bare bytes.
                0xb0u8.serialize(serializer);
                for m in slice {
                    m.0.serialize(serializer);
                }
            }
        }
        impl Deserialize for Marked {
            fn deserialize(
                deserializer: &mut ZDeserializer<'_>,
            ) -> Result<Self, ZDeserializeError> {
                if u8::deserialize(deserializer)? != 0xa0 {
                    return Err(ZDeserializeError);
                }
                Ok(Marked(u8::deserialize(deserializer)?))
            }
            fn deserialize_n(
                len: usize,
                deserializer: &mut ZDeserializer<'_>,
            ) -> Result<Vec<Self>, ZDeserializeError> {
                if u8::deserialize(deserializer)? != 0xb0 {
                    return Err(ZDeserializeError);
                }
                let mut out = Vec::new();
                for _ in 0..len {
                    out.push(Marked(u8::deserialize(deserializer)?));
                }
                Ok(out)
            }
        }

        let v = vec![Marked(1), Marked(2)];
        // VarInt(2), the BULK marker, then the two bare bytes. A plain
        // per-element loop would have written 0xa0 twice instead.
        assert_eq!(z_serialize(&v), vec![2, 0xb0, 1, 2]);
        assert_eq!(z_deserialize::<Vec<Marked>>(&z_serialize(&v)).unwrap(), v);
        // The single-value path is still reachable and still tagged 0xA0.
        assert_eq!(z_serialize(&Marked(9)), vec![0xa0, 9]);
    }

    /// R2362 — the numeric bulk read is bounds-checked over the WHOLE run
    /// before it allocates, so a length prefix that overruns the buffer
    /// fails without a large reservation.
    #[test]
    fn numeric_bulk_read_rejects_an_overrunning_length() {
        // VarInt(0xffff_ffff) then two bytes: the span check fails first.
        let mut bytes = alloc::vec::Vec::new();
        write_leb128(&mut bytes, 0xffff_ffff);
        bytes.extend_from_slice(&[1, 2]);
        assert!(z_deserialize::<Vec<u64>>(&bytes).is_err());
        // The honest form still round-trips through the same path.
        let v: Vec<u64> = vec![1, 2, u64::MAX];
        assert_eq!(z_deserialize::<Vec<u64>>(&z_serialize(&v)).unwrap(), v);
    }

    /// R2362 — wz has no `ZBytes`, and that is a CONTAINER rename rather
    /// than a missing format. Upstream's `impl Serialize for ZBytes`
    /// writes `VarInt(len)` then the raw bytes; wz's payload container is
    /// `Vec<u8>` and its impl writes exactly that.
    #[test]
    fn zbytes_container_shape_is_the_vec_u8_impl() {
        let payload: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef];
        let mut expected = alloc::vec::Vec::new();
        write_leb128(&mut expected, payload.len() as u64);
        expected.extend_from_slice(&payload);
        assert_eq!(z_serialize(&payload), expected);
        assert_eq!(
            z_deserialize::<Vec<u8>>(&z_serialize(&payload)).unwrap(),
            payload
        );
    }

    #[test]
    fn rejects_trailing_bytes_truncation_and_bad_bool() {
        // Trailing byte after a u32 (the !done() reject).
        assert!(z_deserialize::<u32>(&[1, 0, 0, 0, 99]).is_err());
        // Truncated u32 (only 3 bytes).
        assert!(z_deserialize::<u32>(&[1, 0, 0]).is_err());
        // bool byte must be 0 or 1.
        assert!(z_deserialize::<bool>(&[2]).is_err());
        // A length prefix that overruns the buffer.
        assert!(z_deserialize::<Vec<u8>>(&[5, 1, 2]).is_err());
    }
}

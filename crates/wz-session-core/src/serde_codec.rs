// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! - **The `VarInt` length prefix reuses the [`crate::vle`] SSOT**
//!   (`sce_forge_runtime` base-128 VLE), NOT a second `leb128`
//!   dependency. zenoh-ext's `VarInt` uses the `leb128` crate
//!   (serialization.rs:551-561, standard LEB128, up to 10 bytes for a
//!   `u64`); wz's VLE caps a `u64` at 9 bytes. The two encodings are
//!   byte-identical for every value `< 2^63`, and a Rust collection
//!   length is bounded by `isize::MAX = 2^63 - 1`, so EVERY reachable
//!   length prefix encodes identically — the divergence point is
//!   physically unreachable. One varint SSOT, zero drift.
//! - **`HashMap` / `HashSet` are NOT supported.** They are std-only
//!   (no_std has no `std::collections::Hash*`) and their iteration
//!   order is non-deterministic, so their serialization is not
//!   byte-stable. `BTreeMap` / `BTreeSet` are the deterministic
//!   superset wz offers instead.
//! - The `Cow`, `Box<[T]>`, `[T; N]`, and streaming-iterator
//!   (`ZReadIter` / `deserialize_iter`) conveniences are omitted; the
//!   scalar / `Vec` / `String` / tuple / `BTree*` surface above covers
//!   the codec's consumers. They are re-addable without a wire change.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};

use crate::vle::{encode_vle_u64_into, read_vle_u64};

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

/// A type that can be serialized into the Zenoh Serialization Format.
pub trait Serialize {
    /// Append the serialized form of `self` to `serializer`.
    fn serialize(&self, serializer: &mut ZSerializer);
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

    /// Read one base-128 VLE `u64` (the `VarInt` length-prefix reader),
    /// advancing the cursor by the consumed byte count.
    fn read_vle(&mut self) -> Result<u64, ZDeserializeError> {
        let (value, consumed) = read_vle_u64(&self.bytes[self.pos..]).ok_or(ZDeserializeError)?;
        self.pos += consumed;
        Ok(value)
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
        encode_vle_u64_into(&mut serializer.0, self.0 as u64);
    }
}

impl Deserialize for VarInt<usize> {
    fn deserialize(deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError> {
        let n = deserializer.read_vle()?;
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
    for t in slice {
        t.serialize(serializer);
    }
}

impl<T: Serialize> Serialize for [T] {
    fn serialize(&self, serializer: &mut ZSerializer) {
        serialize_slice(self, serializer);
    }
}
impl<T: Serialize> Serialize for Vec<T> {
    fn serialize(&self, serializer: &mut ZSerializer) {
        serialize_slice(self, serializer);
    }
}
impl<T: Deserialize> Deserialize for Vec<T> {
    fn deserialize(deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError> {
        let len = VarInt::<usize>::deserialize(deserializer)?.0;
        // Push in a loop (no pre-`with_capacity(len)`) so a malformed
        // length cannot drive an unbounded allocation before the
        // truncation check fails; the emitted bytes are unaffected.
        let mut out = Vec::new();
        for _ in 0..len {
            out.push(T::deserialize(deserializer)?);
        }
        Ok(out)
    }
}

impl Serialize for str {
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

impl<T: Serialize + Ord> Serialize for BTreeSet<T> {
    fn serialize(&self, serializer: &mut ZSerializer) {
        serializer.serialize_iter(self);
    }
}
impl<T: Deserialize + Ord> Deserialize for BTreeSet<T> {
    fn deserialize(deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError> {
        let len = VarInt::<usize>::deserialize(deserializer)?.0;
        let mut set = BTreeSet::new();
        for _ in 0..len {
            set.insert(T::deserialize(deserializer)?);
        }
        Ok(set)
    }
}
impl<K: Serialize + Ord, V: Serialize> Serialize for BTreeMap<K, V> {
    fn serialize(&self, serializer: &mut ZSerializer) {
        serializer.serialize_iter(self);
    }
}
impl<K: Deserialize + Ord, V: Deserialize> Deserialize for BTreeMap<K, V> {
    fn deserialize(deserializer: &mut ZDeserializer<'_>) -> Result<Self, ZDeserializeError> {
        let len = VarInt::<usize>::deserialize(deserializer)?.0;
        let mut map = BTreeMap::new();
        for _ in 0..len {
            let k = K::deserialize(deserializer)?;
            let v = V::deserialize(deserializer)?;
            map.insert(k, v);
        }
        Ok(map)
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
impl_tuple!(T0 0);
impl_tuple!(T0 0, T1 1);
impl_tuple!(T0 0, T1 1, T2 2);
impl_tuple!(T0 0, T1 1, T2 2, T3 3);
impl_tuple!(T0 0, T1 1, T2 2, T3 3, T4 4);
impl_tuple!(T0 0, T1 1, T2 2, T3 3, T4 4, T5 5);
impl_tuple!(T0 0, T1 1, T2 2, T3 3, T4 4, T5 5, T6 6);
impl_tuple!(T0 0, T1 1, T2 2, T3 3, T4 4, T5 5, T6 6, T7 7);

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

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The zid a session stands on, as a value that is a zid by construction.
//!
//! The INIT `cbyte` carries a zid's length as `len - 1` in four bits, so a
//! session's own zid is one to sixteen bytes. Upstream holds the same bound in
//! its type: `ZenohIdProto` is at most sixteen bytes
//! (`commons/zenoh-protocol/src/core/mod.rs` @ `pub const MAX_SIZE: usize = 16;`)
//! and its conversions from bytes refuse anything longer, and zero: the id is a
//! non-zero `u128`, so a decoder reading one from the wire refuses bytes that
//! spell zero (`commons/zenoh-codec/src/core/zenohid.rs` @
//! `ZenohIdProto::try_from(&id[..size]).map_err(|_| DidntRead)`). A
//! [`SessionZid`] is refused once, where it is made, so the session and
//! everything that names an entity by a zid read a value that cannot be out of
//! range or name no node.
//!
//! No allocation and no feature gate: the fixed-memory profile keeps the same
//! sixteen bytes and length in the session's own storage.

/// The longest zid on the wire, in bytes.
pub const ZID_MAX: usize = 16;

/// A zid: one to [`ZID_MAX`] bytes, not all zero, as the handshake sends it.
///
/// It reads as the byte slice it holds (`Deref<Target = [u8]>`), so a caller
/// that passes a zid on as `&[u8]` needs no conversion. The bytes past the
/// length are always zero, which is what makes the derived equality and hash
/// the equality and hash of the zids.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionZid {
    bytes: [u8; ZID_MAX],
    len: u8,
}

/// Why bytes are not a [`SessionZid`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZidError {
    /// A length outside `1..=16`.
    LengthOutOfRange {
        /// The length that was offered.
        len: usize,
    },
    /// Every byte is zero, which is the id `0`, and no node is.
    AllZero {
        /// The length that was offered.
        len: usize,
    },
}

impl core::fmt::Display for ZidError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LengthOutOfRange { len } => write!(
                f,
                "a zid is 1 to {ZID_MAX} bytes on the wire, and this one is {len}"
            ),
            Self::AllZero { len } => {
                write!(f, "a zid is not zero, and these {len} bytes are all zero")
            }
        }
    }
}

impl SessionZid {
    /// The zid `src` spells, or the refusal when it is not one to [`ZID_MAX`]
    /// bytes long or its bytes are all zero.
    pub const fn new(src: &[u8]) -> Result<Self, ZidError> {
        if src.is_empty() || src.len() > ZID_MAX {
            return Err(ZidError::LengthOutOfRange { len: src.len() });
        }
        let mut nonzero = false;
        let mut at = 0;
        while at < src.len() {
            if src[at] != 0 {
                nonzero = true;
            }
            at += 1;
        }
        if !nonzero {
            return Err(ZidError::AllZero { len: src.len() });
        }
        let mut bytes = [0u8; ZID_MAX];
        let mut i = 0;
        while i < src.len() {
            bytes[i] = src[i];
            i += 1;
        }
        Ok(Self {
            bytes,
            len: src.len() as u8,
        })
    }

    /// The zid of an array whose length is checked when the build is made: an
    /// array of no bytes or of more than [`ZID_MAX`] does not compile. Panics
    /// when the bytes are all zero, which a caller writing the array chose.
    pub const fn from_array<const N: usize>(src: [u8; N]) -> Self {
        const {
            assert!(N != 0 && N <= ZID_MAX, "a zid is 1 to 16 bytes on the wire");
        }
        match Self::new(&src) {
            Ok(zid) => zid,
            Err(_) => panic!("a zid is not zero"),
        }
    }

    /// The zid zero-padded to [`ZID_MAX`] bytes: the form a C ABI's `z_id_t` holds.
    pub const fn to_padded(&self) -> [u8; ZID_MAX] {
        self.bytes
    }

    /// The bytes the handshake sends.
    pub const fn as_slice(&self) -> &[u8] {
        self.bytes.split_at(self.len as usize).0
    }
}

impl core::ops::Deref for SessionZid {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for SessionZid {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl core::fmt::Debug for SessionZid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SessionZid").field(&self.as_slice()).finish()
    }
}

impl TryFrom<&[u8]> for SessionZid {
    type Error = ZidError;

    fn try_from(src: &[u8]) -> Result<Self, ZidError> {
        Self::new(src)
    }
}

impl<const N: usize> From<[u8; N]> for SessionZid {
    fn from(src: [u8; N]) -> Self {
        Self::from_array(src)
    }
}

impl PartialEq<[u8]> for SessionZid {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl PartialEq<&[u8]> for SessionZid {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_slice() == *other
    }
}

impl<const N: usize> PartialEq<[u8; N]> for SessionZid {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.as_slice() == other.as_slice()
    }
}

#[cfg(feature = "alloc")]
impl PartialEq<alloc::vec::Vec<u8>> for SessionZid {
    fn eq(&self, other: &alloc::vec::Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionZid, ZidError, ZID_MAX};

    #[test]
    fn one_to_sixteen_bytes_are_a_zid_and_zero_or_seventeen_are_refused() {
        assert_eq!(
            SessionZid::new(&[]),
            Err(ZidError::LengthOutOfRange { len: 0 })
        );
        assert_eq!(
            SessionZid::new(&[0x11; ZID_MAX + 1]),
            Err(ZidError::LengthOutOfRange { len: 17 })
        );
        let one = SessionZid::new(&[0xa1]).expect("one byte is a zid");
        assert_eq!(one.as_slice(), &[0xa1]);
        let sixteen = SessionZid::new(&[0xb2; ZID_MAX]).expect("sixteen bytes are a zid");
        assert_eq!(sixteen.as_slice(), &[0xb2; ZID_MAX]);
    }

    #[test]
    fn a_zid_reads_as_exactly_the_bytes_it_was_made_from() {
        let zid = SessionZid::from([0x01, 0x02, 0x03, 0x04]);
        assert_eq!(zid.len(), 4);
        assert_eq!(&zid[..], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(zid, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(SessionZid::try_from(&[0x01, 0x02, 0x03, 0x04][..]), Ok(zid));
        let mut padded = [0u8; ZID_MAX];
        padded[..4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(zid.to_padded(), padded);
        // The unused tail never takes part: a shorter prefix of the same bytes is another zid.
        assert_ne!(zid, SessionZid::from([0x01, 0x02, 0x03]));
        assert_ne!(zid, SessionZid::from([0x01, 0x02, 0x03, 0x04, 0x00]));
    }

    /// Zero is no node's id, at any length, and one non-zero byte anywhere makes the bytes a
    /// zid: the trailing zeros of a zid are part of how it is written, not a refusal.
    #[test]
    fn bytes_that_are_all_zero_are_refused_and_one_non_zero_byte_is_a_zid() {
        assert_eq!(SessionZid::new(&[0]), Err(ZidError::AllZero { len: 1 }));
        assert_eq!(
            SessionZid::new(&[0; ZID_MAX]),
            Err(ZidError::AllZero { len: 16 })
        );
        assert!(SessionZid::new(&[0, 0, 0, 0x01]).is_ok());
        assert!(SessionZid::new(&[0x01, 0, 0, 0]).is_ok());
    }

    #[test]
    fn the_refusal_names_the_length_it_refused() {
        let text = std::format!("{}", ZidError::LengthOutOfRange { len: 17 });
        assert!(text.contains("17"), "{text}");
        let text = std::format!("{}", ZidError::AllZero { len: 4 });
        assert!(text.contains("zero") && text.contains('4'), "{text}");
    }
}

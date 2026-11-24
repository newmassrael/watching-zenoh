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
//! [`crate::session_zid::SessionZid`] is refused once, where it is made, so the session and
//! everything that names an entity by a zid read a value that cannot be out of
//! range or name no node.
//!
//! No allocation and no feature gate: the fixed-memory profile keeps the same
//! sixteen bytes and length in the session's own storage.

use sce_forge_runtime::codec::{ArrayBytes, Bounded, Bytes};

/// The longest zid on the wire, in bytes.
pub const ZID_MAX: usize = 16;

/// A zid: one to [`ZID_MAX`] bytes, not all zero, as the handshake sends it.
///
/// It reads as the byte slice it holds (`Deref<Target = [u8]>`), so a caller
/// that passes a zid on as `&[u8]` needs no conversion, and it holds its bytes
/// within the bounds of the codec's zid field, so a message lends them
/// ([`Self::as_field`]) with no check. The bytes past the length are always
/// zero, which is what makes the derived equality and hash the equality and hash
/// of the zids.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionZid {
    bytes: Bounded<ArrayBytes<ZID_MAX>, ZID_MAX, 1>,
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
    pub fn new(src: &[u8]) -> Result<Self, ZidError> {
        let len = src.len();
        // The buffer holds as many bytes as the bound, so a length outside the
        // bounds is the one refusal the copy gives.
        let bytes: Bounded<ArrayBytes<ZID_MAX>, ZID_MAX, 1> =
            Bounded::from_slice(src).map_err(|_| ZidError::LengthOutOfRange { len })?;
        if src.iter().all(|&byte| byte == 0) {
            return Err(ZidError::AllZero { len });
        }
        Ok(Self { bytes })
    }

    /// The zid of an array whose length is checked when the build is made: an
    /// array of no bytes or of more than [`ZID_MAX`] does not compile, and nor
    /// does a constant of bytes all zero, which the assertion below stops when
    /// the build evaluates it.
    ///
    /// A `const fn` for the constants that name a zid; a zid read at run time is
    /// made by [`Self::new`].
    pub const fn from_array<const N: usize>(src: [u8; N]) -> Self {
        let mut nonzero = false;
        let mut rest = src.as_slice();
        while let [byte, tail @ ..] = rest {
            if *byte != 0 {
                nonzero = true;
            }
            rest = tail;
        }
        assert!(nonzero, "a zid is not zero");
        // The length is judged where the build evaluates this: one to `ZID_MAX`.
        Self {
            bytes: Bounded::proven_const(src),
        }
    }

    /// The zid zero-padded to [`ZID_MAX`] bytes: the form a C ABI's `z_id_t` holds.
    pub fn to_padded(&self) -> [u8; ZID_MAX] {
        let mut padded = [0u8; ZID_MAX];
        for (slot, byte) in padded.iter_mut().zip(self.as_slice()) {
            *slot = *byte;
        }
        padded
    }

    /// The bytes the handshake sends.
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.inner().as_slice()
    }

    /// The bytes as the codec's zid field holds them, one to [`ZID_MAX`].
    pub fn as_field(&self) -> Bytes<'_, ZID_MAX, 1> {
        self.bytes.as_bytes()
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

    /// The constant's zid and the run-time zid of the same bytes are one value.
    #[test]
    fn an_array_and_a_slice_of_the_same_bytes_make_the_same_zid() {
        const ONE: SessionZid = SessionZid::from_array([0x01]);
        const LAST_SET: SessionZid = SessionZid::from_array([0, 0, 0, 0x7f]);
        const FULL: SessionZid = SessionZid::from_array([0xc3; ZID_MAX]);
        assert_eq!(SessionZid::new(&[0x01]), Ok(ONE));
        assert_eq!(SessionZid::new(&[0, 0, 0, 0x7f]), Ok(LAST_SET));
        assert_eq!(SessionZid::new(&[0xc3; ZID_MAX]), Ok(FULL));
        assert_eq!(LAST_SET.as_slice(), &[0, 0, 0, 0x7f]);
    }

    /// The field a zid lends a message is its bytes, at every length it can have.
    #[test]
    fn the_field_a_zid_lends_is_its_bytes() {
        let zid = SessionZid::new(&[0x01, 0x02, 0x03]).expect("three bytes are a zid");
        assert_eq!(zid.as_field(), [0x01, 0x02, 0x03]);
        assert_eq!(SessionZid::from_array([0x7f]).as_field(), [0x7f]);
        assert_eq!(
            SessionZid::from_array([0xc3; ZID_MAX]).as_field(),
            [0xc3; ZID_MAX]
        );
    }

    #[test]
    fn the_refusal_names_the_length_it_refused() {
        let text = std::format!("{}", ZidError::LengthOutOfRange { len: 17 });
        assert!(text.contains("17"), "{text}");
        let text = std::format!("{}", ZidError::AllZero { len: 4 });
        assert!(text.contains("zero") && text.contains('4'), "{text}");
    }
}

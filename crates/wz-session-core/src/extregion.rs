// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the `0x8` REGION-NAME establishment extension — a node's region
//! identity, announced on Init and read off the peer's.
//!
//! ## The extension, read at the pin
//!
//! `zenoh` @ `commons/zenoh-protocol/src/transport/init.rs`
//! @ `pub type RegionName = zextzbuf!(0x8, false)` — id `0x8`, ZBUF encoding,
//! NOT mandatory. It rides BOTH `InitSyn` and `InitAck`
//! (`init.rs` @ `pub ext_region_name: Option<ext::RegionName>`, once per
//! message struct), and the value is the region name's UTF-8 bytes
//! (`io/zenoh-transport/src/unicast/establishment/ext/region_name.rs`
//! @ `fn name_to_ext`).
//!
//! ## ⛔ zenoh is the ONLY reference here, and that is measured
//!
//! zenoh-pico does not have this extension at all — the vendored submodule's
//! `src/` and `include/` carry no region identity, and the only occurrences of
//! the word are prose about non-contiguous MEMORY regions. So there is no
//! reference split to weigh: this atom took `GENERIC` over pico's silence for
//! the Close reason byte (R311y823) and a LINK scope for the Close flag
//! (R2389) by exactly this discriminator, and the same one applies.
//!
//! ## What the value is allowed to be
//!
//! `zenoh` @ `commons/zenoh-protocol/src/core/region.rs` @ `fn validate`:
//! NON-EMPTY and at most [`MAX_REGION_NAME_LEN`] bytes. Upstream's two error
//! arms are `InvalidRegionNameError::{Empty, TooLong}`, mirrored by
//! [`RegionNameError`].
//!
//! ⚠⚠ AN EXTENSION THAT IS PRESENT BUT INVALID FAILS THE HANDSHAKE, and this
//! is the half a reader can get backwards. Upstream's receive arms are
//! `state.0.other_region_name = ext.map(ext_to_name).transpose()?` on BOTH
//! roles (`region_name.rs` @ `fn recv_init_ack`, @ `fn recv_init_syn`), and
//! `ext_to_name` runs `String::from_utf8` then `RegionName::try_from`, so a
//! non-UTF-8, empty or over-long value propagates an error out of the FSM
//! rather than being ignored. ABSENT is the only benign reading.
//!
//! ⚠ Do NOT take the empty-string rule from upstream's `RCodec for
//! StateAccept` in that same file, which reads `""` back as `None`. That codec
//! serialises the acceptor's state into the COOKIE, not onto the wire; its
//! empty string is a niche for `Option`, and reading it as the wire rule would
//! turn a value both roles reject into a silent `None`.
//!
//! ## Why its own module
//!
//! One module per establishment ext id, each owning its encode AND its
//! projector so the two spellings of one wire fact cannot drift — the lesson
//! [`crate::extpatch`] was built on after a literal `0x07 | 0x20` sat beside a
//! reader matching named constants, and a `grep` found a complete reader with
//! no emit.

use sce_forge_runtime::codec::{CodecError, SceString};
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_zbuf::ExtZbufOwned;

/// `init::ext::RegionName`'s id in the establishment (Init / Open) ext space.
pub const REGION_NAME_EXT_ID: u8 = crate::ext_header::establishment_ext_id::REGION_NAME;

/// The full header byte wz emits and matches on: id `0x8`, ZBUF encoding, M
/// clear. Non-mandatory is load-bearing in the same way it is for `0x7` — with
/// `M` set, a peer that does not know regions would have to REFUSE the
/// handshake instead of skipping the entry.
pub const REGION_NAME_EXT_HEADER: u8 = REGION_NAME_EXT_ID | crate::ext_header::EXT_ENC_ZBUF;

/// `RegionName::MAX_LEN` — the longest region name upstream will construct or
/// accept, in BYTES (`validate` measures `s.as_ref().len()`, not chars).
pub const MAX_REGION_NAME_LEN: usize = 32;

/// Why a byte string is not a region name — upstream's
/// `InvalidRegionNameError` arms, plus the UTF-8 arm its `ext_to_name` gets
/// from `String::from_utf8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionNameError {
    /// `InvalidRegionNameError::Empty`.
    Empty,
    /// `InvalidRegionNameError::TooLong` — over [`MAX_REGION_NAME_LEN`] bytes.
    TooLong,
    /// `String::from_utf8` failed. Upstream reaches this through `?` on the
    /// same line; it is an arm of the same refusal, not a wz addition.
    NotUtf8,
}

/// A validated region identity — non-empty, at most [`MAX_REGION_NAME_LEN`]
/// bytes.
///
/// Constructed only through [`RegionName::new`], so a value that exists has
/// already been through upstream's rule and no caller can stage an entry the
/// peer would refuse.
///
/// ⚠ The carrier is this crate's PROFILE-AWARE [`SceString`] and not a plain
/// `String`, because `wz-session-core` builds `no_std`. The first draft used
/// `alloc::string::String` and compiled fine at default features while
/// BREAKING `--no-default-features` outright — a whole-crate compile error that
/// the default lane is structurally unable to see. What caught it was the
/// guarded-count gate reporting "NO libtest summary … this gate measured
/// nothing" on three `--no-default-features` invocations, an INPUT ERROR
/// beside an overall rc of 0.
///
/// The capacity is [`MAX_REGION_NAME_LEN`] exactly, which upstream's own
/// ceiling makes safe: a name this type can hold is one `validate` admits.
/// ⚠ `Eq` is NOT derived: the no-alloc profile's `InlineStr` does not implement
/// it, and deriving it here would be a second way this type compiles at default
/// features and not at `--no-default-features`. `PartialEq` is all any caller
/// here needs.
#[derive(Debug, Clone, PartialEq)]
pub struct RegionName(SceString<MAX_REGION_NAME_LEN>);

impl RegionName {
    /// Upstream's `RegionName::validate`, in its order: empty first, then
    /// length. The order is not cosmetic — an empty name is `Empty` and never
    /// `TooLong`, which is what the two arms let a caller tell apart.
    pub fn new(s: &str) -> Result<Self, RegionNameError> {
        if s.is_empty() {
            return Err(RegionNameError::Empty);
        }
        if s.len() > MAX_REGION_NAME_LEN {
            return Err(RegionNameError::TooLong);
        }
        // The length rule above is upstream's and runs FIRST, so the carrier's
        // own capacity check below can only fire on a name this function has
        // already admitted — it cannot. Mapped to `TooLong` rather than
        // unwrapped so a future capacity change is a refusal and not a panic.
        crate::codec_owned::owned_string(s)
            .map(Self)
            .map_err(|_| RegionNameError::TooLong)
    }

    /// The name as upstream's `as_str` gives it.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// The ENTRY wz puts on an Init when this node has a region identity.
///
/// Built here rather than at the staging site, for the reason
/// [`crate::extpatch::encode_patch_ext_at`] is: the emit and [`peer_region`]
/// share ONE spelling of the header, so a move on either side cannot ship an
/// extension wz emits and wz ignores.
///
/// Infallible in its length: [`RegionName`] cannot exceed
/// [`MAX_REGION_NAME_LEN`], which is exactly the declared capacity of the
/// owned ZBuf carrier, so the profile-generic `owned_bytes` cannot reject a
/// name that got this far. The `Result` is the carrier's signature, not a
/// second length rule.
pub fn encode_region_name_ext(name: &RegionName) -> Result<ExtEntryOwned, CodecError> {
    let bytes = name.as_str().as_bytes();
    let value_len = bytes.len() as u64;
    let value = crate::codec_owned::owned_bytes(bytes)?;
    Ok(ExtEntryOwned {
        header: REGION_NAME_EXT_HEADER,
        body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned { value_len, value }),
    })
}

/// Project the PEER's announced region identity out of an INIT ext chain.
///
/// Three answers, and they are upstream's three:
///
/// * `Ok(None)` — no `0x8` ZBUF entry. The benign case, and the ONLY one.
/// * `Ok(Some(name))` — a valid name.
/// * `Err(_)` — the entry is there and its value is not a region name. This
///   must fail the handshake, because upstream's receive arms propagate it.
///
/// The match is on the extension IDENTITY ([`crate::ext_header::ext_eid`]),
/// not the 4-bit id: id `0x8` with another encoding is a different extension,
/// the R311y505 discipline this crate pays elsewhere.
pub fn peer_region(extensions: &[ExtEntryOwned]) -> Result<Option<RegionName>, RegionNameError> {
    let want = crate::ext_header::ext_eid(REGION_NAME_EXT_HEADER);
    for ext in extensions {
        if crate::ext_header::ext_eid(ext.header) != want {
            continue;
        }
        let ExtEntryOwnedVariant::CodecZenohExtZbuf(z) = &ext.body else {
            continue;
        };
        let s = core::str::from_utf8(z.value.as_slice()).map_err(|_| RegionNameError::NotUtf8)?;
        return RegionName::new(s).map(Some);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire form, pinned against the declaration read at the pin:
    /// `zextzbuf!(0x8, false)`.
    #[test]
    fn the_emitted_header_is_id_eight_zbuf_and_not_mandatory() {
        let name = RegionName::new("north").expect("a valid name");
        let entry = encode_region_name_ext(&name).expect("encodes");
        assert_eq!(crate::ext_header::ext_id(entry.header), 0x08);
        assert_eq!(
            entry.header & crate::ext_header::EXT_ENC_MASK,
            crate::ext_header::EXT_ENC_ZBUF,
        );
        assert!(
            !crate::ext_header::ext_mandatory(entry.header),
            "zextzbuf!(0x8, FALSE) -- with M set a peer that does not know \
             regions would have to refuse the handshake",
        );
    }

    /// wz's own emit projected back through wz's own reader — the
    /// [`crate::extpatch`] discipline that caught a reader with no emit.
    #[test]
    fn the_entry_wz_emits_is_the_entry_wz_reads() {
        let name = RegionName::new("south-1").expect("a valid name");
        let entry = encode_region_name_ext(&name).expect("encodes");
        assert_eq!(peer_region(&[entry]), Ok(Some(name)));
    }

    #[test]
    fn an_absent_extension_is_the_benign_none() {
        assert_eq!(peer_region(&[]), Ok(None));
        // A different establishment ext must not be read as a region.
        let patch = crate::extpatch::encode_patch_ext_at(1);
        assert_eq!(peer_region(&[patch]), Ok(None));
    }

    /// Upstream validates on RECEIPT, so each refusal is a handshake failure
    /// rather than an ignored entry.
    #[test]
    fn a_present_but_invalid_value_is_an_error_not_a_none() {
        let empty = ExtEntryOwned {
            header: REGION_NAME_EXT_HEADER,
            body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: 0,
                value: crate::codec_owned::owned_bytes(b"").expect("empty fits"),
            }),
        };
        assert_eq!(peer_region(&[empty]), Err(RegionNameError::Empty));

        let bad_utf8 = ExtEntryOwned {
            header: REGION_NAME_EXT_HEADER,
            body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: 2,
                value: crate::codec_owned::owned_bytes(&[0xff, 0xfe]).expect("fits"),
            }),
        };
        assert_eq!(peer_region(&[bad_utf8]), Err(RegionNameError::NotUtf8));
    }

    /// The boundary, from BOTH sides. A ceiling graded from one side cannot
    /// tell "at the limit" from "over" it.
    #[test]
    fn the_length_ceiling_is_graded_from_both_sides() {
        let at = "x".repeat(MAX_REGION_NAME_LEN);
        assert!(
            RegionName::new(&at).is_ok(),
            "{MAX_REGION_NAME_LEN} bytes is upstream's `len() > MAX_LEN`, so \
             the limit itself is ACCEPTED",
        );
        let over = "x".repeat(MAX_REGION_NAME_LEN + 1);
        assert_eq!(RegionName::new(&over), Err(RegionNameError::TooLong));
    }

    /// Upstream measures BYTES, not chars, and a multi-byte name is where the
    /// two answers differ.
    #[test]
    fn the_ceiling_counts_bytes_and_not_characters() {
        // 11 characters, 33 bytes: accepted by a char count, refused by
        // upstream's `len()`.
        let name = "가".repeat(11);
        assert_eq!(name.chars().count(), 11);
        assert_eq!(name.len(), 33);
        assert_eq!(RegionName::new(&name), Err(RegionNameError::TooLong));
    }

    #[test]
    fn empty_is_empty_and_never_too_long() {
        assert_eq!(RegionName::new(""), Err(RegionNameError::Empty));
    }
}

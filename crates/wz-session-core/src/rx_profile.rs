// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The receive-side storage profile: a decoded message whose byte fields are
//! ranges of the frame it was decoded from.
//!
//! # What this is for
//!
//! A received frame is an [`RxBytes`], and since R2971 it can be a range of the
//! storage the link read into (a recycled buffer, a slot of the node's receive
//! pool, a datagram quinn already refcounts) rather than a copy of it. The
//! decode that follows used to undo that: `try_into_owned` builds every byte
//! field of the owned message from a borrowed slice alone, so the payload was
//! copied out of the frame it sat in, and the sample a subscriber was handed was
//! copied again. SCE's origin seam (`generate --owned-origin`,
//! `OriginStorage`) is the missing place to say where a slice came from, and
//! this module is the profile that uses it: [`RxShared`] builds each byte field
//! as a second reference to the frame, so the payload of a received `Put` is
//! the frame's own bytes for as long as anything holds it.
//!
//! Upstream's receiver does the same thing and calls it a `ZSlice`: an `Arc` on
//! the storage plus a range (`commons/zenoh-buffers/src/zslice.rs` @
//! `pub struct ZSlice {`). [`RxBytes`] is that type here and [`RxSharedBytes`]
//! is the byte container of the owned message, one field wide.
//!
//! # What is shared and what is not
//!
//! Byte fields are shared. TEXT fields are not: a key expression suffix is a
//! few dozen bytes, a `String` here is the heap container the rest of the
//! workspace already uses for it, and sharing a range of a frame as a `str`
//! would add an unchecked-UTF-8 container for a saving nobody can measure. A
//! text field is copied, which is `HeapStr`'s own `from_view`.
//!
//! # What a slice that is not part of the frame does
//!
//! A borrowed view can be built by hand: a default field is the empty slice, a
//! test passes a literal, a builder encodes a message and decodes it back from a
//! buffer of its own. [`OriginStorage::bytes_from`] is told to decide, so this
//! profile COPIES such a slice. The alternative, refusing it, would turn a
//! message assembled outside a frame into a decode error for no reason the
//! sender could act on; copying is what every byte field cost before.
//!
//! # What this module does NOT do
//!
//! An owned value does not remember its origin, so moving a message between
//! profiles (`transcode_in`) still copies; decode straight into this profile.
//! And it is AP-only: `Arc` needs pointer-width atomics, which ARMv6-M does not
//! have, so the MCU profiles keep the owned form and this module does not exist
//! for them (`rx-shared-bytes`).

use alloc::vec::Vec;

use sce_forge_runtime::codec::{
    subrange_of, CodecError, CodecStorage, HeapStr, OriginStorage, SceByteBuf, SceStr,
};

use crate::link::RxBytes;

/// The storage profile whose byte fields are ranges of the frame they were
/// decoded from. Use it with `try_into_owned_in_origin::<RxShared>(&frame)`.
///
/// A zero-sized marker, as [`Heap`](sce_forge_runtime::codec::Heap) is: the
/// profile is a choice of types, and the data lives in the containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxShared;

/// A byte field of a message decoded into [`RxShared`]: a range of the frame,
/// or a copy when the bytes did not come from one.
///
/// `N` is the field's declared `sce:max-size`. It is advisory here exactly as it
/// is for the heap container: the on-wire protocol puts no ceiling on a
/// payload, and the type carries `N` only so a hand-assembled value infers the
/// capacity from the field it is assigned to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RxSharedBytes<const N: usize>(RxBytes);

impl<const N: usize> RxSharedBytes<N> {
    /// The field as a frame-sized handle: cloning it shares the storage, and
    /// handing it up to a subscriber is how a sample comes to hold the frame.
    pub fn as_rx_bytes(&self) -> &RxBytes {
        &self.0
    }

    /// The field as a frame-sized handle, by value.
    pub fn into_rx_bytes(self) -> RxBytes {
        self.0
    }

    /// Whether the field is a range of lent storage (sharing the frame) rather
    /// than owned bytes.
    pub fn is_shared(&self) -> bool {
        self.0.is_shared()
    }

    /// The field's bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<const N: usize> SceByteBuf for RxSharedBytes<N> {
    /// A copy: this is the constructor a field built WITHOUT a frame uses (a
    /// builder's payload, a default), and a slice with no origin has nothing to
    /// share.
    fn from_slice(b: &[u8]) -> Result<Self, CodecError> {
        Ok(Self(RxBytes::from(Vec::from(b))))
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<const N: usize> core::ops::Deref for RxSharedBytes<N> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<const N: usize> PartialEq<&[u8]> for RxSharedBytes<N> {
    fn eq(&self, other: &&[u8]) -> bool {
        self.0.as_slice() == *other
    }
}

impl<const N: usize, const M: usize> PartialEq<&[u8; M]> for RxSharedBytes<N> {
    fn eq(&self, other: &&[u8; M]) -> bool {
        self.0.as_slice() == other.as_slice()
    }
}

impl CodecStorage for RxShared {
    type List<T, const N: usize>
        = Vec<T>
    where
        T: core::fmt::Debug + Clone + PartialEq;
    type Str<const N: usize> = HeapStr<N>;
    type Bytes<const N: usize> = RxSharedBytes<N>;
}

impl OriginStorage for RxShared {
    type Origin = RxBytes;

    fn bytes_from<const N: usize>(
        origin: &RxBytes,
        view: &[u8],
    ) -> Result<RxSharedBytes<N>, CodecError> {
        // An empty view first. `subrange_of` compares addresses, and the empty
        // slice a default field holds has a dangling one that can happen to
        // equal a position in the frame; an empty field shares nothing worth
        // naming, and an owned empty vector is the honest answer.
        if view.is_empty() {
            return Ok(RxSharedBytes(RxBytes::from(Vec::new())));
        }
        match subrange_of(origin.as_slice(), view).and_then(|range| origin.subslice(range)) {
            Some(shared) => Ok(RxSharedBytes(shared)),
            // Not part of the frame (see the module doc): copy.
            None => <RxSharedBytes<N> as SceByteBuf>::from_slice(view),
        }
    }

    fn str_from<const N: usize>(_origin: &RxBytes, view: &str) -> Result<HeapStr<N>, CodecError> {
        <HeapStr<N> as SceStr>::from_view(view)
    }
}

#[cfg(all(test, feature = "codec-push"))]
mod tests {
    use super::*;
    use crate::put_payload::inline_bytes;
    use alloc::sync::Arc;
    use alloc::vec;
    use sce_forge_runtime::codec::{Heap, SceCursor};
    use wz_codecs::push::{Push, PushOwnedVariant};

    use crate::link::RxStorage;

    /// The wire of a literal Push carrying `payload`, laid in a larger storage
    /// at a non-zero offset so a range that were mistaken for the whole storage
    /// would show.
    fn framed(payload: &[u8]) -> (Arc<dyn RxStorage>, RxBytes, core::ops::Range<usize>) {
        let push = crate::push_build::build_push_literal("demo/rx", payload).expect("a push");
        let wire = push
            .try_as_borrowed()
            .expect("the push borrows")
            .encode_to_vec();
        let mut storage = vec![0xEEu8; 7];
        let start = storage.len();
        storage.extend_from_slice(&wire);
        let end = storage.len();
        storage.extend_from_slice(&[0xDD; 5]);
        let storage: Arc<dyn RxStorage> = Arc::new(storage);
        let frame = RxBytes::shared(storage.clone(), start..end).expect("the wire is in storage");
        (storage, frame, start..end)
    }

    fn payload_of<S: CodecStorage>(push: &wz_codecs::push::PushOwned<S>) -> &[u8] {
        match &push.body {
            PushOwnedVariant::CodecZenohMsgPut(put) => {
                inline_bytes(put).expect("an inline Put carries a payload")
            }
            other => panic!("expected a Put body, got {other:?}"),
        }
    }

    /// THE WITNESS. The payload of a Push decoded into [`RxShared`] is the frame's
    /// own bytes -- the same addresses, a reference on the same storage -- and
    /// the storage goes home only when the last of them drops.
    #[test]
    fn a_payload_decoded_in_origin_is_a_range_of_the_frame() {
        let payload = b"zero-copy payload, long enough to be unmistakable";
        let (storage, frame, range) = framed(payload);
        let base = Arc::strong_count(&storage);

        let borrowed =
            Push::decode(&mut SceCursor::new(frame.as_slice())).expect("the frame decodes");
        let owned = borrowed
            .try_into_owned_in_origin::<RxShared>(&frame)
            .expect("the projection succeeds");

        let got = payload_of(&owned);
        assert_eq!(got, payload, "the bytes are the payload");
        let frame_start = frame.as_slice().as_ptr() as usize;
        let at = got.as_ptr() as usize;
        assert!(
            at >= frame_start && at + got.len() <= frame_start + (range.end - range.start),
            "the payload lies INSIDE the frame's own bytes, not beside them"
        );
        assert_eq!(
            Arc::strong_count(&storage),
            base + 1,
            "the payload holds a second reference to the frame's storage"
        );

        drop(owned);
        assert_eq!(
            Arc::strong_count(&storage),
            base,
            "the reference goes home with the message"
        );
    }

    /// THE CONTROL, on the same bytes through the copying projection. The two
    /// agree on what the payload IS and disagree on where it LIVES, which is the
    /// whole of the difference; without this leg the witness above would pass for
    /// any profile that happened to keep an address near the frame.
    #[test]
    fn the_copying_projection_does_not_share_the_frame() {
        let payload = b"zero-copy payload, long enough to be unmistakable";
        let (storage, frame, range) = framed(payload);
        let base = Arc::strong_count(&storage);

        let borrowed =
            Push::decode(&mut SceCursor::new(frame.as_slice())).expect("the frame decodes");
        let owned = borrowed
            .try_into_owned_in::<Heap>()
            .expect("the copying projection succeeds");

        let got = payload_of(&owned);
        assert_eq!(got, payload);
        let frame_start = frame.as_slice().as_ptr() as usize;
        let at = got.as_ptr() as usize;
        assert!(
            at < frame_start || at >= frame_start + (range.end - range.start),
            "a copy lives outside the frame"
        );
        assert_eq!(Arc::strong_count(&storage), base, "and holds no reference");
    }

    /// A view that is not part of the origin is copied, not refused, and the
    /// result is the same bytes -- the case of a message assembled by hand.
    #[test]
    fn a_slice_that_is_not_part_of_the_frame_is_copied() {
        let (storage, frame, _) = framed(b"in the frame");
        let base = Arc::strong_count(&storage);

        let elsewhere = b"not in the frame at all";
        let field: RxSharedBytes<256> =
            RxShared::bytes_from(&frame, elsewhere).expect("a foreign view is accepted");

        assert_eq!(field.as_slice(), elsewhere);
        assert!(!field.is_shared(), "it is owned bytes, not a range");
        assert_eq!(Arc::strong_count(&storage), base, "and holds no reference");
    }

    /// An empty view is an owned empty field whatever its address, which can
    /// equal a position inside the frame.
    #[test]
    fn an_empty_view_shares_nothing() {
        let (storage, frame, _) = framed(b"x");
        let base = Arc::strong_count(&storage);
        let inside_the_frame = &frame.as_slice()[3..3];

        let field: RxSharedBytes<256> =
            RxShared::bytes_from(&frame, inside_the_frame).expect("empty is accepted");

        assert!(field.as_slice().is_empty());
        assert!(!field.is_shared());
        assert_eq!(Arc::strong_count(&storage), base);
    }

    /// An OWNED frame has no storage to share, so a payload decoded in it is a
    /// copy of the same bytes. That is the arm the MCU-shaped and test-built
    /// frames take, and it must stay correct rather than fast.
    #[test]
    fn an_owned_frame_yields_a_copy_with_the_same_bytes() {
        let payload = b"payload in an owned frame";
        let push = crate::push_build::build_push_literal("demo/own", payload).expect("a push");
        let wire = push.try_as_borrowed().expect("borrows").encode_to_vec();
        let frame = RxBytes::from(wire);

        let borrowed = Push::decode(&mut SceCursor::new(frame.as_slice())).expect("decodes");
        let owned = borrowed
            .try_into_owned_in_origin::<RxShared>(&frame)
            .expect("projects");

        assert_eq!(payload_of(&owned), payload);
        match &owned.body {
            PushOwnedVariant::CodecZenohMsgPut(put) => {
                let field = put.payload.as_ref().expect("an inline payload");
                assert!(!field.is_shared(), "an owned frame has nothing to share");
            }
            other => panic!("expected a Put body, got {other:?}"),
        }
    }

    /// `subslice` is relative to the bytes it is called on, not to the storage
    /// behind them, and refuses a range outside them.
    #[test]
    fn a_subslice_is_relative_to_its_own_bytes() {
        let storage: Arc<dyn RxStorage> = Arc::new(vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let frame = RxBytes::shared(storage.clone(), 2..9).expect("inside");
        assert_eq!(frame.as_slice(), &[2, 3, 4, 5, 6, 7, 8]);

        let inner = frame.subslice(1..4).expect("inside the frame");
        assert_eq!(
            inner.as_slice(),
            &[3, 4, 5],
            "1..4 of THE FRAME, not of the storage"
        );
        assert!(inner.is_shared());

        assert!(frame.subslice(0..8).is_none(), "past the end of the frame");
        // Built from variables: a literal `3..2` is a lint error, and a reversed
        // range arriving from a computation is exactly the input this guards.
        let (from, to) = (3usize, 2usize);
        assert!(frame.subslice(from..to).is_none(), "reversed");
        assert_eq!(
            frame.subslice(7..7).expect("empty at the end").as_slice(),
            &[] as &[u8]
        );
    }
}

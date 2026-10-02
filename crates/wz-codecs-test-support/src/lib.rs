// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `TestWire` — the SSOT projection from a decoded `*Owned` codec
//! mirror back to its wire bytes, shared by the wz-session-core and
//! wz-runtime-tokio byte-compare regression tests.
//!
//! The wz builders and registries hold the lifetime-free `*Owned`
//! mirrors that the SCE borrowed-view absorb introduced; encoding lives
//! on the zero-copy borrowed view, so a test obtains wire bytes via
//! `owned.try_as_borrowed().encode_to_vec()`. `.wire()` centralises
//! that chain so the byte-compare tests read `built.wire()` uniformly.
//!
//! R311fu — this trait was duplicated as a local `trait TestWire` (plus
//! a macro) in three places to satisfy coherence: the projected types
//! are wz-codecs types, so a consumer cannot `impl` a foreign trait for
//! them (orphan rule). Pairing the trait with its impls in a sibling
//! crate at the wz-codecs tier is the coherent SSOT; see this crate's
//! `Cargo.toml` header for why it is a third sibling rather than a fold
//! into `wz-session-core-test-support`. Consumed exclusively from
//! `#[cfg(test)]` modules via a dev-dep path edge, so production builds
//! of either crate carry zero of this code regardless of workspace-level
//! Cargo feature unification (recorded in this project's own notes as the sibling-crate fixture rule).
//!
//! The `.expect()` is sound by construction: wz builders emit far fewer
//! extensions than the heapless ext cap `N`, so `try_as_borrowed` never
//! returns the capacity-exceeded error in test fixtures.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// Projects a decoded `*Owned` codec mirror to its wire bytes through
/// the borrowed encode view. Implemented for each owned message mirror
/// behind the `codec-*` feature that defines it.
pub trait TestWire {
    /// The wire bytes the owned mirror encodes to.
    fn wire(&self) -> Vec<u8>;
}

#[cfg(any(
    feature = "codec-push",
    feature = "codec-declare",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final"
))]
macro_rules! impl_test_wire_owned {
    ($($owned:ident)::+) => {
        // Generic over the storage profile: a message a receive path hands up
        // is not on the default profile, and a projection that named one
        // profile would give a test no `.wire()` on the other.
        impl<S: wz_codecs::CodecStorage> TestWire for $($owned)::+<S> {
            fn wire(&self) -> Vec<u8> {
                self.try_as_borrowed()
                    .expect("test: <=N exts by construction")
                    .encode_to_vec()
            }
        }
    };
}

#[cfg(feature = "codec-push")]
impl_test_wire_owned!(wz_codecs::push::PushOwned);
#[cfg(feature = "codec-declare")]
impl_test_wire_owned!(wz_codecs::declare::DeclareOwned);
#[cfg(feature = "codec-declare")]
impl_test_wire_owned!(wz_codecs::interest::InterestOwned);
#[cfg(feature = "codec-request")]
impl_test_wire_owned!(wz_codecs::request::RequestOwned);
#[cfg(feature = "codec-response")]
impl_test_wire_owned!(wz_codecs::response::ResponseOwned);
#[cfg(feature = "codec-response-final")]
impl_test_wire_owned!(wz_codecs::response_final::ResponseFinalOwned);

/// `push` with its Put body carrying an EMPTY inline payload.
///
/// A bare `Push::default()` is not an encodable message: the Put's payload is
/// gated on the extension chain (`msg_put.scxml`), so a default Put names neither
/// layout and the encoder refuses it (`PresentIfMismatch`). A test that wants "a
/// Push, any Push" on the wire says which layout it means through this, once,
/// instead of each one setting the two fields by hand. A Del or unknown body is
/// returned untouched.
#[cfg(feature = "codec-push")]
pub fn with_empty_inline_put(mut push: wz_codecs::push::Push<'_>) -> wz_codecs::push::Push<'_> {
    if let wz_codecs::push::PushVariant::CodecZenohMsgPut(put) = &mut push.body {
        put.payload_len = Some(0);
        put.payload = Some(&[]);
    }
    push
}

/// `response` with the Put inside its Reply carrying an EMPTY inline payload; the
/// `Response` twin of [`with_empty_inline_put`], for the same reason. An Err
/// body, a Del reply or an unknown body is returned untouched.
#[cfg(feature = "codec-response")]
pub fn with_empty_inline_put_reply(
    mut response: wz_codecs::response::Response<'_>,
) -> wz_codecs::response::Response<'_> {
    if let wz_codecs::response::ResponseVariant::CodecZenohReply(reply) = &mut response.body {
        if let wz_codecs::reply::ReplyVariant::CodecZenohMsgPut(put) = &mut reply.body {
            put.payload_len = Some(0);
            put.payload = Some(&[]);
        }
    }
    response
}

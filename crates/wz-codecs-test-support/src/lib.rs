// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `TestWire` — the SSOT projection from a decoded `*Owned` codec
//! mirror back to its wire bytes, shared by the wz-session-core and
//! wz-runtime-tokio byte-compare regression tests.
//!
//! The wz builders and registries hold the lifetime-free `*Owned`
//! mirrors that the SCE borrowed-view absorb introduced; an owned value
//! encodes itself at any storage profile, so a test obtains wire bytes via
//! `owned.encode_to_vec()`. `.wire()` centralises that call so the
//! byte-compare tests read `built.wire()` uniformly.
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

/// What a codec's `encode_to_vec` gives: the bytes of a codec that cannot refuse a value, and a
/// `Result` of them for one that can. A fixture's message is encodable either way.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-declare",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final"
))]
trait Encoded {
    fn encoded(self) -> Vec<u8>;
}

#[cfg(any(
    feature = "codec-push",
    feature = "codec-declare",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final"
))]
impl Encoded for Vec<u8> {
    fn encoded(self) -> Vec<u8> {
        self
    }
}

#[cfg(any(
    feature = "codec-push",
    feature = "codec-declare",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final"
))]
impl<E: core::fmt::Debug> Encoded for Result<Vec<u8>, E> {
    fn encoded(self) -> Vec<u8> {
        self.expect("test: a message a fixture builds is encodable")
    }
}

#[cfg(any(
    feature = "codec-push",
    feature = "codec-declare",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final"
))]
macro_rules! impl_test_wire_owned {
    ($($owned:ident)::+ ; $($storage:ident)::+) => {
        // Generic over the storage profile: a message a receive path hands up
        // is not on the default profile, and an impl that named one profile
        // would give a test no `.wire()` on the other.
        impl<S: $($storage)::+> TestWire for $($owned)::+<S> {
            fn wire(&self) -> Vec<u8> {
                self.encode_to_vec().encoded()
            }
        }
    };
}

#[cfg(feature = "codec-push")]
impl_test_wire_owned!(wz_codecs::push::PushOwned; wz_codecs::push::PushStorage);
#[cfg(feature = "codec-declare")]
impl_test_wire_owned!(wz_codecs::declare::DeclareOwned; wz_codecs::declare::DeclareStorage);
#[cfg(feature = "codec-declare")]
impl_test_wire_owned!(wz_codecs::interest::InterestOwned; wz_codecs::interest::InterestStorage);
#[cfg(feature = "codec-request")]
impl_test_wire_owned!(wz_codecs::request::RequestOwned; wz_codecs::request::RequestStorage);
#[cfg(feature = "codec-response")]
impl_test_wire_owned!(wz_codecs::response::ResponseOwned; wz_codecs::response::ResponseStorage);
#[cfg(feature = "codec-response-final")]
impl_test_wire_owned!(
    wz_codecs::response_final::ResponseFinalOwned;
    wz_codecs::response_final::ResponseFinalStorage
);

/// `put` set to the inline layout with an EMPTY payload, keeping its extension
/// chain. A Put whose chain carries the shared-memory marker holds the sliced
/// layout instead, which has no inline payload to empty, and is left as it is.
#[cfg(any(feature = "codec-push", feature = "codec-response"))]
fn empty_inline_payload(put: &mut wz_codecs::msg_put::MsgPut<'_>) {
    if let wz_codecs::msg_put::MsgPutExtensionsHas0x12::NotHas0x12 { payload, .. } =
        &mut put.extensions_has_0x12
    {
        *payload = Default::default();
        put.payload_len = Some(0);
    }
}

/// `push` with its Put body carrying an EMPTY inline payload.
///
/// The Put's payload layout is chosen by its extension chain (`msg_put.scxml`).
/// A test that wants "a Push, any Push" on the wire says which layout it means
/// through this, once, instead of each one setting the fields by hand. A Del or
/// unknown body is returned untouched.
#[cfg(feature = "codec-push")]
pub fn with_empty_inline_put(mut push: wz_codecs::push::Push<'_>) -> wz_codecs::push::Push<'_> {
    if let wz_codecs::push::PushVariant::CodecZenohMsgPut(put) = &mut push.body {
        empty_inline_payload(put);
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
            empty_inline_payload(put);
        }
    }
    response
}

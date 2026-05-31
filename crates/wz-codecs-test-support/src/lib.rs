// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! Cargo feature unification ([[feedback_test_fixtures_sibling_crate]]).
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
    ($($owned:ty),+ $(,)?) => {
        $(impl TestWire for $owned {
            fn wire(&self) -> Vec<u8> {
                self.try_as_borrowed()
                    .expect("test: <=N exts by construction")
                    .encode_to_vec()
            }
        })+
    };
}

#[cfg(feature = "codec-push")]
impl_test_wire_owned!(wz_codecs::push::PushOwned);
#[cfg(feature = "codec-declare")]
impl_test_wire_owned!(
    wz_codecs::declare::DeclareOwned,
    wz_codecs::interest::InterestOwned
);
#[cfg(feature = "codec-request")]
impl_test_wire_owned!(wz_codecs::request::RequestOwned);
#[cfg(feature = "codec-response")]
impl_test_wire_owned!(wz_codecs::response::ResponseOwned);
#[cfg(feature = "codec-response-final")]
impl_test_wire_owned!(wz_codecs::response_final::ResponseFinalOwned);

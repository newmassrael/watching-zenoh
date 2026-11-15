// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz-tls-mbedtls` -- the secure channel of the fixed-memory profile (decision D9 of
//! `docs/session-lifecycle-intent.md`) over Mbed TLS on its PSA Crypto line.
//!
//! TLS 1.3 with two ways to answer "who is the peer". Pinned: each end presents a certificate
//! self-signed over a P-256 key it generated in the PSA key store, proves the key in the
//! handshake, and is accepted by the zid that key names (decision D1), never by a certificate
//! authority. Chain: the end's certificate chain verifies against roots the program gives
//! ([`channel::Trust`]), as a zenoh router's or a zenoh-pico `tls/` link's does, with the name
//! checked only when one is stated and the dates held only to a time the caller supplies. Every
//! allocation comes from one static arena the program hands [`channel::start`].
//!
//! - [`channel`] -- the library started on its arena, an [`channel::Identity`] (generated, or
//!   read from PEM), the [`channel::Trust`] roots, and a [`channel::Session`] over any byte
//!   [`channel::Transport`].
//! - [`stream`] -- the channel as the cooperative runtime's stream: [`stream::TlsStream`] is a
//!   `StreamSocket` over another one, [`stream::TlsDial`] the `StreamDial` that opens it and
//!   [`stream::TlsListener`] the `StreamListen` that accepts it, so the stream link runs over the
//!   channel unchanged, in either role and under either policy.
//!
//! The Mbed TLS this links is the one revision the Zephyr workspace pins (4.1.0, with
//! TF-PSA-Crypto 1.1.0). With the `vendored` feature `build.rs` builds that revision from
//! `vendor/mbedtls` and `vendor/tf-psa-crypto` with this crate's configuration (`config/`) and
//! compiles the C side of the channel (`csrc/wz_tls.c`) beside it; without it, the image's own
//! build compiles `csrc/wz_tls.c` against the Mbed TLS the platform carries.
#![no_std]

// The two forms of `wz-runtime-coop`'s task pool are this crate's two selectors, and they are
// exclusive: the slot form replaces the heap forms of the session and does not add to them. A
// build with both is no configuration of this crate, so it is refused here by name, as the heap
// crates refuse the slot profile (`wz_session_core::heap_session_profile!`). This crate is written
// for both profiles, so it does not wrap its items in that macro; it refuses only the pair.
#[cfg(all(feature = "alloc", feature = "session-slot"))]
compile_error!(
    "wz-tls-mbedtls: `alloc` and `session-slot` select the two forms of `wz-runtime-coop`'s task \
     pool, the heap form and the per-session slot form of an MCU image. The two are exclusive: \
     the slot form replaces the heap forms of the session and does not add to them. Turn on \
     exactly one; `alloc` is the default, so a slot build turns the defaults off. A build with \
     both reached here by `--all-features` or by feature unification; the configurations this \
     crate has are the feature sets its manifest declares (`[package.metadata.wz-docs]`)."
);

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(any(test, feature = "host-lock"))]
extern crate std;

mod ffi;
mod lock;

pub mod channel;
pub mod stream;

// The tests run the channel, so they link the library `vendored` builds.
#[cfg(all(test, feature = "vendored"))]
mod tests;

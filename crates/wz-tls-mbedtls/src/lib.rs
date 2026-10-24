// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz-tls-mbedtls` -- the secure channel of the fixed-memory profile (decision D9 of
//! `docs/session-lifecycle-intent.md`) over Mbed TLS on its PSA Crypto line.
//!
//! TLS 1.3 with mutual authentication: each end presents a certificate self-signed over a P-256
//! key it generated in the PSA key store, proves the key in the handshake, and is accepted by the
//! zid that key names (decision D1), never by a certificate authority. Every allocation comes
//! from one static arena the program hands [`channel::start`].
//!
//! - [`channel`] -- the library started on its arena, an [`channel::Identity`], and a
//!   [`channel::Session`] over any byte [`channel::Transport`].
//! - [`stream`] -- the channel as the cooperative runtime's stream: [`stream::TlsStream`] is a
//!   `StreamSocket` over another one and [`stream::TlsDial`] the `StreamDial` that opens it, so
//!   the stream link runs over the channel unchanged.
//!
//! The Mbed TLS this links is the one revision the Zephyr workspace pins (4.1.0, with
//! TF-PSA-Crypto 1.1.0). With the `vendored` feature `build.rs` builds that revision from
//! `vendor/mbedtls` and `vendor/tf-psa-crypto` with this crate's configuration (`config/`) and
//! compiles the C side of the channel (`csrc/wz_tls.c`) beside it; without it, the image's own
//! build compiles `csrc/wz_tls.c` against the Mbed TLS the platform carries.
#![no_std]

#[cfg(test)]
extern crate std;

mod ffi;

pub mod channel;
pub mod stream;

#[cfg(test)]
mod tests;

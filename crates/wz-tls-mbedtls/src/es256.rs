// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ES256 over the PSA Crypto API of the library this crate links: what a fixed-memory node
//! verifies a sealed lifecycle command with (decision D17 of `docs/session-lifecycle-intent.md`,
//! `docs/command-seal.md`), so the node links no signature code beside its TLS library's.
//!
//! The C side imports the command's point as a volatile P-256 public key with
//! `PSA_ALG_ECDSA(PSA_ALG_SHA_256)` and `PSA_KEY_USAGE_VERIFY_MESSAGE`, calls `psa_verify_message`
//! and destroys the key (`csrc/wz_tls.c`, `wz_tls_es256_verify`). It needs `PSA_WANT_ALG_ECDSA`,
//! `PSA_WANT_ECC_SECP_R1_256`, `PSA_WANT_ALG_SHA_256` and `PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY`,
//! which the channel's TLS 1.3 with a P-256 peer already needs (`config/wz_tls_crypto_config.h`
//! states them for the build `vendored` makes; an image that builds Mbed TLS itself states them in
//! its own configuration), and one key slot for the length of a call.
//!
//! Both calls need the library started ([`crate::channel::start`]); before it a signature
//! verifies nothing and no echo is drawn.

use core::ffi::c_int;

use wz_command_seal::{Echo, Es256, ECHO_LEN, POINT_LEN, SIGNATURE_LEN};

mod raw {
    use core::ffi::c_int;

    extern "C" {
        pub fn wz_tls_es256_verify(
            point: *const u8,
            message: *const u8,
            len: usize,
            signature: *const u8,
        ) -> c_int;
        pub fn wz_tls_random(out: *mut u8, len: usize) -> c_int;
    }
}

/// ES256 by the library's PSA Crypto: [`Es256`] for `wz_command_seal`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PsaEs256;

impl Es256 for PsaEs256 {
    fn verify(
        &self,
        point: &[u8; POINT_LEN],
        message: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> bool {
        // SAFETY: the point and the signature are arrays of the lengths the C side reads, and the
        // message is read for `message.len()` bytes; nothing is kept past the call. Through the
        // crate's lock, as every call into the library is.
        let verdict: c_int = crate::lock::locked(|| unsafe {
            raw::wz_tls_es256_verify(
                point.as_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
            )
        });
        verdict == 1
    }
}

/// An echo drawn from the library's random generator: what a node hands the commanders it holds
/// no counter for after it starts (RFC 8613, appendix B.1.2). `None` before the library started.
pub fn random_echo() -> Option<Echo> {
    let mut echo = [0u8; ECHO_LEN];
    let out = echo.as_mut_ptr();
    // SAFETY: `out` is `ECHO_LEN` writable bytes, which is all the C side writes.
    let rc: c_int = crate::lock::locked(|| unsafe { raw::wz_tls_random(out, ECHO_LEN) });
    (rc == 0).then_some(echo)
}

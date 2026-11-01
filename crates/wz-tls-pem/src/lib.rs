// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The PEM bytes a TLS config key names, resolved from a file path or a base64 token.
//!
//! The edge that holds the key spellings resolves "path or base64" once and hands PEM BYTES
//! inward, so no layer below it carries key-encoding knowledge. These two functions are that
//! resolution, and they are the only one: the tokio engine's rustls configs and the cooperative
//! engine's Mbed TLS channel both take what they return.

use std::io;
use std::path::Path;

/// Map a decoder's error into the `io::Result` the TLS config surface speaks. `InvalidData` is
/// the kind for malformed cert or key material.
fn invalid_data<E>(err: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::InvalidData, err)
}

/// Read TLS PEM material (a cert chain, a private key, or a CA bundle) from a file into the
/// bytes the decoders consume. This is the wz analogue of zenoh-rust reading the `*_FILE` config
/// keys (`tokio::fs::read` in `zenoh-link-tls/src/utils.rs`) and of pico's file-path
/// `TLS_CONFIG_*` keys.
///
/// Synchronous `std::fs::read` by design: a TLS config is built ONCE at startup, not on a hot
/// path, so reading it synchronously keeps the otherwise-sync config builders free of async
/// colouring (the rustls-idiomatic shape — rustls' own examples load cert files synchronously).
/// Errors if the file is missing OR empty: an empty cert/key file is a misconfiguration that
/// should fail fast rather than silently build a certless config.
pub fn read_pem_file(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    if bytes.is_empty() {
        return Err(invalid_data("TLS PEM file is empty"));
    }
    Ok(bytes)
}

/// Decode base64-wrapped PEM into the raw PEM bytes the decoders consume. Mirrors pico's
/// `*_BASE64` TLS config keys (and zenoh-rust's `*_base64`): a multi-line PEM base64-wrapped into
/// one token so it survives a transport that cannot carry raw newlines (an env var, a JSON
/// field). The decoded bytes ARE PEM — feed them to a decoder like any other PEM source.
/// Standard (RFC 4648) alphabet, matching zenoh-rust's `base64_decode`.
///
/// Surrounding whitespace is trimmed first (a base64 blob from a file or env var commonly
/// carries a trailing newline, which the strict STANDARD engine would otherwise reject);
/// internal non-alphabet bytes still error.
pub fn decode_base64_pem(b64: &str) -> io::Result<Vec<u8>> {
    use base64::{engine::general_purpose, Engine};
    general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(invalid_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine};

    const PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    /// A directory of this test's own, removed when it goes out of scope.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let dir =
                std::env::temp_dir().join(format!("wz-tls-pem-{}-{name}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("create the scratch directory");
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_file_is_read_whole() {
        let scratch = Scratch::new("whole");
        let path = scratch.0.join("cert.pem");
        std::fs::write(&path, PEM).expect("write the file");
        assert_eq!(read_pem_file(&path).expect("read it"), PEM);
    }

    #[test]
    fn an_empty_file_is_refused_as_malformed_material() {
        let scratch = Scratch::new("empty");
        let path = scratch.0.join("empty.pem");
        std::fs::write(&path, b"").expect("write the file");
        let err = read_pem_file(&path).expect_err("an empty file is a misconfiguration");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_missing_file_is_the_operating_systems_refusal() {
        let scratch = Scratch::new("missing");
        let err = read_pem_file(scratch.0.join("absent.pem")).expect_err("no such file");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn a_base64_token_decodes_to_the_pem() {
        let token = general_purpose::STANDARD.encode(PEM);
        assert_eq!(decode_base64_pem(&token).expect("decode it"), PEM);
    }

    #[test]
    fn a_trailing_newline_on_the_token_is_trimmed() {
        let token = format!("\n  {}\n", general_purpose::STANDARD.encode(PEM));
        assert_eq!(decode_base64_pem(&token).expect("decode it"), PEM);
    }

    #[test]
    fn a_byte_outside_the_alphabet_is_malformed_material() {
        let err = decode_base64_pem("!!!not valid base64!!!").expect_err("not base64");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let inside = format!("{}\n{}", "AAAA", "AAAA");
        assert!(
            decode_base64_pem(&inside).is_err(),
            "a newline INSIDE the token is not trimmed away"
        );
    }
}

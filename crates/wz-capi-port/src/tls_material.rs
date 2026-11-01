// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The TLS material a C-ABI `z_open` carries, already RESOLVED to PEM bytes.
//!
//! It is the port's because both engines take it: the tokio engine builds rustls configs from
//! these bytes, and the cooperative engine builds the Mbed TLS channel's identity and roots from
//! the same ones. What each does with them is the engine's; that the edge which holds the key
//! spellings resolved "path or base64" before this value was made is not (the reading is
//! `wz-tls-pem`'s).

use alloc::vec::Vec;

/// The TLS material a C-ABI `z_open` carries, already RESOLVED to PEM bytes.
///
/// R311y534 — this replaces the two `Option<String>` listen-cert PATHS the quic
/// acceptor used to take, and the reason is that the pico key set is wider than
/// a pair of paths in two independent directions. Each certificate value has a
/// PATH form and a `*_BASE64` inline form (`Z_CONFIG_TLS_LISTEN_CERTIFICATE_KEY`
/// vs `..._BASE64_KEY`), and the upstream examples use the INLINE one by default
/// — their PEM blobs are compiled into the program. And the dial side needs
/// material the listen side never did: a root CA to verify the peer against, a
/// name-verification policy, and an optional client cert for mTLS.
///
/// So the shim resolves "path or base64" ONCE, on the ABI side where the key
/// numbers live, and hands PEM BYTES across. That keeps the engines free of
/// key-encoding knowledge and makes the two forms indistinguishable downstream,
/// which is what they are: `-C ca.pem` and the inline bundle are the same trust
/// decision written two ways.
///
/// All fields default to `None`/`false`, which is the cert-free tcp/udp/ws path
/// — [`Default`] is what a non-TLS `z_open` passes.
#[derive(Default, Clone, Debug)]
pub struct CapiTlsConfig {
    /// The trust bundle a `tls/...` DIAL verifies the peer's server cert
    /// against (pico `Z_CONFIG_TLS_ROOT_CA_CERTIFICATE{,_BASE64}_KEY`). `None`
    /// leaves a `tls/...` dial without TLS material, which the runtime reports
    /// as an unsupported dial rather than silently dialing in the clear.
    pub root_ca_pem: Option<Vec<u8>>,
    /// Whether the peer cert's SAN must match the dialed host (pico
    /// `Z_CONFIG_TLS_VERIFY_NAME_ON_CONNECT_KEY`). pico's own default is
    /// `false`, and the stock examples rely on it: they dial a numeric
    /// `tls/127.0.0.1:<port>` while their bundled cert names `localhost`.
    pub verify_name_on_connect: bool,
    /// The client cert a MUTUAL-TLS dial presents (pico
    /// `Z_CONFIG_TLS_CONNECT_CERTIFICATE{,_BASE64}_KEY` + its private key),
    /// gated by `Z_CONFIG_TLS_ENABLE_MTLS_KEY`. Both-or-neither.
    pub connect_cert_pem: Option<Vec<u8>>,
    pub connect_key_pem: Option<Vec<u8>>,
    /// The cert chain + private key a `tls/...` or `quic/...` LISTEN presents
    /// (pico `Z_CONFIG_TLS_LISTEN_{CERTIFICATE,PRIVATE_KEY}{,_BASE64}_KEY`).
    /// zenoh feeds ONE tls block to both backends, so one pair serves both.
    pub listen_cert_pem: Option<Vec<u8>>,
    pub listen_key_pem: Option<Vec<u8>>,
    /// Require and verify a CLIENT cert on the accept side (pico
    /// `Z_CONFIG_TLS_ENABLE_MTLS_KEY` read by a listener). The bundle is
    /// [`Self::root_ca_pem`], mirroring pico, which uses the one CA value for
    /// both roles.
    pub require_client_auth: bool,
}

impl CapiTlsConfig {
    /// The mTLS client-auth pair (certificate chain, private key), `Some` only when BOTH halves
    /// are present.
    ///
    /// Separate from the fields because "mTLS enabled" and "the material for it
    /// arrived" are two conditions, and a half-configured pair must not silently
    /// degrade to one-way TLS.
    pub fn client_auth_pair(&self) -> Option<(&[u8], &[u8])> {
        match (&self.connect_cert_pem, &self.connect_key_pem) {
            (Some(cert), Some(key)) => Some((cert, key)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_auth_pair_needs_both_halves() {
        let both = CapiTlsConfig {
            connect_cert_pem: Some(b"cert".to_vec()),
            connect_key_pem: Some(b"key".to_vec()),
            ..CapiTlsConfig::default()
        };
        assert_eq!(
            both.client_auth_pair(),
            Some((b"cert".as_slice(), b"key".as_slice()))
        );

        let cert_only = CapiTlsConfig {
            connect_cert_pem: Some(b"cert".to_vec()),
            ..CapiTlsConfig::default()
        };
        assert_eq!(cert_only.client_auth_pair(), None, "a half is not a pair");
        assert_eq!(CapiTlsConfig::default().client_auth_pair(), None);
    }
}

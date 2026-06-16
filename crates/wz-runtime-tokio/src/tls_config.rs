// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311og — PEM cert/key material loader for the TLS link.
//!
//! [`crate::tls_pipeline`] runs the rustls handshake over a `ClientConfig` /
//! `ServerConfig`; THIS module builds those configs from the on-disk PEM an
//! application supplies. It is the production answer to "where do the certs
//! come from" — the TLS e2e tests synthesise a self-signed cert with `rcgen`,
//! but a real deployment loads cert chains + private keys (+ a trusted-CA
//! bundle) from PEM files, the universal cert interchange format.
//!
//! ## Mirror of the upstream cert plumbing
//!
//! zenoh-pico reads TLS cert material from the session config keys
//! `TLS_CONFIG_ROOT_CA_CERTIFICATE` / `TLS_CONFIG_CONNECT_CERTIFICATE` /
//! `TLS_CONFIG_LISTEN_CERTIFICATE` / `TLS_CONFIG_ENABLE_MTLS`
//! (`include/zenoh-pico/config.h.in` 0x4B..0x56). zenoh-rust decodes the same
//! material with `rustls_pemfile` in `zenoh-link-tls/src/utils.rs`. wz mirrors
//! the zenoh-rust path (same rustls stack): parse the PEM into the rustls
//! `pki_types`, then drive the rustls builder exactly as upstream does —
//! `with_root_certificates` + `with_client_auth_cert` on the client,
//! `with_client_cert_verifier` + `with_single_cert` on the server.
//!
//! ## mTLS is a parameter, not a separate code path
//!
//! The TLS material lives ENTIRELY inside the rustls `ClientConfig` /
//! `ServerConfig`, so the [`crate::tls_pipeline`] `dial_tls` / `accept_tls`
//! primitives need no change to support mutual TLS — they already take a
//! fully-built config. Mutual auth is therefore expressed here, as the
//! optional `client_auth` (client side: present a cert) / `client_ca_pem`
//! (server side: require + verify the peer's cert) arguments. Absent them, the
//! configs are ordinary one-way TLS (server-authenticated only), exactly as
//! pico's `ENABLE_MTLS` defaults off.
//!
//! ## Three sources for the same PEM
//!
//! The config builders take PEM as `&[u8]`, so the SOURCE of those bytes is
//! orthogonal to the parse. An application can supply the PEM as raw bytes (it
//! already has them), from a file path ([`read_pem_file`]), or base64-wrapped
//! ([`decode_base64_pem`]) — the wz decomposition of zenoh-rust's raw / `*_FILE`
//! / `*_BASE64` config-key cascade and pico's file + `*_BASE64` key pairs. All
//! three converge on the same byte loaders below; no source needs a bespoke
//! config builder.
//!
//! ## Crypto provider
//!
//! Both builders pin the `ring` provider explicitly via
//! `builder_with_provider`, so a config is produced regardless of whether a
//! process-default `CryptoProvider` was installed — matching the
//! `loopback_tls_configs` fixture's reasoning and avoiding a hidden global
//! dependency.

use std::io;
use std::path::Path;
use std::sync::Arc;

use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};

/// Client-authentication (mTLS) material: the cert chain the dialer presents to
/// the server plus its matching private key, both as PEM. `Some(_)` on the
/// client side turns a one-way-TLS dial into a mutual-TLS dial (the wz analogue
/// of pico's `CONNECT_CERTIFICATE` + `CONNECT_PRIVATE_KEY`). Borrowed: the
/// caller owns the PEM bytes; they are parsed into owned DER inside the builder.
pub struct ClientAuthPem<'a> {
    /// PEM cert chain the client presents (leaf first, optional intermediates).
    pub cert_chain_pem: &'a [u8],
    /// PEM private key matching the leaf of `cert_chain_pem` (PKCS#1 / PKCS#8 /
    /// SEC1 — `rustls_pemfile::private_key` accepts any of the three).
    pub private_key_pem: &'a [u8],
}

/// Map a non-`io` error (rustls / verifier-builder) into the `io::Result` the
/// `tls_pipeline` dial/accept surface speaks, so the whole TLS path reports one
/// error type. `InvalidData` is the kind for malformed cert/key material.
fn invalid_data<E>(err: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::InvalidData, err)
}

/// Read TLS PEM material (a cert chain, a private key, or a CA bundle) from a
/// file into the bytes the decoders below consume — the file-path SOURCE for
/// [`certs_from_pem`] / [`private_key_from_pem`] / [`root_store_from_pem`]. This
/// is the wz analogue of zenoh-rust reading the `*_FILE` config keys
/// (`tokio::fs::read` in `zenoh-link-tls/src/utils.rs`) and of pico's file-path
/// `TLS_CONFIG_*` keys.
///
/// Synchronous `std::fs::read` by design: a TLS config is built ONCE at startup,
/// not on a hot path, so reading it synchronously keeps the otherwise-sync
/// config builders free of async colouring (the rustls-idiomatic shape — rustls'
/// own examples load cert files synchronously). Errors if the file is missing OR
/// empty: an empty cert/key file is a misconfiguration that should fail fast
/// rather than silently build a certless config.
pub fn read_pem_file(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    if bytes.is_empty() {
        return Err(invalid_data("TLS PEM file is empty"));
    }
    Ok(bytes)
}

/// Decode base64-wrapped PEM into the raw PEM bytes the decoders consume — the
/// base64 SOURCE for [`certs_from_pem`] / [`private_key_from_pem`] /
/// [`root_store_from_pem`]. Mirrors pico's `*_BASE64` TLS config keys (and
/// zenoh-rust's `*_base64`): a multi-line PEM base64-wrapped into one token so it
/// survives a transport that cannot carry raw newlines (an env var, a JSON
/// field). The decoded bytes ARE PEM — feed them to a decoder like any other PEM
/// source. Standard (RFC 4648) alphabet, matching zenoh-rust's `base64_decode`.
///
/// Surrounding whitespace is trimmed first (a base64 blob from a file or env var
/// commonly carries a trailing newline, which the strict STANDARD engine would
/// otherwise reject); internal non-alphabet bytes still error.
pub fn decode_base64_pem(b64: &str) -> io::Result<Vec<u8>> {
    use base64::{engine::general_purpose, Engine};
    general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(invalid_data)
}

/// Parse a PEM cert chain into DER certificates (leaf first). The chain a TLS
/// peer PRESENTS (`with_single_cert` / `with_client_auth_cert`) and the trust
/// bundle a peer VERIFIES against (via [`root_store_from_pem`]) are both decoded
/// through this. Mirrors zenoh-rust's `rustls_pemfile::certs(...)` usage.
pub fn certs_from_pem(pem: &[u8]) -> io::Result<Vec<CertificateDer<'static>>> {
    // `&[u8]` implements `BufRead`, so the PEM bytes are their own reader.
    rustls_pemfile::certs(&mut &pem[..]).collect()
}

/// Parse the first private key from PEM, accepting PKCS#1 (`RSA PRIVATE KEY`),
/// PKCS#8 (`PRIVATE KEY`), or SEC1 (`EC PRIVATE KEY`). `rustls_pemfile::private_key`
/// is the modern single-call decoder that supersedes zenoh-rust's manual
/// rsa->pkcs8->ec cascade (same outcome, one call). Errors if the PEM carries no
/// private key — a fail-fast on a mis-supplied file rather than a silent empty
/// config.
pub fn private_key_from_pem(pem: &[u8]) -> io::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut &pem[..])?
        .ok_or_else(|| invalid_data("no private key found in PEM material"))
}

/// Build a [`RootCertStore`] trusting every certificate in the PEM bundle. Used
/// for both the client's server-trust roots and the server's client-CA roots
/// (the wz analogue of pico's `ROOT_CA_CERTIFICATE`). Each parsed cert is added
/// as a trust anchor.
pub fn root_store_from_pem(ca_pem: &[u8]) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in certs_from_pem(ca_pem)? {
        roots.add(cert).map_err(invalid_data)?;
    }
    Ok(roots)
}

/// Build a rustls [`ClientConfig`] for a `tls/...` dial from PEM.
///
/// `root_ca_pem` is the trust bundle the dialer verifies the SERVER's cert
/// against (its certificate, or the CA that issued it). `client_auth` is the
/// mTLS knob: `Some(_)` makes the dialer PRESENT a client cert (mutual TLS),
/// `None` is one-way TLS where only the server authenticates.
///
/// The returned config feeds [`crate::session_open::TlsDialConfig::client_config`]
/// (the caller supplies the `ServerName` to verify alongside it).
pub fn client_config_from_pem(
    root_ca_pem: &[u8],
    client_auth: Option<ClientAuthPem<'_>>,
) -> io::Result<Arc<ClientConfig>> {
    let roots = root_store_from_pem(root_ca_pem)?;
    let provider = Arc::new(ring::default_provider());

    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(invalid_data)?
        .with_root_certificates(roots);

    let config = match client_auth {
        Some(auth) => {
            let cert_chain = certs_from_pem(auth.cert_chain_pem)?;
            let key = private_key_from_pem(auth.private_key_pem)?;
            builder
                .with_client_auth_cert(cert_chain, key)
                .map_err(invalid_data)?
        }
        None => builder.with_no_client_auth(),
    };

    Ok(Arc::new(config))
}

/// Build a rustls [`ServerConfig`] for a TLS acceptor from PEM.
///
/// `cert_chain_pem` + `private_key_pem` are the cert the server PRESENTS (the wz
/// analogue of pico's `LISTEN_CERTIFICATE` + `LISTEN_PRIVATE_KEY`).
/// `client_ca_pem` is the mTLS knob: `Some(_)` makes the server REQUIRE and
/// verify a client cert (chained to that CA bundle, pico's `ENABLE_MTLS`),
/// `None` accepts any client without authenticating it (one-way TLS).
///
/// The returned config feeds [`crate::tls_pipeline::accept_tls`].
pub fn server_config_from_pem(
    cert_chain_pem: &[u8],
    private_key_pem: &[u8],
    client_ca_pem: Option<&[u8]>,
) -> io::Result<Arc<ServerConfig>> {
    let cert_chain = certs_from_pem(cert_chain_pem)?;
    let key = private_key_from_pem(private_key_pem)?;
    let provider = Arc::new(ring::default_provider());

    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(invalid_data)?;

    // Choose the client-auth policy first; both arms land on the same
    // `WantsServerCert` builder state so the cert install below is shared.
    let config = match client_ca_pem {
        Some(ca_pem) => {
            let client_roots = root_store_from_pem(ca_pem)?;
            let verifier =
                WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider)
                    .build()
                    .map_err(invalid_data)?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    }
    .with_single_cert(cert_chain, key)
    .map_err(invalid_data)?;

    Ok(Arc::new(config))
}

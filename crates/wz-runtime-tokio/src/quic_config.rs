// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311xk — TLS-1.3 + ALPN rustls config builders for the QUIC link.
//!
//! QUIC mandates TLS 1.3 (the handshake IS carried in QUIC frames), so its
//! rustls [`ClientConfig`] / [`ServerConfig`] differ from the TLS link's
//! ([`crate::tls_config`]) in exactly two ways:
//! - **TLS 1.3 ONLY** — `with_protocol_versions(&[&TLS13])`, not the TLS
//!   link's safe-default 1.2 + 1.3 (`quinn::crypto::rustls::QuicClientConfig::
//!   try_from` rejects a non-1.3 config), and
//! - **ALPN = `hq-29`** — the application-layer protocol id zenoh-link-quic
//!   advertises (`alpn_protocols = [b"hq-29"]`, `zenoh-link-quic/src/unicast.rs`),
//!   so a wz QUIC peer negotiates the same token a zenohd QUIC peer expects.
//!
//! Everything else is shared with the TLS link: the PEM → DER loaders
//! ([`certs_from_pem`](crate::tls_config::certs_from_pem) /
//! [`private_key_from_pem`](crate::tls_config::private_key_from_pem) /
//! [`root_store_from_pem`](crate::tls_config::root_store_from_pem)), the
//! [`ClientAuthPem`](crate::tls_config::ClientAuthPem) mTLS knob, the `ring`
//! crypto provider, and the rustls 0.23 stack itself (quinn 0.11 + tokio-rustls
//! 0.26 share one `rustls` — verified at integration). The built rustls config
//! feeds `quinn::crypto::rustls::{QuicClientConfig,QuicServerConfig}` in
//! [`crate::quic_pipeline`].

use std::io;
use std::sync::Arc;

use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::{version::TLS13, ClientConfig, ServerConfig};

use crate::tls_config::{certs_from_pem, private_key_from_pem, root_store_from_pem, ClientAuthPem};

/// The ALPN protocol id zenoh-link-quic advertises on every QUIC connection
/// (`zenoh-link-quic/src/unicast.rs`: `alpn_protocols = [b"hq-29"]`). Both wz
/// peers MUST advertise the same token for ALPN negotiation to succeed, and it
/// must match zenohd's for a future cross-impl QUIC leg.
pub const QUIC_ALPN: &[u8] = b"hq-29";

/// Map a non-`io` error (rustls builder) into the `io::Result` the QUIC dial /
/// accept surface speaks — the [`crate::quic_pipeline`] analogue of
/// `tls_config`'s private `invalid_data`.
fn invalid_data<E>(err: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::InvalidData, err)
}

/// Build a TLS-1.3 + ALPN-`hq-29` rustls [`ClientConfig`] for a `quic/...` dial
/// from PEM. The QUIC sibling of
/// [`crate::tls_config::client_config_from_pem`], diverging only in the TLS-1.3
/// pin and the ALPN; `root_ca_pem` is the server-trust bundle and `client_auth`
/// is the optional mTLS cert the dialer presents. The returned config feeds
/// `quinn::crypto::rustls::QuicClientConfig::try_from` in
/// [`crate::quic_pipeline::dial_quic`].
///
/// Unlike the TLS link, no `ServerNameVerification::AnyName` knob (yet): the
/// QUIC dial seam always verifies chain + name, the safe default. A raw-IP QUIC
/// dial would need that knob added here (a clean extension point), mirroring how
/// the TLS link grew it.
pub fn quic_client_config_from_pem(
    root_ca_pem: &[u8],
    client_auth: Option<ClientAuthPem<'_>>,
) -> io::Result<Arc<ClientConfig>> {
    let roots = root_store_from_pem(root_ca_pem)?;
    let provider = Arc::new(ring::default_provider());

    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(invalid_data)?
        .with_root_certificates(roots);

    let mut config = match client_auth {
        Some(auth) => {
            let cert_chain = certs_from_pem(auth.cert_chain_pem)?;
            let key = private_key_from_pem(auth.private_key_pem)?;
            builder
                .with_client_auth_cert(cert_chain, key)
                .map_err(invalid_data)?
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    // R311y578 (G10) — install the session-key sink. Inert in a build
    // without `transport-link-tls-keylog`, and inert even there until
    // `SSLKEYLOGFILE` names a destination (see `crate::tls_keylog`).
    // Installed unconditionally rather than behind a `#[cfg]` here so the
    // four config builders cannot drift from one another.
    config.key_log = crate::tls_keylog::key_log();
    Ok(Arc::new(config))
}

/// Build a TLS-1.3 + ALPN-`hq-29` rustls [`ServerConfig`] for a QUIC acceptor
/// from PEM. The QUIC sibling of [`crate::tls_config::server_config_from_pem`]:
/// `cert_chain_pem` + `private_key_pem` are the cert the server presents,
/// `client_ca_pem` is the optional mTLS knob (require + verify a client cert).
/// The returned config feeds `quinn::crypto::rustls::QuicServerConfig::try_from`
/// in [`crate::quic_pipeline::accept_quic_on`].
pub fn quic_server_config_from_pem(
    cert_chain_pem: &[u8],
    private_key_pem: &[u8],
    client_ca_pem: Option<&[u8]>,
) -> io::Result<Arc<ServerConfig>> {
    let cert_chain = certs_from_pem(cert_chain_pem)?;
    let key = private_key_from_pem(private_key_pem)?;
    let provider = Arc::new(ring::default_provider());

    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])
        .map_err(invalid_data)?;

    let mut config = match client_ca_pem {
        Some(ca_pem) => {
            use tokio_rustls::rustls::server::WebPkiClientVerifier;
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
    config.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    // R311y578 (G10) — install the session-key sink, as the three sibling
    // config builders do. See `crate::tls_keylog`.
    config.key_log = crate::tls_keylog::key_log();
    Ok(Arc::new(config))
}

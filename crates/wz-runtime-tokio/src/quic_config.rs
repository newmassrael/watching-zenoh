// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! [`server_trust_roots`](crate::tls_config::server_trust_roots) /
//! [`client_auth_roots`](crate::tls_config::client_auth_roots)), the
//! [`ClientAuthPem`](crate::tls_config::ClientAuthPem) mTLS knob, the `ring`
//! crypto provider, and the rustls 0.23 stack itself (quinn 0.11 + tokio-rustls
//! 0.26 share one `rustls` — verified at integration). The built rustls config
//! feeds `quinn::crypto::rustls::{QuicClientConfig,QuicServerConfig}` in
//! [`crate::quic_pipeline`].

use std::io;
use std::sync::Arc;

use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::{version::TLS13, ClientConfig, ServerConfig};

use crate::tls_config::{
    certs_from_pem, client_auth_roots, private_key_from_pem, server_trust_roots, ClientAuthPem,
};
// R2602 — these two serve ONLY the locator-material builders below, which are
// `transport-unicast`-gated because `session_open` is their sole consumer.
// Ungated here they are `unused_imports` in a `--no-default-features --features
// transport-link-quic` build, which Layer C1ac compiles with `-D warnings`.
#[cfg(feature = "transport-unicast")]
use crate::tls_config::resolve_optional_pem;
#[cfg(feature = "transport-unicast")]
use wz_session_core::locator::LinkTlsMaterial;

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
/// pin and the ALPN; `custom_root_ca_pem` is an ADDITIONAL server-trust anchor
/// on top of the public WebPKI roots
/// ([`server_trust_roots`](crate::tls_config::server_trust_roots)), `None`
/// meaning the public roots alone as zenoh dials (R2603, open-debt 727), and
/// `client_auth`
/// is the optional mTLS cert the dialer presents. The returned config feeds
/// `quinn::crypto::rustls::QuicClientConfig::try_from` in
/// [`crate::quic_pipeline::dial_quic`].
///
/// Unlike the TLS link, no `ServerNameVerification::AnyName` knob (yet): the
/// QUIC dial seam always verifies chain + name, the safe default. A raw-IP QUIC
/// dial would need that knob added here (a clean extension point), mirroring how
/// the TLS link grew it.
pub fn quic_client_config_from_pem(
    custom_root_ca_pem: Option<&[u8]>,
    client_auth: Option<ClientAuthPem<'_>>,
) -> io::Result<Arc<ClientConfig>> {
    let roots = server_trust_roots(custom_root_ca_pem)?;
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
            let client_roots = client_auth_roots(ca_pem)?;
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

/// R2599 — the rustls CLIENT config a quic-family dial uses when the LOCATOR's
/// own `#`-config tail carries the material, or `None` when it carries none.
///
/// `None` is a fallback signal, not a failure: the caller then uses the ambient
/// `DialConfig.quic`. That direction — the locator's own value first, the
/// configured layer beneath — is the one `LinkSocket::resolve` already takes
/// for every socket key, and it is upstream's own: zenoh renders the global
/// `transport/link/tls` block INTO locator-parameter vocabulary
/// (`io/zenoh-link-commons/src/quic/utils.rs` @ `fn inspect_config(&self, config: &ZenohConfig) -> ZResult<String> {`)
/// and an endpoint's own parameters sit above it.
///
/// The client cert is loaded only under `enable_mtls`, as upstream loads it
/// (`io/zenoh-link-commons/src/quic/utils.rs` @ `let tls_client_server_auth: bool = match config.get(TLS_ENABLE_MTLS) {`).
/// ONE NAMED DIVERGENCE: a tail naming one half of the pair is REFUSED here,
/// where upstream's loader bails later inside its own PEM step. Failing at the
/// locator names the key an operator mistyped; failing inside rustls names the
/// decoder.
/// R2602 — gated on `transport-unicast` because its ONLY consumer is
/// `session_open`, which is itself `all(transport-link-tcp, transport-unicast)`.
/// `transport-link-quic` implies tcp but NOT unicast, so a
/// `--no-default-features --features transport-link-quic` build compiles the
/// consumer out and leaves this dead — which Layer C1ac runs with `-D warnings`
/// and hosted redded on run 34763542586. Neither the reduced-features gate (no
/// features) nor the non-default gate (all features) builds that combination.
#[cfg(feature = "transport-unicast")]
pub(crate) async fn quic_client_config_from_locator(
    material: &LinkTlsMaterial,
) -> io::Result<Option<Arc<ClientConfig>>> {
    let root_ca = resolve_optional_pem(material.root_ca.as_ref()).await?;
    let (cert, key) = if material.mtls() {
        (
            resolve_optional_pem(material.connect_certificate.as_ref()).await?,
            resolve_optional_pem(material.connect_private_key.as_ref()).await?,
        )
    } else {
        (None, None)
    };
    let auth =
        match (&cert, &key) {
            (None, None) => None,
            (Some(cert_chain_pem), Some(private_key_pem)) => Some(ClientAuthPem {
                cert_chain_pem,
                private_key_pem,
            }),
            _ => return Err(invalid_data(
                "a locator enabling mTLS needs both connect_certificate and connect_private_key",
            )),
        };
    // R2603 (open-debt 727) — WHICH tails claim the dial. `root_ca` alone does,
    // as before. A tail naming only CONNECT material now does too, because the
    // public roots make it buildable: before 727 such a tail fell through to
    // the ambient config and the client certificate it named was silently
    // dropped, since a client config could not be built without a CA.
    //
    // Deliberately NOT `!material.is_empty()`: a LISTEN-only tail must still
    // fall through. Claiming the dial for it would build a public-roots config
    // that REPLACES an ambient one which may carry a private CA — narrowing
    // trust on a locator that said nothing about dialing.
    if root_ca.is_none() && auth.is_none() {
        return Ok(None);
    }
    quic_client_config_from_pem(root_ca.as_deref(), auth).map(Some)
}

/// R2599 — the rustls SERVER config a quic-family listen uses when the LOCATOR
/// carries the material, or `None` to fall back to the ambient
/// `AcceptConfig.quic`. The accept twin of [`quic_client_config_from_locator`].
///
/// `root_ca` becomes the client-cert verifier ONLY under `enable_mtls`, which
/// is the whole reason that key is parsed: the same key is a DIAL's trust
/// bundle, so using it unconditionally here would make a tail written for the
/// dial half turn a listener into one that DEMANDS client certificates.
/// Upstream gates it the same way and bails when mTLS is on with no roots
/// (`io/zenoh-link-commons/src/quic/utils.rs` @ `|| Err(zerror!("Missing root certificates while mTLS is enabled.")),`).
/// R2602 — gated with its dial twin above, for the same reason.
#[cfg(feature = "transport-unicast")]
pub(crate) async fn quic_server_config_from_locator(
    material: &LinkTlsMaterial,
) -> io::Result<Option<Arc<ServerConfig>>> {
    let cert = resolve_optional_pem(material.listen_certificate.as_ref()).await?;
    let key = resolve_optional_pem(material.listen_private_key.as_ref()).await?;
    let (cert, key) = match (cert, key) {
        (None, None) => return Ok(None),
        (Some(cert), Some(key)) => (cert, key),
        _ => {
            return Err(invalid_data(
                "a locator listening with its own material needs both listen_certificate and listen_private_key",
            ))
        }
    };
    let client_ca = if material.mtls() {
        match resolve_optional_pem(material.root_ca.as_ref()).await? {
            Some(roots) => Some(roots),
            None => {
                return Err(invalid_data(
                    "a locator enabling mTLS on a listen needs root_ca_certificate for the client roots",
                ))
            }
        }
    } else {
        None
    };
    quic_server_config_from_pem(&cert, &key, client_ca.as_deref()).map(Some)
}

/// R2603 (open-debt 727) — WHICH locator tails claim the dial, now that a
/// client config is buildable without a configured CA.
///
/// The unit under test is the discriminator, not the rustls config: `Some(_)`
/// means "this tail supplied the dial's material", `None` means "fall through
/// to the ambient config". Before R2603 that answer was simply "did the tail
/// name `root_ca`", which silently discarded a tail that named a client
/// certificate and no CA.
#[cfg(all(test, feature = "transport-unicast"))]
mod locator_dial_claim_tests {
    use super::quic_client_config_from_locator;
    use wz_session_core::locator::{LinkTlsMaterial, PemSource};

    fn mtls_pems() -> wz_runtime_tokio_test_support::MtlsPems {
        wz_runtime_tokio_test_support::loopback_mtls_pems()
    }

    /// A tail naming nothing falls through, as it always has. The anti-vacuity
    /// arm: without it every assertion below would pass on a function that
    /// returned `None` unconditionally.
    #[tokio::test]
    async fn an_empty_tail_does_not_claim_the_dial() {
        let claimed = quic_client_config_from_locator(&LinkTlsMaterial::NONE)
            .await
            .expect("an empty tail is not an error");
        assert!(
            claimed.is_none(),
            "a tail naming no TLS material must fall through to the ambient config"
        );
    }

    /// A LISTEN-only tail still falls through. This is the arm that keeps the
    /// change from narrowing trust: claiming the dial here would build a
    /// public-roots config that REPLACES an ambient one carrying a private CA,
    /// on a locator that said nothing about dialing.
    #[tokio::test]
    async fn a_listen_only_tail_does_not_claim_the_dial() {
        let pems = mtls_pems();
        let material = LinkTlsMaterial {
            listen_certificate: Some(PemSource::Raw(pems.server_cert_pem.clone())),
            listen_private_key: Some(PemSource::Raw(pems.server_key_pem.clone())),
            ..LinkTlsMaterial::NONE
        };
        let claimed = quic_client_config_from_locator(&material)
            .await
            .expect("a listen-only tail is not a dial error");
        assert!(
            claimed.is_none(),
            "a tail carrying only LISTEN material must leave the dial to the ambient config"
        );
    }

    /// THE 727 CASE. A tail naming a client certificate under mTLS and NO root
    /// CA now claims the dial and carries that certificate. Before R2603 this
    /// returned `None` and the certificate the operator wrote in the locator
    /// was silently dropped, because no client config could be built without a
    /// CA to verify the peer against.
    #[tokio::test]
    async fn a_connect_only_tail_claims_the_dial_and_keeps_its_client_certificate() {
        let pems = mtls_pems();
        let material = LinkTlsMaterial {
            connect_certificate: Some(PemSource::Raw(pems.client_cert_pem.clone())),
            connect_private_key: Some(PemSource::Raw(pems.client_key_pem.clone())),
            enable_mtls: Some(true),
            ..LinkTlsMaterial::NONE
        };
        let claimed = quic_client_config_from_locator(&material)
            .await
            .expect("a connect-only tail must build against the public roots");
        assert!(
            claimed.is_some(),
            "a tail naming a client certificate must claim the dial even with no root_ca; \
             falling through drops the certificate it named"
        );
    }

    /// A tail naming only a root CA keeps claiming the dial, as before — the
    /// path R2599 built. Present so the change is shown to ADD a claiming case
    /// rather than trade one for another.
    #[tokio::test]
    async fn a_root_ca_tail_still_claims_the_dial() {
        let pems = mtls_pems();
        let material = LinkTlsMaterial {
            root_ca: Some(PemSource::Raw(pems.ca_pem.clone())),
            ..LinkTlsMaterial::NONE
        };
        let claimed = quic_client_config_from_locator(&material)
            .await
            .expect("a root_ca tail builds a client config");
        assert!(claimed.is_some(), "a tail naming root_ca claims the dial");
    }
}

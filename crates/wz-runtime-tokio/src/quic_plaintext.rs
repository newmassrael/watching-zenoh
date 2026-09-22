// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2797 — PLAINTEXT QUIC: the crypto session under reliable UDP.
//!
//! Upstream's `udp/...?rel=1` is not a UDP protocol of its own. It is the QUIC
//! stream link with its security switched off
//! (`io/zenoh-links/zenoh-link-udp/src/reliability.rs` @ `} = QuicClientBuilder::new(endpoint).security(false).await?;`),
//! and "off" means something precise, which this module mirrors:
//!
//! - **the TLS 1.3 handshake still runs**, over a per-process self-signed
//!   server certificate and a client that trusts any certificate — but only to
//!   negotiate the connection (version, transport parameters, ALPN);
//! - **every level of packet protection is then replaced by no-op keys** —
//!   Initial, Handshake, 0-RTT and 1-RTT alike: encrypt does nothing, decrypt
//!   accepts anything, the AEAD tag is ZERO bytes long and header protection is
//!   off (`io/zenoh-link-commons/src/quic/plaintext.rs` @ `struct NoOpEncryptionKeys<T>(T);`).
//!
//! So the bytes a session writes are on the wire as written. That is what makes
//! it interoperable with upstream at all: an encrypted endpoint expects a
//! 16-byte tag and protected headers and cannot parse these packets, and a
//! plaintext endpoint "decrypts" an encrypted packet into garbage. A skip-all
//! certificate verifier alone would therefore NOT be this variant — it would
//! be encrypted QUIC that trusts anyone, which upstream does not speak.
//!
//! ## Why the TLS session is wrapped rather than replaced
//!
//! quinn derives everything it needs from the crypto session: when the
//! handshake is complete, what the peer's transport parameters are, and which
//! keys protect which packet space. Wrapping the real rustls session keeps all
//! of that and swaps only the keys on their way out — the same shape upstream
//! uses, and the reason it is buildable here: wz is on quinn 0.11.11 /
//! quinn-proto 0.11.15 and upstream on 0.11.5, the same trait line.
//!
//! ## Why none of this is reachable as an option
//!
//! Everything below is `pub(crate)`, and the only door to it is the reliable
//! UDP variant. The skip-all verifier in particular is NOT a
//! `ServerNameVerification` mode an operator could select for an encrypted
//! link: on this link it verifies nothing because there is nothing to protect,
//! while on an encrypted one it would silently turn the certificate into
//! decoration.

use std::io;
use std::sync::{Arc, OnceLock};

use bytes::BytesMut;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::crypto::{self, CryptoError};
use quinn::{ConnectError, ConnectionId, Side};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::TransportError;
use tokio_rustls::rustls;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{ring, CryptoProvider};
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use tokio_rustls::rustls::version::TLS13;
use tokio_rustls::rustls::{
    ClientConfig as RustlsClientConfig, ServerConfig as RustlsServerConfig,
};

use crate::quic_config::QUIC_ALPN;
use crate::quic_pipeline::io_other;

/// A key that protects nothing. Wraps the real key only so the one limit that
/// still means something — how many forged packets to tolerate before the
/// connection gives up — keeps the real key's value, as upstream's does.
struct NoOpEncryptionKeys<T>(T);

impl crypto::PacketKey for NoOpEncryptionKeys<Box<dyn crypto::PacketKey>> {
    fn encrypt(&self, _packet: u64, _buf: &mut [u8], _header_len: usize) {}

    fn decrypt(
        &self,
        _packet: u64,
        _header: &[u8],
        _payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    /// No AEAD tag. This is the wire-visible half: a peer that expects the
    /// usual 16 bytes would read the last 16 bytes of every packet as a tag.
    fn tag_len(&self) -> usize {
        0
    }

    /// Nothing is confidential, so there is no reason to rotate keys to
    /// protect confidentiality; upstream sets the maximum for the same reason.
    fn confidentiality_limit(&self) -> u64 {
        u64::MAX
    }

    fn integrity_limit(&self) -> u64 {
        self.0.integrity_limit()
    }
}

impl crypto::HeaderKey for NoOpEncryptionKeys<Box<dyn crypto::HeaderKey>> {
    fn decrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

    fn encrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

    /// No header protection, so no sample: a non-zero size would make quinn
    /// pad short packets to have one, for a mask nobody applies.
    fn sample_size(&self) -> usize {
        0
    }
}

fn no_op_packet_keys(
    keys: crypto::KeyPair<Box<dyn crypto::PacketKey>>,
) -> crypto::KeyPair<Box<dyn crypto::PacketKey>> {
    crypto::KeyPair {
        local: Box::new(NoOpEncryptionKeys(keys.local)),
        remote: Box::new(NoOpEncryptionKeys(keys.remote)),
    }
}

fn no_op_header_keys(
    keys: crypto::KeyPair<Box<dyn crypto::HeaderKey>>,
) -> crypto::KeyPair<Box<dyn crypto::HeaderKey>> {
    crypto::KeyPair {
        local: Box::new(NoOpEncryptionKeys(keys.local)),
        remote: Box::new(NoOpEncryptionKeys(keys.remote)),
    }
}

fn no_op_keys(keys: crypto::Keys) -> crypto::Keys {
    crypto::Keys {
        header: no_op_header_keys(keys.header),
        packet: no_op_packet_keys(keys.packet),
    }
}

/// The rustls session with every key it hands out replaced. The FOUR methods
/// that yield keys are the whole difference — `initial_keys`,
/// `write_handshake`, `next_1rtt_keys` and `early_crypto` — and missing any one
/// leaves that packet space encrypted, which a peer sees as a connection that
/// dies at that phase. Everything else is the TLS session's own answer.
struct PlainTextSession(Box<dyn crypto::Session>);

impl crypto::Session for PlainTextSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> crypto::Keys {
        no_op_keys(self.0.initial_keys(dst_cid, side))
    }

    fn handshake_data(&self) -> Option<Box<dyn std::any::Any>> {
        self.0.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn std::any::Any>> {
        self.0.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        let (header, packet) = self.0.early_crypto()?;
        Some((
            Box::new(NoOpEncryptionKeys(header)),
            Box::new(NoOpEncryptionKeys(packet)),
        ))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.0.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.0.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.0.read_handshake(buf)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.0.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        self.0.write_handshake(buf).map(no_op_keys)
    }

    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        self.0.next_1rtt_keys().map(no_op_packet_keys)
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.0.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), crypto::ExportKeyingMaterialError> {
        self.0.export_keying_material(output, label, context)
    }
}

struct PlainTextClientConfig(Arc<QuicClientConfig>);

impl crypto::ClientConfig for PlainTextClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let tls = self.0.clone().start_session(version, server_name, params)?;
        Ok(Box::new(PlainTextSession(tls)))
    }
}

/// The server side needs its own wrapper and not only the session's: a server
/// derives the Initial keys for a packet BEFORE any session exists, from the
/// config, so a wrapped session alone would still read the first packet as
/// encrypted.
struct PlainTextServerConfig(Arc<QuicServerConfig>);

impl crypto::ServerConfig for PlainTextServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::UnsupportedVersion> {
        self.0.initial_keys(version, dst_cid).map(no_op_keys)
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.0.retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        Box::new(PlainTextSession(
            self.0.clone().start_session(version, params),
        ))
    }
}

/// Trusts every server certificate. Private to this module for the reason the
/// module doc gives. The two signature checks are still REAL, as upstream's
/// are: the peer must prove it holds the key of the certificate it sent, which
/// costs nothing here and keeps rustls's handshake invariants intact.
#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The server's certificate and PKCS#8 key, as DER.
struct SelfSignedCert {
    cert: CertificateDer<'static>,
    key_pkcs8: Vec<u8>,
}

/// ONE certificate per process, as upstream generates it
/// (`io/zenoh-link-commons/src/quic/plaintext.rs` @ `rcgen::generate_simple_self_signed(vec![]).map_err(Into::into);`):
/// it identifies nobody — every client trusts any certificate — so a fresh key
/// per listener would buy nothing and cost a key generation each time. No
/// subject alternative names, also as upstream: there is no name to check.
///
/// A failure is kept, not retried: key generation failing is a property of the
/// process (its RNG, its provider), and every later listener gets the same
/// answer the first one did.
fn self_signed_cert() -> io::Result<&'static SelfSignedCert> {
    static CERT: OnceLock<Result<SelfSignedCert, String>> = OnceLock::new();
    CERT.get_or_init(|| {
        rcgen::generate_simple_self_signed(Vec::<String>::new())
            .map(|certified| SelfSignedCert {
                cert: certified.cert.der().clone(),
                key_pkcs8: certified.key_pair.serialize_der(),
            })
            .map_err(|err| err.to_string())
    })
    .as_ref()
    .map_err(|err| {
        io_other(format!(
            "reliable udp: cannot generate the self-signed QUIC certificate: {err}"
        ))
    })
}

/// The client crypto for a reliable UDP dial: TLS 1.3 with the same ALPN as
/// wz's QUIC link, a verifier that trusts any server, no client certificate,
/// every packet key replaced.
///
/// The ALPN is `QUIC_ALPN` because this IS that link. Upstream offers the
/// mixed-reliability and multi-stream protocols on this variant too, and wz's
/// QUIC offers none of them; that gap belongs to the QUIC link and closes for
/// both at once.
///
/// No key-log sink, unlike the four encrypted builders in `crate::quic_config`:
/// the sink exists to make encrypted traffic readable, and this traffic already
/// is. Upstream's unsecure config sets none either.
pub(crate) fn plaintext_client_crypto() -> io::Result<Arc<dyn crypto::ClientConfig>> {
    let provider = Arc::new(ring::default_provider());
    let mut tls = RustlsClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])
        .map_err(io_other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    let quic = QuicClientConfig::try_from(Arc::new(tls)).map_err(io_other)?;
    Ok(Arc::new(PlainTextClientConfig(Arc::new(quic))))
}

/// The server crypto for a reliable UDP listener: TLS 1.3 presenting the
/// process's self-signed certificate, no client authentication, every packet
/// key replaced — including the Initial keys derived before any session
/// exists (see [`PlainTextServerConfig`]).
pub(crate) fn plaintext_server_crypto() -> io::Result<Arc<dyn crypto::ServerConfig>> {
    let cert = self_signed_cert()?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pkcs8.clone()));
    let mut tls = RustlsServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&TLS13])
        .map_err(io_other)?
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.clone()], key)
        .map_err(io_other)?;
    tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    let quic = QuicServerConfig::try_from(Arc::new(tls)).map_err(io_other)?;
    Ok(Arc::new(PlainTextServerConfig(Arc::new(quic))))
}

// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2798 — reliable UDP (`udp/...?rel=1`): the QUIC stream link under a
//! plaintext session.
//!
//! Upstream builds the variant from the same client and server builders as its
//! QUIC link, with `.security(false)`
//! (`io/zenoh-links/zenoh-link-udp/src/reliability.rs` @ `} = QuicClientBuilder::new(endpoint).security(false).await?;`),
//! so the link it yields is that link: one bidirectional stream, the
//! StreamEnvelope framing, MTU `BatchSize::MAX`. This module is therefore not a
//! pipeline of its own. It hands [`crate::quic_pipeline`]'s dial and listen
//! seams the plaintext crypto from the crate-private `quic_plaintext` in place of the
//! rustls config, and everything after the handshake — accept, the stream,
//! the drivers — is the QUIC link's unchanged.
//!
//! What the caller does NOT supply is certificate material: the server presents
//! a per-process self-signed certificate and the client trusts any, which is
//! why these take no config where [`crate::quic_pipeline::dial_quic`] takes one.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::Endpoint;
use wz_session_core::link::LinkKind;

use crate::link_interfaces::{ip_link_endpoints, ip_link_subject};
use crate::link_socket::LinkSocket;
use crate::quic_pipeline::{
    open_quic_stream, quic_server_endpoint, wire_stream_over_quic, QuicLink, QuicReadDriver,
};
use crate::quic_plaintext::{plaintext_client_crypto, plaintext_server_crypto};
use crate::stream_link::StreamWriteDriver;
use crate::writer_queue::WriterHandle;

/// Dial a reliable UDP link to `addr`: a plaintext QUIC connection and its one
/// bidirectional stream, returned as the same [`QuicLink`] a `quic/...` dial
/// yields. `server_name` is what the TLS handshake names; nothing checks it.
pub async fn dial_udp_reliable(
    addr: SocketAddr,
    server_name: &str,
    link_socket: &LinkSocket<'_>,
) -> io::Result<QuicLink> {
    open_quic_stream(addr, plaintext_client_crypto()?, server_name, link_socket).await
}

/// Bind a reliable UDP listener at `addr`: a plaintext QUIC server endpoint
/// allowing ONE bidirectional stream, as the QUIC link's does. Accept on it
/// with [`crate::quic_pipeline::accept_quic_on`] (or the split
/// `accept_quic_incoming` / `complete_quic_accept` halves): accepting is
/// crypto-agnostic, the endpoint already carries the session.
pub async fn bind_udp_reliable(
    addr: SocketAddr,
    link_socket: &LinkSocket<'_>,
) -> io::Result<Endpoint> {
    quic_server_endpoint(addr, plaintext_server_crypto()?, 1, link_socket).await
}

/// R2810 — wire a dialed or accepted reliable UDP link into the session's
/// drivers: the QUIC stream link's drivers, under the reliable UDP link's OWN
/// name.
///
/// Two things differ from [`crate::quic_pipeline::wire_quic_stream`], and both
/// are what upstream's link reports about itself:
///
/// - The subject's kind is [`LinkKind::UdpReliable`], so a rule sees `udp`
///   (`io/zenoh-links/zenoh-link-udp/src/unicast.rs` @ `&LinkAuthId::Udp`) and
///   zenoh-c sees a reliable stream. And it carries NO certificate common name:
///   the peer's certificate is a throwaway self-signed one that nothing
///   verified, and upstream's `LinkAuthId::Udp` has no field to put one in, so
///   a `cert_common_names` rule must not be answerable from it.
/// - The `{src,dst}` pair is plain `udp/<addr>`, WITHOUT the `rel=1` the
///   listener advertises: upstream builds both ends of this link with
///   `socket_addr_to_udp_locator`, which passes empty metadata
///   (`io/zenoh-links/zenoh-link-udp/src/lib.rs` @ `Locator::new(UDP_LOCATOR_PREFIX, addr.to_string(), "").unwrap()`).
///   The advertised locator and the link's own ends are different strings
///   upstream, and this keeps them different here.
pub fn wire_udp_reliable(link: QuicLink) -> (QuicReadDriver, Arc<StreamWriteDriver>, WriterHandle) {
    let local = link.endpoint.local_addr().ok();
    let subject = ip_link_subject(LinkKind::UdpReliable, local);
    let endpoints = ip_link_endpoints(LinkKind::Udp, local, Some(link.connection.remote_address()));
    wire_stream_over_quic(link, subject, endpoints)
}

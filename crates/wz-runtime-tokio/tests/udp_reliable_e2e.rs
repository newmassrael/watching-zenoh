// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "transport-link-udp-reliable")]

//! R2797 — reliable UDP (`udp/...?rel=1`) puts its bytes on the wire IN THE
//! CLEAR, which is what upstream's variant does and what makes it reachable
//! from upstream at all.
//!
//! A handshake that completes proves nothing here: an ENCRYPTED session
//! completes too. So the witness reads the wire. Every datagram between the
//! two ends passes through a recording relay, and the bytes the application
//! wrote to the stream must appear, contiguous, inside a captured datagram —
//! in both directions, because the client's and the server's keys are wrapped
//! by different objects.
//!
//! The same relay is then run over wz's ENCRYPTED QUIC link, and the same bytes
//! must NOT appear. Without that control, finding the marker could mean the
//! capture sees something other than the wire; with it, the difference between
//! the two runs is the session's keys and nothing else.
//!
//! The third test is the interop half of the claim: a plaintext client cannot
//! reach an ordinary encrypted QUIC server, even with a verifier that would
//! trust its certificate, because the server cannot read a packet that carries
//! no tag and no header protection.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use wz_runtime_tokio::link_socket::LinkSocket;
use wz_runtime_tokio::quic_config::{quic_client_config_from_pem, quic_server_config_from_pem};
use wz_runtime_tokio::quic_pipeline::{
    accept_quic_incoming, accept_quic_on, bind_quic, dial_quic, QuicLink,
};
use wz_runtime_tokio::udp_reliable_pipeline::{bind_udp_reliable, dial_udp_reliable};

/// Written by the client. Long enough that finding it by chance in ciphertext
/// is not a possibility worth discussing, and distinct from [`REPLY`] so each
/// direction is judged on its own bytes.
const REQUEST: &[u8] = b"wz reliable udp: the client's bytes, as written";
/// Written by the server.
const REPLY: &[u8] = b"wz reliable udp: the server's bytes, as written";

const BUDGET: Duration = Duration::from_secs(10);

/// What a [`Relay`] saw, per direction.
#[derive(Default)]
struct Capture {
    to_server: Vec<Vec<u8>>,
    to_client: Vec<Vec<u8>>,
}

fn carries(datagrams: &[Vec<u8>], needle: &[u8]) -> bool {
    datagrams.iter().any(|datagram| {
        datagram
            .windows(needle.len())
            .any(|window| window == needle)
    })
}

/// A UDP relay in front of one server that records every datagram it
/// forwards, in either direction, BEFORE forwarding it — so a datagram the far
/// end has acted on has already been recorded.
struct Relay {
    addr: SocketAddr,
    capture: Arc<Mutex<Capture>>,
    task: JoinHandle<()>,
}

impl Relay {
    async fn start(server: SocketAddr) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind relay front");
        let back = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind relay back");
        back.connect(server).await.expect("connect relay back");
        let addr = front.local_addr().expect("relay front addr");
        let capture = Arc::new(Mutex::new(Capture::default()));
        let log = capture.clone();
        let task = tokio::spawn(async move {
            let mut client = None;
            let mut up = vec![0u8; 65_535];
            let mut down = vec![0u8; 65_535];
            loop {
                tokio::select! {
                    received = front.recv_from(&mut up) => {
                        let Ok((len, from)) = received else { return };
                        client = Some(from);
                        log.lock().expect("capture lock").to_server.push(up[..len].to_vec());
                        let _ = back.send(&up[..len]).await;
                    }
                    received = back.recv(&mut down) => {
                        let Ok(len) = received else { return };
                        log.lock().expect("capture lock").to_client.push(down[..len].to_vec());
                        if let Some(client) = client {
                            let _ = front.send_to(&down[..len], client).await;
                        }
                    }
                }
            }
        });
        Self {
            addr,
            capture,
            task,
        }
    }

    fn finish(self) -> Capture {
        self.task.abort();
        std::mem::take(&mut *self.capture.lock().expect("capture lock"))
    }
}

/// The server's half: accept the one stream, read the client's bytes, answer.
/// Returns the link so the connection outlives the client's read of the reply.
async fn answer(mut link: QuicLink) -> QuicLink {
    let mut request = vec![0u8; REQUEST.len()];
    link.recv
        .read_exact(&mut request)
        .await
        .expect("server reads the request");
    assert_eq!(
        request, REQUEST,
        "the server received what the client wrote"
    );
    link.send
        .write_all(REPLY)
        .await
        .expect("server writes the reply");
    link
}

/// The client's half: write, then read the answer.
async fn ask(mut link: QuicLink) -> QuicLink {
    link.send
        .write_all(REQUEST)
        .await
        .expect("client writes the request");
    let mut reply = vec![0u8; REPLY.len()];
    link.recv
        .read_exact(&mut reply)
        .await
        .expect("client reads the reply");
    assert_eq!(reply, REPLY, "the client received what the server wrote");
    link
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reliable_udp_carries_the_stream_bytes_in_the_clear_both_ways() {
    let endpoint = bind_udp_reliable(
        "127.0.0.1:0".parse().expect("loopback addr"),
        &LinkSocket::NONE,
    )
    .await
    .expect("bind reliable udp listener");
    let relay = Relay::start(endpoint.local_addr().expect("listener addr")).await;

    let exchange = async {
        let server = tokio::spawn({
            let endpoint = endpoint.clone();
            async move { answer(accept_quic_on(&endpoint).await.expect("accept")).await }
        });
        let client = dial_udp_reliable(relay.addr, "127.0.0.1", &LinkSocket::NONE)
            .await
            .expect("dial reliable udp through the relay");
        let client = ask(client).await;
        (client, server.await.expect("server task"))
    };
    let _links = tokio::time::timeout(BUDGET, exchange)
        .await
        .expect("the exchange completes within the budget");

    let capture = relay.finish();
    assert!(
        carries(&capture.to_server, REQUEST),
        "the client's bytes must be on the wire as written; {} datagrams to the server, none \
         carries them",
        capture.to_server.len()
    );
    assert!(
        carries(&capture.to_client, REPLY),
        "the server's bytes must be on the wire as written; {} datagrams to the client, none \
         carries them",
        capture.to_client.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_encrypted_quic_link_through_the_same_relay_hides_the_same_bytes() {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed localhost cert");
    let cert_pem = issued.cert.pem();
    let key_pem = issued.key_pair.serialize_pem();
    let server_config = quic_server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), None)
        .expect("build quic server config");
    let client_config = quic_client_config_from_pem(Some(cert_pem.as_bytes()), None)
        .expect("build quic client config");

    let endpoint = bind_quic(
        "127.0.0.1:0".parse().expect("loopback addr"),
        server_config,
        &LinkSocket::NONE,
    )
    .await
    .expect("bind quic listener");
    let relay = Relay::start(endpoint.local_addr().expect("listener addr")).await;

    let exchange = async {
        let server = tokio::spawn({
            let endpoint = endpoint.clone();
            async move { answer(accept_quic_on(&endpoint).await.expect("accept")).await }
        });
        let client = dial_quic(relay.addr, client_config, "localhost", &LinkSocket::NONE)
            .await
            .expect("dial quic through the relay");
        let client = ask(client).await;
        (client, server.await.expect("server task"))
    };
    let _links = tokio::time::timeout(BUDGET, exchange)
        .await
        .expect("the exchange completes within the budget");

    let capture = relay.finish();
    // The exchange above DELIVERED both messages, so the relay did carry them;
    // it just could not read them.
    assert!(
        !capture.to_server.is_empty() && !capture.to_client.is_empty(),
        "the relay recorded traffic both ways"
    );
    assert!(
        !carries(&capture.to_server, REQUEST),
        "an encrypted session must not show the client's bytes to the relay"
    );
    assert!(
        !carries(&capture.to_client, REPLY),
        "an encrypted session must not show the server's bytes to the relay"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plaintext_client_cannot_reach_an_encrypted_quic_server() {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed localhost cert");
    let server_config = quic_server_config_from_pem(
        issued.cert.pem().as_bytes(),
        issued.key_pair.serialize_pem().as_bytes(),
        None,
    )
    .expect("build quic server config");
    let endpoint = bind_quic(
        "127.0.0.1:0".parse().expect("loopback addr"),
        server_config,
        &LinkSocket::NONE,
    )
    .await
    .expect("bind quic listener");
    let addr = endpoint.local_addr().expect("listener addr");

    // The server must be ACCEPTING, or this test proves nothing: quinn answers
    // no connection attempt until the endpoint is accepted on, so an idle
    // endpoint times ANY client out, compatible or not. The first draft of this
    // test did exactly that, and stayed green with the no-op keys removed —
    // which is how it was found.
    //
    // It keeps accepting, too. quinn yields an attempt BEFORE authenticating
    // its payload — the payload check fails later, inside the handshake — so a
    // server that accepted once and stopped would leave every retransmission
    // unanswered for the same reason as an idle one. And a connection it does
    // complete is HELD, so a compatible client is not raced by the server
    // dropping what it accepted.
    let server = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            let mut held = Vec::new();
            while let Ok(incoming) = accept_quic_incoming(&endpoint).await {
                if let Ok(connection) = incoming.await {
                    held.push(connection);
                }
            }
        }
    });

    // The plaintext client trusts ANY certificate, so the outcome cannot be a
    // certificate refusal: the server never gets as far as sending a
    // certificate, because it cannot read the client's first packet and drops
    // it without answering. SILENCE is therefore the one expected outcome, and
    // an early error is a failure of this test rather than a pass — it would
    // mean the dial died of something else before it reached the wire. The
    // same dial against a plaintext server connects, which the first test in
    // this file shows.
    let dial = dial_udp_reliable(addr, "localhost", &LinkSocket::NONE);
    match tokio::time::timeout(Duration::from_secs(3), dial).await {
        Err(_elapsed) => {}
        Ok(Err(err)) => panic!("the dial failed before the server could ignore it: {err}"),
        Ok(Ok(_)) => panic!("a plaintext client reached an encrypted QUIC server"),
    }
    server.abort();
}

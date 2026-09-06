// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y474 — the adminspace `{src,dst}` LOCATOR PAIR of the four link pipelines
//! R311y473 left reporting nothing: udp, quic-datagram, serial and unixpipe.
//!
//! R311y473 wired `sessions[].links` into both wz admin hosts, but
//! `BoxedLinkDriver::link_endpoints` has a `None` default, so those four
//! transports rendered a link with blank `{src,dst}` — the aggregation COUNT was
//! right, the strings were not. Its carry named the gap; this is the witness for
//! closing it.
//!
//! # Why the assertions are shaped this way
//!
//! Reading one driver's pair back and comparing it against a string this test also
//! wrote would prove only that wz agrees with itself. Every leg here instead binds
//! the property to something the emitter does not control:
//!
//! 1. **The MIRROR property** (udp / unixpipe). Both ends of a real link are wired,
//!    and neither end is ever told the other's `src`: the dialer learns only the
//!    address it dials, and the acceptor learns only the peer its own kernel (or
//!    FIFO handshake) reports. So `dialer.src == acceptor.dst` and
//!    `dialer.dst == acceptor.src` is a cross-check between two independently
//!    resolved answers. A pipeline that duplicated one end into both fields, or
//!    swapped them, cannot satisfy it.
//!
//!    It does NOT hold on quic-datagram, and that is a property of the transport
//!    rather than a defect: a QUIC client's endpoint is bound to
//!    `UNSPECIFIED:0` and quinn's `Connection::local_ip` answers `None` on the
//!    initiating side, so the client's own `src` can only be its wildcard bind —
//!    which is verbatim what zenoh publishes there
//!    (`zenoh-link-quic_datagram/src/unicast.rs:255-292`). That leg asserts the half
//!    that does mirror plus a PORT-level cross-check on the half that cannot, and a
//!    second leg proves the `local_ip` preference is load-bearing where quinn DOES
//!    know the answer.
//! 2. **Parse-back** (all four). Every emitted string must round-trip through
//!    `parse_any_locator` — wz's own dial-side parser, a different module written
//!    against pico's grammar. This is the R311y470 contract: that round shipped two
//!    advertise sites whose scheme no peer, and in one case not even wz's parser,
//!    could dial. An admin surface a foreign client reads inherits it.
//! 3. **The filesystem** (unixpipe). The two parsed paths must be FIFO nodes that
//!    exist on disk — a source that is not wz code at all.
//! 4. **Both target variants** (serial). A serial link's address is not readable
//!    off the stream, so there is no mirror to check; instead each end is given a
//!    DISTINCT endpoint — one `Device`, one `Pins` — and must report its own,
//!    parsed back to the exact `SerialEndpoint` value. A pipeline that hard-coded
//!    either spelling fails on the other.
//!
//! Each test drives the REAL seam for its transport (`bind_endpoint` /
//! `accept_raw` / `dial_locator`, or the pipeline's own bind/dial pair), not a
//! hand-assembled driver, so what is asserted is what a session actually gets.

// Every leg needs `transport-unicast` (the bind / dial / wire seams live behind it)
// plus its own link feature, so with none of them armed the file has no tests and
// its shared helpers would be dead code. Gating the FILE rather than allow-ing the
// warnings keeps a genuinely unused helper visible.
#![cfg(all(
    feature = "transport-unicast",
    any(
        feature = "transport-link-udp",
        feature = "transport-link-serial",
        feature = "transport-link-unixpipe",
        feature = "transport-link-quic-datagram",
    )
))]

use wz_session_core::link::{LinkEndpoints, LinkSendOutcome};
use wz_session_core::locator::{parse_any_locator, AnyLocator};

/// Assert both halves of `pair` parse back through wz's own dial-side parser.
/// Returns the two parsed locators so a caller can compare them against an
/// independent address source rather than against the strings.
fn parse_back_both_ends(pair: &LinkEndpoints, what: &str) -> (AnyLocator, AnyLocator) {
    let src = parse_any_locator(&pair.src).unwrap_or_else(|e| {
        panic!(
            "{what}: src {:?} must be a DIALABLE locator, but wz's own parser \
             rejects it ({e:?}) — the R311y470 defect",
            pair.src
        )
    });
    let dst = parse_any_locator(&pair.dst).unwrap_or_else(|e| {
        panic!(
            "{what}: dst {:?} must be a DIALABLE locator, but wz's own parser \
             rejects it ({e:?}) — the R311y470 defect",
            pair.dst
        )
    });
    (src, dst)
}

/// Assert the two ends of one link name the same two locators in mirrored order.
/// Neither end was told the other's `src`, so this compares two independently
/// resolved answers. Only udp and unixpipe mirror exactly — see the module header
/// for why quic-datagram cannot, and the serial leg for why it has no mirror at all.
#[cfg(any(feature = "transport-link-udp", feature = "transport-link-unixpipe"))]
fn assert_mirrored(dialer: &LinkEndpoints, acceptor: &LinkEndpoints, what: &str) {
    assert_eq!(
        dialer.src, acceptor.dst,
        "{what}: the dialer's src must be exactly what the acceptor calls its dst \
         (dialer {dialer:?} vs acceptor {acceptor:?})"
    );
    assert_eq!(
        dialer.dst, acceptor.src,
        "{what}: the dialer's dst must be exactly what the acceptor calls its src \
         (dialer {dialer:?} vs acceptor {acceptor:?})"
    );
    assert_ne!(
        dialer.src, dialer.dst,
        "{what}: a link's two ends are distinct, so reporting one address twice is \
         the duplicated-end defect this pair exists to catch ({dialer:?})"
    );
}

// ───────────────────────── udp ─────────────────────────

/// A UDP session's two faces — the dialer's own socket and the acceptor's demux
/// face on the shared listener socket — report mirrored locator pairs.
///
/// Both `wire_udp_socket` (dial) and `wire_udp_demuxed` (accept) are exercised,
/// which is the whole udp surface: they are the two sites that construct a
/// `UdpWriteDriver`. The ports are kernel-assigned (`:0` on both sides), so no
/// address in the assertion is a constant this test chose.
#[cfg(all(feature = "transport-link-udp", feature = "transport-unicast"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_dial_and_demux_faces_report_mirrored_endpoints() {
    use wz_runtime_tokio::session_open::{
        bind_endpoint, dial_locator, wire_dialed_link, DialConfig,
    };
    use wz_runtime_tokio::Reliability;

    let mut bound = bind_endpoint("udp/127.0.0.1:0")
        .await
        .expect("bind a udp listener on an ephemeral loopback port");
    let listen_addr = bound.local_addr().expect("the listener's assigned address");

    // Dial the listener. The dialer binds its OWN ephemeral socket; it is told
    // `listen_addr` and nothing else.
    let locator =
        parse_any_locator(&format!("udp/{listen_addr}")).expect("parse the udp dial locator");
    let dialed = dial_locator(locator, &DialConfig::default())
        .await
        .expect("dial the udp listener");
    let (_dial_in, dial_out, _dial_h) = wire_dialed_link(dialed);

    // UDP has no `accept()`: the demux pump learns a peer only from a datagram, so
    // the dialer must speak before the acceptor exists.
    //
    // R2371 — the outcome is ASSERTED rather than discarded. This probe is what
    // the whole test depends on reaching the acceptor, so a driver that refused
    // it used to fail the test five seconds later at the accept timeout, with
    // nothing saying why. The `#[must_use]` on `LinkSendOutcome` is what surfaced
    // this call site.
    assert_eq!(
        dial_out.send_blocking(b"probe", Reliability::BestEffort),
        LinkSendOutcome::Sent,
        "the udp driver must accept the probe that teaches the demux pump this peer"
    );

    let (accepted, _peer) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        bound.accept_raw().await
    })
    .await
    .expect("the demux pump surfaces the new src within 5s")
    .expect("accept_raw yields the demux face");
    let (_acc_in, acc_out, _acc_h) = wire_dialed_link(
        accepted
            .handshake()
            .await
            .expect("a udp demux face needs no post-accept handshake"),
    );

    let dial_pair = dial_out
        .link_endpoints()
        .expect("the udp DIAL face must report its endpoints")
        .clone();
    let acc_pair = acc_out
        .link_endpoints()
        .expect("the udp DEMUX face must report its endpoints")
        .clone();

    assert_mirrored(&dial_pair, &acc_pair, "udp");
    let (dial_src, dial_dst) = parse_back_both_ends(&dial_pair, "udp dial face");
    parse_back_both_ends(&acc_pair, "udp demux face");

    // Independent source: the LISTENER's own address, read off the bound listener
    // the driver never saw. The dialer's dst must be it; its src must not.
    match (dial_src, dial_dst) {
        (AnyLocator::Ip(src), AnyLocator::Ip(dst)) => {
            assert_eq!(
                dst.addr, listen_addr,
                "the dialer's dst must be the address the listener reports for itself"
            );
            assert_ne!(
                src.addr, listen_addr,
                "the dialer's src is its OWN ephemeral socket, not the listener's"
            );
        }
        other => panic!("a udp locator must parse as an IP locator; got {other:?}"),
    }
}

// ───────────────────── quic-datagram ─────────────────────

/// Bring up one real quic-datagram link and return `(dialer pair, acceptor pair,
/// server addr)`. `bind_at` is the SERVER endpoint's bind address, which the two
/// legs below vary — that is the whole difference between them.
#[cfg(all(
    feature = "transport-link-quic-datagram",
    feature = "transport-unicast"
))]
async fn quic_datagram_link_pair(
    bind_at: &str,
) -> (LinkEndpoints, LinkEndpoints, std::net::SocketAddr) {
    use wz_runtime_tokio::quic_config::{quic_client_config_from_pem, quic_server_config_from_pem};
    use wz_runtime_tokio::quic_datagram_pipeline::{
        accept_quic_datagram_on, bind_quic_datagram, dial_quic_datagram, wire_quic_datagram,
    };
    // A concrete write driver, so the trait must be in scope to call through it (the
    // udp leg needs no such import: `wire_dialed_link` hands back a trait object).
    use wz_session_core::link::BoxedLinkDriver;

    // Self-signed `localhost` cert through the production config builders — the
    // quic_e2e / quic_datagram_e2e pattern (the leaf is its own trust anchor).
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate a self-signed localhost cert");
    let cert_pem = issued.cert.pem();
    let key_pem = issued.key_pair.serialize_pem();
    let server_config = quic_server_config_from_pem(cert_pem.as_bytes(), key_pem.as_bytes(), None)
        .expect("build the quic server config");
    let client_config = quic_client_config_from_pem(cert_pem.as_bytes(), None)
        .expect("build the quic client config");

    let endpoint = bind_quic_datagram(
        bind_at.parse().expect("server bind address"),
        server_config,
        None,
    )
    .expect("bind the quic-datagram server endpoint");
    let bound = endpoint
        .local_addr()
        .expect("the endpoint's assigned address");
    // A wildcard-bound endpoint is dialled on loopback: the port is the endpoint's,
    // the address is the one that actually reaches it.
    let dial_at = std::net::SocketAddr::new("127.0.0.1".parse().expect("loopback"), bound.port());

    let (accepted, dialed) = tokio::join!(
        async {
            accept_quic_datagram_on(&endpoint)
                .await
                .expect("accept the inbound quic-datagram connection")
        },
        async {
            dial_quic_datagram(dial_at, client_config, "localhost", None)
                .await
                .expect("dial the quic-datagram endpoint")
        }
    );
    let (_acc_in, acc_out, _acc_h) = wire_quic_datagram(accepted);
    let (_dial_in, dial_out, _dial_h) = wire_quic_datagram(dialed);

    let dial_pair = dial_out
        .link_endpoints()
        .expect("the quic-datagram DIAL end must report its endpoints")
        .clone();
    let acc_pair = acc_out
        .link_endpoints()
        .expect("the quic-datagram ACCEPT end must report its endpoints")
        .clone();
    (dial_pair, acc_pair, dial_at)
}

/// A QUIC-datagram link's two ends agree on the link, and every locator carries the
/// `?rel=0` datagram marker that makes the string dial the DATAGRAM transport rather
/// than its reliable sibling.
///
/// That marker is the R311y470 lesson in this transport specifically: `quic/` alone
/// names the stream backend, so an admin client handed the bare spelling would dial
/// the wrong link type.
///
/// The full mirror is NOT asserted, and the module header says why: quinn's
/// `Connection::local_ip` is `None` on the initiating side, so a client's own `src`
/// can only be its `UNSPECIFIED:0` bind — verbatim what zenoh publishes there
/// (`zenoh-link-quic_datagram/src/unicast.rs:255-292`). What IS asserted is the half
/// that mirrors exactly, plus the PORT of the half that cannot: the acceptor learned
/// that port from the QUIC handshake and the dialer from its own endpoint, so the two
/// are still independently resolved.
#[cfg(all(
    feature = "transport-link-quic-datagram",
    feature = "transport-unicast"
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_datagram_link_ends_agree_on_the_link_and_carry_rel0() {
    let (dial_pair, acc_pair, dial_at) = quic_datagram_link_pair("127.0.0.1:0").await;

    parse_back_both_ends(&dial_pair, "quic-datagram dial end");
    parse_back_both_ends(&acc_pair, "quic-datagram accept end");

    for locator in [&dial_pair.src, &dial_pair.dst, &acc_pair.src, &acc_pair.dst] {
        assert!(
            locator.contains("?rel=0"),
            "a quic-datagram locator MUST carry the ?rel=0 datagram marker, else it \
             names the reliable quic transport (R311y470); got {locator:?}"
        );
    }

    // The half that mirrors exactly: the server address. The acceptor read it off
    // its own quinn endpoint; the dialer was handed it.
    assert_eq!(
        dial_pair.dst, acc_pair.src,
        "the dialer's dst must be exactly what the acceptor calls its src \
         (dialer {dial_pair:?} vs acceptor {acc_pair:?})"
    );
    assert_eq!(
        acc_pair.src,
        format!("quic/{dial_at}?rel=0"),
        "the acceptor's src must be the address its own quinn endpoint reports"
    );

    // The half that cannot mirror: the CLIENT's ephemeral socket. Its port is still
    // a cross-check — the acceptor learned it from the handshake, not from wz.
    let client_port = client_port_of(&acc_pair.dst);
    assert_eq!(
        dial_pair.src,
        format!("quic/0.0.0.0:{client_port}?rel=0"),
        "the client's own src is its UNSPECIFIED bind carrying the port the \
         acceptor independently observed — upstream's shape verbatim"
    );
}

/// The `local_ip` preference is LOAD-BEARING, not defensive: with the server
/// endpoint bound to the WILDCARD, its own `local_addr` is `0.0.0.0:<port>`, so the
/// acceptor's `src` can only be concrete if it came from `Connection::local_ip`.
///
/// This is the leg that discriminates the branch. zenoh has no counterpart — it
/// publishes `quic_endpoint.local_addr()` unconditionally
/// (`zenoh-link-quic_datagram/src/unicast.rs:292`), so a wildcard-listening zenoh
/// router reports `quic/0.0.0.0:<port>?rel=0` as its own src. A wildcard listen is
/// the ordinary router deploy, not a corner, which is why wz diverges upward here
/// rather than reproducing it.
#[cfg(all(
    feature = "transport-link-quic-datagram",
    feature = "transport-unicast"
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_datagram_acceptor_on_a_wildcard_bind_reports_a_concrete_src() {
    let (dial_pair, acc_pair, dial_at) = quic_datagram_link_pair("0.0.0.0:0").await;

    assert_eq!(
        acc_pair.src,
        format!("quic/{dial_at}?rel=0"),
        "the endpoint is bound to 0.0.0.0, so a src of {:?} can only have come from \
         Connection::local_ip — reporting the bind would give the wildcard",
        acc_pair.src
    );
    assert!(
        !acc_pair.src.starts_with("quic/0.0.0.0"),
        "a wildcard src is not a dialable locator; got {:?}",
        acc_pair.src
    );
    // And the link still mirrors on the half that can.
    assert_eq!(
        dial_pair.dst, acc_pair.src,
        "the dialer dialled exactly the address the acceptor now names as its src"
    );
}

/// The port span of a `quic/<ip>:<port>?rel=0` locator.
#[cfg(all(
    feature = "transport-link-quic-datagram",
    feature = "transport-unicast"
))]
fn client_port_of(locator: &str) -> u16 {
    match parse_any_locator(locator).expect("the acceptor's dst parses") {
        AnyLocator::Ip(ip) => ip.addr.port(),
        other => panic!("a quic locator must parse as an IP locator; got {other:?}"),
    }
}

// ───────────────────────── unixpipe ─────────────────────────

/// A unixpipe link's two ends report mirrored locator pairs naming the DEDICATED
/// per-link FIFO nodes — and both nodes exist on disk as FIFOs.
///
/// This closes R311y473's named unixpipe residual by correcting its premise. That
/// note said the pair could not be named because the rendezvous BASE path belongs
/// to the acceptor rather than the link. Upstream does not use the base either: it
/// renders the dedicated pair, `src` = the FIFO this end reads and `dst` = the one
/// it writes, on both sides — the listener at
/// `io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs`
/// @ `let mut dedicated_downlink = PipeW::new(&dedicated_downlink_path).await?;`
/// and the client at
/// `io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs`
/// @ `dedicated_donlink_path`. Both nodes are known to both ends.
/// (R2363 re-anchored this: it was root-less with line numbers, which the
/// citation gate could not see until this round's own citations made that
/// segment derivable.)
///
/// The filesystem check is the point: a path that parses but does not exist is a
/// string an admin client cannot act on, and no wz code is consulted to decide it.
#[cfg(all(
    feature = "transport-link-unixpipe",
    feature = "transport-unicast",
    target_os = "linux"
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unixpipe_link_ends_report_mirrored_dedicated_fifo_endpoints() {
    use std::os::unix::fs::FileTypeExt;
    use wz_runtime_tokio::unixpipe_pipeline::{bind_unixpipe, dial_unixpipe, wire_unixpipe_stream};
    use wz_session_core::link::BoxedLinkDriver;

    let base = std::env::temp_dir()
        .join(format!("wz-y474-endpoints-{}", std::process::id()))
        .to_string_lossy()
        .into_owned();

    let mut acceptor = bind_unixpipe(&base, None)
        .await
        .expect("bind the unixpipe rendezvous channel");

    let (accepted, dialed) = tokio::join!(
        async {
            tokio::time::timeout(std::time::Duration::from_secs(10), acceptor.recv_new_link())
                .await
                .expect("the acceptor completes its handshake within 10s")
                .expect("the acceptor yields a connected link")
        },
        async {
            dial_unixpipe(&base, None)
                .await
                .expect("dial the unixpipe rendezvous channel")
        }
    );
    let (_acc_in, acc_out, _acc_h) = wire_unixpipe_stream(accepted);
    let (_dial_in, dial_out, _dial_h) = wire_unixpipe_stream(dialed);

    let dial_pair = dial_out
        .link_endpoints()
        .expect("the unixpipe DIAL end must report its endpoints")
        .clone();
    let acc_pair = acc_out
        .link_endpoints()
        .expect("the unixpipe ACCEPT end must report its endpoints")
        .clone();

    assert_mirrored(&dial_pair, &acc_pair, "unixpipe");
    let (dial_src, dial_dst) = parse_back_both_ends(&dial_pair, "unixpipe dial end");
    parse_back_both_ends(&acc_pair, "unixpipe accept end");

    // Neither end may report the rendezvous BASE: the base is not a link, and two
    // concurrent links on one base would then be indistinguishable.
    for locator in [&dial_pair.src, &dial_pair.dst] {
        assert_ne!(
            locator.as_str(),
            format!("unixpipe/{base}"),
            "a unixpipe link must name its DEDICATED node, not the rendezvous base"
        );
    }

    // The filesystem is the independent source: both parsed paths must be live
    // FIFO nodes while the link is up.
    for (which, parsed) in [("src", dial_src), ("dst", dial_dst)] {
        let path = match parsed {
            AnyLocator::Unixpipe(ep) => ep.path,
            other => panic!("a unixpipe locator must parse as Unixpipe; got {other:?}"),
        };
        let meta = std::fs::metadata(&path).unwrap_or_else(|e| {
            panic!("unixpipe {which} {path:?} must exist on disk while the link is up ({e})")
        });
        assert!(
            meta.file_type().is_fifo(),
            "unixpipe {which} {path:?} must be a FIFO node, not {:?}",
            meta.file_type()
        );
    }
}

// ───────────────────────── serial ─────────────────────────

/// Each end of a serial link reports ITS OWN tty locator, round-tripping back to
/// the exact `SerialEndpoint` that opened it — for both address forms of the
/// grammar, a `Device` path and a `Pins` pair.
///
/// There is no mirror to check here: `SerialStream::pair()` exposes no device name
/// and a tty's address is not readable off the stream, so each end is given its
/// endpoint the way the real dial path is given the one it parsed. Handing the two
/// ends DIFFERENT endpoints is what keeps that non-vacuous, and covering both
/// `SerialTarget` variants is what catches an emitter that hard-codes one spelling.
///
/// Both ends reporting the same locator for `src` and `dst` is upstream's DIAL-side
/// behaviour verbatim (`zenoh-link-serial/src/unicast.rs:310-315` passes its one
/// `path` as both), so `assert_mirrored`'s distinctness rule does not apply.
#[cfg(all(feature = "transport-link-serial", feature = "transport-unicast"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serial_link_ends_report_their_own_endpoint_for_both_address_forms() {
    use tokio_serial::SerialStream;
    use wz_runtime_tokio::serial_pipeline::wire_serial_stream;
    use wz_session_core::link::BoxedLinkDriver;
    use wz_session_core::locator::{SerialEndpoint, SerialTarget};

    let device_end = SerialEndpoint {
        target: SerialTarget::Device("/dev/ttyUSB0".to_string()),
        baudrate: 115_200,
    };
    let pins_end = SerialEndpoint {
        target: SerialTarget::Pins { tx: 12, rx: 13 },
        baudrate: 9_600,
    };

    let (a, b) = SerialStream::pair().expect("openpty serial pair");
    let (_a_in, a_out, _a_h) = wire_serial_stream(a, &device_end);
    let (_b_in, b_out, _b_h) = wire_serial_stream(b, &pins_end);

    for (expected, driver, which) in [(&device_end, &a_out, "Device"), (&pins_end, &b_out, "Pins")]
    {
        let pair = driver
            .link_endpoints()
            .unwrap_or_else(|| panic!("the serial {which} end must report its endpoints"))
            .clone();
        let (src, dst) = parse_back_both_ends(&pair, &format!("serial {which} end"));
        for (half, parsed) in [("src", src), ("dst", dst)] {
            match parsed {
                AnyLocator::Serial(round_tripped) => assert_eq!(
                    &round_tripped, expected,
                    "the serial {which} end's {half} must parse back to the endpoint \
                     that opened the link, not to a lossy rendering of it"
                ),
                other => panic!("a serial locator must parse as Serial; got {other:?}"),
            }
        }
    }

    // The two ends must not collapse onto one string: each reports its own tty.
    assert_ne!(
        a_out.link_endpoints().expect("Device end reports").src,
        b_out.link_endpoints().expect("Pins end reports").src,
        "each serial end reports ITS OWN endpoint, so two different endpoints \
         cannot render the same locator"
    );
}

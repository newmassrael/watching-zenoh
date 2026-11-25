// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host profile's WebSocket links: the host's TCP connections, clock and entropy as what
//! `wz_runtime_coop::ws_link` opens its `ws/` links with (`PosixWsOpen`). The handshake and
//! the framing are that module's; a client's key and the seed of its mask keys are drawn from the
//! kernel's CSPRNG ([`PosixEntropy`](crate::PosixEntropy)) at each dial.

wz_runtime_coop::with_heap_link_seams! {
    use wz_runtime_coop::ws_link::{WsLinks, WsOpen, WsSource};
    use wz_runtime_coop::ClockSource;
    use wz_session_core::entropy::{EntropySource, EntropyUnavailable};

    use crate::stream::PosixTcpDial;

    /// The host's TCP connections, clock and entropy as a stack's WebSocket links open them.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct PosixWsOpen;

    impl WsOpen for PosixWsOpen {
        type Dial = PosixTcpDial;

        fn stream_dial(&self) -> &PosixTcpDial {
            &PosixTcpDial
        }
    }

    impl WsSource for PosixWsOpen {
        fn now_us(&self) -> u64 {
            crate::PosixClock.now_us()
        }

        fn fill_entropy(&self, out: &mut [u8]) -> Result<(), EntropyUnavailable> {
            crate::PosixEntropy.try_fill_bytes(out)
        }
    }

    /// The links of a stack `S` with WebSocket links over the host's TCP connections beside them:
    /// what a cooperative engine on this host dials and listens on `ws/` locators with
    /// (`PosixWsLinks::<S>::new(links, PosixWsOpen, handshakes)`).
    pub type PosixWsLinks<S, N = wz_runtime_coop::link_cells::OneTask> = WsLinks<S, PosixWsOpen, N>;
}

wz_runtime_coop::with_heap_link_seams! {
    #[cfg(test)]
    mod tests {
        use super::*;
        use core::net::{IpAddr, Ipv4Addr, SocketAddr};

        use wz_runtime_coop::session_drive::{
            Locator, PendingDial, SessionDatagramLink, SessionLinks,
        };
        use wz_session_core::link::LinkEndsText;
        use wz_session_core::reliability::Reliability;

        use crate::links::PosixLinks;

        const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

        /// A dial and a listener of the host's links on its loopback upgrade one connection between
        /// them, each link names itself a WebSocket, and a batch the client sends arrives whole at
        /// the server. Turned red by an opener that dials no connection, draws no entropy, or keeps
        /// no time, or by a listener the dial cannot reach.
        #[test]
        fn a_dial_and_a_listener_upgrade_a_loopback_connection() {
            let links = PosixWsLinks::new(PosixLinks::new(LOOPBACK, PosixTcpDial), PosixWsOpen, 1);
            let listener = links
                .open_listener(Locator::ws(SocketAddr::new(LOOPBACK, 0)))
                .expect("a listener");
            let port = listener
                .local()
                .as_ws()
                .expect("a ws/ listener")
                .at
                .port();
            assert_ne!(port, 0, "the port the host chose");
            let mut dial = links
                .begin_initiator(Locator::ws(SocketAddr::new(LOOPBACK, port)))
                .expect("a dial begun");
            let (mut client, mut server) = (None, None);
            for _ in 0..2_000 {
                if client.is_none() {
                    client = dial.poll().map(|made| made.expect("upgraded"));
                }
                if server.is_none() {
                    server = listener.accept().expect("no failure");
                }
                if client.is_some() && server.is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let (client, server) = (client.expect("the client"), server.expect("the server"));
            let ends = client.sink.link_endpoints().expect("both ends");
            assert_eq!(ends.dst.as_str(), std::format!("ws/127.0.0.1:{port}"));
            let ends = server.sink.link_endpoints().expect("both ends");
            assert_eq!(ends.src.as_str(), std::format!("ws/127.0.0.1:{port}"));

            client.sink.send_blocking(b"zenoh", Reliability::Reliable);
            let mut got = None;
            for _ in 0..2_000 {
                server
                    .pump
                    .recv_with(&mut |bytes| got = Some(std::vec::Vec::from(bytes)));
                if got.is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            assert_eq!(got.as_deref(), Some(&b"zenoh"[..]));
        }
    }
}

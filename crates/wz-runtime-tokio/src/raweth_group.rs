// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! Open-debt item 911 — a multicast group over raw Ethernet: the link zenoh-pico's raweth
//! transport runs a multicast session over (`vendor/zenoh-pico/src/transport/raweth/`), as a
//! [`MulticastLinkDriver`](crate::multicast_glue::MulticastLinkDriver) the group face drives
//! like a UDP group.
//!
//! What pico does on it, and so what this link does:
//!
//! - every frame carries ONE zenoh datagram behind pico's 16- or 20-byte header
//!   ([`wz_session_core::raweth_link`]), and each goes to the destination the endpoint's
//!   `mapping` gives the key of the message it carries, the first entry when it carries none
//!   or a key no entry meets (`vendor/zenoh-pico/src/transport/raweth/tx.c` @
//!   `_Z_CLEAN_RETURN_IF_ERR(_zp_raweth_set_socket(keyexpr, &ztm->_common._link->_socket._raweth),`);
//! - a frame from a source the `whitelist` does not name is dropped, and a member is the source
//!   MAC its frames come from (`vendor/zenoh-pico/src/link/transport/udp/raweth_unix.c` @
//!   `(void)memcpy((uint8_t *)addr->start, (header_addr + ETH_ALEN), sizeof(ETH_ALEN));`);
//! - nothing filters on the ethertype: the socket takes every frame of the interface
//!   (`ETH_P_ALL`), and what does not deframe is not zenoh;
//! - a datagram holds the frame less its header, `min(1514, batch)` in all
//!   (`_ZP_MAX_ETH_FRAME_SIZE`), while the JOIN advertises the group's batch.
//!
//! The group's members are keyed by address, as on UDP; a source MAC is given the IPv6
//! link-local address its modified EUI-64 makes (RFC 4291 appendix A), which is unique per MAC
//! and names it in a member listing.
//!
//! The socket is behind [`RawEthCarrier`](crate::raweth_group::RawEthCarrier): `AF_PACKET`
//! needs `CAP_NET_RAW`, which an unprivileged run does not have, and the link above it is the
//! same over any carrier of whole frames
//! ([`AfPacketCarrier`](crate::raweth_group::AfPacketCarrier) is the one a session opens).

use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
#[cfg(feature = "reassembly")]
use std::sync::Mutex;

use tokio::io::unix::AsyncFd;
use wz_packet_socket::raweth_socket::AfPacketSocket;
use wz_session_core::link::{LinkEvent, LostCause, RxFrame, TxFrame};
use wz_session_core::raweth_link::{
    deframe, frame, leading_message_key, RawEthHeader, RethLocator, ETH_HEADER_LEN,
    ETH_VLAN_HEADER_LEN, MAC_LEN, MAX_ETH_FRAME_SIZE,
};
use wz_session_core::reliability::Reliability;

use crate::multicast_glue::{MulticastDatagramSender, MulticastLinkDriver};
use crate::LinkDriver;

/// A carrier of whole raweth frames: one send is one frame on the medium, one receive one frame
/// off it.
pub trait RawEthCarrier: Send + Sync + 'static {
    /// Write one frame.
    fn send_frame(&self, frame: &[u8])
        -> impl core::future::Future<Output = io::Result<()>> + Send;
    /// Read one frame into `buf`, returning its length.
    fn recv_frame(
        &self,
        buf: &mut [u8],
    ) -> impl core::future::Future<Output = io::Result<usize>> + Send;
}

/// The carrier a session opens: an `AF_PACKET` socket bound to the endpoint's interface, read
/// and written through the reactor.
pub struct AfPacketCarrier {
    socket: AsyncFd<AfPacketSocket>,
}

impl AfPacketCarrier {
    /// Open the socket on `interface`. Fails without `CAP_NET_RAW`, as pico's `_z_open_raweth`
    /// does.
    pub fn open(interface: &str) -> io::Result<Self> {
        let socket = AfPacketSocket::open(interface)?;
        socket.set_nonblocking()?;
        Ok(Self {
            socket: AsyncFd::new(socket)?,
        })
    }
}

impl RawEthCarrier for AfPacketCarrier {
    async fn send_frame(&self, frame: &[u8]) -> io::Result<()> {
        use wz_packet_socket::raweth_socket::RawEthIo;
        loop {
            let mut ready = self.socket.writable().await?;
            match ready.try_io(|socket| socket.get_ref().send_frame(frame)) {
                Ok(result) => return result.map(drop),
                Err(_would_block) => continue,
            }
        }
    }

    async fn recv_frame(&self, buf: &mut [u8]) -> io::Result<usize> {
        use wz_packet_socket::raweth_socket::RawEthIo;
        loop {
            let mut ready = self.socket.readable().await?;
            match ready.try_io(|socket| socket.get_ref().recv_frame(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

/// The address a member whose frames come from `mac` is keyed by: the IPv6 link-local address
/// of the MAC's modified EUI-64.
pub fn member_address(mac: [u8; MAC_LEN]) -> SocketAddr {
    let ip = Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        u16::from_be_bytes([mac[0] ^ 0x02, mac[1]]),
        u16::from_be_bytes([mac[2], 0xff]),
        u16::from_be_bytes([0xfe, mac[3]]),
        u16::from_be_bytes([mac[4], mac[5]]),
    );
    SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, 0))
}

/// The `reth/` locator of the member [`member_address`] keyed `addr` by: its MAC, read back out
/// of the modified EUI-64. `None` for an address no raweth member is keyed by.
pub fn member_locator(addr: &SocketAddr) -> Option<String> {
    let SocketAddr::V6(v6) = addr else {
        return None;
    };
    let o = v6.ip().octets();
    if o[..8] != [0xfe, 0x80, 0, 0, 0, 0, 0, 0] || o[11] != 0xff || o[12] != 0xfe {
        return None;
    }
    let mac = [o[8] ^ 0x02, o[9], o[10], o[13], o[14], o[15]];
    Some(format!("reth/{}", mac_text(&mac)))
}

/// `aa:bb:cc:dd:ee:ff`.
fn mac_text(mac: &[u8; MAC_LEN]) -> String {
    mac.iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A group over raw Ethernet, as the endpoint `endpoint` configures it, on `carrier`.
pub struct RawEthGroupDriver<C> {
    carrier: Option<Arc<C>>,
    endpoint: Arc<RethLocator>,
    #[cfg(feature = "reassembly")]
    routes: Arc<Mutex<FragmentRoutes>>,
}

impl<C: RawEthCarrier> RawEthGroupDriver<C> {
    /// The link `endpoint` describes, over `carrier`.
    pub fn new(carrier: C, endpoint: RethLocator) -> Self {
        Self {
            carrier: Some(Arc::new(carrier)),
            endpoint: Arc::new(endpoint),
            #[cfg(feature = "reassembly")]
            routes: Arc::new(Mutex::new(FragmentRoutes::default())),
        }
    }
}

/// The mapping entry the fragments of the message on each channel go by, from its first
/// fragment until its last: pico picks a message's destination once, by its key, and sends
/// every fragment of it there (`vendor/zenoh-pico/src/transport/raweth/tx.c` @
/// `// The message does not fit in the current batch, let's fragment it`). One message is
/// fragmented at a time on a channel, so a channel holds one route. A build without
/// `reassembly` has no fragment to route: the group's sender cuts none, and the wire form of
/// one is not decoded.
#[cfg(feature = "reassembly")]
#[derive(Default)]
struct FragmentRoutes {
    reliable: Option<usize>,
    best_effort: Option<usize>,
}

impl RawEthGroupDriver<AfPacketCarrier> {
    /// Open the link `endpoint` describes on its interface's socket.
    pub fn open_endpoint(endpoint: RethLocator) -> io::Result<Self> {
        let carrier = AfPacketCarrier::open(&endpoint.interface)?;
        Ok(Self::new(carrier, endpoint))
    }
}

impl<C: RawEthCarrier> LinkDriver for RawEthGroupDriver<C> {
    async fn open(&mut self) -> io::Result<()> {
        match self.carrier {
            Some(_) => Ok(()),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the raweth link was closed",
            )),
        }
    }

    async fn send(&mut self, frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
        self.datagram_sender()?.send(frame.bytes).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.carrier = None;
        Ok(())
    }

    async fn poll_event(&mut self) -> LinkEvent {
        let Some(carrier) = self.carrier.as_ref() else {
            return LinkEvent::Lost {
                cause: LostCause::PeerClosed,
            };
        };
        let mut buf = vec![0u8; MAX_ETH_FRAME_SIZE];
        loop {
            let n = match carrier.recv_frame(&mut buf).await {
                Ok(n) => n,
                Err(_) => {
                    return LinkEvent::Lost {
                        cause: LostCause::OsError,
                    }
                }
            };
            // Whatever does not deframe is another protocol on the interface.
            let Ok((header, payload)) = deframe(&buf[..n]) else {
                continue;
            };
            if !self.endpoint.whitelist.accepts(&header.smac) {
                continue;
            }
            return LinkEvent::Rx(RxFrame::with_src(
                payload.to_vec(),
                member_address(header.smac),
            ));
        }
    }
}

impl<C: RawEthCarrier> MulticastLinkDriver for RawEthGroupDriver<C> {
    type Sender = RawEthGroupSender<C>;

    fn datagram_sender(&self) -> io::Result<RawEthGroupSender<C>> {
        let carrier = self.carrier.clone().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "the raweth link was closed")
        })?;
        Ok(RawEthGroupSender {
            carrier,
            endpoint: self.endpoint.clone(),
            #[cfg(feature = "reassembly")]
            routes: self.routes.clone(),
        })
    }

    /// The link's own MAC, and the destination of a message no mapping entry names.
    fn group_locators(&self) -> io::Result<(String, String)> {
        Ok((
            format!("reth/{}", mac_text(&self.endpoint.smac)),
            format!("reth/{}", mac_text(&self.endpoint.mapping_for(None).dmac)),
        ))
    }

    /// The frame less the widest header a mapping entry makes.
    fn frame_budget(&self) -> Option<u16> {
        let header = if self
            .endpoint
            .mapping
            .iter()
            .any(|entry| entry.vlan.is_some())
        {
            ETH_VLAN_HEADER_LEN
        } else {
            ETH_HEADER_LEN
        };
        u16::try_from(MAX_ETH_FRAME_SIZE - header).ok()
    }
}

/// The send half of a [`RawEthGroupDriver`]: frames each datagram for the destination its
/// message's key maps to.
pub struct RawEthGroupSender<C> {
    carrier: Arc<C>,
    endpoint: Arc<RethLocator>,
    #[cfg(feature = "reassembly")]
    routes: Arc<Mutex<FragmentRoutes>>,
}

impl<C: RawEthCarrier> RawEthGroupSender<C> {
    /// The index of the mapping entry `datagram` goes by: a frame's by the key of the message it
    /// carries, a fragment's by the key of the message it is part of, read off the chain's
    /// first fragment, and anything else (a JOIN, a declaration) by the first entry, as pico
    /// sends a message that names no key (`vendor/zenoh-pico/src/transport/raweth/tx.c` @
    /// `// Store default value into socket`).
    fn route(&self, datagram: &[u8]) -> usize {
        use wz_session_core::inbound::{parse_inbound, InboundFrame};
        // A mapping of one entry sends everything one way, and the key need not be read.
        if self.endpoint.mapping.len() < 2 {
            return 0;
        }
        match parse_inbound(datagram) {
            Ok(InboundFrame::Frame { payload, .. }) => self
                .endpoint
                .mapping_index_for(leading_message_key(&payload).as_deref()),
            #[cfg(feature = "reassembly")]
            Ok(InboundFrame::Fragment {
                reliable,
                more,
                payload,
                markers,
                ..
            }) => {
                let mut routes = self
                    .routes
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let slot = if reliable {
                    &mut routes.reliable
                } else {
                    &mut routes.best_effort
                };
                // A chain's first fragment, by its marker where the chain carries one and by
                // the channel holding no route where it does not, picks the route.
                if markers.first || slot.is_none() {
                    *slot = Some(
                        self.endpoint
                            .mapping_index_for(leading_message_key(&payload).as_deref()),
                    );
                }
                let index = slot.unwrap_or(0);
                // The last fragment, or the one that abandons the chain, ends it.
                if !more || markers.dropped {
                    *slot = None;
                }
                index
            }
            _ => 0,
        }
    }
}

impl<C: RawEthCarrier> MulticastDatagramSender for RawEthGroupSender<C> {
    fn send(&self, datagram: &[u8]) -> impl core::future::Future<Output = io::Result<()>> + Send {
        let entry = &self.endpoint.mapping[self.route(datagram)];
        let mut header =
            RawEthHeader::new(entry.dmac, self.endpoint.smac, self.endpoint.ethtype, 0);
        if let Some(tag) = entry.vlan {
            header = header.with_vlan(tag);
        }
        let framed = frame(&header, datagram)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()));
        let carrier = self.carrier.clone();
        async move { carrier.send_frame(&framed?).await }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixDatagram;
    use wz_session_core::raweth_link::parse_reth_locator;

    /// Two ends of a datagram pair stand in for the medium: one send, one receive.
    struct PairCarrier(UnixDatagram);

    impl RawEthCarrier for PairCarrier {
        async fn send_frame(&self, frame: &[u8]) -> io::Result<()> {
            self.0.send(frame).await.map(drop)
        }
        async fn recv_frame(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.recv(buf).await
        }
    }

    fn pair(
        left: &str,
        right: &str,
    ) -> (
        RawEthGroupDriver<PairCarrier>,
        RawEthGroupDriver<PairCarrier>,
    ) {
        let (a, b) = UnixDatagram::pair().expect("a datagram pair");
        (
            RawEthGroupDriver::new(PairCarrier(a), parse_reth_locator(left).expect("left")),
            RawEthGroupDriver::new(PairCarrier(b), parse_reth_locator(right).expect("right")),
        )
    }

    fn put(key: &str) -> Vec<u8> {
        wz_session_core::frame_encode::encode_frame_with_push(
            0,
            wz_session_core::push_build::build_push_literal(key, b"x").expect("the put builds"),
            true,
        )
    }

    /// A put leaves for the destination its key maps to, from the link's own MAC, and arrives
    /// as one datagram attributed to that MAC.
    #[tokio::test]
    async fn a_put_goes_where_its_key_maps_and_is_attributed_to_its_source() {
        let (mut left, mut right) = pair(
            "reth/02:00:00:00:00:01#mapping=demo/a#02:00:00:00:00:aa#,demo/b/**#02:00:00:00:00:bb#0005",
            "reth/02:00:00:00:00:02",
        );
        let datagram = put("demo/b/x");
        left.send(&TxFrame { bytes: &datagram }, Reliability::Reliable)
            .await
            .expect("sent");
        let LinkEvent::Rx(received) = right.poll_event().await else {
            panic!("nothing arrived");
        };
        assert_eq!(&received.bytes[..], &datagram[..]);
        assert_eq!(received.src, Some(member_address([0x02, 0, 0, 0, 0, 0x01])));
        // The frame on the medium: what the second entry names, with its VLAN tag.
        let (raw_left, raw_right) = UnixDatagram::pair().expect("a datagram pair");
        let sender = RawEthGroupDriver::new(
            PairCarrier(raw_left),
            parse_reth_locator(
                "reth/02:00:00:00:00:01#mapping=demo/a#02:00:00:00:00:aa#,demo/b/**#02:00:00:00:00:bb#0005",
            )
            .expect("endpoint"),
        );
        sender
            .datagram_sender()
            .expect("a sender")
            .send(&datagram)
            .await
            .expect("sent");
        let mut buf = vec![0u8; MAX_ETH_FRAME_SIZE];
        let n = raw_right.recv(&mut buf).await.expect("a frame");
        let (header, payload) = deframe(&buf[..n]).expect("a raweth frame");
        assert_eq!(header.dmac, [0x02, 0, 0, 0, 0, 0xbb]);
        assert_eq!(header.vlan, Some(0x0005));
        assert_eq!(payload, &datagram[..]);
    }

    /// A frame from a source the whitelist does not name is not delivered, and the next one is.
    #[tokio::test]
    async fn a_source_the_whitelist_does_not_name_is_dropped() {
        let (left, mut right) = pair(
            "reth/02:00:00:00:00:01",
            "reth/02:00:00:00:00:02#whitelist=02:00:00:00:00:03",
        );
        let sender = left.datagram_sender().expect("a sender");
        sender.send(&put("demo/a")).await.expect("sent");
        // The second frame is forged from the admitted source, straight onto the medium.
        let admitted = frame(
            &RawEthHeader::new([0xaa; 6], [0x02, 0, 0, 0, 0, 0x03], 0x72e0, 0),
            &put("demo/a"),
        )
        .expect("a frame");
        left.carrier
            .as_ref()
            .expect("open")
            .send_frame(&admitted)
            .await
            .expect("sent");
        let LinkEvent::Rx(received) = right.poll_event().await else {
            panic!("nothing arrived");
        };
        assert_eq!(
            received.src,
            Some(member_address([0x02, 0, 0, 0, 0, 0x03])),
            "the first frame's source is not on the whitelist"
        );
    }

    /// Every fragment of a put that does not fit one frame goes where the put's key maps, as
    /// pico sends a fragmented message, and the chain's route ends with it: a put after it on a
    /// key no entry meets goes by the first entry.
    ///
    /// # Control
    ///
    /// The chain's later fragments carry no key of their own: reading each fragment alone (a
    /// route of `None` per fragment) sends them to the first entry and reds the assert.
    #[cfg(feature = "transport-fragmentation")]
    #[tokio::test]
    async fn the_fragments_of_a_message_go_where_its_key_maps() {
        let endpoint =
            "reth/02:00:00:00:00:01#mapping=demo/a#02:00:00:00:00:aa#,demo/b/**#02:00:00:00:00:bb#";
        let (raw_left, raw_right) = UnixDatagram::pair().expect("a datagram pair");
        let sender = RawEthGroupDriver::new(
            PairCarrier(raw_left),
            parse_reth_locator(endpoint).expect("endpoint"),
        )
        .datagram_sender()
        .expect("a sender");
        let big = wz_session_core::frame_encode::encode_frame_with_push(
            0,
            wz_session_core::push_build::build_push_literal("demo/b/x", &[7u8; 600])
                .expect("the put builds"),
            true,
        );
        let mut conduits = wz_session_core::sn::MulticastTxConduits::new(u64::from(u32::MAX));
        let fragments = wz_session_core::frame_encode::multicast_frame_or_fragments(
            big,
            0,
            true,
            200,
            &mut conduits,
            None,
        );
        assert!(fragments.len() > 2, "the put is cut into a chain");
        for fragment in &fragments {
            sender.send(fragment).await.expect("sent");
        }
        let mut buf = vec![0u8; MAX_ETH_FRAME_SIZE];
        for i in 0..fragments.len() {
            let n = raw_right.recv(&mut buf).await.expect("a frame");
            let (header, _) = deframe(&buf[..n]).expect("a raweth frame");
            assert_eq!(header.dmac, [0x02, 0, 0, 0, 0, 0xbb], "fragment {i}");
        }
        // After the chain, a put on a key no entry meets goes by the first entry.
        let keyless = wz_session_core::frame_encode::encode_frame_with_push(
            1,
            wz_session_core::push_build::build_push_literal("other/key", b"x")
                .expect("the put builds"),
            true,
        );
        sender.send(&keyless).await.expect("sent");
        let n = raw_right.recv(&mut buf).await.expect("a frame");
        let (header, _) = deframe(&buf[..n]).expect("a raweth frame");
        assert_eq!(header.dmac, [0x02, 0, 0, 0, 0, 0xaa]);
    }

    /// A member's address reads back as its MAC's `reth/` locator, and an address no raweth
    /// member is keyed by reads as none.
    #[test]
    fn a_member_address_reads_back_as_its_mac() {
        let mac = [0x30, 0x03, 0x8c, 0xc8, 0x00, 0xa1];
        assert_eq!(
            member_locator(&member_address(mac)).as_deref(),
            Some("reth/30:03:8c:c8:00:a1")
        );
        assert_eq!(member_locator(&"127.0.0.1:7447".parse().unwrap()), None);
        assert_eq!(member_locator(&"[fe80::1]:0".parse().unwrap()), None);
    }

    /// The link frames to what a raweth frame holds, the widest header its mapping makes taken
    /// off.
    #[tokio::test]
    async fn the_frame_budget_is_the_frame_less_its_widest_header() {
        let (plain, tagged) = pair(
            "reth/02:00:00:00:00:01",
            "reth/02:00:00:00:00:01#mapping=x#02:00:00:00:00:aa#0005",
        );
        assert_eq!(plain.frame_budget(), Some(1514 - 16));
        assert_eq!(tagged.frame_budget(), Some(1514 - 20));
    }
}

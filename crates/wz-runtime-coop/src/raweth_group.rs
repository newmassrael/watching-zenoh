// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A multicast group over raw Ethernet on this engine: the link zenoh-pico's raweth transport
//! runs a multicast session over (`vendor/zenoh-pico/src/transport/raweth/`), as a
//! [`GroupTransport`] the group drive loop steps as it steps a UDP group's.
//!
//! What the link does with each frame is the session core's (`wz_session_core::raweth_link`), and
//! the tokio engine's raweth group does the same with it: a datagram goes behind pico's header to
//! the destination the endpoint's `mapping` gives its message's key ([`RethRoutes`]), a frame is
//! read from a source the `whitelist` names as the member its MAC keys
//! ([`RethLocator::admit`]), and the group frames its batches to what one frame carries
//! ([`RethLocator::frame_budget`]). What this module adds is the device, the host's raw socket on
//! the endpoint's interface ([`RawEthOpen`], [`RawEthDevice`]), and the joiner that opens it for
//! a `reth/` group and hands every other group to the joiner it wraps ([`RawethJoiner`]).
//!
//! [`GroupTransport`]: crate::group_transport::GroupTransport
//! [`RawEthOpen`]: crate::raweth_group::RawEthOpen
//! [`RawEthDevice`]: crate::raweth_group::RawEthDevice
//! [`RawethJoiner`]: crate::raweth_group::RawethJoiner
//! [`RethLocator::admit`]: wz_session_core::raweth_link::RethLocator::admit
//! [`RethLocator::frame_budget`]: wz_session_core::raweth_link::RethLocator::frame_budget
//! [`RethRoutes`]: wz_session_core::raweth_link::RethRoutes

use alloc::boxed::Box;
use core::net::SocketAddr;

use wz_session_core::byte_cells::ByteBuf;
use wz_session_core::group_locator::GroupLocator;
use wz_session_core::raweth_link::{frame_into, RethLocator, RethRoutes, MAX_ETH_FRAME_SIZE};

use crate::group_transport::{GroupJoiner, GroupRx, GroupSend, GroupTransport};
use crate::session_drive::{LinkOpenError, WaitOn};

/// One end of a raw Ethernet medium: whole frames written to and read from one interface.
pub trait RawEthDevice {
    /// Write one frame: [`GroupSend::Full`] when the device has no room for it now, which nothing
    /// was written to, and [`GroupSend::Failed`] when the host refused it otherwise.
    fn send_frame(&mut self, frame: &[u8]) -> GroupSend;

    /// Read the next frame into `buf`, cut to it, and say how long what was read is; `None` when
    /// no frame is queued.
    fn recv_frame(&mut self, buf: &mut [u8]) -> Option<usize>;

    /// What a host waits on for the device's next frame ([`GroupTransport::input_wait`]); `None`,
    /// the provided answer, for a device that gives none.
    fn input_wait(&self) -> Option<WaitOn> {
        None
    }

    /// What a host waits on for the device to take another frame ([`GroupTransport::room_wait`]);
    /// `None`, the provided answer, for a device that gives none.
    fn room_wait(&self) -> Option<WaitOn> {
        None
    }
}

/// What opens the device of the interface a `reth/` group names.
pub trait RawEthOpen {
    /// The device it opens.
    type Device: RawEthDevice + 'static;

    /// The device bound to `interface`: [`LinkOpenError::Refused`] when the host does not open it
    /// (no such interface, no privilege for a raw socket), as pico's `_z_open_raweth` fails.
    fn open(&self, interface: &str) -> Result<Self::Device, LinkOpenError>;
}

/// A group over raw Ethernet, as its endpoint configures it, on a device `D`.
pub struct RawEthGroup<D> {
    /// `None` once the group is left: it sends and reads nothing after.
    device: Option<D>,
    endpoint: RethLocator,
    routes: RethRoutes,
    /// What each frame is read into: a frame longer than it is cut, and a cut frame does not
    /// deframe, so a lent buffer shorter than a frame drops the frames it cannot hold.
    rx: GroupRx<Box<[u8]>>,
    /// What each frame is written into before it is sent.
    tx: Box<[u8]>,
}

impl<D: RawEthDevice> RawEthGroup<D> {
    /// The group `endpoint` describes, on `device`, reading into `rx` when the session lent one.
    pub fn new(device: D, endpoint: RethLocator, rx: Option<ByteBuf>) -> Self {
        Self {
            device: Some(device),
            endpoint,
            routes: RethRoutes::default(),
            rx: GroupRx::lent_or_own(rx, || {
                alloc::vec![0u8; MAX_ETH_FRAME_SIZE].into_boxed_slice()
            }),
            tx: alloc::vec![0u8; MAX_ETH_FRAME_SIZE].into_boxed_slice(),
        }
    }
}

impl<D: RawEthDevice> GroupTransport for RawEthGroup<D> {
    fn open(&mut self) -> bool {
        self.device.is_some()
    }

    fn close(&mut self) {
        self.device = None;
    }

    fn service(&self) {}

    /// pico's raweth link has no carrier to report.
    fn carrier_up(&self) -> bool {
        true
    }

    fn send_to_group(&mut self, datagram: &[u8]) {
        let _ = self.try_send_to_group(datagram);
    }

    fn try_send_to_group(&mut self, datagram: &[u8]) -> GroupSend {
        let Some(device) = self.device.as_mut() else {
            return GroupSend::Failed;
        };
        // A datagram a full device did not take is offered again, and is routed then as if this
        // offer had not been: the last fragment of a chain ends the chain's route.
        let before = self.routes;
        let header = self
            .endpoint
            .header_for(self.routes.route(&self.endpoint, datagram));
        let Ok(len) = frame_into(&header, datagram, &mut self.tx) else {
            return GroupSend::Failed;
        };
        let sent = device.send_frame(self.tx.get(..len).unwrap_or_default());
        if sent == GroupSend::Full {
            self.routes = before;
        }
        sent
    }

    fn room_wait(&self) -> Option<WaitOn> {
        self.device.as_ref().and_then(RawEthDevice::room_wait)
    }

    fn input_wait(&self) -> Option<WaitOn> {
        self.device.as_ref().and_then(RawEthDevice::input_wait)
    }

    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        let Some(device) = self.device.as_mut() else {
            return false;
        };
        // A frame of another protocol on the interface, or from a source the whitelist does not
        // name, is read past.
        while let Some(len) = device.recv_frame(self.rx.as_mut_slice()) {
            let frame = self.rx.as_slice().get(..len).unwrap_or_default();
            if let Some((datagram, from)) = self.endpoint.admit(frame) {
                f(datagram, from);
                return true;
            }
        }
        false
    }

    fn give_back_rx(&mut self) -> Option<ByteBuf> {
        self.rx.give_back()
    }

    fn frame_budget(&self) -> Option<u16> {
        Some(self.endpoint.frame_budget())
    }
}

/// The joiner of a stack whose host also opens raw Ethernet: a `reth/` group is joined on the
/// device `O` opens on its interface, and every other group by the joiner `J` it wraps.
pub struct RawethJoiner<J, O> {
    inner: J,
    raweth: O,
}

impl<J, O> RawethJoiner<J, O> {
    /// `inner`'s groups, and the `reth/` groups of the devices `raweth` opens.
    pub fn new(inner: J, raweth: O) -> Self {
        Self { inner, raweth }
    }
}

impl<J: GroupJoiner, O: RawEthOpen> GroupJoiner for RawethJoiner<J, O> {
    fn join(
        &self,
        group: &GroupLocator,
        rx: Option<ByteBuf>,
    ) -> Result<Box<dyn GroupTransport>, LinkOpenError> {
        let Some(endpoint) = group.raweth() else {
            return self.inner.join(group, rx);
        };
        let device = self.raweth.open(endpoint.interface())?;
        Ok(Box::new(RawEthGroup::new(device, endpoint.clone(), rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_transport::NoGroups;
    use alloc::collections::VecDeque;
    use alloc::rc::Rc;
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use wz_session_core::group_locator::parse_group_locator;
    use wz_session_core::raweth_link::{
        deframe, frame, member_address, RawEthHeader, DEFAULT_ETHTYPE,
    };

    const OWN: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    #[cfg(feature = "reassembly")]
    const ENTRY_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0xaa];
    const ENTRY_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0xbb];
    #[cfg(feature = "reassembly")]
    const MAPPED: &str = "reth/02:00:00:00:00:01#mapping=demo/a#02:00:00:00:00:aa#,\
                          demo/b/**#02:00:00:00:00:bb#0005";

    /// The medium the devices share: the frames written to it, the frames queued to be read, and
    /// whether it is full and takes no more.
    #[derive(Default)]
    struct Medium {
        sent: Vec<Vec<u8>>,
        queued: VecDeque<Vec<u8>>,
        full: bool,
    }

    struct Wire(Rc<RefCell<Medium>>);

    impl RawEthDevice for Wire {
        fn send_frame(&mut self, frame: &[u8]) -> GroupSend {
            let mut medium = self.0.borrow_mut();
            if medium.full {
                return GroupSend::Full;
            }
            medium.sent.push(frame.to_vec());
            GroupSend::Sent
        }

        fn recv_frame(&mut self, buf: &mut [u8]) -> Option<usize> {
            let frame = self.0.borrow_mut().queued.pop_front()?;
            let len = frame.len().min(buf.len());
            buf.get_mut(..len)?.copy_from_slice(frame.get(..len)?);
            Some(len)
        }
    }

    /// Opens a [`Wire`] on the medium, and records the interface it was asked for; refuses the
    /// interface `down`.
    struct Opener {
        medium: Rc<RefCell<Medium>>,
        opened: RefCell<Vec<String>>,
    }

    impl RawEthOpen for Opener {
        type Device = Wire;

        fn open(&self, interface: &str) -> Result<Wire, LinkOpenError> {
            if interface == "down" {
                return Err(LinkOpenError::Refused);
            }
            self.opened.borrow_mut().push(String::from(interface));
            Ok(Wire(Rc::clone(&self.medium)))
        }
    }

    fn joiner(medium: &Rc<RefCell<Medium>>) -> RawethJoiner<NoGroups, Opener> {
        RawethJoiner::new(
            NoGroups,
            Opener {
                medium: Rc::clone(medium),
                opened: RefCell::default(),
            },
        )
    }

    fn joined(medium: &Rc<RefCell<Medium>>, endpoint: &str) -> Box<dyn GroupTransport> {
        let group = parse_group_locator(endpoint).expect("a group endpoint");
        let mut joined = joiner(medium)
            .join(&group, None)
            .expect("a reth group joins");
        assert!(joined.open());
        joined
    }

    /// A put on `key` behind the transport header `head` (a frame or a fragment) and the SN `0`.
    fn put(head: u8, key: &[u8]) -> Vec<u8> {
        let mut bytes = alloc::vec![head, 0x00, 0x3d, 0x00, key.len() as u8];
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(&[0x01, 0x01, b'x']);
        bytes
    }

    /// The destination of each frame written to the medium.
    #[cfg(feature = "reassembly")]
    fn destinations(medium: &Rc<RefCell<Medium>>) -> Vec<[u8; 6]> {
        medium
            .borrow()
            .sent
            .iter()
            .map(|sent| deframe(sent).expect("a raweth frame").0.dmac)
            .collect()
    }

    /// A `reth/` group is joined on the device of the interface it names, which refuses it when
    /// the host does, and any other group is the wrapped joiner's. Turned red by a joiner that
    /// hands a `reth/` group to the wrapped one.
    #[test]
    fn a_reth_group_opens_its_interface_and_another_is_the_wrapped_joiners() {
        let medium = Rc::default();
        let joiner = joiner(&medium);
        let reth = parse_group_locator("reth/02:00:00:00:00:01#iface=eth9").expect("reth");
        let group = joiner.join(&reth, None).expect("a reth group joins");
        assert_eq!(joiner.raweth.opened.borrow().as_slice(), ["eth9"]);
        assert_eq!(group.frame_budget(), Some(1514 - 16));
        let udp = parse_group_locator("udp/224.0.0.224:7446").expect("udp");
        assert!(matches!(
            joiner.join(&udp, None),
            Err(LinkOpenError::Unsupported)
        ));
        let down = parse_group_locator("reth/02:00:00:00:00:01#iface=down").expect("reth");
        assert!(matches!(
            joiner.join(&down, None),
            Err(LinkOpenError::Refused)
        ));
    }

    /// A datagram leaves from the link's own MAC for the entry its message's key meets, tagged as
    /// the entry is; a frame is read from a source the whitelist names as the member its MAC
    /// keys, and a frame from another source or of another protocol is read past. A group left
    /// sends nothing and does not open again.
    #[test]
    fn a_datagram_leaves_for_its_entry_and_a_named_source_is_read() {
        let medium = Rc::default();
        let mut group = joined(
            &medium,
            "reth/02:00:00:00:00:01#mapping=demo/a#02:00:00:00:00:aa#,\
             demo/b/**#02:00:00:00:00:bb#0005;whitelist=02:00:00:00:00:03",
        );
        assert_eq!(group.frame_budget(), Some(1514 - 20));
        let datagram = put(0x25, b"demo/b/x");
        assert_eq!(group.try_send_to_group(&datagram), GroupSend::Sent);
        let sent = medium.borrow().sent.first().cloned().expect("a frame");
        let (header, payload) = deframe(&sent).expect("a raweth frame");
        assert_eq!(
            (header.dmac, header.smac, header.vlan),
            (ENTRY_B, OWN, Some(5))
        );
        assert_eq!(payload, &datagram[..]);

        let from = |smac| {
            frame(&RawEthHeader::new(OWN, smac, DEFAULT_ETHTYPE, 0), b"hello").expect("a frame")
        };
        medium.borrow_mut().queued.extend([
            from([0x02, 0, 0, 0, 0, 0x04]),
            alloc::vec![0u8; 8],
            from([0x02, 0, 0, 0, 0, 0x03]),
        ]);
        let mut read = Vec::new();
        assert!(group.recv_with(&mut |bytes, src| read.push((bytes.to_vec(), src))));
        assert_eq!(
            read,
            [(b"hello".to_vec(), member_address([0x02, 0, 0, 0, 0, 0x03]))]
        );
        assert!(!group.recv_with(&mut |_, _| panic!("nothing more is queued")));

        group.close();
        assert_eq!(group.try_send_to_group(&datagram), GroupSend::Failed);
        assert!(!group.open(), "a group left does not open again");
    }

    /// The last fragment of a chain that a full device did not take goes where the chain went when
    /// it is offered again.
    ///
    /// # Control
    ///
    /// The last fragment names no key: routed afresh, after its first offer ended the chain's
    /// route, it goes by the first entry and reds the assert.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_fragment_a_full_device_left_goes_where_its_chain_went() {
        let medium = Rc::default();
        let mut group = joined(&medium, MAPPED);
        // Reliable fragments: the first with more to come, the last without.
        let first = put(0x66, b"demo/b/x");
        let last = alloc::vec![0x26, 0x01, 0xaa, 0xbb];
        assert_eq!(group.try_send_to_group(&first), GroupSend::Sent);
        medium.borrow_mut().full = true;
        assert_eq!(group.try_send_to_group(&last), GroupSend::Full);
        medium.borrow_mut().full = false;
        assert_eq!(group.try_send_to_group(&last), GroupSend::Sent);
        assert_eq!(destinations(&medium), [ENTRY_B, ENTRY_B]);
        // The chain ended: a put on a key no entry meets goes by the first entry.
        assert_eq!(
            group.try_send_to_group(&put(0x25, b"other")),
            GroupSend::Sent
        );
        assert_eq!(destinations(&medium), [ENTRY_B, ENTRY_B, ENTRY_A]);
    }
}

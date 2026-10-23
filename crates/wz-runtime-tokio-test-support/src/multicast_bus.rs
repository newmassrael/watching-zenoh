// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! An in-memory multicast group: every attached link receives what any OTHER
//! attached link sends, with the sender's address, as a group delivers.
//!
//! What a group session's tests run over instead of a socket. A real group is
//! environment-dependent (a host without a multicast route drops the join), so
//! the socket witnesses are opt-in, and everything above the socket is tested
//! here, in paused time where a test wants it. Shared by every crate that drives
//! a group, so the members of one test agree on what a group is.
//!
//! # What a member's place is
//!
//! A member's place in the group is held by its link AND by every send half made
//! from the link, and lasts while any of them lives, as a socket does when a send
//! half holds the descriptor: the runtime's contract
//! ([`MulticastLink`](wz_runtime_tokio::multicast_glue::MulticastLink)) is that the
//! transmit task writes through a handle of its own, so a departing Close queued
//! before the link is released still leaves after it. The transmit task runs on
//! another thread than the loop that released the link, so whether the Close was
//! written before or after the release is a race; a bus that forgot a member the
//! moment its link dropped lost the Close in the runs where the release won.
//!
//! A LOST CARRIER is another thing: the interface is gone, and nothing leaves it
//! whoever still holds a handle ([`GroupBus::attach`]).

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, Notify};

use wz_runtime_tokio::multicast_glue::{MulticastDatagramSender, MulticastLinkDriver};
use wz_runtime_tokio::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};

type Datagram = (Vec<u8>, SocketAddr);

/// One member's place: which attachment it is (a link that re-joins at an
/// address it held before is a new member), and where datagrams for it go.
struct Member {
    id: u64,
    inbound: mpsc::UnboundedSender<Datagram>,
}

/// The group, named by the endpoint its members were given.
#[derive(Clone)]
pub struct GroupBus {
    endpoint: Arc<str>,
    members: Arc<Mutex<Vec<Member>>>,
    next_id: Arc<AtomicU64>,
}

impl GroupBus {
    /// A group with no member yet, named `endpoint` (`udp/<group>:<port>`).
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.into(),
            members: Arc::default(),
            next_id: Arc::default(),
        }
    }

    /// Attach a link at `addr`. Notifying `carrier` drops it, as a lost
    /// interface does; it is then detached from the group, and nothing sent
    /// through it or through a send half of it reaches the group any more.
    pub fn attach(&self, addr: SocketAddr, carrier: Arc<Notify>) -> GroupBusLink {
        let (tx, inbound) = mpsc::unbounded_channel();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.members().push(Member { id, inbound: tx });
        GroupBusLink {
            place: Arc::new(Place {
                bus: self.clone(),
                addr,
                id,
            }),
            inbound,
            carrier,
        }
    }

    fn members(&self) -> std::sync::MutexGuard<'_, Vec<Member>> {
        self.members
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A place that is no longer in the group sends nothing: its interface is gone.
    fn deliver(&self, from: &Place, datagram: &[u8]) {
        let members = self.members();
        if !members.iter().any(|m| m.id == from.id) {
            return;
        }
        for member in members.iter() {
            if member.id != from.id {
                let _ = member.inbound.send((datagram.to_vec(), from.addr));
            }
        }
    }

    fn detach(&self, id: u64) {
        self.members().retain(|m| m.id != id);
    }
}

/// A member's place in the group, shared by its link and every send half of it;
/// the member leaves the group when the last of them drops, or at once when the
/// carrier is lost.
struct Place {
    bus: GroupBus,
    addr: SocketAddr,
    id: u64,
}

impl Drop for Place {
    fn drop(&mut self) {
        self.bus.detach(self.id);
    }
}

/// One join's link on a [`GroupBus`].
pub struct GroupBusLink {
    place: Arc<Place>,
    inbound: mpsc::UnboundedReceiver<Datagram>,
    carrier: Arc<Notify>,
}

/// The send half of a [`GroupBusLink`]: it holds the member's place in the group,
/// as a socket handle holds its descriptor.
pub struct GroupBusSender {
    place: Arc<Place>,
}

impl MulticastDatagramSender for GroupBusSender {
    fn send(&self, datagram: &[u8]) -> impl std::future::Future<Output = io::Result<()>> + Send {
        self.place.bus.deliver(&self.place, datagram);
        std::future::ready(Ok(()))
    }
}

impl MulticastLinkDriver for GroupBusLink {
    type Sender = GroupBusSender;

    fn datagram_sender(&self) -> io::Result<GroupBusSender> {
        Ok(GroupBusSender {
            place: self.place.clone(),
        })
    }

    /// The member's own address on the bus, and the endpoint the group is named
    /// by, as a UDP group link would name the two.
    fn group_locators(&self) -> io::Result<(String, String)> {
        Ok((
            format!("udp/{}", self.place.addr),
            self.place.bus.endpoint.to_string(),
        ))
    }
}

impl LinkDriver for GroupBusLink {
    async fn open(&mut self) -> io::Result<()> {
        Ok(())
    }

    async fn send(&mut self, frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
        self.place.bus.deliver(&self.place, frame.bytes);
        Ok(())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }

    async fn poll_event(&mut self) -> LinkEvent {
        tokio::select! {
            datagram = self.inbound.recv() => match datagram {
                Some((bytes, src)) => LinkEvent::Rx(RxFrame::with_src(bytes, src)),
                None => LinkEvent::Lost { cause: LostCause::OsError },
            },
            () = self.carrier.notified() => {
                self.place.bus.detach(self.place.id);
                LinkEvent::Lost { cause: LostCause::OsError }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    fn attach(bus: &GroupBus, port: u16) -> GroupBusLink {
        bus.attach(addr(port), Arc::new(Notify::new()))
    }

    #[tokio::test]
    async fn a_member_hears_what_another_sends_with_the_senders_address() {
        let bus = GroupBus::new("udp/224.0.0.224:7447");
        let (a, mut b) = (attach(&bus, 1), attach(&bus, 2));
        a.datagram_sender().unwrap().send(b"hello").await.unwrap();
        // A send delivers before it returns, so what B hears is already in its channel.
        let (bytes, src) = b.inbound.try_recv().expect("B heard nothing");
        assert_eq!((&bytes[..], src), (&b"hello"[..], addr(1)));
        assert!(
            a.inbound.is_empty(),
            "a member does not hear its own datagram"
        );
    }

    /// The runtime's contract for a group link: the transmit task writes through a handle of its
    /// own, so a datagram queued before the link was released leaves after it. A bus that forgot
    /// the member when its link dropped lost A's Close in the runs where the release won the
    /// race, which is what this test makes certain rather than likely. It reads B's channel and
    /// does not wait on it, so a bus that regressed fails this test and does not hang it.
    #[tokio::test]
    async fn a_datagram_written_after_its_link_dropped_still_reaches_the_group() {
        let bus = GroupBus::new("udp/224.0.0.224:7447");
        let (a, mut b) = (attach(&bus, 1), attach(&bus, 2));
        let sender = a.datagram_sender().unwrap();
        drop(a);
        sender.send(b"close").await.unwrap();
        let (bytes, src) = b
            .inbound
            .try_recv()
            .expect("the Close written after the link dropped never reached the group");
        assert_eq!((&bytes[..], src), (&b"close"[..], addr(1)));
    }

    #[tokio::test]
    async fn a_member_leaves_the_group_when_its_last_handle_drops() {
        let bus = GroupBus::new("udp/224.0.0.224:7447");
        let a = attach(&bus, 1);
        let sender = a.datagram_sender().unwrap();
        assert_eq!(bus.members().len(), 1);
        drop(a);
        assert_eq!(
            bus.members().len(),
            1,
            "the send half still holds the place"
        );
        drop(sender);
        assert!(bus.members().is_empty());
    }

    /// A lost interface sends nothing, whoever still holds a handle: the member is out of the
    /// group at the loss, and what its send half writes afterwards goes nowhere.
    #[tokio::test]
    async fn a_lost_carrier_ends_what_every_handle_sends() {
        let bus = GroupBus::new("udp/224.0.0.224:7447");
        let carrier = Arc::new(Notify::new());
        let mut a = bus.attach(addr(1), carrier.clone());
        let b = attach(&bus, 2);
        let sender = a.datagram_sender().unwrap();
        carrier.notify_one();
        assert!(matches!(
            a.poll_event().await,
            LinkEvent::Lost {
                cause: LostCause::OsError
            }
        ));
        sender.send(b"late").await.unwrap();
        assert!(b.inbound.is_empty(), "the interface was gone");
        assert_eq!(bus.members().len(), 1, "only B remains");
    }

    /// A link that re-joins at the address an earlier one held is a new member: the earlier
    /// one's handles leaving does not take the new member out.
    #[tokio::test]
    async fn a_rejoin_at_the_same_address_is_not_taken_out_by_the_old_handles() {
        let bus = GroupBus::new("udp/224.0.0.224:7447");
        let old = attach(&bus, 1);
        let old_sender = old.datagram_sender().unwrap();
        drop(old);
        let new = attach(&bus, 1);
        drop(old_sender);
        assert_eq!(bus.members().len(), 1, "the new member is still in");
        drop(new);
        assert!(bus.members().is_empty());
    }
}

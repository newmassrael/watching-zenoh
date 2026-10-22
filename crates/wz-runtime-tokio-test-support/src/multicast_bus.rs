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

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, Notify};

use wz_runtime_tokio::multicast_glue::{MulticastDatagramSender, MulticastLinkDriver};
use wz_runtime_tokio::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};

type Datagram = (Vec<u8>, SocketAddr);

/// One attached link: its address and where datagrams for it go.
type Member = (SocketAddr, mpsc::UnboundedSender<Datagram>);

/// The group, named by the endpoint its members were given.
#[derive(Clone)]
pub struct GroupBus {
    endpoint: Arc<str>,
    members: Arc<Mutex<Vec<Member>>>,
}

impl GroupBus {
    /// A group with no member yet, named `endpoint` (`udp/<group>:<port>`).
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.into(),
            members: Arc::default(),
        }
    }

    /// Attach a link at `addr`. Notifying `carrier` drops it, as a lost
    /// interface does; it is then detached from the group.
    pub fn attach(&self, addr: SocketAddr, carrier: Arc<Notify>) -> GroupBusLink {
        let (tx, inbound) = mpsc::unbounded_channel();
        self.members().push((addr, tx));
        GroupBusLink {
            addr,
            bus: self.clone(),
            inbound,
            carrier,
        }
    }

    fn members(&self) -> std::sync::MutexGuard<'_, Vec<Member>> {
        self.members
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A link that is no longer attached sends nothing: its socket is gone.
    fn deliver(&self, from: SocketAddr, datagram: &[u8]) {
        let members = self.members();
        if !members.iter().any(|(addr, _)| *addr == from) {
            return;
        }
        for (addr, tx) in members.iter() {
            if *addr != from {
                let _ = tx.send((datagram.to_vec(), from));
            }
        }
    }

    fn detach(&self, addr: SocketAddr) {
        self.members().retain(|(a, _)| *a != addr);
    }
}

/// One join's link on a [`GroupBus`].
pub struct GroupBusLink {
    addr: SocketAddr,
    bus: GroupBus,
    inbound: mpsc::UnboundedReceiver<Datagram>,
    carrier: Arc<Notify>,
}

impl Drop for GroupBusLink {
    fn drop(&mut self) {
        self.bus.detach(self.addr);
    }
}

/// The send half of a [`GroupBusLink`].
pub struct GroupBusSender {
    addr: SocketAddr,
    bus: GroupBus,
}

impl MulticastDatagramSender for GroupBusSender {
    fn send(&self, datagram: &[u8]) -> impl std::future::Future<Output = io::Result<()>> + Send {
        self.bus.deliver(self.addr, datagram);
        std::future::ready(Ok(()))
    }
}

impl MulticastLinkDriver for GroupBusLink {
    type Sender = GroupBusSender;

    fn datagram_sender(&self) -> io::Result<GroupBusSender> {
        Ok(GroupBusSender {
            addr: self.addr,
            bus: self.bus.clone(),
        })
    }

    /// The member's own address on the bus, and the endpoint the group is named
    /// by, as a UDP group link would name the two.
    fn group_locators(&self) -> io::Result<(String, String)> {
        Ok((format!("udp/{}", self.addr), self.bus.endpoint.to_string()))
    }
}

impl LinkDriver for GroupBusLink {
    async fn open(&mut self) -> io::Result<()> {
        Ok(())
    }

    async fn send(&mut self, frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
        self.bus.deliver(self.addr, frame.bytes);
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
                self.bus.detach(self.addr);
                LinkEvent::Lost { cause: LostCause::OsError }
            }
        }
    }
}

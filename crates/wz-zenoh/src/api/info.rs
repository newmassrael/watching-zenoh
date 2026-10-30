//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.2, file
// src/api/info.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2). The transports and the links
// are read off the faces of the engine (`Face`), where upstream reads the transports of its manager,
// and the events of the two listeners are told by the engine when a face comes up or goes down
// (docs/zenoh-api-on-the-engine.md, slice Z6a).

//! Tools to access information about the current zenoh [`Session`](crate::Session).

#[cfg(feature = "unstable")]
use zenoh_config::{wrappers::ZenohId, WhatAmI};
#[cfg(feature = "unstable")]
use zenoh_core::{Resolve, ResolveClosure};
#[cfg(feature = "unstable")]
use zenoh_protocol::core::{Locator, Reliability};

use crate::api::{
    builders::info::{PeersZenohIdBuilder, RoutersZenohIdBuilder, ZenohIdBuilder},
    session::WeakSession,
};
#[cfg(feature = "unstable")]
use crate::api::{
    builders::{
        info_links::{LinkEventsListenerBuilder, LinksBuilder},
        info_transport::{TransportEventsListenerBuilder, TransportsBuilder},
    },
    handlers::{CallbackParameter, DefaultHandler},
    sample::SampleKind,
};

/// Struct returned by [`Session::info()`](crate::Session::info) that allows
/// access to information about the current zenoh [`Session`](crate::Session).
///
/// This information includes the [`ZenohId`](crate::session::ZenohId) identifier of the current session,
/// and the identifiers of the connected routers and peers (see also [`WhatAmI`](crate::config::WhatAmI)
/// for more information about peers and routers).
///
/// # Examples
/// ```
/// # #[tokio::main]
/// # async fn main() {
/// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// let info = session.info();
/// let zid = info.zid().await;
/// # }
/// ```
pub struct SessionInfo {
    pub(crate) session: WeakSession,
}

impl std::fmt::Debug for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SessionInfo").field(&"..").finish()
    }
}

impl SessionInfo {
    /// Return the [`ZenohId`](crate::session::ZenohId) of the current zenoh [`Session`](crate::Session).
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let zid = session.info().zid().await;
    /// # }
    /// ```
    pub fn zid(&self) -> ZenohIdBuilder<'_> {
        ZenohIdBuilder::new(&self.session)
    }

    /// Return the [`ZenohId`](crate::session::ZenohId) of the zenoh routers this process is currently connected to,
    /// or the [`ZenohId`](crate::session::ZenohId) of the current router if this code is run from a router (plugin).
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let mut routers_zid = session.info().routers_zid().await;
    /// while let Some(router_zid) = routers_zid.next() {}
    /// # }
    /// ```
    pub fn routers_zid(&self) -> RoutersZenohIdBuilder<'_> {
        RoutersZenohIdBuilder::new(&self.session)
    }

    /// Return the [`ZenohId`](crate::session::ZenohId) of the zenoh peers this process is currently connected to.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let mut peers_zid = session.info().peers_zid().await;
    /// while let Some(peer_zid) = peers_zid.next() {}
    /// # }
    /// ```
    pub fn peers_zid(&self) -> PeersZenohIdBuilder<'_> {
        PeersZenohIdBuilder::new(&self.session)
    }

    /// Return the locators on which the current zenoh [`Session`](crate::Session) is listening to.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// println!("{:?}", session.info().locators().await);
    /// // print ["tcp/127.0.0.1:7447"]
    /// # }
    /// ```
    #[zenoh_macros::unstable]
    pub fn locators(&self) -> impl Resolve<Vec<Locator>> + '_ {
        ResolveClosure::new(|| self.session.locators())
    }

    /// Return information about currently opened transport sessions. Transport session is a connection to another zenoh node.
    ///
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let transports = session.info().transports().await;
    /// for transport in transports {
    ///     println!("Transport: zid={}, whatami={:?}", transport.zid(), transport.whatami());
    /// }
    /// # }
    /// ```
    #[zenoh_macros::unstable]
    pub fn transports(&self) -> TransportsBuilder<'_> {
        TransportsBuilder::new(&self.session)
    }

    /// Return information about links across all transports.
    ///
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let links = session.info().links().await;
    /// for link in links {
    ///     println!("Link: {} -> {}", link.src(), link.dst());
    /// }
    /// # }
    /// ```
    #[zenoh_macros::unstable]
    pub fn links(&self) -> LinksBuilder<'_> {
        LinksBuilder::new(&self.session)
    }

    /// Subscribe to transport lifecycle events.
    ///
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    /// use zenoh::sample::SampleKind;
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let events = session.info()
    ///     .transport_events_listener()
    ///     .history(true)
    ///     .with(flume::bounded(32))
    ///     .await
    ///     .expect("Failed to declare transport events listener");
    ///
    /// while let Ok(event) = events.recv_async().await {
    ///     match event.kind() {
    ///         SampleKind::Put => println!("Transport opened: {}", event.transport().zid()),
    ///         SampleKind::Delete => println!("Transport closed"),
    ///     }
    /// }
    /// # }
    /// ```
    #[zenoh_macros::unstable]
    pub fn transport_events_listener(&self) -> TransportEventsListenerBuilder<'_, DefaultHandler> {
        TransportEventsListenerBuilder::new(&self.session)
    }

    /// Subscribe to link lifecycle events.
    ///
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    /// use zenoh::sample::SampleKind;
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let listener = session.info()
    ///     .link_events_listener()
    ///     .history(true)
    ///     .with(flume::bounded(32))
    ///     .await
    ///     .expect("Failed to declare link events listener");
    ///
    /// while let Ok(event) = listener.recv_async().await {
    ///     match event.kind() {
    ///         SampleKind::Put => println!("Link added: {} -> {}",
    ///             event.link().src(), event.link().dst()),
    ///         SampleKind::Delete => println!("Link removed"),
    ///     }
    /// }
    /// # }
    /// ```
    #[zenoh_macros::unstable]
    pub fn link_events_listener(&self) -> LinkEventsListenerBuilder<'_, DefaultHandler> {
        LinkEventsListenerBuilder::new(&self.session)
    }
}

/// Transport is a connection established to zenoh peer node.
/// Multiple transports to the same peer can exist. At this moment it's possible
/// to have both a unicast and a multicast transport to the same peer.
///
/// Each transport can have multiple corresponding [`Link`](crate::session::Link)s which represent
/// actual established data links with various protocols.
#[cfg(feature = "unstable")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transport {
    pub(crate) zid: ZenohId,
    pub(crate) whatami: WhatAmI,
    pub(crate) is_qos: bool,
    pub(crate) is_multicast: bool,
    #[cfg(feature = "shared-memory")]
    pub(crate) is_shm: bool,
}

#[cfg(feature = "unstable")]
impl Transport {
    /// Constructs an uninitialized empty Transport.
    #[zenoh_macros::internal]
    pub fn empty() -> Self {
        Transport {
            zid: ZenohId::default(),
            whatami: WhatAmI::default(),
            is_qos: false,
            is_multicast: false,
            #[cfg(feature = "shared-memory")]
            is_shm: false,
        }
    }

    /// Constructs a Transport from individual fields.
    #[zenoh_macros::internal]
    pub fn new_from_fields(
        zid: ZenohId,
        whatami: WhatAmI,
        is_qos: bool,
        is_multicast: bool,
        #[cfg(feature = "shared-memory")] is_shm: bool,
    ) -> Self {
        Transport {
            zid,
            whatami,
            is_qos,
            is_multicast,
            #[cfg(feature = "shared-memory")]
            is_shm,
        }
    }

    /// Gets the ZenohId of the remote zenoh node.
    #[inline]
    pub fn zid(&self) -> &ZenohId {
        &self.zid
    }

    /// Gets the type of the remote zenoh node (Router, Peer, or Client).
    #[inline]
    pub fn whatami(&self) -> WhatAmI {
        self.whatami
    }

    /// Returns whether this transport supports QoS.
    #[inline]
    pub fn is_qos(&self) -> bool {
        self.is_qos
    }

    /// Returns whether this transport supports shared memory.
    #[cfg(feature = "shared-memory")]
    #[inline]
    pub fn is_shm(&self) -> bool {
        self.is_shm
    }

    /// Returns whether this transport is multicast.
    #[inline]
    pub fn is_multicast(&self) -> bool {
        self.is_multicast
    }
}

/// Describes a concrete link within a [`Transport`](crate::session::Transport).
/// Zenoh can establish multiple links to the same remote zenoh node using different protocols
/// (e.g., TCP, UDP, QUIC, etc.)
#[cfg(feature = "unstable")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Link {
    pub(crate) zid: ZenohId,
    pub(crate) src: Locator,
    pub(crate) dst: Locator,
    pub(crate) group: Option<Locator>,
    pub(crate) mtu: u16,
    pub(crate) is_streamed: bool,
    pub(crate) interfaces: Vec<String>,
    pub(crate) auth_identifier: Option<String>,
    pub(crate) priorities: Option<(u8, u8)>,
    pub(crate) reliability: Option<Reliability>,
}

#[cfg(feature = "unstable")]
impl Link {
    /// Constructs an uninitialized empty Link.
    #[zenoh_macros::internal]
    pub fn empty() -> Self {
        Link {
            zid: ZenohId::default(),
            src: Locator::empty(),
            dst: Locator::empty(),
            group: None,
            mtu: 0,
            is_streamed: false,
            interfaces: Vec::new(),
            auth_identifier: None,
            priorities: None,
            reliability: None,
        }
    }

    /// Gets the ZenohId of the transport this link belongs to.
    #[inline]
    pub fn zid(&self) -> &ZenohId {
        &self.zid
    }

    /// Gets the source locator (local endpoint).
    #[inline]
    pub fn src(&self) -> &Locator {
        &self.src
    }

    /// Gets the destination locator (remote endpoint).
    #[inline]
    pub fn dst(&self) -> &Locator {
        &self.dst
    }

    /// Gets the optional group locator (destination if link is for multicast).
    #[inline]
    pub fn group(&self) -> Option<&Locator> {
        self.group.as_ref()
    }

    /// Gets the maximum transmission unit in bytes (MTU) of the link.
    #[inline]
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Returns whether the link is streamed.
    #[inline]
    pub fn is_streamed(&self) -> bool {
        self.is_streamed
    }

    /// Gets the network interfaces associated with the link.
    #[inline]
    pub fn interfaces(&self) -> &[String] {
        &self.interfaces
    }

    /// Iterate over the network interfaces associated with the link without allocating.
    ///
    /// The iterator borrows the interface names from this link, in the same order as
    /// [`Self::interfaces`].
    #[inline]
    pub fn interfaces_iter(&self) -> std::slice::Iter<'_, String> {
        self.interfaces.iter()
    }

    /// Gets the authentication identifier used for the link (if any).
    #[inline]
    pub fn auth_identifier(&self) -> Option<&str> {
        self.auth_identifier.as_deref()
    }

    /// Gets the optional priority range (min, max) associated with the link.
    /// The numeric priority values corresponds [`Priority`](crate::qos::Priority)
    /// but can also contain value 0 (Control) not exposed in the public enum.
    /// Returns None if the transport does not support QoS.
    #[inline]
    pub fn priorities(&self) -> Option<(u8, u8)> {
        self.priorities
    }

    /// Gets the reliability level of the link.
    /// Returns None if the transport does not support QoS.
    #[inline]
    pub fn reliability(&self) -> Option<Reliability> {
        self.reliability
    }
}

/// Event emitted when a transport is opened or closed
#[cfg(feature = "unstable")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportEvent {
    pub(crate) kind: SampleKind, // Put = opened, Delete = closed
    pub(crate) transport: Transport,
}

#[cfg(feature = "unstable")]
impl TransportEvent {
    /// Constructs an uninitialized empty TransportEvent.
    #[zenoh_macros::internal]
    pub fn empty() -> Self {
        TransportEvent {
            kind: SampleKind::Put,
            transport: Transport::empty(),
        }
    }

    /// Returns the kind of event (Put for opened, Delete for closed)
    pub fn kind(&self) -> SampleKind {
        self.kind
    }

    /// Returns a reference to the transport
    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Returns a mutable reference to the transport
    pub fn transport_mut(&mut self) -> &mut Transport {
        &mut self.transport
    }
}

#[cfg(feature = "unstable")]
impl CallbackParameter for TransportEvent {
    type Message<'a> = Self;
    fn from_message(msg: Self::Message<'_>) -> Self {
        msg
    }
}

/// Event emitted when a link is added or removed
#[cfg(feature = "unstable")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkEvent {
    pub(crate) kind: SampleKind, // Put = added, Delete = removed
    pub(crate) link: Link,
}

#[cfg(feature = "unstable")]
impl LinkEvent {
    /// Constructs an uninitialized empty LinkEvent.
    #[zenoh_macros::internal]
    pub fn empty() -> Self {
        LinkEvent {
            kind: SampleKind::Put,
            link: Link::empty(),
        }
    }

    /// Returns the kind of event (Put for added, Delete for removed)
    pub fn kind(&self) -> SampleKind {
        self.kind
    }

    /// Returns a reference to the link
    pub fn link(&self) -> &Link {
        &self.link
    }

    /// Returns a mutable reference to the link
    pub fn link_mut(&mut self) -> &mut Link {
        &mut self.link
    }
}

#[cfg(feature = "unstable")]
impl CallbackParameter for LinkEvent {
    type Message<'a> = Self;
    fn from_message(msg: Self::Message<'_>) -> Self {
        msg
    }
}

/// A transport the engine holds and the links under it: what a face is, as the engine reports it.
///
/// The links are carried beside the transport and not inside it because a transport outlives any
/// one of its links, as the model of the engine states
/// (`crates/wz-session-core/src/face.rs`).
#[cfg(feature = "unstable")]
#[derive(Debug, Clone)]
pub(crate) struct Face {
    pub(crate) transport: Transport,
    pub(crate) links: Vec<Link>,
}

#[cfg(feature = "unstable")]
impl Face {
    /// Whether `transport` is this face's: the identity a listener filtered by transport reads, a
    /// node and the kind of connection to it, as upstream's broadcast does.
    pub(crate) fn is_the_face_of(&self, transport: &Transport) -> bool {
        self.transport.zid == transport.zid && self.transport.is_multicast == transport.is_multicast
    }
}

/// What the engine tells of a face: that it came up (Put) or went down (Delete).
#[cfg(feature = "unstable")]
pub(crate) type FaceSink = std::sync::Arc<dyn Fn(SampleKind, &Face) + Send + Sync>;

// `Link::empty` is an `internal` door, so the test is held to the build that has it.
#[cfg(all(test, feature = "unstable", feature = "internal"))]
mod interfaces_iter_tests {
    use super::*;

    #[test]
    fn link_interfaces_iter() {
        let mut link = Link::empty();
        assert_eq!(link.interfaces_iter().next(), None);

        link.interfaces = vec!["eth0".into(), "lo".into()];
        let mut iter = link.interfaces_iter();
        let mut independent = iter.clone();
        assert_eq!(iter.len(), link.interfaces().len());
        for interface in link.interfaces() {
            assert!(std::ptr::eq(iter.next().unwrap(), interface));
        }
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
        assert!(std::ptr::eq(
            independent.next_back().unwrap(),
            &link.interfaces()[1]
        ));
    }
}

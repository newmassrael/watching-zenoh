// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a session reports of the peers it holds: one `FaceSnapshot` for each established
//! transport and a `LinkSnapshot` for each physical link under it, and the `FaceEventKind`
//! a watcher is told when a face comes up or goes down.
//!
//! The model is the session's, not an engine's: it is read off a session's own
//! `SessionLinkActions`, so an engine that holds a session builds its snapshots the same way
//! and an ABI that reports them (a connectivity plane, an admin space) names none.
//!
//! Every field is READ off the face, never defaulted into a plausible-looking value:
//! `interfaces` keeps the three-state answer of a link's subject (resolved, resolved-empty,
//! undetermined) rather than flattening a failed lookup to an empty set the way upstream does,
//! and `kind` is `None` for a driver that cannot name itself. An ABI decides how to spell
//! "unknown", and can only do that honestly if the unknown survives to it.
//!
//! The names are plain code and not links on purpose: rustdoc reads a module's first paragraph
//! in its parent's scope as well, where these items are not named.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::link::{LinkKind, LinkSubject};
#[cfg(feature = "session-unicast")]
use {
    crate::link::SessionRuntime, crate::session_actions::SessionLinkActions,
    wz_runtime_core::TimeSource,
};

/// One PHYSICAL link of an established face.
#[derive(Debug, Clone)]
pub struct LinkSnapshot {
    /// This end's locator.
    pub src: String,
    /// The peer end's locator.
    pub dst: String,
    /// The KIND of link, or `None` when the driver cannot say.
    pub kind: Option<LinkKind>,
    /// The NICs this link's local address sits on, with `None` meaning "could not be
    /// determined" — see [`crate::link::LinkSubject`].
    pub interfaces: Option<Vec<String>>,
    /// The negotiated outbound frame budget, clamped into the `u16` both upstreams report.
    pub mtu: u16,
    /// The group a member of a joined group is reached through, `None` on a unicast link.
    pub group: Option<GroupLink>,
    /// The common name on the peer's leaf certificate, `None` for a link that presents no
    /// certificate or whose certificate names none ([`crate::link::LinkSubject::cert_common_name`]
    /// states the collapse). Read it through [`Self::auth_identifier`], which says for which
    /// links a name is the identifier of the link.
    pub cert_common_name: Option<String>,
    /// The inclusive priority band the transport negotiated for the link, as the wire's bytes,
    /// the highest priority (the lowest number) first: what the QoS extension of the handshake
    /// carried (`prio=` of the endpoint). `None` when none was named, or when the transport did
    /// not negotiate QoS.
    pub priorities: Option<(u8, u8)>,
    /// Whether the link was negotiated as a reliable one (`rel=` of the endpoint), `None` when it
    /// named none.
    pub reliable: Option<bool>,
}

impl LinkSnapshot {
    /// A link of a unicast face from `src` to `dst`, as the `subject` of its transport and the
    /// `mtu` negotiated on it describe it. A link whose driver gives no subject has no kind, no
    /// interfaces and no certificate.
    pub fn unicast(src: &str, dst: &str, subject: Option<&LinkSubject>, mtu: u16) -> Self {
        Self {
            src: String::from(src),
            dst: String::from(dst),
            kind: subject.and_then(|s| s.kind),
            interfaces: subject.and_then(|s| s.interfaces.clone()),
            mtu,
            group: None,
            cert_common_name: subject.and_then(|s| s.cert_common_name.clone()),
            priorities: None,
            reliable: None,
        }
    }

    /// Whether the link carries a byte stream rather than framed datagrams, as the Rust API's
    /// `Link::is_streamed` reports it. A link whose driver cannot name its kind is not streamed:
    /// nothing is known of it to say otherwise.
    pub fn is_streamed(&self) -> bool {
        self.kind.is_some_and(|kind| kind.is_streamed())
    }

    /// Whether the link delivers reliably, as the Rust API's `Link::reliability` reports it, and
    /// `None` for a link whose driver cannot name its kind.
    pub fn is_reliable(&self) -> Option<bool> {
        self.kind.map(|kind| kind.is_reliable())
    }

    /// The identifier the link authenticated the peer by, as the Rust API's
    /// `Link::auth_identifier` reports it: the common name of the leaf certificate of a TLS or a
    /// QUIC link, and nothing for the others, the reliable UDP link among them, which upstream
    /// gives the UDP auth id although it runs over QUIC
    /// (`io/zenoh-links/zenoh-link-udp/src/unicast.rs` @ `&LinkAuthId::Udp`).
    pub fn auth_identifier(&self) -> Option<&str> {
        use crate::link::LinkKind;
        match self.kind? {
            LinkKind::Tls | LinkKind::Quic | LinkKind::QuicDatagram => {
                self.cert_common_name.as_deref()
            }
            LinkKind::Tcp
            | LinkKind::Udp
            | LinkKind::UdpReliable
            | LinkKind::Serial
            | LinkKind::Unixpipe
            | LinkKind::UnixsockStream
            | LinkKind::Vsock
            | LinkKind::Ws => None,
        }
    }
}

/// The group under a group member's link, in the two spellings the two upstreams report it
/// by: each ABI picks its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupLink {
    /// The group's locator, which zenoh reports as the link's `group`
    /// (`io/zenoh-link-commons/src/lib.rs` @ `group: Some(link.get_dst().to_owned()),`).
    pub locator: String,
    /// The endpoint the session joined it by, its socket keys included, which zenoh-pico
    /// reports as the link's `src` (`vendor/zenoh-pico/src/transport/multicast/rx.c` @
    /// `entry->common._link_src = _z_endpoint_to_string(&ztm->_common._link->_endpoint);`).
    pub endpoint: String,
}

/// One ESTABLISHED face, plus the links under it.
///
/// The transport half is the identity and the negotiated booleans a transport value carries;
/// the links are carried alongside rather than inside because a transport outlives any one of
/// its links.
#[derive(Debug, Clone)]
pub struct FaceSnapshot {
    /// The peer's zid.
    pub zid: [u8; 16],
    /// The peer's role as the raw 2-bit INIT wire form.
    pub whatami: u8,
    /// Whether QoS was negotiated on this transport.
    pub is_qos: bool,
    /// Whether this is a multicast transport: `false` for a unicast face, `true` for a member
    /// of a group the session joined, which both upstreams report as a transport of its own.
    pub is_multicast: bool,
    /// Whether SHM was negotiated on this transport. Reported on every build: the FACT is one
    /// a session can state either way, and gating the field would make an ABI's shape decide
    /// what the session is allowed to know.
    pub is_shm: bool,
    /// This face's physical links, one entry each.
    pub links: Vec<LinkSnapshot>,
}

#[cfg(feature = "session-unicast")]
impl FaceSnapshot {
    /// Snapshot the face a session's `actions` are the end of, or `None` when its INIT has not
    /// populated the identity slots yet.
    ///
    /// The `None` is the half-open case, and it is a REFUSAL rather than a default: a transport
    /// reported with a zero zid is a peer an application can neither match nor dial.
    pub fn of_actions<R: SessionRuntime, T: TimeSource>(
        actions: &SessionLinkActions<R, T>,
    ) -> Option<Self> {
        let peer = actions.peer_zid()?;
        let whatami = actions.peer_whatami_wire()?;
        let mut zid = [0u8; 16];
        let n = peer.len().min(16);
        zid[..n].copy_from_slice(&peer[..n]);
        let subject = actions.link_subject().cloned();
        let mtu = u16::try_from(actions.negotiated_batch_mtu()).unwrap_or(u16::MAX);
        // What the handshake negotiated for the links of the transport: the band and the class the
        // QoS extension carried, which the links of the face share.
        #[cfg(feature = "session-extqos")]
        let (priorities, reliable) = {
            let negotiated = actions.qos_link_metadata();
            (
                negotiated
                    .priorities
                    .map(|band| (band.start() as u8, band.end() as u8)),
                negotiated
                    .reliability
                    .map(|class| matches!(class, crate::reliability::Reliability::Reliable)),
            )
        };
        #[cfg(not(feature = "session-extqos"))]
        let (priorities, reliable) = (None, None);
        let links = actions
            .link_endpoints_all()
            .into_iter()
            .map(|e| {
                let mut link =
                    LinkSnapshot::unicast(e.src.as_str(), e.dst.as_str(), subject.as_ref(), mtu);
                link.priorities = priorities;
                link.reliable = reliable;
                link
            })
            .collect();
        // A build without `transport-qos` never negotiates the ext, so `false` is the MEASURED
        // answer there rather than a stand-in: there is no conduit split to report. `is_qos`
        // itself is gated, so this is also the only spelling that compiles in both
        // configurations.
        #[cfg(feature = "transport-qos")]
        let is_qos = actions.is_qos();
        #[cfg(not(feature = "transport-qos"))]
        let is_qos = false;
        // Same shape, same reason, for the SHM ext.
        #[cfg(feature = "transport-shm")]
        let is_shm = actions.is_shm();
        #[cfg(not(feature = "transport-shm"))]
        let is_shm = false;
        Some(Self {
            zid,
            whatami,
            is_qos,
            is_multicast: false,
            is_shm,
            links,
        })
    }
}

/// Which way a face moved: the input to the kind an event of a transport or a link carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaceEventKind {
    /// The face reached Established.
    Up,
    /// The face left the live set.
    Down,
}

/// A face-lifecycle observer.
///
/// `Arc` rather than `Box` because a registry clones the sink list OUT of its lock before it
/// invokes any of them: a sink may reach code that re-enters the registry.
pub type FaceEventSink = Arc<dyn Fn(FaceEventKind, &FaceSnapshot) + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;

    fn named_subject(kind: Option<LinkKind>) -> LinkSubject {
        LinkSubject {
            kind,
            interfaces: Some(alloc::vec![String::from("lo")]),
            ..LinkSubject::default()
        }
        .with_cert_common_name(Some(String::from("alice")))
    }

    #[test]
    fn a_unicast_link_reads_what_its_subject_says() {
        let subject = named_subject(Some(LinkKind::Tls));
        let link = LinkSnapshot::unicast(
            "tls/10.0.0.1:7447",
            "tls/10.0.0.2:5000",
            Some(&subject),
            1200,
        );
        assert_eq!(link.src, "tls/10.0.0.1:7447");
        assert_eq!(link.dst, "tls/10.0.0.2:5000");
        assert_eq!(link.kind, Some(LinkKind::Tls));
        assert_eq!(link.interfaces, Some(alloc::vec![String::from("lo")]));
        assert_eq!(link.mtu, 1200);
        assert!(link.group.is_none());
        assert_eq!(link.cert_common_name.as_deref(), Some("alice"));
    }

    #[test]
    fn a_link_with_no_subject_says_nothing_of_itself() {
        let link = LinkSnapshot::unicast("tcp/a", "tcp/b", None, 1);
        assert_eq!(link.kind, None);
        assert_eq!(link.interfaces, None);
        assert_eq!(link.cert_common_name, None);
        assert!(
            !link.is_streamed(),
            "nothing is known of it to say it streams"
        );
        assert_eq!(link.is_reliable(), None);
        assert_eq!(link.auth_identifier(), None);
    }

    #[test]
    fn a_link_answers_streamed_and_reliable_as_its_kind_does() {
        for kind in LinkKind::ALL {
            let subject = named_subject(Some(*kind));
            let link = LinkSnapshot::unicast("a", "b", Some(&subject), 1);
            assert_eq!(link.is_streamed(), kind.is_streamed(), "{kind:?}");
            assert_eq!(link.is_reliable(), Some(kind.is_reliable()), "{kind:?}");
        }
    }

    #[test]
    fn only_a_tls_or_quic_link_names_its_peer_by_the_name_on_its_certificate() {
        for kind in LinkKind::ALL {
            let subject = named_subject(Some(*kind));
            let link = LinkSnapshot::unicast("a", "b", Some(&subject), 1);
            let names = matches!(
                kind,
                LinkKind::Tls | LinkKind::Quic | LinkKind::QuicDatagram
            );
            assert_eq!(
                link.auth_identifier(),
                names.then_some("alice"),
                "{kind:?}: the reliable UDP link, which runs over QUIC, has the UDP auth id"
            );
        }
        // A TLS link whose peer presented no certificate has no name to give.
        let mut subject = named_subject(Some(LinkKind::Tls));
        subject.cert_common_name = None;
        let link = LinkSnapshot::unicast("a", "b", Some(&subject), 1);
        assert_eq!(link.auth_identifier(), None);
    }
}

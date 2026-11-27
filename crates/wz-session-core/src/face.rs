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
use core::ffi::c_void;
use core::ptr::NonNull;

use crate::link::{LinkEnd, LinkEnds, LinkKind, LinkSubject};
use crate::text_out::TextOut;
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

    /// The link of `row` as [`Self::of_row`] reads it, with what its snapshot says beyond the row
    /// (`facts`): the same link [`FaceSnapshot::of_actions`] reads, where `facts` were read off
    /// the same session (`LinkFacts::of_actions`).
    pub fn of_row_with(row: &FaceLinkRow, facts: &LinkFacts) -> Option<Self> {
        let mut link = Self::of_row(row)?;
        link.interfaces = facts.interfaces.clone();
        link.cert_common_name = facts.cert_common_name.clone();
        link.priorities = facts.priorities;
        link.reliable = facts.reliable;
        Some(link)
    }

    /// The link of `row`, `None` for the row of a face alone: what a watcher of snapshots told
    /// through rows builds a face's links from. What a row does not hold reads as not known (the
    /// NICs, the name on the peer's certificate, the band and the class the handshake
    /// negotiated), and a group's locator is the endpoint it was joined by without its metadata
    /// and config, as the group is labelled where it is joined.
    pub fn of_row(row: &FaceLinkRow) -> Option<Self> {
        if row.links == 0 {
            return None;
        }
        let group = row.group_endpoint.as_ref().map(|endpoint| {
            let endpoint = endpoint.as_str();
            GroupLink {
                locator: String::from(endpoint.split(['#', '?']).next().unwrap_or(endpoint)),
                endpoint: String::from(endpoint),
            }
        });
        Some(Self {
            src: row.src_text(),
            dst: row.dst_text(),
            kind: row.kind,
            interfaces: None,
            mtu: row.mtu,
            group,
            cert_common_name: None,
            priorities: None,
            reliable: None,
        })
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

/// What a link's snapshot says beyond its row ([`FaceLinkRow`]), none of which changes while the
/// link lives: what a session that keeps its faces' rows reads off a link as it makes a snapshot
/// of it ([`LinkSnapshot::of_row_with`]). The names it holds are on the heap, as a snapshot's
/// are, so a session that takes no heap after its open keeps the rows alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkFacts {
    /// As [`LinkSnapshot::interfaces`].
    pub interfaces: Option<Vec<String>>,
    /// As [`LinkSnapshot::cert_common_name`].
    pub cert_common_name: Option<String>,
    /// As [`LinkSnapshot::priorities`].
    pub priorities: Option<(u8, u8)>,
    /// As [`LinkSnapshot::reliable`].
    pub reliable: Option<bool>,
}

#[cfg(feature = "session-unicast")]
impl LinkFacts {
    /// What the link of the session `actions` are the end of says beyond its row: what its
    /// transport's subject names, and the band and the class the handshake's QoS extension
    /// carried.
    pub fn of_actions<R: SessionRuntime, T: TimeSource>(
        actions: &SessionLinkActions<R, T>,
    ) -> Self {
        let subject = actions.link_subject();
        let (priorities, reliable) = negotiated_band(actions);
        Self {
            interfaces: subject.and_then(|s| s.interfaces.clone()),
            cert_common_name: subject.and_then(|s| s.cert_common_name.clone()),
            priorities,
            reliable,
        }
    }
}

/// The band and the class the QoS extension of the handshake of the session `actions` carried
/// for its links, as a link's snapshot states them (`LinkSnapshot::priorities`,
/// `LinkSnapshot::reliable`).
#[cfg(feature = "session-unicast")]
fn negotiated_band<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
) -> (Option<(u8, u8)>, Option<bool>) {
    #[cfg(feature = "session-extqos")]
    {
        let negotiated = actions.qos_link_metadata();
        (
            negotiated
                .priorities
                .map(|band| (band.start() as u8, band.end() as u8)),
            negotiated
                .reliability
                .map(|class| matches!(class, crate::reliability::Reliability::Reliable)),
        )
    }
    #[cfg(not(feature = "session-extqos"))]
    {
        let _ = actions;
        (None, None)
    }
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

impl FaceSnapshot {
    /// The face of `row`, with no link yet: what a watcher of snapshots told through rows starts
    /// a face from, at its first row, and adds each row's link to ([`LinkSnapshot::of_row`]).
    pub fn of_face_row(row: &FaceLinkRow) -> Self {
        Self {
            zid: row.zid,
            whatami: row.whatami,
            is_qos: row.is_qos,
            is_multicast: row.is_multicast,
            is_shm: row.is_shm,
            links: Vec::new(),
        }
    }
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
        // Read in its fixed form: a copy of the heap would be made each time a face comes up or
        // goes while something watches the faces.
        let peer = actions.peer_session_zid()?;
        let whatami = actions.peer_whatami_wire()?;
        let mut zid = [0u8; 16];
        // The first sixteen bytes at most, as many as the peer's zid has.
        for (into, byte) in zid.iter_mut().zip(peer.as_slice()) {
            *into = *byte;
        }
        let subject = actions.link_subject().cloned();
        let mtu = u16::try_from(actions.negotiated_batch_mtu()).unwrap_or(u16::MAX);
        // What the handshake negotiated for the links of the transport: the band and the class the
        // QoS extension carried, which the links of the face share.
        let (priorities, reliable) = negotiated_band(actions);
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
/// A text as a [`FaceLinkRow`] holds it, always whole: in the row itself when it is at most `N`
/// bytes, on the heap when it is longer. Only a heap engine reaches the heap form, for a locator
/// of upstream's length that no row bound sizes (a unix socket path); an engine that reserves
/// its memory refuses a link or a group whose text would not fit where it admits it, so its rows
/// are read with nothing allocated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowTextOf<const N: usize> {
    /// A text of at most `N` bytes, held in the row.
    Inline(heapless::String<N>),
    /// A longer text, on the heap.
    Spilled(String),
}

impl<const N: usize> RowTextOf<N> {
    /// `text`, whole: in the row when it fits.
    pub fn of(text: &str) -> Self {
        heapless::String::try_from(text)
            .map_or_else(|_| Self::Spilled(String::from(text)), Self::Inline)
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Inline(text) => text.as_str(),
            Self::Spilled(text) => text.as_str(),
        }
    }

    /// Whether the text is held in the row, with nothing allocated.
    pub fn is_inline(&self) -> bool {
        matches!(self, Self::Inline(_))
    }
}

impl<const N: usize> core::ops::Deref for RowTextOf<N> {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

/// A locator, or the name of a link's end, as a [`FaceLinkRow`] holds it: in the row up to
/// [`crate::caps::MAX_LOCATOR_LEN`] bytes.
pub type RowText = RowTextOf<{ crate::caps::MAX_LOCATOR_LEN }>;

/// One end of a link its driver lent ([`LinkEnd`]), owned by a [`FaceLinkRow`]: the fact the
/// end's locator is written from, which outlives the link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LentEnd {
    /// The address of an IP socket.
    Ip(core::net::SocketAddr),
    /// The name of an end of another family, as its kind writes it after the scheme.
    Named(RowText),
}

impl LentEnd {
    /// `end`, owned: a name copied into its row, or onto the heap past it, as [`RowTextOf::of`]
    /// keeps a text.
    pub fn of(end: LinkEnd<'_>) -> Self {
        match end {
            LinkEnd::Ip(at) => Self::Ip(at),
            LinkEnd::Named(name) => Self::Named(RowText::of(name)),
        }
    }

    /// The end, lent as its driver lends it.
    pub fn lent(&self) -> LinkEnd<'_> {
        match self {
            Self::Ip(at) => LinkEnd::Ip(*at),
            Self::Named(name) => LinkEnd::Named(name.as_str()),
        }
    }
}

/// The two ends of a link as a [`FaceLinkRow`] holds them: the facts their locators are written
/// from when the row is read ([`FaceLinkRow::write_src`], [`FaceLinkRow::write_dst`]), so an
/// engine that tells its faces a row at a time writes no locator, and a reader writes each one
/// once, where it hands it on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowEnds {
    /// No ends: the row of a face alone, or of a link whose driver lends none.
    None,
    /// The ends a link's driver lent, on a link of `kind`, which names both locators' scheme.
    Lent {
        /// The kind of link the driver named with its ends.
        kind: LinkKind,
        /// This end.
        src: LentEnd,
        /// The peer's end.
        dst: LentEnd,
    },
    /// The link to a member of a group: this node's end on the group, written whole, and the
    /// address the member's datagrams come from, whose locator the kind of the group's members
    /// names ([`FaceLinkRow::group_endpoint`]).
    Member {
        /// This node's end on the group.
        src: RowText,
        /// The address the member's datagrams come from.
        at: core::net::SocketAddr,
    },
    /// Two locators held written whole, as an engine that reports its faces by their snapshots
    /// keeps them.
    Written {
        /// This end's locator.
        src: RowText,
        /// The peer end's locator.
        dst: RowText,
    },
}

impl RowEnds {
    /// The ends `link` lends, owned; none for a link whose driver lends none.
    pub fn lent(link: Option<LinkEnds<'_>>) -> Self {
        match link {
            Some(link) => Self::Lent {
                kind: link.kind,
                src: LentEnd::of(link.src),
                dst: LentEnd::of(link.dst),
            },
            None => Self::None,
        }
    }
}

/// A group's endpoint as a [`FaceLinkRow`] holds it, its socket keys included: in the row up to
/// [`GROUP_ROW_LEN`] bytes.
pub type GroupRowText = RowTextOf<GROUP_ROW_LEN>;

/// The bytes a group endpoint's row holds: the longest endpoint the build joins a group by,
/// [`crate::caps::MAX_GROUP_ENDPOINT_LEN`], or a raw Ethernet group's bound where the build has
/// that transport and its bound is the longer.
#[cfg(feature = "transport-link-raweth")]
pub const GROUP_ROW_LEN: usize =
    if crate::caps::MAX_RAWETH_ENDPOINT_LEN > crate::caps::MAX_GROUP_ENDPOINT_LEN {
        crate::caps::MAX_RAWETH_ENDPOINT_LEN
    } else {
        crate::caps::MAX_GROUP_ENDPOINT_LEN
    };

/// The bytes a group endpoint's row holds: the longest endpoint the build joins a group by.
#[cfg(not(feature = "transport-link-raweth"))]
pub const GROUP_ROW_LEN: usize = crate::caps::MAX_GROUP_ENDPOINT_LEN;

/// One link of an established face, with the face it is under, as a reader takes it out of the
/// session's lock to hand on: every field is held in the row, so reading the faces one row at a
/// time allocates nothing. What a connectivity plane reports of a transport and of its link; the
/// fields an ABI that keeps a face's snapshot reads beyond them stay on [`FaceSnapshot`].
#[derive(Debug, Clone)]
pub struct FaceLinkRow {
    /// The peer's zid.
    pub zid: [u8; 16],
    /// The peer's role as the raw 2-bit INIT wire form.
    pub whatami: u8,
    /// Whether QoS was negotiated on the transport.
    pub is_qos: bool,
    /// Whether the transport is a member of a group the session joined.
    pub is_multicast: bool,
    /// Whether SHM was negotiated on the transport.
    pub is_shm: bool,
    /// Which link of its face this is, `0` for the first: a reader that reports transports reads
    /// the rows whose link is `0`, one for each face.
    pub link: usize,
    /// How many links its face has: a reader told a face's departure a row at a time tells the
    /// transport after the last ([`Self::is_last_of_face`]). `0` for the one row a face with no
    /// link is told by, which names the face alone: its ends are empty, with no kind and no MTU.
    pub links: usize,
    /// The link's two ends, from which its locators are written as the row is read.
    pub ends: RowEnds,
    /// The kind of link, `None` when the driver cannot say.
    pub kind: Option<LinkKind>,
    /// The negotiated outbound frame budget, clamped into a `u16`.
    pub mtu: u16,
    /// The endpoint the session joined the group by, for a member of a joined group.
    pub group_endpoint: Option<GroupRowText>,
    /// How many rows of faces that came or went after this one the session kept for no watcher,
    /// its queue of them full ([`crate::caps::MAX_FACE_WATCH_ROWS`]): told with this row, once,
    /// so a watcher knows that what it holds of the faces may miss them. `0` in a row of the
    /// faces that stand, and in a row told while nothing was lost after it.
    pub lost_after: usize,
}

impl FaceLinkRow {
    /// The `at`-th link of `face`, copied into a row; `None` past its last link.
    pub fn of_snapshot(face: &FaceSnapshot, at: usize) -> Option<Self> {
        let link = face.links.get(at)?;
        let ends = RowEnds::Written {
            src: RowText::of(&link.src),
            dst: RowText::of(&link.dst),
        };
        let group_endpoint = link
            .group
            .as_ref()
            .map(|group| GroupRowText::of(&group.endpoint));
        Some(Self {
            zid: face.zid,
            whatami: face.whatami,
            is_qos: face.is_qos,
            is_multicast: face.is_multicast,
            is_shm: face.is_shm,
            link: at,
            links: face.links.len(),
            ends,
            kind: link.kind,
            mtu: link.mtu,
            group_endpoint,
            lost_after: 0,
        })
    }

    /// The one row a face with no link is told by: the facts of `face` alone, no link
    /// ([`Self::links`] `0`) and empty ends.
    pub fn of_face_alone(face: &FaceSnapshot) -> Self {
        Self {
            zid: face.zid,
            whatami: face.whatami,
            is_qos: face.is_qos,
            is_multicast: face.is_multicast,
            is_shm: face.is_shm,
            link: 0,
            links: 0,
            ends: RowEnds::None,
            kind: None,
            mtu: 0,
            group_endpoint: None,
            lost_after: 0,
        }
    }

    /// Hand `tell` each row of `face`, its links in order, or the one row of the face alone when
    /// it has none: what a watcher of the faces' rows is told of a face an engine reports by its
    /// snapshot.
    pub fn each_of_snapshot(face: &FaceSnapshot, mut tell: impl FnMut(Self)) {
        if face.links.is_empty() {
            tell(Self::of_face_alone(face));
            return;
        }
        for at in 0..face.links.len() {
            if let Some(row) = Self::of_snapshot(face, at) {
                tell(row);
            }
        }
    }

    /// Whether this is the last row of its face, the row of a face alone among them: where a
    /// reader told a face's departure a row at a time tells the transport, after its last link.
    pub fn is_last_of_face(&self) -> bool {
        self.link.saturating_add(1) >= self.links
    }

    /// Write the locator of this end of the row's link into `out`: nothing for a row with no
    /// ends ([`RowEnds::None`]).
    pub fn write_src<W: TextOut + ?Sized>(&self, out: &mut W) {
        match &self.ends {
            RowEnds::None => {}
            RowEnds::Lent { kind, src, .. } => crate::link::write_locator(*kind, src.lent(), out),
            RowEnds::Member { src, .. } | RowEnds::Written { src, .. } => out.push_str(src),
        }
    }

    /// Write the locator of the peer's end of the row's link into `out`: a group member's as
    /// the kind of the group's members names it (a raweth group's by its MAC); nothing for a row
    /// with no ends.
    pub fn write_dst<W: TextOut + ?Sized>(&self, out: &mut W) {
        match &self.ends {
            RowEnds::None => {}
            RowEnds::Lent { kind, dst, .. } => crate::link::write_locator(*kind, dst.lent(), out),
            RowEnds::Member { at, .. } => member_end(*at, self.group_endpoint.as_deref(), out),
            RowEnds::Written { dst, .. } => out.push_str(dst),
        }
    }

    /// The locator of this end, written now ([`Self::write_src`]).
    pub fn src_text(&self) -> String {
        let mut text = String::new();
        self.write_src(&mut text);
        text
    }

    /// The locator of the peer's end, written now ([`Self::write_dst`]).
    pub fn dst_text(&self) -> String {
        let mut text = String::new();
        self.write_dst(&mut text);
        text
    }
}

#[cfg(feature = "session-unicast")]
impl FaceLinkRow {
    /// How many links the face `actions` is the end of has, `0` while its INIT has not populated
    /// the identity slots (the half-open face [`FaceSnapshot::of_actions`] refuses).
    pub fn links_of<R: SessionRuntime, T: TimeSource>(actions: &SessionLinkActions<R, T>) -> usize {
        if actions.peer_session_zid().is_none() || actions.peer_whatami_wire().is_none() {
            return 0;
        }
        let mut links: usize = 0;
        actions.visit_link_ends(|_| {
            // A count of the links a face holds, each a link the session admitted: it cannot
            // reach the width of the count, and a saturated one would still be a bound.
            links = links.saturating_add(1);
            true
        });
        links
    }

    /// The `at`-th link of the face `actions` is the end of, read as
    /// [`FaceSnapshot::of_actions`] reads it and written into the row; `None` for a half-open
    /// face or past its last link.
    pub fn of_actions<R: SessionRuntime, T: TimeSource>(
        actions: &SessionLinkActions<R, T>,
        at: usize,
    ) -> Option<Self> {
        let face = Self::face_of_actions(actions)?;
        let mut links: usize = 0;
        let mut ends = None;
        actions.visit_link_ends(|link| {
            if links == at {
                ends = Some(RowEnds::lent(link));
            }
            // A count of the links a face holds, each a link the session admitted: it cannot
            // reach the width of the count, and a saturated one would still be a bound.
            links = links.saturating_add(1);
            true
        });
        let ends = ends?;
        Some(Self {
            link: at,
            links,
            ends,
            ..face
        })
    }

    /// Hand `tell` each row of the face `actions` is the end of, read as [`Self::of_actions`]
    /// reads one, its links in order, or the one row of the face alone when it has none; none for
    /// a half-open face. What a watcher of the faces' rows is told of a face that came up or went,
    /// with nothing allocated for a link whose ends fit their rows.
    pub fn each_of_actions<R: SessionRuntime, T: TimeSource>(
        actions: &SessionLinkActions<R, T>,
        mut tell: impl FnMut(Self),
    ) {
        let Some(face) = Self::face_of_actions(actions) else {
            return;
        };
        let links = Self::links_of(actions);
        if links == 0 {
            tell(Self {
                kind: None,
                mtu: 0,
                ..face
            });
            return;
        }
        let mut at: usize = 0;
        actions.visit_link_ends(|link| {
            tell(Self {
                link: at,
                links,
                ends: RowEnds::lent(link),
                ..face.clone()
            });
            at = at.saturating_add(1);
            at < links
        });
    }

    /// The facts of the face `actions` is the end of, with its transport's kind of link and MTU,
    /// in a row of no link yet (`links` `0`, empty ends); `None` for a half-open face, whose
    /// INIT has not populated the identity slots.
    fn face_of_actions<R: SessionRuntime, T: TimeSource>(
        actions: &SessionLinkActions<R, T>,
    ) -> Option<Self> {
        let peer = actions.peer_session_zid()?;
        let whatami = actions.peer_whatami_wire()?;
        let mut zid = [0u8; 16];
        // The first sixteen bytes at most, as many as the peer's zid has.
        for (into, byte) in zid.iter_mut().zip(peer.as_slice()) {
            *into = *byte;
        }
        let kind = actions.link_subject().and_then(|subject| subject.kind);
        let mtu = u16::try_from(actions.negotiated_batch_mtu()).unwrap_or(u16::MAX);
        #[cfg(feature = "transport-qos")]
        let is_qos = actions.is_qos();
        #[cfg(not(feature = "transport-qos"))]
        let is_qos = false;
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
            link: 0,
            links: 0,
            ends: RowEnds::None,
            kind,
            mtu,
            group_endpoint: None,
            lost_after: 0,
        })
    }
}

#[cfg(feature = "session-multicast")]
impl FaceLinkRow {
    /// `member` of a group as its row, the transport [`FaceSnapshot::of_group_member`] reports
    /// and its one link: from the group's locator `src` to the address the member's datagrams come
    /// from, held as the address, labelled by the `endpoint` the group was joined by. Every text
    /// that fits its row is held there, so an engine that admits only those reads its members with
    /// nothing allocated.
    /// `None` for a member whose JOIN named a role this node does not know.
    pub fn of_group_member(
        member: &crate::multicast_dispatch::MulticastMember,
        src: &str,
        endpoint: &str,
        is_shm: bool,
    ) -> Option<Self> {
        let whatami = member.whatami?.to_wire();
        let mut zid = [0u8; 16];
        for (into, byte) in zid.iter_mut().zip(member.peer.as_slice()) {
            *into = *byte;
        }
        Some(Self {
            zid,
            whatami,
            is_qos: false,
            is_multicast: true,
            is_shm,
            link: 0,
            links: 1,
            ends: RowEnds::Member {
                src: RowText::of(src),
                at: member.locator,
            },
            kind: member_link_kind(endpoint),
            mtu: 0,
            group_endpoint: Some(GroupRowText::of(endpoint)),
            lost_after: 0,
        })
    }
}

/// The locator of the end of a member of the group joined by `endpoint` whose datagrams come
/// from `at`, written into `out`: a raweth group's member is the `reth/` locator of its MAC
/// (`raweth_member_text`), any other group's its address on UDP, as upstream records a member's
/// locator. The one writer of a member's end, for its row and its snapshot alike.
fn member_end<W: TextOut + ?Sized>(at: core::net::SocketAddr, endpoint: Option<&str>, out: &mut W) {
    #[cfg(feature = "transport-link-raweth")]
    if endpoint.is_some_and(|endpoint| endpoint.starts_with("reth/")) {
        out.push_str(&raweth_member_text(at));
        return;
    }
    #[cfg(not(feature = "transport-link-raweth"))]
    let _ = endpoint;
    out.push_str("udp/");
    out.push_socket_addr(at);
}

/// The kind of a link to a member of the group joined by `endpoint`: none [`LinkKind`] names for
/// a raweth group's, UDP for any other group's.
#[cfg(feature = "session-multicast")]
fn member_link_kind(endpoint: &str) -> Option<LinkKind> {
    #[cfg(feature = "transport-link-raweth")]
    if endpoint.starts_with("reth/") {
        return None;
    }
    #[cfg(not(feature = "transport-link-raweth"))]
    let _ = endpoint;
    Some(LinkKind::Udp)
}

/// The `reth/` locator of the MAC a raweth group keyed its member by `at` for
/// ([`crate::raweth_link::member_locator`]), or `reth/<at>` for an address no raweth member is
/// keyed by, which still names it.
#[cfg(feature = "transport-link-raweth")]
fn raweth_member_text(at: core::net::SocketAddr) -> String {
    crate::raweth_link::member_locator(&at).unwrap_or_else(|| alloc::format!("reth/{at}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaceEventKind {
    /// The face reached Established.
    Up,
    /// The face left the live set.
    Down,
}

/// A face-lifecycle observer told the whole face, a snapshot of it and of its links
/// ([`FaceSnapshot`]), each time one comes up or goes: a count of the watcher, as a
/// [`FaceRowSink`] is, and copied out of a registry's lock before it is told, so a sink may reach
/// code that re-enters the registry.
pub type FaceEventSink = FaceWatcher<FaceSnapshot>;

/// A face-lifecycle observer told a row at a time ([`FaceLinkRow`]): each link of a face that
/// came up or went, its links in order, or the one row of a face with none, the face's facts in
/// each. The rows of one face are told one after another. A row holds everything in itself, so
/// an engine that writes its rows in place tells them with nothing allocated.
pub type FaceRowSink = FaceWatcher<FaceLinkRow>;

/// A count of a watcher of the faces told a `T` of each face that came up or went
/// ([`FaceEventSink`], [`FaceRowSink`]), copied out of a registry's lock before it is told. The
/// watcher lies where its maker put it and is counted by its maker's functions
/// ([`Self::counted`]), so one in a place its session lent takes nothing of the heap; one in an
/// `Arc` is counted by the `Arc`'s counts ([`Self::of_arc`]).
pub struct FaceWatcher<T> {
    raw: NonNull<c_void>,
    tell: unsafe fn(*const c_void, FaceEventKind, &T),
    retain: unsafe fn(*const c_void),
    release: unsafe fn(*mut c_void),
}

// SAFETY: made only by `FaceWatcher::counted`, whose caller vouches that the watcher and its
// counts are reached from any thread; the sink holds no `T`, only functions that are handed one.
unsafe impl<T> Send for FaceWatcher<T> {}
// SAFETY: as `Send`.
unsafe impl<T> Sync for FaceWatcher<T> {}

impl<T> Clone for FaceWatcher<T> {
    fn clone(&self) -> Self {
        // SAFETY: this count holds the watcher, so another may be taken from it (`counted`).
        unsafe { (self.retain)(self.raw.as_ptr().cast_const()) };
        Self {
            raw: self.raw,
            tell: self.tell,
            retain: self.retain,
            release: self.release,
        }
    }
}

impl<T> Drop for FaceWatcher<T> {
    fn drop(&mut self) {
        // SAFETY: this count was given to the sink (`counted`) and is let go of once, here.
        unsafe { (self.release)(self.raw.as_ptr()) };
    }
}

impl<T> FaceWatcher<T> {
    /// The watcher `sink` counts, in its `Arc`: each copy one more count of the `Arc`.
    pub fn of_arc<F>(sink: Arc<F>) -> Self
    where
        F: Fn(FaceEventKind, &T) + Send + Sync + 'static,
    {
        // SAFETY: `into_raw` gives up the `Arc`'s count, never null, to the sink; `F` is `Send +
        // Sync`, stands while a count of its `Arc` is held, and the three functions tell, take
        // and let go of a count of that `Arc<F>`.
        unsafe {
            Self::counted(
                NonNull::new_unchecked(Arc::into_raw(sink).cast_mut().cast::<c_void>()),
                tell_arc::<T, F>,
                retain_arc::<F>,
                release_arc::<F>,
            )
        }
    }

    /// The watcher at `raw`, of which this sink is one count: `tell` tells it what came or went,
    /// `retain` takes one more count of it, and `release` lets one go, the last letting the
    /// watcher go as its maker said.
    ///
    /// # Safety
    /// `raw` is a count of a watcher that may be reached from any thread, given up to the sink;
    /// the watcher stands while a count of it is held; each function may be called with `raw`
    /// from any thread while a count is held, `release` once for each count.
    pub unsafe fn counted(
        raw: NonNull<c_void>,
        tell: unsafe fn(*const c_void, FaceEventKind, &T),
        retain: unsafe fn(*const c_void),
        release: unsafe fn(*mut c_void),
    ) -> Self {
        Self {
            raw,
            tell,
            retain,
            release,
        }
    }

    /// Tell the watcher of a face that came up or went.
    pub fn tell(&self, kind: FaceEventKind, what: &T) {
        // SAFETY: this sink is a count of the watcher, which stands while it is held (`counted`).
        unsafe { (self.tell)(self.raw.as_ptr().cast_const(), kind, what) }
    }
}

/// Tell the watcher in the `Arc` at `raw` what came or went.
///
/// # Safety
/// `raw` is an `Arc<F>`'s pointer, of which the caller holds a count for the call.
unsafe fn tell_arc<T, F: Fn(FaceEventKind, &T)>(raw: *const c_void, kind: FaceEventKind, what: &T) {
    // SAFETY: the caller's count holds the value.
    (unsafe { &*raw.cast::<F>() })(kind, what);
}

/// Take one more count of the `Arc` at `raw`.
///
/// # Safety
/// As [`tell_arc`].
unsafe fn retain_arc<F>(raw: *const c_void) {
    // SAFETY: the caller's.
    unsafe { Arc::increment_strong_count(raw.cast::<F>()) };
}

/// Let go of one count of the `Arc` at `raw`.
///
/// # Safety
/// `raw` is a count of an `Arc<F>` the caller gives up, once.
unsafe fn release_arc<F>(raw: *mut c_void) {
    // SAFETY: the caller's.
    drop(unsafe { Arc::from_raw(raw.cast_const().cast::<F>()) });
}

/// The one link of a group member's transport, as the host that joined the group labels it:
/// this node's end on the group (`src`), the member's end and the kind of link the group is
/// (`dst`, `kind`), and the group under it, by its locator and by the endpoint the session
/// joined it by (see [`GroupLink`]).
#[cfg(feature = "session-multicast")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMemberLink<'a> {
    /// This node's end on the group.
    pub src: &'a str,
    /// The member's end.
    pub dst: String,
    /// The kind of link the group is, `None` for one no [`LinkKind`] names.
    pub kind: Option<LinkKind>,
    /// The group's locator.
    pub group: &'a str,
    /// The endpoint the session joined the group by.
    pub endpoint: &'a str,
}

#[cfg(feature = "session-multicast")]
impl<'a> GroupMemberLink<'a> {
    /// The link to `member` of the group joined by `endpoint`, of the kind the endpoint names: a
    /// raweth group's member's end is the `reth/` locator of its MAC, which the member table keys
    /// by an address of the MAC's own, on a link of no kind [`LinkKind`] names; any other group's
    /// is [`Self::udp`]. Every engine labels its members by it.
    pub fn of_group(
        src: &'a str,
        member: &crate::multicast_dispatch::MulticastMember,
        group: &'a str,
        endpoint: &'a str,
    ) -> Self {
        let mut dst = String::new();
        member_end(member.locator, Some(endpoint), &mut dst);
        Self {
            src,
            dst,
            kind: member_link_kind(endpoint),
            group,
            endpoint,
        }
    }

    /// The link to `member` of a UDP group: its end is the address its datagrams come from, as
    /// upstream records a member's locator, and the link a UDP one.
    pub fn udp(
        src: &'a str,
        member: &crate::multicast_dispatch::MulticastMember,
        group: &'a str,
        endpoint: &'a str,
    ) -> Self {
        let mut dst = String::new();
        member_end(member.locator, None, &mut dst);
        Self {
            src,
            dst,
            kind: Some(LinkKind::Udp),
            group,
            endpoint,
        }
    }
}

#[cfg(feature = "session-multicast")]
impl FaceSnapshot {
    /// One member of a group as the transport both upstreams report it as: its zid and role,
    /// shared memory as the calling ABI says (`is_shm`), and the one link `link` labels. `None`
    /// for a member whose JOIN named a role this node does not know, which a transport cannot
    /// report, as a face with no role is not reported.
    ///
    /// Not QoS: zenoh reports a member's QoS as its JOIN advertised it, and the member table
    /// does not keep that, so a member whose JOIN carries the QoS extension is reported without
    /// it. A group with QoS is off by default on both upstreams. The link's MTU is each ABI's to
    /// report by its own table, so it is 0 here.
    pub fn of_group_member(
        member: &crate::multicast_dispatch::MulticastMember,
        link: GroupMemberLink<'_>,
        is_shm: bool,
    ) -> Option<Self> {
        let whatami = member.whatami?.to_wire();
        let peer = member.peer.as_slice();
        let mut zid = [0u8; 16];
        for (into, byte) in zid.iter_mut().zip(peer) {
            *into = *byte;
        }
        let GroupMemberLink {
            src,
            dst,
            kind,
            group,
            endpoint,
        } = link;
        Some(Self {
            zid,
            whatami,
            is_qos: false,
            is_multicast: true,
            is_shm,
            links: alloc::vec![LinkSnapshot {
                src: String::from(src),
                dst,
                kind,
                interfaces: None,
                mtu: 0,
                group: Some(GroupLink {
                    locator: String::from(group),
                    endpoint: String::from(endpoint),
                }),
                cert_common_name: None,
                priorities: None,
                reliable: None,
            }],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link read from its row with the facts kept beside it carries every fact the row does not
    /// hold, and the row's own. Turned red by a fact of [`LinkFacts`] left out of
    /// `LinkSnapshot::of_row_with`, which reads as not known.
    #[test]
    fn a_link_read_from_its_row_keeps_the_facts_kept_beside_it() {
        let face = FaceSnapshot {
            zid: [9; 16],
            whatami: 1,
            is_qos: true,
            is_multicast: false,
            is_shm: false,
            links: alloc::vec![LinkSnapshot::unicast("tcp/a:1", "tcp/b:2", None, 1024)],
        };
        let row = FaceLinkRow::of_snapshot(&face, 0).expect("the face's one link");
        let facts = LinkFacts {
            interfaces: Some(alloc::vec![String::from("eth0")]),
            cert_common_name: Some(String::from("peer")),
            priorities: Some((1, 6)),
            reliable: Some(true),
        };
        let link = LinkSnapshot::of_row_with(&row, &facts).expect("a row of a link");
        assert_eq!(link.interfaces, facts.interfaces);
        assert_eq!(link.cert_common_name, facts.cert_common_name);
        assert_eq!(link.priorities, Some((1, 6)));
        assert_eq!(link.reliable, Some(true));
        assert_eq!(
            (link.src.as_str(), link.dst.as_str()),
            ("tcp/a:1", "tcp/b:2")
        );
        assert_eq!(link.mtu, 1024);
    }

    /// The two locators a row of a face's snapshot holds written whole.
    fn written(row: &FaceLinkRow) -> (&RowText, &RowText) {
        match &row.ends {
            RowEnds::Written { src, dst } => (src, dst),
            other => panic!("a snapshot's row holds its locators written: {other:?}"),
        }
    }

    /// A face of one TCP link from `src` to `dst`, and a group member's link.
    fn face_of(src: &str, dst: &str) -> FaceSnapshot {
        let mut tcp = LinkSnapshot::unicast(src, dst, None, 2048);
        tcp.kind = Some(LinkKind::Tcp);
        let mut member = LinkSnapshot::unicast("udp/a", "udp/b", None, 0);
        member.group = Some(GroupLink {
            locator: String::from("udp/224.0.0.224:7447"),
            endpoint: String::from("udp/224.0.0.224:7447#iface=lo"),
        });
        FaceSnapshot {
            zid: [7; 16],
            whatami: 1,
            is_qos: false,
            is_multicast: false,
            is_shm: false,
            links: alloc::vec![tcp, member],
        }
    }

    /// A row is the face's transport and one of its links, each link at its own index, and none
    /// past the last. Turned red by a row that reads another link than the one asked, or that
    /// drops the group's endpoint.
    #[test]
    fn a_row_holds_the_face_and_the_link_asked() {
        let face = face_of("tcp/127.0.0.1:1", "tcp/127.0.0.1:2");
        let first = FaceLinkRow::of_snapshot(&face, 0).expect("the first link");
        assert_eq!(
            (first.zid, first.whatami, first.link, first.links),
            ([7; 16], 1, 0, 2)
        );
        assert_eq!(first.src_text(), "tcp/127.0.0.1:1");
        assert_eq!(first.dst_text(), "tcp/127.0.0.1:2");
        assert_eq!((first.kind, first.mtu), (Some(LinkKind::Tcp), 2048));
        assert!(first.group_endpoint.is_none());
        let (src, dst) = written(&first);
        assert!(src.is_inline() && dst.is_inline());
        let second = FaceLinkRow::of_snapshot(&face, 1).expect("the second link");
        assert_eq!(second.link, 1);
        assert_eq!(
            second.group_endpoint.as_deref(),
            Some("udp/224.0.0.224:7447#iface=lo")
        );
        assert!(
            FaceLinkRow::of_snapshot(&face, 2).is_none(),
            "past the last link"
        );
    }

    /// A face is told as each of its links in order, the last named so, and a face with no link as
    /// one row of the face alone, which is its last. Turned red by a face with no link told by no
    /// row, which would hide its transport, or by a row that miscounts its face's links, which
    /// would tell a departure's transport early or never.
    #[test]
    fn a_face_is_its_links_rows_in_order_or_one_row_of_the_face_alone() {
        let face = face_of("tcp/127.0.0.1:1", "tcp/127.0.0.1:2");
        let mut rows = Vec::new();
        FaceLinkRow::each_of_snapshot(&face, |row| rows.push(row));
        let read: Vec<_> = rows
            .iter()
            .map(|row| (row.link, row.links, row.is_last_of_face()))
            .collect();
        assert_eq!(read, [(0, 2, false), (1, 2, true)]);
        assert_eq!(rows[1].src_text(), "udp/a", "the second link's row");

        let alone = FaceSnapshot {
            links: Vec::new(),
            ..face
        };
        let mut rows = Vec::new();
        FaceLinkRow::each_of_snapshot(&alone, |row| rows.push(row));
        assert_eq!(rows.len(), 1, "one row for a face with no link");
        let row = &rows[0];
        assert_eq!((row.zid, row.link, row.links), ([7; 16], 0, 0));
        assert!(row.is_last_of_face());
        assert_eq!(row.ends, RowEnds::None);
        assert_eq!(
            (row.src_text(), row.dst_text()),
            (String::new(), String::new())
        );
        assert_eq!((row.kind, row.mtu), (None, 0));
        assert!(
            LinkSnapshot::of_row(row).is_none(),
            "a face alone has no link"
        );
    }

    /// A snapshot made again from a face's rows holds the face and every link the rows hold, a
    /// group's locator read off the endpoint it was joined by, and what no row holds as not known.
    /// Turned red by a link dropped or reordered between the rows and the snapshot, or by a
    /// group's locator that keeps the endpoint's config.
    #[test]
    fn a_snapshot_made_from_its_rows_holds_what_the_rows_hold() {
        let face = face_of("tcp/127.0.0.1:1", "tcp/127.0.0.1:2");
        let mut rows = Vec::new();
        FaceLinkRow::each_of_snapshot(&face, |row| rows.push(row));
        let mut again = FaceSnapshot::of_face_row(&rows[0]);
        again
            .links
            .extend(rows.iter().filter_map(LinkSnapshot::of_row));
        assert_eq!(
            (
                again.zid,
                again.whatami,
                again.is_multicast,
                again.links.len()
            ),
            (face.zid, face.whatami, face.is_multicast, 2)
        );
        for (made, held) in again.links.iter().zip(&face.links) {
            assert_eq!((&made.src, &made.dst), (&held.src, &held.dst));
            assert_eq!((made.kind, made.mtu), (held.kind, held.mtu));
            assert_eq!(made.group, held.group);
            assert_eq!(made.interfaces, None, "the NICs are not in a row");
        }
    }

    /// A locator of the bound and the longest group endpoint within its own bound read whole from
    /// rows that hold them in place; a locator past the bound still reads whole, from the heap,
    /// which only a heap engine's link reaches. Turned red by a row that cuts a text short or
    /// blanks it, which would name another peer, or by one that spills a text that fits.
    /// In a build with the raweth transport a group's row holds a raw Ethernet group's endpoint
    /// of that bound whole and in place, as it holds a UDP group's. Turned red by a row sized
    /// from the UDP bound alone.
    #[test]
    #[cfg(feature = "transport-link-raweth")]
    fn a_group_row_holds_a_raweth_endpoint_of_its_bound() {
        let endpoint = "e".repeat(crate::caps::MAX_RAWETH_ENDPOINT_LEN);
        let row = GroupRowText::of(&endpoint);
        assert_eq!(row.as_str(), endpoint);
        assert!(row.is_inline());
    }

    #[test]
    fn every_text_reads_whole_from_a_row_and_one_that_fits_is_held_in_place() {
        let fits = "t".repeat(crate::caps::MAX_LOCATOR_LEN);
        let mut face = face_of(&fits, "tcp/127.0.0.1:2");
        let endpoint = "e".repeat(crate::caps::MAX_GROUP_ENDPOINT_LEN);
        if let Some(group) = face.links[1].group.as_mut() {
            group.endpoint = endpoint.clone();
        }
        let row = FaceLinkRow::of_snapshot(&face, 0).expect("the link");
        assert_eq!(row.src_text(), fits);
        assert!(
            written(&row).0.is_inline(),
            "a locator of the bound is held in the row"
        );
        let member = FaceLinkRow::of_snapshot(&face, 1).expect("the member's link");
        let held = member.group_endpoint.expect("the group's endpoint");
        assert_eq!(held.as_str(), endpoint);
        assert!(
            held.is_inline(),
            "an endpoint of its bound is held in the row"
        );

        let long = "t".repeat(crate::caps::MAX_LOCATOR_LEN + 1);
        let row = FaceLinkRow::of_snapshot(&face_of(&long, "d"), 0).expect("the link");
        assert_eq!(row.src_text(), long, "a longer locator reads whole");
        assert!(!written(&row).0.is_inline());
    }

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

    /// A member of a UDP group is a multicast transport of its own, of its zid and role, with one
    /// UDP link to the address its datagrams come from, over the group; a member whose role this
    /// node does not know is no transport it can report.
    /// A group member's row read in place is the row of its snapshot: it holds the address the
    /// member's datagrams come from, not its locator, and reads as the snapshot's text; the group's
    /// locator and the longest endpoint of its bound are held in the row. Turned red by a row that
    /// reports another end, kind or label than the snapshot, or that spills a text that fits.
    #[cfg(feature = "session-multicast")]
    #[test]
    fn a_group_members_row_is_the_row_of_its_snapshot_held_in_place() {
        use crate::multicast_dispatch::MulticastMember;
        use crate::multicast_peer_lost::MulticastPeerId;
        let member = MulticastMember {
            peer: MulticastPeerId::from_wire(&[0x0a, 0x0b]),
            whatami: Some(crate::WhatAmI::Peer),
            locator: core::net::SocketAddr::from(([192, 0, 2, 9], 7447)),
        };
        let group = "udp/239.1.2.3:7447";
        let endpoint = "e".repeat(crate::caps::MAX_GROUP_ENDPOINT_LEN);
        let face = FaceSnapshot::of_group_member(
            &member,
            GroupMemberLink::udp(group, &member, group, &endpoint),
            true,
        )
        .expect("a member of a known role");
        let snapshot = FaceLinkRow::of_snapshot(&face, 0).expect("its link");
        let row = FaceLinkRow::of_group_member(&member, group, &endpoint, true).expect("its row");
        assert_eq!(
            (row.zid, row.whatami, row.is_multicast, row.is_shm, row.link),
            (
                snapshot.zid,
                snapshot.whatami,
                snapshot.is_multicast,
                snapshot.is_shm,
                0
            )
        );
        assert_eq!((row.kind, row.mtu), (snapshot.kind, snapshot.mtu));
        assert_eq!(row.src_text(), snapshot.src_text());
        assert_eq!(row.dst_text(), "udp/192.0.2.9:7447");
        assert_eq!(row.dst_text(), snapshot.dst_text());
        let RowEnds::Member { src, at } = &row.ends else {
            panic!(
                "a member's row holds its ends as a member's: {:?}",
                row.ends
            );
        };
        assert_eq!(*at, member.locator, "the member's address, not its text");
        let held = row.group_endpoint.as_ref().expect("the group's endpoint");
        assert_eq!(held.as_str(), endpoint);
        assert!(src.is_inline() && held.is_inline());
        let unknown = MulticastMember {
            whatami: None,
            ..member
        };
        assert!(FaceLinkRow::of_group_member(&unknown, group, &endpoint, true).is_none());
    }

    /// A raweth group's member reads as the `reth/` locator of its MAC on a link of no kind, in its
    /// snapshot and in its row alike, and an address no raweth member is keyed by as `reth/` and the
    /// address. Turned red by a raweth member labelled as a UDP one.
    ///
    /// # Control
    ///
    /// The same member over a UDP group reads as its address on a UDP link.
    #[cfg(all(feature = "session-multicast", feature = "transport-link-raweth"))]
    #[test]
    fn a_raweth_group_member_is_its_mac() {
        use crate::multicast_dispatch::MulticastMember;
        use crate::multicast_peer_lost::MulticastPeerId;
        let member = MulticastMember {
            peer: MulticastPeerId::from_wire(&[0x0a, 0x0b]),
            whatami: Some(crate::WhatAmI::Peer),
            locator: crate::raweth_link::member_address([0x30, 0x03, 0x8c, 0xc8, 0, 0xa1]),
        };
        let group = "reth/30:03:8c:c8:00:a2";
        let endpoint = "reth/30:03:8c:c8:00:a2#iface=lo";
        let link = GroupMemberLink::of_group(group, &member, group, endpoint);
        assert_eq!(
            (link.dst.as_str(), link.kind),
            ("reth/30:03:8c:c8:00:a1", None)
        );
        let row = FaceLinkRow::of_group_member(&member, group, endpoint, false).expect("its row");
        assert_eq!(
            (row.dst_text().as_str(), row.kind),
            ("reth/30:03:8c:c8:00:a1", None)
        );

        let stranger = MulticastMember {
            locator: core::net::SocketAddr::from(([192, 0, 2, 9], 7447)),
            ..member
        };
        assert_eq!(
            GroupMemberLink::of_group(group, &stranger, group, endpoint).dst,
            "reth/192.0.2.9:7447"
        );

        let udp = "udp/224.0.0.224:7447#iface=lo";
        let link = GroupMemberLink::of_group(group, &stranger, group, udp);
        assert_eq!(
            (link.dst.as_str(), link.kind),
            ("udp/192.0.2.9:7447", Some(LinkKind::Udp))
        );
    }

    /// A group member's end is `udp/` and the address as `Display` writes it, whole, the widest
    /// address too. Turned red by a text that differs from the formatter's or is cut short.
    #[test]
    fn a_member_end_is_written_whole() {
        let widest = core::net::SocketAddr::V6(core::net::SocketAddrV6::new(
            core::net::Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
            65535,
            0,
            u32::MAX,
        ));
        for at in [core::net::SocketAddr::from(([10, 0, 0, 1], 7447)), widest] {
            let mut text = String::new();
            member_end(at, None, &mut text);
            assert_eq!(text, alloc::format!("udp/{at}"));
            let mut joined = String::new();
            member_end(at, Some("udp/224.0.0.224:7447#iface=lo"), &mut joined);
            assert_eq!(joined, text, "a UDP group's member is its address on UDP");
        }
    }

    /// A row holds the ends its link's driver lent as facts, an IP end's address and another
    /// family's name, and reads as the locators the driver's ends write, a name past the row's
    /// bound whole too. Turned red by a row that writes another scheme, suffix or address than the
    /// driver's ends, or that keeps the text of an end rather than its address.
    #[test]
    fn a_row_holds_the_ends_its_driver_lent_and_reads_as_their_locators() {
        let local = core::net::SocketAddr::from(([10, 0, 0, 2], 40000));
        let peer = core::net::SocketAddr::from(([10, 0, 0, 1], 7447));
        let long = "p".repeat(crate::caps::MAX_LOCATOR_LEN + 1);
        let lent = [
            LinkEnds::ip(LinkKind::Tcp, local, peer),
            LinkEnds::ip(LinkKind::UdpReliable, local, peer),
            LinkEnds::named(LinkKind::Unixpipe, "/tmp/a", &long),
        ];
        for ends in lent {
            let row = FaceLinkRow {
                ends: RowEnds::lent(Some(ends)),
                ..FaceLinkRow::of_face_alone(&face_of("a", "b"))
            };
            let (mut src, mut dst) = (String::new(), String::new());
            ends.write_src(&mut src);
            ends.write_dst(&mut dst);
            assert_eq!((row.src_text(), row.dst_text()), (src, dst), "{ends:?}");
            let RowEnds::Lent {
                kind,
                src: held_src,
                dst: held_dst,
            } = &row.ends
            else {
                panic!("a lent link's row holds its ends as lent: {:?}", row.ends);
            };
            assert_eq!(
                (*kind, held_src.lent(), held_dst.lent()),
                (ends.kind, ends.src, ends.dst)
            );
        }
        assert_eq!(
            RowEnds::lent(None),
            RowEnds::None,
            "a driver that lends no ends"
        );
    }

    #[cfg(feature = "session-multicast")]
    #[test]
    fn a_group_member_is_a_multicast_transport_with_one_link_over_the_group() {
        use crate::multicast_dispatch::MulticastMember;
        use crate::multicast_peer_lost::MulticastPeerId;
        let member = MulticastMember {
            peer: MulticastPeerId::from_wire(&[0x0a, 0x0b]),
            whatami: Some(crate::WhatAmI::Peer),
            locator: core::net::SocketAddr::from(([192, 0, 2, 9], 7447)),
        };
        let group = "udp/239.1.2.3:7447";
        let endpoint = "udp/239.1.2.3:7447#iface=lan7";
        let face = FaceSnapshot::of_group_member(
            &member,
            GroupMemberLink::udp(group, &member, group, endpoint),
            false,
        )
        .expect("a member of a role this node knows");
        assert_eq!(&face.zid[..2], &[0x0a, 0x0b]);
        assert!(face.zid[2..].iter().all(|byte| *byte == 0));
        assert_eq!(face.whatami, crate::WhatAmI::Peer.to_wire());
        assert!(face.is_multicast && !face.is_qos && !face.is_shm);
        assert_eq!(face.links.len(), 1);
        let link = &face.links[0];
        assert_eq!(link.src, group);
        assert_eq!(link.dst, "udp/192.0.2.9:7447");
        assert_eq!(link.kind, Some(LinkKind::Udp));
        assert_eq!(
            link.group,
            Some(GroupLink {
                locator: String::from(group),
                endpoint: String::from(endpoint),
            })
        );
        let unknown = MulticastMember {
            whatami: None,
            ..member
        };
        assert!(FaceSnapshot::of_group_member(
            &unknown,
            GroupMemberLink::udp(group, &unknown, group, endpoint),
            false
        )
        .is_none());
    }
}

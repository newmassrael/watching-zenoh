// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2844 — the stats registry of a node, across every transport it holds and
//! has held.
//!
//! Upstream keeps ONE registry per runtime, and its transport manager is what
//! fills it: a unicast transport is registered when it is established
//! (`io/zenoh-transport/src/unicast/manager.rs` @ `let stats = self.stats.unicast_transport_stats(`)
//! and its handle is dropped when it closes, which marks it disconnected until
//! the registry's garbage collection retires it into the node's totals. The
//! admin space's metrics leg then writes that one registry.
//!
//! A wz node's transport manager is whatever drives its sessions: the face
//! loop (`accept_loop::face_drive_loop`) for a peer or a router, where every
//! face enters the held set at one site and leaves it at one of two; and the
//! storage host's own accept loop, which holds one client session at a time.
//! Each reports a transport opening and closing here, keyed by an id of its
//! own choosing, so no admin host re-learns a session lifecycle to report it.
//!
//! Each session records into its OWN partition without a node-wide lock
//! (R2825); this registry copies a live transport's partition when a GET is
//! answered and takes a final copy when the transport closes. The final copy
//! is taken after the session's links are closed, which is what folds their
//! counts into the transport, as dropping a link does upstream.
//!
//! Time is this handle's own: a monotonic origin taken at construction. The
//! recording side and the admin host each hold a clone, so neither has to
//! share a clock with the other for the collection delay to mean what it says.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use wz_session_core::stats_registry::{StatsRegistry, StatsTransportId};
use wz_session_core::WhatAmI;

use crate::session_glue::SessionLinkActions;

/// A cheap, cloneable handle on one node's stats registry. The code that
/// drives the node's sessions records into it; the admin host reads a
/// snapshot of it per GET.
#[derive(Clone)]
pub struct NodeStats {
    inner: Arc<Mutex<Inner>>,
}

/// The registry and the keys of the open transports — what a reader of a
/// debug print wants. The session actions behind each key have no `Debug`,
/// and their counts are already in the registry.
impl std::fmt::Debug for NodeStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.with(|inner| {
            f.debug_struct("NodeStats")
                .field("registry", &inner.registry)
                .field("open", &inner.open.keys().collect::<Vec<_>>())
                .finish()
        })
    }
}

struct Inner {
    registry: StatsRegistry,
    origin: Instant,
    /// The open transports, by the recorder's own key. The session's actions
    /// are kept because its counters live in its own partition: they are read
    /// at every snapshot and once more when the transport closes.
    open: BTreeMap<u64, (StatsTransportId, Arc<SessionLinkActions>)>,
    /// R2849 — the open MULTICAST transports, by the recorder's own key: one
    /// per group face, each with the peers the registry holds for it.
    #[cfg(all(feature = "transport-multicast", feature = "transport-stats"))]
    groups: BTreeMap<u64, OpenGroup>,
}

/// R2849 — one group face as the registry holds it: the group's transport,
/// the handle its drive loop records into, and a registry transport per peer
/// the registry has seen on it, by zid.
#[cfg(all(feature = "transport-multicast", feature = "transport-stats"))]
struct OpenGroup {
    transport: StatsTransportId,
    stats: crate::multicast_glue::MulticastTransportStats,
    peers: BTreeMap<Vec<u8>, StatsTransportId>,
}

impl Inner {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// R2849 — bring the registry's copy of every group face up to its
    /// handle: the group's partition, each peer on it (registered the first
    /// time the registry sees it), and each peer that left since the last sync
    /// — its final partition copied in and its transport closed, which marks
    /// it disconnected until collection retires it, as upstream's registry
    /// does when a departed peer's stats handle is dropped.
    ///
    /// Departures are applied BEFORE the live peers: a peer that left and came
    /// back between two syncs has an old partition in the departures and a new
    /// one on the group, and they are two registry transports, as they are two
    /// peer records upstream.
    #[cfg(all(feature = "transport-multicast", feature = "transport-stats"))]
    fn sync_groups(&mut self, now_ms: u64) {
        let registry = &mut self.registry;
        for group in self.groups.values_mut() {
            let metrics = group.stats.metrics();
            registry.set_transport_metrics(group.transport, metrics.transport().clone());
            for (zid, left) in group.stats.take_departed() {
                let id = match group.peers.remove(&zid) {
                    Some(id) => id,
                    // Joined and left between two syncs: registered only to be
                    // reported as the disconnected transport it now is.
                    None => registry.open_multicast_peer(
                        &wz_session_core::zid_hex::zid_to_zenoh_hex(&zid),
                        left.whatami,
                        metrics.group(),
                    ),
                };
                registry.set_transport_metrics(id, left.metrics().clone());
                registry.close_transport(id, now_ms);
            }
            for (zid, peer) in metrics.peers() {
                let id = *group.peers.entry(zid.to_vec()).or_insert_with(|| {
                    registry.open_multicast_peer(
                        &wz_session_core::zid_hex::zid_to_zenoh_hex(zid),
                        peer.whatami,
                        metrics.group(),
                    )
                });
                registry.set_transport_metrics(id, peer.metrics().clone());
            }
        }
    }
}

impl NodeStats {
    /// An empty registry for the node `zid_hex` in role `whatami`, reporting
    /// `build_version` in its build-info block.
    pub fn new(zid_hex: &str, whatami: WhatAmI, build_version: &str) -> Self {
        NodeStats {
            inner: Arc::new(Mutex::new(Inner {
                registry: StatsRegistry::new(zid_hex, whatami, build_version),
                origin: Instant::now(),
                open: BTreeMap::new(),
                #[cfg(all(feature = "transport-multicast", feature = "transport-stats"))]
                groups: BTreeMap::new(),
            })),
        }
    }

    /// The registry a node of this BUILD keeps: `Some` when it is built with
    /// `transport-stats`, `None` otherwise.
    ///
    /// The choice lives here, in the crate that owns the feature, rather than
    /// in each host: a host that holds `None` serves the build-info block
    /// alone, which is upstream's metrics body without its own `stats`
    /// feature, and one that holds `Some` serves the registry's document,
    /// which is its body with it (`zenoh/src/net/runtime/adminspace.rs` @ `.encode_metrics(`).
    /// A registry without counters would be neither.
    pub fn for_node(zid_hex: &str, whatami: WhatAmI, build_version: &str) -> Option<Self> {
        if cfg!(feature = "transport-stats") {
            Some(Self::new(zid_hex, whatami, build_version))
        } else {
            None
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        // A poisoned lock means a panic mid-record; the counts are still the
        // best this node has, so they are served rather than lost.
        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut guard)
    }

    /// The session behind `actions` was established as this node's transport
    /// `key`: register it. A session whose handshake named no peer has no
    /// transport to register, and is not tracked.
    pub fn transport_opened(&self, key: u64, actions: &Arc<SessionLinkActions>) {
        self.with(|inner| {
            if let Some(transport) = actions.open_stats_transport(&mut inner.registry) {
                inner.open.insert(key, (transport, Arc::clone(actions)));
            }
        });
    }

    /// Transport `key` closed: close its links, take its final counts, and
    /// mark it disconnected. A later [`Self::snapshot`] retires it once the
    /// collection delay has passed.
    pub fn transport_closed(&self, key: u64) {
        let now_ms = self.with(|inner| inner.now_ms());
        self.transport_closed_at(key, now_ms);
    }

    /// [`Self::transport_closed`] at `now_ms` on this handle's clock.
    fn transport_closed_at(&self, key: u64, now_ms: u64) {
        self.with(|inner| {
            if let Some((transport, actions)) = inner.open.remove(&key) {
                #[cfg(feature = "transport-stats")]
                {
                    actions.close_stats_links();
                    inner
                        .registry
                        .set_transport_metrics(transport, actions.stats_metrics());
                }
                #[cfg(not(feature = "transport-stats"))]
                let _ = actions;
                inner.registry.close_transport(transport, now_ms);
            }
        });
    }

    /// The registry as of now, for one metrics answer: every open transport's
    /// counts copied in. The transports disconnected for longer than the
    /// collection delay are retired AFTER the copy is taken, because upstream
    /// garbage-collects at the END of a collection
    /// (`commons/zenoh-stats/src/family.rs` @ `if garbage_collection {`) — the
    /// answer that crosses the delay still reports the transport once more, and
    /// the next does not.
    pub fn snapshot(&self) -> StatsRegistry {
        let now_ms = self.with(|inner| inner.now_ms());
        self.snapshot_at(now_ms)
    }

    /// [`Self::snapshot`] at `now_ms` on this handle's clock.
    fn snapshot_at(&self, now_ms: u64) -> StatsRegistry {
        self.with(|inner| {
            #[cfg(feature = "transport-stats")]
            for (transport, actions) in inner.open.values() {
                inner
                    .registry
                    .set_transport_metrics(*transport, actions.stats_metrics());
            }
            #[cfg(all(feature = "transport-multicast", feature = "transport-stats"))]
            inner.sync_groups(now_ms);
            let answer = inner.registry.clone();
            inner.registry.collect_garbage(now_ms);
            answer
        })
    }

    /// R2849 — the group face `key`, recording into `stats`, has joined its
    /// group: register it as one multicast transport. Its peers are
    /// registered as the registry sees them, at each snapshot.
    ///
    /// Upstream registers a multicast transport when its manager opens one on
    /// a group locator
    /// (`io/zenoh-transport/src/multicast/transport.rs` @ `.multicast_transport_stats(config.link.link.get_dst().to_string());`),
    /// which is the moment a face's drive loop starts here. A key already open
    /// is left as it is.
    #[cfg(all(feature = "transport-multicast", feature = "transport-stats"))]
    pub fn multicast_opened(
        &self,
        key: u64,
        stats: &crate::multicast_glue::MulticastTransportStats,
    ) {
        self.with(|inner| {
            if inner.groups.contains_key(&key) {
                return;
            }
            let group = stats.metrics().group().to_string();
            let transport = inner.registry.open_multicast_transport(&group);
            inner.groups.insert(
                key,
                OpenGroup {
                    transport,
                    stats: stats.clone(),
                    peers: BTreeMap::new(),
                },
            );
        });
    }

    /// R2849 — group face `key` stopped: take its final counts, then close its
    /// peers and the group's transport, all marked disconnected until the
    /// collection delay retires them. A stopped face's peers go with it, as a
    /// deleted multicast transport drops every peer record it held.
    #[cfg(all(feature = "transport-multicast", feature = "transport-stats"))]
    pub fn multicast_closed(&self, key: u64) {
        let now_ms = self.with(|inner| inner.now_ms());
        self.multicast_closed_at(key, now_ms);
    }

    /// [`Self::multicast_closed`] at `now_ms` on this handle's clock.
    #[cfg(all(feature = "transport-multicast", feature = "transport-stats"))]
    fn multicast_closed_at(&self, key: u64, now_ms: u64) {
        self.with(|inner| {
            inner.sync_groups(now_ms);
            let Some(group) = inner.groups.remove(&key) else {
                return;
            };
            let mut last = group.stats.metrics();
            last.close_links();
            inner
                .registry
                .set_transport_metrics(group.transport, last.transport().clone());
            for (zid, peer) in last.peers() {
                if let Some(id) = group.peers.get(zid) {
                    inner
                        .registry
                        .set_transport_metrics(*id, peer.metrics().clone());
                }
            }
            for id in group.peers.values() {
                inner.registry.close_transport(*id, now_ms);
            }
            inner.registry.close_transport(group.transport, now_ms);
        });
    }
}

#[cfg(all(test, feature = "transport-stats"))]
mod tests {
    use super::*;
    use crate::test_fixtures::recording_actions;
    use wz_session_core::stats_registry::{MetricsQuery, GARBAGE_COLLECTION_DELAY_MS};

    /// A session the handshake has named: the peer zid and role stamped the
    /// way the INIT exchange fills them.
    fn named_session(zid: u8) -> Arc<SessionLinkActions> {
        let (actions, _driver) = recording_actions();
        *actions
            .remote_peer_zid
            .lock()
            .expect("remote_peer_zid poisoned in test fixture") = Some(vec![zid; 4]);
        *actions
            .peer_whatami
            .lock()
            .expect("peer_whatami poisoned in test fixture") = Some(WhatAmI::Peer.to_wire());
        actions
    }

    fn document(registry: &StatsRegistry, query: MetricsQuery) -> String {
        let mut doc = String::new();
        registry.encode_metrics(&mut doc, query);
        doc
    }

    const HEAD: &str = r#"local_id="a1b2",local_whatami="router""#;

    fn opened(doc: &str) -> String {
        let prefix = format!("zenoh_transports_opened{{{HEAD}}} ");
        doc.lines()
            .find_map(|line| line.strip_prefix(prefix.as_str()))
            .unwrap_or_else(|| panic!("no transports gauge:\n{doc}"))
            .to_string()
    }

    /// R2844 — a node's registry follows its transports through their whole
    /// life, as upstream's does: counted while open, still listed (marked
    /// disconnected) after they close, and retired only once the collection
    /// delay has passed — reported one last time by the answer that crosses
    /// it, and not by the next.
    #[test]
    fn a_transport_is_counted_open_listed_closed_and_retired_after_the_delay() {
        let stats = NodeStats::new("a1b2", WhatAmI::Router, "v1");
        stats.transport_opened(7, &named_session(0x11));
        stats.transport_opened(8, &named_session(0x22));
        let open = document(&stats.snapshot_at(0), MetricsQuery::default());
        assert_eq!(opened(&open), "2", "two transports open:\n{open}");

        stats.transport_closed_at(7, 1_000);
        let closed = stats.snapshot_at(1_000);
        assert_eq!(opened(&document(&closed, MetricsQuery::default())), "1");
        assert_eq!(
            closed.clone(),
            stats.snapshot_at(1_000 + GARBAGE_COLLECTION_DELAY_MS),
            "inside the delay the closed transport is still held"
        );

        // The answer that crosses the delay still carries it; the next does not.
        let crossing = stats.snapshot_at(1_001 + GARBAGE_COLLECTION_DELAY_MS);
        let after = stats.snapshot_at(1_002 + GARBAGE_COLLECTION_DELAY_MS);
        assert_eq!(crossing, closed, "the crossing answer still holds it");
        assert_ne!(
            crossing, after,
            "the collection after the delay retires the closed transport"
        );
        assert_eq!(opened(&document(&after, MetricsQuery::default())), "1");

        // A closed key that was never opened, and a second close, change nothing.
        stats.transport_closed_at(7, 99_999_999);
        stats.transport_closed_at(3, 99_999_999);
        assert_eq!(
            opened(&document(
                &stats.snapshot_at(99_999_999),
                MetricsQuery::default()
            )),
            "1"
        );
    }

    /// R2849 — a group face through its whole life in the node registry: the
    /// group is ONE opened transport and its peers are partitions that do not
    /// count as opened; a peer that leaves is listed disconnected; stopping the
    /// face closes the group, its link and the peers still on it.
    ///
    /// The gauge's walk below is upstream's: a peer's partition is built
    /// without an increment, but dropping it decrements like any transport
    /// (`commons/zenoh-stats/src/transport.rs` @ `self.registry.remove_transport(&self.transport)`),
    /// so a group whose one peer left, then stopped, reads -1. The registry
    /// keeps that asymmetry on purpose; this pins that the face drives it.
    #[cfg(feature = "transport-multicast")]
    #[test]
    fn a_group_face_is_one_transport_whose_peers_come_and_go() {
        use crate::multicast_glue::{MulticastStatsRecorder, MulticastTransportStats};
        use wz_session_core::multicast_peer_arrived::MulticastPeerArrived;
        use wz_session_core::multicast_peer_lost::{
            MulticastPeerId, MulticastPeerLost, MulticastPeerLostReason,
        };

        let stats = NodeStats::new("a1b2", WhatAmI::Router, "v1");
        let face = MulticastTransportStats::new("udp/10.0.0.1:7446", "udp/224.0.0.224:7446");
        stats.multicast_opened(5, &face);
        face.datagram_received(30);
        let peer = MulticastPeerId::from_wire(&[0xaa]);
        face.peer_arrived(&MulticastPeerArrived {
            peer,
            whatami: Some(WhatAmI::Peer),
        });

        let all = MetricsQuery {
            disconnected: true,
            ..MetricsQuery::default()
        };
        let links = |doc: &str| {
            doc.lines()
                .find_map(|l| {
                    l.strip_prefix(&format!("zenoh_links_opened{{{HEAD},protocol=\"udp\"}} "))
                })
                .map(str::to_string)
                .unwrap_or_else(|| panic!("no udp links gauge:\n{doc}"))
        };
        let peer_bytes = |doc: &str, disconnected: &str| {
            doc.lines().any(|l| {
                l.starts_with("zenoh_rx_per_transport_bytes_total{")
                    && l.contains("remote_zid=\"aa\"")
                    && l.contains(&format!("disconnected=\"{disconnected}\""))
            })
        };

        let open = document(&stats.snapshot_at(0), all);
        assert_eq!(opened(&open), "1", "the group, not its peer:\n{open}");
        assert_eq!(links(&open), "1", "the group's one link:\n{open}");
        assert!(peer_bytes(&open, "false"), "the peer is listed:\n{open}");
        assert!(
            open.contains(
                "remote_group=\"udp/224.0.0.224:7446\",remote_cn=\"\",disconnected=\"false\"} 30"
            ),
            "the group's received bytes:\n{open}"
        );

        face.peer_lost(&MulticastPeerLost {
            peer,
            reason: MulticastPeerLostReason::Closed,
        });
        let left = document(&stats.snapshot_at(10), all);
        assert!(
            peer_bytes(&left, "true"),
            "the peer that left is disconnected:\n{left}"
        );
        assert!(!peer_bytes(&left, "false"), "and listed once:\n{left}");
        assert_eq!(opened(&left), "0", "{left}");

        stats.multicast_closed_at(5, 20);
        let closed = document(&stats.snapshot_at(20), all);
        assert_eq!(opened(&closed), "-1", "{closed}");
        assert_eq!(
            links(&closed),
            "0",
            "the group's link closed with it:\n{closed}"
        );
        assert!(
            closed.contains(
                "remote_group=\"udp/224.0.0.224:7446\",remote_cn=\"\",disconnected=\"true\"} 30"
            ),
            "the group is kept, disconnected, with its counts:\n{closed}"
        );
    }

    /// A session whose handshake has not named its peer has no transport to
    /// register: the gauge stays at zero rather than counting an unlabelled
    /// transport.
    #[test]
    fn an_unnamed_session_registers_no_transport() {
        let stats = NodeStats::new("a1b2", WhatAmI::Router, "v1");
        let (anonymous, _driver) = recording_actions();
        stats.transport_opened(1, &anonymous);
        let doc = document(&stats.snapshot_at(0), MetricsQuery::default());
        assert_eq!(opened(&doc), "0", "{doc}");
    }
}

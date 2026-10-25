// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2721 (`session-close-ingress` residual (c)) — the AP binding for the
//! lifecycle grammar's `open` verb.
//!
//! R2720 put `SessionOpener` in `wz-session-core` as a node-scoped port and left
//! it unbound: `close` acts on the session the injector already holds, while
//! `open`'s subject is a session that does not exist, so the two cannot share a
//! collaborator. This is the collaborator, for the one profile that has the
//! parts.
//!
//! ⛔ NOTHING NEW IS INVENTED HERE, and that is worth stating because the round
//! that wrote it began by looking for what was missing and found nothing. Every
//! piece already existed and none of them had been joined:
//!
//!   * `wz_session_core::zid_hex::zenoh_hex_to_zid` — the grammar's `<peer-zid>`
//!     chunk is a zid rendered the way zenoh renders one INTO A KEY EXPRESSION,
//!     and this module's SSOT parses it back. (`Zid`'s own `Display` renders
//!     the same form since R2956; a per-byte wire-order spelling would look up
//!     a zid nobody advertised.)
//!   * `LinkstateNetwork::node_locators` — the retained zid -> dial-locator
//!     directory, populated by the link-state flood this node already ingests.
//!   * `session_open::plan_endpoint` — the locator-string parse.
//!   * `ConnectReconcile::Add` — the desired-connect-set merge that ends in a
//!     dial, and the same one `connect-add` drives. This verb sends its
//!     `AddNode` form, which dials each locator for the node's zid (decision
//!     D4 of `docs/session-lifecycle-intent.md`).
//!
//! WHICH IS WHY `connect-add` STAYS. It addresses by LOCATOR and this verb
//! addresses by ZID; they are two ways onto one mechanism, not two mechanisms,
//! and the owner's interface decision keeps the first as the AP alias for
//! exactly that reason.
//!
//! ⚠ AP-ONLY BY THE OTHER PROFILE'S SHAPE, not by neglect. No MCU crate depends
//! on `wz-routing-graph`, so no MCU profile has the directory; and
//! `wz-session-lwip`'s `run_session` drives exactly one session whose
//! Acceptor/Initiator role is fixed before the loop starts, so it has no session
//! manager to bind. An MCU host passes `None` for the opener and its `open` rows
//! are refused out loud — which is why the port is an `Option` and why the
//! refusal logs.

use std::sync::Arc;

use wz_routing_graph::{LinkstateNetwork, Zid};
use wz_session_core::credential_identity::zid_from_wire;
use wz_session_core::drive::{LifecycleKey, SessionOpener};
use wz_session_core::lifecycle_query::{OpenOutcome, PeerOpener};
use wz_session_core::zid_hex::zenoh_hex_to_zid;

use crate::accept_loop::{ConnectReconcile, ReconcileSender};
use crate::session_open::plan_endpoint;
use crate::sync::PlainRwLock;

/// The link-state graphs a node learns where its peers can be reached from: one
/// for a peer, and one per region for a router. Read-only: all it answers is the
/// locators a node advertised.
///
/// Holds each graph by `Arc<PlainRwLock<..>>` because that is how the router
/// already holds it (shared between the threads that drive its faces), so this
/// shares the graphs the floods populate rather than a copy that could disagree
/// with them. A forwarder mints one for its own graphs
/// (`node_locators`); the handle is never something a consumer mints over a graph
/// it obtained some other way.
#[derive(Clone)]
pub struct NodeLocators {
    nets: Vec<Arc<PlainRwLock<LinkstateNetwork>>>,
}

impl NodeLocators {
    /// The locators of `nets`, in order.
    pub(crate) fn new(nets: Vec<Arc<PlainRwLock<LinkstateNetwork>>>) -> Self {
        Self { nets }
    }

    /// The locators any graph holds for `zid`, in the order the graphs and the
    /// node's advertisement give them, or `None` when no graph holds the node.
    /// Borrowed, copied out and dropped, so a caller may send on a channel with
    /// no graph borrowed.
    fn of(&self, zid: &Zid) -> Option<Vec<String>> {
        let mut found: Option<Vec<String>> = None;
        for net in &self.nets {
            if let Some(locators) = net.read().node_locators(zid) {
                let all = found.get_or_insert_with(Vec::new);
                for locator in locators {
                    if !all.contains(locator) {
                        all.push(locator.clone());
                    }
                }
            }
        }
        found
    }
}

/// Opens sessions by resolving the key's target through the link-state
/// directory and asking the face loop to dial what that node advertised.
pub struct LinkstateOpener {
    locators: NodeLocators,
    reconcile: ReconcileSender,
}

impl LinkstateOpener {
    /// Bind one graph and the connect-set channel this opener works through.
    pub fn new(net: Arc<PlainRwLock<LinkstateNetwork>>, reconcile: ReconcileSender) -> Self {
        Self::over(NodeLocators::new(vec![net]), reconcile)
    }

    /// Bind a node's graphs and the connect-set channel this opener works through.
    pub fn over(locators: NodeLocators, reconcile: ReconcileSender) -> Self {
        Self {
            locators,
            reconcile,
        }
    }

    /// Ask the face loop to hold the node whose zid is `peer_zid` (wire bytes): the
    /// one request both forms of the verb, the Push and the query, make (decision
    /// D7).
    ///
    /// Each refusal below is a DIFFERENT fact and each says which, because the
    /// only thing an operator sees from outside is that nothing happened: a
    /// target that is not a zid at all, a zid this node has never heard of, a node
    /// that advertised nothing dialable, and a face loop that is gone. A peer the
    /// node does not know is refused here and does not take an entry of the
    /// bounded peer table, which a flood of opens for zids nobody advertises
    /// would otherwise fill.
    fn ask(&self, peer_zid: &[u8]) -> OpenOutcome {
        let name = wz_session_core::zid_hex::zid_to_zenoh_hex(peer_zid);
        let Some(expected) = zid_from_wire(peer_zid) else {
            log::warn!(
                "LinkstateOpener: `{name}` does not read as a sixteen-byte zid; refusing to open."
            );
            return OpenOutcome::PeerUnknown;
        };
        let zid = Zid::from_slice(peer_zid);

        let Some(advertised) = self.locators.of(&zid) else {
            log::warn!(
                "LinkstateOpener: no link-state entry advertises dial locators for \
                 `{name}`; refusing to open a session to a node this one has never \
                 heard announce itself."
            );
            return OpenOutcome::PeerUnknown;
        };

        // The locators as the node advertised them: the loop takes them into its
        // directory as link-state hints (decision D3), so the text is kept, and
        // one that does not parse is dropped here, where the node is named.
        let planned: Vec<String> = advertised
            .into_iter()
            .filter_map(|locator| match plan_endpoint(&locator) {
                Ok(_) => Some(locator),
                Err(why) => {
                    log::warn!(
                        "LinkstateOpener: `{name}` advertises `{locator}`, which does not \
                         parse as a locator ({why:?}); skipping that one."
                    );
                    None
                }
            })
            .collect();
        if planned.is_empty() {
            log::warn!(
                "LinkstateOpener: `{name}` is known but advertises nothing dialable; \
                 refusing to open."
            );
            return OpenOutcome::NoDialableLocator;
        }

        // ADD, never Replace: this verb asks for one more peer, and adopting its
        // locators as the WHOLE desired set would silently stop re-dialling every
        // endpoint the startup seed and earlier commands put there. And an add of
        // the NODE, not of its locators (decision D4): a locator is a hint for
        // reaching the zid, so each dial is made for the zid and a session that
        // another node answers closes at its InitAck.
        let request = ConnectReconcile::AddNode {
            zid: expected,
            locators: planned,
        };
        if self.reconcile.send(request).is_err() {
            log::warn!(
                "LinkstateOpener: the face loop is gone, so the dial request for `{name}` \
                 reached nobody."
            );
            return OpenOutcome::OpenerGone;
        }
        OpenOutcome::Accepted
    }
}

impl SessionOpener for LinkstateOpener {
    /// `true` when a dial request reached the face loop — accepted, not
    /// completed, exactly as the port's contract says.
    fn request_open(&self, key: &LifecycleKey<'_>) -> bool {
        let Some(bytes) = zenoh_hex_to_zid(key.peer_zid) else {
            log::warn!(
                "LinkstateOpener: `{}` is not a zid in the rendering a key expression \
                 carries; refusing to open.",
                key.peer_zid
            );
            return false;
        };
        self.ask(&bytes) == OpenOutcome::Accepted
    }
}

impl PeerOpener for LinkstateOpener {
    fn open(&self, peer_zid: &[u8]) -> OpenOutcome {
        self.ask(peer_zid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sce_forge_runtime::codec::{SceBytes, SceStr, SceString};
    use wz_codecs::linkstate::LinkstateOwned;
    use wz_codecs::linkstate_link::LinkstateLink;
    use wz_codecs::linkstate_list::LinkstateListOwned;
    use wz_codecs::locator::LocatorOwned;
    use wz_routing_graph::WhatAmI;
    use wz_session_core::zid_hex::zid_to_zenoh_hex;

    const SELF_ZID: &[u8] = &[0x01];
    const NEIGHBOUR_ZID: &[u8] = &[0xaa];
    const PEER_ZID: &[u8] = &[0xab, 0x01];
    const ADVERTISED: &str = "tcp/127.0.0.1:7447";

    fn entry(psid: u64, sn: u64, zid: &[u8], links: &[u64]) -> LinkstateOwned {
        LinkstateOwned {
            options: 0,
            psid,
            sn,
            zid_len: Some(zid.len() as u64),
            zid: Some(SceBytes::from_slice(zid).unwrap()),
            whatami: Some(2),
            num_locators: None,
            locators: None,
            links_len: links.len() as u64,
            links: links.iter().map(|&psid| LinkstateLink { psid }).collect(),
            weights: None,
        }
    }

    /// The flood shape a DISTANT node is discovered through: self (psid 0,
    /// stale so its own links are not clobbered), the neighbour that links both
    /// ways, and the node itself advertising `locs`. Two entries are not enough
    /// — without a neighbour joining them the node is detached and pruned, which
    /// is what the first cut of this fixture got wrong and the positive arm
    /// caught.
    fn flood(locs: &[&str]) -> LinkstateListOwned {
        let mut peer = entry(2, 5, PEER_ZID, &[1]);
        if !locs.is_empty() {
            peer.num_locators = Some(locs.len() as u64);
            peer.locators = Some(
                locs.iter()
                    .map(|s| LocatorOwned {
                        locator_len: s.len() as u64,
                        locator: SceString::from_view(s).unwrap(),
                    })
                    .collect(),
            );
        }
        let entries = vec![
            entry(0, 1, SELF_ZID, &[]),
            peer,
            entry(1, 5, NEIGHBOUR_ZID, &[0, 2]),
        ];
        LinkstateListOwned {
            num_link_states: entries.len() as u64,
            link_states: entries,
        }
    }

    fn seeded(locs: &[&str]) -> Arc<PlainRwLock<LinkstateNetwork>> {
        let mut net = LinkstateNetwork::new(Zid::from_slice(SELF_ZID), WhatAmI::Peer);
        let link = net.add_link(Zid::from_slice(NEIGHBOUR_ZID), WhatAmI::Peer);
        net.ingest_linkstate_list(link, flood(locs));
        Arc::new(PlainRwLock::new(net))
    }

    fn key_for(peer_hex: &str) -> String {
        format!("@/0100/peer/session/open/{peer_hex}")
    }

    /// The whole join in one arm: a key naming a peer BY ZID becomes a dial
    /// request carrying the locators that peer advertised over link-state.
    #[test]
    fn a_known_peer_becomes_a_dial_request_for_what_it_advertised() {
        let net = seeded(&[ADVERTISED]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let opener = LinkstateOpener::new(net, tx);

        // The target is spelled through the SSOT, not by hand: an arm that wrote
        // its own hex would pass with the opener parsing a different rendering.
        let peer_hex = zid_to_zenoh_hex(PEER_ZID);
        let raw = key_for(&peer_hex);
        let key = LifecycleKey::parse(&raw).expect("the fixture key is the grammar");

        assert!(
            opener.request_open(&key),
            "a peer the flood placed and gave locators to is dialable"
        );
        match rx.try_recv().expect("a reconcile request was sent") {
            ConnectReconcile::AddNode { zid, locators } => {
                assert_eq!(locators.len(), 1, "one advertised locator, one dial");
                // Decision D4: the dial is made for the node the key named.
                assert_eq!(
                    Some(zid),
                    zid_from_wire(PEER_ZID),
                    "the dial carries the zid the key named"
                );
            }
            other => panic!("open must ADD the node to the connect set, got {other:?}"),
        }
    }

    /// A zid this node has never heard announce itself is refused — the case
    /// that makes the directory load-bearing rather than decorative.
    #[test]
    fn an_unknown_peer_is_refused_and_asks_for_no_dial() {
        let net = seeded(&[ADVERTISED]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let opener = LinkstateOpener::new(net, tx);

        let raw = key_for(&zid_to_zenoh_hex(&[0xff, 0xff]));
        let key = LifecycleKey::parse(&raw).unwrap();

        assert!(!opener.request_open(&key));
        assert!(rx.try_recv().is_err(), "nothing was asked of the face loop");
    }

    /// Known, but advertising nothing dialable. Distinct from "unknown", and
    /// the arm exists because both would otherwise read as the same silence.
    #[test]
    fn a_known_peer_advertising_nothing_is_refused() {
        let net = seeded(&[]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let opener = LinkstateOpener::new(net, tx);

        let raw = key_for(&zid_to_zenoh_hex(PEER_ZID));
        let key = LifecycleKey::parse(&raw).unwrap();

        assert!(!opener.request_open(&key));
        assert!(rx.try_recv().is_err());
    }

    /// Decision D6 / D7 — the query form of the verb makes the same request as the
    /// Push form, and each way it can end is its own outcome: taken, a zid nobody
    /// advertised, a node with nothing dialable, a face loop that is gone.
    #[test]
    fn the_query_form_asks_the_same_loop_and_names_each_outcome() {
        use wz_session_core::lifecycle_query::{OpenOutcome, PeerOpener};

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let opener = LinkstateOpener::new(seeded(&[ADVERTISED]), tx);
        assert_eq!(opener.open(PEER_ZID), OpenOutcome::Accepted);
        match rx.try_recv().expect("a reconcile request was sent") {
            ConnectReconcile::AddNode { zid, locators } => {
                assert_eq!(Some(zid), zid_from_wire(PEER_ZID));
                assert_eq!(locators, vec![String::from(ADVERTISED)]);
            }
            other => panic!("open must ADD the node to the connect set, got {other:?}"),
        }
        assert_eq!(
            opener.open(&[0xff, 0xff]),
            OpenOutcome::PeerUnknown,
            "a zid nobody advertised"
        );
        assert!(rx.try_recv().is_err(), "and nothing was asked of the loop");

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let silent = LinkstateOpener::new(seeded(&[]), tx);
        assert_eq!(
            silent.open(PEER_ZID),
            OpenOutcome::PeerUnknown,
            "a node that advertises nothing is, to the graph, a node it holds no locator for"
        );
        assert!(rx.try_recv().is_err());

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let garbled = LinkstateOpener::new(seeded(&["no-such-scheme/1.2.3.4:5"]), tx);
        assert_eq!(
            garbled.open(PEER_ZID),
            OpenOutcome::NoDialableLocator,
            "locators the node advertised, none of which parses"
        );
        assert!(rx.try_recv().is_err());

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let orphaned = LinkstateOpener::new(seeded(&[ADVERTISED]), tx);
        drop(rx);
        assert_eq!(orphaned.open(PEER_ZID), OpenOutcome::OpenerGone);
    }

    /// The whole join in one arm, the query form: a GET on the open key, answered by
    /// the lifecycle answerer over this opener, becomes the dial request the loop
    /// takes, and the reply says the request was taken. The loop's own handling of
    /// that request is `node_peer_open_e2e`'s.
    #[test]
    fn an_open_query_reaches_the_loop_as_a_dial_request() {
        use wz_session_core::lifecycle_query::{Answered, LifecycleQueries, OpenVerdict};
        use wz_session_core::lifecycle_query::{CloseOrder, SessionDirectory, SessionLinks};
        use wz_session_core::query_sink::{BorrowedQuery, QueryView, ReplyError, ReplyOut};
        use wz_session_core::sample::{EncodingHint, QosLevel};

        struct NoSessions;
        impl SessionDirectory for NoSessions {
            fn order_close(&self, _peer_zid: &[u8]) -> CloseOrder {
                CloseOrder::default()
            }
            fn links(&self, _peer_zid: &[u8]) -> SessionLinks {
                SessionLinks::default()
            }
        }
        struct Permit;
        impl wz_session_core::lifecycle_query::SessionLifecycleAuthority for Permit {
            fn admits_close(&self, _key: &LifecycleKey<'_>) -> bool {
                false
            }
            fn admits_open(&self, _key: &LifecycleKey<'_>) -> bool {
                true
            }
        }
        #[derive(Default)]
        struct Replies(Vec<String>);
        impl ReplyOut for Replies {
            fn reply(&mut self, _payload: &[u8]) {}
            fn reply_del(&mut self) {}
            fn reply_keyed_encoded(
                &mut self,
                _keyexpr: &str,
                payload: &[u8],
                _encoding: Option<&EncodingHint>,
            ) -> Result<(), ReplyError> {
                self.0
                    .push(String::from_utf8(payload.to_vec()).expect("text"));
                Ok(())
            }
            fn reply_err(&mut self, _id: Option<u32>, _schema: Option<&str>, _payload: &[u8]) {}
            fn with_responder(&mut self, _zid: &[u8], _eid: u32) {}
            fn clear_responder(&mut self) {}
            fn responder(&self) -> Option<(&[u8], u32)> {
                None
            }
        }

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let node = LifecycleQueries::new("0100", "router", Permit, NoSessions)
            .with_opener(LinkstateOpener::new(seeded(&[ADVERTISED]), tx));
        let key = format!("@/0100/router/session/open/{}", zid_to_zenoh_hex(PEER_ZID));
        let view = BorrowedQuery {
            keyexpr: &key,
            parameters: None,
            attachment: None,
            source_info: None,
            payload: None,
            encoding: None,
            rid: 1,
            is_local: false,
            qos: QosLevel::DEFAULT,
        };
        let mut out = Replies::default();
        assert_eq!(
            node.answer(&view as &dyn QueryView, &mut out),
            Answered::Open(OpenVerdict::Opening)
        );
        assert_eq!(out.0, vec![String::from("{\"verdict\":\"opening\"}")]);
        assert!(
            matches!(
                rx.try_recv(),
                Ok(ConnectReconcile::AddNode { zid, .. }) if Some(zid) == zid_from_wire(PEER_ZID)
            ),
            "the loop was asked to hold the node the key named"
        );
    }

    /// A router holds one graph per region, and a node it learned of in either is a
    /// node it can open: the locators of every graph that holds it are asked for,
    /// each once.
    #[test]
    fn a_node_two_graphs_hold_is_asked_for_at_the_locators_of_both() {
        use wz_session_core::lifecycle_query::PeerOpener;

        let routers = seeded(&[ADVERTISED]);
        let peers = seeded(&[ADVERTISED, "tcp/127.0.0.1:7448"]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let opener = LinkstateOpener::over(NodeLocators::new(vec![routers, peers]), tx);
        opener.open(PEER_ZID);
        match rx.try_recv().expect("a reconcile request was sent") {
            ConnectReconcile::AddNode { locators, .. } => assert_eq!(
                locators,
                vec![String::from(ADVERTISED), String::from("tcp/127.0.0.1:7448")],
                "the locator both graphs hold is asked once"
            ),
            other => panic!("open must ADD the node to the connect set, got {other:?}"),
        }
    }

    /// R2956 — `Zid`'s `Display` IS zenoh's form now, the string the key
    /// expression carries. It rendered per-byte wire-order hex until R2956, and
    /// this test pinned the two as DIFFERENT; it now pins them EQUAL, over
    /// shapes where a per-byte render would differ (reversal, an inner zero, a
    /// single leading zero to strip). `wz-routing-graph` does not depend on
    /// `wz-session-core`, which holds `zid_to_zenoh_hex`, so this is where the
    /// two recipes are held to one answer.
    #[test]
    fn a_zid_displays_as_the_key_expression_renders_it() {
        for zid in [
            PEER_ZID,
            &[0x1a, 0x2b, 0x0c][..],
            &[0x01, 0x00, 0x02],
            &[0x0f],
        ] {
            assert_eq!(
                Zid::from_slice(zid).to_string(),
                zid_to_zenoh_hex(zid),
                "{zid:02x?}"
            );
        }
    }

    /// ⛔ The per-byte WIRE-ORDER spelling is not zenoh's and names no node: an
    /// opener handed it would look up a zid nobody advertised. Kept after R2956
    /// made `Zid`'s `Display` zenoh's, because that spelling still reaches a key
    /// wherever something renders the bytes by hand.
    #[test]
    fn the_key_carries_the_keyexpr_rendering_not_the_wire_order_one() {
        let wire_order: String = PEER_ZID.iter().map(|b| format!("{b:02x}")).collect();
        assert_ne!(
            wire_order,
            zid_to_zenoh_hex(PEER_ZID),
            "this fixture only says something if the two renderings differ"
        );

        let net = seeded(&[ADVERTISED]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let opener = LinkstateOpener::new(net, tx);

        let wrong = key_for(&wire_order);
        let key = LifecycleKey::parse(&wrong).unwrap();
        assert!(
            !opener.request_open(&key),
            "the wire-order rendering names no node in the directory"
        );
        assert!(rx.try_recv().is_err());
    }
}

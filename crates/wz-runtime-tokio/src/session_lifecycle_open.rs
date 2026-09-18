// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//!     and this module's SSOT parses it back. (`Zid`'s own `Display` is a
//!     DIFFERENT, wire-order rendering for diagnostics; using it here would look
//!     up a zid nobody advertised.)
//!   * `LinkstateNetwork::node_locators` — the retained zid -> dial-locator
//!     directory, populated by the link-state flood this node already ingests.
//!   * `session_open::plan_endpoint` — the locator-string parse.
//!   * `ConnectReconcile::Add` — the desired-connect-set merge that ends in a
//!     dial, and the same one `connect-add` drives.
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

use std::cell::RefCell;
use std::rc::Rc;

use wz_routing_graph::{LinkstateNetwork, Zid};
use wz_session_core::drive::{LifecycleKey, SessionOpener};
use wz_session_core::zid_hex::zenoh_hex_to_zid;

use crate::accept_loop::{ConnectReconcile, ReconcileSender};
use crate::locator::AnyLocator;
use crate::session_open::plan_endpoint;

/// Opens sessions by resolving the key's target through the link-state
/// directory and asking the face loop to dial what that node advertised.
///
/// Holds the graph by `Rc<RefCell<..>>` because that is how the AP runtime
/// already holds it (`LinkstateForwarder::net`), so this shares the ONE graph
/// the floods populate rather than a copy that could disagree with it.
pub struct LinkstateOpener {
    net: Rc<RefCell<LinkstateNetwork>>,
    reconcile: ReconcileSender,
}

impl LinkstateOpener {
    /// Bind the directory and the connect-set channel this opener works through.
    pub fn new(net: Rc<RefCell<LinkstateNetwork>>, reconcile: ReconcileSender) -> Self {
        Self { net, reconcile }
    }
}

impl SessionOpener for LinkstateOpener {
    /// `true` when a dial request reached the face loop — accepted, not
    /// completed, exactly as the port's contract says.
    ///
    /// Each refusal below is a DIFFERENT fact and each says which, because the
    /// only thing an operator sees from outside is that nothing happened:
    /// a target that is not a zid at all, a zid this node has never heard of, a
    /// node that advertised nothing dialable, and a face loop that is gone.
    fn request_open(&self, key: &LifecycleKey<'_>) -> bool {
        let Some(bytes) = zenoh_hex_to_zid(key.peer_zid) else {
            log::warn!(
                "LinkstateOpener: `{}` is not a zid in the rendering a key expression \
                 carries; refusing to open.",
                key.peer_zid
            );
            return false;
        };
        let zid = Zid::from_slice(&bytes);

        // Borrow, copy out, drop — the channel send below must not happen with
        // the graph borrowed, and an owned Vec is what keeps the two apart.
        let advertised: Vec<String> = match self.net.borrow().node_locators(&zid) {
            Some(locators) => locators.to_vec(),
            None => {
                log::warn!(
                    "LinkstateOpener: no link-state entry advertises dial locators for \
                     `{}`; refusing to open a session to a node this one has never \
                     heard announce itself.",
                    key.peer_zid
                );
                return false;
            }
        };

        let planned: Vec<AnyLocator> = advertised
            .iter()
            .filter_map(|locator| match plan_endpoint(locator) {
                Ok(parsed) => Some(parsed),
                Err(why) => {
                    log::warn!(
                        "LinkstateOpener: `{}` advertises `{locator}`, which does not \
                         parse as a locator ({why:?}); skipping that one.",
                        key.peer_zid
                    );
                    None
                }
            })
            .collect();
        if planned.is_empty() {
            log::warn!(
                "LinkstateOpener: `{}` is known but advertises nothing dialable; \
                 refusing to open.",
                key.peer_zid
            );
            return false;
        }

        // ADD, never Replace: this verb asks for one more peer, and adopting its
        // locators as the WHOLE desired set would silently stop re-dialling every
        // endpoint the startup seed and earlier commands put there.
        if self.reconcile.send(ConnectReconcile::Add(planned)).is_err() {
            log::warn!(
                "LinkstateOpener: the face loop is gone, so the dial request for `{}` \
                 reached nobody.",
                key.peer_zid
            );
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sce_forge_runtime::codec::{SceBytes, SceString};
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

    fn seeded(locs: &[&str]) -> Rc<RefCell<LinkstateNetwork>> {
        let mut net = LinkstateNetwork::new(Zid::from_slice(SELF_ZID), WhatAmI::Peer);
        let link = net.add_link(Zid::from_slice(NEIGHBOUR_ZID), WhatAmI::Peer);
        net.ingest_linkstate_list(link, flood(locs));
        Rc::new(RefCell::new(net))
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
            ConnectReconcile::Add(locators) => {
                assert_eq!(locators.len(), 1, "one advertised locator, one dial");
            }
            other => panic!("open must ADD to the connect set, got {other:?}"),
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

    /// ⛔ THE RENDERING IS NOT INTERCHANGEABLE. `Zid`'s `Display` is wire-order
    /// per-byte hex and the key expression carries zenoh's LE-u128 form; for
    /// this peer they DIFFER, so an opener parsing the wrong one would look up a
    /// zid nobody advertised. The arm pins that the two strings are different
    /// and that only the key-expression one resolves.
    #[test]
    fn the_key_carries_the_keyexpr_rendering_not_the_diagnostic_one() {
        let display_form = Zid::from_slice(PEER_ZID).to_string();
        let keyexpr_form = zid_to_zenoh_hex(PEER_ZID);
        assert_ne!(
            display_form, keyexpr_form,
            "this fixture only says something if the two renderings differ"
        );

        let net = seeded(&[ADVERTISED]);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let opener = LinkstateOpener::new(net, tx);

        let wrong = key_for(&display_form);
        let key = LifecycleKey::parse(&wrong).unwrap();
        assert!(
            !opener.request_open(&key),
            "the diagnostic rendering names no node in the directory"
        );
        assert!(rx.try_recv().is_err());
    }
}

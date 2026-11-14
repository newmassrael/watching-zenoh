// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pin's CLIENT hat on the region-hat forwarder: the north of a node whose mode is Client
//! (`docs/peer-region-hats.md`, section 15). Each test states one rule of the hat and, where the
//! rule is the client hat's own, the peer node beside it as the control.

use super::*;
use crate::runtime_impl::TokioRuntime;
use crate::session_glue::{parse_frame_payload, parse_inbound, InboundFrame};
use crate::test_fixtures::{recording_actions, RecordingLinkDriver};
use wz_runtime_core::runtime::Runtime;

const WIRE_ROUTER: u8 = 0b00;
const WIRE_PEER: u8 = 0b01;
const WIRE_CLIENT: u8 = 0b10;

fn zid(b: u8) -> Zid {
    Zid::from_slice(&[b, b, b, b])
}

/// A face whose remote is `peer`, announced with the 2-bit wire mode `wire_whatami`, and what
/// its link was given.
fn face(peer: Zid, wire_whatami: u8) -> (Arc<SessionLinkActions>, Arc<RecordingLinkDriver>) {
    let (actions, sink) = recording_actions();
    TokioRuntime::with_mutex_mut(&actions.remote_peer_zid, |s| {
        *s = Some(peer.as_slice().to_vec())
    });
    TokioRuntime::with_mutex_mut(&actions.peer_whatami, |s| *s = Some(wire_whatami));
    (actions, sink)
}

/// `message` brought by `face`, as the face's drive hands a frame to the node.
fn bring(fwd: &RouterForwarder, face: FaceId, message: NetworkMessage) {
    let outcome = DriverLoopOutcome::FramePayload {
        priority: Priority::DEFAULT,
        reliable: true,
        sn: 0,
        messages: vec![message],
        has_ext: false,
        extensions: Vec::new(),
    };
    fwd.forward(face, IterationEvent::Poll(&outcome));
}

/// Every message of every frame `sink` was given, in order.
fn messages(sink: &RecordingLinkDriver) -> Vec<NetworkMessage> {
    (0..sink.frame_count())
        .filter_map(|i| match parse_inbound(&sink.frame_bytes(i)) {
            Ok(InboundFrame::Frame { payload, .. }) => parse_frame_payload(&payload).ok(),
            _ => None,
        })
        .flatten()
        .collect()
}

fn oams(sink: &RecordingLinkDriver) -> usize {
    messages(sink)
        .iter()
        .filter(|m| matches!(m, NetworkMessage::Oam(_)))
        .count()
}

fn interests(sink: &RecordingLinkDriver) -> Vec<u64> {
    messages(sink)
        .into_iter()
        .filter_map(|m| match m {
            NetworkMessage::Interest(interest) => Some(interest.interest_id),
            _ => None,
        })
        .collect()
}

/// The ids of the subscriber declarations `sink` was given.
fn subscriber_ids(sink: &RecordingLinkDriver) -> Vec<u64> {
    messages(sink)
        .into_iter()
        .filter_map(|m| match m {
            NetworkMessage::Declare(declare) => match &declare.body {
                DeclareOwnedVariant::CodecZenohDeclSubscriber(s) => Some(s.id),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn declare_sub(keyexpr: &str) -> NetworkMessage {
    NetworkMessage::Declare(Box::new(
        build_declare_subscriber(0, 0, Some(keyexpr)).expect("build declare"),
    ))
}

fn put(keyexpr: &str) -> NetworkMessage {
    NetworkMessage::Push(Box::new(
        wz_session_core::push_build::build_push_literal(keyexpr, b"x").expect("build push"),
    ))
}

fn query(rid: u64, keyexpr: &str) -> NetworkMessage {
    NetworkMessage::Request(Box::new(
        wz_session_core::request_build::build_request_query(rid, 0, Some(keyexpr))
            .expect("build request"),
    ))
}

/// The south of a client node as upstream's tests of its regions keep it: one subregion that
/// holds every peer and every client, so that only a router is placed north.
fn south_of_clients_and_peers() -> SouthPartition {
    use wz_codecs::whatami::WhatAmIMatcher;
    use wz_session_core::region_partition::{RegionFilter, SouthSubregion};
    SouthPartition::Custom(vec![SouthSubregion {
        filters: Some(vec![RegionFilter {
            modes: Some(WhatAmIMatcher::empty().client().peer()),
            ..RegionFilter::default()
        }]),
    }])
}

fn client_node() -> RouterForwarder {
    RouterForwarder::client(zid(0x05)).with_south_partition(south_of_clients_and_peers())
}

/// The peer region south of the node, which [`south_of_clients_and_peers`] makes.
const SOUTH_PEERS: Region = Region::South {
    id: 0,
    mode: WhatAmI::Peer,
};

/// A client node with the router it is attached to as face 0 and a peer of its south as face
/// 1, every sink empty.
fn client_node_with_router_and_south_peer() -> (
    RouterForwarder,
    Arc<RecordingLinkDriver>,
    Arc<RecordingLinkDriver>,
) {
    let node = client_node();
    let (router, sink_router) = face(zid(0xAA), WIRE_ROUTER);
    let (peer, sink_peer) = face(zid(0xCC), WIRE_PEER);
    node.register(FaceId(0), &router);
    node.register(FaceId(1), &peer);
    sink_router.reset();
    sink_peer.reset();
    (node, sink_router, sink_peer)
}

/// The north of a client node is the client hat, held as the router and peer hats are, and it is
/// no leaf: a broker hat there would keep the router as a client of the node. Turned red by an
/// `is_leaf` that takes the client hat, which builds a broker hat in the north.
#[test]
fn the_north_of_a_client_node_is_the_client_hat() {
    assert!(is_client_hat(NORTH_REGION, WhatAmI::Client));
    assert!(!is_client_hat(NORTH_REGION, WhatAmI::Peer));
    assert!(!is_client_hat(NORTH_REGION, WhatAmI::Router));
    assert!(
        !is_client_hat(Region::Local, WhatAmI::Client),
        "the node's own face is the broker hat's"
    );
    assert!(!is_leaf(NORTH_REGION, WhatAmI::Client));

    let node = client_node();
    let on = node.on_tables();
    assert!(on.tables.north_is_client());
    assert!(
        on.tables.mesh_hat(NORTH_REGION).is_some(),
        "the client hat is held in a mesh hat"
    );
    assert!(on.tables.face_based(NORTH_REGION));
    assert!(!on.tables.exchanges_topology(NORTH_REGION));
    assert!(
        on.tables.exchanges_topology(SOUTH_PEERS),
        "the peer region it keeps south of it does"
    );
    assert!(on.tables.routes_interest_north());
    drop(on);

    let peer = RouterForwarder::peer(zid(0x05));
    assert!(!peer.on_tables().tables.north_is_client());
    assert!(peer.on_tables().tables.routes_interest_north());
    let router = RouterForwarder::new(zid(0x05));
    assert!(!router.on_tables().tables.routes_interest_north());
}

/// The client hat sends no link state: the router it is attached to holds it as a client, a
/// leaf that routes no topology. A peer node sends its gateway its graph on the same link, which
/// is the control. Turned red by a flood that reads the client hat's graph.
#[test]
fn a_client_node_sends_the_router_it_is_attached_to_no_link_state() {
    let link_state_sent = |node: RouterForwarder| {
        let (router, sink) = face(zid(0xAA), WIRE_ROUTER);
        node.register(FaceId(0), &router);
        oams(&sink)
    };
    assert!(
        link_state_sent(RouterForwarder::peer(zid(0x05))) > 0,
        "a peer node tells its gateway its graph"
    );
    assert_eq!(link_state_sent(client_node()), 0);
}

/// What the router a client node is attached to sends it as link state is not read: the pin's
/// client hat answers an OAM with nothing (`zenoh/src/net/routing/hat/client/mod.rs` @
/// `fn handle_oam(`). A peer node reads the same list, which is the control. Turned red by an
/// ingest that reads the client hat's graph.
#[test]
fn a_client_node_reads_no_link_state_from_the_router_it_is_attached_to() {
    use wz_codecs::linkstate_link::LinkstateLink;
    use wz_session_core::transport_profile::owned::LinkstateOwned;
    const OPT_P: u8 = 0x01;
    const OPT_W: u8 = 0x02;
    let entry = |psid: u64, sn: u64, node: u8, links: &[u64]| LinkstateOwned {
        options: OPT_P | OPT_W,
        psid,
        sn,
        zid_len: Some(4),
        zid: Some(wz_session_core::codec_owned::owned_bytes(zid(node).as_slice()).unwrap()),
        whatami: Some(2),
        num_locators: None,
        locators: None,
        links_len: links.len() as u64,
        options_h: wz_codecs::linkstate::LinkstateOptionsH::NotH {
            links: wz_session_core::held_list::held(
                links
                    .iter()
                    .map(|&psid| LinkstateLink { psid })
                    .collect::<Vec<_>>(),
            )
            .expect("a fixture's links are within the bound"),
        },
    };
    let read = |node: RouterForwarder| {
        let (router, _sink) = face(zid(0xAA), WIRE_ROUTER);
        node.register(FaceId(0), &router);
        let entries = vec![entry(0, 1, 0x05, &[]), entry(1, 5, 0xAA, &[0])];
        let list = LinkstateListOwned {
            num_link_states: entries.len() as u64,
            link_states: wz_session_core::held_list::held(entries)
                .expect("a fixture's entries are within the bound"),
        };
        let oam = build_linkstate_oam_owned(&list).expect("build oam");
        bring(&node, FaceId(0), NetworkMessage::Oam(oam));
        node.ingested()
    };
    assert_eq!(
        read(RouterForwarder::peer(zid(0x05))),
        1,
        "a peer node reads it"
    );
    assert_eq!(read(client_node()), 0);
}

/// A client node takes one north-bound remote (`zenoh/src/net/runtime/mod.rs` @
/// `bail!("Client runtimes only accept one north-bound transport");`). A second link of the
/// same remote is no second transport, a remote the partition places south is served, and a
/// peer node takes any number of routers. Turned red by a refusal that does not count the north
/// faces, or that counts the remote the north face already is.
#[test]
fn a_client_node_refuses_a_second_north_bound_remote() {
    let node = client_node();
    let (router, _s) = face(zid(0xAA), WIRE_ROUTER);
    assert_eq!(node.refuses_face(&router), None, "the first is its north");
    node.register(FaceId(0), &router);

    let (again, _s) = face(zid(0xAA), WIRE_ROUTER);
    assert_eq!(
        node.refuses_face(&again),
        None,
        "a second link of the remote the north face is"
    );
    let (other, _s) = face(zid(0xBB), WIRE_ROUTER);
    let why = node
        .refuses_face(&other)
        .expect("a second router is refused");
    assert!(why.contains("one north-bound transport"), "{why}");
    let (south, _s) = face(zid(0xCC), WIRE_PEER);
    assert_eq!(node.refuses_face(&south), None, "a peer placed south");

    let peer = RouterForwarder::peer(zid(0x05));
    let (first, _s) = face(zid(0xAA), WIRE_ROUTER);
    peer.register(FaceId(0), &first);
    let (second, _s) = face(zid(0xBB), WIRE_ROUTER);
    assert_eq!(
        peer.refuses_face(&second),
        None,
        "a peer node takes a second router"
    );
}

/// The end of the initial declarations, the `DeclareFinal` of interest id 0, passes between two
/// peers of the north region of a peer node and on no other face: the pin's peer hat sends it on
/// a face of its north region whose remote is north-bound as well
/// (`zenoh/src/net/routing/hat/peer/mod.rs` @ `let do_initial_interest =`). A peer the partition
/// places south of a client node, or south of a peer node, is sent none and owes none; a peer of a
/// peer node's own region, the control, is sent one and owes one. Turned red by a rule that reads
/// the two modes and the announced bound alone, which places the south peer north.
#[test]
fn only_a_peer_of_a_peer_nodes_north_region_ends_its_initial_declarations() {
    let ends_sent = |sink: &RecordingLinkDriver| {
        messages(sink)
            .iter()
            .filter(|m| match m {
                NetworkMessage::Declare(declare) => {
                    declare.interest_id == Some(INITIAL_INTEREST_ID)
                        && matches!(declare.body, DeclareOwnedVariant::CodecZenohDeclFinal(_))
                }
                _ => false,
            })
            .count()
    };
    let peer_face_of = |node: RouterForwarder| {
        let (peer, sink) = face(zid(0xCC), WIRE_PEER);
        node.register(FaceId(1), &peer);
        (ends_sent(&sink), node.initial_declares_pending())
    };
    assert_eq!(
        peer_face_of(client_node()),
        (0, 0),
        "a peer south of a client node"
    );
    assert_eq!(
        peer_face_of(
            RouterForwarder::peer(zid(0x05)).with_south_partition(south_of_clients_and_peers())
        ),
        (0, 0),
        "a peer south of a peer node"
    );
    assert_eq!(
        peer_face_of(RouterForwarder::peer(zid(0x05))),
        (1, 1),
        "a peer of a peer node's own region"
    );
}

/// The client hat sends north every Put whose source is south, as the node it is attached to
/// declares only what the client asked for (`zenoh/src/net/routing/hat/client/pubsub.rs` @
/// `dst.has_unfinalized_subscriber_interest = true`), and sends it no Put that came from it.
/// Turned red by a gateway rule that leaves the client hat out.
#[test]
fn a_client_node_sends_a_south_put_to_the_router_and_none_back() {
    let (node, sink_router, _sink_peer) = client_node_with_router_and_south_peer();
    bring(&node, FaceId(1), put("demo/a"));
    assert_eq!(
        sink_router.frame_count(),
        1,
        "the south peer's Put goes north"
    );
    sink_router.reset();
    bring(&node, FaceId(0), put("demo/b"));
    assert_eq!(
        sink_router.frame_count(),
        0,
        "the router's own Put does not"
    );
}

/// The query twin (`zenoh/src/net/routing/hat/client/queries.rs` @
/// `dst.has_unfinalized_queryable_interest = true`): a south query is asked of the router once,
/// from the north region. A south client's query is routed into the south peer region as well,
/// and the router is not asked from there a second time. Turned red by a gateway rule that leaves
/// the client hat out, or by a block that asks the gateways from a region they are not in.
#[test]
fn a_client_node_asks_the_router_a_south_query_once() {
    let requests = |sink: &RecordingLinkDriver| {
        messages(sink)
            .iter()
            .filter(|m| matches!(m, NetworkMessage::Request(_)))
            .count()
    };
    let (node, sink_router, _sink_peer) = client_node_with_router_and_south_peer();
    let (client, _sink_client) = face(zid(0xDD), WIRE_CLIENT);
    node.register(FaceId(2), &client);
    sink_router.reset();
    bring(&node, FaceId(2), query(3, "demo/q"));
    assert_eq!(requests(&sink_router), 1, "a south client's query");
    sink_router.reset();
    bring(&node, FaceId(1), query(4, "demo/q"));
    assert_eq!(requests(&sink_router), 1, "a south peer's query");
}

/// The client hat declares to its one face what its south holds, under an id of its own and
/// never the sourced id 0, without waiting for a tree: it propagates to the face it owns
/// (`zenoh/src/net/routing/hat/client/pubsub.rs` @ `fn propagate_subscriber(`). Turned red by a
/// client hat that is not face-based, which sends along a tree no tick has computed.
#[test]
fn a_client_node_declares_its_souths_subscriber_to_the_router_under_its_own_id() {
    let (node, sink_router, _sink_peer) = client_node_with_router_and_south_peer();
    bring(&node, FaceId(1), declare_sub("demo/s"));
    let ids = subscriber_ids(&sink_router);
    assert_eq!(ids.len(), 1, "declared once: {ids:?}");
    assert_ne!(ids[0], 0, "numbered by the node");
}

/// What the router declares to a client node it withdraws by the id alone, as the pin's broker hat
/// withdraws from a client (`zenoh/src/net/routing/hat/broker/pubsub.rs` @
/// `ext_wire_expr: WireExprType::null(),`), and the client hat resolves the id it was given
/// (`zenoh/src/net/routing/hat/client/pubsub.rs` @ `.remote_subs.remove(&id)`). Turned red by a
/// client hat that does not keep the ids its face declared by.
#[test]
fn a_client_node_resolves_the_routers_withdrawal_by_its_id() {
    let (node, _sink_router, _sink_peer) = client_node_with_router_and_south_peer();
    let held = |node: &RouterForwarder| {
        node.on_tables()
            .tables
            .mesh(NORTH_REGION)
            .subs
            .source_count("demo/w")
    };
    let declared = build_declare_subscriber(3, 0, Some("demo/w")).expect("build declare");
    bring(
        &node,
        FaceId(0),
        NetworkMessage::Declare(Box::new(declared)),
    );
    assert_eq!(held(&node), 1, "the router's subscriber is held");
    bring(
        &node,
        FaceId(0),
        NetworkMessage::Declare(Box::new(build_undeclare_subscriber(3))),
    );
    assert_eq!(held(&node), 0, "and withdrawn by the id alone");
}

/// The node's own publisher asks the router it is attached to for the subscribers of its key,
/// the one it had before the router came up as well (`zenoh/src/net/routing/hat/client/interests.rs`
/// @ `fn repropagate_interests`). Turned red by a node that asks only when it is a peer.
#[test]
fn a_client_nodes_own_publisher_asks_the_router_it_is_attached_to() {
    let node = client_node();
    node.declare_local_interest(7, "demo/data", false);
    let (router, sink_router) = face(zid(0xAA), WIRE_ROUTER);
    node.register(FaceId(0), &router);
    assert_eq!(interests(&sink_router), vec![7], "asked when it comes up");
    sink_router.reset();
    node.declare_local_interest(8, "demo/more", false);
    assert_eq!(interests(&sink_router), vec![8], "and when the node asks");
}

/// The interest of a peer south of a client node goes north to the router, and the peer's final
/// waits for the router's answer (`zenoh/src/net/routing/hat/client/interests.rs` @
/// `fn route_interest`). A peer node answers a south peer's interest itself, from what its own
/// north tells it unasked, which is the control. Turned red by an interest broker that acts for
/// a peer node alone.
#[cfg(feature = "routing-interest-pending-gc")]
#[test]
fn a_south_peers_interest_is_sent_to_the_router_a_client_node_is_attached_to() {
    use wz_session_core::interest_build::build_interest_subscribers;

    let (node, sink_router, sink_peer) = client_node_with_router_and_south_peer();
    let interest = build_interest_subscribers(5, true, true, 0, Some("demo/**"))
        .expect("build current-future interest");
    bring(&node, FaceId(1), NetworkMessage::Interest(interest));
    assert_eq!(interests(&sink_router).len(), 1, "the router is asked");
    assert_eq!(node.pending_interests_len(), 1, "and its answer awaited");
    assert_eq!(sink_peer.frame_count(), 0, "the peer's final is withheld");
}

/// The linkstate legs of the admin space answer the peer and router regions and not the client
/// hat (`zenoh/src/net/runtime/adminspace.rs` @ `.filter(|(_, hat)| hat.mode().is_peer() || hat.mode().is_router())`).
/// Turned red by a client node that answers its north as a peer node does.
#[cfg(feature = "adminspace-router-linkstate")]
#[test]
fn a_client_node_answers_the_linkstate_of_its_south_regions_alone() {
    let regions: Vec<String> = client_node()
        .linkstate_regions_text()
        .into_iter()
        .map(|(region, _)| region)
        .collect();
    assert!(!regions.iter().any(|r| r == "north"), "{regions:?}");
    let south_peers = SOUTH_PEERS.to_string();
    assert!(regions.iter().any(|r| *r == south_peers), "{regions:?}");
}

/// A declaration the router makes to a client node is named in the admin legs by the mode of
/// the face it came from, a router (`zenoh/src/net/routing/hat/client/pubsub.rs` @
/// `WhatAmI::Router => srcs.routers.push(face.zid),`). Turned red by admin legs that read the
/// router and peer hats only, which leave the client hat's declarations out.
#[cfg(feature = "adminspace-introspection-handlers")]
#[test]
fn a_client_node_names_its_routers_declaration_among_the_routers() {
    use wz_session_core::zid_hex::zid_to_zenoh_hex;

    let (node, _sink_router, _sink_peer) = client_node_with_router_and_south_peer();
    bring(&node, FaceId(0), declare_sub("demo/r"));
    let rows = node.admin_subscribers();
    let (_, sources) = rows
        .iter()
        .find(|(key, _)| key == "demo/r")
        .unwrap_or_else(|| panic!("the router's subscriber is listed: {rows:?}"));
    assert_eq!(
        sources.routers,
        vec![zid_to_zenoh_hex(zid(0xAA).as_slice())]
    );
    assert!(sources.peers.is_empty() && sources.clients.is_empty());
}

// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The event sequences behind `crates/wz-session-core/src/stats_registry/zenoh_1_10_1.golden`,
//! driven through the REAL `zenoh-stats` registry at the pin.
//!
//! `scripts/lib/zenoh_stats_golden.py` runs this binary and writes or checks
//! the golden from its output. Each scenario here has a twin in the wz test
//! module that performs the same events on
//! `wz_session_core::stats_registry::StatsRegistry`; a scenario changed on one
//! side only is a golden the other side can no longer reproduce.

use std::str::FromStr;

use zenoh_buffers::ZBuf;
use zenoh_keyexpr::keyexpr;
use zenoh_protocol::{
    core::{Locator, Priority, WhatAmI, WireExpr, ZenohIdProto},
    network::{push, NetworkBody, NetworkMessage, Push},
    zenoh::{PushBody, Put},
};
use zenoh_stats::{
    LocalityLabel, MessageLabel, ReasonLabel, ResourceLabel, SpaceLabel, StatsDirection::*,
    StatsKeys, StatsKeysTree, StatsRegistry,
};

fn put(priority: Priority, len: usize) -> NetworkMessage {
    NetworkBody::Push(Push {
        wire_expr: WireExpr::from("a/b"),
        ext_qos: push::ext::QoSType::new(priority, Default::default(), false),
        ext_tstamp: None,
        ext_nodeid: push::ext::NodeIdType::DEFAULT,
        ext_ts_stack: None,
        payload: PushBody::Put(Put {
            timestamp: None,
            encoding: Default::default(),
            ext_sinfo: None,
            ext_attachment: None,
            ext_unknown: vec![],
            payload: ZBuf::from(vec![7u8; len]),
        }),
    })
    .into()
}

fn dump(title: &str, registry: &StatsRegistry, pt: bool, pl: bool, dc: bool, pk: bool) {
    let mut body = String::new();
    registry.encode_metrics(&mut body, pt, pl, dc, pk).unwrap();
    println!("===== {title} per_transport={pt} per_link={pl} disconnected={dc} per_key={pk}");
    print!("{body}");
    println!("===== END");
}

fn zid(hex: &str) -> ZenohIdProto {
    ZenohIdProto::from_str(hex).unwrap()
}

fn locator(s: &str) -> Locator {
    Locator::from_str(s).unwrap()
}

fn main() {
    let local = zid("a1b2");

    // S1 — nothing opened: the descriptor skeleton, with and without partitions.
    let registry = StatsRegistry::new(local, WhatAmI::Router, "v1");
    dump("S1 empty", &registry, true, true, false, true);
    dump("S1 empty", &registry, false, false, false, false);

    // S2 — one unicast transport over one tcp link, every family touched.
    let registry = StatsRegistry::new(local, WhatAmI::Router, "v1");
    let transport = registry.unicast_transport_stats(zid("c3d4"), WhatAmI::Peer, None);
    let link = transport.link_stats(
        &locator("tcp/127.0.0.1:7447"),
        &locator("tcp/127.0.0.1:50000"),
    );
    link.inc_bytes(Tx, 100);
    link.inc_bytes(Rx, 50);
    link.inc_transport_message(Tx, 2);
    link.inc_network_message(Tx, &put(Priority::Data, 40));
    link.inc_network_message(Tx, &put(Priority::Data, 40));
    link.inc_network_message(Rx, &put(Priority::RealTime, 3));
    for size in [40, 2000] {
        transport.observe_network_message_payload(
            Tx,
            MessageLabel::Put,
            Priority::Data,
            size,
            SpaceLabel::User,
            &StatsKeys::default(),
            false,
        );
    }
    transport
        .drop_stats(ReasonLabel::AccessControl)
        .observe_network_message_dropped_payload(Rx, &put(Priority::Data, 5));
    link.tx_observe_congestion(&put(Priority::Background, 9));
    registry.inc_resource_declared(ResourceLabel::Subscriber, LocalityLabel::Local);
    dump("S2 one", &registry, true, true, false, true);

    // S3 — a second transport over udp; then the first one's link and the
    // transport itself close, leaving it disconnected but not yet collected.
    let second = registry.unicast_transport_stats(zid("e5f6"), WhatAmI::Client, Some("cn1".into()));
    let second_link = second.link_stats(
        &locator("udp/10.0.0.1:7447"),
        &locator("udp/10.0.0.2:7447"),
    );
    second_link.inc_bytes(Tx, 7);
    second_link.inc_network_message(Tx, &put(Priority::Data, 1));
    drop(link);
    drop(transport);
    dump("S3 first-gone", &registry, true, true, false, false);
    dump("S3 first-gone", &registry, true, true, true, false);

    // S4 — a multicast group and one peer seen on it.
    let registry = StatsRegistry::new(local, WhatAmI::Peer, "v1");
    let group = registry.multicast_transport_stats("udp/224.0.0.224:7446".into());
    let group_link = group.link_stats(
        &locator("udp/10.0.0.1:7446"),
        &locator("udp/224.0.0.224:7446"),
    );
    group_link.inc_bytes(Tx, 11);
    let peer_link = group.peer_link_stats(zid("aa"), WhatAmI::Peer, &group_link);
    peer_link.inc_bytes(Rx, 13);
    dump("S4 mcast", &registry, true, true, false, false);

    // S6 — a multicast group as upstream's multicast TRANSPORT records one
    // (R2847): bytes and transport messages both ways on the group link, the
    // sent Put counted there too, the received Put counted in the sending
    // peer's partition, and BOTH payloads observed on the group, because every
    // multicast face is built with the group transport's stats. S4 above
    // exercises the registry's API; this exercises the attribution.
    let registry = StatsRegistry::new(local, WhatAmI::Peer, "v1");
    let group = registry.multicast_transport_stats("udp/224.0.0.224:7446".into());
    let group_link = group.link_stats(
        &locator("udp/10.0.0.1:7446"),
        &locator("udp/224.0.0.224:7446"),
    );
    let none = StatsKeys::default();
    group_link.inc_bytes(Tx, 20);
    group_link.inc_transport_message(Tx, 1);
    group_link.inc_network_message(Tx, &put(Priority::Data, 4));
    group.observe_network_message_payload(
        Tx,
        MessageLabel::Put,
        Priority::Data,
        4,
        SpaceLabel::User,
        &none,
        false,
    );
    group_link.inc_bytes(Rx, 30);
    group_link.inc_transport_message(Rx, 2);
    let peer_link = group.peer_link_stats(zid("aa"), WhatAmI::Peer, &group_link);
    peer_link.inc_network_message(Rx, &put(Priority::Data, 6));
    group.observe_network_message_payload(
        Rx,
        MessageLabel::Put,
        Priority::Data,
        6,
        SpaceLabel::User,
        &none,
        false,
    );
    dump("S6 mcast-flow", &registry, true, true, false, false);

    // S5 — per-key payloads: one payload matched by two configured keys.
    let registry = StatsRegistry::new(local, WhatAmI::Router, "v1");
    let mut tree = StatsKeysTree::default();
    let keys = [keyexpr::new("a/**").unwrap(), keyexpr::new("a/b").unwrap()];
    registry.update_keys(&mut tree, keys.iter().copied());
    // SAFETY: no cache is passed, so none can be shared with another tree.
    let matched = unsafe { tree.get_keys(|| None, || Some(keyexpr::new("a/b").unwrap())) };
    let transport = registry.unicast_transport_stats(zid("c3d4"), WhatAmI::Peer, None);
    transport.observe_network_message_payload(
        Rx,
        MessageLabel::Put,
        Priority::Data,
        64,
        SpaceLabel::User,
        &matched,
        false,
    );
    dump("S5 perkey", &registry, true, false, false, true);
}

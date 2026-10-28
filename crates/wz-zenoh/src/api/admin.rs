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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.1, file
// src/api/admin.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1). The session's own part of
// the admin space: the transports and the links it holds, published as they come and go and
// answered to a query. They are read from the session (`WeakSession::transports` and `links`),
// which lists the faces of its engine, where upstream reads its runtime, so the module is
// upstream's otherwise. The transports and links are the unstable part of the API in this crate,
// so the module is too: a build without `unstable` serves no admin key of its own, where upstream's
// answers a query for them.

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use zenoh_config::{wrappers::ZenohId, WhatAmI};
use zenoh_core::Wait;
use zenoh_keyexpr::{keyexpr, OwnedKeyExpr};
use zenoh_macros::ke;
use zenoh_protocol::core::{CongestionControl, Locator, Reliability};

// `ke!` writes its paths from `zenoh`, as the crate of a user of the macro; this is that crate.
use crate::{
    self as zenoh,
    api::{
        encoding::Encoding,
        handlers::Callback,
        info::{Link, LinkEvent, Transport, TransportEvent},
        key_expr::KeyExpr,
        publisher::Priority,
        queryable::Query,
        sample::{Locality, SampleKind},
        session::{SessionClosedError, WeakSession},
    },
};

static KE_AT: &keyexpr = ke!("@");
static KE_ADV_PREFIX: &keyexpr = ke!("@adv");
static KE_PUB: &keyexpr = ke!("pub");
static KE_EMPTY: &keyexpr = ke!("_");
static KE_STARSTAR: &keyexpr = ke!("**");
static KE_SESSION: &keyexpr = ke!("session");
static KE_TRANSPORT_UNICAST: &keyexpr = ke!("transport/unicast");
static KE_TRANSPORT_MULTICAST: &keyexpr = ke!("transport/multicast");
static KE_LINK: &keyexpr = ke!("link");

// JSON structures for making adminspace independent of internal structures
#[derive(serde::Serialize)]
struct TransportJson {
    zid: ZenohId,
    whatami: WhatAmI,
    is_qos: bool,
    #[cfg(feature = "shared-memory")]
    is_shm: bool,
}

impl From<Transport> for TransportJson {
    fn from(transport: Transport) -> Self {
        Self {
            zid: transport.zid,
            whatami: transport.whatami,
            is_qos: transport.is_qos,
            #[cfg(feature = "shared-memory")]
            is_shm: transport.is_shm,
        }
    }
}

#[derive(serde::Serialize)]
struct PrioritiesJson {
    start: zenoh_protocol::core::Priority,
    end: zenoh_protocol::core::Priority,
}

impl From<(u8, u8)> for PrioritiesJson {
    fn from(priorities: (u8, u8)) -> Self {
        Self {
            start: priorities.0.try_into().unwrap_or_default(),
            end: priorities.1.try_into().unwrap_or_default(),
        }
    }
}

#[derive(serde::Serialize)]
struct LinkJson {
    src: Locator,
    dst: Locator,
    group: Option<Locator>,
    mtu: u16,
    is_streamed: bool,
    interfaces: Vec<String>,
    auth_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priorities: Option<PrioritiesJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reliability: Option<Reliability>,
}

impl From<Link> for LinkJson {
    fn from(link: Link) -> Self {
        Self {
            src: link.src,
            dst: link.dst,
            group: link.group,
            mtu: link.mtu,
            is_streamed: link.is_streamed,
            interfaces: link.interfaces,
            auth_identifier: link.auth_identifier,
            priorities: link.priorities.map(PrioritiesJson::from),
            reliability: link.reliability,
        }
    }
}

fn ke_prefix(own_zid: &keyexpr) -> OwnedKeyExpr {
    KE_AT / own_zid / KE_SESSION
}

fn ke_adv_prefix(own_zid: &keyexpr) -> OwnedKeyExpr {
    KE_ADV_PREFIX / KE_PUB / own_zid / KE_EMPTY / KE_EMPTY / KE_AT / KE_AT / own_zid / KE_SESSION
}

fn ke_transport(transport: &Transport) -> OwnedKeyExpr {
    ke_transport_of(&transport.zid, transport.is_multicast)
}

fn ke_transport_of(zid: &ZenohId, is_multicast: bool) -> OwnedKeyExpr {
    if is_multicast {
        KE_TRANSPORT_MULTICAST / &zid.into_keyexpr()
    } else {
        KE_TRANSPORT_UNICAST / &zid.into_keyexpr()
    }
}

fn ke_link(link: &Link) -> OwnedKeyExpr {
    let mut s = DefaultHasher::new();
    link.hash(&mut s);
    let link_hash = s.finish().to_string();
    // link_hash is number, no disallowed characters, it is safe to use unchecked
    let link_key = unsafe { keyexpr::from_str_unchecked(&link_hash) };
    KE_LINK / link_key
}

/// Publish one event of the admin space: a put of `payload` for an event that opened something,
/// a delete for one that closed it, delivered to this session's own subscribers only.
fn publish(session: &WeakSession, key_expr: OwnedKeyExpr, kind: SampleKind, payload: Vec<u8>) {
    let key_expr = KeyExpr::from(key_expr);
    if let Err(e) = session.resolve_put(
        &key_expr,
        payload.into(),
        kind,
        Encoding::APPLICATION_JSON,
        CongestionControl::default(),
        Priority::default(),
        false,
        Locality::SessionLocal,
        Reliability::default(),
        None,
        None,
        None,
        None,
    ) {
        if e.downcast_ref::<SessionClosedError>().is_none() {
            tracing::error!("Unable to publish an event of the admin space: {}", e);
        }
    }
}

pub(crate) fn init(session: WeakSession) {
    // Normal adminspace queryable
    let own_zid = session.zid().into_keyexpr();
    let prefix = ke_prefix(&own_zid);
    let _admin_qabl = session.declare_queryable_inner(
        &KeyExpr::from(&prefix / KE_STARSTAR),
        true,
        Locality::SessionLocal,
        Callback::from({
            let session = session.clone();
            move |q| on_admin_query(&session, &prefix, &prefix, q)
        }),
        None,
    );

    // Queryable simulating advanced publisher to allow advanced subscriber to receive historical data
    let prefix = ke_prefix(&own_zid);
    let adv_prefix = ke_adv_prefix(&own_zid);
    let _admin_adv_qabl = session.declare_queryable_inner(
        &KeyExpr::from(&adv_prefix / KE_STARSTAR),
        true,
        Locality::SessionLocal,
        Callback::from({
            let session = session.clone();
            move |q| on_admin_query(&session, &adv_prefix, &prefix, q)
        }),
        None,
    );

    // Subscribe to transport events and publish them to the adminspace
    // key "@/<own_zid>/session/transport/<unicast|multicast>/<peer_zid>"
    let callback = Callback::from({
        let session = session.clone();
        let own_zid = session.zid().into_keyexpr();
        move |event: TransportEvent| {
            let key_expr = ke_prefix(&own_zid) / &ke_transport(&event.transport);
            tracing::trace!(
                "Publishing transport event: {:?} : {:?} on {}",
                &event.kind,
                &event.transport,
                key_expr
            );
            let payload = match &event.kind {
                SampleKind::Put => {
                    let json = TransportJson::from(event.transport);
                    serde_json::to_vec(&json).unwrap_or_default()
                }
                SampleKind::Delete => Vec::new(),
            };
            publish(&session, key_expr, event.kind, payload);
        }
    });
    if let Err(e) = session.declare_transport_events_listener_inner(callback, false, None) {
        tracing::error!("Unable to subscribe to transport events: {}", e);
    }

    // Subscribe to link events and publish them to the adminspace
    // key "@/<own_zid>/session/transport/<unicast|multicast>/<peer_zid>/link/<link_hash>"
    let callback = Callback::from({
        let session = session.clone();
        let own_zid = session.zid().into_keyexpr();
        move |event: LinkEvent| {
            // Upstream finds the transport in the runtime to learn whether it is multicast. The
            // engine tells a link that goes down together with its face, which is gone from the
            // listing by then, so the link says it: only a member of a group has a group locator.
            let key_expr = ke_prefix(&own_zid)
                / &ke_transport_of(&event.link.zid, event.link.group.is_some())
                / &ke_link(&event.link);
            tracing::trace!(
                "Publishing link event: {:?} : {:?} on {}",
                &event.kind,
                &event.link,
                key_expr
            );
            let payload = match &event.kind {
                SampleKind::Put => {
                    serde_json::to_vec(&LinkJson::from(event.link)).unwrap_or_default()
                }
                SampleKind::Delete => Vec::new(),
            };
            publish(&session, key_expr, event.kind, payload);
        }
    });
    if let Err(e) = session.declare_link_events_listener_inner(callback, false, None, None) {
        tracing::error!("Unable to subscribe to link events: {}", e);
    }
}

fn reply<T: serde::Serialize>(
    match_prefix: &keyexpr,
    reply_prefix: &keyexpr,
    key: &keyexpr,
    query: &Query,
    payload: &T,
) {
    let match_keyexpr = match_prefix / key;
    if query.key_expr().intersects(&match_keyexpr) {
        let reply_keyexpr = reply_prefix / key;
        match serde_json::to_vec(payload) {
            Ok(bytes) => {
                let _ = query
                    .reply(reply_keyexpr, bytes)
                    .encoding(Encoding::APPLICATION_JSON)
                    .wait();
            }
            Err(e) => tracing::debug!("Admin query error: {}", e),
        }
    }
}

pub(crate) fn on_admin_query(
    session: &WeakSession,
    match_prefix: &keyexpr,
    reply_prefix: &keyexpr,
    query: Query,
) {
    for transport in session.transports() {
        let ke_transport = ke_transport(&transport);
        let transport_json = TransportJson::from(transport.clone());
        reply(
            match_prefix,
            reply_prefix,
            &ke_transport,
            &query,
            &transport_json,
        );
        for link in session.links(Some(&transport)) {
            let ke_link = &ke_transport / &ke_link(&link);
            let link_json = LinkJson::from(link);
            reply(match_prefix, reply_prefix, &ke_link, &query, &link_json);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(zid: ZenohId, group: Option<Locator>) -> Link {
        let locator = |text: &str| Locator::try_from(text).expect("a locator");
        Link {
            zid,
            src: locator("tcp/127.0.0.1:7447"),
            dst: locator("tcp/127.0.0.1:50000"),
            group,
            mtu: 1500,
            is_streamed: true,
            interfaces: vec![],
            auth_identifier: None,
            priorities: None,
            reliability: None,
        }
    }

    #[test]
    fn a_transport_is_named_by_its_kind_and_its_peer() {
        let zid = ZenohId::try_from(&[0x0a_u8, 0x0b][..]).expect("an id");
        let own = ZenohId::try_from(&[0x01_u8][..]).expect("an id");
        let prefix = ke_prefix(&own.into_keyexpr());
        // An id is written as the number its little-endian bytes make, without leading zeros.
        assert_eq!(prefix.as_str(), "@/1/session");
        assert_eq!(
            (&prefix / &ke_transport_of(&zid, false)).as_str(),
            "@/1/session/transport/unicast/b0a"
        );
        assert_eq!(
            (&prefix / &ke_transport_of(&zid, true)).as_str(),
            "@/1/session/transport/multicast/b0a"
        );
    }

    #[test]
    fn a_link_has_the_same_key_when_it_comes_up_and_when_it_goes_down() {
        let zid = ZenohId::try_from(&[0x0a_u8][..]).expect("an id");
        let up = link(zid, None);
        let down = up.clone();
        assert_eq!(ke_link(&up), ke_link(&down));
        let other = link(
            zid,
            Some(Locator::try_from("udp/224.0.0.224:7447").unwrap()),
        );
        assert_ne!(ke_link(&up), ke_link(&other));
    }
}

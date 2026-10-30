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
// src/api/admin.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2). The session's own part of
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
        sample::{Locality, Sample, SampleKind},
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

/// Apply a put or a delete under `@/<zid>/<whatami>/config/**` to the configuration of the
/// session, when the configuration grants the write permission (read at each write, as upstream
/// reads it, so a permission changed at run time reaches the next write). The zid and the role of
/// the key may be wildcards: the key is the session's when it intersects its own config space,
/// and the path it writes is what follows `config/`. A value that is an array item by id is
/// inserted as one (`zenoh/src/net/runtime/adminspace.rs` @ `try_insert_json5_array_item`).
fn on_config_write(session: &WeakSession, own_config: &keyexpr, sample: Sample) {
    let config = session.config_notifier();
    if !config.lock().adminspace.permissions().write {
        tracing::error!(
            "Received PUT on '{}' but adminspace.permissions.write=false in configuration",
            sample.key_expr()
        );
        return;
    }
    let key_expr = sample.key_expr();
    if !own_config.intersects(key_expr) {
        return;
    }
    // `@/<zid>/<whatami>/config/<key>`: the path is what follows the fourth segment.
    let mut parts = key_expr.as_str().splitn(5, '/');
    let path = match (parts.next(), parts.nth(2), parts.next()) {
        (Some("@"), Some("config"), Some(path)) if !path.is_empty() => path,
        _ => {
            tracing::error!(
                "Failed to extract non-empty config key suffix from {}",
                key_expr
            );
            return;
        }
    };
    match sample.kind() {
        SampleKind::Put => match std::str::from_utf8(&sample.payload().to_bytes()) {
            Ok(json) => {
                tracing::trace!("Insert conf value {} : {}", key_expr, json);
                if let Err(e) = config
                    .try_insert_json5_array_item(path, json)
                    .and_then(|applied| {
                        if applied {
                            Ok(())
                        } else {
                            config.insert_json5(path, json)
                        }
                    })
                {
                    tracing::error!("Error inserting conf value {} : {} - {}", key_expr, json, e);
                }
            }
            Err(e) => tracing::error!("Received non utf8 conf value on {} : {}", key_expr, e),
        },
        SampleKind::Delete => {
            tracing::trace!("Deleting conf value {}", key_expr);
            if let Err(e) = config
                .try_remove_json5_array_item(path)
                .and_then(|applied| if applied { Ok(()) } else { config.remove(path) })
            {
                tracing::error!("Error deleting conf value {} : {}", key_expr, e);
            }
        }
    }
}

pub(crate) fn init(session: WeakSession) {
    // The configuration is written through the admin space, when the node serves one.
    let config = session.config_notifier();
    let (admin_enabled, whatami) = {
        let config = config.lock();
        (*config.adminspace.enabled(), config.mode())
    };
    if admin_enabled {
        let own_zid = session.zid().into_keyexpr();
        let own_config: OwnedKeyExpr = format!("@/{own_zid}/{whatami}/config/**")
            .try_into()
            .expect("the config space of a node is a key");
        let subscribed = session.declare_subscriber_inner(
            &KeyExpr::from(own_config.clone()),
            Locality::Any,
            Callback::from({
                let session = session.clone();
                move |sample: Sample| on_config_write(&session, &own_config, sample)
            }),
            None,
        );
        if let Err(e) = subscribed {
            tracing::error!("Unable to serve the config space of the admin space: {}", e);
        }
    }

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

    // The graph of each region the node holds, `@/<own_zid>/<whatami>/linkstate/<region>`
    // (`zenoh/src/net/runtime/adminspace.rs` @ `add_handler!("linkstate", "*", linkstate_data);`),
    // served by a node that runs the runtime's admin space.
    if admin_enabled {
        let own_zid = session.zid().into_keyexpr();
        let prefix: OwnedKeyExpr = format!("@/{own_zid}/{whatami}/linkstate")
            .try_into()
            .expect("the linkstate space of a node is a key");
        let linkstate = session.declare_queryable_inner(
            &KeyExpr::from(&prefix / KE_STARSTAR),
            true,
            Locality::SessionLocal,
            Callback::from({
                let session = session.clone();
                move |query| on_linkstate_query(&session, &prefix, query)
            }),
            None,
        );
        if let Err(e) = linkstate {
            tracing::error!(
                "Unable to serve the linkstate space of the admin space: {}",
                e
            );
        }
        // A router node answers the rest of the runtime's admin space too.
        #[cfg(feature = "engine-tokio")]
        host_router_admin(&session);
    }

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

/// Host the admin space a router node answers on `@/<own_zid>/router/**`: the root with the
/// sessions and locators it holds, its configuration and metrics, what the faces declared by kind,
/// and the successor routes of its graph (`zenoh/src/net/runtime/adminspace.rs` @
/// `add_handler!(local_data);`). The answers are the library's, the ones the demo's router host
/// gives, built per query from views of the router's tables, so an entity declared a moment ago is
/// listed and one undeclared is not. The `linkstate` space has its own queryable, by region.
#[cfg(feature = "engine-tokio")]
fn host_router_admin(session: &WeakSession) {
    use wz_runtime_tokio::adminspace::{
        admin_queryable_key, answer_admin_query, answer_router_admin_query, AdminAnswerCtx,
        AdminAnswerOutcome, AdminDeclaration, AdminEntityKind, AdminPlugin, AdminRouterCtx,
    };
    use wz_session_core::query_sink::{QueryView, ReplyOut};

    let Some(views) = session.router_admin_views() else {
        return;
    };
    let zid_hex = session.zid().to_string();
    let whatami = WhatAmI::Router.to_str();
    let key = admin_queryable_key(&zid_hex, whatami);
    let config = session.config_notifier();
    let version = env!("CARGO_PKG_VERSION").to_owned();
    let handler = move |view: &dyn QueryView, out: &mut dyn ReplyOut| {
        let (read, config_json, metadata_json) = {
            let config = config.lock();
            (
                config.adminspace.permissions().read,
                config.get_json("").unwrap_or_else(|_| "{}".to_owned()),
                config
                    .get_json("metadata")
                    .unwrap_or_else(|_| "null".to_owned()),
            )
        };
        let ctx = AdminAnswerCtx {
            zid_hex: &zid_hex,
            whatami,
            version: &version,
            locators: &views.locators,
            metadata_json: &metadata_json,
            read,
            stats: None,
            multicast_peers: &[],
        };
        let kinds = [
            (
                AdminEntityKind::Subscriber,
                views.declarations.subscribers(),
            ),
            (AdminEntityKind::Publisher, views.declarations.publishers()),
            (AdminEntityKind::Queryable, views.declarations.queryables()),
            (AdminEntityKind::Querier, views.declarations.queriers()),
            (AdminEntityKind::Token, views.declarations.tokens()),
        ];
        let declarations: Vec<AdminDeclaration> = kinds
            .into_iter()
            .flat_map(|(kind, entries)| {
                entries
                    .into_iter()
                    .map(move |(keyexpr, sources)| AdminDeclaration {
                        kind,
                        keyexpr,
                        sources,
                    })
            })
            .collect();
        let plugins: Vec<AdminPlugin> = Vec::new();
        let sessions = views.sessions.admin_sessions();
        if answer_admin_query(
            view,
            out,
            &ctx,
            &sessions,
            &declarations,
            &plugins,
            &config_json,
        ) == AdminAnswerOutcome::DeniedRead
        {
            tracing::error!(
                "{}",
                wz_runtime_tokio::adminspace::denied_read_diagnostic(view.keyexpr())
            );
        }
        let successors = views.routers.route_successors_hex();
        let routes = AdminRouterCtx {
            zid_hex: &zid_hex,
            whatami,
            routers_dot: None,
            peers_dot: None,
            successors: &successors,
            read,
        };
        let _ = answer_router_admin_query(view, out, &routes);
    };
    if !session.host_router_queryable(&key, Box::new(handler)) {
        tracing::error!("Unable to serve the admin space of the router node");
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

/// Answer a query on the `linkstate` space: one reply for each region whose key the query
/// intersects, with the graph of that region as text
/// (`zenoh/src/net/runtime/adminspace.rs` @ `fn linkstate_data`).
fn on_linkstate_query(session: &WeakSession, prefix: &keyexpr, query: Query) {
    for (region, graph) in session.linkstate_regions() {
        let Ok(region) = keyexpr::new(region.as_str()) else {
            continue;
        };
        let reply_key = prefix / region;
        if query.key_expr().intersects(&reply_key) {
            if let Err(e) = query
                .reply(reply_key, graph)
                .encoding(Encoding::TEXT_PLAIN)
                .wait()
            {
                tracing::error!("Error sending AdminSpace reply: {:?}", e);
            }
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

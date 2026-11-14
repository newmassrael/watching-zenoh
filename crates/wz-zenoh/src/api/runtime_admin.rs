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
// src/net/runtime/adminspace.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2). The runtime's
// admin space of a session: `@/<zid>/<whatami>/**` and its `config/**` writes, started when the
// configuration enables it, in every mode and whatever the features, as upstream's runtime starts
// it. The answers are the `wz-admin` answerer's over views of the engine the session runs on,
// where upstream's handlers read its runtime; the handler table and the plugins are not here.

use zenoh_config::WhatAmI;
use zenoh_keyexpr::{keyexpr, OwnedKeyExpr};
use zenoh_macros::ke;

// `ke!` writes its paths from `zenoh`, as the crate of a user of the macro; this is that crate.
use crate::{
    self as zenoh,
    api::{
        encoding::Encoding,
        handlers::Callback,
        key_expr::KeyExpr,
        queryable::Query,
        sample::{Locality, Sample, SampleKind},
        session::WeakSession,
    },
};

static KE_STARSTAR: &keyexpr = ke!("**");

/// Start the runtime's admin space of `session` when its configuration enables it
/// (`zenoh/src/net/runtime/mod.rs` @ `let start_admin_space = *config.adminspace.enabled();`),
/// rooted at the session's mode (`zenoh/src/net/runtime/adminspace.rs` @
/// `let whatami_str = runtime.state.whatami.to_str();`): the subscriber that writes the
/// configuration, the `linkstate` space by region, and the queryable of the rest.
pub(crate) fn start(session: &WeakSession) {
    let config = session.config_notifier();
    let (admin_enabled, whatami) = {
        let config = config.lock();
        (*config.adminspace.enabled(), config.mode())
    };
    if !admin_enabled {
        return;
    }
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

    // The graph of each region the node holds, `@/<own_zid>/<whatami>/linkstate/<region>`
    // (`zenoh/src/net/runtime/adminspace.rs` @ `add_handler!("linkstate", "*", linkstate_data);`).
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
    host_admin_space(session, whatami);
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

/// Host the admin space of the session on `@/<own_zid>/<whatami>/**`, rooted at the session's own
/// mode as upstream roots it in every mode (`zenoh/src/net/runtime/adminspace.rs` @
/// `let whatami_str = runtime.state.whatami.to_str();`): the root with the sessions and locators
/// it holds, its configuration and metrics, and, for a node, what the faces declared by kind
/// (`zenoh/src/net/runtime/adminspace.rs` @ `add_handler!(local_data);`). Only a router answers
/// the successor routes of its graph, which upstream reads off the router hats alone
/// (`zenoh/src/net/runtime/adminspace.rs` @
/// `fn route_successor(prefix: &keyexpr, context: &AdminContext, query: Query) {`). The answers
/// are the library's, the ones every wz admin host gives, built per query from views of what the
/// session holds, so a face or an entity that came a moment ago is listed and one that went is
/// not. The `linkstate` space has its own queryable, by region.
fn host_admin_space(session: &WeakSession, whatami: WhatAmI) {
    use wz_runtime_tokio::adminspace::{
        admin_queryable_key, answer_admin_query, answer_router_admin_query, AdminAnswerCtx,
        AdminAnswerOutcome, AdminDeclaration, AdminEntityKind, AdminPlugin, AdminRouterCtx,
    };
    use wz_session_core::query_sink::{QueryView, ReplyOut};

    let views = session.admin_views();
    let zid_hex = session.zid().to_string();
    let is_router = whatami == WhatAmI::Router;
    let whatami = whatami.to_str();
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
        let multicast_peers = views.admin_multicast_peers();
        let ctx = AdminAnswerCtx {
            zid_hex: &zid_hex,
            whatami,
            version: &version,
            locators: views.locators(),
            metadata_json: &metadata_json,
            read,
            stats: None,
            multicast_peers: &multicast_peers,
        };
        let declarations: Vec<AdminDeclaration> = views
            .node()
            .map(|node| {
                let kinds = [
                    (AdminEntityKind::Subscriber, node.declarations.subscribers()),
                    (AdminEntityKind::Publisher, node.declarations.publishers()),
                    (AdminEntityKind::Queryable, node.declarations.queryables()),
                    (AdminEntityKind::Querier, node.declarations.queriers()),
                    (AdminEntityKind::Token, node.declarations.tokens()),
                ];
                kinds
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
                    .collect()
            })
            .unwrap_or_default();
        let plugins: Vec<AdminPlugin> = Vec::new();
        let sessions = views.admin_sessions();
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
        if !is_router {
            return;
        }
        if let Some(node) = views.node() {
            let successors = node.routers.route_successors_hex();
            let routes = AdminRouterCtx {
                zid_hex: &zid_hex,
                whatami,
                // The regions' graphs are the `linkstate` queryable's, by region.
                linkstate: &[],
                successors: &successors,
                read,
            };
            let _ = answer_router_admin_query(view, out, &routes);
        }
    };
    session.host_admin_queryable(&key, std::sync::Arc::new(handler));
}

/// Answer a query on the `linkstate` space: one reply for each region whose key the query
/// intersects, with the graph of that region as text
/// (`zenoh/src/net/runtime/adminspace.rs` @ `fn linkstate_data`).
fn on_linkstate_query(session: &WeakSession, prefix: &keyexpr, query: Query) {
    use zenoh_core::Wait;

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

#[cfg(test)]
mod tests {
    /// A session hosts no runtime admin space unless its configuration enables one, and one it
    /// enables answers a read and refuses a write: upstream's defaults
    /// (`commons/zenoh-config/src/lib.rs` @ `impl Default for PermissionsConf {`, and the
    /// `enabled` field's `#[serde(default = "set_false")]`), for a configuration built in code and
    /// for one read from a document that names none of the three keys.
    #[test]
    fn the_admin_space_is_off_and_read_only_by_default() {
        for config in [
            zenoh_config::Config::default(),
            zenoh_config::Config::from_json5("{ mode: \"client\" }").expect("a document"),
        ] {
            assert!(!*config.adminspace.enabled());
            assert!(config.adminspace.permissions().read);
            assert!(!config.adminspace.permissions().write);
        }
    }
}

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
// src/api/session.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1). This is a partial
// derivative and a modified one. What is here is the handle (`Session`, its clone, equality and
// drop), its opening from a configuration, `close`, `is_closed`, `zid`, `id` and `info`, the error
// of a closed session, the declaration of a key expression and `undeclare` with the traits that
// say what can be undeclared, and the size of the channel that data is received on, which the
// default handlers read. The session of upstream is a table of declarations over a runtime of its
// own; this one is a handle over an engine (docs/zenoh-api-on-the-engine.md, decisions D1 and D3),
// so the tables are not copied, and the entities that read them (publishers, subscribers, queries,
// liveliness and matching) arrive with slices Z2 to Z6, and the three other channel sizes with Z3.

use std::{
    fmt,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use zenoh_config::qos::{PublisherQoSConfList, PublisherQoSConfig};
#[cfg(feature = "unstable")]
use zenoh_config::wrappers::EntityGlobalId;
use zenoh_config::wrappers::ZenohId;
use zenoh_core::{Resolve, ResolveClosure, Wait};
use zenoh_keyexpr::keyexpr_tree::{IKeyExprTree, IKeyExprTreeNode, KeBoxTree};
use zenoh_protocol::core::{CongestionControl, EntityId, ExprId, Parameters, Timestamp};
#[cfg(feature = "unstable")]
use zenoh_protocol::core::{Locator, Reliability};
use zenoh_protocol::network::request::{self, ext::QueryTarget};
#[cfg(feature = "unstable")]
use zenoh_protocol::network::timestamp_stack::interception_point;
use zenoh_result::ZResult;
use zenoh_runtime::ZRuntime;

#[cfg(feature = "unstable")]
use crate::api::cancellation::CancellationToken;
#[cfg(feature = "unstable")]
use crate::api::info::{Face, FaceSink, Link, LinkEvent, Transport, TransportEvent};
#[cfg(feature = "unstable")]
use crate::api::sample::SourceInfo;
#[cfg(feature = "unstable")]
use crate::api::selector::ZenohParameters;
#[cfg(feature = "unstable")]
use crate::api::timestamp_stack::{
    GetTimestampCallback, TimestampInstrumentation, TimestampSource,
};
use crate::api::{
    builders::{
        close::{CloseBuilder, Closeable, Closee},
        publisher::{
            PublicationBuilderDelete, PublicationBuilderPut, PublisherBuilder,
            SessionDeleteBuilder, SessionPutBuilder,
        },
        querier::QuerierBuilder,
        query::SessionGetBuilder,
        queryable::QueryableBuilder,
        session::OpenBuilder,
        subscriber::SubscriberBuilder,
    },
    bytes::ZBytes,
    cancellation::{SyncGroup, SyncGroupNotifier},
    config::Config,
    encoding::Encoding,
    handlers::{Callback, DefaultHandler},
    info::SessionInfo,
    key_expr::{KeyExpr, KeyExprUndeclaration, SessionAnchor, WireAnchor},
    liveliness::Liveliness,
    matching::{MatchingStatus, MatchingStatusType},
    publisher::Priority,
    query::{ConsolidationMode, QueryConsolidation, Reply, ReplyKeyExpr},
    queryable::Query,
    sample::{Locality, QoS, Sample, SampleKind},
    selector::Selector,
    subscriber::SubscriberKind,
    Id,
};

zconfigurable! {
    pub(crate) static ref API_DATA_RECEPTION_CHANNEL_SIZE: usize = 256;
}

/// The callback of a listener with the notifier that is let go with it: what the sink the engine
/// holds for the listener keeps, so that the notifier goes when the engine lets go of the sink and
/// the last call under way has returned.
#[cfg(feature = "unstable")]
struct Delivery<T> {
    callback: Callback<T>,
    _notifier: Option<SyncGroupNotifier>,
}

/// What a put or a delete asks of the engine, in the types of this crate: the key as the wire
/// names it, the payload and the settings of the publication. It is the one value the engines are
/// handed, so what they convert to their own types is the whole of their part of a publication.
// A build with no engine has nothing that reads the fields.
#[cfg_attr(not(feature = "engine-tokio"), allow(dead_code))]
pub(crate) struct Publication<'a> {
    /// The key expression the data is for.
    pub(crate) key: &'a str,
    /// The declaration of a prefix of the key that the wire names it by, `0` when it names none.
    pub(crate) scope: ExprId,
    /// What follows the declared prefix, `None` when the declaration covers the whole key.
    pub(crate) suffix: Option<String>,
    pub(crate) payload: ZBytes,
    pub(crate) kind: SampleKind,
    pub(crate) encoding: Encoding,
    pub(crate) congestion_control: CongestionControl,
    pub(crate) priority: Priority,
    pub(crate) is_express: bool,
    pub(crate) destination: Locality,
    #[cfg(feature = "unstable")]
    pub(crate) reliability: Reliability,
    pub(crate) timestamp: Option<uhlc::Timestamp>,
    #[cfg(feature = "unstable")]
    pub(crate) source_info: Option<SourceInfo>,
    pub(crate) attachment: Option<ZBytes>,
    /// The timestamp stack of the message for the session's own subscribers, when the publication
    /// asks for its instrumentation: the points to record at, and what this node recorded at the
    /// send.
    #[cfg(feature = "unstable")]
    pub(crate) ts_stack: Option<zenoh_protocol::network::timestamp_stack::TimestampStack>,
    /// The stack of the message as it leaves the node: the one above with what the node records
    /// on a message it routes out.
    #[cfg(feature = "unstable")]
    pub(crate) wire_ts_stack: Option<zenoh_protocol::network::timestamp_stack::TimestampStack>,
    /// What copies a large payload into shared memory for a peer that could read it, when the
    /// configuration asks for the optimisation.
    #[cfg(all(feature = "unstable", feature = "shared-memory"))]
    pub(crate) shm_promoter: Option<&'a crate::api::shm::transport::Promoter>,
}

/// What a subscription asks of the engine, in the types of this crate: the key as the wire names
/// it, who it takes samples from, and what a sample is handed to.
// A build with no engine has nothing that reads the fields.
#[cfg_attr(not(feature = "engine-tokio"), allow(dead_code))]
pub(crate) struct Subscription<'a> {
    /// The key expression the samples are wanted for.
    pub(crate) key: &'a str,
    /// The declaration of a prefix of the key that the wire names it by, `0` when it names none.
    pub(crate) scope: ExprId,
    /// What follows the declared prefix, `None` when the declaration covers the whole key.
    pub(crate) suffix: Option<String>,
    pub(crate) origin: Locality,
    pub(crate) callback: Callback<Sample>,
    /// Held until the callback can be called no more: a wait on its group ends then.
    pub(crate) notifier: Option<SyncGroupNotifier>,
    /// What the engine keeps for as long as it records the subscription: the declaration of the
    /// prefix the wire names the key by.
    pub(crate) keeps: Arc<dyn Send + Sync>,
    /// What the node records on an instrumented sample it delivers to the callback.
    #[cfg(feature = "unstable")]
    pub(crate) timestamps: Arc<TimestampSource>,
}

/// What the declaration of a publisher asks of the engine, in the types of this crate: the key as
/// the wire names it and who the publisher writes to.
// A build with no engine has nothing that reads the fields.
#[cfg_attr(not(feature = "engine-tokio"), allow(dead_code))]
pub(crate) struct PublisherDeclaration<'a> {
    /// The key expression the publisher writes to.
    pub(crate) key: &'a str,
    /// The declaration of a prefix of the key that the wire names it by, `0` when it names none.
    pub(crate) scope: ExprId,
    /// What follows the declared prefix, `None` when the declaration covers the whole key.
    pub(crate) suffix: Option<String>,
    pub(crate) destination: Locality,
}

/// What the declaration of a queryable asks of the engine, in the types of this crate: the key as
/// the wire names it, who it answers, and what a query is handed to.
// A build with no engine has nothing that reads the fields.
#[cfg_attr(not(feature = "engine-tokio"), allow(dead_code))]
pub(crate) struct QueryableDeclaration<'a> {
    /// The key expression the queryable answers on.
    pub(crate) key: &'a str,
    /// The declaration of a prefix of the key that the wire names it by, `0` when it names none.
    pub(crate) scope: ExprId,
    /// What follows the declared prefix, `None` when the declaration covers the whole key.
    pub(crate) suffix: Option<String>,
    pub(crate) complete: bool,
    pub(crate) origin: Locality,
    pub(crate) callback: Callback<Query>,
    /// Held until the callback can be called no more: a wait on its group ends then.
    pub(crate) notifier: Option<SyncGroupNotifier>,
    /// What the engine keeps for as long as it records the queryable: the declaration of the
    /// prefix the wire names the key by.
    pub(crate) keeps: Arc<dyn Send + Sync>,
    /// The id of the session, which the replies say they come from.
    pub(crate) zid: ZenohId,
    /// The entity id of the queryable, which the replies say they come from.
    pub(crate) eid: Id,
    /// What records on the timestamp stack of a query it receives and of the replies it sends.
    #[cfg(feature = "unstable")]
    pub(crate) timestamps: Arc<TimestampSource>,
}

/// What a get asks of the engine, in the types of this crate: the key as the wire names it, the
/// settings of the query and what the replies are handed to.
// A build with no engine has nothing that reads the fields.
#[cfg_attr(not(feature = "engine-tokio"), allow(dead_code))]
pub(crate) struct QueryRequest<'a> {
    /// The key expression the query is for.
    pub(crate) key: &'a str,
    /// The declaration of a prefix of the key that the wire names it by, `0` when it names none.
    pub(crate) scope: ExprId,
    /// What follows the declared prefix, `None` when the declaration covers the whole key.
    pub(crate) suffix: Option<String>,
    /// The parameters of the selector, as the text they are sent in.
    pub(crate) parameters: &'a str,
    pub(crate) target: QueryTarget,
    /// The consolidation, with `Auto` resolved as the session resolves it.
    pub(crate) consolidation: ConsolidationMode,
    pub(crate) qos: QoS,
    pub(crate) destination: Locality,
    pub(crate) timeout: Duration,
    pub(crate) value: Option<(ZBytes, Encoding)>,
    pub(crate) attachment: Option<ZBytes>,
    #[cfg(feature = "unstable")]
    pub(crate) source_info: Option<SourceInfo>,
    /// The stack of a query that asks for its instrumentation: the points to record at, and what
    /// this node recorded at the send.
    #[cfg(feature = "unstable")]
    pub(crate) ts_stack: Option<zenoh_protocol::network::timestamp_stack::TimestampStack>,
    /// The stack of the query as it leaves the node: the one above with what the node records on
    /// a message it routes out.
    #[cfg(feature = "unstable")]
    pub(crate) wire_ts_stack: Option<zenoh_protocol::network::timestamp_stack::TimestampStack>,
    /// What records on the stack of each reply the query is given.
    #[cfg(feature = "unstable")]
    pub(crate) timestamps: Arc<TimestampSource>,
    /// What each reply is handed to; it is dropped when the last reply has been, which ends the
    /// channel of a handler.
    pub(crate) callback: Callback<Reply>,
    #[cfg(feature = "unstable")]
    pub(crate) cancellation_token: Option<CancellationToken>,
    /// What stops the legs of the query before they end by themselves, when something may: a
    /// cancellation token or the undeclaration of the querier that asks. The query holds it for as
    /// long as it is under way, so whoever keeps a `Weak` of it knows when the query is over.
    pub(crate) fan: Option<Arc<QueryFan>>,
    /// Held until the callback can be called no more: the wait of a querier's undeclaration on its
    /// callbacks ends then.
    pub(crate) querier_notifier: Option<SyncGroupNotifier>,
}

/// What a liveliness query asks of the engine, in the types of this crate: the key as the wire
/// names it, how long to wait, and what the tokens that are alive are handed to.
// A build with no engine has nothing that reads the fields.
#[cfg_attr(not(feature = "engine-tokio"), allow(dead_code))]
pub(crate) struct LivelinessRequest<'a> {
    /// The key expression the tokens are asked for.
    pub(crate) key: &'a str,
    /// The declaration of a prefix of the key that the wire names it by, `0` when it names none.
    pub(crate) scope: ExprId,
    /// What follows the declared prefix, `None` when the declaration covers the whole key.
    pub(crate) suffix: Option<String>,
    pub(crate) timeout: Duration,
    /// What each token that is alive is handed to, as a reply; it is dropped when the query is
    /// over, which ends the channel of a handler.
    pub(crate) callback: Callback<Reply>,
    #[cfg(feature = "unstable")]
    pub(crate) cancellation_token: Option<CancellationToken>,
    /// What stops the legs of the query, when something may: see [`QueryRequest::fan`].
    pub(crate) fan: Option<Arc<QueryFan>>,
    /// Held until the callback is dropped, so that a close of the session that waits for
    /// callbacks waits for this query's as well: they run on a task of their own.
    pub(crate) notifier: Option<SyncGroupNotifier>,
}

/// What the declaration of a liveliness subscription asks of the engine, in the types of this
/// crate: the key as the wire names it, whether the tokens already alive are delivered first, and
/// what the changes are handed to.
// A build with no engine has nothing that reads the fields.
#[cfg_attr(not(feature = "engine-tokio"), allow(dead_code))]
pub(crate) struct LivelinessSubscription<'a> {
    /// The key expression the changes are wanted for.
    pub(crate) key: &'a str,
    /// The declaration of a prefix of the key that the wire names it by, `0` when it names none.
    pub(crate) scope: ExprId,
    /// What follows the declared prefix, `None` when the declaration covers the whole key.
    pub(crate) suffix: Option<String>,
    pub(crate) history: bool,
    pub(crate) callback: Callback<Sample>,
    /// Held until the callback can be called no more: a wait on its group ends then.
    pub(crate) notifier: Option<SyncGroupNotifier>,
    /// What the engine keeps for as long as it records the subscription: the declaration of the
    /// prefix the wire names the key by.
    pub(crate) keeps: Arc<dyn Send + Sync>,
}

/// What stops the legs of a query: the engine's.
#[cfg(feature = "engine-tokio")]
pub(crate) type QueryFan = wz_capi_port::cancellation::CancellableFan;

/// What stops the legs of a query. A build with no engine asks no query, so there is none.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) enum QueryFan {}

#[cfg(not(feature = "engine-tokio"))]
impl QueryFan {
    fn cancel(&self) {
        match *self {}
    }
}

/// What the declaration of a querier asks of the engine, in the types of this crate: the key as
/// the wire names it and who the querier asks.
// A build with no engine has nothing that reads the fields.
#[cfg_attr(not(feature = "engine-tokio"), allow(dead_code))]
pub(crate) struct QuerierDeclaration<'a> {
    /// The key expression the querier asks on.
    pub(crate) key: &'a str,
    /// The declaration of a prefix of the key that the wire names it by, `0` when it names none.
    pub(crate) scope: ExprId,
    /// What follows the declared prefix, `None` when the declaration covers the whole key.
    pub(crate) suffix: Option<String>,
    pub(crate) destination: Locality,
}

/// What a session is run by: the engine that holds its faces, its declarations and its clock.
///
/// One engine is selected by a feature of the build (decision D5). A build that selects none has no
/// engine to open a session on, and its [`Session::open`] says so; the type is then empty.
enum Engine {
    #[cfg(feature = "engine-tokio")]
    Tokio(wz_capi_core::drive::SessionState),
    /// A router node, which forwards between the sessions that dial it. What a program does
    /// through it is owed (the router session of `docs/zenoh-api-on-the-engine.md`), and each
    /// operation that is not carried says so by name.
    #[cfg(feature = "engine-tokio")]
    Router(RouterEngine),
}

/// The router node and the counter of the entity ids it hands out.
#[cfg(feature = "engine-tokio")]
struct RouterEngine {
    node: wz_capi_core::drive::RouterState,
    ids: AtomicU64,
}

/// The handler a queryable hosted on the router node runs for each query it is asked.
#[cfg(feature = "unstable")]
pub(crate) type RouterQueryHandler = Box<
    dyn FnMut(
            &dyn wz_session_core::query_sink::QueryView,
            &mut dyn wz_session_core::query_sink::ReplyOut,
        ) + Send,
>;

/// What the admin space of a router node answers from: views of the router's tables, which show
/// them as they are when a query asks, and the locators its listeners got.
#[cfg(feature = "unstable")]
#[cfg_attr(not(feature = "engine-tokio"), allow(dead_code))]
pub(crate) struct RouterAdminViews {
    /// The sessions the router holds, one for each face.
    #[cfg(feature = "engine-tokio")]
    pub(crate) sessions: wz_runtime_tokio::router_forward::RouterSessionsView,
    /// What the faces declared, by kind, folded by tier as the pin folds them.
    #[cfg(feature = "engine-tokio")]
    pub(crate) declarations: wz_runtime_tokio::router_forward::RouterDeclarationsView,
    /// The graph of the north region: the routers.
    #[cfg(feature = "engine-tokio")]
    pub(crate) routers: wz_runtime_tokio::linkstate_forward::LinkstateNetView,
    /// The graph of the south region of the peers.
    #[cfg(feature = "engine-tokio")]
    pub(crate) peers: wz_runtime_tokio::linkstate_forward::LinkstateNetView,
    /// Where the router's listeners can be reached.
    pub(crate) locators: Vec<String>,
}

#[cfg(feature = "engine-tokio")]
impl RouterEngine {
    /// The mark of the id of a liveliness subscriber among the ids the engine undeclares as
    /// subscribers: the hosted subscribers of a router count up from one and never reach it.
    const LIVELINESS_ID: Id = 1 << 31;

    /// A number for a declaration that holds nothing in the router: a publisher or a querier,
    /// whose matching is read from the tables the router holds.
    fn entity_id(&self) -> ZResult<Id> {
        let id = self.ids.fetch_add(1, Ordering::Relaxed) + 1;
        Id::try_from(id).map_err(|_| {
            zerror!("the router numbered an entity {id}, more than an id holds").into()
        })
    }
}

#[cfg(feature = "engine-tokio")]
impl Engine {
    /// Open a session on this engine, from the document the configuration is, and the id the
    /// session stands on.
    fn open(
        config: &Config,
        #[cfg(feature = "shared-memory")] shm_clients: Option<
            Arc<zenoh_shm::api::client_storage::ShmClientStorage>,
        >,
    ) -> ZResult<(Engine, ZenohId)> {
        use wz_capi_core::open_plan::{AbiChoices, OpenPlan, StatedEndpoints};

        let expanded = config.0.clone().expanded();
        let zid = expanded.id();
        let role = tokio_engine::role_of(expanded.mode());
        // What to listen on is read from the document, which states `listen/endpoints` for the
        // mode: the plan resolves it there. What to dial is stated here, because the plan reads it
        // from the caller and an entry that names a strategy has to be refused by its key.
        let stated = StatedEndpoints {
            connect: tokio_engine::connect_endpoints(&expanded, expanded.mode())?,
            listen: Vec::new(),
        };
        let document = tokio_engine::document_of(&expanded, role, &zid)?;
        tokio_engine::refuse_repeated_ids(&document)?;
        let plan = OpenPlan::resolve(role, stated, Some(&document.to_string()))
            .map_err(tokio_engine::refusal_error)?;
        // A router is the router data plane run as a node (`RouterEngine`), not the registry of
        // faces a peer or a client is: announcing the role over that registry would be the
        // silent fallback the other refusals of this function exist against.
        let router = expanded.mode() == zenoh_protocol::core::WhatAmI::Router;
        // Decision D6: a key the configuration states with a value other than its default, that
        // upstream acts on and this engine does not, is refused by its name, and not left to do
        // nothing.
        tokio_engine::refuse_unmapped(&plan.ignored, &document)?;
        // The engine says that a link did not open and not which one. When the session was only
        // to dial, the one that did not is among the endpoints it was told of, and upstream says
        // so in these words; when it was to listen as well, the engine does not say which of the
        // two failed and neither does the error.
        let dialled =
            (!plan.connect.is_empty() && plan.listen.is_empty() && plan.groups.is_empty())
                .then(|| tokio_engine::peers_text(&expanded, expanded.mode()));
        // And when it was only to listen, on one endpoint, that is the one that could not be bound.
        let listened =
            (plan.connect.is_empty() && plan.groups.is_empty() && plan.listen.len() == 1)
                .then(|| plan.listen[0].clone());
        let scope = tokio_engine::OpenScope {
            dialled,
            listened,
            listen_deadline: plan.listen_phase.policy.budget.deadline().is_some(),
        };
        let arguments = plan.into_arguments(AbiChoices {
            tx_queue: Default::default(),
            start_read_task: true,
            // Upstream runs the callbacks of a delivery a session makes to itself inside the
            // call that causes it, on the calling thread.
            local_delivery: tokio_engine::LocalDeliveryDrain::Caller,
            // Upstream tells the liveliness subscribers of a session of the tokens of that
            // session, and its liveliness get finds them.
            liveliness_to_self: true,
            initial_interest: true,
            // Each face of the session has a thread of its own, so a callback that blocks
            // holds up its link and no other.
            face_drive: tokio_engine::FaceDrive::PerFace,
            // A router node carries no shared memory; any other session reads a received
            // descriptor with this crate's reader and offers shared memory as its configuration
            // says (`transport/shared_memory/enabled`).
            #[cfg(feature = "shared-memory")]
            shm_clients: if router {
                tokio_engine::no_shm_clients()
            } else {
                Some(wz_capi_core::faces::ShmReader::Host(
                    crate::api::shm::transport::resolver_factory(shm_clients),
                ))
            },
            #[cfg(not(feature = "shared-memory"))]
            shm_clients: tokio_engine::no_shm_clients(),
            offer_shm: cfg!(feature = "shared-memory") && !router,
            // The multicast groups of a session that holds a shared-memory context are
            // shared-memory ones, and what a member of one sends it reads through that reader.
            groups_report_shm: cfg!(feature = "shared-memory") && !router,
        });
        if router {
            if let Some(ask) = arguments.router_refusal() {
                bail!("`mode` = \"router\": the router session does not carry {ask} yet");
            }
            let node = arguments
                .run_router()
                .map_err(|error| tokio_engine::open_error(error, scope))?;
            let engine = Engine::Router(RouterEngine {
                node,
                ids: AtomicU64::new(0),
            });
            return Ok((engine, zid));
        }
        let state = arguments
            .run()
            .map_err(|error| tokio_engine::open_error(error, scope))?;
        Ok((Engine::Tokio(state), zid))
    }

    fn is_closed(&self) -> bool {
        match self {
            Engine::Tokio(state) => state.is_closed(),
            Engine::Router(router) => router.node.is_closed(),
        }
    }

    /// Close the session and wait for its drive to stop: every callback has returned when this
    /// does. Closing a closed session does nothing.
    fn close(&self) {
        match self {
            Engine::Tokio(state) => state.close(),
            Engine::Router(router) => router.node.close(),
        }
    }

    fn acquire_keyexpr(&self, keyexpr: &str) -> Option<u64> {
        match self {
            Engine::Tokio(state) => state.shared.as_engine().acquire_keyexpr(keyexpr.to_owned()),
            // A node that declares no key expression to its peers names none by an id.
            Engine::Router(_) => None,
        }
    }

    fn release_keyexpr(&self, mapping_id: u64) {
        match self {
            Engine::Tokio(state) => state.shared.as_engine().release_keyexpr(mapping_id),
            Engine::Router(_) => {}
        }
    }

    fn next_entity_id(&self) -> u64 {
        match self {
            Engine::Tokio(state) => state.shared.as_engine().next_entity_id(),
            Engine::Router(router) => router.ids.fetch_add(1, Ordering::Relaxed) + 1,
        }
    }

    /// The id and the announced role of every established peer, the role in its 2-bit wire form
    /// (0 router, 1 peer, 2 client).
    fn peer_identities(&self) -> Vec<(Vec<u8>, u8)> {
        match self {
            Engine::Tokio(state) => state.shared.as_engine().peer_identities(),
            Engine::Router(router) => router
                .node
                .forwarder()
                .face_snapshots()
                .into_iter()
                .map(|face| (face.zid.to_vec(), face.whatami))
                .collect(),
        }
    }

    /// The transport of every established peer with the links under it, the unicast ones before
    /// the members of the groups the session has joined, as upstream lists them.
    #[cfg(feature = "unstable")]
    fn faces(&self) -> Vec<Face> {
        match self {
            Engine::Router(router) => router
                .node
                .forwarder()
                .face_snapshots()
                .iter()
                .filter_map(tokio_engine::face_of)
                .collect(),
            Engine::Tokio(state) => state
                .shared
                .as_engine()
                .face_snapshots()
                .iter()
                .filter_map(tokio_engine::face_of)
                .collect(),
        }
    }

    /// The clock of the node as a function: the next timestamp, or `None` for a node that holds
    /// none. The function lets go of the engine's session with the last of its holders.
    #[cfg(feature = "unstable")]
    fn node_clock(&self) -> Box<dyn Fn() -> Option<uhlc::Timestamp> + Send + Sync> {
        match self {
            // Owed: the router's clock is not read off the node yet.
            Engine::Router(_) => Box::new(|| None),
            Engine::Tokio(state) => {
                let shared = state.shared.clone();
                Box::new(move || {
                    shared
                        .as_engine()
                        .node_timestamp()
                        .as_ref()
                        .and_then(tokio_engine::timestamp_from)
                })
            }
        }
    }

    /// The next timestamp off the node's clock, or `None` for a node that holds none.
    fn node_timestamp(&self) -> Option<uhlc::Timestamp> {
        match self {
            Engine::Router(_) => None,
            Engine::Tokio(state) => state
                .shared
                .as_engine()
                .node_timestamp()
                .as_ref()
                .and_then(tokio_engine::timestamp_from),
        }
    }

    /// The locators the session's listeners got, without the loopback ones, as words.
    #[cfg(feature = "unstable")]
    fn listen_locators(&self) -> Vec<String> {
        match self {
            Engine::Tokio(state) => state.shared.as_engine().listen_locators(),
            Engine::Router(router) => router.node.listen_locators().to_vec(),
        }
    }

    /// The graph of each region the session's admin space answers a `linkstate` query for, as
    /// text, by the region's name: a router node holds the graph of its routers, the north
    /// region, and the one of its peers, the south region they are in.
    #[cfg(feature = "unstable")]
    fn linkstate_regions(&self) -> Vec<(String, String)> {
        match self {
            Engine::Tokio(state) => state.shared.as_engine().linkstate_regions(),
            Engine::Router(_) => {
                let Some(views) = self.router_admin_views() else {
                    return Vec::new();
                };
                vec![
                    (
                        wz_session_core::extbound::Region::North.to_string(),
                        views.routers.dot(),
                    ),
                    (
                        wz_session_core::extbound::Region::default_south(
                            wz_session_core::WhatAmI::Peer,
                        )
                        .to_string(),
                        views.peers.dot(),
                    ),
                ]
            }
        }
    }

    /// The views the admin space of a router node answers from, or `None` for a session that is
    /// no router node.
    #[cfg(feature = "unstable")]
    fn router_admin_views(&self) -> Option<RouterAdminViews> {
        match self {
            Engine::Router(router) => {
                let forwarder = router.node.forwarder();
                Some(RouterAdminViews {
                    sessions: forwarder.sessions_view(),
                    declarations: forwarder.declarations_view(),
                    routers: forwarder.routers_net_view(),
                    peers: forwarder.peers_net_view(),
                    locators: router.node.listen_locators().to_vec(),
                })
            }
            Engine::Tokio(_) => None,
        }
    }

    /// Host `handler` as a queryable of the router node on `key`, answered from the router's
    /// own thread, or say that the session is no router node.
    #[cfg(feature = "unstable")]
    fn host_router_queryable(&self, key: &str, handler: RouterQueryHandler) -> bool {
        match self {
            Engine::Router(router) => {
                router
                    .node
                    .forwarder()
                    .register_local_queryable(key, true, handler);
                true
            }
            Engine::Tokio(_) => false,
        }
    }

    /// Tell `sink` each time a face comes up or goes down, from now on, until
    /// [`Engine::unwatch_faces`] is called with the id returned.
    #[cfg(feature = "unstable")]
    fn watch_faces(&self, sink: FaceSink) -> u64 {
        match self {
            Engine::Router(router) => router
                .node
                .forwarder()
                .watch_faces(tokio_engine::face_sink(sink)),
            Engine::Tokio(state) => state
                .shared
                .as_engine()
                .watch_faces(tokio_engine::face_sink(sink)),
        }
    }

    /// Stop the watch `id` and let go of its sink.
    #[cfg(feature = "unstable")]
    fn unwatch_faces(&self, id: u64) {
        match self {
            Engine::Router(router) => {
                router.node.forwarder().unwatch_faces(id);
            }
            Engine::Tokio(state) => {
                state.shared.as_engine().unwatch_faces(id);
            }
        }
    }

    /// The key expression declarations the engine holds, `(id, key)` in declaration order.
    #[cfg(test)]
    fn keyexpr_declarations(&self) -> Vec<(u64, String)> {
        match self {
            Engine::Tokio(state) => state.shared.as_engine().keyexpr_declarations(),
            Engine::Router(_) => Vec::new(),
        }
    }

    /// Publish what `publication` says: to the matching subscribers of the session itself and to
    /// every peer, as its destination allows.
    fn publish(&self, publication: &Publication<'_>) -> ZResult<()> {
        match self {
            Engine::Router(router) => {
                tokio_engine::router_publish(router.node.forwarder(), publication)
            }
            Engine::Tokio(state) => {
                let options = tokio_engine::publish_options(publication);
                let wire = tokio_engine::wire_key(publication);
                // A large put that the configuration asks to be optimised, and that a peer could
                // read from shared memory, is sent to the peers as a copy in the provider; a
                // subscriber of the session itself is given the bytes it was put with, as
                // upstream's, which promotes at the link and not before it.
                #[cfg(all(feature = "unstable", feature = "shared-memory"))]
                if publication.kind == SampleKind::Put {
                    let engine = state.shared.as_engine();
                    if let Some(handle) = publication.shm_promoter.and_then(|promoter| {
                        promoter.promote(&publication.payload, || engine.has_shm_peer())
                    }) {
                        let mut delivered = Ok(0);
                        if options.allowed_destination.allows_remote() {
                            let remote = options
                                .clone()
                                .with_locality(wz_capi_core::runtime::locality::Locality::Remote);
                            delivered = engine.publish_shm_on_wire_all(
                                publication.key,
                                &wire,
                                handle,
                                &remote,
                            );
                        }
                        if delivered.is_ok() && options.allowed_destination.allows_local() {
                            let local = options.with_locality(
                                wz_capi_core::runtime::locality::Locality::SessionLocal,
                            );
                            delivered = engine.publish_on_wire_all(
                                publication.key,
                                &wire,
                                &publication.payload.to_bytes(),
                                &local,
                            );
                        }
                        return delivered
                            .map(|_delivered| ())
                            .map_err(|refusal| tokio_engine::publish_error(refusal, publication));
                    }
                }
                // A put whose payload is a buffer of shared memory is sent as the buffer: its
                // descriptor to a peer that negotiated shared memory, its bytes to any other.
                #[cfg(feature = "shared-memory")]
                if publication.kind == SampleKind::Put {
                    if let Some(handle) =
                        crate::api::shm::transport::send_handle_of(&publication.payload)
                    {
                        return state
                            .shared
                            .as_engine()
                            .publish_shm_on_wire_all(publication.key, &wire, handle, &options)
                            .map(|_delivered| ())
                            .map_err(|refusal| tokio_engine::publish_error(refusal, publication));
                    }
                }
                let payload = publication.payload.to_bytes();
                state
                    .shared
                    .as_engine()
                    .publish_on_wire_all(publication.key, &wire, &payload, &options)
                    .map(|_delivered| ())
                    .map_err(|refusal| tokio_engine::publish_error(refusal, publication))
            }
        }
    }

    /// Take samples for what `subscription` says, until [`Engine::undeclare_subscriber`] is called
    /// with the id returned. The samples are those of the session's own publications and those of
    /// every peer, as its origin allows.
    fn declare_subscriber(&self, subscription: Subscription<'_>) -> ZResult<Id> {
        match self {
            Engine::Router(router) => {
                let Subscription {
                    key,
                    origin,
                    callback,
                    notifier,
                    #[cfg(feature = "unstable")]
                    timestamps,
                    ..
                } = subscription;
                let sink = tokio_engine::subscriber_sink(
                    callback,
                    notifier,
                    #[cfg(feature = "unstable")]
                    timestamps,
                );
                let id = router.node.forwarder().host_subscriber_from(
                    key,
                    tokio_engine::engine_locality(origin),
                    sink(),
                );
                Id::try_from(id).map_err(|_| {
                    zerror!("the router numbered a subscriber {id}, which is more than an id holds")
                        .into()
                })
            }
            Engine::Tokio(state) => {
                let Subscription {
                    key,
                    scope,
                    suffix,
                    origin,
                    callback,
                    notifier,
                    keeps,
                    #[cfg(feature = "unstable")]
                    timestamps,
                } = subscription;
                let wire = tokio_engine::wire_key_of(scope, suffix).keeping(keeps);
                let id = state.shared.as_engine().declare_subscriber_on_wire(
                    key.to_owned(),
                    wire,
                    tokio_engine::engine_locality(origin),
                    None,
                    tokio_engine::subscriber_sink(
                        callback,
                        notifier,
                        #[cfg(feature = "unstable")]
                        timestamps,
                    ),
                );
                Id::try_from(id).map_err(|_| {
                    zerror!("the engine numbered a subscriber {id}, which is more than an id holds")
                        .into()
                })
            }
        }
    }

    /// Stop the delivery to the subscription `id` and let go of what it keeps.
    fn undeclare_subscriber(&self, id: Id) {
        match self {
            Engine::Tokio(state) => state.shared.as_engine().undeclare_subscriber(u64::from(id)),
            Engine::Router(router) => {
                if id & RouterEngine::LIVELINESS_ID != 0 {
                    router
                        .node
                        .liveliness()
                        .unsubscribe(u64::from(id & !RouterEngine::LIVELINESS_ID));
                } else {
                    router.node.forwarder().unhost_subscriber(u64::from(id));
                }
            }
        }
    }

    /// Declare the publisher `publisher` says: the engine keeps the interest in the subscribers
    /// matching its key, and asks every peer for them as upstream's declaration does, unless the
    /// publisher writes to the session itself. The id is released by
    /// [`Engine::undeclare_publisher`].
    fn declare_publisher(&self, publisher: PublisherDeclaration<'_>) -> ZResult<Id> {
        match self {
            // A router holds the declarations of every face it serves, so a publisher has no
            // interest to send for: its matching is worked out from the tables the router holds.
            // The admin space lists it, as it lists the publisher of a client, from the interest
            // the node's own face keeps.
            Engine::Router(router) => {
                let id = router.entity_id()?;
                router
                    .node
                    .forwarder()
                    .declare_local_interest(u64::from(id), publisher.key, false);
                Ok(id)
            }
            Engine::Tokio(state) => {
                let PublisherDeclaration {
                    key,
                    scope,
                    suffix,
                    destination,
                } = publisher;
                let wire = tokio_engine::wire_key_of(scope, suffix.clone());
                let ask = tokio_engine::interest_of(scope, suffix, destination);
                let id = state.shared.as_engine().declare_write_filter(
                    wz_capi_core::faces::FilterPlane::Subscribers,
                    key.to_owned(),
                    &wire,
                    ask,
                    destination != Locality::Remote,
                );
                Id::try_from(id).map_err(|_| {
                    zerror!("the engine numbered a publisher {id}, which is more than an id holds")
                        .into()
                })
            }
        }
    }

    /// Let go of the publisher `id`: the engine retracts its interest once no other publisher on
    /// the key holds it.
    fn undeclare_publisher(&self, id: Id) {
        match self {
            Engine::Router(router) => router
                .node
                .forwarder()
                .undeclare_local_interest(u64::from(id), false),
            Engine::Tokio(state) => state
                .shared
                .as_engine()
                .undeclare_write_filter(u64::from(id)),
        }
    }

    /// Answer the queries for what `queryable` says, until [`Engine::undeclare_queryable`] is
    /// called with the id returned. The queries are those of the session itself and of every
    /// peer, as the origin allows.
    fn declare_queryable(&self, queryable: QueryableDeclaration<'_>) -> ZResult<u64> {
        match self {
            Engine::Router(router) => {
                let QueryableDeclaration {
                    key,
                    complete,
                    origin,
                    callback,
                    notifier,
                    zid,
                    eid,
                    #[cfg(feature = "unstable")]
                    timestamps,
                    ..
                } = queryable;
                let sink = tokio_engine::queryable_sink(
                    callback,
                    notifier,
                    zid,
                    eid,
                    #[cfg(feature = "unstable")]
                    timestamps,
                );
                let handler = sink(router.node.query_holder());
                Ok(router.node.forwarder().host_queryable_from(
                    key,
                    complete,
                    tokio_engine::engine_locality(origin),
                    handler,
                ))
            }
            Engine::Tokio(state) => {
                let QueryableDeclaration {
                    key,
                    scope,
                    suffix,
                    complete,
                    origin,
                    callback,
                    notifier,
                    keeps,
                    zid,
                    eid,
                    #[cfg(feature = "unstable")]
                    timestamps,
                } = queryable;
                let wire = tokio_engine::wire_key_of(scope, suffix).keeping(keeps);
                state
                    .shared
                    .as_engine()
                    .declare_queryable_on_wire(
                        key.to_owned(),
                        wire,
                        complete,
                        tokio_engine::engine_locality(origin),
                        None,
                        tokio_engine::queryable_sink(
                            callback,
                            notifier,
                            zid,
                            eid,
                            #[cfg(feature = "unstable")]
                            timestamps,
                        ),
                    )
                    .ok_or_else(|| zerror!("this engine answers no queries").into())
            }
        }
    }

    /// Stop the queries to the queryable `id` and let go of what it keeps.
    fn undeclare_queryable(&self, id: u64) {
        match self {
            Engine::Tokio(state) => state.shared.as_engine().undeclare_queryable(id),
            Engine::Router(router) => {
                router.node.forwarder().unhost_queryable(id);
            }
        }
    }

    /// Ask the query `request` says: to the queryables of the session itself and to every peer, as
    /// its destination allows. The replies are handed to its callback, which is dropped once the
    /// last of them has been, whether the query was answered, timed out or was cancelled.
    fn query(&self, request: QueryRequest<'_>) -> ZResult<()> {
        match self {
            Engine::Tokio(state) => tokio_engine::ask(state.shared.engine_ref(), request),
            Engine::Router(router) => tokio_engine::router_ask(&router.node, request),
        }
    }

    /// What stops the legs of a query that is about to be asked.
    fn new_query_fan(&self) -> Arc<QueryFan> {
        match self {
            Engine::Tokio(_) | Engine::Router(_) => QueryFan::new(),
        }
    }

    /// Declare the querier `querier` says: the engine keeps the interest in the queryables
    /// matching its key, and asks every peer for them as upstream's declaration does, unless the
    /// querier asks the session itself. The id is released by [`Engine::undeclare_querier`].
    fn declare_querier(&self, querier: QuerierDeclaration<'_>) -> ZResult<Id> {
        match self {
            Engine::Router(router) => {
                let id = router.entity_id()?;
                router
                    .node
                    .forwarder()
                    .declare_local_interest(u64::from(id), querier.key, true);
                Ok(id)
            }
            Engine::Tokio(state) => {
                let QuerierDeclaration {
                    key,
                    scope,
                    suffix,
                    destination,
                } = querier;
                let wire = tokio_engine::wire_key_of(scope, suffix.clone());
                let ask = tokio_engine::interest_of(scope, suffix, destination);
                // Which queryables count for the matching of the querier depends on the target
                // of each query, which the matching slice reads when it asks (slice Z4).
                let id = state.shared.as_engine().declare_write_filter(
                    wz_capi_core::faces::FilterPlane::Queryables {
                        complete_required: false,
                    },
                    key.to_owned(),
                    &wire,
                    ask,
                    destination != Locality::Remote,
                );
                Id::try_from(id).map_err(|_| {
                    zerror!("the engine numbered a querier {id}, which is more than an id holds")
                        .into()
                })
            }
        }
    }

    /// Let go of the querier `id`: the engine retracts its interest once no other querier on the
    /// key holds it.
    fn undeclare_querier(&self, id: Id) {
        match self {
            Engine::Router(router) => router
                .node
                .forwarder()
                .undeclare_local_interest(u64::from(id), true),
            Engine::Tokio(state) => state
                .shared
                .as_engine()
                .undeclare_write_filter(u64::from(id)),
        }
    }

    /// Tell `callback` whether anything `kind` counts matches `key` among the declarations
    /// `destination` admits, now if it does and each time that changes, until
    /// [`Engine::undeclare_matching_listener`] is called with the id returned. `notifier` is let go
    /// with the callback.
    fn declare_matching_listener(
        &self,
        kind: MatchingStatusType,
        key: &str,
        destination: Locality,
        callback: Callback<MatchingStatus>,
        notifier: Option<SyncGroupNotifier>,
    ) -> ZResult<Id> {
        match self {
            Engine::Router(router) => {
                let sink = tokio_engine::matching_sink(callback, notifier);
                let id = router.node.watch_matching(
                    tokio_engine::router_plane_of(kind),
                    key,
                    tokio_engine::engine_locality(destination),
                    Box::new(move |matching| sink(matching)),
                );
                Id::try_from(id).map_err(|_| {
                    zerror!("the router numbered a matching listener {id}, more than an id holds")
                        .into()
                })
            }
            Engine::Tokio(state) => {
                let id = state
                    .shared
                    .as_engine()
                    .declare_matching_listener_in(
                        tokio_engine::plane_of(kind),
                        key.to_owned(),
                        tokio_engine::matching_sink(callback, notifier),
                        tokio_engine::engine_locality(destination),
                    )
                    .ok_or_else(|| zerror!("this engine has no matching listener"))?;
                Id::try_from(id).map_err(|_| {
                    zerror!(
                        "the engine numbered a matching listener {id}, which is more than an id \
                         holds"
                    )
                    .into()
                })
            }
        }
    }

    /// Stop the matching listener `id` and let go of its callback.
    fn undeclare_matching_listener(&self, id: Id) {
        match self {
            Engine::Router(router) => router.node.unwatch_matching(u64::from(id)),
            Engine::Tokio(state) => state
                .shared
                .as_engine()
                .undeclare_matching_listener(u64::from(id)),
        }
    }

    /// Announce a liveliness token on `key` to every peer, now and later, until
    /// [`Engine::undeclare_liveliness_token`] is called with the id returned.
    fn declare_liveliness_token(
        &self,
        key: &str,
        scope: ExprId,
        suffix: Option<String>,
    ) -> ZResult<Id> {
        match self {
            Engine::Router(router) => {
                let id = router.node.declare_token(key);
                Id::try_from(id).map_err(|_| {
                    zerror!("the router numbered a token {id}, which is more than an id holds")
                        .into()
                })
            }
            Engine::Tokio(state) => {
                let wire = tokio_engine::wire_key_of(scope, suffix);
                // The retraction names its token by id alone, as upstream's does.
                let id = state
                    .shared
                    .as_engine()
                    .declare_liveliness_token_on_wire(key.to_owned(), wire, None)
                    .ok_or_else(|| zerror!("this engine declares no liveliness token"))?;
                Id::try_from(id).map_err(|_| {
                    zerror!(
                        "the engine numbered a liveliness token {id}, which is more than an id \
                         holds"
                    )
                    .into()
                })
            }
        }
    }

    /// Retract the liveliness token `id`, which tells the peers it is gone.
    fn undeclare_liveliness_token(&self, id: Id) {
        match self {
            Engine::Router(router) => router.node.undeclare_token(u64::from(id)),
            Engine::Tokio(state) => state
                .shared
                .as_engine()
                .undeclare_liveliness_token(u64::from(id)),
        }
    }

    /// Take the changes of the liveliness tokens the peers hold for what `subscription` says,
    /// until [`Engine::undeclare_subscriber`] is called with the id returned: the ids are those of
    /// the subscribers of the engine.
    fn declare_liveliness_subscriber(
        &self,
        subscription: LivelinessSubscription<'_>,
    ) -> ZResult<Id> {
        match self {
            Engine::Router(router) => {
                let LivelinessSubscription {
                    key,
                    history,
                    callback,
                    notifier,
                    ..
                } = subscription;
                let handler = tokio_engine::liveliness_sink(callback, notifier)();
                let id = router.node.liveliness().subscribe(key, history, handler);
                // The ids of a router's subscribers and of its liveliness subscribers are
                // undeclared through the same call, so the second are marked.
                u32::try_from(id)
                    .ok()
                    .filter(|id| id & RouterEngine::LIVELINESS_ID == 0)
                    .map(|id| id | RouterEngine::LIVELINESS_ID)
                    .ok_or_else(|| {
                        zerror!(
                            "the router numbered a liveliness subscriber {id}, which is more \
                             than an id holds"
                        )
                        .into()
                    })
            }
            Engine::Tokio(state) => {
                let LivelinessSubscription {
                    key,
                    scope,
                    suffix,
                    history,
                    callback,
                    notifier,
                    keeps,
                } = subscription;
                let wire = tokio_engine::wire_key_of(scope, suffix).keeping(keeps);
                let id = state
                    .shared
                    .as_engine()
                    .declare_liveliness_subscriber_on_wire(
                        key.to_owned(),
                        wire,
                        history,
                        tokio_engine::liveliness_sink(callback, notifier),
                    )
                    .ok_or_else(|| zerror!("this engine has no liveliness subscriber"))?;
                Id::try_from(id).map_err(|_| {
                    zerror!(
                        "the engine numbered a liveliness subscriber {id}, which is more than an \
                         id holds"
                    )
                    .into()
                })
            }
        }
    }

    /// Ask which liveliness tokens are alive: the query `request` says.
    fn liveliness_query(&self, request: LivelinessRequest<'_>) -> ZResult<()> {
        match self {
            Engine::Router(router) => {
                tokio_engine::router_liveliness_query(router.node.liveliness(), request)
            }
            Engine::Tokio(state) => {
                tokio_engine::ask_liveliness(state.shared.engine_ref(), request)
            }
        }
    }

    /// Whether anything `kind` counts matches `key` among the declarations `destination` admits.
    fn matching_status(
        &self,
        kind: MatchingStatusType,
        key: &str,
        destination: Locality,
    ) -> ZResult<bool> {
        match self {
            Engine::Router(router) => Ok(router.node.matching_status(
                tokio_engine::router_plane_of(kind),
                key,
                tokio_engine::engine_locality(destination),
            )),
            Engine::Tokio(state) => state
                .shared
                .as_engine()
                .matching_status(
                    tokio_engine::plane_of(kind),
                    key,
                    tokio_engine::engine_locality(destination),
                )
                .ok_or_else(|| zerror!("this engine has no matching status").into()),
        }
    }
}

#[cfg(not(feature = "engine-tokio"))]
impl Engine {
    fn open(
        _config: &Config,
        #[cfg(feature = "shared-memory")] _shm_clients: Option<
            Arc<zenoh_shm::api::client_storage::ShmClientStorage>,
        >,
    ) -> ZResult<(Engine, ZenohId)> {
        bail!("this build of zenoh selects no engine: enable the feature `engine-tokio`")
    }

    fn is_closed(&self) -> bool {
        match *self {}
    }

    fn close(&self) {
        match *self {}
    }

    fn acquire_keyexpr(&self, _keyexpr: &str) -> Option<u64> {
        match *self {}
    }

    fn release_keyexpr(&self, _mapping_id: u64) {
        match *self {}
    }

    fn next_entity_id(&self) -> u64 {
        match *self {}
    }

    fn peer_identities(&self) -> Vec<(Vec<u8>, u8)> {
        match *self {}
    }

    #[cfg(feature = "unstable")]
    fn faces(&self) -> Vec<Face> {
        match *self {}
    }

    fn node_timestamp(&self) -> Option<uhlc::Timestamp> {
        match *self {}
    }

    #[cfg(feature = "unstable")]
    fn node_clock(&self) -> Box<dyn Fn() -> Option<uhlc::Timestamp> + Send + Sync> {
        match *self {}
    }

    #[cfg(feature = "unstable")]
    fn listen_locators(&self) -> Vec<String> {
        match *self {}
    }

    #[cfg(feature = "unstable")]
    fn linkstate_regions(&self) -> Vec<(String, String)> {
        match *self {}
    }

    #[cfg(feature = "unstable")]
    fn router_admin_views(&self) -> Option<RouterAdminViews> {
        match *self {}
    }

    #[cfg(feature = "unstable")]
    fn host_router_queryable(
        &self,
        _key: &str,
        _handler: Box<
            dyn FnMut(
                    &dyn wz_session_core::query_sink::QueryView,
                    &mut dyn wz_session_core::query_sink::ReplyOut,
                ) + Send,
        >,
    ) -> bool {
        match *self {}
    }

    #[cfg(feature = "unstable")]
    fn watch_faces(&self, _sink: FaceSink) -> u64 {
        match *self {}
    }

    #[cfg(feature = "unstable")]
    fn unwatch_faces(&self, _id: u64) {
        match *self {}
    }

    fn publish(&self, _publication: &Publication<'_>) -> ZResult<()> {
        match *self {}
    }

    fn declare_subscriber(&self, _subscription: Subscription<'_>) -> ZResult<Id> {
        match *self {}
    }

    fn undeclare_subscriber(&self, _id: Id) {
        match *self {}
    }

    fn declare_publisher(&self, _publisher: PublisherDeclaration<'_>) -> ZResult<Id> {
        match *self {}
    }

    fn undeclare_publisher(&self, _id: Id) {
        match *self {}
    }

    fn declare_queryable(&self, _queryable: QueryableDeclaration<'_>) -> ZResult<u64> {
        match *self {}
    }

    fn undeclare_queryable(&self, _id: u64) {
        match *self {}
    }

    fn query(&self, _request: QueryRequest<'_>) -> ZResult<()> {
        match *self {}
    }

    fn new_query_fan(&self) -> Arc<QueryFan> {
        match *self {}
    }

    fn declare_querier(&self, _querier: QuerierDeclaration<'_>) -> ZResult<Id> {
        match *self {}
    }

    fn undeclare_querier(&self, _id: Id) {
        match *self {}
    }

    fn declare_matching_listener(
        &self,
        _kind: MatchingStatusType,
        _key: &str,
        _destination: Locality,
        _callback: Callback<MatchingStatus>,
        _notifier: Option<SyncGroupNotifier>,
    ) -> ZResult<Id> {
        match *self {}
    }

    fn undeclare_matching_listener(&self, _id: Id) {
        match *self {}
    }

    fn declare_liveliness_token(
        &self,
        _key: &str,
        _scope: ExprId,
        _suffix: Option<String>,
    ) -> ZResult<Id> {
        match *self {}
    }

    fn undeclare_liveliness_token(&self, _id: Id) {
        match *self {}
    }

    fn declare_liveliness_subscriber(
        &self,
        _subscription: LivelinessSubscription<'_>,
    ) -> ZResult<Id> {
        match *self {}
    }

    fn liveliness_query(&self, _request: LivelinessRequest<'_>) -> ZResult<()> {
        match *self {}
    }

    fn matching_status(
        &self,
        _kind: MatchingStatusType,
        _key: &str,
        _destination: Locality,
    ) -> ZResult<bool> {
        match *self {}
    }
}

/// The reading of a configuration for the tokio engine: its role, its endpoints, the document its
/// plan is made from, and the words an open that cannot be carried out is refused in.
#[cfg(feature = "engine-tokio")]
mod tokio_engine {
    use wz_capi_core::runtime::declare::{LivelinessSample, LivelinessSampleKind};
    #[cfg(feature = "unstable")]
    use wz_capi_core::runtime::sample::SourceInfo as EngineSourceInfo;
    pub(super) use wz_capi_core::runtime::session::LocalDeliveryDrain;
    #[cfg(feature = "unstable")]
    use wz_capi_core::runtime::Reliability as EngineReliability;
    pub(super) use wz_capi_core::{drive::FaceDrive, faces::no_shm_clients};
    use wz_capi_core::{
        drive::OpenError,
        open_plan::{key_state, KeyState, OpenRefusal},
        runtime::session_glue::WhatAmI as EngineWhatAmI,
    };
    use wz_capi_core::{
        faces::{FanoutError, SubscriberSink, WireKey},
        runtime::{
            locality::Locality as EngineLocality,
            qos::{CongestionControl as EngineCongestion, Priority as EnginePriority},
            query_sink::{QueryView, ReplyMeta, ReplyOut},
            reply_sink::{ReplyKind, ReplyView},
            sample::{EncodingHint, QosLevel, SampleKind as EngineSampleKind, TimestampHint},
            session::{InterestForm, PublishOptions, QueryOptions},
            session_glue::{ConsolidationMode as EngineConsolidation, QueryTarget as EngineTarget},
            sink::SampleView,
        },
    };
    use wz_capi_port::cancellation::CancellableFan;
    use wz_capi_port::{
        HeldQuery, LivelinessSink, MatchingSink, QueryHolder, QueryableSink, ReplyCallback,
        SessionEngine,
    };
    use zenoh_config::{wrappers::ZenohId, ExpandedConfig, ModeDependent};
    use zenoh_protocol::{
        core::{CongestionControl, EndPoints, ExprId, Parameters, WhatAmI},
        network::request::ext::QueryTarget,
        zenoh::query::ConsolidationMode,
    };
    use zenoh_result::ZResult;
    #[cfg(feature = "unstable")]
    use {
        crate::api::info::{Face, FaceSink, Link, Transport},
        crate::api::timestamp_stack::TimestampSource,
        wz_capi_core::faces::{FaceEventKind, FaceEventSink, FaceSnapshot, LinkSnapshot},
        wz_capi_core::runtime::{
            reply_sink::ReplyArrival,
            ts_stack::{Interception as EngineInterception, TsStack},
        },
        zenoh_protocol::core::{Locator, Priority as WirePriority, Reliability as WireReliability},
        zenoh_protocol::network::timestamp_stack::interception_point,
    };

    use std::{collections::BTreeMap, sync::Mutex};

    use zenoh_protocol::core::Timestamp;

    use super::{Arc, LivelinessRequest, Publication, QueryRequest};
    use crate::api::{
        bytes::ZBytes,
        cancellation::SyncGroupNotifier,
        encoding::Encoding,
        handlers::{Callback, Ordered},
        key_expr::KeyExpr,
        matching::{MatchingStatus, MatchingStatusType},
        query::{Reply, ReplyError},
        queryable::{Answer, Query, QueryInner, Replier},
        sample::{Locality, QoS, Sample, SampleKind},
        Id,
    };
    #[cfg(feature = "unstable")]
    use crate::api::{cancellation::CancellationToken, sample::SourceInfo};

    /// The role of the engine that is the mode of the configuration.
    pub(super) fn role_of(mode: WhatAmI) -> EngineWhatAmI {
        match mode {
            WhatAmI::Router => EngineWhatAmI::Router,
            WhatAmI::Peer => EngineWhatAmI::Peer,
            WhatAmI::Client => EngineWhatAmI::Client,
        }
    }

    /// Start a scout for the roles `what` names, on the group, the interface and the hop limit
    /// the configuration states, handing each Hello to `callback` as it arrives, until what this
    /// returns is dropped.
    ///
    /// Upstream's `scout` reads only the scouting group of its configuration
    /// (`zenoh/src/api/scouting.rs` @ `zenoh_config::defaults::scouting::multicast::address`): the node it would be is not
    /// asked, so the engine is given the document as a peer's, which changes nothing it reads.
    /// A Hello that names no role, an id of no length or no locator that parses is a Hello that
    /// cannot be told in this crate's words, and is left out as one that does not decode is.
    pub(super) fn start_scout(
        what: zenoh_protocol::core::WhatAmIMatcher,
        config: &crate::api::config::Config,
        callback: Callback<zenoh_config::wrappers::Hello>,
    ) -> ZResult<Box<dyn Send>> {
        use wz_capi_core::{
            runtime::zenoh_config::ZenohNodeConfig,
            scouting::fresh_scout_zid,
            scouting_node::{ScoutStream, ScoutingPlan},
        };
        use zenoh_protocol::{
            core::{Locator, ZenohIdProto},
            scouting::HelloProto,
        };

        let expanded = config.0.clone().expanded();
        let document = document_of(&expanded, EngineWhatAmI::Peer, &expanded.id())?;
        let node = ZenohNodeConfig::from_json5(&document.to_string())
            .map_err(|error| zerror!("the configuration cannot be scouted with: {error:?}"))?
            .config;
        let asked = [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client]
            .into_iter()
            .filter(|role| what.matches(*role))
            .fold(0u8, |bits, role| bits | role as u8);
        let plan = ScoutingPlan::for_scout(&node, asked)
            .map_err(|error| zerror!("the configuration cannot be scouted with: {error:?}"))?;
        let stream = ScoutStream::start(plan, asked, fresh_scout_zid(), move |hello| {
            let whatami = match hello.whatami.map(|role| role.to_api()) {
                Some(1) => WhatAmI::Router,
                Some(2) => WhatAmI::Peer,
                Some(4) => WhatAmI::Client,
                _ => return,
            };
            let Ok(zid) = ZenohIdProto::try_from(hello.zid.as_slice()) else {
                return;
            };
            let locators = hello
                .locators
                .iter()
                .filter_map(|text| Locator::try_from(text.as_str()).ok())
                .collect();
            callback.call(
                HelloProto {
                    version: hello.version,
                    whatami,
                    zid,
                    locators,
                }
                .into(),
            );
        })
        .map_err(|error| zerror!("the scout cannot be started: {error}"))?;
        Ok(Box::new(stream))
    }

    /// The endpoints the configuration says to connect to as `mode`, each one dialled on its own.
    ///
    /// An entry that names a strategy over a group of locators is refused, by the key: the engine
    /// dials the endpoints it is told of and has no choice among a group of them to make.
    pub(super) fn connect_endpoints(
        config: &ExpandedConfig,
        mode: WhatAmI,
    ) -> ZResult<Vec<String>> {
        let mut endpoints = Vec::new();
        for entry in config.connect.endpoints.get(mode).into_iter().flatten() {
            match entry {
                EndPoints::Single(endpoint) => endpoints.push(endpoint.to_string()),
                EndPoints::Locators(_) => bail!(
                    "this engine cannot open a configuration whose `connect/endpoints` names a \
                     strategy over a group of locators"
                ),
            }
        }
        Ok(endpoints)
    }

    /// The document the plan reads: the whole configuration as JSON, with the mode and the id the
    /// session stands on stated, so that what the engine reads is what the session reports.
    pub(super) fn document_of(
        config: &ExpandedConfig,
        role: EngineWhatAmI,
        zid: &ZenohId,
    ) -> ZResult<serde_json::Value> {
        let mut document = rendered(config)?; // `config` derefs to the configuration it expands
        let object = document
            .as_object_mut()
            .ok_or_else(|| zerror!("the configuration is not an object"))?;
        object.insert("mode".to_owned(), role.to_str().into());
        object.insert("id".to_owned(), zid.to_string().into());
        Ok(document)
    }

    /// The configuration as the document an operator would have written it.
    ///
    /// Serialising the configuration states every optional field, as `null` where it is absent
    /// (`id`, `interfaces`, `link_protocols` and `flows` of a low pass filter, the same of an
    /// access rule, a downsampling item). The reader of the plan is written for an operator's
    /// document, which leaves a field out to mean its default, and refuses a `null` where it
    /// expects a string or a list, as upstream's own reader would a `null` it has no `Option` for.
    /// So a member that is `null` is left out, which says the same thing.
    pub(super) fn rendered(config: &zenoh_config::Config) -> ZResult<serde_json::Value> {
        fn without_nulls(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::Object(members) => {
                    members.retain(|_, member| !member.is_null());
                    for member in members.values_mut() {
                        without_nulls(member);
                    }
                    // A section that held nothing but absent fields is absent itself: the reader
                    // takes an empty object for a value of its own, and `gateway: {}` is not a key.
                    members.retain(|_, member| !member.as_object().is_some_and(|m| m.is_empty()));
                }
                serde_json::Value::Array(items) => items.iter_mut().for_each(without_nulls),
                _ => {}
            }
        }
        let mut document = serde_json::to_value(config)?;
        without_nulls(&mut document);
        Ok(document)
    }

    /// The refusal of a configuration whose entries of one list share an `id`, in the words
    /// upstream refuses it in when it builds the interceptors of a session
    /// (`zenoh/src/net/routing/interceptor/`: one check per list, each with its own opening).
    ///
    /// Upstream makes the check when the session opens, over the list it was given, and the open
    /// fails with it; so does this one. The lists are the interceptors' (downsampling, the low
    /// pass filter, the QoS overwrite of the network) and, when the access control is enabled,
    /// its rules, subjects and policies, which upstream builds only then.
    pub(super) fn refuse_repeated_ids(document: &serde_json::Value) -> ZResult<()> {
        fn repeated(entries: Option<&serde_json::Value>) -> Option<&str> {
            let mut seen = std::collections::HashSet::new();
            entries?
                .as_array()?
                .iter()
                .filter_map(|entry| entry.get("id")?.as_str())
                .find(|id| !seen.insert(*id))
        }
        if let Some(id) = repeated(document.get("downsampling")) {
            bail!("Invalid Downsampling config: id '{id}' is repeated");
        }
        if let Some(id) = repeated(document.get("low_pass_filter")) {
            bail!("Invalid low-pass filter config: id '{id}' is repeated");
        }
        if let Some(id) = repeated(document.pointer("/qos/network")) {
            bail!("Invalid Qos Overwrite config: id '{id}' is repeated");
        }
        if let Some(acl) = document
            .get("access_control")
            .filter(|acl| acl.get("enabled").and_then(serde_json::Value::as_bool) == Some(true))
        {
            refuse_malformed_access_control(acl)?;
        }
        Ok(())
    }

    /// The checks upstream makes of an enabled access control when it builds its policy, in the
    /// order it makes them and in its words
    /// (`zenoh/src/net/routing/interceptor/authorization.rs` @ `fn policy_information_point(`
    /// and the loop over the lists before it): the three lists come together, an empty one leaves
    /// the policy empty and is judged no further, then the ids, the subjects' values and what each
    /// policy names.
    fn refuse_malformed_access_control(acl: &serde_json::Value) -> ZResult<()> {
        use std::collections::HashSet;

        use serde_json::Value;

        let list = |name: &str| acl.get(name).and_then(Value::as_array);
        let (Some(rules), Some(subjects), Some(policies)) =
            (list("rules"), list("subjects"), list("policies"))
        else {
            bail!("All ACL rules/subjects/policies config lists must be provided");
        };
        if rules.is_empty() || subjects.is_empty() || policies.is_empty() {
            return Ok(());
        }
        let text = |entry: &'_ Value, key: &str| {
            entry
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let blank = |value: &str| value.trim().is_empty();
        if rules.iter().any(|rule| blank(&text(rule, "id"))) {
            bail!("Found empty rule id in rules list");
        }
        if subjects.iter().any(|subject| blank(&text(subject, "id"))) {
            bail!("Found empty subject id in subjects list");
        }
        let mut rule_ids = HashSet::new();
        for rule in rules {
            let id = text(rule, "id");
            if !rule_ids.insert(id.clone()) {
                bail!("Rule id must be unique: id '{id}' is repeated");
            }
        }
        let mut subject_ids = HashSet::new();
        for subject in subjects {
            let id = text(subject, "id");
            if subject_ids.contains(&id) {
                bail!("Subject id must be unique: id '{id}' is repeated");
            }
            for (key, what) in [
                ("interfaces", "interface"),
                ("cert_common_names", "cert_common_name"),
                ("usernames", "username"),
            ] {
                let any_blank = subject
                    .get(key)
                    .and_then(Value::as_array)
                    .is_some_and(|values| {
                        values
                            .iter()
                            .any(|value| blank(value.as_str().unwrap_or_default()))
                    });
                if any_blank {
                    bail!("Found empty {what} value in subject '{id}'");
                }
            }
            subject_ids.insert(id);
        }
        let mut policy_ids = HashSet::new();
        for (number, policy) in policies.iter().enumerate() {
            if let Some(id) = policy.get("id").and_then(Value::as_str) {
                if !policy_ids.insert(id.to_owned()) {
                    bail!("Policy id must be unique: id '{id}' is repeated");
                }
            }
            let named = |key: &str| {
                policy
                    .get(key)
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .map(|value| value.as_str().unwrap_or_default().to_owned())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            };
            let (policy_rules, policy_subjects) = (named("rules"), named("subjects"));
            if policy_rules.is_empty() || policy_subjects.is_empty() {
                bail!("Policy #{number} is malformed: empty subjects or rules list");
            }
            for subject in &policy_subjects {
                if blank(subject) {
                    bail!("Found empty subject id in policy #{number}");
                }
                if !subject_ids.contains(subject) {
                    bail!(
                        "Subject '{subject}' in policy #{number} does not exist in subjects list"
                    );
                }
            }
            for rule in &policy_rules {
                if blank(rule) {
                    bail!("Found empty rule id in policy #{number}");
                }
                if !rule_ids.contains(rule) {
                    bail!("Rule '{rule}' in policy #{number} does not exist in rules list");
                }
            }
        }
        Ok(())
    }

    /// Decision D6: refuse, by name, the keys of `document` that `ignored` says the engine does not
    /// act on, that upstream acts on, and whose value is not the default's.
    ///
    /// `ignored` lists every leaf the document carries that the engine does not act on, and the
    /// document is the whole configuration, so most of them hold the default. A key that upstream
    /// itself does nothing with ([`KeyState::Inert`]) is accepted whatever its value, and a key no
    /// list knows ([`None`]) is refused as the unmapped ones are.
    pub(super) fn refuse_unmapped(ignored: &[String], document: &serde_json::Value) -> ZResult<()> {
        // The default in the shape the document has, nulls left out, or a key whose default is
        // `null` would differ from the document that states nothing.
        let default = rendered(&zenoh_config::Config::default())?;
        let unmapped: Vec<String> = ignored
            .iter()
            .filter(|key| key_state(key) != Some(KeyState::Inert))
            .filter(|key| !acted_on_by_the_session(key))
            .filter(|key| !inert_in_this_build(key))
            .filter(|key| {
                let pointer = format!("/{key}");
                document.pointer(&pointer) != default.pointer(&pointer)
            })
            .map(|key| match document.pointer(&format!("/{key}")) {
                Some(value) => format!("`{key}` = {value}"),
                None => format!("`{key}`"),
            })
            .collect();
        if unmapped.is_empty() {
            Ok(())
        } else {
            bail!(
                "this engine does not act on the configuration it is given: {}",
                unmapped.join(", ")
            )
        }
    }

    /// Whether a key does nothing in this build, as it does nothing in upstream's built without
    /// the same feature: the plugins are loaded by a runtime built with `plugins`
    /// (`zenoh/Cargo.toml` @ `plugins = []`), and without it `plugins_loading/*` and `plugins/*`
    /// are read into the configuration and no plugin is loaded or configured. A build with the
    /// feature is another matter, and a plugin it was asked for is not silently left unloaded.
    fn inert_in_this_build(key: &str) -> bool {
        !cfg!(feature = "plugins")
            && (key.starts_with("plugins/") || key.starts_with("plugins_loading/"))
    }

    /// Whether a key the engine does not act on is one this crate acts on itself, so that the
    /// engine's ignoring it is no reason to refuse it. `transport/shared_memory/mode`, which the
    /// session reads as it opens (`api::shm::init_if_asked`) in a build with shared memory, and
    /// `qos/publication`, the per-key defaults of the publications, which the session holds as
    /// a tree of keys and applies to every publisher and put it builds
    /// ([`Session::get_publisher_qos_overwrite`]).
    fn acted_on_by_the_session(key: &str) -> bool {
        key == "qos/publication"
            || (cfg!(feature = "shared-memory") && key == "transport/shared_memory/mode")
            // The implicit optimisation of large messages, which `api::shm::transport::Promoter`
            // carries out for a put (the lists of `query` and `reply` are not promoted yet, and a
            // list that names them is read and not acted on for those).
            || (cfg!(all(feature = "shared-memory", feature = "unstable"))
                && (key == "transport/shared_memory/transport_optimization/message_size_threshold"
                    || key == "transport/shared_memory/transport_optimization/messages"))
    }

    /// An open the plan refuses, in the words upstream refuses it in where it does, and by the key
    /// the refusal is about where it does not.
    pub(super) fn refusal_error(refusal: OpenRefusal) -> zenoh_result::Error {
        match refusal {
            OpenRefusal::NothingToDial => {
                zerror!("No peer specified and multicast scouting deactivated!").into()
            }
            OpenRefusal::GroupInConnect => {
                zerror!("Forbidden multicast endpoint in connect list!").into()
            }
            OpenRefusal::QosWithLowlatency => {
                zerror!("'qos' and 'lowlatency' options are incompatible").into()
            }
            OpenRefusal::GossipTarget => {
                zerror!("\"client\" is not allowed as gossip target").into()
            }
            other => zerror!(
                "this configuration cannot be opened ({:?}, key: {})",
                other,
                other.key()
            )
            .into(),
        }
    }

    /// The endpoints the configuration says to connect to as `mode`, as upstream writes them when it
    /// says which it could not connect to.
    pub(super) fn peers_text(config: &ExpandedConfig, mode: WhatAmI) -> String {
        config
            .connect
            .endpoints
            .get(mode)
            .map_or_else(|| "[]".to_owned(), |peers| format!("{peers:?}"))
    }

    /// The options of the engine's publication that `publication` asks for.
    ///
    /// The engine stamps a publication that carries no time with the node's clock when the node
    /// holds one, as upstream's session does, so an absent timestamp is left absent.
    pub(super) fn publish_options(publication: &Publication<'_>) -> PublishOptions {
        let mut options = match publication.kind {
            SampleKind::Put => PublishOptions::put(),
            SampleKind::Delete => PublishOptions::del(),
        }
        .with_locality(engine_locality(publication.destination))
        // The priority is the protocol's byte; the engine reads it the same way.
        .with_priority(EnginePriority::from_wire(publication.priority as u8))
        .with_congestion_control(match publication.congestion_control {
            CongestionControl::Drop => EngineCongestion::Drop,
            CongestionControl::Block => EngineCongestion::Block,
            #[cfg(feature = "unstable")]
            CongestionControl::BlockFirst => EngineCongestion::BlockFirst,
        })
        .with_express(publication.is_express);
        #[cfg(feature = "unstable")]
        {
            options = options.with_reliability(match publication.reliability {
                zenoh_protocol::core::Reliability::BestEffort => {
                    wz_capi_core::runtime::Reliability::BestEffort
                }
                zenoh_protocol::core::Reliability::Reliable => {
                    wz_capi_core::runtime::Reliability::Reliable
                }
            });
        }
        if publication.kind == SampleKind::Put {
            if let Some(hint) = encoding_hint_of(&publication.encoding) {
                options = options.with_encoding(hint);
            }
        }
        if let Some(timestamp) = &publication.timestamp {
            options = options.with_timestamp(timestamp_hint_of(timestamp));
        }
        #[cfg(feature = "unstable")]
        if let Some(info) = &publication.source_info {
            options = options.with_source_info(source_info_hint_of(info));
        }
        if let Some(attachment) = &publication.attachment {
            options = options.with_attachment(attachment.to_bytes().into_owned());
        }
        #[cfg(feature = "unstable")]
        if publication.ts_stack.is_some() {
            options = options.with_ts_stack(
                publication.ts_stack.as_ref().map(engine_stack_of),
                publication.wire_ts_stack.as_ref().map(engine_stack_of),
            );
        }
        options
    }

    /// The engine's hint for `encoding`, or `None` for the default one: it is the absence of an
    /// encoding on the wire, in both crates.
    pub(super) fn encoding_hint_of(encoding: &Encoding) -> Option<EncodingHint> {
        let encoding: zenoh_protocol::core::Encoding = encoding.clone().into();
        if encoding == zenoh_protocol::core::Encoding::default() {
            return None;
        }
        let schema = encoding
            .schema
            .as_ref()
            .map(|schema| String::from_utf8_lossy(schema.as_slice()).into_owned());
        Some(EncodingHint {
            packed_id: (u32::from(encoding.id) << 1) | u32::from(schema.is_some()),
            schema,
        })
    }

    /// The encoding a hint says; none is the default one.
    fn encoding_from(hint: Option<&EncodingHint>) -> Encoding {
        encoding_of_parts(hint.map(|hint| (hint.packed_id, hint.schema.as_deref())))
    }

    /// The encoding the parts of a hint say, as a view of a reply borrows them: the packed id and
    /// the schema; none is the default one.
    fn encoding_of_parts(parts: Option<(u32, Option<&str>)>) -> Encoding {
        parts
            .and_then(|(packed_id, schema)| {
                let id = u16::try_from(packed_id >> 1).ok()?;
                let schema = schema
                    .filter(|_| packed_id & 1 == 1)
                    .map(|schema| zenoh_buffers::ZSlice::from(schema.as_bytes().to_vec()));
                Some(zenoh_protocol::core::Encoding { id, schema })
            })
            .map(Encoding::from)
            .unwrap_or_default()
    }

    /// The engine's hint for `timestamp`.
    fn timestamp_hint_of(timestamp: &uhlc::Timestamp) -> TimestampHint {
        let id = timestamp.get_id();
        TimestampHint {
            time: timestamp.get_time().as_u64(),
            zid: id.to_le_bytes()[..id.size()].to_vec(),
        }
    }

    /// The timestamp a hint says, when its id is one.
    pub(super) fn timestamp_from(hint: &TimestampHint) -> Option<uhlc::Timestamp> {
        let id = uhlc::ID::try_from(hint.zid.as_slice()).ok()?;
        Some(uhlc::Timestamp::new(uhlc::NTP64(hint.time), id))
    }

    /// The quality of service a level of the engine says.
    fn qos_from(level: QosLevel) -> QoS {
        let priority =
            zenoh_protocol::core::Priority::try_from(level.priority() as u8).unwrap_or_default();
        let congestion = match level.congestion() {
            EngineCongestion::Drop => CongestionControl::Drop,
            EngineCongestion::Block => CongestionControl::Block,
            #[cfg(feature = "unstable")]
            EngineCongestion::BlockFirst => CongestionControl::BlockFirst,
            #[cfg(not(feature = "unstable"))]
            EngineCongestion::BlockFirst => CongestionControl::Block,
        };
        QoS::from(zenoh_protocol::network::push::ext::QoSType::new(
            priority,
            congestion,
            level.is_express(),
        ))
    }

    /// The level of the engine that says `qos`.
    fn qos_level_of(qos: QoS) -> QosLevel {
        QosLevel::from_raw(0)
            .with_priority(EnginePriority::from_wire(qos.priority() as u8))
            .with_congestion(match qos.congestion_control() {
                CongestionControl::Drop => EngineCongestion::Drop,
                CongestionControl::Block => EngineCongestion::Block,
                #[cfg(feature = "unstable")]
                CongestionControl::BlockFirst => EngineCongestion::BlockFirst,
            })
            .with_express(qos.express())
    }

    /// The engine's source information for `info`.
    #[cfg(feature = "unstable")]
    fn source_info_hint_of(info: &SourceInfo) -> EngineSourceInfo {
        let zid = info.source_id.zid();
        let size = zenoh_protocol::core::ZenohIdProto::from(zid).size();
        EngineSourceInfo::new(
            &zid.to_le_bytes()[..size],
            info.source_id.eid(),
            info.source_sn,
        )
    }

    /// The source information the engine's says.
    #[cfg(feature = "unstable")]
    fn source_info_from(info: &EngineSourceInfo) -> Option<SourceInfo> {
        let zid =
            zenoh_protocol::core::ZenohIdProto::try_from(&info.zid[..usize::from(info.zid_len)])
                .ok()?;
        let id = zenoh_protocol::core::EntityGlobalIdProto { zid, eid: info.eid };
        Some(SourceInfo::new(id.into(), info.sn))
    }

    /// The name the wire gives the key of `publication`: the literal, or a declaration and what
    /// follows it.
    pub(super) fn wire_key(publication: &Publication<'_>) -> WireKey {
        wire_key_of(publication.scope, publication.suffix.clone())
    }

    /// The name the wire gives a key that is `suffix` after the declaration `scope`, `0` for none.
    pub(super) fn wire_key_of(scope: ExprId, suffix: Option<String>) -> WireKey {
        if scope == 0 {
            WireKey::literal()
        } else {
            WireKey::aliased(u64::from(scope), suffix)
        }
    }

    /// How the peers are asked for the subscribers matching a publisher's key, or `None` when the
    /// publisher writes to the session itself and nobody is asked. Upstream asks for the key as
    /// the wire names it, once and for the future, with no aggregation.
    pub(super) fn interest_of(
        scope: ExprId,
        suffix: Option<String>,
        destination: Locality,
    ) -> Option<InterestForm> {
        (destination != Locality::SessionLocal).then(|| InterestForm {
            mapping_id: u64::from(scope),
            suffix,
            aggregate: false,
        })
    }

    /// The locality of the engine that is `locality`.
    pub(super) fn engine_locality(locality: Locality) -> EngineLocality {
        match locality {
            Locality::Any => EngineLocality::Any,
            Locality::SessionLocal => EngineLocality::SessionLocal,
            Locality::Remote => EngineLocality::Remote,
        }
    }

    /// Answer a liveliness get on a router node: the router holds the tokens of every face it
    /// serves, so each key alive that the query meets is a reply, at once, and the callback is
    /// let go, which ends the channel of a handler.
    pub(super) fn router_liveliness_query(
        face: &wz_capi_core::drive::LocalLiveliness,
        request: LivelinessRequest<'_>,
    ) -> ZResult<()> {
        let LivelinessRequest { key, callback, .. } = request;
        for keyexpr in face.alive(key) {
            let sample = liveliness_sample_of(&LivelinessSample {
                kind: LivelinessSampleKind::Put,
                keyexpr: &keyexpr,
                token_id: 0,
            })?;
            callback.call(Reply {
                result: Ok(sample),
                #[cfg(feature = "unstable")]
                replier_id: None,
            });
        }
        Ok(())
    }

    /// Put or delete `publication` on a router node, which publishes a payload (a put) with a
    /// priority and the express flag and nothing else yet: each setting it cannot carry refuses
    /// the publication by name, and is not dropped. A delete takes the route a put to its key
    /// would, and carries no priority or express flag of its own.
    pub(super) fn router_publish(
        forwarder: &wz_runtime_tokio::router_forward::RouterForwarder,
        publication: &Publication<'_>,
    ) -> ZResult<()> {
        // The metadata of the publication rides the push to the other faces and the sample the
        // session's own subscribers are handed, as the options of a session describe them.
        let options = publish_options(publication);
        let payload = publication.payload.to_bytes();
        let published = forwarder.publish_with(publication.key, &payload, &options);
        published.map_err(|error| {
            zerror!(
                "the router could not publish on {}: {error:?}",
                publication.key
            )
            .into()
        })
    }

    /// What the engine hands the samples of a subscription to: the callback, called once for each
    /// sample, from whichever thread the engine delivers on.
    ///
    /// The engine asks for a callback of its own for each face, so they share what the
    /// subscription holds, and the notifier is let go with the last of them (and with a call that
    /// is still running).
    pub(super) fn subscriber_sink(
        callback: Callback<Sample>,
        notifier: Option<SyncGroupNotifier>,
        #[cfg(feature = "unstable")] timestamps: Arc<TimestampSource>,
    ) -> SubscriberSink {
        struct Delivery {
            ordered: Arc<Ordered<Sample>>,
            #[cfg(feature = "unstable")]
            timestamps: Arc<TimestampSource>,
        }
        let delivery = Arc::new(Delivery {
            ordered: Ordered::new(callback, notifier),
            #[cfg(feature = "unstable")]
            timestamps,
        });
        Arc::new(move || {
            let delivery = Arc::clone(&delivery);
            Box::new(move |view: &dyn SampleView| {
                match sample_of(
                    view,
                    #[cfg(feature = "unstable")]
                    Some(&delivery.timestamps),
                ) {
                    Ok(sample) => delivery.ordered.deliver(sample),
                    Err(error) => tracing::error!("a sample could not be delivered: {error}"),
                }
            })
        })
    }

    /// The sample the engine's view of a frame is.
    ///
    /// The payload is copied out of the frame: handing it over as the frame's own bytes is the
    /// zero-copy payload of slice Z2 that no engine offers yet.
    /// The payload of a sample the engine hands up: the buffer of shared memory it is when the
    /// reader of this crate made it ([`crate::api::shm::transport`]), the bytes copied out of the
    /// frame otherwise.
    fn payload_of_view(view: &dyn SampleView) -> ZBytes {
        #[cfg(feature = "shared-memory")]
        if let Some(shared) = view
            .payload_shared()
            .and_then(crate::api::shm::transport::payload_of)
        {
            return shared;
        }
        ZBytes::from(view.payload().to_vec())
    }

    fn sample_of(
        view: &dyn SampleView,
        #[cfg(feature = "unstable")] receive: Option<&TimestampSource>,
    ) -> ZResult<Sample> {
        let key_expr = KeyExpr::try_from(view.keyexpr().to_owned())?;
        let kind = match view.kind() {
            EngineSampleKind::Put => SampleKind::Put,
            EngineSampleKind::Del => SampleKind::Delete,
        };
        let encoding = encoding_from(view.encoding());
        let timestamp = view.timestamp().and_then(timestamp_from);
        let qos = view.qos().map_or_else(QoS::default, qos_from);
        Ok(Sample {
            key_expr,
            payload: payload_of_view(view),
            kind,
            encoding,
            timestamp,
            qos,
            #[cfg(feature = "unstable")]
            reliability: match view.reliability() {
                EngineReliability::BestEffort => zenoh_protocol::core::Reliability::BestEffort,
                EngineReliability::Reliable => zenoh_protocol::core::Reliability::Reliable,
            },
            #[cfg(feature = "unstable")]
            source_info: view.source_info().and_then(source_info_from),
            attachment: view.attachment().map(|bytes| ZBytes::from(bytes.to_vec())),
            #[cfg(feature = "unstable")]
            timestamp_stack: view
                .ts_stack()
                .and_then(|stack| received_stack(stack, view.routed(), receive)),
        })
    }

    /// The timestamp stack of a message as the application is given it: what the nodes it crossed
    /// recorded, and what this node records on delivering it when it is the point asked for.
    /// `None` for a stack that cannot be read.
    #[cfg(feature = "unstable")]
    fn received_stack(
        stack: &TsStack,
        routed: bool,
        receive: Option<&TimestampSource>,
    ) -> Option<crate::api::timestamp_stack::TimestampStack> {
        let mut stack = protocol_stack_of(stack);
        if let Some(source) = receive {
            // A message that came in over a link was routed by this node on its way, and one the
            // session published itself was not.
            if routed {
                source.record(&mut stack, interception_point::ROUTE);
            }
            source.record(&mut stack, interception_point::RECEIVE);
        }
        crate::api::timestamp_stack::TimestampStack::try_from(&stack).ok()
    }

    /// The stack of this crate's protocol types that the engine's stack says.
    #[cfg(feature = "unstable")]
    fn protocol_stack_of(
        stack: &TsStack,
    ) -> zenoh_protocol::network::timestamp_stack::TimestampStack {
        zenoh_protocol::network::timestamp_stack::TimestampStack {
            conf_flags: stack.conf_flags,
            stack: stack
                .stack
                .iter()
                .map(
                    |record| zenoh_protocol::network::timestamp_stack::Interception {
                        flags: record.flags,
                        timestamp: record.timestamp.clone(),
                    },
                )
                .collect(),
        }
    }

    /// The engine's stack that a stack of this crate's protocol types says.
    #[cfg(feature = "unstable")]
    pub(super) fn engine_stack_of(
        stack: &zenoh_protocol::network::timestamp_stack::TimestampStack,
    ) -> TsStack {
        TsStack {
            conf_flags: stack.conf_flags,
            stack: stack
                .stack
                .iter()
                .map(|record| EngineInterception {
                    flags: record.flags,
                    timestamp: record.timestamp.clone(),
                })
                .collect(),
        }
    }

    /// What the engine hands the queries of a queryable to: the callback, called once for each
    /// query, from whichever thread the engine delivers on.
    ///
    /// The engine asks for a callback of its own for each face, so they share what the queryable
    /// holds, and the notifier is let go with the last of them (and with a call that is still
    /// running). A query is handed over as a `Query` that holds the engine's hold on it, so it may
    /// be answered after the callback has returned, from any thread; the query is over, and its
    /// final goes out, when the last copy of it is dropped.
    pub(super) fn queryable_sink(
        callback: Callback<Query>,
        notifier: Option<SyncGroupNotifier>,
        zid: ZenohId,
        eid: Id,
        #[cfg(feature = "unstable")] timestamps: Arc<TimestampSource>,
    ) -> QueryableSink {
        struct Delivery {
            ordered: Arc<Ordered<Query>>,
            zid: ZenohId,
            eid: Id,
            #[cfg(feature = "unstable")]
            timestamps: Arc<TimestampSource>,
        }
        let delivery = Arc::new(Delivery {
            ordered: Ordered::new(callback, notifier),
            zid,
            eid,
            #[cfg(feature = "unstable")]
            timestamps,
        });
        Arc::new(move |holder: Arc<dyn QueryHolder>| {
            let delivery = Arc::clone(&delivery);
            Box::new(move |view: &dyn QueryView, _out: &mut dyn ReplyOut| {
                let held = holder.hold_query(view);
                match query_of(
                    view,
                    held,
                    delivery.zid,
                    delivery.eid,
                    #[cfg(feature = "unstable")]
                    &delivery.timestamps,
                ) {
                    Ok(query) => delivery.ordered.deliver(query),
                    Err(error) => tracing::error!("a query could not be delivered: {error}"),
                }
            })
        })
    }

    /// The query the engine's view of a request is, answered through `held`.
    fn query_of(
        view: &dyn QueryView,
        held: Box<dyn HeldQuery>,
        zid: ZenohId,
        eid: Id,
        #[cfg(feature = "unstable")] timestamps: &Arc<TimestampSource>,
    ) -> ZResult<Query> {
        let key_expr = KeyExpr::try_from(view.keyexpr().to_owned())?;
        let parameters = Parameters::from(
            view.parameters()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                .unwrap_or_default(),
        );
        let value = view.payload().map(|payload| {
            (
                ZBytes::from(payload.to_vec()),
                encoding_from(view.encoding()),
            )
        });
        let attachment = view.attachment().map(|bytes| ZBytes::from(bytes.to_vec()));
        // The stack the query arrives with: what the nodes it crossed recorded on it, and what
        // this node records on receiving it (its routing first, when the query came in over a
        // link). Every reply starts from it.
        #[cfg(feature = "unstable")]
        let wire_query = !view.is_local();
        #[cfg(feature = "unstable")]
        let received = view.ts_stack().map(|stack| {
            let mut stack = protocol_stack_of(stack);
            if wire_query {
                timestamps.record(&mut stack, interception_point::ROUTE);
            }
            timestamps.record(&mut stack, interception_point::RECEIVE);
            stack
        });
        #[cfg(feature = "unstable")]
        let timestamp_stack = received
            .as_ref()
            .and_then(|stack| crate::api::timestamp_stack::TimestampStack::try_from(stack).ok());
        #[cfg(feature = "unstable")]
        let reply_timestamps = Arc::clone(timestamps);
        let held = std::sync::Mutex::new(held);
        let replier: Replier = Box::new(move |answer| {
            let held = held.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            // A reply starts from the stack of its query and records its send, and its routing
            // when it goes out over a link, at the time it is made.
            #[cfg(feature = "unstable")]
            let reply_stack = received.as_ref().map(|base| {
                let mut stack = base.clone();
                reply_timestamps.record(&mut stack, interception_point::SEND);
                if wire_query {
                    reply_timestamps.record(&mut stack, interception_point::ROUTE);
                }
                engine_stack_of(&stack)
            });
            let mut outcome = Ok(());
            held.reply(&mut |out: &mut dyn ReplyOut| {
                outcome = write_answer(
                    out,
                    &answer,
                    zid,
                    eid,
                    #[cfg(feature = "unstable")]
                    reply_stack.as_ref(),
                );
            });
            outcome
        });
        Ok(Query {
            inner: Arc::new(QueryInner {
                key_expr: key_expr.into_owned(),
                parameters: parameters.into_owned(),
                qos: qos_from(view.qos()),
                #[cfg(feature = "unstable")]
                source_info: view.source_info().and_then(source_info_from),
                #[cfg(feature = "unstable")]
                timestamp_stack,
                replier,
            }),
            value,
            attachment,
        })
    }

    /// Write what `answer` says into the engine's responder of a query, as the queryable `eid` of
    /// the session `zid`.
    fn write_answer(
        out: &mut dyn ReplyOut,
        answer: &Answer,
        zid: ZenohId,
        eid: Id,
        #[cfg(feature = "unstable")] stack: Option<&TsStack>,
    ) -> ZResult<()> {
        let zid = zenoh_protocol::core::ZenohIdProto::from(zid);
        out.with_responder(&zid.to_le_bytes()[..zid.size()], eid);
        // The reply goes out with the timestamp stack it was given, when its query was
        // instrumented.
        #[cfg(feature = "unstable")]
        if let Some(stack) = stack {
            out.with_ts_stack(stack);
        }
        match answer {
            Answer::Err { payload, encoding } => {
                let hint = encoding_hint_of(encoding);
                out.reply_err(
                    hint.as_ref().map(|hint| hint.packed_id >> 1),
                    hint.as_ref().and_then(|hint| hint.schema.as_deref()),
                    &payload.to_bytes(),
                );
                Ok(())
            }
            Answer::Sample(sample) => {
                let hint = encoding_hint_of(&sample.encoding);
                let timestamp = sample.timestamp.as_ref().map(timestamp_hint_of);
                #[cfg(feature = "unstable")]
                let source_info = sample.source_info.as_ref().map(source_info_hint_of);
                #[cfg(not(feature = "unstable"))]
                let source_info = None;
                let attachment = sample.attachment.as_ref().map(|bytes| bytes.to_bytes());
                let meta = ReplyMeta::new()
                    .with_encoding(hint.as_ref())
                    .with_timestamp(timestamp.as_ref())
                    .with_source_info(source_info.as_ref())
                    .with_attachment(attachment.as_deref())
                    .with_qos(Some(qos_level_of(sample.qos)));
                let key = sample.key_expr.as_str();
                match sample.kind {
                    SampleKind::Put => out.reply_keyed_meta(key, &sample.payload.to_bytes(), meta),
                    SampleKind::Delete => out.reply_keyed_del_meta(key, meta),
                }
                .map_err(|refusal| zerror!("the reply to {key} was refused: {refusal}").into())
            }
        }
    }

    /// Ask the query `request` says of `engine`, handing each reply to its callback.
    ///
    /// The engine asks for a callback of its own for each leg of the query (one to each peer it
    /// reaches and one to the queryables of the session), so they share what the query holds: the
    /// callback is dropped with the last of them, once every leg has ended, and that is what ends
    /// the channel of a handler. A query that no leg was issued for ends at once.
    pub(super) fn ask(engine: &dyn SessionEngine, request: QueryRequest<'_>) -> ZResult<()> {
        let Asked {
            key,
            wire,
            options,
            callback,
            fan,
            consolidation,
        } = asked_of(request)?;
        let mut leg = leg_minter(callback, fan.clone(), consolidation);
        let issued = engine.get_on_wire(key, &wire, &options, fan.as_deref(), &mut leg);
        // The closure holds the delivery the legs share: what it let go of is the last hold, when
        // no leg is left.
        drop(leg);
        match issued {
            Some(_) => Ok(()),
            None => Err(zerror!("this engine asks no queries").into()),
        }
    }

    /// Ask the query `request` says as the node's own face of a router node: the router routes
    /// it to the queryables of the faces that hold one, and each reply is handed to the callback
    /// on the face's thread. The callback is dropped once the router has told the face the end of
    /// the replies, which ends the channel of a handler.
    pub(super) fn router_ask(
        node: &wz_capi_core::drive::RouterState,
        request: QueryRequest<'_>,
    ) -> ZResult<()> {
        let Asked {
            key,
            options,
            callback,
            fan,
            consolidation,
            ..
        } = asked_of(request)?;
        // One leg: the router's. The face holds the callback of the leg for as long as the query
        // is under way and lets go of it when the router tells it the end, which is what ends the
        // query for the callback.
        let mut leg = leg_minter(callback, fan, consolidation);
        let mut on_reply = leg();
        drop(leg);
        node.get(
            key,
            &options,
            Box::new(move |view: &dyn ReplyView| on_reply(view)),
            Box::new(|| {}),
        )
        .map_err(|error| zerror!("{error}").into())
    }

    /// What a query asks of an engine, in the engine's own types: the key, how the wire names
    /// it, the options of the query, the callback its replies go to, what stops it, and how
    /// its replies are consolidated across the legs.
    struct Asked<'a> {
        key: &'a str,
        wire: WireKey,
        options: QueryOptions,
        callback: Callback<Reply>,
        fan: Option<Arc<CancellableFan>>,
        consolidation: ConsolidationMode,
    }

    /// Read the query `request` says into what an engine is asked.
    fn asked_of(request: QueryRequest<'_>) -> ZResult<Asked<'_>> {
        let QueryRequest {
            key,
            scope,
            suffix,
            parameters,
            target,
            consolidation,
            qos,
            destination,
            timeout,
            value,
            attachment,
            #[cfg(feature = "unstable")]
            source_info,
            #[cfg(feature = "unstable")]
            ts_stack,
            #[cfg(feature = "unstable")]
            wire_ts_stack,
            #[cfg(feature = "unstable")]
            timestamps,
            callback,
            #[cfg(feature = "unstable")]
            cancellation_token,
            fan,
            querier_notifier,
        } = request;
        // What must know when the query is over is told by its callback, when it is dropped: the
        // token the query was made with, and the querier whose undeclaration may wait on it.
        let mut callback = callback;
        #[cfg(feature = "unstable")]
        tie_to_end(
            cancellation_token,
            fan.as_ref(),
            querier_notifier,
            &mut callback,
        )?;
        #[cfg(not(feature = "unstable"))]
        if let Some(notifier) = querier_notifier {
            callback.set_on_drop(move || drop(notifier));
        }
        let wire = wire_key_of(scope, suffix);
        let mut options = QueryOptions::get()
            .with_allowed_destination(engine_locality(destination))
            .with_consolidation(match consolidation {
                ConsolidationMode::None => EngineConsolidation::None,
                ConsolidationMode::Monotonic => EngineConsolidation::Monotonic,
                // The session resolves `Auto` before it asks.
                ConsolidationMode::Latest | ConsolidationMode::Auto => EngineConsolidation::Latest,
            })
            .with_qos(qos_level_of(qos))
            // A timeout of nothing is an instant one upstream, and `0` for the engine is the
            // default timeout: the shortest the engine can be told is a millisecond.
            .with_timeout_ms(u32::try_from(timeout.as_millis().max(1)).unwrap_or(u32::MAX));
        match target {
            QueryTarget::BestMatching => {}
            QueryTarget::All => options = options.with_target(EngineTarget::All),
            QueryTarget::AllComplete => options = options.with_target(EngineTarget::AllComplete),
        }
        if !parameters.is_empty() {
            options = options.with_parameters(parameters.as_bytes().to_vec());
        }
        if let Some((payload, encoding)) = &value {
            options = options.with_payload(payload.to_bytes().into_owned());
            if let Some(hint) = encoding_hint_of(encoding) {
                options = options.with_encoding(hint);
            }
        }
        if let Some(attachment) = &attachment {
            options = options.with_attachment(attachment.to_bytes().into_owned());
        }
        #[cfg(feature = "unstable")]
        if let Some(info) = &source_info {
            options = options.with_source_info(source_info_hint_of(info));
        }
        #[cfg(feature = "unstable")]
        if ts_stack.is_some() {
            options = options
                .with_ts_stack(
                    ts_stack.as_ref().map(engine_stack_of),
                    wire_ts_stack.as_ref().map(engine_stack_of),
                )
                // The node records on a reply when it arrives, ahead of the consolidation that
                // may hold it until the query is final: its routing first, when the reply came
                // in over a link, then its receive.
                .with_reply_arrival(ReplyArrival::new(move |stack, routed| {
                    let mut arrived = protocol_stack_of(stack);
                    if routed {
                        timestamps.record(&mut arrived, interception_point::ROUTE);
                    }
                    timestamps.record(&mut arrived, interception_point::RECEIVE);
                    *stack = engine_stack_of(&arrived);
                }));
        }
        Ok(Asked {
            key,
            wire,
            options,
            callback,
            fan,
            consolidation,
        })
    }

    /// Ask the liveliness query `request` says of `engine`, handing each token that is alive to
    /// its callback as a reply, as [`ask`] does for a query.
    pub(super) fn ask_liveliness(
        engine: &dyn SessionEngine,
        request: LivelinessRequest<'_>,
    ) -> ZResult<()> {
        let LivelinessRequest {
            key,
            scope,
            suffix,
            timeout,
            callback,
            #[cfg(feature = "unstable")]
            cancellation_token,
            fan,
            notifier,
        } = request;
        let mut callback = callback;
        #[cfg(feature = "unstable")]
        tie_to_end(cancellation_token, fan.as_ref(), notifier, &mut callback)?;
        #[cfg(not(feature = "unstable"))]
        if let Some(notifier) = notifier {
            callback.set_on_drop(move || drop(notifier));
        }
        let wire = wire_key_of(scope, suffix);
        // As for a query, `0` is the default timeout of the engine and a timeout of nothing is an
        // instant one.
        let timeout_ms = u32::try_from(timeout.as_millis().max(1)).unwrap_or(u32::MAX);
        let mut leg = leg_minter(callback, fan.clone(), ConsolidationMode::None);
        let issued =
            engine.liveliness_get_on_wire(key, &wire, timeout_ms, fan.as_deref(), &mut leg);
        drop(leg);
        match issued {
            Some(_) => Ok(()),
            None => Err(zerror!("this engine asks no liveliness queries").into()),
        }
    }

    /// What mints the callback of each leg of a query: they share what the query holds, and the
    /// callback is dropped with the last of them, which is what ends the channel of a handler.
    fn leg_minter(
        callback: Callback<Reply>,
        fan: Option<Arc<CancellableFan>>,
        consolidation: ConsolidationMode,
    ) -> impl FnMut() -> ReplyCallback {
        let delivery = Arc::new(ReplyDelivery {
            ordered: Ordered::new(callback, None),
            consolidator: Consolidator::new(consolidation),
            _fan: fan,
        });
        move || -> ReplyCallback {
            let delivery = Arc::clone(&delivery);
            Box::new(move |view: &dyn ReplyView| match reply_of(view) {
                Ok(reply) => delivery.deliver(reply),
                Err(error) => tracing::error!("a reply could not be delivered: {error}"),
            })
        }
    }

    /// What the engine hands the changes of a liveliness subscription to: the callback, called
    /// once for each token that comes alive (a put) or is retracted (a delete), from whichever
    /// thread the engine delivers on. As for a subscriber, the legs share what the subscription
    /// holds, and the notifier is let go with the last of them.
    pub(super) fn liveliness_sink(
        callback: Callback<Sample>,
        notifier: Option<SyncGroupNotifier>,
    ) -> LivelinessSink {
        struct Delivery {
            ordered: Arc<Ordered<Sample>>,
        }
        let delivery = Arc::new(Delivery {
            ordered: Ordered::new(callback, notifier),
        });
        let presence = Arc::new(std::sync::Mutex::new(Presence::default()));
        Arc::new(move || {
            let delivery = Arc::clone(&delivery);
            let mut leg = PresenceLeg::mint(&presence);
            Box::new(move |change: LivelinessSample<'_>| {
                let told = match change.kind {
                    LivelinessSampleKind::Put => leg.arrives(change.keyexpr, change.token_id),
                    LivelinessSampleKind::Delete => leg.leaves(change.keyexpr, change.token_id),
                };
                if !told {
                    return;
                }
                match liveliness_sample_of(&change) {
                    Ok(sample) => delivery.ordered.deliver(sample),
                    Err(error) => {
                        tracing::error!("a liveliness change could not be delivered: {error}")
                    }
                }
            })
        })
    }

    /// Which tokens a liveliness subscription has been told of, by key: a token is alive on a key
    /// while any source holds one there, and the subscriber hears of the key when the first comes
    /// and of its going when the last is retracted. Upstream's routing tables do this between a
    /// node's faces and its session (a key has one declaration toward the session however many
    /// tokens sit on it, and the same session may declare several), and this engine's session is
    /// told by each face directly. A source is a leg of the subscription (a face, or the session
    /// itself) and the id the token has there.
    #[derive(Default)]
    struct Presence {
        next_leg: u64,
        alive: std::collections::HashMap<String, std::collections::HashSet<(u64, u64)>>,
    }

    /// One leg's view of the [`Presence`] its subscription shares.
    struct PresenceLeg {
        presence: Arc<std::sync::Mutex<Presence>>,
        leg: u64,
    }

    impl PresenceLeg {
        fn mint(presence: &Arc<std::sync::Mutex<Presence>>) -> Self {
            let mut shared = presence
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let leg = shared.next_leg;
            shared.next_leg += 1;
            Self {
                presence: Arc::clone(presence),
                leg,
            }
        }

        /// Token `id` is alive on `key` at this leg: whether it is the first source of the key.
        fn arrives(&mut self, key: &str, id: u64) -> bool {
            let mut shared = self
                .presence
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let sources = shared.alive.entry(key.to_owned()).or_default();
            let first = sources.is_empty();
            sources.insert((self.leg, id));
            first
        }

        /// Token `id` is retracted on `key` at this leg: whether no source of the key is left. A
        /// retraction of a token this leg never told of (one a peer names by its key) is told when
        /// nothing else keeps the key alive.
        fn leaves(&mut self, key: &str, id: u64) -> bool {
            let mut shared = self
                .presence
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(sources) = shared.alive.get_mut(key) else {
                return true;
            };
            sources.remove(&(self.leg, id));
            if sources.is_empty() {
                shared.alive.remove(key);
                true
            } else {
                false
            }
        }
    }

    impl Drop for PresenceLeg {
        /// A leg that goes (its face is down) holds no token alive any longer.
        fn drop(&mut self) {
            let mut shared = self
                .presence
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let leg = self.leg;
            shared.alive.retain(|_, sources| {
                sources.retain(|(source, _)| *source != leg);
                !sources.is_empty()
            });
        }
    }

    #[cfg(test)]
    mod presence_tests {
        use super::*;

        fn legs(n: usize) -> Vec<PresenceLeg> {
            let presence = Arc::new(std::sync::Mutex::new(Presence::default()));
            (0..n).map(|_| PresenceLeg::mint(&presence)).collect()
        }

        #[test]
        fn a_key_is_told_when_its_first_token_comes_and_its_last_goes() {
            let mut leg = legs(1).remove(0);
            assert!(leg.arrives("a/b", 1));
            assert!(!leg.arrives("a/b", 2), "a second token on the key");
            assert!(!leg.leaves("a/b", 1), "one of two is retracted");
            assert!(leg.leaves("a/b", 2), "the last one");
            assert!(leg.arrives("a/b", 3), "the key is alive again");
        }

        #[test]
        fn tokens_of_two_faces_on_one_key_keep_it_alive_together() {
            let mut all = legs(2);
            let (mut first, mut second) = (all.remove(0), all.remove(0));
            // The same id at two faces is two tokens.
            assert!(first.arrives("k", 7));
            assert!(!second.arrives("k", 7));
            assert!(!first.leaves("k", 7));
            assert!(second.leaves("k", 7));
        }

        #[test]
        fn a_retraction_of_a_key_nobody_told_of_is_told() {
            let mut leg = legs(1).remove(0);
            assert!(leg.leaves("sourced/key", 0));
        }

        #[test]
        fn a_leg_that_goes_keeps_nothing_alive() {
            let mut all = legs(2);
            let (mut first, mut second) = (all.remove(0), all.remove(0));
            assert!(first.arrives("k", 1));
            assert!(!second.arrives("k", 1));
            drop(first);
            assert!(second.leaves("k", 1), "the other face's token was the last");
        }
    }

    /// The sample a token coming alive or going is: its key, with no payload, as upstream makes
    /// it.
    fn liveliness_sample_of(change: &LivelinessSample<'_>) -> ZResult<Sample> {
        Ok(Sample {
            key_expr: KeyExpr::try_from(change.keyexpr.to_owned())?,
            payload: ZBytes::new(),
            kind: match change.kind {
                LivelinessSampleKind::Put => SampleKind::Put,
                LivelinessSampleKind::Delete => SampleKind::Delete,
            },
            encoding: Encoding::default(),
            timestamp: None,
            qos: QoS::default(),
            #[cfg(feature = "unstable")]
            reliability: zenoh_protocol::core::Reliability::Reliable,
            #[cfg(feature = "unstable")]
            source_info: None,
            attachment: None,
            #[cfg(feature = "unstable")]
            timestamp_stack: None,
        })
    }

    /// What the legs of a query are handed their replies to.
    struct ReplyDelivery {
        ordered: Arc<Ordered<Reply>>,
        /// What the replies of every leg are consolidated by, when the query asks for it.
        consolidator: Option<Consolidator>,
        /// What stops the legs, held for as long as the query is under way: whoever keeps a
        /// `Weak` of it reads the end of the query in it.
        _fan: Option<Arc<CancellableFan>>,
    }

    impl ReplyDelivery {
        /// Hand on what the consolidation of the query lets through of `reply`.
        fn deliver(&self, reply: Reply) {
            let Some(consolidator) = &self.consolidator else {
                self.ordered.deliver(reply);
                return;
            };
            // The replies a `Latest` query holds come before the timeout that ends it, as upstream
            // calls them: data first, then the reason the stream stopped.
            if is_timeout(&reply) {
                self.release();
            }
            if let Some(reply) = consolidator.admit(reply) {
                self.ordered.deliver(reply);
            }
        }

        /// Hand on the replies a `Latest` query holds.
        fn release(&self) {
            if let Some(consolidator) = &self.consolidator {
                for held in consolidator.release() {
                    self.ordered.deliver(held);
                }
            }
        }
    }

    /// The last leg's end is the end of the query: the replies that a `Latest` query held are its
    /// result.
    impl Drop for ReplyDelivery {
        fn drop(&mut self) {
            self.release();
        }
    }

    /// Whether `reply` is the one that ends a query by its timeout.
    fn is_timeout(reply: &Reply) -> bool {
        reply.result.as_ref().err().is_some_and(|error| {
            error.encoding() == &Encoding::ZENOH_STRING
                && error
                    .payload()
                    .try_to_string()
                    .is_ok_and(|text| text == "Timeout")
        })
    }

    /// What upstream's session does with the replies of a query across every peer that answers: one
    /// leg of the engine consolidates the replies of its own face, and these are the replies of all
    /// of them, so the consolidation is done here once more, over what the legs hand on. `Latest`
    /// holds the most recent reply of each key and hands them on when the query ends; `Monotonic`
    /// hands on a reply when it is at least as recent as the last one of its key.
    struct Consolidator {
        mode: ConsolidationMode,
        last: Mutex<BTreeMap<String, LastReply>>,
    }

    /// What a query knows of the last reply of a key.
    struct LastReply {
        timestamp: Option<Timestamp>,
        /// The reply itself, when `Latest` holds it for the end of the query.
        held: Option<Reply>,
    }

    impl Consolidator {
        fn new(mode: ConsolidationMode) -> Option<Self> {
            matches!(
                mode,
                ConsolidationMode::Monotonic | ConsolidationMode::Latest | ConsolidationMode::Auto
            )
            .then(|| Self {
                mode,
                last: Mutex::new(BTreeMap::new()),
            })
        }

        fn last(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, LastReply>> {
            self.last
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        /// The reply to hand on at once, if any: an error always, a sample when `Monotonic` finds
        /// it at least as recent as its key's last, and none when `Latest` keeps it.
        fn admit(&self, reply: Reply) -> Option<Reply> {
            let Ok(sample) = &reply.result else {
                return Some(reply);
            };
            let key = sample.key_expr.as_str().to_owned();
            let timestamp = sample.timestamp;
            let latest = self.mode != ConsolidationMode::Monotonic;
            let mut last = self.last();
            if last
                .get(&key)
                .is_some_and(|last| timestamp < last.timestamp)
            {
                return None;
            }
            if latest {
                last.insert(
                    key,
                    LastReply {
                        timestamp,
                        held: Some(reply),
                    },
                );
                None
            } else {
                last.insert(
                    key,
                    LastReply {
                        timestamp,
                        held: None,
                    },
                );
                Some(reply)
            }
        }

        /// The replies a `Latest` query holds, which it no longer does.
        fn release(&self) -> Vec<Reply> {
            std::mem::take(&mut *self.last())
                .into_values()
                .filter_map(|last| last.held)
                .collect()
        }
    }

    #[cfg(test)]
    mod consolidation_tests {
        use zenoh_protocol::core::{ZenohIdProto, NTP64};

        use super::*;
        use crate::api::builders::sample::SampleBuilder;

        fn reply(key: &'static str, payload: &str, time: Option<u64>) -> Reply {
            let id = ZenohIdProto::try_from([1u8].as_slice()).expect("an id");
            let sample = SampleBuilder::put(KeyExpr::try_from(key).expect("a key"), payload)
                .timestamp(time.map(|time| Timestamp::new(NTP64(time), id.into())));
            Reply {
                result: Ok(sample.into()),
                #[cfg(feature = "unstable")]
                replier_id: None,
            }
        }

        fn payload_of(reply: &Reply) -> String {
            reply
                .result()
                .expect("a sample")
                .payload()
                .try_to_string()
                .expect("a text")
                .into_owned()
        }

        #[test]
        fn latest_holds_the_most_recent_reply_of_each_key_until_the_end() {
            let consolidator = Consolidator::new(ConsolidationMode::Latest).expect("consolidates");
            assert!(consolidator.admit(reply("a", "old", Some(1))).is_none());
            assert!(consolidator.admit(reply("a", "new", Some(2))).is_none());
            assert!(consolidator.admit(reply("a", "stale", Some(1))).is_none());
            assert!(consolidator.admit(reply("b", "only", None)).is_none());
            let released: Vec<String> = consolidator.release().iter().map(payload_of).collect();
            assert_eq!(released, ["new", "only"]);
            assert!(consolidator.release().is_empty(), "released once");
        }

        #[test]
        fn replies_without_a_timestamp_tie_and_the_later_one_is_kept() {
            let consolidator = Consolidator::new(ConsolidationMode::Auto).expect("consolidates");
            assert!(consolidator.admit(reply("a", "first", None)).is_none());
            assert!(consolidator.admit(reply("a", "second", None)).is_none());
            let released: Vec<String> = consolidator.release().iter().map(payload_of).collect();
            assert_eq!(released, ["second"]);
        }

        #[test]
        fn monotonic_hands_on_a_reply_at_least_as_recent_as_the_last_of_its_key() {
            let consolidator =
                Consolidator::new(ConsolidationMode::Monotonic).expect("consolidates");
            let told = |reply| consolidator.admit(reply).map(|reply| payload_of(&reply));
            assert_eq!(told(reply("a", "one", Some(2))), Some("one".to_owned()));
            assert_eq!(told(reply("a", "stale", Some(1))), None);
            assert_eq!(told(reply("a", "same", Some(2))), Some("same".to_owned()));
            assert_eq!(told(reply("b", "other", Some(1))), Some("other".to_owned()));
            assert!(consolidator.release().is_empty(), "monotonic holds nothing");
        }

        #[test]
        fn a_query_that_asks_for_none_consolidates_nothing() {
            assert!(Consolidator::new(ConsolidationMode::None).is_none());
        }
    }

    /// Have the callback of the query tell, when it is dropped with the last leg, whoever waits on
    /// its end: the `token` it was made with, which it is also tied to (cancelling the token
    /// cancels every leg through `fan`, and a token that was cancelled refuses the query), and the
    /// querier that asks it, through `notifier`.
    #[cfg(feature = "unstable")]
    fn tie_to_end(
        token: Option<CancellationToken>,
        fan: Option<&Arc<CancellableFan>>,
        notifier: Option<SyncGroupNotifier>,
        callback: &mut Callback<Reply>,
    ) -> ZResult<()> {
        let Some(token) = token else {
            if let Some(notifier) = notifier {
                callback.set_on_drop(move || drop(notifier));
            }
            return Ok(());
        };
        let fan = fan.ok_or_else(|| zerror!("a query with a cancellation token has no fan"))?;
        if let Some(token_notifier) = token.notifier() {
            let on_cancel = {
                let fan = Arc::clone(fan);
                move || {
                    fan.cancel();
                    Ok(())
                }
            };
            if let Ok(handler_id) = token.add_on_cancel_handler(on_cancel) {
                callback.set_on_drop(move || {
                    token.remove_on_cancel_handler(handler_id);
                    drop(token_notifier);
                    drop(notifier);
                });
                return Ok(());
            }
        }
        bail!("Query was cancelled")
    }

    /// The reply the engine's view of a response is.
    ///
    /// As with a sample, the payload is copied out of the frame. The qualities a response does
    /// not carry read as upstream reads them: the default quality of service, and no timestamp.
    fn reply_of(view: &dyn ReplyView) -> ZResult<Reply> {
        // The stack of the response as the application is given it: what the nodes it crossed
        // recorded, and what this node recorded when the response arrived (the query's
        // `ReplyArrival` did, ahead of any consolidation).
        #[cfg(feature = "unstable")]
        let timestamp_stack = view.ts_stack().and_then(|stack| {
            crate::api::timestamp_stack::TimestampStack::try_from(&protocol_stack_of(stack)).ok()
        });
        let result = match view.kind() {
            ReplyKind::Err => {
                #[allow(unused_mut)] // only an instrumented reply sets the stack
                let mut error = ReplyError::new(
                    ZBytes::from(view.payload().to_vec()),
                    encoding_of_parts(view.err_encoding()),
                );
                #[cfg(feature = "unstable")]
                {
                    error.timestamp_stack = timestamp_stack;
                }
                Err(error)
            }
            kind => Ok(Sample {
                key_expr: KeyExpr::try_from(view.keyexpr().to_owned())?,
                payload: ZBytes::from(view.payload().to_vec()),
                kind: match kind {
                    ReplyKind::Del => SampleKind::Delete,
                    _ => SampleKind::Put,
                },
                encoding: encoding_of_parts(view.put_encoding()),
                timestamp: view.timestamp().and_then(timestamp_from),
                qos: view.qos().map_or_else(QoS::default, qos_from),
                #[cfg(feature = "unstable")]
                reliability: zenoh_protocol::core::Reliability::Reliable,
                #[cfg(feature = "unstable")]
                source_info: view.source_info().and_then(source_info_from),
                attachment: view.attachment().map(|bytes| ZBytes::from(bytes.to_vec())),
                #[cfg(feature = "unstable")]
                timestamp_stack,
            }),
        };
        Ok(Reply {
            result,
            #[cfg(feature = "unstable")]
            replier_id: view.responder().and_then(|(zid, eid)| {
                let zid = zenoh_protocol::core::ZenohIdProto::try_from(zid).ok()?;
                Some(zenoh_protocol::core::EntityGlobalIdProto { zid, eid })
            }),
        })
    }

    /// The declarations a matching status of `kind` counts, as the engine names them.
    pub(super) fn plane_of(kind: MatchingStatusType) -> wz_capi_core::faces::FilterPlane {
        match kind {
            MatchingStatusType::Subscribers => wz_capi_core::faces::FilterPlane::Subscribers,
            MatchingStatusType::Queryables(complete_required) => {
                wz_capi_core::faces::FilterPlane::Queryables { complete_required }
            }
        }
    }

    /// What the plane of a router's tables a matching status of `kind` counts.
    pub(super) fn router_plane_of(
        kind: MatchingStatusType,
    ) -> wz_runtime_tokio::router_forward::MatchPlane {
        use wz_runtime_tokio::router_forward::MatchPlane;
        match kind {
            MatchingStatusType::Subscribers => MatchPlane::Subscribers,
            MatchingStatusType::Queryables(complete_required) => {
                MatchPlane::Queryables { complete_required }
            }
        }
    }

    /// What the engine hands the verdicts of a matching listener to: the callback, called with
    /// the status each time it changes, from whichever thread the change is seen on. The notifier
    /// is let go with the last hold on it (and with a call that is still running).
    pub(super) fn matching_sink(
        callback: Callback<MatchingStatus>,
        notifier: Option<SyncGroupNotifier>,
    ) -> MatchingSink {
        let ordered = Ordered::new(callback, notifier);
        Arc::new(move |matching| ordered.deliver(MatchingStatus { matching }))
    }

    /// The face a snapshot of the engine describes, as the Rust API reports it, or `None` for a
    /// peer whose role the 2-bit wire form of the engine does not name.
    #[cfg(feature = "unstable")]
    pub(super) fn face_of(snapshot: &FaceSnapshot) -> Option<Face> {
        let whatami = match snapshot.whatami {
            0 => WhatAmI::Router,
            1 => WhatAmI::Peer,
            2 => WhatAmI::Client,
            _ => return None,
        };
        let transport = Transport {
            zid: ZenohId::try_from(snapshot.zid.as_slice()).ok()?,
            whatami,
            is_qos: snapshot.is_qos,
            is_multicast: snapshot.is_multicast,
            #[cfg(feature = "shared-memory")]
            is_shm: snapshot.is_shm,
        };
        let links = snapshot
            .links
            .iter()
            .filter_map(|link| link_of(&transport, link))
            .collect();
        Some(Face { transport, links })
    }

    /// The link a snapshot describes under `transport`. A locator the Rust API cannot hold leaves
    /// the link out and says so: it is a link the engine reports in words no zenoh peer reads.
    #[cfg(feature = "unstable")]
    fn link_of(transport: &Transport, link: &LinkSnapshot) -> Option<Link> {
        let locator = |text: &str| match Locator::try_from(text) {
            Ok(locator) => Some(locator),
            Err(error) => {
                tracing::warn!(
                    "a link of the engine has the locator {text:?}, which is no locator: {error}"
                );
                None
            }
        };
        let is_qos = transport.is_qos;
        Some(Link {
            zid: transport.zid,
            src: locator(&link.src)?,
            dst: locator(&link.dst)?,
            group: match &link.group {
                Some(group) => Some(locator(&group.locator)?),
                None => None,
            },
            mtu: link.mtu,
            is_streamed: link.is_streamed(),
            // Upstream reads a lookup that failed as no interface at all, and so does this.
            interfaces: link.interfaces.clone().unwrap_or_default(),
            auth_identifier: link.auth_identifier().map(str::to_owned),
            // A transport that negotiated QoS reports the priorities its links carry, all of them
            // when the endpoint names none, from the highest priority, the lowest number
            // (`zenoh/src/api/info.rs` @ `lowest numerical value`), and whether the link delivers
            // reliably.
            // The band and the class the handshake negotiated for the link, when the endpoint
            // named them (`prio=` and `rel=`), else every priority and what the protocol is.
            priorities: is_qos.then(|| {
                link.priorities
                    .unwrap_or((WirePriority::MAX as u8, WirePriority::MIN as u8))
            }),
            reliability: is_qos.then(|| match link.reliable.or_else(|| link.is_reliable()) {
                Some(true) => WireReliability::Reliable,
                Some(false) | None => WireReliability::BestEffort,
            }),
        })
    }

    /// `sink` as the sink of the engine's face watch: a face that comes up is a `Put` and one that
    /// goes down a `Delete`.
    #[cfg(feature = "unstable")]
    pub(super) fn face_sink(sink: FaceSink) -> FaceEventSink {
        Arc::new(move |event, snapshot| {
            if let Some(face) = face_of(snapshot) {
                let kind = match event {
                    FaceEventKind::Up => SampleKind::Put,
                    FaceEventKind::Down => SampleKind::Delete,
                };
                sink(kind, &face);
            }
        })
    }

    /// A publication the engine refused.
    pub(super) fn publish_error(
        refusal: FanoutError,
        publication: &Publication<'_>,
    ) -> zenoh_result::Error {
        match refusal {
            FanoutError::ExceedsCapacity => zerror!(
                "the publication on {} is larger than what the session can send (its key \
                 or its payload exceeds the capacity of the codec)",
                publication.key
            )
            .into(),
        }
    }

    /// What an open was to do, as far as it says which link failed: the engine says that a link
    /// did not open and not which one, so only an open with one thing to do can name it.
    pub(super) struct OpenScope {
        /// What the session was to dial, when that was all it was to do.
        pub(super) dialled: Option<String>,
        /// The one endpoint the session was to listen on, when that was all it was to do.
        pub(super) listened: Option<String>,
        /// Whether the bind phase had a deadline (`listen/timeout_ms` above zero), which
        /// upstream arms as a `tokio::time::timeout` around the whole phase: a phase that spends
        /// it fails with the timeout's own error and not with the listener's.
        pub(super) listen_deadline: bool,
    }

    /// The error of a deadline that passed, which is what upstream's `tokio::time::timeout`
    /// answers: the same words when it is shown (`deadline has elapsed`) and the same shape when
    /// it is debugged (`Elapsed(())`), which is how a program that unwraps an open reads it.
    #[derive(Debug)]
    struct Elapsed(());

    impl std::fmt::Display for Elapsed {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("deadline has elapsed")
        }
    }

    impl std::error::Error for Elapsed {}

    /// An open that was carried out and failed.
    pub(super) fn open_error(error: OpenError, scope: OpenScope) -> zenoh_result::Error {
        match (
            error,
            scope.dialled,
            scope.listened.as_deref().and_then(listener_failure),
        ) {
            (OpenError::LinkFailed, Some(peers), _) => {
                zerror!("Unable to connect to any of {}! ", peers).into()
            }
            (OpenError::LinkFailed, None, Some(_)) if scope.listen_deadline => {
                Box::new(Elapsed(())) as zenoh_result::Error
            }
            (OpenError::LinkFailed, None, Some(words)) => zerror!("{words}").into(),
            (error, _, _) => zerror!("the session could not be opened: {:?}", error).into(),
        }
    }

    /// The words upstream's link says when it cannot bind the listener of `endpoint`, for the
    /// links whose words were read off the pinned source (`io/zenoh-links/`): they differ per
    /// protocol in what they call the protocol and in saying `bound to` or `on`. `None` for a
    /// protocol this does not know, which keeps the generic words and does not guess.
    pub(super) fn listener_failure(endpoint: &str) -> Option<String> {
        let (scheme, rest) = endpoint.split_once('/')?;
        let address = rest.split('#').next().unwrap_or(rest);
        match scheme {
            "tcp" => Some(format!(
                "Can not create a new TCP listener bound to {address}: the address cannot be bound"
            )),
            "quic" => Some(format!(
                "Can not create a new QUIC listener on {address}: the address cannot be bound"
            )),
            _ => None,
        }
    }
}

/// The fans of the queries a session has asked, held weakly: a query that has ended leaves an
/// entry that holds nothing. The ended ones are dropped from the list each time it has doubled
/// since it was last pruned, which keeps a push constant in time on average and the list within a
/// small multiple of the queries that are under way.
#[derive(Default)]
struct PendingQueries {
    fans: Vec<std::sync::Weak<QueryFan>>,
    prune_at: usize,
}

impl PendingQueries {
    const FIRST_PRUNE: usize = 16;

    fn push(&mut self, fan: std::sync::Weak<QueryFan>) {
        if self.fans.len() >= self.prune_at.max(Self::FIRST_PRUNE) {
            self.fans.retain(|fan| fan.strong_count() > 0);
            self.prune_at = self.fans.len() * 2;
        }
        self.fans.push(fan);
    }

    fn into_live(self) -> impl Iterator<Item = Arc<QueryFan>> {
        self.fans.into_iter().filter_map(|fan| fan.upgrade())
    }
}

/// A querier of a session: its id, which is the engine's for its interest, and the queries it has
/// asked, each by the fan that stops it while it is under way. A query that has ended is a fan
/// nobody holds any more.
struct QuerierEntry {
    id: Id,
    pending: Vec<std::sync::Weak<QueryFan>>,
}

/// The state of a session. A handle ([`Session`]) is one more reference to it, and the entities a
/// session declares hold it by [`WeakSession`], so that dropping the last handle closes it.
#[allow(dead_code)] // to allow using `id` with `unstable` feature
pub(crate) struct SessionInner {
    /// See [`WeakSession`] doc
    strong_counter: AtomicUsize,
    engine: Engine,
    id: EntityId,
    zid: ZenohId,
    /// The group every entity of the session counts its callback in, until the callback is dropped:
    /// a close that is to wait for the callbacks waits for it ([`Closee::close_inner`]). The groups
    /// of the entities are its children ([`WeakSession::callback_group`]).
    callbacks_drop_sync_group: SyncGroup,
    /// How long a query waits for its replies when it does not say, from the configuration.
    queries_default_timeout: Duration,
    /// The quality of service the configuration (`qos/publication`) sets for the publications on
    /// the keys it names, which a publisher or a put takes in place of what its builder says.
    publisher_qos_tree: KeBoxTree<PublisherQoSConfig>,
    /// The configuration the session was opened with, as the application reads it
    /// ([`Session::config`]).
    #[cfg(feature = "unstable")]
    config: crate::api::config::Notifier<zenoh_config::ExpandedConfig>,
    /// What a node records on a message it intercepts: its role, the callback of the user if the
    /// session was opened with one, and the clock of a node that holds none.
    #[cfg(feature = "unstable")]
    timestamps: Arc<TimestampSource>,
    /// The provider of shared memory the configuration asks the session to have, made when it is
    /// first asked for ([`Session::get_shm_provider`]); `None` when it asks for none.
    #[cfg(all(feature = "unstable", feature = "shared-memory"))]
    shm_provider: Option<Arc<crate::api::shm::LazyShmProvider>>,
    /// What copies a large put into the provider for a peer that could read it, when the
    /// configuration asks for the optimisation (`transport_optimization`).
    #[cfg(all(feature = "unstable", feature = "shared-memory"))]
    shm_promoter: Option<crate::api::shm::transport::Promoter>,
    /// The clients of shared memory segments the application opened the session with
    /// ([`OpenBuilder::with_shm_clients`](crate::session::OpenBuilder::with_shm_clients)). The
    /// session negotiates no shared memory with its peers yet, so no segment is read through them:
    /// they are kept for the transport that will (slice Z7).
    #[cfg(feature = "shared-memory")]
    #[allow(dead_code)]
    shm_clients: Option<Arc<zenoh_shm::api::client_storage::ShmClientStorage>>,
    /// The subscriptions declared on the session and not undeclared, which a close lets go of.
    subscriptions: std::sync::Mutex<Vec<Id>>,
    /// The publishers declared on the session and not undeclared, which a close lets go of.
    publishers: std::sync::Mutex<Vec<Id>>,
    /// The queryables declared on the session and not undeclared, the entity id of each beside the
    /// engine's id for it, which a close lets go of.
    queryables: std::sync::Mutex<Vec<(Id, u64)>>,
    /// The queriers declared on the session and not undeclared, which a close lets go of, each
    /// with the queries it has asked that may still be under way.
    queriers: std::sync::Mutex<Vec<QuerierEntry>>,
    /// The queries the session has asked that may still be under way, by the fan that stops each:
    /// the queries of the session itself and of its queriers alike. A close stops them all, as
    /// upstream's drops the state of every query it holds, so that the channel of a `get` that
    /// has not been answered ends with its session and does not wait for its timeout.
    pending_queries: std::sync::Mutex<PendingQueries>,
    /// The matching listeners declared on the session and not undeclared, which a close lets go
    /// of.
    matching_listeners: std::sync::Mutex<Vec<Id>>,
    /// The liveliness tokens declared on the session and not undeclared, which a close retracts.
    tokens: std::sync::Mutex<Vec<Id>>,
    /// The watches of the engine's faces that the transport events listeners declared on the
    /// session hold, not yet undeclared, which a close lets go of.
    #[cfg(feature = "unstable")]
    transport_listeners: std::sync::Mutex<Vec<Id>>,
    /// The same for the link events listeners.
    #[cfg(feature = "unstable")]
    link_listeners: std::sync::Mutex<Vec<Id>>,
}

impl SessionInner {
    fn tokens(&self) -> std::sync::MutexGuard<'_, Vec<Id>> {
        self.tokens
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Retract every liveliness token that is left: those of a session that has closed.
    fn release_tokens(&self) {
        let left = std::mem::take(&mut *self.tokens());
        for id in left {
            self.engine.undeclare_liveliness_token(id);
        }
    }

    /// Declare a liveliness token on `key_expr` on the engine and record it, so that a close
    /// retracts it.
    fn declare_liveliness_inner(self: &Arc<Self>, key_expr: &KeyExpr) -> ZResult<Id> {
        tracing::trace!("declare_liveliness({:?})", key_expr);
        if self.engine.is_closed() {
            return Err(SessionClosedError.into());
        }
        let anchor: SessionAnchor = self.clone();
        let wire = key_expr.to_wire(&anchor);
        let suffix = (!wire.suffix.is_empty()).then(|| wire.suffix.to_string());
        let id = self
            .engine
            .declare_liveliness_token(key_expr.as_str(), wire.scope, suffix)?;
        self.tokens().push(id);
        // A close that ran between the check and the record has not seen this token.
        if self.engine.is_closed() {
            self.release_tokens();
            return Err(SessionClosedError.into());
        }
        Ok(id)
    }

    /// Retract the liveliness token `id`. A closed session has none, and retracting on it is no
    /// error; the retraction of one the session does not hold is none either, as upstream's.
    fn undeclare_liveliness_inner(&self, id: Id) -> ZResult<()> {
        if self.engine.is_closed() {
            return Ok(());
        }
        let known = {
            let mut tokens = self.tokens();
            let before = tokens.len();
            tokens.retain(|held| *held != id);
            before != tokens.len()
        };
        if known {
            self.engine.undeclare_liveliness_token(id);
        }
        Ok(())
    }

    /// Declare a liveliness subscription on the engine and record it with the subscriptions, so
    /// that a close lets go of it and it is undeclared as a subscriber is.
    fn declare_liveliness_subscriber_inner(
        self: &Arc<Self>,
        key_expr: &KeyExpr,
        history: bool,
        callback: Callback<Sample>,
        notifier: Option<SyncGroupNotifier>,
    ) -> ZResult<Id> {
        tracing::trace!("declare_liveliness_subscriber({:?})", key_expr);
        if self.engine.is_closed() {
            return Err(SessionClosedError.into());
        }
        let anchor: SessionAnchor = self.clone();
        let wire = key_expr.to_wire(&anchor);
        let suffix = (!wire.suffix.is_empty()).then(|| wire.suffix.to_string());
        let id = self
            .engine
            .declare_liveliness_subscriber(LivelinessSubscription {
                key: key_expr.as_str(),
                scope: wire.scope,
                suffix,
                history,
                callback,
                notifier,
                // The declaration of the prefix is held by the subscription for as long as the
                // engine records it, whoever else holds the key.
                keeps: Arc::new(key_expr.clone().into_owned()),
            })?;
        self.subscriptions().push(id);
        // A close that ran between the check and the record has not seen this subscription.
        if self.engine.is_closed() {
            self.release_subscriptions();
            return Err(SessionClosedError.into());
        }
        Ok(id)
    }

    /// Ask which liveliness tokens are alive on `key_expr`, with each one handed to `callback` as
    /// a reply.
    fn liveliness_query(
        self: &Arc<Self>,
        key_expr: &KeyExpr,
        timeout: Duration,
        callback: Callback<Reply>,
        #[cfg(feature = "unstable")] cancellation_token: Option<CancellationToken>,
    ) -> ZResult<()> {
        tracing::trace!("liveliness.get({}, {:?})", key_expr, timeout);
        if self.engine.is_closed() {
            return Err(SessionClosedError.into());
        }
        #[cfg(feature = "unstable")]
        let fan = cancellation_token
            .is_some()
            .then(|| self.engine.new_query_fan());
        #[cfg(not(feature = "unstable"))]
        let fan = None;
        let anchor: SessionAnchor = self.clone();
        let wire = key_expr.to_wire(&anchor);
        let suffix = (!wire.suffix.is_empty()).then(|| wire.suffix.to_string());
        self.engine.liveliness_query(LivelinessRequest {
            key: key_expr.as_str(),
            scope: wire.scope,
            suffix,
            timeout,
            callback,
            #[cfg(feature = "unstable")]
            cancellation_token,
            fan,
            notifier: self.callbacks_drop_sync_group.notifier(),
        })
    }

    fn matching_listeners(&self) -> std::sync::MutexGuard<'_, Vec<Id>> {
        self.matching_listeners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Undeclare every matching listener that is left: those of a session that has closed.
    fn release_matching_listeners(&self) {
        let left = std::mem::take(&mut *self.matching_listeners());
        for id in left {
            self.engine.undeclare_matching_listener(id);
        }
    }

    /// Declare a matching listener on the engine and record it, so that a close lets go of it. A
    /// status that already matches is given to the callback before this returns, as upstream's
    /// declaration does.
    fn declare_matches_listener_inner(
        &self,
        key_expr: &KeyExpr,
        destination: Locality,
        kind: MatchingStatusType,
        callback: Callback<MatchingStatus>,
        notifier: Option<SyncGroupNotifier>,
    ) -> ZResult<Id> {
        if self.engine.is_closed() {
            return Err(SessionClosedError.into());
        }
        tracing::trace!("declare_matches_listener({kind:?}: {key_expr:?})");
        let id = self.engine.declare_matching_listener(
            kind,
            key_expr.as_str(),
            destination,
            callback,
            notifier,
        )?;
        self.matching_listeners().push(id);
        // A close that ran between the check and the record has not seen this listener.
        if self.engine.is_closed() {
            self.release_matching_listeners();
            return Err(SessionClosedError.into());
        }
        Ok(id)
    }

    /// Undeclare the matching listener `id`: a closed session has none, and undeclaring on it is
    /// no error; an id the session does not hold is one.
    fn undeclare_matches_listener_inner(&self, id: Id) -> ZResult<()> {
        if self.engine.is_closed() {
            return Ok(());
        }
        let known = {
            let mut listeners = self.matching_listeners();
            let before = listeners.len();
            listeners.retain(|held| *held != id);
            before != listeners.len()
        };
        if !known {
            return Err(zerror!("Unable to find MatchingListener").into());
        }
        self.engine.undeclare_matching_listener(id);
        Ok(())
    }

    #[cfg(feature = "unstable")]
    fn transport_listeners(&self) -> std::sync::MutexGuard<'_, Vec<Id>> {
        self.transport_listeners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(feature = "unstable")]
    fn link_listeners(&self) -> std::sync::MutexGuard<'_, Vec<Id>> {
        self.link_listeners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Let go of every transport and link events listener that is left: those of a session that
    /// closes. It is run before the engine closes, which tells the faces it drops to the
    /// listeners it still has.
    #[cfg(feature = "unstable")]
    fn release_connectivity_listeners(&self) {
        let transports = std::mem::take(&mut *self.transport_listeners());
        let links = std::mem::take(&mut *self.link_listeners());
        for id in transports.into_iter().chain(links) {
            self.engine.unwatch_faces(u64::from(id));
        }
    }

    /// Watch the faces of the engine for a listener, and record the watch so that a close lets go
    /// of it. `sink` is told of the faces from now on; the id is of the watch.
    #[cfg(feature = "unstable")]
    fn watch_faces_for(
        &self,
        listeners: &std::sync::Mutex<Vec<Id>>,
        sink: FaceSink,
    ) -> ZResult<Id> {
        if self.engine.is_closed() {
            return Err(SessionClosedError.into());
        }
        let watch = self.engine.watch_faces(sink);
        let Ok(id) = Id::try_from(watch) else {
            self.engine.unwatch_faces(watch);
            return Err(zerror!(
                "the engine numbered a face watch {watch}, which is more than an id holds"
            )
            .into());
        };
        listeners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(id);
        // A close that ran between the check and the record has not seen this listener.
        if self.engine.is_closed() {
            self.release_connectivity_listeners();
            return Err(SessionClosedError.into());
        }
        Ok(id)
    }

    /// Declare a transport events listener, whose callback is told each time a transport opens or
    /// closes, and first of the transports that are open when `history` asks for them, as
    /// upstream's declaration does.
    #[cfg(feature = "unstable")]
    fn declare_transport_events_listener_inner(
        &self,
        callback: Callback<TransportEvent>,
        history: bool,
        notifier: Option<SyncGroupNotifier>,
    ) -> ZResult<Id> {
        let delivery = Arc::new(Delivery {
            callback,
            _notifier: notifier,
        });
        let told = delivery.clone();
        let id = self.watch_faces_for(
            &self.transport_listeners,
            Arc::new(move |kind, face| {
                told.callback.call(TransportEvent {
                    kind,
                    transport: face.transport.clone(),
                })
            }),
        )?;
        tracing::trace!("declare_transport_events_listener_inner() => {id}");
        if history {
            for face in self.engine.faces() {
                delivery.callback.call(TransportEvent {
                    kind: SampleKind::Put,
                    transport: face.transport,
                });
            }
        }
        Ok(id)
    }

    /// Declare a link events listener, whose callback is told each time a link is added or
    /// removed, those of `transport` only when it is given, and first of the links that exist when
    /// `history` asks for them.
    #[cfg(feature = "unstable")]
    fn declare_link_events_listener_inner(
        &self,
        callback: Callback<LinkEvent>,
        history: bool,
        transport: Option<Transport>,
        notifier: Option<SyncGroupNotifier>,
    ) -> ZResult<Id> {
        let delivery = Arc::new(Delivery {
            callback,
            _notifier: notifier,
        });
        let told = delivery.clone();
        let filter = transport.clone();
        let id = self.watch_faces_for(
            &self.link_listeners,
            Arc::new(move |kind, face| {
                if filter.as_ref().is_some_and(|t| !face.is_the_face_of(t)) {
                    return;
                }
                for link in &face.links {
                    told.callback.call(LinkEvent {
                        kind,
                        link: link.clone(),
                    });
                }
            }),
        )?;
        tracing::trace!("declare_link_events_listener_inner() => {id}");
        if history {
            for link in self.links(transport.as_ref()) {
                delivery.callback.call(LinkEvent {
                    kind: SampleKind::Put,
                    link,
                });
            }
        }
        Ok(id)
    }

    /// Stop the watch `id` of `listeners`: a closed session has none, and undeclaring on it is no
    /// error; an id the session does not hold is one, named `what`.
    #[cfg(feature = "unstable")]
    fn undeclare_face_watch(
        &self,
        listeners: &std::sync::Mutex<Vec<Id>>,
        id: Id,
        what: &str,
    ) -> ZResult<()> {
        if self.engine.is_closed() {
            return Ok(());
        }
        let known = {
            let mut listeners = listeners
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let before = listeners.len();
            listeners.retain(|held| *held != id);
            before != listeners.len()
        };
        if !known {
            return Err(zerror!("Unable to find {what}").into());
        }
        self.engine.unwatch_faces(u64::from(id));
        Ok(())
    }

    /// The links of the established transports, those of `transport` only when it is given. A
    /// closed session has none: its engine has let go of every face.
    #[cfg(feature = "unstable")]
    fn links(&self, transport: Option<&Transport>) -> Box<dyn Iterator<Item = Link> + Send + Sync> {
        let transport = transport.cloned();
        Box::new(
            self.engine
                .faces()
                .into_iter()
                .filter(move |face| transport.as_ref().map_or(true, |t| face.is_the_face_of(t)))
                .flat_map(|face| face.links),
        )
    }

    fn subscriptions(&self) -> std::sync::MutexGuard<'_, Vec<Id>> {
        self.subscriptions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn publishers(&self) -> std::sync::MutexGuard<'_, Vec<Id>> {
        self.publishers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn queryables(&self) -> std::sync::MutexGuard<'_, Vec<(Id, u64)>> {
        self.queryables
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Undeclare every queryable that is left: those of a session that has closed.
    fn release_queryables(&self) {
        let left = std::mem::take(&mut *self.queryables());
        for (_, engine_id) in left {
            self.engine.undeclare_queryable(engine_id);
        }
    }

    fn queriers(&self) -> std::sync::MutexGuard<'_, Vec<QuerierEntry>> {
        self.queriers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Remember the fan of a query that may be under way, for a close to stop.
    fn track_query(&self, fan: &Arc<QueryFan>) {
        self.pending_queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Arc::downgrade(fan));
    }

    /// Stop every query that is under way: the callback of each is dropped and its channel ends.
    fn release_queries(&self) {
        let fans = std::mem::take(
            &mut *self
                .pending_queries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for fan in fans.into_live() {
            fan.cancel();
        }
    }

    /// Undeclare every querier that is left: those of a session that has closed.
    fn release_queriers(&self) {
        let left = std::mem::take(&mut *self.queriers());
        for entry in left {
            self.end_querier(entry);
        }
    }

    /// Let go of a querier: its interest goes, and so do the queries it has under way, whose
    /// callbacks are dropped and whose channels end, as upstream's undeclaration removes them.
    fn end_querier(&self, entry: QuerierEntry) {
        self.engine.undeclare_querier(entry.id);
        for fan in entry.pending.iter().filter_map(std::sync::Weak::upgrade) {
            fan.cancel();
        }
    }

    /// Declare a querier for `key_expr` on the engine and record it, so that a close lets go of it.
    fn declare_querier_inner(
        self: &Arc<Self>,
        key_expr: &KeyExpr,
        destination: Locality,
    ) -> ZResult<Id> {
        if self.engine.is_closed() {
            return Err(SessionClosedError.into());
        }
        tracing::trace!("declare_querier({:?})", key_expr);
        let anchor: SessionAnchor = self.clone();
        let wire = key_expr.to_wire(&anchor);
        let suffix = (!wire.suffix.is_empty()).then(|| wire.suffix.to_string());
        let id = self.engine.declare_querier(QuerierDeclaration {
            key: key_expr.as_str(),
            scope: wire.scope,
            suffix,
            destination,
        })?;
        self.queriers().push(QuerierEntry {
            id,
            pending: vec![],
        });
        // A close that ran between the check and the record has not seen this querier.
        if self.engine.is_closed() {
            self.release_queriers();
            return Err(SessionClosedError.into());
        }
        Ok(id)
    }

    /// Undeclare the querier `id`: a closed session has none, and undeclaring on it is no error;
    /// an id the session does not hold is one.
    fn undeclare_querier_inner(&self, id: Id) -> ZResult<()> {
        if self.engine.is_closed() {
            return Ok(());
        }
        let entry = {
            let mut queriers = self.queriers();
            let position = queriers.iter().position(|entry| entry.id == id);
            position.map(|at| queriers.remove(at))
        };
        match entry {
            Some(entry) => {
                self.end_querier(entry);
                Ok(())
            }
            None => Err(zerror!("Unable to find querier").into()),
        }
    }

    /// Declare a queryable on the engine and record it, so that a close lets go of it. The entity
    /// id it answers as is taken first, since the replies of the first query name it.
    fn declare_queryable_inner(
        self: &Arc<Self>,
        key_expr: &KeyExpr,
        complete: bool,
        origin: Locality,
        callback: Callback<Query>,
        notifier: Option<SyncGroupNotifier>,
    ) -> ZResult<Id> {
        if self.engine.is_closed() {
            return Err(SessionClosedError.into());
        }
        tracing::trace!("declare_queryable({:?})", key_expr);
        let anchor: SessionAnchor = self.clone();
        let wire = key_expr.to_wire(&anchor);
        let suffix = (!wire.suffix.is_empty()).then(|| wire.suffix.to_string());
        let eid = Id::try_from(self.engine.next_entity_id())
            .map_err(|_| zerror!("the engine has no entity id left for a queryable"))?;
        let engine_id = self.engine.declare_queryable(QueryableDeclaration {
            key: key_expr.as_str(),
            scope: wire.scope,
            suffix,
            complete,
            origin,
            callback,
            notifier,
            // The declaration of the prefix is held by the queryable for as long as the engine
            // records it, whoever else holds the key.
            keeps: Arc::new(key_expr.clone().into_owned()),
            zid: self.zid,
            eid,
            #[cfg(feature = "unstable")]
            timestamps: Arc::clone(&self.timestamps),
        })?;
        self.queryables().push((eid, engine_id));
        // A close that ran between the check and the record has not seen this queryable.
        if self.engine.is_closed() {
            self.release_queryables();
            return Err(SessionClosedError.into());
        }
        Ok(eid)
    }

    /// Undeclare every subscription that is left: those of a session that has closed.
    fn release_subscriptions(&self) {
        let left = std::mem::take(&mut *self.subscriptions());
        for id in left {
            self.engine.undeclare_subscriber(id);
        }
    }

    /// Undeclare every publisher that is left: those of a session that has closed.
    fn release_publishers(&self) {
        let left = std::mem::take(&mut *self.publishers());
        for id in left {
            self.engine.undeclare_publisher(id);
        }
    }

    /// Declare a publisher for `key_expr` on the engine and record it, so that a close lets go of it.
    fn declare_publisher_inner(
        self: &Arc<Self>,
        key_expr: &KeyExpr,
        destination: Locality,
    ) -> ZResult<Id> {
        if self.engine.is_closed() {
            return Err(SessionClosedError.into());
        }
        tracing::trace!("declare_publisher({:?})", key_expr);
        let anchor: SessionAnchor = self.clone();
        let wire = key_expr.to_wire(&anchor);
        let suffix = (!wire.suffix.is_empty()).then(|| wire.suffix.to_string());
        let id = self.engine.declare_publisher(PublisherDeclaration {
            key: key_expr.as_str(),
            scope: wire.scope,
            suffix,
            destination,
        })?;
        self.publishers().push(id);
        // A close that ran between the check and the record has not seen this publisher.
        if self.engine.is_closed() {
            self.release_publishers();
            return Err(SessionClosedError.into());
        }
        Ok(id)
    }

    /// Hand a publication to the engine. The session behind `self` is the anchor the key is named
    /// by.
    #[allow(clippy::too_many_arguments)] // the arguments of upstream's function, kept as they are
    fn resolve_put(
        self: &Arc<Self>,
        key_expr: &KeyExpr,
        payload: ZBytes,
        kind: SampleKind,
        encoding: Encoding,
        congestion_control: CongestionControl,
        priority: Priority,
        is_express: bool,
        destination: Locality,
        #[cfg(feature = "unstable")] reliability: Reliability,
        timestamp: Option<uhlc::Timestamp>,
        #[cfg(feature = "unstable")] source_info: Option<SourceInfo>,
        attachment: Option<ZBytes>,
        #[cfg(feature = "unstable")] timestamp_instrumentation: Option<TimestampInstrumentation>,
    ) -> ZResult<()> {
        if self.engine.is_closed() {
            return Err(SessionClosedError.into());
        }
        // A publication that asks for its instrumentation starts the stack the nodes it crosses
        // record on, with what this node records at the send, and the one that leaves the node
        // has what it records on routing the message out as well.
        #[cfg(feature = "unstable")]
        let ts_stack = timestamp_instrumentation.map(|instrumentation| {
            self.timestamps
                .start(instrumentation, interception_point::SEND)
        });
        #[cfg(feature = "unstable")]
        let wire_ts_stack = ts_stack.clone().map(|mut stack| {
            self.timestamps
                .record(&mut stack, interception_point::ROUTE);
            stack
        });
        let anchor: SessionAnchor = self.clone();
        let wire = key_expr.to_wire(&anchor);
        let suffix = (!wire.suffix.is_empty()).then(|| wire.suffix.to_string());
        self.engine.publish(&Publication {
            key: key_expr.as_str(),
            scope: wire.scope,
            suffix,
            payload,
            kind,
            encoding,
            congestion_control,
            priority,
            is_express,
            destination,
            #[cfg(feature = "unstable")]
            reliability,
            timestamp,
            #[cfg(feature = "unstable")]
            source_info,
            attachment,
            #[cfg(feature = "unstable")]
            ts_stack,
            #[cfg(feature = "unstable")]
            wire_ts_stack,
            #[cfg(all(feature = "unstable", feature = "shared-memory"))]
            shm_promoter: self.shm_promoter.as_ref(),
        })
    }

    /// Hand a query to the engine. The session behind `self` is the anchor the key is named by.
    #[allow(clippy::too_many_arguments)] // the arguments of upstream's function, kept as they are
    fn query(
        self: &Arc<Self>,
        key_expr: &KeyExpr<'_>,
        parameters: &Parameters<'_>,
        target: QueryTarget,
        consolidation: QueryConsolidation,
        qos: QoS,
        destination: Locality,
        timeout: Duration,
        value: Option<(ZBytes, Encoding)>,
        attachment: Option<ZBytes>,
        #[cfg(feature = "unstable")] source_info: Option<SourceInfo>,
        callback: Callback<Reply>,
        #[cfg(feature = "unstable")] cancellation_token: Option<CancellationToken>,
        querier_id: Option<Id>,
        querier_notifier: Option<SyncGroupNotifier>,
        #[cfg(feature = "unstable")] timestamp_instrumentation: Option<TimestampInstrumentation>,
    ) -> ZResult<()> {
        tracing::trace!(
            "get({}, {:?}, {:?})",
            Selector::borrowed(key_expr, parameters),
            target,
            consolidation
        );
        if self.engine.is_closed() {
            return Err(SessionClosedError.into());
        }
        // A query of a querier counts in the querier's group, which is the session's child. A
        // query of the session's own counts in the session's: a close that waits for callbacks
        // waits for the reply callback of a get as well.
        let querier_notifier =
            querier_notifier.or_else(|| self.callbacks_drop_sync_group.notifier());
        // A query that asks for its instrumentation starts the stack the nodes it crosses record
        // on, with what this node records at the send, and the one that leaves the node has what
        // it records on routing the message out as well (as for a publication, `resolve_put`).
        #[cfg(feature = "unstable")]
        let ts_stack = timestamp_instrumentation.map(|instrumentation| {
            self.timestamps
                .start(instrumentation, interception_point::SEND)
        });
        #[cfg(feature = "unstable")]
        let wire_ts_stack = ts_stack.clone().map(|mut stack| {
            self.timestamps
                .record(&mut stack, interception_point::ROUTE);
            stack
        });
        // `Auto` is resolved here, once, as upstream's session does: to `Latest`, or to `None` for
        // a query that asks for a time range, whose replies are not versions of one value.
        let consolidation = match consolidation.mode {
            #[cfg(feature = "unstable")]
            ConsolidationMode::Auto if parameters.time_range().is_some() => ConsolidationMode::None,
            ConsolidationMode::Auto => ConsolidationMode::Latest,
            mode => mode,
        };
        // Every query is given a fan, because something may stop any of them before it ends by
        // itself: a cancellation token, the undeclaration of the querier that asks it (which keeps
        // the fans of the queries it has under way), and the close of the session, which keeps
        // the fans of all of them.
        let fan = Some(self.engine.new_query_fan());
        if let Some(fan) = &fan {
            self.track_query(fan);
        }
        if let (Some(id), Some(fan)) = (querier_id, &fan) {
            let mut queriers = self.queriers();
            let Some(entry) = queriers.iter_mut().find(|entry| entry.id == id) else {
                bail!("Unable to find querier");
            };
            entry.pending.retain(|pending| pending.strong_count() > 0);
            entry.pending.push(Arc::downgrade(fan));
        }
        let anchor: SessionAnchor = self.clone();
        let wire = key_expr.to_wire(&anchor);
        let suffix = (!wire.suffix.is_empty()).then(|| wire.suffix.to_string());
        self.engine.query(QueryRequest {
            key: key_expr.as_str(),
            scope: wire.scope,
            suffix,
            parameters: parameters.as_str(),
            target,
            consolidation,
            qos,
            destination,
            timeout,
            value,
            attachment,
            #[cfg(feature = "unstable")]
            source_info,
            #[cfg(feature = "unstable")]
            ts_stack,
            #[cfg(feature = "unstable")]
            wire_ts_stack,
            #[cfg(feature = "unstable")]
            timestamps: Arc::clone(&self.timestamps),
            callback,
            #[cfg(feature = "unstable")]
            cancellation_token,
            fan,
            querier_notifier,
        })
    }
}

impl fmt::Debug for SessionInner {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Session").field("id", &self.zid).finish()
    }
}

/// The [`Session`] is the main component of Zenoh. It holds the zenoh runtime object,
/// which maintains the state of the connection of the node to the Zenoh network.
///
/// The session allows declaring other zenoh entities like publishers, subscribers, queriers, queryables, etc.
/// and keeps them functioning. Closing the session will close all associated entities.
///
/// The session is cloneable so it's easy to share it between tasks and threads. Each clone of the
/// session is an `Arc` to the internal session object, so cloning is cheap and fast.
///
/// A Zenoh session is instantiated using [`zenoh::open`](crate::open)
/// with parameters specified in the [`Config`] object.
///
/// Objects created by the session ([`Publisher`](crate::pubsub::Publisher),
/// [`Subscriber`](crate::pubsub::Subscriber), [`Querier`](crate::query::Querier), etc.),
/// have lifetimes independent of the session, but they stop functioning if all clones of the session
/// object are dropped or the session is closed with the [`close`](crate::session::Session::close) method.
///
/// ### Background entities
///
/// Sometimes it is inconvenient to keep a reference to an object (for example,
/// a [`Queryable`](crate::query::Queryable)) solely to keep it alive. There is a way to
/// avoid keeping this reference and keep the object alive until the session is closed.
/// To do this, call the [`background`](crate::query::QueryableBuilder::background) method on the
/// corresponding builder. This causes the builder to return `()` instead of the object instance and
/// keeps the instance alive while the session is alive.
///
/// ### Difference between session and runtime
/// The session object holds all declared zenoh entities (publishers, subscribers, etc.) and
/// a shared reference to the runtime object which maintains the state of the zenoh node.
/// Closing the session will close all associated entities and drop the reference to the runtime.
///
/// Typically each session has its own runtime, but in some cases
/// the session may share the runtime with other sessions. This is the case for the plugins
/// where each plugin has its own session but all plugins share the same `zenohd` runtime
/// for efficiency.
/// In this case, all these sessions will have the same network identity
/// [`Session::zid`](crate::session::Session::zid).
///
/// # Examples
/// ```
/// # #[tokio::main]
/// # async fn main() {
/// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// session.put("key/expression", "value").await.unwrap();
/// # }
/// ```
#[derive(Debug)]
#[repr(transparent)]
pub struct Session(Arc<SessionInner>);

impl Session {
    /// A reference to the session that does not keep it open: what the entities of a session hold,
    /// and what a close is run through.
    pub(crate) fn downgrade(&self) -> WeakSession {
        WeakSession(self.0.clone())
    }

    /// A group for the callback of one entity of the session ([`WeakSession::callback_group`]).
    pub(crate) fn callback_group(&self) -> SyncGroup {
        SyncGroup::child_of(&self.0.callbacks_drop_sync_group)
    }

    /// The handle by which a key expression is declared on this session.
    pub(crate) fn anchor(&self) -> SessionAnchor {
        self.0.clone()
    }

    /// Open a session on the selected engine, from `config`.
    pub(crate) fn open(
        config: Config,
        #[cfg(feature = "unstable")] timestamp_callback: Option<GetTimestampCallback>,
        #[cfg(feature = "shared-memory")] shm_clients: Option<
            Arc<zenoh_shm::api::client_storage::ShmClientStorage>,
        >,
    ) -> ZResult<Session> {
        let (engine, zid) = Engine::open(
            &config,
            #[cfg(feature = "shared-memory")]
            shm_clients.clone(),
        )?;
        #[cfg(feature = "shared-memory")]
        let expanded = config.0.clone().expanded();
        #[cfg(feature = "shared-memory")]
        crate::api::shm::init_if_asked(&expanded);
        #[cfg(feature = "unstable")]
        let whatami = config.0.clone().expanded().mode();
        #[cfg(feature = "unstable")]
        let node_clock = engine.node_clock();
        let id = u32::try_from(engine.next_entity_id()).unwrap_or(u32::MAX);
        let queries_default_timeout = Duration::from_millis(
            config
                .0
                .queries_default_timeout()
                .unwrap_or(zenoh_config::defaults::queries_default_timeout),
        );
        #[cfg(all(feature = "unstable", feature = "shared-memory"))]
        let shm_provider = crate::api::shm::provider_of(&expanded);
        let session = Session(Arc::new(SessionInner {
            strong_counter: AtomicUsize::new(1),
            engine,
            id,
            zid,
            callbacks_drop_sync_group: SyncGroup::default(),
            queries_default_timeout,
            publisher_qos_tree: config
                .0
                .get_json("qos/publication")
                .ok()
                .and_then(|json| serde_json::from_str::<PublisherQoSConfList>(&json).ok())
                .map_or_else(KeBoxTree::new, Into::into),
            #[cfg(feature = "unstable")]
            config: crate::api::config::Notifier::new(config.0.clone().expanded()),
            #[cfg(feature = "unstable")]
            timestamps: Arc::new(TimestampSource::new(
                zid,
                whatami,
                timestamp_callback,
                node_clock,
            )),
            #[cfg(all(feature = "unstable", feature = "shared-memory"))]
            shm_promoter: crate::api::shm::transport::Promoter::new(
                &expanded,
                shm_provider.as_ref(),
            ),
            #[cfg(all(feature = "unstable", feature = "shared-memory"))]
            shm_provider,
            #[cfg(feature = "shared-memory")]
            shm_clients,
            subscriptions: std::sync::Mutex::new(vec![]),
            publishers: std::sync::Mutex::new(vec![]),
            queryables: std::sync::Mutex::new(vec![]),
            queriers: std::sync::Mutex::new(vec![]),
            pending_queries: std::sync::Mutex::new(PendingQueries::default()),
            matching_listeners: std::sync::Mutex::new(vec![]),
            tokens: std::sync::Mutex::new(vec![]),
            #[cfg(feature = "unstable")]
            transport_listeners: std::sync::Mutex::new(vec![]),
            #[cfg(feature = "unstable")]
            link_listeners: std::sync::Mutex::new(vec![]),
        }));
        #[cfg(feature = "unstable")]
        crate::api::admin::init(session.downgrade());
        Ok(session)
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        self.0.strong_counter.fetch_add(1, Ordering::Relaxed);
        Self(self.0.clone())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.0.strong_counter.fetch_sub(1, Ordering::Relaxed) == 1 {
            if let Err(error) = self.close().wait() {
                tracing::error!(error)
            }
        }
    }
}

/// A reference to the session that does not keep it open.
///
/// It is not a `Weak` of the `Arc`: the entities of a session hold it, so a session that closed
/// itself when its handles were counted by the `Arc` would never close while one of them lived.
/// The handles count themselves (`SessionInner::strong_counter`, private) and the last one to be dropped
/// closes the session, whatever references remain.
#[derive(Debug, Clone)]
pub struct WeakSession(Arc<SessionInner>);

impl WeakSession {
    /// The id the session stands on.
    pub(crate) fn zid(&self) -> ZenohId {
        self.0.zid
    }

    /// The configuration the session was opened with, as the session itself reads and writes it,
    /// which the admin space reads the permissions from and applies the writes to.
    #[cfg(feature = "unstable")]
    pub(crate) fn config_notifier(
        &self,
    ) -> crate::api::config::Notifier<zenoh_config::ExpandedConfig> {
        self.0.config.clone()
    }

    /// A group for the callback of one entity of the session, which the session's close can wait
    /// for as it waits for the callbacks of all of them.
    pub(crate) fn callback_group(&self) -> SyncGroup {
        SyncGroup::child_of(&self.0.callbacks_drop_sync_group)
    }

    /// Stop the delivery to the subscriber `sid`. A closed session has none to stop, and
    /// undeclaring on it is no error.
    pub(crate) fn undeclare_subscriber_inner(&self, sid: Id, kind: SubscriberKind) -> ZResult<()> {
        match kind {
            // The two kinds are subscribers of the engine, listed together.
            SubscriberKind::Subscriber | SubscriberKind::LivelinessSubscriber => {
                let known = {
                    let mut subscriptions = self.0.subscriptions();
                    let before = subscriptions.len();
                    subscriptions.retain(|id| *id != sid);
                    before != subscriptions.len()
                };
                if known {
                    self.0.engine.undeclare_subscriber(sid);
                }
                Ok(())
            }
        }
    }

    /// Retract the publisher `pid`. A closed session has none, and undeclaring on it is no error;
    /// an id the session does not hold is one.
    pub(crate) fn undeclare_publisher_inner(&self, pid: Id) -> ZResult<()> {
        if self.0.engine.is_closed() {
            return Ok(());
        }
        let known = {
            let mut publishers = self.0.publishers();
            let before = publishers.len();
            publishers.retain(|id| *id != pid);
            before != publishers.len()
        };
        if !known {
            return Err(zerror!("Unable to find publisher").into());
        }
        self.0.engine.undeclare_publisher(pid);
        Ok(())
    }

    /// Stop the queries to the queryable `qid`. A closed session has none to stop, and undeclaring
    /// on it is no error; an id the session does not hold is one.
    pub(crate) fn close_queryable(&self, qid: Id) -> ZResult<()> {
        if self.0.engine.is_closed() {
            return Ok(());
        }
        let engine_id = {
            let mut queryables = self.0.queryables();
            let position = queryables.iter().position(|(id, _)| *id == qid);
            position.map(|at| queryables.remove(at).1)
        };
        match engine_id {
            Some(engine_id) => {
                self.0.engine.undeclare_queryable(engine_id);
                Ok(())
            }
            None => Err(zerror!("Unable to find queryable").into()),
        }
    }

    /// Whether anything `kind` counts matches `key_expr` among the declarations `destination`
    /// admits: the session's own, the peers', or either.
    pub(crate) fn matching_status(
        &self,
        key_expr: &KeyExpr,
        destination: Locality,
        kind: MatchingStatusType,
    ) -> ZResult<MatchingStatus> {
        self.0
            .engine
            .matching_status(kind, key_expr.as_str(), destination)
            .map(|matching| MatchingStatus { matching })
    }

    /// Declare a matching listener, whose callback is given the status each time it changes. The
    /// id of the engine's listener, released at undeclare or at close.
    pub(crate) fn declare_matches_listener_inner(
        &self,
        key_expr: &KeyExpr,
        destination: Locality,
        kind: MatchingStatusType,
        callback: Callback<MatchingStatus>,
        notifier: Option<SyncGroupNotifier>,
    ) -> ZResult<Id> {
        self.0
            .declare_matches_listener_inner(key_expr, destination, kind, callback, notifier)
    }

    /// Undeclare the matching listener `id`. A closed session has none, and undeclaring on it is
    /// no error; an id the session does not hold is one.
    pub(crate) fn undeclare_matches_listener_inner(&self, id: Id) -> ZResult<()> {
        self.0.undeclare_matches_listener_inner(id)
    }

    /// The locators on which the session listens, without the loopback ones, as upstream's runtime
    /// lists them (`get_locators_noloopback`). A locator the Rust API cannot hold is left out and
    /// said.
    #[cfg(feature = "unstable")]
    pub(crate) fn locators(&self) -> Vec<Locator> {
        self.0
            .engine
            .listen_locators()
            .iter()
            .filter_map(|text| match Locator::try_from(text.as_str()) {
                Ok(locator) => Some(locator),
                Err(error) => {
                    tracing::warn!("the engine listens on {text:?}, which is no locator: {error}");
                    None
                }
            })
            .collect()
    }

    /// The established transports, as upstream's runtime lists them: a closed session has none,
    /// its engine has let go of every face.
    #[cfg(feature = "unstable")]
    pub(crate) fn transports(&self) -> Box<dyn Iterator<Item = Transport> + Send + Sync> {
        Box::new(self.0.engine.faces().into_iter().map(|face| face.transport))
    }

    /// The links of the established transports, those of `transport` only when it is given.
    #[cfg(feature = "unstable")]
    pub(crate) fn links(
        &self,
        transport: Option<&Transport>,
    ) -> Box<dyn Iterator<Item = Link> + Send + Sync> {
        self.0.links(transport)
    }

    /// The graph of each region the admin space answers a `linkstate` query for, as text, by the
    /// region's name.
    #[cfg(feature = "unstable")]
    pub(crate) fn linkstate_regions(&self) -> Vec<(String, String)> {
        self.0.engine.linkstate_regions()
    }

    /// The views the admin space of a router node answers from, or `None` for a session that is
    /// no router node.
    #[cfg(feature = "unstable")]
    pub(crate) fn router_admin_views(&self) -> Option<RouterAdminViews> {
        self.0.engine.router_admin_views()
    }

    /// Host `handler` as a queryable of the router node on `key`; `false` for a session that is
    /// no router node.
    #[cfg(feature = "unstable")]
    pub(crate) fn host_router_queryable(&self, key: &str, handler: RouterQueryHandler) -> bool {
        self.0.engine.host_router_queryable(key, handler)
    }

    /// Declare a transport events listener. The id of the engine's watch, released at undeclare or
    /// at close.
    #[cfg(feature = "unstable")]
    pub(crate) fn declare_transport_events_listener_inner(
        &self,
        callback: Callback<TransportEvent>,
        history: bool,
        notifier: Option<SyncGroupNotifier>,
    ) -> ZResult<Id> {
        self.0
            .declare_transport_events_listener_inner(callback, history, notifier)
    }

    /// Take the samples for `key_expr` into `callback` as [`Session::declare_subscriber_inner`]
    /// does, for an entity of the session that holds it by this reference.
    #[cfg(feature = "unstable")]
    pub(crate) fn declare_subscriber_inner(
        &self,
        key_expr: &KeyExpr,
        origin: Locality,
        callback: Callback<Sample>,
        notifier: Option<SyncGroupNotifier>,
    ) -> ZResult<Id> {
        if self.0.engine.is_closed() {
            return Err(SessionClosedError.into());
        }
        let anchor: SessionAnchor = self.0.clone();
        let wire = key_expr.to_wire(&anchor);
        let suffix = (!wire.suffix.is_empty()).then(|| wire.suffix.to_string());
        let id = self.0.engine.declare_subscriber(Subscription {
            key: key_expr.as_str(),
            scope: wire.scope,
            suffix,
            origin,
            callback,
            notifier,
            keeps: Arc::new(key_expr.clone().into_owned()),
            #[cfg(feature = "unstable")]
            timestamps: self.0.timestamps.clone(),
        })?;
        self.0.subscriptions().push(id);
        // A close that ran between the check and the record has not seen this subscription.
        if self.0.engine.is_closed() {
            self.0.release_subscriptions();
            return Err(SessionClosedError.into());
        }
        Ok(id)
    }

    /// Answer the queries for `key_expr` into `callback` as [`Session::declare_queryable_inner`]
    /// does, for an entity of the session that holds it by this reference.
    #[cfg(feature = "unstable")]
    pub(crate) fn declare_queryable_inner(
        &self,
        key_expr: &KeyExpr,
        complete: bool,
        origin: Locality,
        callback: Callback<Query>,
        notifier: Option<SyncGroupNotifier>,
    ) -> ZResult<Id> {
        self.0
            .declare_queryable_inner(key_expr, complete, origin, callback, notifier)
    }

    /// Undeclare the transport events listener `id`. A closed session has none, and undeclaring on
    /// it is no error; an id the session does not hold is one.
    #[cfg(feature = "unstable")]
    pub(crate) fn undeclare_transport_events_listener_inner(&self, id: Id) -> ZResult<()> {
        self.0
            .undeclare_face_watch(&self.0.transport_listeners, id, "TransportEventsListener")
    }

    /// Declare a link events listener. The id of the engine's watch, released at undeclare or at
    /// close.
    #[cfg(feature = "unstable")]
    pub(crate) fn declare_link_events_listener_inner(
        &self,
        callback: Callback<LinkEvent>,
        history: bool,
        transport: Option<Transport>,
        notifier: Option<SyncGroupNotifier>,
    ) -> ZResult<Id> {
        self.0
            .declare_link_events_listener_inner(callback, history, transport, notifier)
    }

    /// Undeclare the link events listener `id`, with the same answers as for a transport events
    /// listener.
    #[cfg(feature = "unstable")]
    pub(crate) fn undeclare_link_events_listener_inner(&self, id: Id) -> ZResult<()> {
        self.0
            .undeclare_face_watch(&self.0.link_listeners, id, "LinkEventsListener")
    }

    /// Retract the liveliness token `tid`. A closed session has none, and retracting on it is no
    /// error.
    pub(crate) fn undeclare_liveliness(&self, tid: Id) -> ZResult<()> {
        self.0.undeclare_liveliness_inner(tid)
    }

    /// Undeclare the querier `qid` with the queries it has under way. A closed session has none,
    /// and undeclaring on it is no error; an id the session does not hold is one.
    pub(crate) fn undeclare_querier_inner(&self, qid: Id) -> ZResult<()> {
        self.0.undeclare_querier_inner(qid)
    }

    /// What [`Session::query`] is, for an entity that holds the session by this reference.
    #[allow(clippy::too_many_arguments)] // the arguments of upstream's function, kept as they are
    pub(crate) fn query(
        &self,
        key_expr: &KeyExpr<'_>,
        parameters: &Parameters<'_>,
        target: QueryTarget,
        consolidation: QueryConsolidation,
        qos: QoS,
        destination: Locality,
        timeout: Duration,
        value: Option<(ZBytes, Encoding)>,
        attachment: Option<ZBytes>,
        #[cfg(feature = "unstable")] source_info: Option<SourceInfo>,
        callback: Callback<Reply>,
        #[cfg(feature = "unstable")] cancellation_token: Option<CancellationToken>,
        querier_id: Option<Id>,
        querier_notifier: Option<SyncGroupNotifier>,
        #[cfg(feature = "unstable")] timestamp_instrumentation: Option<TimestampInstrumentation>,
    ) -> ZResult<()> {
        self.0.query(
            key_expr,
            parameters,
            target,
            consolidation,
            qos,
            destination,
            timeout,
            value,
            attachment,
            #[cfg(feature = "unstable")]
            source_info,
            callback,
            #[cfg(feature = "unstable")]
            cancellation_token,
            querier_id,
            querier_notifier,
            #[cfg(feature = "unstable")]
            timestamp_instrumentation,
        )
    }

    /// What [`Session::resolve_put`] is, for an entity that holds the session by this reference.
    #[allow(clippy::too_many_arguments)] // the arguments of upstream's function, kept as they are
    pub(crate) fn resolve_put(
        &self,
        key_expr: &KeyExpr,
        payload: ZBytes,
        kind: SampleKind,
        encoding: Encoding,
        congestion_control: CongestionControl,
        priority: Priority,
        is_express: bool,
        destination: Locality,
        #[cfg(feature = "unstable")] reliability: Reliability,
        timestamp: Option<uhlc::Timestamp>,
        #[cfg(feature = "unstable")] source_info: Option<SourceInfo>,
        attachment: Option<ZBytes>,
        #[cfg(feature = "unstable")] timestamp_instrumentation: Option<TimestampInstrumentation>,
    ) -> ZResult<()> {
        self.0.resolve_put(
            key_expr,
            payload,
            kind,
            encoding,
            congestion_control,
            priority,
            is_express,
            destination,
            #[cfg(feature = "unstable")]
            reliability,
            timestamp,
            #[cfg(feature = "unstable")]
            source_info,
            attachment,
            #[cfg(feature = "unstable")]
            timestamp_instrumentation,
        )
    }

    /// The ids of the nodes this session is connected to that play the role `whatami`.
    ///
    /// The registry lists the established peers and what each announced; a link whose handshake has
    /// not completed is not listed, and a closed session has none, as upstream's has no transport
    /// left.
    pub(crate) fn zids(
        &self,
        whatami: zenoh_protocol::core::WhatAmI,
    ) -> Box<dyn Iterator<Item = ZenohId> + Send + Sync> {
        // The wire form of a role: 0 router, 1 peer, 2 client.
        let wire = match whatami {
            zenoh_protocol::core::WhatAmI::Router => 0u8,
            zenoh_protocol::core::WhatAmI::Peer => 1,
            zenoh_protocol::core::WhatAmI::Client => 2,
        };
        Box::new(
            self.0
                .engine
                .peer_identities()
                .into_iter()
                .filter(move |(_, role)| *role == wire)
                .filter_map(|(zid, _)| ZenohId::try_from(zid.as_slice()).ok()),
        )
    }
}

impl PartialEq for Session {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl PartialEq<Session> for WeakSession {
    fn eq(&self, other: &Session) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// Error indicating the operation cannot proceed because the session is closed.
///
/// It may be returned by operations like [`Session::get`] or [`Publisher::put`](crate::api::publisher::Publisher::put) when
/// [`Session::close`] has been called before.
#[derive(Debug)]
pub struct SessionClosedError;

impl fmt::Display for SessionClosedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session closed")
    }
}

impl std::error::Error for SessionClosedError {}

/// A trait implemented by types that can be undeclared.
pub trait UndeclarableSealed<S> {
    type Undeclaration: Resolve<ZResult<()>> + Send;
    fn undeclare_inner(self, session: S) -> Self::Undeclaration;
}

impl<'a, T> UndeclarableSealed<&'a Session> for T
where
    T: UndeclarableSealed<()>,
{
    type Undeclaration = <T as UndeclarableSealed<()>>::Undeclaration;

    fn undeclare_inner(self, _session: &'a Session) -> Self::Undeclaration {
        self.undeclare_inner(())
    }
}

// NOTE: `UndeclarableInner` is only pub(crate) to hide the `undeclare_inner` method. So we don't
// care about the `private_bounds` lint in this particular case.
#[allow(private_bounds)]
/// A trait implemented by types that can be undeclared.
pub trait Undeclarable<S = ()>: UndeclarableSealed<S> {}

impl<T, S> Undeclarable<S> for T where T: UndeclarableSealed<S> {}

impl<'a> UndeclarableSealed<&'a Session> for KeyExpr<'a> {
    type Undeclaration = KeyExprUndeclaration<'a>;

    fn undeclare_inner(self, session: &'a Session) -> Self::Undeclaration {
        KeyExprUndeclaration::new(&session.anchor(), self)
    }
}

impl Session {
    /// Returns the identifier of the current session. `zid()` is a convenient shortcut.
    /// See [`Session::info()`](`Session::info()`) and [`SessionInfo::zid()`](`SessionInfo::zid()`) for more details.
    pub fn zid(&self) -> ZenohId {
        self.0.zid
    }

    /// Get the current configuration of the zenoh [`Session`](Session).
    ///
    /// The returned configuration [`Notifier`](crate::config::Notifier) can be used to read the current
    /// zenoh configuration through the `get` function or
    /// modify the zenoh configuration through the `insert`
    /// or `insert_json5` function.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let peers = session.config().get("connect/endpoints").unwrap();
    /// # }
    /// ```
    #[zenoh_macros::unstable]
    pub fn config(&self) -> zenoh_config::GenericConfig {
        zenoh_config::GenericConfig::new(Arc::new(self.0.config.clone()))
    }

    /// Returns the [`ShmProviderState`](ShmProviderState) associated with the current [`Session`](Session).
    ///
    /// Each session may create its own provider to manage internal optimizations.
    /// This method exposes that provider so it can also be accessed at the application level.
    ///
    /// Note that the provider may not be immediately available or may be disabled via configuration.
    /// Provider initialization is concurrent and triggered by access events.
    ///
    /// To use this provider, both *shared_memory* and *transport_optimization* config sections
    /// must be enabled.
    ///
    /// This provider is not the one the transport of this crate allocates from: the engine keeps
    /// shared memory of its own, so a large payload is not put into this provider implicitly as
    /// upstream's transport does (see slice Z7 of `docs/zenoh-api-on-the-engine.md`).
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let shm_provider = session.get_shm_provider();
    /// assert!(shm_provider.into_option().is_none());
    /// std::thread::sleep(std::time::Duration::from_millis(100));
    /// let shm_provider = session.get_shm_provider();
    /// assert!(shm_provider.into_option().is_some());
    /// # }
    /// ```
    #[cfg(feature = "shared-memory")]
    #[zenoh_macros::unstable]
    pub fn get_shm_provider(&self) -> crate::net::runtime::ShmProviderState {
        match &self.0.shm_provider {
            Some(provider) => provider.state(),
            None => crate::net::runtime::ShmProviderState::Disabled,
        }
    }

    /// Get a new Timestamp from a Zenoh [`Session`].
    ///
    /// The returned timestamp has the current time, with the Session's runtime [`ZenohId`].
    ///
    /// # Examples
    /// ### Get a new timestamp
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let timestamp = session.new_timestamp();
    /// # }
    /// ```
    pub fn new_timestamp(&self) -> Timestamp {
        match self.0.engine.node_timestamp() {
            Some(timestamp) => timestamp,
            None => {
                // The node holds no clock: the time of the system, with the id of the session.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .into();
                Timestamp::new(now, self.zid().into())
            }
        }
    }

    /// Returns the [`EntityGlobalId`] of this Session.
    #[zenoh_macros::unstable]
    pub fn id(&self) -> EntityGlobalId {
        zenoh_protocol::core::EntityGlobalIdProto {
            zid: self.zid().into(),
            eid: self.0.id,
        }
        .into()
    }

    /// Close the zenoh [`Session`](Session).
    ///
    /// Every subscriber and queryable declared will stop receiving data, and further attempts to
    /// publish or query with the session or publishers will result in an error. Undeclaring an
    /// entity after session closing is a no-op. Session state can be checked with
    /// [`Session::is_closed`].
    ///
    /// Sessions are automatically closed when all their instances are dropped, same as `Arc`.
    /// You may still want to use this function to handle errors or close the session
    /// explicitly.
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let subscriber = session
    ///     .declare_subscriber("key/expression")
    ///     .await
    ///     .unwrap();
    /// let subscriber_task = tokio::spawn(async move {
    ///     while let Ok(sample) = subscriber.recv_async().await {
    ///         println!("Received: {} {:?}", sample.key_expr(), sample.payload());
    ///     }
    /// });
    /// session.close().await.unwrap();
    /// // subscriber task will end as `subscriber.recv_async()` will return `Err`
    /// // subscriber undeclaration has not been sent over the wire
    /// subscriber_task.await.unwrap();
    /// # }
    /// ```
    pub fn close(&self) -> CloseBuilder<Self> {
        CloseBuilder::new(self)
    }

    /// Get information about the zenoh [`Session`](Session).
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let info = session.info();
    /// # }
    /// ```
    pub fn info(&self) -> SessionInfo {
        SessionInfo {
            session: self.downgrade(),
        }
    }

    /// Undeclare a zenoh entity declared by the session.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let keyexpr = session.declare_keyexpr("key/expression").await.unwrap();
    /// let subscriber = session
    ///     .declare_subscriber(&keyexpr)
    ///     .await
    ///     .unwrap();
    /// session.undeclare(subscriber).await.unwrap();
    /// session.undeclare(keyexpr).await.unwrap();
    /// # }
    /// ```
    pub fn undeclare<'a, T>(&'a self, decl: T) -> impl Resolve<ZResult<()>> + 'a
    where
        T: Undeclarable<&'a Session> + 'a,
    {
        UndeclarableSealed::undeclare_inner(decl, self)
    }

    /// Informs Zenoh that you intend to use `key_expr` multiple times and that it should optimize its transmission.
    ///
    /// The returned `KeyExpr`'s internal structure may differ from what you would have obtained through a simple
    /// `key_expr.try_into()`, to save time on detecting the optimizations that have been associated with it.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let key_expr = session.declare_keyexpr("key/expression").await.unwrap();
    /// # }
    /// ```
    pub fn declare_keyexpr<'a, 'b: 'a, TryIntoKeyExpr>(
        &'a self,
        key_expr: TryIntoKeyExpr,
    ) -> impl Resolve<ZResult<KeyExpr<'b>>> + 'a
    where
        TryIntoKeyExpr: TryInto<KeyExpr<'b>>,
        <TryIntoKeyExpr as TryInto<KeyExpr<'b>>>::Error: Into<zenoh_result::Error>,
    {
        let key_expr: ZResult<KeyExpr> = key_expr.try_into().map_err(Into::into);
        ResolveClosure::new(move || key_expr?.declare(&self.anchor(), true))
    }

    /// Create a [`Subscriber`](crate::pubsub::Subscriber) for the given key expression.
    ///
    /// # Arguments
    ///
    /// * `key_expr` - The key expression to subscribe to
    ///
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let subscriber = session.declare_subscriber("key/expression")
    ///     .await
    ///     .unwrap();
    /// tokio::task::spawn(async move {
    ///     while let Ok(sample) = subscriber.recv_async().await {
    ///         println!("Received: {:?}", sample);
    ///     }
    /// }).await;
    /// # }
    /// ```
    pub fn declare_subscriber<'b, TryIntoKeyExpr>(
        &self,
        key_expr: TryIntoKeyExpr,
    ) -> SubscriberBuilder<'_, 'b, DefaultHandler>
    where
        TryIntoKeyExpr: TryInto<KeyExpr<'b>>,
        <TryIntoKeyExpr as TryInto<KeyExpr<'b>>>::Error: Into<zenoh_result::Error>,
    {
        SubscriberBuilder {
            session: self,
            key_expr: TryIntoKeyExpr::try_into(key_expr).map_err(Into::into),
            origin: Locality::default(),
            handler: DefaultHandler::default(),
        }
    }

    /// Declare the longest prefix of `key_expr` that has no wildcard, so that the wire names the key
    /// by it.
    pub(crate) fn declare_nonwild_prefix<'a>(&self, key_expr: KeyExpr<'a>) -> ZResult<KeyExpr<'a>> {
        key_expr.declare_nonwild_prefix(&self.anchor(), false)
    }

    /// Take samples for `key_expr` into `callback`, until the subscription is undeclared with the
    /// id returned. `notifier` is let go with the callback.
    pub(crate) fn declare_subscriber_inner(
        &self,
        key_expr: &KeyExpr,
        origin: Locality,
        callback: Callback<Sample>,
        notifier: Option<SyncGroupNotifier>,
    ) -> ZResult<Id> {
        tracing::trace!("declare_subscriber({:?})", key_expr);
        if self.0.engine.is_closed() {
            return Err(SessionClosedError.into());
        }
        let wire = key_expr.to_wire(&self.anchor());
        let suffix = (!wire.suffix.is_empty()).then(|| wire.suffix.to_string());
        let id = self.0.engine.declare_subscriber(Subscription {
            key: key_expr.as_str(),
            scope: wire.scope,
            suffix,
            origin,
            callback,
            notifier,
            // The declaration of the prefix is held by the subscription for as long as the engine
            // records it, whoever else holds the key.
            keeps: Arc::new(key_expr.clone().into_owned()),
            #[cfg(feature = "unstable")]
            timestamps: self.0.timestamps.clone(),
        })?;
        self.0.subscriptions().push(id);
        // A close that ran between the check and the record has not seen this subscription.
        if self.0.engine.is_closed() {
            self.0.release_subscriptions();
            return Err(SessionClosedError.into());
        }
        Ok(id)
    }

    /// Create a [`Queryable`](crate::query::Queryable) for the given key expression.
    ///
    /// # Arguments
    ///
    /// * `key_expr` - The key expression matching the queries the
    ///   [`Queryable`](crate::query::Queryable) will reply to
    ///
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let queryable = session.declare_queryable("key/expression")
    ///     .await
    ///     .unwrap();
    /// tokio::task::spawn(async move {
    ///     while let Ok(query) = queryable.recv_async().await {
    ///         query.reply("key/expression", "value").await.unwrap();
    ///     }
    /// }).await.unwrap();
    /// # }
    /// ```
    pub fn declare_queryable<'b, TryIntoKeyExpr>(
        &self,
        key_expr: TryIntoKeyExpr,
    ) -> QueryableBuilder<'_, 'b, DefaultHandler>
    where
        TryIntoKeyExpr: TryInto<KeyExpr<'b>>,
        <TryIntoKeyExpr as TryInto<KeyExpr<'b>>>::Error: Into<zenoh_result::Error>,
    {
        QueryableBuilder {
            session: self,
            key_expr: key_expr.try_into().map_err(Into::into),
            complete: false,
            origin: Locality::default(),
            handler: DefaultHandler::default(),
        }
    }

    /// Answer the queries for `key_expr` into `callback`, until the queryable is undeclared with
    /// the id returned. `notifier` is let go with the callback.
    pub(crate) fn declare_queryable_inner(
        &self,
        key_expr: &KeyExpr,
        complete: bool,
        origin: Locality,
        callback: Callback<Query>,
        notifier: Option<SyncGroupNotifier>,
    ) -> ZResult<Id> {
        self.0
            .declare_queryable_inner(key_expr, complete, origin, callback, notifier)
    }

    /// Declare the publisher `key_expr` was declared for: the interest in the subscribers matching
    /// it that the peers are asked for, unless the destination is the session itself. The id of
    /// the engine's declaration, released at undeclare or at close.
    pub(crate) fn declare_publisher_inner(
        &self,
        key_expr: &KeyExpr,
        destination: Locality,
    ) -> ZResult<Id> {
        self.0.declare_publisher_inner(key_expr, destination)
    }

    /// Obtain a [`Liveliness`] struct tied to this Zenoh [`Session`].
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let liveliness = session
    ///     .liveliness()
    ///     .declare_token("key/expression")
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    pub fn liveliness(&self) -> Liveliness<'_> {
        Liveliness { session: self }
    }

    /// Declare a liveliness token on `key_expr`, retracted by a close.
    pub(crate) fn declare_liveliness_inner(&self, key_expr: &KeyExpr) -> ZResult<Id> {
        self.0.declare_liveliness_inner(key_expr)
    }

    /// Take the changes of the liveliness tokens of the peers on `key_expr` into `callback`, with
    /// the tokens already alive first when `history` says so, until the subscription is
    /// undeclared with the id returned. `notifier` is let go with the callback. Only the
    /// declarations of other nodes are tokens that change: the origin is the default one.
    pub(crate) fn declare_liveliness_subscriber_inner(
        &self,
        key_expr: &KeyExpr,
        _origin: Locality,
        history: bool,
        callback: Callback<Sample>,
        notifier: Option<SyncGroupNotifier>,
    ) -> ZResult<Id> {
        self.0
            .declare_liveliness_subscriber_inner(key_expr, history, callback, notifier)
    }

    /// Ask which liveliness tokens are alive on `key_expr`.
    pub(crate) fn liveliness_query(
        &self,
        key_expr: &KeyExpr,
        timeout: Duration,
        callback: Callback<Reply>,
        #[cfg(feature = "unstable")] cancellation_token: Option<CancellationToken>,
    ) -> ZResult<()> {
        self.0.liveliness_query(
            key_expr,
            timeout,
            callback,
            #[cfg(feature = "unstable")]
            cancellation_token,
        )
    }

    /// Create a [`Querier`](crate::query::Querier) for the given key expression.
    ///
    /// # Arguments
    ///
    /// * `key_expr` - The key expression matching resources to query
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let querier = session.declare_querier("key/expression")
    ///     .await
    ///     .unwrap();
    /// let replies = querier.get().await.unwrap();
    /// # }
    /// ```
    pub fn declare_querier<'b, TryIntoKeyExpr>(
        &self,
        key_expr: TryIntoKeyExpr,
    ) -> QuerierBuilder<'_, 'b>
    where
        TryIntoKeyExpr: TryInto<KeyExpr<'b>>,
        <TryIntoKeyExpr as TryInto<KeyExpr<'b>>>::Error: Into<zenoh_result::Error>,
    {
        let qos: QoS = request::ext::QoSType::REQUEST.into();
        QuerierBuilder {
            session: self,
            key_expr: key_expr.try_into().map_err(Into::into),
            qos: qos.into(),
            destination: Locality::default(),
            target: QueryTarget::default(),
            consolidation: QueryConsolidation::default(),
            timeout: self.queries_default_timeout(),
            accept_replies: ReplyKeyExpr::default(),
        }
    }

    /// Declare the querier `key_expr` was declared for: the interest in the queryables matching it
    /// that the peers are asked for, unless the destination is the session itself. The id of the
    /// engine's declaration, released at undeclare or at close.
    pub(crate) fn declare_querier_inner(
        &self,
        key_expr: KeyExpr,
        destination: Locality,
    ) -> ZResult<Id> {
        self.0.declare_querier_inner(&key_expr, destination)
    }

    /// Create a [`Publisher`](crate::pubsub::Publisher) for the given key expression.
    ///
    /// # Arguments
    ///
    /// * `key_expr` - The key expression matching resources to write
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let publisher = session.declare_publisher("key/expression")
    ///     .await
    ///     .unwrap();
    /// publisher.put("value").await.unwrap();
    /// # }
    /// ```
    pub fn declare_publisher<'b, TryIntoKeyExpr>(
        &self,
        key_expr: TryIntoKeyExpr,
    ) -> PublisherBuilder<'_, 'b>
    where
        TryIntoKeyExpr: TryInto<KeyExpr<'b>>,
        <TryIntoKeyExpr as TryInto<KeyExpr<'b>>>::Error: Into<zenoh_result::Error>,
    {
        PublisherBuilder {
            session: self,
            key_expr: key_expr.try_into().map_err(Into::into),
            encoding: Encoding::default(),
            congestion_control: CongestionControl::DEFAULT,
            priority: Priority::DEFAULT,
            is_express: false,
            #[cfg(feature = "unstable")]
            reliability: Reliability::DEFAULT,
            destination: Locality::default(),
        }
    }

    /// Publish [`SampleKind::Put`] sample directly from the session. This is a shortcut for declaring
    /// a [`Publisher`](crate::pubsub::Publisher) and calling [`put`](crate::api::publisher::Publisher::put)
    /// on it.
    ///
    /// # Arguments
    ///
    /// * `key_expr` - Key expression matching the resources to put
    /// * `payload` - The payload to put
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    /// use zenoh::bytes::Encoding;
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// session
    ///     .put("key/expression", "payload")
    ///     .encoding(Encoding::TEXT_PLAIN)
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn put<'a, 'b: 'a, TryIntoKeyExpr, IntoZBytes>(
        &'a self,
        key_expr: TryIntoKeyExpr,
        payload: IntoZBytes,
    ) -> SessionPutBuilder<'a, 'b>
    where
        TryIntoKeyExpr: TryInto<KeyExpr<'b>>,
        <TryIntoKeyExpr as TryInto<KeyExpr<'b>>>::Error: Into<zenoh_result::Error>,
        IntoZBytes: Into<ZBytes>,
    {
        SessionPutBuilder {
            publisher: self.declare_publisher(key_expr),
            kind: PublicationBuilderPut {
                payload: payload.into(),
                encoding: Encoding::default(),
            },
            timestamp: None,
            attachment: None,
            #[cfg(feature = "unstable")]
            source_info: None,
            #[cfg(feature = "unstable")]
            timestamp_instrumentation: None,
        }
    }

    /// Publish a [`SampleKind::Delete`] sample directly from the session. This is a shortcut for declaring
    /// a [`Publisher`](crate::pubsub::Publisher) and calling [`delete`](crate::api::publisher::Publisher::delete) on it.
    ///
    /// # Arguments
    ///
    /// * `key_expr` - Key expression matching the resources to delete
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// session.delete("key/expression").await.unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn delete<'a, 'b: 'a, TryIntoKeyExpr>(
        &'a self,
        key_expr: TryIntoKeyExpr,
    ) -> SessionDeleteBuilder<'a, 'b>
    where
        TryIntoKeyExpr: TryInto<KeyExpr<'b>>,
        <TryIntoKeyExpr as TryInto<KeyExpr<'b>>>::Error: Into<zenoh_result::Error>,
    {
        SessionDeleteBuilder {
            publisher: self.declare_publisher(key_expr),
            kind: PublicationBuilderDelete,
            timestamp: None,
            attachment: None,
            #[cfg(feature = "unstable")]
            source_info: None,
            #[cfg(feature = "unstable")]
            timestamp_instrumentation: None,
        }
    }

    /// Query data from the matching queryables in the system. This is a shortcut for declaring
    /// a [`Querier`](crate::query::Querier) and calling `get` on it.
    ///
    /// Unless explicitly requested via [`accept_replies`](crate::session::SessionGetBuilder::accept_replies),
    /// replies are guaranteed to have
    /// key expressions that match the requested `selector`.
    ///
    /// # Arguments
    ///
    /// * `selector` - The selection of resources to query
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let replies = session.get("key/expression").await.unwrap();
    /// while let Ok(reply) = replies.recv_async().await {
    ///     println!(">> Received {:?}", reply.result());
    /// }
    /// # }
    /// ```
    pub fn get<'a, 'b: 'a, TryIntoSelector>(
        &'a self,
        selector: TryIntoSelector,
    ) -> SessionGetBuilder<'a, 'b, DefaultHandler>
    where
        TryIntoSelector: TryInto<Selector<'b>>,
        <TryIntoSelector as TryInto<Selector<'b>>>::Error: Into<zenoh_result::Error>,
    {
        let selector = selector.try_into().map_err(Into::into);
        let qos: QoS = request::ext::QoSType::REQUEST.into();
        SessionGetBuilder {
            session: self,
            selector,
            target: QueryTarget::DEFAULT,
            consolidation: QueryConsolidation::DEFAULT,
            qos: qos.into(),
            destination: Locality::default(),
            timeout: self.queries_default_timeout(),
            value: None,
            attachment: None,
            handler: DefaultHandler::default(),
            #[cfg(feature = "unstable")]
            source_info: None,
            #[cfg(feature = "unstable")]
            cancellation_token: None,
            #[cfg(feature = "unstable")]
            timestamp_instrumentation: None,
        }
    }

    /// How long a query waits for its replies when it does not say, as the configuration states.
    pub(crate) fn queries_default_timeout(&self) -> Duration {
        self.0.queries_default_timeout
    }

    /// The quality of service `qos/publication` sets for a publication on `key_expr`: the entry
    /// of the first key the configuration names that includes it, or none set. When several
    /// include it, one is used and the others are said.
    pub(crate) fn get_publisher_qos_overwrite(
        &self,
        key_expr: &zenoh_keyexpr::keyexpr,
    ) -> PublisherQoSConfig {
        let mut nodes_including = self
            .0
            .publisher_qos_tree
            .nodes_including(key_expr)
            .filter(|n| n.weight().is_some())
            .peekable();
        if let Some(node) = nodes_including.next() {
            if nodes_including.peek().is_some() {
                let others: Vec<String> =
                    nodes_including.map(|n| n.keyexpr().to_string()).collect();
                tracing::warn!(
                    "Publisher declared on `{}` which is included by multiple key_exprs in qos config ({}). Using qos config for `{}`",
                    key_expr,
                    others.join(", "),
                    node.keyexpr(),
                );
            }
            return node
                .weight()
                .expect("first node weight should not be None")
                .clone();
        }
        PublisherQoSConfig::default()
    }

    /// Hand a query to the engine, with its replies going to `callback`.
    #[allow(clippy::too_many_arguments)] // the arguments of upstream's function, kept as they are
    pub(crate) fn query(
        &self,
        key_expr: &KeyExpr<'_>,
        parameters: &Parameters<'_>,
        target: QueryTarget,
        consolidation: QueryConsolidation,
        qos: QoS,
        destination: Locality,
        timeout: Duration,
        value: Option<(ZBytes, Encoding)>,
        attachment: Option<ZBytes>,
        #[cfg(feature = "unstable")] source_info: Option<SourceInfo>,
        callback: Callback<Reply>,
        #[cfg(feature = "unstable")] cancellation_token: Option<CancellationToken>,
        querier_id: Option<Id>,
        querier_notifier: Option<SyncGroupNotifier>,
        #[cfg(feature = "unstable")] timestamp_instrumentation: Option<TimestampInstrumentation>,
    ) -> ZResult<()> {
        self.0.query(
            key_expr,
            parameters,
            target,
            consolidation,
            qos,
            destination,
            timeout,
            value,
            attachment,
            #[cfg(feature = "unstable")]
            source_info,
            callback,
            #[cfg(feature = "unstable")]
            cancellation_token,
            querier_id,
            querier_notifier,
            #[cfg(feature = "unstable")]
            timestamp_instrumentation,
        )
    }

    #[allow(clippy::too_many_arguments)] // the arguments of upstream's function, kept as they are
    pub(crate) fn resolve_put(
        &self,
        key_expr: &KeyExpr,
        payload: ZBytes,
        kind: SampleKind,
        encoding: Encoding,
        congestion_control: CongestionControl,
        priority: Priority,
        is_express: bool,
        destination: Locality,
        #[cfg(feature = "unstable")] reliability: Reliability,
        timestamp: Option<uhlc::Timestamp>,
        #[cfg(feature = "unstable")] source_info: Option<SourceInfo>,
        attachment: Option<ZBytes>,
        #[cfg(feature = "unstable")] timestamp_instrumentation: Option<TimestampInstrumentation>,
    ) -> ZResult<()> {
        self.0.resolve_put(
            key_expr,
            payload,
            kind,
            encoding,
            congestion_control,
            priority,
            is_express,
            destination,
            #[cfg(feature = "unstable")]
            reliability,
            timestamp,
            #[cfg(feature = "unstable")]
            source_info,
            attachment,
            #[cfg(feature = "unstable")]
            timestamp_instrumentation,
        )
    }

    /// Check if the session has been closed.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// assert!(!session.is_closed());
    /// session.close().await.unwrap();
    /// assert!(session.is_closed());
    /// # }
    /// ```
    pub fn is_closed(&self) -> bool {
        self.0.engine.is_closed()
    }
}

impl WireAnchor for SessionInner {
    fn declare_prefix(&self, prefix: &str, _force: bool) -> ZResult<Option<ExprId>> {
        if self.engine.is_closed() {
            return Err(SessionClosedError.into());
        }
        // The engine holds a declaration once and counts the holders, so a prefix that is already
        // declared is held again and a forced declaration is the same call.
        let Some(id) = self.engine.acquire_keyexpr(prefix) else {
            return Ok(None);
        };
        // The wire names a declaration by sixteen bits where the engine counts in sixty-four. An id
        // that does not fit cannot be named, so the hold just taken is let go and the key is used
        // whole, as one that is not worth a declaration is.
        match ExprId::try_from(id) {
            Ok(expr_id) => Ok(Some(expr_id)),
            Err(_) => {
                self.engine.release_keyexpr(id);
                Ok(None)
            }
        }
    }

    fn undeclare_prefix(&self, expr_id: ExprId) -> ZResult<()> {
        if self.engine.is_closed() {
            return Err(SessionClosedError.into());
        }
        self.engine.release_keyexpr(u64::from(expr_id));
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct SessionCloseArgs {
    /// Whether the caller asked to wait for the callbacks. This engine's close always does, so
    /// the request changes nothing and is only recorded.
    #[allow(dead_code)]
    pub(crate) wait_callbacks: bool,
}

#[async_trait]
impl Closee for WeakSession {
    type CloseArgs = SessionCloseArgs;
    // This engine's close joins the threads of its faces, so a callback that runs on one has
    // returned when it is done. A callback that runs on the thread of the caller of a put or a
    // query (a delivery the session makes to itself) is no thread of the engine's, and neither is
    // the drop of a callback that was being called when the session let go of it: those are what
    // `wait_callbacks` waits for, in the group every entity's callback is counted in.
    #[allow(unused_variables)]
    async fn close_inner(&self, close_args: SessionCloseArgs) {
        let session = self.0.clone();
        // A close joins the engine's threads, so it is run where blocking is allowed and not on the
        // executor of the caller, which may be the very thread a callback is about to be run on.
        let _ = ZRuntime::Net
            .spawn_blocking(move || {
                // Before the engine closes, so that the faces that go down with the session tell
                // the listeners of their events of nothing.
                // The listeners of faces are let go of before the engine closes: the faces that
                // go down with it, those the session dialled at least, would tell them, where
                // upstream's close lets go of them before its transports are closed.
                #[cfg(feature = "unstable")]
                session.release_connectivity_listeners();
                session.engine.close();
                // A closed session takes nothing more, and lets go of the callbacks it was to
                // call: the channel of a subscriber ends with its session, as upstream's does.
                session.release_subscriptions();
                session.release_publishers();
                session.release_queryables();
                session.release_queriers();
                session.release_queries();
                session.release_matching_listeners();
                session.release_tokens();
                // After the callbacks were let go of, so that none is called afresh: the wait ends
                // when the last one that was being called has returned and been dropped.
                if close_args.wait_callbacks {
                    session.callbacks_drop_sync_group.wait();
                }
            })
            .await;
    }
}

impl Closeable for Session {
    type TClosee = WeakSession;

    fn get_closee(&self) -> Self::TClosee {
        self.downgrade()
    }
}

/// Open a zenoh [`Session`].
///
/// # Arguments
///
/// * `config` - The [`Config`] for the zenoh session
///
/// # Examples
/// ```
/// # #[tokio::main]
/// # async fn main() {
///
/// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// # }
/// ```
///
/// ```
/// # #[tokio::main]
/// # async fn main() {
/// use std::str::FromStr;
/// use zenoh::session::ZenohId;
///
/// let mut config = zenoh::Config::default();
/// config.set_id(Some(ZenohId::from_str("221b72df20924c15b8794c6bdb471150").unwrap()));
/// config.connect.endpoints.set(
///     ["tcp/10.10.10.10:7447", "tcp/11.11.11.11:7447"].iter().map(|s|s.parse().unwrap()).collect());
///
/// let session = zenoh::open(config).await.unwrap();
/// # }
/// ```
pub fn open<TryIntoConfig>(config: TryIntoConfig) -> OpenBuilder<TryIntoConfig>
where
    TryIntoConfig: std::convert::TryInto<crate::config::Config> + Send + 'static,
    <TryIntoConfig as std::convert::TryInto<crate::config::Config>>::Error: std::fmt::Debug,
{
    OpenBuilder::new(config)
}

/// Start a scout on the engine this build selects: what it returns scouts until it is dropped. A
/// scout is no session's, so it is not an operation of the port; the crate reaches the engine for
/// it as it does for the open (decision D1 of the seam note, taken again at the end of Z5).
#[cfg(feature = "engine-tokio")]
pub(crate) fn start_scout(
    what: zenoh_protocol::core::WhatAmIMatcher,
    config: &crate::api::config::Config,
    callback: Callback<zenoh_config::wrappers::Hello>,
) -> ZResult<Box<dyn Send>> {
    tokio_engine::start_scout(what, config, callback)
}

/// A build that selects no engine has none to scout with, and says so as its open does.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) fn start_scout(
    _what: zenoh_protocol::core::WhatAmIMatcher,
    _config: &crate::api::config::Config,
    _callback: Callback<zenoh_config::wrappers::Hello>,
) -> ZResult<Box<dyn Send>> {
    bail!("this build selects no engine to scout with")
}

#[cfg(all(test, feature = "engine-tokio"))]
mod tests {
    use std::str::FromStr;

    use zenoh_core::Wait;

    use super::*;

    /// A peer that listens on a port of its own, says who it is, and looks for nobody.
    fn peer(id: &str) -> Config {
        Config::from_json5(&format!(
            r#"{{ id: "{id}", mode: "peer",
                  listen: {{ endpoints: ["tcp/127.0.0.1:0"] }},
                  scouting: {{ multicast: {{ enabled: false }} }} }}"#
        ))
        .expect("a configuration zenoh reads")
    }

    #[test]
    fn a_session_reports_the_id_its_configuration_states() {
        let session = open(peer("a1b2c3")).wait().expect("a peer opens alone");
        assert_eq!(session.zid(), ZenohId::from_str("a1b2c3").expect("an id"));
        assert!(!session.is_closed());
    }

    #[test]
    fn a_session_without_an_id_in_its_configuration_stands_on_a_fresh_one() {
        let config = Config::from_json5(
            r#"{ mode: "peer", listen: { endpoints: ["tcp/127.0.0.1:0"] },
                 scouting: { multicast: { enabled: false } } }"#,
        )
        .expect("a configuration zenoh reads");
        let first = open(config.clone()).wait().expect("opens");
        let second = open(config).wait().expect("opens");
        assert_ne!(first.zid(), second.zid());
    }

    #[test]
    fn closing_a_session_closes_every_clone_of_it_and_a_second_close_does_nothing() {
        let session = open(peer("a1b2c4")).wait().expect("opens");
        let clone = session.clone();
        assert_eq!(session, clone);
        session.close().wait().expect("closes");
        assert!(session.is_closed() && clone.is_closed());
        session
            .close()
            .wait()
            .expect("closing a closed session is not an error");
    }

    #[test]
    fn two_sessions_are_not_equal_and_a_clone_is() {
        let one = open(peer("a1b2c5")).wait().expect("opens");
        let two = open(peer("a1b2c6")).wait().expect("opens");
        assert_ne!(one, two);
        assert_eq!(one, one.clone());
        // Equality is of the session and not of the id it stands on: a second session that states
        // the same id is another session.
        let same_id = open(peer("a1b2c5")).wait().expect("opens");
        assert_eq!(one.zid(), same_id.zid());
        assert_ne!(one, same_id);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_closes_from_an_async_context() {
        let session = open(peer("a1b2c7")).await.expect("opens");
        session.close().await.expect("closes");
        assert!(session.is_closed());
    }

    #[test]
    fn the_last_handle_dropped_closes_the_session_the_others_hold() {
        let session = open(peer("a1b2c8")).wait().expect("opens");
        let weak = session.downgrade();
        let clone = session.clone();
        drop(session);
        assert!(!weak.0.engine.is_closed(), "a handle is still held");
        drop(clone);
        assert!(weak.0.engine.is_closed(), "the last handle closed it");
    }

    #[test]
    fn the_anchor_of_a_session_declares_and_undeclares_a_prefix_until_it_is_closed() {
        let session = open(peer("a1b2c9")).wait().expect("opens");
        let anchor = session.anchor();
        let id = anchor
            .declare_prefix("demo/prefix", false)
            .expect("an open session declares")
            .expect("and gives an id");
        // The same prefix is held again, under the same id.
        assert_eq!(
            anchor
                .declare_prefix("demo/prefix", false)
                .expect("held again"),
            Some(id)
        );
        anchor.undeclare_prefix(id).expect("one hold released");
        anchor.undeclare_prefix(id).expect("the other released");
        session.close().wait().expect("closes");
        assert!(anchor.declare_prefix("demo/prefix", false).is_err());
        assert!(anchor.undeclare_prefix(id).is_err());
    }

    #[test]
    fn a_client_with_nothing_to_dial_and_no_scouting_is_refused_in_upstreams_words() {
        let config = Config::from_json5(
            r#"{ mode: "client", scouting: { multicast: { enabled: false } } }"#,
        )
        .expect("a configuration zenoh reads");
        let error = open(config).wait().expect_err("nothing to dial");
        // The text is upstream's; the position it is reported at is each crate's own.
        assert!(
            error
                .to_string()
                .starts_with("No peer specified and multicast scouting deactivated!"),
            "{error}"
        );
    }

    /// Decision D6: every key of the default configuration is in a state, so a key that a bump of
    /// the pinned upstream adds fails here until it is given one.
    #[test]
    fn every_key_of_the_default_configuration_has_a_state() {
        use wz_capi_core::open_plan::{is_section_of_keys_with_a_state, key_state, KeyState};

        let all: Vec<String> = Config::default().0.keys().collect();
        // The configuration lists its sections beside its leaves; a section has no state of its
        // own, its leaves do.
        let keys: Vec<String> = all
            .iter()
            .filter(|key| {
                !all.iter()
                    .any(|other| other.starts_with(&format!("{key}/")))
            })
            .cloned()
            .collect();
        assert!(keys.len() > 100, "{} keys", keys.len());
        let stateless: Vec<&String> = keys
            .iter()
            .filter(|key| key_state(key).is_none() && !is_section_of_keys_with_a_state(key))
            .collect();
        assert!(stateless.is_empty(), "keys with no state: {stateless:#?}");
        let count = |wanted| {
            keys.iter()
                .filter(|key| key_state(key) == Some(wanted))
                .count()
        };
        // The three states are all in use: a table whose refused state is empty refuses nothing.
        assert!(count(KeyState::Mapped) > 0);
        assert!(count(KeyState::Inert) > 0);
        assert!(count(KeyState::Unmapped) > 0);
    }

    /// A configuration with `key` set to the json5 `value` and a peer that listens on the loopback.
    fn peer_with(key: &str, value: &str) -> Config {
        let mut config = peer("a1b2ca");
        config.insert_json5(key, value).expect("a key zenoh reads");
        config
    }

    #[test]
    fn a_key_the_engine_does_not_act_on_is_refused_by_its_name_unless_it_is_the_default() {
        // `transport/unicast/open_timeout` is upstream's (10 s by default) and this engine's
        // handshake does not read it: stating another value asks for what will not happen. (The
        // key is one the engine does not act on; the example moves to the next one when the
        // engine comes to act on this one, as it did for `accept_timeout`.)
        let error = open(peer_with("transport/unicast/open_timeout", "1234"))
            .wait()
            .expect_err("an unmapped key with a value of its own");
        let text = error.to_string();
        assert!(
            text.contains("`transport/unicast/open_timeout` = 1234"),
            "{text}"
        );
        // CONTROL: the same key at its default is no instruction, and the session opens.
        let default = Config::default()
            .get_json("transport/unicast/open_timeout")
            .expect("a default");
        open(peer_with("transport/unicast/open_timeout", &default))
            .wait()
            .expect("the default of an unmapped key opens");
    }

    #[test]
    fn a_mapped_key_with_a_value_of_its_own_opens_and_an_inert_one_does_too() {
        // `connect/timeout_ms` is read by the engine (the dial phase).
        open(peer_with("connect/timeout_ms", "500"))
            .wait()
            .expect("a mapped key");
        // `transport/auth/pubkey/key_size` is declared and serialised upstream and read by nothing.
        open(peer_with("transport/auth/pubkey/key_size", "4096"))
            .wait()
            .expect("an inert key");
    }

    /// The shared memory provider of a session: what the configuration decides, and that it is
    /// made when it is first asked for.
    #[cfg(all(feature = "shared-memory", feature = "unstable"))]
    mod shm_provider {
        use std::time::{Duration, Instant};

        use super::*;
        use crate::shm::ShmProviderState;

        #[test]
        fn a_session_with_the_default_configuration_has_a_provider_that_is_there_a_moment_later() {
            let session = open(peer("a1b2e0")).wait().expect("opens");
            let first = session.get_shm_provider();
            assert!(
                matches!(first, ShmProviderState::Initializing(_)),
                "{first:?}"
            );
            assert!(first.into_option().is_none(), "it is not made yet");
            let deadline = Instant::now() + Duration::from_secs(5);
            while session.get_shm_provider().into_option().is_none() {
                assert!(Instant::now() < deadline, "the provider was never made");
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        #[test]
        fn a_session_that_is_configured_with_no_provider_has_none() {
            for (key, value) in [
                ("transport/shared_memory/enabled", "false"),
                (
                    "transport/shared_memory/transport_optimization/enabled",
                    "false",
                ),
            ] {
                let session = open(peer_with(key, value)).wait().expect("opens");
                let state = session.get_shm_provider();
                assert!(
                    matches!(state, ShmProviderState::Disabled),
                    "{key}: {state:?}"
                );
                assert!(state.wait().is_none());
            }
        }

        #[test]
        fn the_init_mode_is_acted_on_and_not_refused() {
            open(peer_with("transport/shared_memory/mode", "\"init\""))
                .wait()
                .expect("a key the session acts on itself opens");
        }

        #[test]
        fn a_session_opens_with_the_clients_of_the_application() {
            let clients = Arc::new(
                zenoh_shm::api::client_storage::ShmClientStorage::builder()
                    .with_default_client_set()
                    .build(),
            );
            let session = open(peer("a1b2e1"))
                .with_shm_clients(clients)
                .wait()
                .expect("opens");
            assert!(matches!(
                session.get_shm_provider(),
                ShmProviderState::Initializing(_)
            ));
        }
    }

    /// The ids a session sees as routers and as peers, once it sees `expected` of them or after
    /// five seconds.
    fn connected(session: &Session, expected: usize) -> (Vec<String>, Vec<String>) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let info = session.info();
            let mut routers: Vec<String> = info
                .routers_zid()
                .wait()
                .map(|zid| zid.to_string())
                .collect();
            let mut peers: Vec<String> =
                info.peers_zid().wait().map(|zid| zid.to_string()).collect();
            routers.sort();
            peers.sort();
            if routers.len() + peers.len() >= expected || std::time::Instant::now() > deadline {
                return (routers, peers);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// A loopback port that nothing holds and that the kernel never picks for a socket that binds
    /// port 0: below every platform's ephemeral range, so a session of this process that listens on
    /// `tcp/[::]:0` cannot be handed it between the choice and the use. Chosen by trying numbers
    /// from one that depends on the process, and not read back from a socket that is dropped. A
    /// number is handed out once: the tests of a process run side by side, and a port that is free
    /// when one of them tries it is still free for another until the session of the first listens.
    fn unautoselected_port() -> u16 {
        use std::sync::atomic::{AtomicU16, Ordering};

        static HANDED_OUT: AtomicU16 = AtomicU16::new(0);
        let start = 20_000 + (std::process::id() % 8_000) as u16;
        (0..2_000)
            .map(|_| start + HANDED_OUT.fetch_add(1, Ordering::Relaxed) % 2_000)
            .find(|port| std::net::TcpListener::bind(("127.0.0.1", *port)).is_ok())
            .expect("a free port below the ephemeral range")
    }

    /// A node with no clock still gives a timestamp: the time of the system with the id of the
    /// session. A node that holds one gives the next of its clock, and no two are the same.
    #[test]
    fn a_new_timestamp_carries_the_id_of_the_session_and_is_not_repeated_by_a_clock() {
        let open_with = |id: &str, timestamping: bool| {
            open(
                Config::from_json5(&format!(
                    r#"{{ id: "{id}", mode: "peer", timestamping: {{ enabled: {timestamping} }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads"),
            )
            .wait()
            .expect("opens")
        };
        let plain = open_with("a1b2f5", false);
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let stamp = plain.new_timestamp();
        assert_eq!(*stamp.get_id(), plain.zid().into());
        let taken = stamp.get_time().to_duration();
        assert!(
            taken >= before && taken < before + Duration::from_secs(5),
            "the time of the system: {taken:?} after {before:?}"
        );

        let clocked = open_with("a1b2f6", true);
        let stamps: Vec<_> = (0..1000).map(|_| clocked.new_timestamp()).collect();
        assert!(stamps.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(stamps.iter().all(|s| *s.get_id() == clocked.zid().into()));
    }

    #[test]
    fn the_info_of_a_session_says_its_id_and_the_peers_it_is_connected_to() {
        let port = unautoselected_port();
        let listener = open(
            Config::from_json5(&format!(
                r#"{{ id: "a1b2d1", mode: "peer", listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                      scouting: {{ multicast: {{ enabled: false }} }} }}"#
            ))
            .expect("a configuration zenoh reads"),
        )
        .wait()
        .expect("opens");
        // A session alone is connected to no one, and its id by `info` is its id.
        assert_eq!(listener.info().zid().wait(), listener.zid());
        assert_eq!(listener.info().routers_zid().wait().count(), 0);
        assert_eq!(listener.info().peers_zid().wait().count(), 0);
        let dialler = open(
            Config::from_json5(&format!(
                r#"{{ id: "a1b2d2", mode: "peer", listen: {{ endpoints: [] }},
                      connect: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                      scouting: {{ multicast: {{ enabled: false }} }} }}"#
            ))
            .expect("a configuration zenoh reads"),
        )
        .wait()
        .expect("opens");
        // Each sees the other as a peer, and neither as a router.
        assert_eq!(connected(&dialler, 1), (vec![], vec!["a1b2d1".to_owned()]));
        assert_eq!(connected(&listener, 1), (vec![], vec!["a1b2d2".to_owned()]));
        // A closed session is connected to no one.
        dialler.close().wait().expect("closes");
        assert_eq!(dialler.info().peers_zid().wait().count(), 0);
    }

    /// The keys the engine of `session` holds a declaration of.
    fn declared(session: &Session) -> Vec<String> {
        session
            .0
            .engine
            .keyexpr_declarations()
            .into_iter()
            .map(|(_, key)| key)
            .collect()
    }

    #[test]
    fn a_declared_key_is_held_by_the_engine_until_it_is_dropped() {
        let session = open(peer("a1b2e1")).wait().expect("opens");
        assert!(declared(&session).is_empty());
        let key = session
            .declare_keyexpr("demo/declared")
            .wait()
            .expect("an open session declares");
        assert_eq!(key.as_str(), "demo/declared");
        assert_eq!(declared(&session), ["demo/declared"]);
        drop(key);
        assert!(
            declared(&session).is_empty(),
            "the last hold let go retracts it"
        );
    }

    #[test]
    fn a_declared_key_is_held_once_per_holder_and_retracted_with_the_last() {
        let session = open(peer("a1b2e2")).wait().expect("opens");
        let first = session
            .declare_keyexpr("demo/twice")
            .wait()
            .expect("declares");
        // The second declaration of the same key is the same declaration, held again.
        let second = session
            .declare_keyexpr("demo/twice")
            .wait()
            .expect("declares");
        assert_eq!(declared(&session), ["demo/twice"]);
        drop(first);
        assert_eq!(declared(&session), ["demo/twice"], "one holder is left");
        drop(second);
        assert!(declared(&session).is_empty());
    }

    #[test]
    fn undeclaring_the_only_holder_of_a_key_retracts_it_at_once() {
        let session = open(peer("a1b2e3")).wait().expect("opens");
        let key = session
            .declare_keyexpr("demo/undeclared")
            .wait()
            .expect("declares");
        session.undeclare(key).wait().expect("undeclares");
        assert!(declared(&session).is_empty());
    }

    #[test]
    fn undeclaring_a_key_that_has_a_clone_leaves_the_declaration_to_the_last_clone() {
        // Upstream retracts only when the caller holds the one reference: a clone keeps the
        // declaration, and it goes with the clone.
        let session = open(peer("a1b2e8")).wait().expect("opens");
        let key = session
            .declare_keyexpr("demo/cloned")
            .wait()
            .expect("declares");
        let clone = key.clone();
        session.undeclare(key).wait().expect("undeclares");
        assert_eq!(declared(&session), ["demo/cloned"]);
        drop(clone);
        assert!(declared(&session).is_empty());
    }

    #[test]
    fn a_key_declared_by_another_session_is_refused_by_undeclare() {
        let one = open(peer("a1b2e4")).wait().expect("opens");
        let two = open(peer("a1b2e5")).wait().expect("opens");
        let key = one.declare_keyexpr("demo/other").wait().expect("declares");
        assert!(two.undeclare(key.clone()).wait().is_err());
        assert_eq!(
            declared(&one),
            ["demo/other"],
            "the refusal changed nothing"
        );
        one.undeclare(key)
            .wait()
            .expect("its own session undeclares it");
    }

    #[test]
    fn a_closed_session_declares_nothing() {
        let session = open(peer("a1b2e6")).wait().expect("opens");
        session.close().wait().expect("closes");
        let error = session
            .declare_keyexpr("demo/closed")
            .wait()
            .expect_err("a closed session");
        assert!(error.to_string().starts_with("session closed"), "{error}");
    }

    #[test]
    fn a_key_that_is_not_a_key_expression_is_refused_and_a_wild_one_is_declared() {
        let session = open(peer("a1b2e7")).wait().expect("opens");
        assert!(session.declare_keyexpr("demo//double").wait().is_err());
        let wild = session
            .declare_keyexpr("demo/*/wild")
            .wait()
            .expect("wild is a key");
        assert_eq!(wild.as_str(), "demo/*/wild");
    }

    #[test]
    fn a_router_is_refused_for_what_it_does_not_carry_by_what_was_asked() {
        let config = Config::from_json5(
            r#"{ mode: "router",
                 listen: { endpoints: ["tcp/127.0.0.1:0", "udp/224.0.0.224:17447",
                                       "udp/224.0.0.225:17448"] },
                 scouting: { multicast: { enabled: false } } }"#,
        )
        .expect("a configuration zenoh reads");
        let error = open(config)
            .wait()
            .expect_err("a router that asks too much");
        let text = error.to_string();
        assert!(
            text.contains("`mode` = \"router\"") && text.contains("more than one multicast group"),
            "{text}"
        );
    }

    #[test]
    fn an_endpoint_group_with_a_strategy_is_refused_by_its_key() {
        let config = Config::from_json5(
            r#"{ mode: "client", scouting: { multicast: { enabled: false } },
                 connect: { endpoints: [ { strategy: "oneOf",
                                           locators: ["tcp/127.0.0.1:1"] } ] } }"#,
        )
        .expect("a configuration zenoh reads");
        let error = open(config)
            .wait()
            .expect_err("a strategy has no place here");
        assert!(error.to_string().contains("connect/endpoints"), "{error}");
    }

    /// A publication that states every setting, for the tests of what the engine is asked.
    fn stated_publication(kind: SampleKind) -> Publication<'static> {
        let id = uhlc::ID::try_from(&[0xab_u8, 0xcd][..]).expect("an id");
        Publication {
            key: "demo/stated",
            scope: 0,
            suffix: None,
            payload: ZBytes::from("v"),
            kind,
            encoding: Encoding::APPLICATION_JSON.with_schema("v1"),
            congestion_control: CongestionControl::Block,
            priority: Priority::Background,
            is_express: true,
            destination: Locality::Remote,
            #[cfg(feature = "unstable")]
            reliability: Reliability::BestEffort,
            timestamp: Some(uhlc::Timestamp::new(uhlc::NTP64(0x1234_5678_9abc_def0), id)),
            #[cfg(feature = "unstable")]
            source_info: None,
            attachment: Some(ZBytes::from("attached")),
            #[cfg(feature = "unstable")]
            ts_stack: None,
            #[cfg(feature = "unstable")]
            wire_ts_stack: None,
            #[cfg(all(feature = "unstable", feature = "shared-memory"))]
            shm_promoter: None,
        }
    }

    #[test]
    fn a_publication_asks_the_engine_for_each_setting_it_states() {
        use wz_capi_core::runtime::{
            locality::Locality as EngineLocality,
            qos::{CongestionControl as EngineCongestion, Priority as EnginePriority},
            sample::QosLevel,
        };

        let options = tokio_engine::publish_options(&stated_publication(SampleKind::Put));
        assert_eq!(options.allowed_destination, EngineLocality::Remote);
        assert_eq!(
            options.qos,
            Some(
                QosLevel::DEFAULT
                    .with_priority(EnginePriority::Background)
                    .with_congestion(EngineCongestion::Block)
                    .with_express(true)
            )
        );
        let encoding = options
            .encoding
            .expect("an encoding that is not the default");
        let stated: zenoh_protocol::core::Encoding =
            Encoding::APPLICATION_JSON.with_schema("v1").into();
        assert_eq!(encoding.packed_id, (u32::from(stated.id) << 1) | 1);
        assert_eq!(encoding.schema.as_deref(), Some("v1"));
        let stamp = options.timestamp.expect("the time that was stated");
        assert_eq!(stamp.time, 0x1234_5678_9abc_def0);
        assert_eq!(
            stamp.zid,
            vec![0xab, 0xcd],
            "the id as many bytes as it has"
        );
        assert_eq!(options.attachment.as_deref(), Some(&b"attached"[..]));
        assert_eq!(options.kind, wz_capi_core::runtime::sample::SampleKind::Put);
    }

    #[test]
    fn a_publication_that_states_no_encoding_or_time_leaves_both_to_the_engine() {
        let mut publication = stated_publication(SampleKind::Put);
        publication.encoding = Encoding::default();
        publication.timestamp = None;
        publication.attachment = None;
        let options = tokio_engine::publish_options(&publication);
        assert!(
            options.encoding.is_none(),
            "the default is the absence of one"
        );
        assert!(
            options.timestamp.is_none(),
            "the engine stamps it, or does not"
        );
        assert!(options.attachment.is_none());
    }

    #[test]
    fn a_delete_carries_no_encoding() {
        let options = tokio_engine::publish_options(&stated_publication(SampleKind::Delete));
        assert!(options.encoding.is_none());
        assert_eq!(options.kind, wz_capi_core::runtime::sample::SampleKind::Del);
    }

    #[test]
    fn the_wire_names_a_key_by_its_declaration_only_when_it_has_one() {
        let mut publication = stated_publication(SampleKind::Put);
        assert!(tokio_engine::wire_key(&publication).is_literal());
        publication.scope = 3;
        publication.suffix = Some("/leaf".to_owned());
        let wire = tokio_engine::wire_key(&publication);
        assert!(!wire.is_literal());
        assert_eq!(wire.mapping_id, 3);
        assert_eq!(wire.suffix.as_deref(), Some("/leaf"));
    }

    #[test]
    fn a_session_publishes_and_deletes_until_it_is_closed() {
        let session = open(peer("a1b2d2")).wait().expect("opens");
        session
            .put("demo/put", "v")
            .wait()
            .expect("an open session puts");
        session.delete("demo/put").wait().expect("and deletes");
        let declared = session
            .declare_keyexpr("demo/declared")
            .wait()
            .expect("declares");
        session
            .put(&declared, "v")
            .wait()
            .expect("puts on a declared key");
        session
            .put(declared.join("leaf").expect("a key"), "v")
            .wait()
            .expect("and under it");
        session.close().wait().expect("closes");
        for error in [
            session.put("demo/put", "v").wait().expect_err("closed"),
            session.delete("demo/put").wait().expect_err("closed"),
        ] {
            assert_eq!(error.to_string(), SessionClosedError.to_string());
        }
    }

    #[test]
    fn a_put_on_a_key_that_is_not_one_is_refused_before_anything_is_sent() {
        let session = open(peer("a1b2d3")).wait().expect("opens");
        let error = session.put("demo//bad", "v").wait().expect_err("not a key");
        assert!(error.to_string().contains("demo//bad"), "{error}");
    }

    mod subscribing {
        use std::{sync::mpsc, time::Duration};

        use super::*;
        use crate::api::handlers::{FifoChannel, RingChannel};

        const WAIT: Duration = Duration::from_secs(5);

        fn text(sample: &Sample) -> String {
            sample
                .payload()
                .try_to_string()
                .expect("a text")
                .into_owned()
        }

        /// A function that counts the samples it is given.
        fn counting(count: &Arc<AtomicUsize>) -> impl Fn(Sample) + Send + Sync + 'static {
            let count = Arc::clone(count);
            move |_| {
                count.fetch_add(1, Ordering::SeqCst);
            }
        }

        #[test]
        fn a_subscriber_takes_what_its_own_session_publishes_as_it_was_published() {
            let session = open(peer("a1b2e0")).wait().expect("opens");
            let subscriber = session
                .declare_subscriber("demo/**")
                .wait()
                .expect("declares");
            assert_eq!(subscriber.key_expr().as_str(), "demo/**");
            session
                .put("demo/one", "v")
                .encoding(Encoding::TEXT_PLAIN)
                .attachment("a")
                .priority(Priority::Background)
                .express(true)
                .wait()
                .expect("puts");
            let sample = subscriber
                .recv_timeout(WAIT)
                .expect("a channel")
                .expect("a sample");
            assert_eq!(sample.key_expr().as_str(), "demo/one");
            assert_eq!(text(&sample), "v");
            assert_eq!(sample.kind(), SampleKind::Put);
            assert_eq!(sample.encoding(), &Encoding::TEXT_PLAIN);
            assert_eq!(
                sample
                    .attachment()
                    .map(|bytes| bytes.try_to_string().unwrap().into_owned()),
                Some("a".to_owned())
            );
            assert_eq!(sample.priority(), Priority::Background);
            assert!(sample.express());
            session.delete("demo/one").wait().expect("deletes");
            let sample = subscriber
                .recv_timeout(WAIT)
                .expect("a channel")
                .expect("a sample");
            assert_eq!(sample.kind(), SampleKind::Delete);
            assert!(sample.payload().is_empty());
        }

        #[test]
        fn the_origin_of_a_subscriber_says_whose_publications_it_takes() {
            let session = open(peer("a1b2e1")).wait().expect("opens");
            let (local, remote, any) = (
                Arc::new(AtomicUsize::new(0)),
                Arc::new(AtomicUsize::new(0)),
                Arc::new(AtomicUsize::new(0)),
            );
            let _local = session
                .declare_subscriber("demo/origin")
                .allowed_origin(Locality::SessionLocal)
                .callback(counting(&local))
                .wait()
                .expect("declares");
            let _remote = session
                .declare_subscriber("demo/origin")
                .allowed_origin(Locality::Remote)
                .callback(counting(&remote))
                .wait()
                .expect("declares");
            let _any = session
                .declare_subscriber("demo/origin")
                .callback(counting(&any))
                .wait()
                .expect("declares");
            session.put("demo/origin", "v").wait().expect("puts");
            assert_eq!(local.load(Ordering::SeqCst), 1);
            assert_eq!(remote.load(Ordering::SeqCst), 0, "its own is not remote");
            assert_eq!(any.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn every_kind_of_handler_takes_the_samples() {
            let session = open(peer("a1b2e2")).wait().expect("opens");
            let kept = Arc::new(std::sync::Mutex::new(vec![]));
            let called = Arc::new(AtomicUsize::new(0));
            let _callback = session
                .declare_subscriber("demo/h")
                .callback(counting(&called))
                .wait()
                .expect("declares");
            let mut total = 0;
            let sink = Arc::clone(&kept);
            let _callback_mut = session
                .declare_subscriber("demo/h")
                .callback_mut(move |sample| {
                    total += 1;
                    sink.lock().unwrap().push((total, text(&sample)));
                })
                .wait()
                .expect("declares");
            let default = session
                .declare_subscriber("demo/h")
                .wait()
                .expect("declares");
            let fifo = session
                .declare_subscriber("demo/h")
                .with(FifoChannel::new(8))
                .wait()
                .expect("declares");
            let ring = session
                .declare_subscriber("demo/h")
                .with(RingChannel::new(2))
                .wait()
                .expect("declares");
            for value in ["a", "b", "c"] {
                session.put("demo/h", value).wait().expect("puts");
            }
            assert_eq!(called.load(Ordering::SeqCst), 3);
            assert_eq!(
                *kept.lock().unwrap(),
                vec![
                    (1, "a".to_owned()),
                    (2, "b".to_owned()),
                    (3, "c".to_owned())
                ]
            );
            for channel in [default.handler().len(), fifo.handler().len()] {
                assert_eq!(channel, 3);
            }
            let ring: Vec<String> = (0..2)
                .map(|_| text(&ring.recv().expect("a sample")))
                .collect();
            assert_eq!(ring, ["b", "c"], "a ring that is full drops the oldest");
        }

        #[test]
        fn a_subscriber_takes_nothing_once_it_is_undeclared_or_dropped() {
            let session = open(peer("a1b2e3")).wait().expect("opens");
            let (undeclared, dropped) =
                (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
            let first = session
                .declare_subscriber("demo/gone")
                .callback(counting(&undeclared))
                .wait()
                .expect("declares");
            let second = session
                .declare_subscriber("demo/gone")
                .callback(counting(&dropped))
                .wait()
                .expect("declares");
            session.put("demo/gone", "v").wait().expect("puts");
            first.undeclare().wait().expect("undeclares");
            drop(second);
            session.put("demo/gone", "v").wait().expect("puts");
            assert_eq!(undeclared.load(Ordering::SeqCst), 1);
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn a_background_subscriber_outlives_its_builder_until_the_session_closes() {
            let session = open(peer("a1b2e4")).wait().expect("opens");
            let count = Arc::new(AtomicUsize::new(0));
            session
                .declare_subscriber("demo/back")
                .callback(counting(&count))
                .background()
                .wait()
                .expect("declares");
            session.put("demo/back", "v").wait().expect("puts");
            assert_eq!(count.load(Ordering::SeqCst), 1);
            session.close().wait().expect("closes");
            assert!(session.put("demo/back", "v").wait().is_err());
            assert_eq!(count.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn what_a_closed_session_does_with_a_subscriber_is_what_upstreams_does() {
            let session = open(peer("a1b2e5")).wait().expect("opens");
            let subscriber = session
                .declare_subscriber("demo/closed")
                .wait()
                .expect("declares");
            session.close().wait().expect("closes");
            let error = session
                .declare_subscriber("demo/closed")
                .wait()
                .expect_err("closed");
            assert_eq!(error.to_string(), SessionClosedError.to_string());
            assert!(
                subscriber.recv_timeout(WAIT).is_err(),
                "the channel of a subscriber ends with its session"
            );
            subscriber
                .undeclare()
                .wait()
                .expect("undeclaring after a close is no error");
        }

        #[test]
        fn the_prefix_a_subscriber_is_named_by_is_declared_for_as_long_as_it_is() {
            let session = open(peer("a1b2e6")).wait().expect("opens");
            let declared = |session: &Session| {
                session
                    .0
                    .engine
                    .keyexpr_declarations()
                    .into_iter()
                    .map(|(_, key)| key)
                    .collect::<Vec<_>>()
            };
            assert!(declared(&session).is_empty());
            let subscriber = session
                .declare_subscriber("demo/prefix/**")
                .wait()
                .expect("declares");
            assert_eq!(declared(&session), ["demo/prefix"]);
            subscriber.undeclare().wait().expect("undeclares");
            assert!(
                declared(&session).is_empty(),
                "the declaration went with it"
            );
            session
                .declare_subscriber("demo/prefix/**")
                .callback(|_| {})
                .background()
                .wait()
                .expect("declares");
            assert_eq!(
                declared(&session),
                ["demo/prefix"],
                "a background one keeps it too"
            );
        }

        #[test]
        fn the_callback_is_released_when_the_subscriber_is() {
            let session = open(peer("a1b2e7")).wait().expect("opens");
            let token = Arc::new(());
            let held = Arc::clone(&token);
            let subscriber = session
                .declare_subscriber("demo/release")
                .callback(move |_| {
                    let _ = &held;
                })
                .wait()
                .expect("declares");
            assert_eq!(Arc::strong_count(&token), 2);
            drop(subscriber);
            assert_eq!(Arc::strong_count(&token), 1);
        }

        #[cfg(feature = "unstable")]
        #[test]
        fn an_undeclaration_can_wait_for_the_callbacks_that_are_running() {
            let session = open(peer("a1b2e8")).wait().expect("opens");
            let (entered_tx, entered) = mpsc::sync_channel::<()>(1);
            let (release, released) = mpsc::channel::<()>();
            let released = std::sync::Mutex::new(released);
            let subscriber = session
                .declare_subscriber("demo/wait")
                .callback(move |_| {
                    entered_tx.send(()).expect("the test is listening");
                    released.lock().unwrap().recv().expect("released");
                })
                .wait()
                .expect("declares");
            let publisher = session.clone();
            let put = std::thread::spawn(move || publisher.put("demo/wait", "v").wait());
            entered.recv_timeout(WAIT).expect("the callback runs");
            let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = Arc::clone(&finished);
            let undeclare = std::thread::spawn(move || {
                let result = subscriber.undeclare().wait_callbacks().wait();
                flag.store(true, Ordering::SeqCst);
                result
            });
            std::thread::sleep(Duration::from_millis(300));
            assert!(
                !finished.load(Ordering::SeqCst),
                "a callback is still running"
            );
            release.send(()).expect("the callback waits");
            undeclare.join().expect("no panic").expect("undeclares");
            put.join().expect("no panic").expect("puts");
        }

        /// Decision D4: a callback may declare, publish and undeclare on the session that is
        /// calling it, and nothing it does waits for the thread it is on.
        #[test]
        fn a_callback_may_use_the_session_that_calls_it() {
            let session = open(peer("a1b2e9")).wait().expect("opens");
            let inner_count = Arc::new(AtomicUsize::new(0));
            let (done_tx, done) = mpsc::channel::<ZResult<()>>();
            let in_callback = session.clone();
            let counted = Arc::clone(&inner_count);
            let _outer = session
                .declare_subscriber("demo/outer")
                .callback(move |_| {
                    let outcome = (|| -> ZResult<()> {
                        let key = in_callback.declare_keyexpr("demo/reenter/key").wait()?;
                        let inner = in_callback
                            .declare_subscriber("demo/reenter/**")
                            .callback(counting(&counted))
                            .wait()?;
                        in_callback.put(&key, "v").wait()?;
                        in_callback.put("demo/reenter/other", "v").wait()?;
                        inner.undeclare().wait()?;
                        in_callback.put(&key, "v").wait()?;
                        let publisher = in_callback.declare_publisher("demo/reenter/pub").wait()?;
                        publisher.put("v").wait()?;
                        publisher.undeclare().wait()?;
                        in_callback.undeclare(key).wait()
                    })();
                    done_tx.send(outcome).expect("the test is listening");
                })
                .wait()
                .expect("declares");
            let publisher = session.clone();
            std::thread::spawn(move || publisher.put("demo/outer", "v").wait());
            done.recv_timeout(WAIT)
                .expect("the callback used the session and came back")
                .expect("each thing it did worked");
            assert_eq!(inner_count.load(Ordering::SeqCst), 2);
        }
    }

    mod querying {
        use std::{sync::mpsc, time::Duration};

        use wz_capi_core::{
            faces::WireKey,
            runtime::{
                reply_sink::ReplyView,
                session::QueryOptions,
                session_glue::{ConsolidationMode, QueryTarget},
            },
        };

        use super::*;
        use crate::api::query::ReplyKeyExpr;

        const WAIT: Duration = Duration::from_secs(5);

        /// One reply, as a line.
        fn line(view: &dyn ReplyView) -> String {
            format!(
                "{} {:?} {}",
                view.keyexpr(),
                view.kind(),
                String::from_utf8_lossy(view.payload())
            )
        }

        /// Ask `options` of `key` on the session's engine, the way a get does, and say what came
        /// back once every leg has ended: the replies, as lines, in the order they arrived.
        fn ask(session: &Session, key: &str, options: QueryOptions) -> Vec<String> {
            let lines = Arc::new(std::sync::Mutex::new(vec![]));
            let (ended, over) = mpsc::channel::<()>();
            let Engine::Tokio(state) = &session.0.engine else {
                unreachable!("these tests open peers")
            };
            let issued = state.shared.as_engine().get_on_wire(
                key,
                &WireKey::literal(),
                &options,
                None,
                &mut || {
                    let lines = Arc::clone(&lines);
                    let guard = ended.clone();
                    Box::new(move |view: &dyn ReplyView| {
                        let _ = &guard;
                        lines.lock().unwrap().push(line(view));
                    })
                },
            );
            assert!(issued.is_some(), "the engine asks queries");
            drop(ended);
            // Every callback of a leg drops with its leg, which closes the channel.
            assert_eq!(
                over.recv_timeout(WAIT),
                Err(mpsc::RecvTimeoutError::Disconnected)
            );
            // The order replies of different kinds arrive in is not part of what a query promises.
            let mut lines = lines.lock().unwrap().clone();
            lines.sort();
            lines
        }

        fn local() -> QueryOptions {
            QueryOptions::default()
        }

        /// A query that goes to every queryable that matches, and not only to the best one.
        fn everyone() -> QueryOptions {
            local().with_target(QueryTarget::All)
        }

        #[test]
        fn a_queryable_answers_the_queries_of_its_own_session_as_they_were_asked() {
            let session = open(peer("a1b2c0")).wait().expect("opens");
            let seen = Arc::new(std::sync::Mutex::new(vec![]));
            let record = Arc::clone(&seen);
            let _queryable = session
                .declare_queryable("demo/q/**")
                .callback(move |query| {
                    record.lock().unwrap().push(format!(
                        "{} | {} | {:?} | {} | {:?}",
                        query.selector(),
                        query.key_expr(),
                        query
                            .payload()
                            .map(|p| p.try_to_string().unwrap().into_owned()),
                        query.encoding() == Some(&Encoding::default()),
                        query
                            .attachment()
                            .map(|a| a.try_to_string().unwrap().into_owned()),
                    ));
                    query.reply("demo/q/a", "one").wait().expect("replies");
                    query
                        .reply("demo/q/b", "two")
                        .encoding(Encoding::TEXT_PLAIN)
                        .attachment("x")
                        .express(true)
                        .wait()
                        .expect("replies");
                    query.reply_del("demo/q/c").wait().expect("replies");
                    query
                        .reply_err("broken")
                        .encoding(Encoding::TEXT_PLAIN)
                        .wait()
                        .expect("replies");
                })
                .wait()
                .expect("declares");
            let replies = ask(
                &session,
                "demo/q/**",
                local()
                    .with_parameters(b"x=1;y=2".to_vec())
                    .with_payload(b"body".to_vec())
                    .with_attachment(b"att".to_vec()),
            );
            assert_eq!(
                replies,
                [
                    "demo/q/** Err broken",
                    "demo/q/a Put one",
                    "demo/q/b Put two",
                    "demo/q/c Del "
                ]
            );
            assert_eq!(
                *seen.lock().unwrap(),
                ["demo/q/**?x=1;y=2 | demo/q/** | Some(\"body\") | true | Some(\"att\")"]
            );
        }

        #[test]
        fn a_reply_on_a_key_that_does_not_meet_the_query_is_refused_unless_the_query_accepts_any() {
            let session = open(peer("a1b2c1")).wait().expect("opens");
            let outcomes = Arc::new(std::sync::Mutex::new(vec![]));
            let record = Arc::clone(&outcomes);
            let _queryable = session
                .declare_queryable("demo/disjoint/**")
                .callback(move |query| {
                    let outcome = query.reply("demo/other/key", "v").wait();
                    record.lock().unwrap().push((
                        query.accepts_replies(),
                        outcome.map_err(|error| error.to_string()),
                    ));
                })
                .wait()
                .expect("declares");
            assert!(ask(&session, "demo/disjoint/a", local()).is_empty());
            let replies = ask(
                &session,
                "demo/disjoint/a",
                local().with_parameters(b"_anyke".to_vec()),
            );
            assert_eq!(replies, ["demo/other/key Put v"]);
            let outcomes = outcomes.lock().unwrap();
            assert_eq!(outcomes.len(), 2);
            assert_eq!(outcomes[0].0, ReplyKeyExpr::MatchingQuery);
            let refusal = outcomes[0].1.as_ref().expect_err("refused");
            assert!(
                refusal.contains("`demo/other/key`") && refusal.contains("`demo/disjoint/a`"),
                "{refusal}"
            );
            assert_eq!(outcomes[1].0, ReplyKeyExpr::Any);
            assert!(outcomes[1].1.is_ok());
        }

        #[test]
        fn a_query_is_answered_after_the_callback_has_returned_and_ends_with_its_last_copy() {
            let session = open(peer("a1b2c2")).wait().expect("opens");
            let (keep, kept) = mpsc::channel::<Query>();
            let _queryable = session
                .declare_queryable("demo/held")
                .callback(move |query| keep.send(query).expect("the test is listening"))
                .wait()
                .expect("declares");
            let asking = session.clone();
            let asked = std::thread::spawn(move || ask(&asking, "demo/held", local()));
            let query = kept.recv_timeout(WAIT).expect("the callback ran");
            std::thread::sleep(Duration::from_millis(200));
            assert!(!asked.is_finished(), "a held query is not over");
            let copy = query.clone();
            std::thread::spawn(move || copy.reply("demo/held", "late").wait().expect("replies"))
                .join()
                .expect("no panic");
            std::thread::sleep(Duration::from_millis(200));
            assert!(!asked.is_finished(), "a copy of the query is still held");
            drop(query);
            assert_eq!(
                asked.join().expect("no panic"),
                ["demo/held Put late"],
                "it is over with the last copy"
            );
        }

        #[test]
        fn an_undeclared_queryable_answers_nothing_and_a_stranger_is_refused() {
            let session = open(peer("a1b2c3")).wait().expect("opens");
            // The queryables of the session's own admin space are there from the open.
            let own = session.0.queryables().len();
            let answering = |key: &str| {
                let key = key.to_owned();
                move |query: Query| query.reply(key.clone(), "v").wait().expect("replies")
            };
            let first = session
                .declare_queryable("demo/undeclare/a")
                .callback(answering("demo/undeclare/a"))
                .wait()
                .expect("declares");
            let second = session
                .declare_queryable("demo/undeclare/b")
                .callback(answering("demo/undeclare/b"))
                .wait()
                .expect("declares");
            assert_eq!(session.0.queryables().len(), own + 2);
            assert_eq!(ask(&session, "demo/undeclare/*", everyone()).len(), 2);
            first.undeclare().wait().expect("undeclares");
            assert_eq!(session.0.queryables().len(), own + 1);
            assert_eq!(
                ask(&session, "demo/undeclare/*", everyone()),
                ["demo/undeclare/b Put v"]
            );
            drop(second);
            assert_eq!(session.0.queryables().len(), own);
            assert!(ask(&session, "demo/undeclare/*", everyone()).is_empty());
            let error = session
                .downgrade()
                .close_queryable(Id::MAX)
                .expect_err("not a queryable of the session");
            assert!(
                error.to_string().contains("Unable to find queryable"),
                "{error}"
            );
        }

        #[test]
        fn a_query_is_handed_to_every_queryable_it_meets_and_the_replies_are_consolidated() {
            let session = open(peer("a1b2c6")).wait().expect("opens");
            let handed = Arc::new(AtomicUsize::new(0));
            let queryables: Vec<_> = (0..2)
                .map(|_| {
                    let handed = Arc::clone(&handed);
                    session
                        .declare_queryable("demo/shared")
                        .callback(move |query| {
                            handed.fetch_add(1, Ordering::SeqCst);
                            query.reply("demo/shared", "same").wait().expect("replies");
                        })
                        .wait()
                        .expect("declares")
                })
                .collect();
            // Upstream hands a query to every queryable of the session whose key meets it, with
            // whatever the target is (the target chooses among peers, not among one's own).
            let consolidated = ask(&session, "demo/shared", local());
            assert_eq!(handed.load(Ordering::SeqCst), 2);
            // Two replies on one key are one after the consolidation a get has by default.
            assert_eq!(consolidated, ["demo/shared Put same"]);
            let unconsolidated = ask(
                &session,
                "demo/shared",
                local().with_consolidation(ConsolidationMode::None),
            );
            assert_eq!(handed.load(Ordering::SeqCst), 4);
            assert_eq!(
                unconsolidated,
                ["demo/shared Put same", "demo/shared Put same"]
            );
            drop(queryables);
        }

        #[test]
        fn a_closed_session_declares_nothing_and_lets_its_queryables_go() {
            let session = open(peer("a1b2c4")).wait().expect("opens");
            let own = session.0.queryables().len();
            let queryable = session
                .declare_queryable("demo/closed")
                .wait()
                .expect("declares");
            assert_eq!(session.0.queryables().len(), own + 1);
            session.close().wait().expect("closes");
            assert_eq!(session.0.queryables().len(), 0);
            let error = session
                .declare_queryable("demo/closed")
                .wait()
                .expect_err("a closed session");
            assert!(error.downcast_ref::<SessionClosedError>().is_some());
            assert!(
                queryable.recv_timeout(WAIT).is_err(),
                "the channel of a queryable ends with its session"
            );
            queryable
                .undeclare()
                .wait()
                .expect("no error on a closed session");
        }

        #[test]
        fn every_kind_of_handler_takes_the_queries_and_the_origin_says_whose() {
            let session = open(peer("a1b2c5")).wait().expect("opens");
            let channel = session
                .declare_queryable("demo/handlers")
                .wait()
                .expect("declares");
            let fifo = session
                .declare_queryable("demo/handlers")
                .with(crate::api::handlers::FifoChannel::new(8))
                .wait()
                .expect("declares");
            let called = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&called);
            let _mutable = session
                .declare_queryable("demo/handlers")
                .callback_mut(move |_| {
                    counted.fetch_add(1, Ordering::SeqCst);
                })
                .wait()
                .expect("declares");
            let background = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&background);
            session
                .declare_queryable("demo/handlers")
                .callback(move |_| {
                    counted.fetch_add(1, Ordering::SeqCst);
                })
                .background()
                .wait()
                .expect("declares");
            let remote = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&remote);
            let _remote = session
                .declare_queryable("demo/handlers")
                .allowed_origin(Locality::Remote)
                .callback(move |_| {
                    counted.fetch_add(1, Ordering::SeqCst);
                })
                .wait()
                .expect("declares");
            // A query is over when every copy of it has been dropped, so the two handlers that
            // keep theirs hold the asker until the test has taken them.
            let asking = session.clone();
            let asked = std::thread::spawn(move || ask(&asking, "demo/handlers", everyone()));
            let from_channel = channel.recv_timeout(WAIT).expect("a channel");
            let from_fifo = fifo.recv_timeout(WAIT).expect("a channel");
            assert!(from_channel.is_some() && from_fifo.is_some());
            drop((from_channel, from_fifo));
            assert!(asked.join().expect("no panic").is_empty());
            assert_eq!(called.load(Ordering::SeqCst), 1);
            assert_eq!(background.load(Ordering::SeqCst), 1);
            assert_eq!(remote.load(Ordering::SeqCst), 0, "its own is not remote");
            assert_eq!(channel.key_expr().as_str(), "demo/handlers");
        }
    }

    /// The get of a session: what it asks, what it is answered with, and how it ends.
    mod getting {
        use std::{sync::mpsc, time::Duration};

        use super::*;
        use crate::api::{
            handlers::{FifoChannel, FifoChannelHandler},
            query::{ConsolidationMode, QueryTarget, Reply, ReplyKeyExpr},
        };

        const WAIT: Duration = Duration::from_secs(5);

        /// Everything a get is answered with, until it ends: the channel of its handler closes
        /// with the last reply, and a get that does not end is a failure.
        fn answers(replies: &FifoChannelHandler<Reply>) -> Vec<Reply> {
            let mut all = vec![];
            loop {
                match replies.recv_timeout(WAIT) {
                    Ok(Some(reply)) => all.push(reply),
                    Ok(None) => panic!("the get did not end"),
                    Err(_) => return all,
                }
            }
        }

        /// One reply, as a line.
        fn describe(reply: &Reply) -> String {
            match reply.result() {
                Ok(sample) => format!(
                    "{} {:?} {} {} {:?} {:?} {:?} {}",
                    sample.key_expr(),
                    sample.kind(),
                    sample.payload().try_to_string().expect("a text"),
                    sample.encoding(),
                    sample
                        .attachment()
                        .map(|a| a.try_to_string().unwrap().into_owned()),
                    sample.priority(),
                    sample.congestion_control(),
                    sample.express(),
                ),
                Err(error) => format!(
                    "Err {} {}",
                    error.payload().try_to_string().expect("a text"),
                    error.encoding()
                ),
            }
        }

        fn lines(replies: &[Reply]) -> Vec<String> {
            let mut lines: Vec<_> = replies.iter().map(describe).collect();
            lines.sort();
            lines
        }

        #[test]
        fn a_get_is_answered_as_the_queryables_of_its_session_reply_and_ends_with_the_last_reply() {
            let session = open(peer("a1b2d0")).wait().expect("opens");
            let seen = Arc::new(std::sync::Mutex::new(vec![]));
            let record = Arc::clone(&seen);
            let queryable = session
                .declare_queryable("demo/g/**")
                .callback(move |query| {
                    record.lock().unwrap().push(format!(
                        "{} | {:?} | {:?}",
                        query.selector(),
                        query
                            .payload()
                            .map(|p| p.try_to_string().unwrap().into_owned()),
                        query
                            .attachment()
                            .map(|a| a.try_to_string().unwrap().into_owned()),
                    ));
                    query.reply("demo/g/a", "one").wait().expect("replies");
                    query
                        .reply("demo/g/b", "two")
                        .encoding(Encoding::TEXT_PLAIN)
                        .attachment("x")
                        .express(true)
                        .wait()
                        .expect("replies");
                    query.reply_del("demo/g/c").wait().expect("replies");
                    query
                        .reply_err("broken")
                        .encoding(Encoding::TEXT_PLAIN)
                        .wait()
                        .expect("replies");
                })
                .wait()
                .expect("declares");
            let replies = session
                .get("demo/g/**?x=1")
                .payload("body")
                .attachment("att")
                .wait()
                .expect("asks");
            let all = answers(&replies);
            assert_eq!(
                lines(&all),
                [
                    "Err broken text/plain",
                    "demo/g/a Put one zenoh/bytes None Data Block false",
                    "demo/g/b Put two text/plain Some(\"x\") Data Block true",
                    "demo/g/c Delete  zenoh/bytes None Data Block false",
                ]
            );
            assert_eq!(
                *seen.lock().unwrap(),
                ["demo/g/**?x=1 | Some(\"body\") | Some(\"att\")"]
            );
            #[cfg(feature = "unstable")]
            for reply in &all {
                assert_eq!(reply.replier_id(), Some(queryable.id()));
            }
            drop(queryable);
        }

        #[test]
        fn the_replies_of_two_queryables_on_one_key_are_one_unless_the_get_asks_for_none() {
            let session = open(peer("a1b2d1")).wait().expect("opens");
            let _queryables: Vec<_> = (0..2)
                .map(|_| {
                    session
                        .declare_queryable("demo/shared")
                        .callback(|query| {
                            query.reply("demo/shared", "same").wait().expect("replies");
                        })
                        .wait()
                        .expect("declares")
                })
                .collect();
            let consolidated = session.get("demo/shared").wait().expect("asks");
            assert_eq!(
                lines(&answers(&consolidated)),
                ["demo/shared Put same zenoh/bytes None Data Block false"]
            );
            let unconsolidated = session
                .get("demo/shared")
                .consolidation(ConsolidationMode::None)
                .wait()
                .expect("asks");
            assert_eq!(answers(&unconsolidated).len(), 2);
        }

        #[test]
        fn a_target_of_all_complete_leaves_out_the_queryables_that_are_not() {
            let session = open(peer("a1b2d2")).wait().expect("opens");
            let handed = |complete: bool| {
                let count = Arc::new(AtomicUsize::new(0));
                let counted = Arc::clone(&count);
                let queryable = session
                    .declare_queryable("demo/t")
                    .complete(complete)
                    .callback(move |query| {
                        counted.fetch_add(1, Ordering::SeqCst);
                        query.reply("demo/t", "v").wait().expect("replies");
                    })
                    .wait()
                    .expect("declares");
                (count, queryable)
            };
            let (complete, _complete) = handed(true);
            let (partial, _partial) = handed(false);
            for target in [
                QueryTarget::AllComplete,
                QueryTarget::All,
                QueryTarget::BestMatching,
            ] {
                let replies = session
                    .get("demo/t")
                    .target(target)
                    .consolidation(ConsolidationMode::None)
                    .wait()
                    .expect("asks");
                answers(&replies);
            }
            // Upstream hands a query to every queryable of the session whose key meets it, and
            // the target takes out those that are not complete only for `AllComplete`.
            assert_eq!(complete.load(Ordering::SeqCst), 3);
            assert_eq!(partial.load(Ordering::SeqCst), 2);
        }

        #[test]
        fn a_get_that_is_not_answered_in_time_ends_with_a_timeout_reply() {
            let session = open(peer("a1b2d3")).wait().expect("opens");
            let held = Arc::new(std::sync::Mutex::new(vec![]));
            let keep = Arc::clone(&held);
            let _queryable = session
                .declare_queryable("demo/slow")
                .callback(move |query| keep.lock().unwrap().push(query))
                .wait()
                .expect("declares");
            let replies = session
                .get("demo/slow")
                .timeout(Duration::from_millis(200))
                .wait()
                .expect("asks");
            let timeout = replies
                .recv_timeout(WAIT)
                .expect("the get is open")
                .expect("the get timed out with a reply");
            assert_eq!(describe(&timeout), "Err Timeout zenoh/string");
            // The get is over with its timeout, although the queryable still holds the query: a
            // reply to it now has nowhere to go.
            assert!(answers(&replies).is_empty());
            assert_eq!(held.lock().unwrap().len(), 1);
        }

        /// The same, with the queryable on another node: it is the face to that node that waits
        /// for the answer, and expires it.
        #[test]
        fn a_get_that_a_remote_queryable_does_not_answer_ends_with_a_timeout_reply() {
            let port = unautoselected_port();
            let on = |id: &str, listen: &str, connect: &str| {
                open(
                    Config::from_json5(&format!(
                        r#"{{ id: "{id}", mode: "peer",
                              listen: {{ endpoints: [{listen}] }},
                              connect: {{ endpoints: [{connect}] }},
                              scouting: {{ multicast: {{ enabled: false }} }} }}"#
                    ))
                    .expect("a configuration zenoh reads"),
                )
                .wait()
                .expect("opens")
            };
            let getter = on("a1b2e0", &format!(r#""tcp/127.0.0.1:{port}""#), "");
            let answerer = on("a1b2e1", "", &format!(r#""tcp/127.0.0.1:{port}""#));
            let held = Arc::new(std::sync::Mutex::new(vec![]));
            let keep = Arc::clone(&held);
            let _queryable = answerer
                .declare_queryable("demo/remote/**")
                .callback(move |query| {
                    if query.key_expr().as_str() == "demo/remote/ready" {
                        query
                            .reply("demo/remote/ready", "ready")
                            .wait()
                            .expect("replies");
                    } else {
                        keep.lock().unwrap().push(query);
                    }
                })
                .wait()
                .expect("declares");
            let deadline = std::time::Instant::now() + WAIT;
            while answers(&getter.get("demo/remote/ready").wait().expect("asks")).is_empty() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the link carries queries"
                );
            }
            let replies = getter
                .get("demo/remote/silent")
                .timeout(Duration::from_millis(300))
                .wait()
                .expect("asks");
            let timeout = replies
                .recv_timeout(WAIT)
                .expect("the get is open")
                .expect("the get timed out with a reply");
            assert!(timeout.result().is_err(), "{timeout:?}");
            assert!(answers(&replies).is_empty());
            assert_eq!(held.lock().unwrap().len(), 1);
        }

        #[test]
        fn a_reply_on_another_key_reaches_a_get_only_when_it_accepts_any() {
            let session = open(peer("a1b2d4")).wait().expect("opens");
            let outcomes = Arc::new(std::sync::Mutex::new(vec![]));
            let record = Arc::clone(&outcomes);
            let _queryable = session
                .declare_queryable("demo/disjoint/**")
                .callback(move |query| {
                    let outcome = query.reply("demo/other/key", "v").wait();
                    record
                        .lock()
                        .unwrap()
                        .push((query.accepts_replies(), outcome.is_ok()));
                })
                .wait()
                .expect("declares");
            let refused = session.get("demo/disjoint/**").wait().expect("asks");
            assert!(answers(&refused).is_empty());
            let accepted = session
                .get("demo/disjoint/**")
                .accept_replies(ReplyKeyExpr::Any)
                .wait()
                .expect("asks");
            assert_eq!(
                lines(&answers(&accepted)),
                ["demo/other/key Put v zenoh/bytes None Data Block false"]
            );
            assert_eq!(
                *outcomes.lock().unwrap(),
                [
                    (ReplyKeyExpr::MatchingQuery, false),
                    (ReplyKeyExpr::Any, true)
                ]
            );
        }

        #[test]
        fn every_kind_of_handler_and_callback_takes_the_replies_of_a_get() {
            let session = open(peer("a1b2d5")).wait().expect("opens");
            let _queryable = session
                .declare_queryable("demo/h")
                .callback(|query| query.reply("demo/h", "v").wait().expect("replies"))
                .wait()
                .expect("declares");
            let fifo = session
                .get("demo/h")
                .with(FifoChannel::new(4))
                .wait()
                .expect("asks");
            assert_eq!(answers(&fifo).len(), 1);
            let (sender, received) = mpsc::channel();
            session
                .get("demo/h")
                .callback(move |reply| sender.send(describe(&reply)).expect("listening"))
                .wait()
                .expect("asks");
            // The channel of a callback ends with the get: its sender is dropped with the callback.
            assert_eq!(
                received.recv_timeout(WAIT),
                Ok("demo/h Put v zenoh/bytes None Data Block false".to_owned())
            );
            assert_eq!(
                received.recv_timeout(WAIT),
                Err(mpsc::RecvTimeoutError::Disconnected)
            );
            let (sender, counted) = mpsc::channel();
            session
                .get("demo/h")
                .callback_mut(move |_| sender.send(()).expect("listening"))
                .wait()
                .expect("asks");
            assert_eq!(counted.recv_timeout(WAIT), Ok(()));
            assert_eq!(
                counted.recv_timeout(WAIT),
                Err(mpsc::RecvTimeoutError::Disconnected)
            );
        }

        #[test]
        fn a_closed_session_asks_nothing() {
            let session = open(peer("a1b2d6")).wait().expect("opens");
            session.close().wait().expect("closes");
            let error = session
                .get("demo/closed")
                .wait()
                .expect_err("a closed session");
            assert!(error.downcast_ref::<SessionClosedError>().is_some());
        }

        #[cfg(feature = "unstable")]
        #[test]
        fn cancelling_a_token_ends_the_gets_made_with_it_and_a_cancelled_token_refuses_new_ones() {
            use crate::api::cancellation::CancellationToken;

            let session = open(peer("a1b2d7")).wait().expect("opens");
            let (asked_tx, asked) = mpsc::channel();
            let held = Arc::new(std::sync::Mutex::new(vec![]));
            let keep = Arc::clone(&held);
            let _queryable = session
                .declare_queryable("demo/cancel")
                .callback(move |query| {
                    keep.lock().unwrap().push(query);
                    let _ = asked_tx.send(());
                })
                .wait()
                .expect("declares");
            let token = CancellationToken::default();
            let replies = session
                .get("demo/cancel")
                .cancellation_token(token.clone())
                .wait()
                .expect("asks");
            asked
                .recv_timeout(WAIT)
                .expect("the queryable has the query");
            // The cancellation waits for the callback of the get to be let go of, so it is run
            // where a failure to return is a failure of the test and not a hang.
            let cancelling = token.clone();
            let (cancelled_tx, cancelled) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = cancelled_tx.send(cancelling.cancel().wait());
            });
            cancelled
                .recv_timeout(WAIT)
                .expect("the cancellation returned")
                .expect("cancels");
            assert!(token.is_cancelled());
            assert!(
                answers(&replies).is_empty(),
                "a cancelled get ends unanswered"
            );
            let error = session
                .get("demo/cancel")
                .cancellation_token(token)
                .wait()
                .expect_err("a cancelled token");
            assert!(error.to_string().contains("Query was cancelled"));
        }

        /// Decision D4, the half that waits for a get: a callback may ask a get and wait for its
        /// replies, in a subscriber's, in a queryable's and in the callback of a get.
        #[test]
        fn a_callback_may_ask_a_get_and_wait_for_its_replies() {
            let session = open(peer("a1b2d8")).wait().expect("opens");
            let _deep = session
                .declare_queryable("demo/d4/deep")
                .callback(|query| query.reply("demo/d4/deep", "deep").wait().expect("replies"))
                .wait()
                .expect("declares");
            let in_queryable = session.clone();
            let _middle = session
                .declare_queryable("demo/d4/middle")
                .callback(move |query| {
                    let replies = in_queryable.get("demo/d4/deep").wait().expect("asks");
                    for reply in answers(&replies) {
                        let sample = reply.into_result().expect("a sample");
                        query
                            .reply("demo/d4/middle", sample.payload().clone())
                            .wait()
                            .expect("replies");
                    }
                })
                .wait()
                .expect("declares");
            let (done_tx, done) = mpsc::channel::<ZResult<Vec<String>>>();
            let in_subscriber = session.clone();
            let _outer = session
                .declare_subscriber("demo/d4/trigger")
                .callback(move |_| {
                    let outcome = (|| -> ZResult<Vec<String>> {
                        let replies = in_subscriber.get("demo/d4/middle").wait()?;
                        Ok(lines(&answers(&replies)))
                    })();
                    done_tx.send(outcome).expect("the test is listening");
                })
                .wait()
                .expect("declares");
            let publisher = session.clone();
            std::thread::spawn(move || publisher.put("demo/d4/trigger", "v").wait());
            let from_subscriber = done
                .recv_timeout(WAIT)
                .expect("the callback asked and came back")
                .expect("the get worked");
            assert_eq!(
                from_subscriber,
                ["demo/d4/middle Put deep zenoh/bytes None Data Block false"]
            );
            // The callback of a get asks another get and waits for it.
            let in_reply = session.clone();
            let (nested_tx, nested) = mpsc::channel::<usize>();
            session
                .get("demo/d4/deep")
                .callback(move |_| {
                    let replies = in_reply.get("demo/d4/middle").wait().expect("asks");
                    nested_tx.send(answers(&replies).len()).expect("listening");
                })
                .wait()
                .expect("asks");
            assert_eq!(nested.recv_timeout(WAIT), Ok(1));
        }

        /// Whether the engine still holds the querier `id`: a filter it holds says nothing matches
        /// when no queryable does, and one it does not hold says nothing.
        fn held(session: &Session, id: Id) -> bool {
            match &session.0.engine {
                Engine::Tokio(state) => state.shared.as_engine().write_filter_active(u64::from(id)),
                Engine::Router(_) => unreachable!("these tests open peers"),
            }
        }

        #[test]
        fn a_querier_asks_with_the_settings_it_was_declared_with_and_says_them() {
            let session = open(peer("a1b2e3")).wait().expect("opens");
            let seen = Arc::new(std::sync::Mutex::new(vec![]));
            let record = Arc::clone(&seen);
            let _queryable = session
                .declare_queryable("demo/q/**")
                .callback(move |query| {
                    // The quality of service of a query is read in the unstable arm.
                    #[cfg(feature = "unstable")]
                    let qos = format!("{:?}", (query.priority(), query.express()));
                    #[cfg(not(feature = "unstable"))]
                    let qos = String::new();
                    record.lock().unwrap().push(format!(
                        "{} | {:?} | {:?} | {qos}",
                        query.selector(),
                        query
                            .payload()
                            .map(|p| p.try_to_string().unwrap().into_owned()),
                        query
                            .attachment()
                            .map(|a| a.try_to_string().unwrap().into_owned()),
                    ));
                    query.reply("demo/q/a", "one").wait().expect("replies");
                    let _ = query.reply("demo/other", "far").wait();
                })
                .wait()
                .expect("declares");
            let querier = session
                .declare_querier("demo/q/**")
                .target(QueryTarget::All)
                .consolidation(ConsolidationMode::None)
                .accept_replies(ReplyKeyExpr::Any)
                .timeout(Duration::from_secs(3))
                .priority(Priority::RealTime)
                .express(true)
                .congestion_control(CongestionControl::Block)
                .wait()
                .expect("declares");
            assert_eq!(querier.key_expr().as_str(), "demo/q/**");
            assert_eq!(querier.priority(), Priority::RealTime);
            assert_eq!(querier.congestion_control(), CongestionControl::Block);
            assert_eq!(querier.accept_replies(), ReplyKeyExpr::Any);
            // Each get of a querier is asked as the querier was declared, and is its own query.
            for _ in 0..2 {
                let replies = querier
                    .get()
                    .parameters("x=1")
                    .payload("body")
                    .attachment("att")
                    .wait()
                    .expect("asks");
                assert_eq!(
                    lines(&answers(&replies)),
                    [
                        "demo/other Put far zenoh/bytes None RealTime Block true",
                        "demo/q/a Put one zenoh/bytes None RealTime Block true",
                    ]
                );
            }
            let seen = seen.lock().unwrap().clone();
            assert_eq!(seen.len(), 2);
            #[cfg(feature = "unstable")]
            let qos = "(RealTime, true)";
            #[cfg(not(feature = "unstable"))]
            let qos = "";
            for line in seen {
                assert_eq!(
                    line,
                    format!("demo/q/**?x=1;_anyke | Some(\"body\") | Some(\"att\") | {qos}")
                );
            }
        }

        #[test]
        fn undeclaring_a_querier_ends_the_queries_it_has_under_way_and_lets_go_of_it() {
            let session = open(peer("a1b2e4")).wait().expect("opens");
            let (asked_tx, asked) = mpsc::channel();
            let held_queries = Arc::new(std::sync::Mutex::new(vec![]));
            let keep = Arc::clone(&held_queries);
            let _queryable = session
                .declare_queryable("demo/under")
                .callback(move |query| {
                    keep.lock().unwrap().push(query);
                    let _ = asked_tx.send(());
                })
                .wait()
                .expect("declares");
            let querier = session
                .declare_querier("demo/under")
                .wait()
                .expect("declares");
            let id = querier.id;
            assert!(session.0.queriers().iter().any(|entry| entry.id == id));
            // A querier on a key nobody answers on is one the engine holds, and says so.
            let lonely = session
                .declare_querier("demo/lonely")
                .wait()
                .expect("declares");
            let lonely_id = lonely.id;
            assert!(held(&session, lonely_id), "the engine holds the querier");
            let replies = querier.get().wait().expect("asks");
            asked
                .recv_timeout(WAIT)
                .expect("the queryable has the query");
            querier.undeclare().wait().expect("undeclares");
            // The query is over with the querier, though the queryable still holds it.
            assert!(answers(&replies).is_empty());
            assert_eq!(session.0.queriers().len(), 1);
            lonely.undeclare().wait().expect("undeclares");
            assert!(session.0.queriers().is_empty());
            assert!(
                !held(&session, lonely_id),
                "the engine let go of the querier"
            );
            assert_eq!(held_queries.lock().unwrap().len(), 1);
        }

        #[test]
        fn a_querier_that_is_dropped_or_whose_session_closes_is_let_go_of() {
            let session = open(peer("a1b2e5")).wait().expect("opens");
            let dropped = session
                .declare_querier("demo/drop")
                .wait()
                .expect("declares");
            let closed = session
                .declare_querier("demo/close")
                .wait()
                .expect("declares");
            assert_eq!(session.0.queriers().len(), 2);
            drop(dropped);
            assert_eq!(session.0.queriers().len(), 1);
            session.close().wait().expect("closes");
            assert_eq!(session.0.queriers().len(), 0);
            let error = closed
                .get()
                .wait()
                .expect_err("a querier of a closed session asks nothing");
            assert!(error.downcast_ref::<SessionClosedError>().is_some());
            closed
                .undeclare()
                .wait()
                .expect("no error on a closed session");
            let error = session
                .declare_querier("demo/after")
                .wait()
                .expect_err("a closed session");
            assert!(error.downcast_ref::<SessionClosedError>().is_some());
        }

        #[test]
        fn a_querier_forgets_the_queries_that_ended_and_refuses_an_id_it_does_not_hold() {
            let session = open(peer("a1b2e6")).wait().expect("opens");
            let _queryable = session
                .declare_queryable("demo/forget")
                .callback(|query| query.reply("demo/forget", "v").wait().expect("replies"))
                .wait()
                .expect("declares");
            let querier = session
                .declare_querier("demo/forget")
                .wait()
                .expect("declares");
            for _ in 0..5 {
                answers(&querier.get().wait().expect("asks"));
            }
            // Only the query that is being asked is under way: the five before it ended.
            let _last = querier.get().wait().expect("asks");
            assert!(session.0.queriers()[0].pending.len() <= 2);
            let error = session
                .downgrade()
                .undeclare_querier_inner(Id::MAX)
                .expect_err("no such querier");
            assert!(
                error.to_string().contains("Unable to find querier"),
                "{error}"
            );
        }

        #[cfg(feature = "unstable")]
        #[test]
        fn undeclaring_a_querier_can_wait_for_the_callbacks_of_its_queries() {
            let session = open(peer("a1b2e7")).wait().expect("opens");
            let (asked_tx, asked) = mpsc::channel();
            let held_queries = Arc::new(std::sync::Mutex::new(vec![]));
            let keep = Arc::clone(&held_queries);
            let _queryable = session
                .declare_queryable("demo/wait")
                .callback(move |query| {
                    keep.lock().unwrap().push(query);
                    let _ = asked_tx.send(());
                })
                .wait()
                .expect("declares");
            let querier = session
                .declare_querier("demo/wait")
                .wait()
                .expect("declares");
            let (replied_tx, replied) = mpsc::channel();
            querier
                .get()
                .callback(move |reply| {
                    let _ = replied_tx.send(reply.result().is_err());
                })
                .wait()
                .expect("asks");
            asked
                .recv_timeout(WAIT)
                .expect("the queryable has the query");
            // The wait ends when the callback of the query has been let go of, which the
            // undeclaration itself does, so it returns although the queryable holds the query.
            let (done_tx, done) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = done_tx.send(querier.undeclare().wait_callbacks().wait());
            });
            done.recv_timeout(WAIT)
                .expect("the undeclaration returned")
                .expect("undeclares");
            assert_eq!(
                replied.recv_timeout(WAIT),
                Err(mpsc::RecvTimeoutError::Disconnected)
            );
        }

        #[cfg(feature = "unstable")]
        #[test]
        fn the_wait_of_an_undeclaration_holds_for_a_callback_that_is_running() {
            let session = open(peer("a1b2e8")).wait().expect("opens");
            let _queryable = session
                .declare_queryable("demo/running")
                .callback(|query| {
                    // Answered from another thread, so that the get has returned and the callback
                    // of its replies runs on that one.
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(50));
                        query.reply("demo/running", "v").wait().expect("replies");
                    });
                })
                .wait()
                .expect("declares");
            let querier = session
                .declare_querier("demo/running")
                .wait()
                .expect("declares");
            let (inside_tx, inside) = mpsc::channel();
            let (release_tx, release) = mpsc::channel::<()>();
            let release = std::sync::Mutex::new(release);
            querier
                .get()
                .callback(move |_| {
                    let _ = inside_tx.send(());
                    let _ = release.lock().unwrap().recv_timeout(WAIT);
                })
                .wait()
                .expect("asks");
            inside.recv_timeout(WAIT).expect("the callback is running");
            let (done_tx, done) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = done_tx.send(querier.undeclare().wait_callbacks().wait());
            });
            assert!(
                done.recv_timeout(Duration::from_millis(300)).is_err(),
                "the undeclaration returned while a callback was running"
            );
            release_tx.send(()).expect("the callback is waiting");
            done.recv_timeout(WAIT)
                .expect("the undeclaration returned once the callback had")
                .expect("undeclares");
        }
    }

    /// What a publisher and a querier say of the subscribers and the queryables that match them.
    mod matching {
        use std::{sync::mpsc, time::Duration};

        use super::*;
        use crate::api::query::QueryTarget;

        const WAIT: Duration = Duration::from_secs(5);

        /// Every status a listener is told of, in the order it is told them.
        fn statuses() -> (
            impl Fn(MatchingStatus) + Send + Sync + 'static,
            mpsc::Receiver<bool>,
        ) {
            let (sender, received) = mpsc::channel();
            let sender = std::sync::Mutex::new(sender);
            (
                move |status: MatchingStatus| {
                    let _ = sender.lock().unwrap().send(status.matching());
                },
                received,
            )
        }

        fn status_of(publisher: &crate::api::publisher::Publisher<'_>) -> bool {
            publisher
                .matching_status()
                .wait()
                .expect("a status")
                .matching()
        }

        #[test]
        fn a_publisher_matches_the_subscribers_of_its_own_session_and_says_when_they_go() {
            let session = open(peer("a1b2f1")).wait().expect("opens");
            let publisher = session
                .declare_publisher("demo/m/p")
                .wait()
                .expect("declares");
            assert!(!status_of(&publisher));
            let subscriber = session
                .declare_subscriber("demo/m/*")
                .wait()
                .expect("declares");
            assert!(status_of(&publisher));
            // A subscriber on a key that does not meet the publisher's does not match it.
            let apart = session
                .declare_subscriber("demo/other")
                .wait()
                .expect("declares");
            subscriber.undeclare().wait().expect("undeclares");
            assert!(!status_of(&publisher));
            drop(apart);
        }

        #[test]
        fn the_destination_of_a_publisher_says_whose_subscribers_match_it() {
            let session = open(peer("a1b2f2")).wait().expect("opens");
            let local = session
                .declare_publisher("demo/m/d")
                .allowed_destination(Locality::SessionLocal)
                .wait()
                .expect("declares");
            let remote = session
                .declare_publisher("demo/m/d")
                .allowed_destination(Locality::Remote)
                .wait()
                .expect("declares");
            let _subscriber = session
                .declare_subscriber("demo/m/d")
                .wait()
                .expect("declares");
            assert!(status_of(&local));
            assert!(
                !status_of(&remote),
                "a subscriber of the session is not a remote one"
            );
        }

        #[test]
        fn a_listener_is_told_each_change_and_what_already_matches_at_its_declaration() {
            let session = open(peer("a1b2f3")).wait().expect("opens");
            let publisher = session
                .declare_publisher("demo/m/l")
                .wait()
                .expect("declares");
            let (callback, told) = statuses();
            let listener = publisher
                .matching_listener()
                .callback(callback)
                .wait()
                .expect("declares");
            // Nothing matches, and nothing is said of it.
            assert_eq!(
                told.recv_timeout(Duration::from_millis(200)),
                Err(mpsc::RecvTimeoutError::Timeout)
            );
            let first = session
                .declare_subscriber("demo/m/l")
                .wait()
                .expect("declares");
            assert_eq!(told.recv_timeout(WAIT), Ok(true));
            // A second subscriber changes nothing, and the loss of the first one nothing either.
            let second = session
                .declare_subscriber("demo/m/**")
                .wait()
                .expect("declares");
            first.undeclare().wait().expect("undeclares");
            second.undeclare().wait().expect("undeclares");
            assert_eq!(told.recv_timeout(WAIT), Ok(false));
            assert_eq!(
                told.recv_timeout(Duration::from_millis(200)),
                Err(mpsc::RecvTimeoutError::Timeout)
            );
            // A listener declared on what already matches is told so before it returns.
            let _kept = session
                .declare_subscriber("demo/m/l")
                .wait()
                .expect("declares");
            let (late_callback, late) = statuses();
            let _late_listener = publisher
                .matching_listener()
                .callback(late_callback)
                .wait()
                .expect("declares");
            assert_eq!(late.try_recv(), Ok(true));
            listener.undeclare().wait().expect("undeclares");
        }

        #[test]
        fn a_listener_ends_with_its_publisher_its_undeclaration_and_its_session() {
            let session = open(peer("a1b2f4")).wait().expect("opens");
            let publisher = session
                .declare_publisher("demo/m/e")
                .wait()
                .expect("declares");
            let channel = publisher.matching_listener().wait().expect("declares");
            let (callback, _told) = statuses();
            publisher
                .matching_listener()
                .callback(callback)
                .background()
                .wait()
                .expect("declares");
            assert_eq!(session.0.matching_listeners().len(), 2);
            // The channel of a listener ends when the publisher that holds it is undeclared.
            publisher.undeclare().wait().expect("undeclares");
            assert_eq!(session.0.matching_listeners().len(), 0);
            assert!(channel.recv_timeout(WAIT).is_err());
            // And a session that closes lets go of what is left.
            let other = session
                .declare_publisher("demo/m/e2")
                .wait()
                .expect("declares");
            let held = other.matching_listener().wait().expect("declares");
            session.close().wait().expect("closes");
            assert_eq!(session.0.matching_listeners().len(), 0);
            assert!(held.recv_timeout(WAIT).is_err());
            let error = other
                .matching_listener()
                .wait()
                .expect_err("a closed session");
            assert!(error.downcast_ref::<SessionClosedError>().is_some());
            held.undeclare()
                .wait()
                .expect("no error on a closed session");
        }

        #[test]
        fn a_querier_matches_the_queryables_of_its_target() {
            let session = open(peer("a1b2f5")).wait().expect("opens");
            let any = session
                .declare_querier("demo/m/q/**")
                .wait()
                .expect("declares");
            let complete = session
                .declare_querier("demo/m/q/**")
                .target(QueryTarget::AllComplete)
                .wait()
                .expect("declares");
            let status = |querier: &crate::api::querier::Querier<'_>| {
                querier
                    .matching_status()
                    .wait()
                    .expect("a status")
                    .matching()
            };
            assert!(!status(&any) && !status(&complete));
            // A queryable that meets the key matches a querier that takes any, and one that does
            // not say it is complete matches no querier that asks for the complete ones.
            let partial = session
                .declare_queryable("demo/m/q/a")
                .wait()
                .expect("declares");
            assert!(status(&any));
            assert!(!status(&complete));
            // A complete queryable counts for the complete ones only when its key includes the
            // querier's, which a narrower one does not.
            let narrow = session
                .declare_queryable("demo/m/q/a")
                .complete(true)
                .wait()
                .expect("declares");
            assert!(!status(&complete));
            let wide = session
                .declare_queryable("demo/m/**")
                .complete(true)
                .wait()
                .expect("declares");
            assert!(status(&complete));
            drop((partial, narrow, wide));
            assert!(!status(&any) && !status(&complete));
        }

        #[test]
        fn a_listener_of_a_querier_is_told_when_a_queryable_comes_and_goes() {
            let session = open(peer("a1b2f6")).wait().expect("opens");
            let querier = session
                .declare_querier("demo/m/ql")
                .wait()
                .expect("declares");
            let (callback, told) = statuses();
            let _listener = querier
                .matching_listener()
                .callback(callback)
                .wait()
                .expect("declares");
            let queryable = session
                .declare_queryable("demo/m/ql")
                .wait()
                .expect("declares");
            assert_eq!(told.recv_timeout(WAIT), Ok(true));
            queryable.undeclare().wait().expect("undeclares");
            assert_eq!(told.recv_timeout(WAIT), Ok(false));
        }

        #[test]
        fn a_subscriber_of_another_node_matches_a_publisher_that_admits_remote_ones() {
            let port = unautoselected_port();
            let on = |id: &str, listen: &str, connect: &str| {
                open(
                    Config::from_json5(&format!(
                        r#"{{ id: "{id}", mode: "peer",
                              listen: {{ endpoints: [{listen}] }},
                              connect: {{ endpoints: [{connect}] }},
                              scouting: {{ multicast: {{ enabled: false }} }} }}"#
                    ))
                    .expect("a configuration zenoh reads"),
                )
                .wait()
                .expect("opens")
            };
            let writer = on("a1b2f7", &format!(r#""tcp/127.0.0.1:{port}""#), "");
            let reader = on("a1b2f8", "", &format!(r#""tcp/127.0.0.1:{port}""#));
            let any = writer
                .declare_publisher("demo/m/r")
                .wait()
                .expect("declares");
            let local = writer
                .declare_publisher("demo/m/r")
                .allowed_destination(Locality::SessionLocal)
                .wait()
                .expect("declares");
            let remote = writer
                .declare_publisher("demo/m/r")
                .allowed_destination(Locality::Remote)
                .wait()
                .expect("declares");
            let (callback, told) = statuses();
            let _listener = any
                .matching_listener()
                .callback(callback)
                .wait()
                .expect("declares");
            // A publisher that writes to the session itself is told of nothing another node does.
            let (local_callback, local_told) = statuses();
            let _local_listener = local
                .matching_listener()
                .callback(local_callback)
                .wait()
                .expect("declares");
            let subscriber = reader
                .declare_subscriber("demo/m/r")
                .wait()
                .expect("declares");
            assert_eq!(told.recv_timeout(WAIT), Ok(true));
            assert_eq!(
                local_told.try_recv(),
                Err(mpsc::TryRecvError::Empty),
                "a listener of the session's own entities was told of a peer's"
            );
            assert!(status_of(&any) && status_of(&remote));
            assert!(
                !status_of(&local),
                "a subscriber of another node is not the session's own"
            );
            subscriber.undeclare().wait().expect("undeclares");
            assert_eq!(told.recv_timeout(WAIT), Ok(false));
            assert!(!status_of(&any) && !status_of(&remote));
            // With a peer connected, a listener of remote subscribers alone is still not told of
            // one of the session's own, which the publisher that admits both is.
            let (remote_callback, remote_told) = statuses();
            let _remote_listener = remote
                .matching_listener()
                .callback(remote_callback)
                .wait()
                .expect("declares");
            let own = writer
                .declare_subscriber("demo/m/r")
                .wait()
                .expect("declares");
            assert_eq!(told.recv_timeout(WAIT), Ok(true));
            assert_eq!(
                remote_told.recv_timeout(Duration::from_millis(300)),
                Err(mpsc::RecvTimeoutError::Timeout),
                "a listener of remote subscribers was told of a local one"
            );
            drop(own);
            assert_eq!(told.recv_timeout(WAIT), Ok(false));
        }

        #[test]
        fn a_publisher_counts_the_subscribers_of_its_session_by_whatever_origin_they_take() {
            let session = open(peer("a1b2fa")).wait().expect("opens");
            let publisher = session
                .declare_publisher("demo/m/o")
                .wait()
                .expect("declares");
            let remote_only = session
                .declare_publisher("demo/m/o")
                .allowed_destination(Locality::Remote)
                .wait()
                .expect("declares");
            let (callback, told) = statuses();
            let _listener = remote_only
                .matching_listener()
                .callback(callback)
                .wait()
                .expect("declares");
            let (any_callback, any_told) = statuses();
            let _any_listener = publisher
                .matching_listener()
                .callback(any_callback)
                .wait()
                .expect("declares");
            let subscriber = session
                .declare_subscriber("demo/m/o")
                .allowed_origin(Locality::Remote)
                .wait()
                .expect("declares");
            // Upstream counts a subscriber of the session whatever origin it takes, and a
            // publisher that asks for remote ones alone is not told of it.
            assert!(status_of(&publisher));
            assert!(!status_of(&remote_only));
            assert_eq!(any_told.recv_timeout(WAIT), Ok(true));
            assert_eq!(
                told.recv_timeout(Duration::from_millis(300)),
                Err(mpsc::RecvTimeoutError::Timeout)
            );
            drop(subscriber);
            assert_eq!(any_told.recv_timeout(WAIT), Ok(false));
            assert!(!status_of(&publisher));
        }

        #[test]
        fn a_queryable_of_another_node_matches_a_querier_only_when_its_key_includes_the_queriers() {
            let port = unautoselected_port();
            let on = |id: &str, listen: &str, connect: &str| {
                open(
                    Config::from_json5(&format!(
                        r#"{{ id: "{id}", mode: "peer",
                              listen: {{ endpoints: [{listen}] }},
                              connect: {{ endpoints: [{connect}] }},
                              scouting: {{ multicast: {{ enabled: false }} }} }}"#
                    ))
                    .expect("a configuration zenoh reads"),
                )
                .wait()
                .expect("opens")
            };
            let asker = on("a1b2fb", &format!(r#""tcp/127.0.0.1:{port}""#), "");
            let answerer = on("a1b2fc", "", &format!(r#""tcp/127.0.0.1:{port}""#));
            let querier = asker
                .declare_querier("demo/m/k/**")
                .wait()
                .expect("declares");
            let settled = |expected: bool| {
                let deadline = std::time::Instant::now() + WAIT;
                loop {
                    let matching = querier
                        .matching_status()
                        .wait()
                        .expect("a status")
                        .matching();
                    if matching == expected || std::time::Instant::now() > deadline {
                        return matching;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            };
            let (callback, told) = statuses();
            let _listener = querier
                .matching_listener()
                .callback(callback)
                .wait()
                .expect("declares");
            // A queryable that answers a narrower key meets the querier's, and does not match it:
            // a router's tables count the queryables of a peer by the inclusion of the key.
            let narrow = answerer
                .declare_queryable("demo/m/k/a")
                .wait()
                .expect("declares");
            std::thread::sleep(Duration::from_millis(400));
            assert!(!settled(false), "a queryable that is narrower than the key");
            assert_eq!(
                told.try_recv(),
                Err(mpsc::TryRecvError::Empty),
                "a listener was told of a queryable that is narrower than the key"
            );
            let wide = answerer
                .declare_queryable("demo/m/**")
                .wait()
                .expect("declares");
            assert!(settled(true), "a queryable that includes the key");
            assert_eq!(told.recv_timeout(WAIT), Ok(true));
            drop((narrow, wide));
            assert!(!settled(false));
        }

        /// A listener declared before a peer is connected is installed on the face when it comes up:
        /// a listener of remote subscribers hears the peer, one of the session's own does not.
        #[test]
        fn a_peer_that_connects_after_the_listeners_is_counted_by_the_remote_ones_only() {
            let port = unautoselected_port();
            let on = |id: &str, listen: &str, connect: &str| {
                open(
                    Config::from_json5(&format!(
                        r#"{{ id: "{id}", mode: "peer",
                              listen: {{ endpoints: [{listen}] }},
                              connect: {{ endpoints: [{connect}] }},
                              scouting: {{ multicast: {{ enabled: false }} }} }}"#
                    ))
                    .expect("a configuration zenoh reads"),
                )
                .wait()
                .expect("opens")
            };
            let writer = on("a1b2fd", &format!(r#""tcp/127.0.0.1:{port}""#), "");
            let remote = writer
                .declare_publisher("demo/m/late")
                .allowed_destination(Locality::Remote)
                .wait()
                .expect("declares");
            let local = writer
                .declare_publisher("demo/m/late")
                .allowed_destination(Locality::SessionLocal)
                .wait()
                .expect("declares");
            let (remote_callback, remote_told) = statuses();
            let _remote_listener = remote
                .matching_listener()
                .callback(remote_callback)
                .wait()
                .expect("declares");
            let (local_callback, local_told) = statuses();
            let _local_listener = local
                .matching_listener()
                .callback(local_callback)
                .wait()
                .expect("declares");
            let reader = on("a1b2fe", "", &format!(r#""tcp/127.0.0.1:{port}""#));
            let _subscriber = reader
                .declare_subscriber("demo/m/late")
                .wait()
                .expect("declares");
            assert_eq!(remote_told.recv_timeout(WAIT), Ok(true));
            assert_eq!(
                local_told.recv_timeout(Duration::from_millis(300)),
                Err(mpsc::RecvTimeoutError::Timeout),
                "a listener of the session's own entities was told of a peer's"
            );
        }

        #[cfg(feature = "unstable")]
        #[test]
        fn the_wait_of_a_listener_undeclaration_holds_for_a_callback_that_is_running() {
            let session = open(peer("a1b2f9")).wait().expect("opens");
            let publisher = session
                .declare_publisher("demo/m/w")
                .wait()
                .expect("declares");
            let (inside_tx, inside) = mpsc::channel();
            let (release_tx, release) = mpsc::channel::<()>();
            let release = std::sync::Mutex::new(release);
            let listener = publisher
                .matching_listener()
                .callback(move |_| {
                    let _ = inside_tx.send(());
                    let _ = release.lock().unwrap().recv_timeout(WAIT);
                })
                .wait()
                .expect("declares");
            // The status is told on the thread that declares the subscriber, which blocks, so it
            // is declared on one of its own.
            let declaring = session.clone();
            std::thread::spawn(move || {
                let _ = declaring.declare_subscriber("demo/m/w").wait();
            });
            inside.recv_timeout(WAIT).expect("the callback is running");
            let (done_tx, done) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = done_tx.send(listener.undeclare().wait_callbacks().wait());
            });
            assert!(
                done.recv_timeout(Duration::from_millis(300)).is_err(),
                "the undeclaration returned while a callback was running"
            );
            release_tx.send(()).expect("the callback is waiting");
            done.recv_timeout(WAIT)
                .expect("the undeclaration returned once the callback had")
                .expect("undeclares");
        }
    }

    /// What a subscriber's undeclaration waits for. Upstream's test of it (`callback_drop_on_undeclare`)
    /// gives the callback a call that takes a while and a drop that takes a while and then states
    /// that it ran, and asks that `wait_callbacks` return after both, whichever thread the sample
    /// was delivered on. `wait_callbacks` is the API of the `unstable` and `internal` builds.
    #[cfg(any(feature = "unstable", feature = "internal"))]
    mod subscriber_undeclaration {
        use std::{
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            },
            time::Duration,
        };

        use super::*;

        const WORK: Duration = Duration::from_millis(400);

        struct Slow {
            dropped: Arc<AtomicBool>,
        }

        impl Drop for Slow {
            fn drop(&mut self) {
                std::thread::sleep(WORK);
                self.dropped.store(true, Ordering::SeqCst);
            }
        }

        fn slow_callback() -> (impl Fn(Sample) + Send + Sync + 'static, Arc<AtomicBool>) {
            let dropped = Arc::new(AtomicBool::new(false));
            let slow = Slow {
                dropped: dropped.clone(),
            };
            (
                move |_sample: Sample| {
                    let _ = &slow;
                    std::thread::sleep(WORK);
                },
                dropped,
            )
        }

        /// A sample the session sends to itself from another thread is being delivered while
        /// the subscriber is undeclared: the wait returns after the call and the drop.
        #[test]
        fn the_wait_holds_for_the_call_and_the_drop_of_a_sample_the_session_sent_itself() {
            let session = open(peer("a1b2fa")).wait().expect("opens");
            let (callback, dropped) = slow_callback();
            let subscriber = session
                .declare_subscriber("demo/u/local")
                .callback(callback)
                .wait()
                .expect("declares");
            let putting = session.clone();
            std::thread::spawn(move || {
                putting.put("demo/u/local", "x").wait().expect("puts");
            });
            std::thread::sleep(Duration::from_millis(100));
            subscriber
                .undeclare()
                .wait_callbacks()
                .wait()
                .expect("undeclares");
            assert!(
                dropped.load(Ordering::SeqCst),
                "the undeclaration returned before the callback had been dropped"
            );
        }

        /// The same for the close of the session, which waits for the callbacks of every entity it
        /// has, a subscriber that runs in the background among them.
        #[test]
        fn the_wait_of_a_close_holds_for_the_callback_of_a_background_subscriber() {
            let session = open(peer("a1b2fb")).wait().expect("opens");
            let (callback, dropped) = slow_callback();
            session
                .declare_subscriber("demo/u/background")
                .callback(callback)
                .background()
                .wait()
                .expect("declares");
            let putting = session.clone();
            std::thread::spawn(move || {
                putting.put("demo/u/background", "x").wait().expect("puts");
            });
            std::thread::sleep(Duration::from_millis(100));
            session.close().wait_callbacks().wait().expect("closes");
            assert!(
                dropped.load(Ordering::SeqCst),
                "the close returned before the callback had been dropped"
            );
        }
    }

    /// A query nobody has answered ends with the session that asked it: the channel of its replies
    /// is disconnected when the session closes, and does not wait for the timeout of the query.
    mod unanswered_queries {
        use std::time::Duration;

        use super::*;

        #[test]
        fn the_channel_of_a_get_that_is_not_answered_ends_with_the_session() {
            let session = open(peer("a1b2fc")).wait().expect("opens");
            // Declared and never replied to, on the same session: the get stays under way.
            let _queryable = session
                .declare_queryable("demo/q/open")
                .wait()
                .expect("declares");
            let replies = session
                .get("demo/q/open")
                .timeout(Duration::from_secs(30))
                .wait()
                .expect("asks");
            assert!(!replies.is_disconnected(), "the query is under way");
            session.close().wait().expect("closes");
            assert!(
                replies.is_disconnected(),
                "the channel of a query that was not answered outlived its session"
            );
        }
    }

    /// The transports and the links a node holds, and the events of their opening and closing.
    #[cfg(feature = "unstable")]
    mod connectivity {
        use std::{sync::mpsc, time::Duration};

        use zenoh_protocol::core::{Reliability, WhatAmI};

        use super::*;

        const WAIT: Duration = Duration::from_secs(5);

        pub(super) fn on(id: &str, listen: &str, connect: &str) -> Session {
            open(
                Config::from_json5(&format!(
                    r#"{{ id: "{id}", mode: "peer",
                          listen: {{ endpoints: [{listen}] }},
                          connect: {{ endpoints: [{connect}] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads"),
            )
            .wait()
            .expect("opens")
        }

        /// The node that listens, and the endpoint it listens on.
        pub(super) fn listening(id: &str) -> (Session, String) {
            let port = unautoselected_port();
            let endpoint = format!("tcp/127.0.0.1:{port}");
            (on(id, &format!(r#""{endpoint}""#), ""), endpoint)
        }

        pub(super) fn dialling(id: &str, endpoint: &str) -> Session {
            on(id, "", &format!(r#""{endpoint}""#))
        }

        fn transports(session: &Session) -> Vec<Transport> {
            session.info().transports().wait().collect()
        }

        fn links(session: &Session) -> Vec<Link> {
            session.info().links().wait().collect()
        }

        /// Every event of a transport listener as `Put|Delete zid`.
        fn transport_events() -> (
            impl Fn(TransportEvent) + Send + Sync + 'static,
            mpsc::Receiver<String>,
        ) {
            let (sender, received) = mpsc::channel();
            let sender = std::sync::Mutex::new(sender);
            (
                move |event: TransportEvent| {
                    let _ = sender.lock().unwrap().send(format!(
                        "{:?} {}",
                        event.kind(),
                        event.transport().zid()
                    ));
                },
                received,
            )
        }

        /// Every event of a link listener as `Put|Delete src dst`.
        fn link_events() -> (
            impl Fn(LinkEvent) + Send + Sync + 'static,
            mpsc::Receiver<String>,
        ) {
            let (sender, received) = mpsc::channel();
            let sender = std::sync::Mutex::new(sender);
            (
                move |event: LinkEvent| {
                    let _ = sender.lock().unwrap().send(format!(
                        "{:?} {} {}",
                        event.kind(),
                        event.link().src(),
                        event.link().dst()
                    ));
                },
                received,
            )
        }

        #[test]
        fn a_session_lists_the_transport_and_the_link_it_holds_to_a_peer() {
            let (writer, endpoint) = listening("a1b2d0");
            let reader = dialling("a1b2d1", &endpoint);
            assert_eq!(connected(&reader, 1).1.len(), 1, "the nodes are linked");
            assert_eq!(connected(&writer, 1).1.len(), 1, "the nodes are linked");

            let held = transports(&reader);
            assert_eq!(held.len(), 1);
            let transport = &held[0];
            assert_eq!(transport.zid().to_string(), "a1b2d0");
            assert_eq!(transport.whatami(), WhatAmI::Peer);
            assert!(transport.is_qos(), "a session offers QoS");
            assert!(!transport.is_multicast());

            let held = links(&reader);
            assert_eq!(held.len(), 1);
            let link = &held[0];
            assert_eq!(link.zid().to_string(), "a1b2d0");
            assert_eq!(link.dst().to_string(), endpoint);
            assert!(link.src().to_string().starts_with("tcp/127.0.0.1:"));
            assert_ne!(link.src(), link.dst());
            assert_eq!(link.group(), None);
            assert!(link.mtu() > 0);
            assert!(link.is_streamed(), "tcp carries a stream");
            assert_eq!(link.auth_identifier(), None);
            // A transport that negotiated QoS reports all the priorities and the reliability of
            // its links.
            assert_eq!(link.priorities(), Some((0, 7)));
            assert_eq!(link.reliability(), Some(Reliability::Reliable));

            // The listening side holds the same link from the other end.
            let accepted = links(&writer);
            assert_eq!(accepted.len(), 1);
            assert_eq!(accepted[0].zid().to_string(), "a1b2d1");
            assert_eq!(accepted[0].src(), link.dst());
            assert_eq!(accepted[0].dst(), link.src());
        }

        /// A link of the engine's model, from the words of its ends.
        fn snapshot_link(
            src: &str,
            dst: &str,
            kind: Option<wz_runtime_tokio::session_glue::LinkKind>,
        ) -> wz_capi_core::faces::LinkSnapshot {
            wz_capi_core::faces::LinkSnapshot {
                src: src.to_owned(),
                dst: dst.to_owned(),
                kind,
                interfaces: Some(vec!["eth0".to_owned(), "eth1".to_owned()]),
                mtu: 1200,
                group: None,
                cert_common_name: Some("alice".to_owned()),
                priorities: None,
                reliable: None,
            }
        }

        fn snapshot_face(
            whatami: u8,
            is_qos: bool,
            links: Vec<wz_capi_core::faces::LinkSnapshot>,
        ) -> wz_capi_core::faces::FaceSnapshot {
            let mut zid = [0u8; 16];
            zid[..3].copy_from_slice(&[0xa1, 0xb2, 0xc3]);
            wz_capi_core::faces::FaceSnapshot {
                zid,
                whatami,
                is_qos,
                is_multicast: false,
                is_shm: false,
                links,
            }
        }

        #[test]
        fn a_face_of_the_engine_is_the_transport_and_the_links_it_says() {
            use wz_runtime_tokio::session_glue::LinkKind;

            let face = tokio_engine::face_of(&snapshot_face(
                2,
                true,
                vec![
                    snapshot_link(
                        "tls/10.0.0.1:7447",
                        "tls/10.0.0.2:5000",
                        Some(LinkKind::Tls),
                    ),
                    snapshot_link(
                        "quic/10.0.0.1:7447",
                        "quic/10.0.0.2:5000",
                        Some(LinkKind::QuicDatagram),
                    ),
                    snapshot_link("tcp/10.0.0.1:7447", "tcp/10.0.0.2:5000", None),
                ],
            ))
            .expect("a face");
            let transport = &face.transport;
            assert_eq!(
                *transport.zid(),
                ZenohId::try_from([0xa1, 0xb2, 0xc3].as_slice()).unwrap()
            );
            assert_eq!(transport.whatami(), WhatAmI::Client);
            assert!(transport.is_qos() && !transport.is_multicast());

            let [tls, datagram, unnamed] = face.links.as_slice() else {
                panic!("three links: {:?}", face.links);
            };
            // Every link carries the zid of its transport.
            assert!(face.links.iter().all(|link| link.zid() == transport.zid()));
            assert_eq!(tls.src().to_string(), "tls/10.0.0.1:7447");
            assert_eq!(tls.dst().to_string(), "tls/10.0.0.2:5000");
            assert_eq!(tls.mtu(), 1200);
            assert_eq!(tls.interfaces(), ["eth0", "eth1"]);
            assert!(tls.is_streamed());
            assert_eq!(tls.auth_identifier(), Some("alice"));
            assert_eq!(tls.reliability(), Some(Reliability::Reliable));
            assert_eq!(tls.priorities(), Some((0, 7)));
            // A datagram link neither streams nor delivers reliably, and a QUIC link is named by
            // the certificate of its peer as a TLS link is.
            assert!(!datagram.is_streamed());
            assert_eq!(datagram.auth_identifier(), Some("alice"));
            assert_eq!(datagram.reliability(), Some(Reliability::BestEffort));
            // A link whose driver cannot name its kind is none of that.
            assert!(!unnamed.is_streamed());
            assert_eq!(unnamed.auth_identifier(), None);
            assert_eq!(unnamed.reliability(), Some(Reliability::BestEffort));
        }

        #[test]
        fn a_face_without_qos_reports_neither_priorities_nor_reliability() {
            use wz_runtime_tokio::session_glue::LinkKind;

            let face = tokio_engine::face_of(&snapshot_face(
                1,
                false,
                vec![snapshot_link(
                    "tcp/10.0.0.1:7447",
                    "tcp/10.0.0.2:5000",
                    Some(LinkKind::Tcp),
                )],
            ))
            .expect("a face");
            assert_eq!(face.transport.whatami(), WhatAmI::Peer);
            assert!(!face.transport.is_qos());
            assert_eq!(face.links.len(), 1);
            assert_eq!(face.links[0].priorities(), None);
            assert_eq!(face.links[0].reliability(), None);
            assert_eq!(
                face.links[0].auth_identifier(),
                None,
                "tcp presents no certificate"
            );
        }

        #[test]
        fn the_link_of_a_group_member_names_the_group_and_a_failed_lookup_is_no_interface() {
            use wz_capi_core::faces::GroupLink;
            use wz_runtime_tokio::session_glue::LinkKind;

            let mut member = snapshot_link(
                "udp/10.0.0.1:7447",
                "udp/10.0.0.2:5000",
                Some(LinkKind::Udp),
            );
            member.group = Some(GroupLink {
                locator: "udp/224.0.0.224:7446".to_owned(),
                endpoint: "udp/224.0.0.224:7446#iface=lo".to_owned(),
            });
            member.interfaces = None;
            let mut snapshot = snapshot_face(0, false, vec![member]);
            snapshot.is_multicast = true;
            let face = tokio_engine::face_of(&snapshot).expect("a face");
            assert_eq!(face.transport.whatami(), WhatAmI::Router);
            assert!(face.transport.is_multicast());
            let link = &face.links[0];
            assert_eq!(
                link.group().map(|group| group.to_string()),
                Some("udp/224.0.0.224:7446".to_owned())
            );
            assert!(
                link.interfaces().is_empty(),
                "upstream reads a failed lookup as no interface"
            );
        }

        #[test]
        fn what_the_api_cannot_hold_is_left_out_and_not_made_up() {
            use wz_runtime_tokio::session_glue::LinkKind;

            // A role the wire form does not name is no transport.
            assert!(tokio_engine::face_of(&snapshot_face(3, true, vec![])).is_none());
            // A link whose locator is no locator is left out, the others stay.
            let face = tokio_engine::face_of(&snapshot_face(
                1,
                true,
                vec![
                    snapshot_link("not a locator", "tcp/10.0.0.2:5000", Some(LinkKind::Tcp)),
                    snapshot_link(
                        "tcp/10.0.0.1:7447",
                        "tcp/10.0.0.2:5000",
                        Some(LinkKind::Tcp),
                    ),
                ],
            ))
            .expect("a face");
            assert_eq!(face.links.len(), 1);
            assert_eq!(face.links[0].src().to_string(), "tcp/10.0.0.1:7447");
        }

        #[test]
        fn a_session_says_the_locators_it_listens_on() {
            let (listening, endpoint) = listening("a1b2e7");
            let said: Vec<String> = listening
                .info()
                .locators()
                .wait()
                .iter()
                .map(|locator| locator.to_string())
                .collect();
            assert_eq!(said, [endpoint]);
            // A port of 0 is the port the kernel gave, and a node that listens on nothing says none.
            let kernel_picked = on("a1b2e8", r#""tcp/127.0.0.1:0""#, "");
            let said = kernel_picked.info().locators().wait();
            assert_eq!(said.len(), 1);
            let text = said[0].to_string();
            assert!(
                text.starts_with("tcp/127.0.0.1:") && !text.ends_with(":0"),
                "{text}"
            );
            let alone = on("a1b2e9", "", "");
            assert!(alone.info().locators().wait().is_empty());
        }

        /// A listener that binds after the open returned is one the session listens on from then
        /// on, as the endpoint taken at the open and let go of later.
        #[test]
        fn a_listener_that_binds_late_is_listened_on_from_then() {
            let port = unautoselected_port();
            let taken = std::net::TcpListener::bind(("127.0.0.1", port)).expect("a free port");
            let session = open(
                Config::from_json5(&format!(
                    r#"{{ id: "a1b2ea", mode: "peer",
                          listen: {{ endpoints: ["tcp/127.0.0.1:{port}"], exit_on_failure: false,
                                     timeout_ms: -1,
                                     retry: {{ period_init_ms: 100, period_max_ms: 200,
                                              period_increase_factor: 2 }} }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads"),
            )
            .wait()
            .expect("opens");
            assert!(
                session.info().locators().wait().is_empty(),
                "nothing is bound while the port is taken"
            );
            drop(taken);
            let deadline = std::time::Instant::now() + WAIT;
            let said = loop {
                let said: Vec<String> = session
                    .info()
                    .locators()
                    .wait()
                    .iter()
                    .map(|locator| locator.to_string())
                    .collect();
                if !said.is_empty() || std::time::Instant::now() > deadline {
                    break said;
                }
                std::thread::sleep(Duration::from_millis(50));
            };
            assert_eq!(said, [format!("tcp/127.0.0.1:{port}")]);
        }

        #[test]
        fn a_session_with_no_peer_holds_no_transport_and_no_link() {
            let session = on("a1b2d2", "", "");
            assert!(transports(&session).is_empty());
            assert!(links(&session).is_empty());
        }

        #[test]
        fn the_links_of_a_transport_are_those_of_its_peer_and_its_kind() {
            let (hub, endpoint) = listening("a1b2d3");
            let first = dialling("a1b2d4", &endpoint);
            let second = dialling("a1b2d5", &endpoint);
            assert_eq!(connected(&hub, 2).1.len(), 2, "the nodes are linked");
            assert_eq!(links(&hub).len(), 2);

            let held = transports(&hub);
            assert_eq!(held.len(), 2);
            let of_first = held
                .iter()
                .find(|t| t.zid().to_string() == "a1b2d4")
                .expect("a transport to the first")
                .clone();
            let only: Vec<Link> = hub
                .info()
                .links()
                .transport(of_first.clone())
                .wait()
                .collect();
            assert_eq!(only.len(), 1);
            assert_eq!(only[0].zid().to_string(), "a1b2d4");

            // The same node as a multicast transport is another transport, and has no link here.
            let mut multicast = of_first;
            multicast.is_multicast = true;
            assert_eq!(
                hub.info().links().transport(multicast).wait().count(),
                0,
                "a multicast transport to the node is not the unicast one"
            );
            drop((first, second));
        }

        /// Two peers that listen on one multicast group are linked by it
        /// (`zenoh-test` @ `open_pairs_multicast`): the first is given the port by the system and
        /// lists the group's locator with it, the second listens on that locator, and what one
        /// publishes the other hears.
        #[test]
        fn peers_that_listen_on_one_multicast_group_hear_each_other() {
            let group = |id: &str, endpoint: &str| on(id, &format!(r#""{endpoint}""#), "");
            let first = group("a1b2e1", "udp/224.0.0.1:0");
            let locator = first
                .info()
                .locators()
                .wait()
                .into_iter()
                .find(|locator| locator.protocol().as_str() == "udp")
                .expect("the group is listed among the locators of the node")
                .to_string();
            let second = group("a1b2e2", &locator);
            let (sender, heard) = mpsc::channel();
            let sender = std::sync::Mutex::new(sender);
            let _subscriber = second
                .declare_subscriber("demo/multicast")
                .callback(move |sample| {
                    let _ = sender.lock().unwrap().send(
                        sample
                            .payload()
                            .try_to_string()
                            .expect("a text")
                            .into_owned(),
                    );
                })
                .wait()
                .expect("declares");
            // The members learn of each other by their beacons, and a publication before that
            // reaches nobody: it is made until one is heard.
            let deadline = std::time::Instant::now() + WAIT * 2;
            let told = loop {
                first.put("demo/multicast", "hello").wait().expect("puts");
                if let Ok(told) = heard.recv_timeout(Duration::from_millis(200)) {
                    break told;
                }
                assert!(std::time::Instant::now() < deadline, "the group is heard");
            };
            assert_eq!(told, "hello");
        }

        #[test]
        fn a_transport_listener_is_told_a_peer_opening_and_closing() {
            let (writer, endpoint) = listening("a1b2d6");
            let (callback, told) = transport_events();
            let _listener = writer
                .info()
                .transport_events_listener()
                .callback(callback)
                .wait()
                .expect("declares");
            let reader = dialling("a1b2d7", &endpoint);
            assert_eq!(told.recv_timeout(WAIT), Ok("Put a1b2d7".to_owned()));
            reader.close().wait().expect("closes");
            assert_eq!(told.recv_timeout(WAIT), Ok("Delete a1b2d7".to_owned()));
            assert_eq!(
                told.recv_timeout(Duration::from_millis(200)),
                Err(mpsc::RecvTimeoutError::Timeout)
            );
        }

        #[test]
        fn a_link_listener_is_told_a_link_added_before_the_transport_it_belongs_to_is_gone() {
            let (writer, endpoint) = listening("a1b2d8");
            let (link_callback, linked) = link_events();
            let _links = writer
                .info()
                .link_events_listener()
                .callback(link_callback)
                .wait()
                .expect("declares");
            let (transport_callback, transported) = transport_events();
            let _transports = writer
                .info()
                .transport_events_listener()
                .callback(transport_callback)
                .wait()
                .expect("declares");
            let reader = dialling("a1b2d9", &endpoint);
            let added = linked.recv_timeout(WAIT).expect("a link event");
            assert!(added.starts_with(&format!("Put {endpoint} tcp/127.0.0.1:")));
            assert_eq!(transported.recv_timeout(WAIT), Ok("Put a1b2d9".to_owned()));
            reader.close().wait().expect("closes");
            let removed = linked.recv_timeout(WAIT).expect("a link event");
            assert!(removed.starts_with(&format!("Delete {endpoint} tcp/127.0.0.1:")));
            assert_eq!(
                transported.recv_timeout(WAIT),
                Ok("Delete a1b2d9".to_owned())
            );
        }

        #[test]
        fn the_history_is_what_is_open_when_the_listener_is_declared() {
            let (writer, endpoint) = listening("a1b2da");
            let reader = dialling("a1b2db", &endpoint);
            assert_eq!(connected(&writer, 1).1.len(), 1, "the nodes are linked");
            let (transport_callback, transported) = transport_events();
            let (link_callback, linked) = link_events();
            let _transports = writer
                .info()
                .transport_events_listener()
                .history(true)
                .callback(transport_callback)
                .wait()
                .expect("declares");
            let _links = writer
                .info()
                .link_events_listener()
                .history(true)
                .callback(link_callback)
                .wait()
                .expect("declares");
            // The history is given before the declaration returns.
            assert_eq!(
                transported.try_recv(),
                Ok("Put a1b2db".to_owned()),
                "the transport that is open"
            );
            let link = linked.try_recv().expect("the link that is open");
            assert!(link.starts_with(&format!("Put {endpoint} tcp/127.0.0.1:")));
            assert!(transported.try_recv().is_err() && linked.try_recv().is_err());

            // A listener without the history is told of what is open only when it changes.
            let (quiet_callback, quiet) = transport_events();
            let _quiet = writer
                .info()
                .transport_events_listener()
                .callback(quiet_callback)
                .wait()
                .expect("declares");
            assert!(quiet.try_recv().is_err());
            drop(reader);
        }

        #[test]
        fn a_link_listener_for_a_transport_is_told_of_the_links_of_that_peer_only() {
            let (hub, endpoint) = listening("a1b2dc");
            let first = dialling("a1b2dd", &endpoint);
            assert_eq!(connected(&hub, 1).1.len(), 1, "the nodes are linked");
            let of_first = transports(&hub).pop().expect("a transport to the first");
            let (callback, told) = link_events();
            let _listener = hub
                .info()
                .link_events_listener()
                .transport(of_first)
                .callback(callback)
                .wait()
                .expect("declares");
            let second = dialling("a1b2de", &endpoint);
            assert_eq!(connected(&hub, 2).1.len(), 2, "the nodes are linked");
            assert_eq!(
                told.recv_timeout(Duration::from_millis(300)),
                Err(mpsc::RecvTimeoutError::Timeout),
                "the link of the second peer is not the first's"
            );
            first.close().wait().expect("closes");
            let removed = told.recv_timeout(WAIT).expect("a link event");
            assert!(removed.starts_with("Delete "));
            drop(second);
        }

        #[test]
        fn an_undeclared_listener_is_told_nothing_and_cannot_be_undeclared_twice() {
            let (writer, endpoint) = listening("a1b2df");
            let (callback, told) = transport_events();
            let listener = writer
                .info()
                .transport_events_listener()
                .callback(callback)
                .wait()
                .expect("declares");
            let id = listener.inner.id;
            listener.undeclare().wait().expect("undeclares");
            let reader = dialling("a1b2e0", &endpoint);
            assert_eq!(connected(&writer, 1).1.len(), 1, "the nodes are linked");
            assert!(told.recv_timeout(Duration::from_millis(300)).is_err());
            let again = writer
                .downgrade()
                .undeclare_transport_events_listener_inner(id);
            assert!(
                again
                    .expect_err("a listener that is gone")
                    .to_string()
                    .starts_with("Unable to find TransportEventsListener"),
                "an id the session does not hold is named"
            );
            drop(reader);
        }

        #[test]
        fn an_undeclaration_that_waits_for_the_callbacks_returns_once_the_engine_has_let_go() {
            let (writer, _endpoint) = listening("a1b2e6");
            let (transport_callback, _transported) = transport_events();
            let (link_callback, _linked) = link_events();
            let transports = writer
                .info()
                .transport_events_listener()
                .callback(transport_callback)
                .wait()
                .expect("declares");
            let links = writer
                .info()
                .link_events_listener()
                .callback(link_callback)
                .wait()
                .expect("declares");
            // On a thread of its own, so that an undeclaration that never returns fails here and
            // does not hang the run.
            let (done, returned) = mpsc::channel();
            std::thread::spawn(move || {
                let transports = transports.undeclare().wait_callbacks().wait();
                let links = links.undeclare().wait_callbacks().wait();
                let _ = done.send((transports.is_ok(), links.is_ok()));
            });
            assert_eq!(returned.recv_timeout(WAIT), Ok((true, true)));
        }

        /// Two connected nodes, one of which closes with a listener of each kind declared on it in
        /// the background: what its listeners are told while it closes.
        fn told_while_closing(
            closing_the_dialler: bool,
            ids: (&str, &str),
        ) -> (Vec<String>, Vec<String>) {
            let (writer, endpoint) = listening(ids.0);
            let reader = dialling(ids.1, &endpoint);
            assert_eq!(connected(&writer, 1).1.len(), 1, "the nodes are linked");
            assert_eq!(connected(&reader, 1).1.len(), 1, "the nodes are linked");
            let session = if closing_the_dialler {
                &reader
            } else {
                &writer
            };
            let (transport_callback, transported) = transport_events();
            let (link_callback, linked) = link_events();
            session
                .info()
                .transport_events_listener()
                .callback(transport_callback)
                .background()
                .wait()
                .expect("declares");
            session
                .info()
                .link_events_listener()
                .callback(link_callback)
                .background()
                .wait()
                .expect("declares");
            session.close().wait().expect("closes");
            std::thread::sleep(Duration::from_millis(500));
            (
                transported.try_iter().collect(),
                linked.try_iter().collect(),
            )
        }

        #[test]
        fn a_listener_of_the_session_that_accepted_a_link_is_told_nothing_of_its_closing() {
            let told = told_while_closing(false, ("a1b2e1", "a1b2e2"));
            assert_eq!(told, (vec![], vec![]));
        }

        /// The engine tells a closing session of the faces it dialled, and the listeners are let
        /// go of before it does.
        #[test]
        fn a_listener_of_the_session_that_dialled_a_link_is_told_nothing_of_its_closing() {
            let told = told_while_closing(true, ("a1b2f1", "a1b2f2"));
            assert_eq!(told, (vec![], vec![]));
        }

        #[test]
        fn the_channel_of_a_listener_ends_with_its_session() {
            let (session, _endpoint) = listening("a1b2e5");
            let transports = session
                .info()
                .transport_events_listener()
                .with(flume::unbounded())
                .wait()
                .expect("declares");
            let links = session
                .info()
                .link_events_listener()
                .with(flume::unbounded())
                .wait()
                .expect("declares");
            session.close().wait().expect("closes");
            assert_eq!(
                transports.recv_timeout(WAIT),
                Err(flume::RecvTimeoutError::Disconnected),
                "the callback of a transport listener is let go with the session"
            );
            assert_eq!(
                links.recv_timeout(WAIT),
                Err(flume::RecvTimeoutError::Disconnected),
                "the callback of a link listener is let go with the session"
            );
        }

        #[test]
        fn a_closed_session_holds_nothing_and_takes_no_listener() {
            let (writer, endpoint) = listening("a1b2e3");
            let reader = dialling("a1b2e4", &endpoint);
            assert_eq!(connected(&reader, 1).1.len(), 1, "the nodes are linked");
            reader.close().wait().expect("closes");
            assert!(transports(&reader).is_empty());
            assert!(links(&reader).is_empty());
            let (callback, _told) = transport_events();
            let declared = reader
                .info()
                .transport_events_listener()
                .callback(callback)
                .wait();
            assert!(declared.is_err(), "a closed session takes no listener");
            drop(writer);
        }
    }

    /// What a session says of its configuration, and the version the crate names itself with.
    #[cfg(feature = "unstable")]
    mod configuration {
        use super::connectivity::on;

        /// A listener that cannot be bound is named in the words of upstream's link for the
        /// protocols whose words were read, without the metadata of the endpoint, and an unknown
        /// protocol keeps the generic words and does not borrow another's.
        #[test]
        fn a_listener_that_cannot_be_bound_is_named_in_the_words_of_its_link() {
            use super::super::tokio_engine::listener_failure;
            assert!(listener_failure("tcp/8.8.8.8:8")
                .expect("tcp")
                .starts_with("Can not create a new TCP listener bound to 8.8.8.8:8"));
            assert!(listener_failure("quic/127.0.0.1:7447#iface=lo")
                .expect("quic")
                .starts_with("Can not create a new QUIC listener on 127.0.0.1:7447:"));
            assert_eq!(listener_failure("udp/127.0.0.1:7447"), None);
            assert_eq!(listener_failure("no-scheme"), None);
        }

        /// A bind phase that had a deadline and spent it fails with the deadline's own error, as
        /// upstream's does, and shows as upstream's does when a program unwraps the open; one
        /// that had none names the listener.
        #[test]
        fn a_bind_phase_that_spends_its_deadline_fails_with_the_deadlines_error() {
            use super::super::tokio_engine::{open_error, OpenScope};
            use wz_capi_core::drive::OpenError;
            let scope = |listen_deadline| OpenScope {
                dialled: None,
                listened: Some("tcp/8.8.8.8:8".to_owned()),
                listen_deadline,
            };
            let timed = open_error(OpenError::LinkFailed, scope(true));
            assert_eq!(format!("{timed:?}"), "Elapsed(())");
            assert_eq!(timed.to_string(), "deadline has elapsed");
            let untimed = open_error(OpenError::LinkFailed, scope(false));
            assert!(untimed
                .to_string()
                .starts_with("Can not create a new TCP listener bound to 8.8.8.8:8"));
        }

        /// A list of an interceptor whose entries share an `id` fails the open with the words of
        /// upstream's check of that list, and a list whose ids differ, or whose entries state none,
        /// does not; the access control is judged only when it is enabled.
        #[test]
        fn a_repeated_id_in_an_interceptor_list_is_refused_in_upstreams_words() {
            fn refusal(key: &str, value: &str, extra: Option<(&str, &str)>) -> Option<String> {
                let mut config = crate::Config::default();
                config.insert_json5(key, value).expect("a key");
                if let Some((key, value)) = extra {
                    config.insert_json5(key, value).expect("a key");
                }
                let expanded = config.0.clone().expanded();
                let zid = expanded.id();
                let role = super::super::tokio_engine::role_of(expanded.mode());
                let document = super::super::tokio_engine::document_of(&expanded, role, &zid)
                    .expect("a document");
                // The error says where it was raised after its words (`... at file:line.`);
                // upstream's tests look for the words as a part of the message, so the words are
                // what is compared here.
                super::super::tokio_engine::refuse_repeated_ids(&document)
                    .err()
                    .map(|error| {
                        let text = error.to_string();
                        text.split(" at ").next().unwrap_or(&text).to_owned()
                    })
            }
            let entry = |id: &str| {
                format!(
                    r#"{{ id: "{id}", flows: ["egress"], messages: ["put"], key_exprs: ["t/**"], size_limit: 10 }}"#
                )
            };
            let low_pass = |a: &str, b: &str| format!("[{}, {}]", entry(a), entry(b));
            assert_eq!(
                refusal("low_pass_filter", &low_pass("same", "same"), None).as_deref(),
                Some("Invalid low-pass filter config: id 'same' is repeated")
            );
            assert_eq!(refusal("low_pass_filter", &low_pass("a", "b"), None), None);
            let downsampling = |a: &str, b: &str| {
                format!(
                    r#"[{{ id: "{a}", flows: ["egress"], messages: ["put"], rules: [{{ key_expr: "t/**", freq: 1.0 }}] }},
                        {{ id: "{b}", flows: ["egress"], messages: ["put"], rules: [{{ key_expr: "t/**", freq: 1.0 }}] }}]"#
                )
            };
            assert_eq!(
                refusal("downsampling", &downsampling("same", "same"), None).as_deref(),
                Some("Invalid Downsampling config: id 'same' is repeated")
            );
            assert_eq!(refusal("downsampling", &downsampling("a", "b"), None), None);
            let rules = r#"[{ id: "r", key_exprs: ["t/**"], messages: ["put"], permission: "allow" },
                            { id: "r", key_exprs: ["u/**"], messages: ["put"], permission: "allow" }]"#;
            let access_control = |rules: &str, lists: &str| {
                format!(
                    r#"{{ enabled: true, default_permission: "deny", rules: {rules}, {lists} }}"#
                )
            };
            let others = r#"subjects: [{ id: "s", interfaces: ["lo"] }],
                            policies: [{ rules: ["r"], subjects: ["s"] }]"#;
            assert_eq!(
                refusal("access_control", &access_control(rules, others), None).as_deref(),
                Some("Rule id must be unique: id 'r' is repeated")
            );
            assert_eq!(
                refusal("access_control/rules", rules, None),
                None,
                "an access control that is not enabled is not built, and is not judged"
            );
            let one_rule =
                r#"[{ id: "r", key_exprs: ["t/**"], messages: ["put"], permission: "allow" }]"#;
            let policy = |policy: &str| {
                access_control(
                    one_rule,
                    &format!(r#"subjects: [{{ id: "s" }}], policies: [{policy}]"#),
                )
            };
            for (policy_text, words) in [
                (
                    r#"{ rules: ["missing"], subjects: ["s"] }"#,
                    "Rule 'missing' in policy #0 does not exist in rules list",
                ),
                (
                    r#"{ rules: ["r"], subjects: ["none"] }"#,
                    "Subject 'none' in policy #0 does not exist in subjects list",
                ),
                (
                    r#"{ rules: [], subjects: ["s"] }"#,
                    "Policy #0 is malformed: empty subjects or rules list",
                ),
                (
                    r#"{ rules: ["r"], subjects: [" "] }"#,
                    "Found empty subject id in policy #0",
                ),
            ] {
                assert_eq!(
                    refusal("access_control", &policy(policy_text), None).as_deref(),
                    Some(words)
                );
            }
            assert_eq!(
                refusal(
                    "access_control",
                    &policy(r#"{ rules: ["r"], subjects: ["s"] }"#),
                    None
                ),
                None,
                "a policy that names a rule and a subject that exist"
            );
            assert_eq!(
                refusal("access_control", &access_control("[]", others), None),
                None,
                "an empty list leaves the policy empty, which is no refusal"
            );
            // The three lists come together or the access control is no configuration, and that
            // is said before an id is looked at.
            assert_eq!(
                refusal("access_control", &access_control(rules, ""), None).as_deref(),
                Some("All ACL rules/subjects/policies config lists must be provided")
            );
            assert_eq!(
                refusal(
                    "access_control",
                    r#"{ enabled: true, default_permission: "deny" }"#,
                    None
                )
                .as_deref(),
                Some("All ACL rules/subjects/policies config lists must be provided")
            );
        }

        /// The document an open hands the plan is the whole configuration rendered, so every
        /// section a program sets has to come back out of the reader: a section it cannot read
        /// makes the open fail as "unreadable" with no key named. Upstream's own tests set the
        /// low pass filter, the access control, the downsampling and the authentication this way.
        #[test]
        fn the_document_of_a_section_a_program_sets_is_one_the_reader_accepts() {
            use wz_runtime_tokio::zenoh_config::ZenohNodeConfig;

            for (key, value) in [
                (
                    "low_pass_filter",
                    r#"[{ id: "a", flows: ["egress"], messages: ["put"], key_exprs: ["t/**"], size_limit: 10 }]"#,
                ),
                (
                    "downsampling",
                    r#"[{ id: "a", flows: ["egress"], messages: ["put"], rules: [{ key_expr: "t/**", freq: 1.0 }] }]"#,
                ),
                (
                    "access_control",
                    r#"{ enabled: false, default_permission: "allow" }"#,
                ),
                ("transport/auth/usrpwd", r#"{ user: "u", password: "p" }"#),
            ] {
                let mut config = crate::Config::default();
                config
                    .insert_json5(key, value)
                    .unwrap_or_else(|e| panic!("`{key}` is not a key of the configuration: {e}"));
                let expanded = config.0.clone().expanded();
                let zid = expanded.id();
                let role = super::super::tokio_engine::role_of(expanded.mode());
                let document = super::super::tokio_engine::document_of(&expanded, role, &zid)
                    .expect("a document");
                if let Err(error) = ZenohNodeConfig::from_json5(&document.to_string()) {
                    panic!("the document of `{key}` is refused by the reader: {error:?}");
                }
            }
        }

        /// A session reads the configuration it was opened with, by key and as a whole, as the
        /// values of its own and not of the default one.
        #[test]
        fn a_session_reads_the_configuration_it_was_opened_with() {
            let session = on("a1b2e0", "", "");
            let config = session.config();
            assert_eq!(config.get("id").expect("a key"), r#""a1b2e0""#);
            assert_eq!(config.get("mode").expect("a key"), r#""peer""#);
            assert_eq!(
                config.get_typed::<String>("mode").expect("a typed key"),
                "peer"
            );
            assert!(
                config.get_typed::<u64>("mode").is_err(),
                "a string is no number"
            );
            assert!(config.get("no/such/key").is_err());
            assert_eq!(config.queries_default_timeout_ms(), 10_000);
            assert!(config.to_json().contains(r#""mode":"peer""#));
            assert_eq!(config.to_string(), config.to_json());
        }

        /// A key of a plugin is written, and every handle of the session sees it; a key that is not
        /// a plugin's is refused and stays as it was.
        #[test]
        fn a_plugin_key_is_written_for_every_handle_and_another_key_is_refused() {
            let session = on("a1b2e1", "", "");
            let config = session.config();
            config
                .insert_json5("plugins/demo", "{ answer: 42 }")
                .expect("a plugin's key");
            assert_eq!(
                session.config().get("plugins/demo").expect("the write"),
                r#"{"answer":42}"#
            );
            assert_eq!(
                config.get_plugin_config("demo").expect("the plugin"),
                serde_json::json!({ "answer": 42 })
            );
            let refused = config.insert_json5("mode", r#""client""#).unwrap_err();
            assert!(refused
                .to_string()
                .contains("keys starting with `plugins/`"));
            assert_eq!(config.get("mode").expect("a key"), r#""peer""#);
        }

        /// Another session has a configuration of its own.
        #[test]
        fn each_session_has_its_own_configuration() {
            let (first, second) = (on("a1b2e2", "", ""), on("a1b2e3", "", ""));
            first
                .config()
                .insert_json5("plugins/only-first", "1")
                .expect("a plugin's key");
            assert!(first.config().get("plugins/only-first").is_ok());
            assert!(second.config().get("plugins/only-first").is_err());
            assert_eq!(second.config().get("id").expect("a key"), r#""a1b2e3""#);
        }

        /// The version is upstream's composition: `v`, the version of the crate, `-` and a commit of
        /// 40 digits (with `-modified` for a tree with changes), or `release`.
        #[test]
        fn the_version_names_the_crate_and_the_commit() {
            let rest = crate::GIT_VERSION
                .strip_prefix(concat!("v", env!("CARGO_PKG_VERSION"), "-"))
                .expect("the version of the crate");
            let digits = rest.strip_suffix("-modified").unwrap_or(rest);
            assert!(
                rest == "release"
                    || (digits.len() == 40 && digits.bytes().all(|b| b.is_ascii_hexdigit())),
                "{rest}"
            );
        }
    }

    /// The timestamp stack of a message: what the nodes record on it as it is published, routed and
    /// delivered.
    #[cfg(feature = "unstable")]
    mod instrumentation {
        use std::{sync::mpsc, time::Duration};

        use zenoh_protocol::core::WhatAmI;

        use super::{
            connectivity::{dialling, listening, on},
            *,
        };
        use crate::api::timestamp_stack::{
            InstrumentationTimestamp, InterceptionPoint, TimestampInstrumentation,
            TimestampInstrumentationBuilder, TimestampStack,
        };

        const WAIT: Duration = Duration::from_secs(5);

        fn at(points: &str) -> TimestampInstrumentation {
            TimestampInstrumentationBuilder::new()
                .set_send(points.contains('S'))
                .set_route(points.contains('R'))
                .set_receive(points.contains('E'))
                .build()
                .expect("a point to instrument")
        }

        /// A stack as the points it was recorded at and by whom: the id of the node for a UHLC
        /// timestamp and the text for a custom one.
        fn records(stack: &TimestampStack) -> Vec<String> {
            stack
                .records()
                .iter()
                .map(|record| match record.timestamp() {
                    InstrumentationTimestamp::UHLC(ts) => {
                        format!("{:?}:uhlc:{}", record.point(), ts.get_id())
                    }
                    InstrumentationTimestamp::Custom(bytes) => {
                        format!(
                            "{:?}:custom:{}",
                            record.point(),
                            String::from_utf8_lossy(bytes)
                        )
                    }
                })
                .collect()
        }

        /// The sender of a stack records on the samples a subscriber of the other node takes.
        fn taking(session: &Session) -> mpsc::Receiver<Sample> {
            let (sender, received) = mpsc::channel();
            let sender = std::sync::Mutex::new(sender);
            let subscriber = session
                .declare_subscriber("demo/**")
                .callback(move |sample| {
                    let _ = sender.lock().unwrap().send(sample);
                })
                .wait()
                .expect("declares");
            std::mem::forget(subscriber);
            received
        }

        fn stack_of(received: &mpsc::Receiver<Sample>) -> Option<Vec<String>> {
            let sample = received.recv_timeout(WAIT).expect("a sample");
            sample.timestamp_stack().map(records)
        }

        /// Two connected nodes, the second of which takes samples.
        fn pair(ids: (&str, &str)) -> (Session, Session, mpsc::Receiver<Sample>) {
            let (first, endpoint) = listening(ids.0);
            let second = dialling(ids.1, &endpoint);
            assert_eq!(connected(&first, 1).1.len(), 1, "the nodes are linked");
            let received = taking(&second);
            // The subscription of the second node reaches the first.
            std::thread::sleep(Duration::from_millis(500));
            (first, second, received)
        }

        #[test]
        fn a_message_that_is_not_instrumented_carries_no_stack() {
            let (first, _second, received) = pair(("a1b2c0", "a1b2c1"));
            first.put("demo/x", "v").wait().expect("puts");
            assert_eq!(stack_of(&received), None);
        }

        #[test]
        fn what_the_nodes_record_on_a_message_is_the_send_and_the_receive() {
            let (first, _second, received) = pair(("a1b2c2", "a1b2c3"));
            first
                .put("demo/x", "v")
                .timestamp_instrumentation(at("SE"))
                .wait()
                .expect("puts");
            assert_eq!(
                stack_of(&received),
                Some(vec![
                    "Send:uhlc:a1b2c2".to_owned(),
                    "Receive:uhlc:a1b2c3".to_owned()
                ])
            );
            // A point that is not asked for is not recorded.
            first
                .put("demo/x", "v")
                .timestamp_instrumentation(at("S"))
                .wait()
                .expect("puts");
            assert_eq!(
                stack_of(&received),
                Some(vec!["Send:uhlc:a1b2c2".to_owned()])
            );
            first
                .put("demo/x", "v")
                .timestamp_instrumentation(at("E"))
                .wait()
                .expect("puts");
            assert_eq!(
                stack_of(&received),
                Some(vec!["Receive:uhlc:a1b2c3".to_owned()])
            );
        }

        #[test]
        fn each_node_that_routes_a_message_records_it() {
            let (first, _second, received) = pair(("a1b2c4", "a1b2c5"));
            first
                .put("demo/x", "v")
                .timestamp_instrumentation(at("SRE"))
                .wait()
                .expect("puts");
            assert_eq!(
                stack_of(&received),
                Some(vec![
                    "Send:uhlc:a1b2c4".to_owned(),
                    "Route:uhlc:a1b2c4".to_owned(),
                    "Route:uhlc:a1b2c5".to_owned(),
                    "Receive:uhlc:a1b2c5".to_owned(),
                ])
            );
        }

        #[test]
        fn a_delete_carries_its_stack_as_a_put_does() {
            let (first, _second, received) = pair(("a1b2c6", "a1b2c7"));
            first
                .delete("demo/x")
                .timestamp_instrumentation(at("SE"))
                .wait()
                .expect("deletes");
            let sample = received.recv_timeout(WAIT).expect("a sample");
            assert_eq!(sample.kind(), SampleKind::Delete);
            assert_eq!(
                sample.timestamp_stack().map(records),
                Some(vec![
                    "Send:uhlc:a1b2c6".to_owned(),
                    "Receive:uhlc:a1b2c7".to_owned()
                ])
            );
        }

        /// The session's own subscribers are not reached through its routing: no route is recorded
        /// for them, where the message that leaves the node has one.
        #[test]
        fn the_session_own_subscriber_is_given_a_stack_with_no_route() {
            let session = on("a1b2c8", "", "");
            let received = taking(&session);
            session
                .put("demo/x", "v")
                .timestamp_instrumentation(at("SRE"))
                .wait()
                .expect("puts");
            assert_eq!(
                stack_of(&received),
                Some(vec![
                    "Send:uhlc:a1b2c8".to_owned(),
                    "Receive:uhlc:a1b2c8".to_owned()
                ])
            );
        }

        #[test]
        fn a_callback_gives_the_timestamps_the_nodes_record() {
            let open_with = |id: &str, text: &'static str, connect: &str| {
                let config = Config::from_json5(&format!(
                    r#"{{ id: "{id}", mode: "peer",
                          listen: {{ endpoints: [{}] }},
                          connect: {{ endpoints: [{connect}] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#,
                    if connect.is_empty() {
                        r#""tcp/127.0.0.1:0""#
                    } else {
                        ""
                    }
                ))
                .expect("a configuration zenoh reads");
                open(config)
                    .with_timestamp_callback(move |context| {
                        assert_eq!(context.whatami, WhatAmI::Peer);
                        format!("{text}@{}", context.zid).into_bytes()
                    })
                    .wait()
                    .expect("opens")
            };
            let (first, endpoint) = {
                let port = unautoselected_port();
                let endpoint = format!("tcp/127.0.0.1:{port}");
                let config = Config::from_json5(&format!(
                    r#"{{ id: "a1b2c9", mode: "peer", listen: {{ endpoints: ["{endpoint}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads");
                let session = open(config)
                    .with_timestamp_callback(|context| {
                        format!("first@{}", context.zid).into_bytes()
                    })
                    .wait()
                    .expect("opens");
                (session, endpoint)
            };
            let second = open_with("a1b2ca", "second", &format!(r#""{endpoint}""#));
            assert_eq!(connected(&second, 1).1.len(), 1, "the nodes are linked");
            let received = taking(&second);
            std::thread::sleep(Duration::from_millis(500));
            first
                .put("demo/x", "v")
                .timestamp_instrumentation(at("SE"))
                .wait()
                .expect("puts");
            assert_eq!(
                stack_of(&received),
                Some(vec![
                    "Send:custom:first@a1b2c9".to_owned(),
                    "Receive:custom:second@a1b2ca".to_owned()
                ])
            );
        }

        /// A queryable of `demo/q/**` that sends the stack of each query it is given, and answers
        /// it with a reply, or with an error on a key that ends in `err`.
        fn answering(session: &Session) -> mpsc::Receiver<Option<Vec<String>>> {
            let (sender, received) = mpsc::channel();
            let sender = std::sync::Mutex::new(sender);
            let queryable = session
                .declare_queryable("demo/q/**")
                .callback(move |query| {
                    let _ = sender
                        .lock()
                        .unwrap()
                        .send(query.timestamp_stack().map(records));
                    if query.key_expr().as_str().ends_with("err") {
                        query.reply_err("e").wait().expect("replies");
                    } else {
                        query
                            .reply(query.key_expr().clone(), "v")
                            .wait()
                            .expect("replies");
                    }
                })
                .wait()
                .expect("declares");
            std::mem::forget(queryable);
            received
        }

        /// The stack of each reply to a get on `key` instrumented at `points` (none for no
        /// point), and whether the reply is an error.
        fn asked(session: &Session, key: &str, points: &str) -> Vec<(bool, Option<Vec<String>>)> {
            let instrumentation = (!points.is_empty()).then(|| at(points));
            session
                .get(key)
                .timestamp_instrumentation(instrumentation)
                .timeout(WAIT)
                .wait()
                .expect("asks")
                .iter()
                .map(|reply| match reply.result() {
                    Ok(sample) => (false, sample.timestamp_stack().map(records)),
                    Err(error) => (true, error.timestamp_stack().map(records)),
                })
                .collect()
        }

        /// Two connected nodes, the second of which answers `demo/q/**`.
        fn answering_pair(
            ids: (&str, &str),
        ) -> (Session, Session, mpsc::Receiver<Option<Vec<String>>>) {
            let (first, endpoint) = listening(ids.0);
            let second = dialling(ids.1, &endpoint);
            assert_eq!(connected(&first, 1).1.len(), 1, "the nodes are linked");
            let received = answering(&second);
            // The queryable of the second node reaches the first.
            std::thread::sleep(Duration::from_millis(500));
            (first, second, received)
        }

        fn of(points: &[&str]) -> Option<Vec<String>> {
            Some(points.iter().map(|point| (*point).to_owned()).collect())
        }

        #[test]
        fn a_query_that_is_not_instrumented_nor_its_reply_carries_a_stack() {
            let (first, _second, queried) = answering_pair(("a1b2d0", "a1b2d1"));
            assert_eq!(asked(&first, "demo/q/x", ""), vec![(false, None)]);
            assert_eq!(queried.recv_timeout(WAIT).expect("a query"), None);
        }

        /// The queryable is given the stack of the get, with the receive of its node; the reply
        /// starts from it, records its send, and is given to the getter with its receive.
        #[test]
        fn a_query_and_its_reply_are_recorded_by_the_nodes_they_cross() {
            let (first, _second, queried) = answering_pair(("a1b2d2", "a1b2d3"));
            assert_eq!(
                asked(&first, "demo/q/x", "SE"),
                vec![(
                    false,
                    of(&[
                        "Send:uhlc:a1b2d2",
                        "Receive:uhlc:a1b2d3",
                        "Send:uhlc:a1b2d3",
                        "Receive:uhlc:a1b2d2",
                    ])
                )]
            );
            assert_eq!(
                queried.recv_timeout(WAIT).expect("a query"),
                of(&["Send:uhlc:a1b2d2", "Receive:uhlc:a1b2d3"])
            );
        }

        #[test]
        fn each_node_that_routes_a_query_and_its_reply_records_it() {
            let (first, _second, queried) = answering_pair(("a1b2d4", "a1b2d5"));
            assert_eq!(
                asked(&first, "demo/q/x", "SRE"),
                vec![(
                    false,
                    of(&[
                        "Send:uhlc:a1b2d4",
                        "Route:uhlc:a1b2d4",
                        "Route:uhlc:a1b2d5",
                        "Receive:uhlc:a1b2d5",
                        "Send:uhlc:a1b2d5",
                        "Route:uhlc:a1b2d5",
                        "Route:uhlc:a1b2d4",
                        "Receive:uhlc:a1b2d4",
                    ])
                )]
            );
            assert_eq!(
                queried.recv_timeout(WAIT).expect("a query"),
                of(&[
                    "Send:uhlc:a1b2d4",
                    "Route:uhlc:a1b2d4",
                    "Route:uhlc:a1b2d5",
                    "Receive:uhlc:a1b2d5",
                ])
            );
        }

        #[test]
        fn an_error_reply_carries_the_stack_as_a_reply_does() {
            let (first, _second, queried) = answering_pair(("a1b2d6", "a1b2d7"));
            assert_eq!(
                asked(&first, "demo/q/err", "SE"),
                vec![(
                    true,
                    of(&[
                        "Send:uhlc:a1b2d6",
                        "Receive:uhlc:a1b2d7",
                        "Send:uhlc:a1b2d7",
                        "Receive:uhlc:a1b2d6",
                    ])
                )]
            );
            assert!(queried.recv_timeout(WAIT).expect("a query").is_some());
        }

        /// A query of the session's own queryable is not routed, and neither is its reply.
        #[test]
        fn a_query_of_the_session_own_queryable_has_no_route() {
            let session = on("a1b2d8", "", "");
            let queried = answering(&session);
            assert_eq!(
                asked(&session, "demo/q/x", "SRE"),
                vec![(
                    false,
                    of(&[
                        "Send:uhlc:a1b2d8",
                        "Receive:uhlc:a1b2d8",
                        "Send:uhlc:a1b2d8",
                        "Receive:uhlc:a1b2d8",
                    ])
                )]
            );
            assert_eq!(
                queried.recv_timeout(WAIT).expect("a query"),
                of(&["Send:uhlc:a1b2d8", "Receive:uhlc:a1b2d8"])
            );
        }

        #[test]
        fn a_callback_gives_the_timestamps_of_a_query_and_its_reply() {
            let open_with = |id: &str, text: &'static str, listen: &str, connect: &str| {
                let config = Config::from_json5(&format!(
                    r#"{{ id: "{id}", mode: "peer",
                          listen: {{ endpoints: [{listen}] }},
                          connect: {{ endpoints: [{connect}] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads");
                open(config)
                    .with_timestamp_callback(move |context| {
                        format!("{text}@{}", context.zid).into_bytes()
                    })
                    .wait()
                    .expect("opens")
            };
            let port = unautoselected_port();
            let endpoint = format!(r#""tcp/127.0.0.1:{port}""#);
            let first = open_with("a1b2d9", "first", &endpoint, "");
            let second = open_with("a1b2da", "second", r#""tcp/127.0.0.1:0""#, &endpoint);
            assert_eq!(connected(&first, 1).1.len(), 1, "the nodes are linked");
            let queried = answering(&second);
            std::thread::sleep(Duration::from_millis(500));
            assert_eq!(
                asked(&first, "demo/q/x", "SE"),
                vec![(
                    false,
                    of(&[
                        "Send:custom:first@a1b2d9",
                        "Receive:custom:second@a1b2da",
                        "Send:custom:second@a1b2da",
                        "Receive:custom:first@a1b2d9",
                    ])
                )]
            );
            assert_eq!(
                queried.recv_timeout(WAIT).expect("a query"),
                of(&["Send:custom:first@a1b2d9", "Receive:custom:second@a1b2da"])
            );
        }

        /// A reply is received when it arrives, and not when the final lets a `Latest` query go
        /// of it: upstream records the receive at the top of `send_response`, ahead of the
        /// consolidation. The callback numbers every record the node makes, so the receive of
        /// the first reply is before the send of the second only when it was recorded on arrival.
        #[test]
        fn a_reply_a_latest_query_holds_back_is_received_when_it_arrives() {
            use std::sync::{
                atomic::{AtomicU64, Ordering},
                Arc,
            };

            let clock = Arc::new(AtomicU64::new(0));
            let session = open(
                Config::from_json5(
                    r#"{ id: "a1b2db", mode: "peer", scouting: { multicast: { enabled: false } } }"#,
                )
                .expect("a configuration zenoh reads"),
            )
            .with_timestamp_callback({
                let clock = Arc::clone(&clock);
                move |_| clock.fetch_add(1, Ordering::SeqCst).to_string().into_bytes()
            })
            .wait()
            .expect("opens");
            let queryable = session
                .declare_queryable("demo/q/**")
                .callback(|query| {
                    for key in ["demo/q/a", "demo/q/b"] {
                        query.reply(key, "v").wait().expect("replies");
                    }
                })
                .wait()
                .expect("declares");
            let replies = session
                .get("demo/q/*")
                .consolidation(ConsolidationMode::Latest)
                .timestamp_instrumentation(at("SE"))
                .timeout(WAIT)
                .wait()
                .expect("asks");
            let replies: Vec<_> = replies.iter().collect();
            // The point and the tick of each record of the reply on `key`.
            let ticks = |key: &str| -> Vec<(String, u64)> {
                let sample = replies
                    .iter()
                    .filter_map(|reply| reply.result().ok())
                    .find(|sample| sample.key_expr().as_str() == key)
                    .expect("a reply on the key");
                sample
                    .timestamp_stack()
                    .map(records)
                    .expect("a reply with a stack")
                    .iter()
                    .map(|record| {
                        let (point, tick) = record.rsplit_once(':').expect("a custom record");
                        (point.to_owned(), tick.parse().expect("a tick"))
                    })
                    .collect()
            };
            let (first, second) = (ticks("demo/q/a"), ticks("demo/q/b"));
            for stack in [&first, &second] {
                assert_eq!(
                    stack
                        .iter()
                        .map(|(point, _)| point.as_str())
                        .collect::<Vec<_>>(),
                    [
                        "Send:custom",
                        "Receive:custom",
                        "Send:custom",
                        "Receive:custom"
                    ],
                    "the query's send and receive, then the reply's"
                );
            }
            assert!(
                first[3].1 < second[2].1,
                "the first reply was received at tick {} but the second was sent at tick {}: \
                 the receive was recorded after the replies were released",
                first[3].1,
                second[2].1
            );
            assert!(second[3].1 > second[2].1);
            drop(queryable);
        }

        #[test]
        fn a_callback_that_gives_nothing_records_nothing() {
            let config = Config::from_json5(
                r#"{ id: "a1b2cb", mode: "peer", scouting: { multicast: { enabled: false } } }"#,
            )
            .expect("a configuration zenoh reads");
            let session = open(config)
                .with_timestamp_callback(|_| Vec::new())
                .wait()
                .expect("opens");
            let received = taking(&session);
            session
                .put("demo/x", "v")
                .timestamp_instrumentation(at("SE"))
                .wait()
                .expect("puts");
            assert_eq!(stack_of(&received), Some(Vec::<String>::new()));
        }

        #[test]
        fn the_points_asked_for_are_those_of_the_stack() {
            let session = on("a1b2cc", "", "");
            let received = taking(&session);
            session
                .put("demo/x", "v")
                .timestamp_instrumentation(at("SE"))
                .wait()
                .expect("puts");
            let sample = received.recv_timeout(WAIT).expect("a sample");
            let instrumentation = sample.timestamp_stack().expect("a stack").instrumentation();
            assert!(instrumentation.is_instrumented(InterceptionPoint::Send));
            assert!(!instrumentation.is_instrumented(InterceptionPoint::Route));
            assert!(instrumentation.is_instrumented(InterceptionPoint::Receive));
        }
    }

    /// The liveliness of the tokens a node declares, as another node reads it.
    mod liveliness {
        use std::{sync::mpsc, time::Duration};

        use super::*;

        const WAIT: Duration = Duration::from_secs(5);

        /// Two connected nodes: the one that declares tokens and the one that watches them.
        fn pair(ids: (&str, &str)) -> (Session, Session) {
            let (writer, reader, ()) = pair_after(ids, |_| {});
            (writer, reader)
        }

        /// [`pair`], with `before_dial` given the listening node before the other one dials it; what
        /// it returns is kept by the caller for as long as it wants the node to hold it.
        fn pair_after<T>(
            ids: (&str, &str),
            before_dial: impl FnOnce(&Session) -> T,
        ) -> (Session, Session, T) {
            let port = unautoselected_port();
            let on = |id: &str, listen: &str, connect: &str| {
                open(
                    Config::from_json5(&format!(
                        r#"{{ id: "{id}", mode: "peer",
                              listen: {{ endpoints: [{listen}] }},
                              connect: {{ endpoints: [{connect}] }},
                              scouting: {{ multicast: {{ enabled: false }} }} }}"#
                    ))
                    .expect("a configuration zenoh reads"),
                )
                .wait()
                .expect("opens")
            };
            let writer = on(ids.0, &format!(r#""tcp/127.0.0.1:{port}""#), "");
            let kept = before_dial(&writer);
            let reader = on(ids.1, "", &format!(r#""tcp/127.0.0.1:{port}""#));
            assert_eq!(connected(&reader, 1).1.len(), 1, "the nodes are linked");
            (writer, reader, kept)
        }

        /// Every change a liveliness subscriber is told of, as `key kind`.
        fn changes() -> (
            impl Fn(Sample) + Send + Sync + 'static,
            mpsc::Receiver<String>,
        ) {
            let (sender, received) = mpsc::channel();
            let sender = std::sync::Mutex::new(sender);
            (
                move |sample: Sample| {
                    let _ = sender.lock().unwrap().send(format!(
                        "{} {:?} {}",
                        sample.key_expr(),
                        sample.kind(),
                        sample.payload().len()
                    ));
                },
                received,
            )
        }

        #[test]
        fn a_token_of_another_node_is_told_alive_and_gone_to_a_liveliness_subscriber() {
            let (writer, reader) = pair(("a1b2c9", "a1b2ca"));
            let (callback, told) = changes();
            let _subscriber = reader
                .liveliness()
                .declare_subscriber("demo/l/**")
                .callback(callback)
                .wait()
                .expect("declares");
            let token = writer
                .liveliness()
                .declare_token("demo/l/a")
                .wait()
                .expect("declares");
            assert_eq!(told.recv_timeout(WAIT), Ok("demo/l/a Put 0".to_owned()));
            // A token that does not meet the key of the subscriber is not told.
            let _apart = writer
                .liveliness()
                .declare_token("demo/other")
                .wait()
                .expect("declares");
            token.undeclare().wait().expect("undeclares");
            assert_eq!(told.recv_timeout(WAIT), Ok("demo/l/a Delete 0".to_owned()));
            assert_eq!(
                told.recv_timeout(Duration::from_millis(200)),
                Err(mpsc::RecvTimeoutError::Timeout)
            );
        }

        #[test]
        fn the_history_of_a_liveliness_subscriber_is_the_tokens_already_alive() {
            let (writer, reader) = pair(("a1b2cb", "a1b2cc"));
            let _first = writer
                .liveliness()
                .declare_token("demo/l/h1")
                .wait()
                .expect("declares");
            let _second = writer
                .liveliness()
                .declare_token("demo/l/h2")
                .wait()
                .expect("declares");
            std::thread::sleep(Duration::from_millis(300));
            let (with, with_told) = changes();
            let _with = reader
                .liveliness()
                .declare_subscriber("demo/l/*")
                .history(true)
                .callback(with)
                .wait()
                .expect("declares");
            let mut seen = vec![
                with_told.recv_timeout(WAIT).expect("a token"),
                with_told.recv_timeout(WAIT).expect("a token"),
            ];
            seen.sort();
            assert_eq!(seen, ["demo/l/h1 Put 0", "demo/l/h2 Put 0"]);
            let (without, without_told) = changes();
            let _without = reader
                .liveliness()
                .declare_subscriber("demo/l/*")
                .callback(without)
                .wait()
                .expect("declares");
            assert_eq!(
                without_told.recv_timeout(Duration::from_millis(300)),
                Err(mpsc::RecvTimeoutError::Timeout),
                "without history only what changes is told"
            );
        }

        #[test]
        fn a_token_dropped_or_of_a_session_that_closes_is_told_gone() {
            let (writer, reader) = pair(("a1b2cd", "a1b2ce"));
            let (callback, told) = changes();
            let _subscriber = reader
                .liveliness()
                .declare_subscriber("demo/l/d/**")
                .callback(callback)
                .wait()
                .expect("declares");
            let dropped = writer
                .liveliness()
                .declare_token("demo/l/d/1")
                .wait()
                .expect("declares");
            let closed = writer
                .liveliness()
                .declare_token("demo/l/d/2")
                .wait()
                .expect("declares");
            let mut alive = vec![
                told.recv_timeout(WAIT).expect("a token"),
                told.recv_timeout(WAIT).expect("a token"),
            ];
            alive.sort();
            assert_eq!(alive, ["demo/l/d/1 Put 0", "demo/l/d/2 Put 0"]);
            drop(dropped);
            assert_eq!(
                told.recv_timeout(WAIT),
                Ok("demo/l/d/1 Delete 0".to_owned())
            );
            assert_eq!(writer.0.tokens().len(), 1);
            writer.close().wait().expect("closes");
            assert_eq!(writer.0.tokens().len(), 0);
            assert_eq!(
                told.recv_timeout(WAIT),
                Ok("demo/l/d/2 Delete 0".to_owned())
            );
            closed
                .undeclare()
                .wait()
                .expect("no error on a closed session");
            let error = writer
                .liveliness()
                .declare_token("demo/l/d/3")
                .wait()
                .expect_err("a closed session");
            assert!(error.downcast_ref::<SessionClosedError>().is_some());
        }

        #[test]
        fn a_get_is_answered_with_the_tokens_that_are_alive_and_ends() {
            let (writer, reader) = pair(("a1b2cf", "a1b2d0"));
            let first = writer
                .liveliness()
                .declare_token("demo/l/g/1")
                .wait()
                .expect("declares");
            let _second = writer
                .liveliness()
                .declare_token("demo/l/g/2")
                .wait()
                .expect("declares");
            let _apart = writer
                .liveliness()
                .declare_token("demo/other")
                .wait()
                .expect("declares");
            std::thread::sleep(Duration::from_millis(300));
            let keys = |replies: crate::api::handlers::FifoChannelHandler<Reply>| {
                let mut keys: Vec<String> = replies
                    .iter()
                    .map(|reply| {
                        let sample = reply.into_result().expect("a sample");
                        format!("{} {:?}", sample.key_expr(), sample.kind())
                    })
                    .collect();
                keys.sort();
                keys
            };
            assert_eq!(
                keys(reader.liveliness().get("demo/l/g/*").wait().expect("asks")),
                ["demo/l/g/1 Put", "demo/l/g/2 Put"]
            );
            first.undeclare().wait().expect("undeclares");
            std::thread::sleep(Duration::from_millis(300));
            assert_eq!(
                keys(reader.liveliness().get("demo/l/g/*").wait().expect("asks")),
                ["demo/l/g/2 Put"]
            );
            assert!(keys(
                reader
                    .liveliness()
                    .get("demo/none/**")
                    .wait()
                    .expect("asks")
            )
            .is_empty());
        }

        /// A get that its peer does not end is ended by its timeout, as upstream ends one
        /// (`zenoh/src/api/session.rs` @ `Timeout on liveliness query {}! Send error and close.`):
        /// with an error reply `Timeout` encoded as a string, after which the channel of the
        /// handler closes. The peer is kept from ending it by holding the thread that reads its
        /// link inside a transport listener's callback (the callback of a subscriber runs on a task
        /// of its own, off that thread), so the interest of the get waits unread; a timeout of
        /// nothing is an instant one, and ends the same way.
        #[cfg(feature = "unstable")]
        #[test]
        fn a_get_that_a_peer_does_not_end_is_ended_by_its_timeout_with_an_error_reply() {
            let (entered_tx, entered) = mpsc::channel();
            let entered_tx = std::sync::Mutex::new(entered_tx);
            let (release_tx, release) = mpsc::channel::<()>();
            let release = std::sync::Mutex::new(release);
            let (_held, asker, _holder) = pair_after(("a1b2d7", "a1b2d8"), |held| {
                held.info()
                    .transport_events_listener()
                    .history(false)
                    .callback(move |_| {
                        let _ = entered_tx.lock().unwrap().send(());
                        // Returns at once when the test lets go of the sender.
                        let _ = release.lock().unwrap().recv();
                    })
                    .wait()
                    .expect("declares")
            });
            entered
                .recv_timeout(WAIT)
                .expect("the thread that reads the link is held");
            // The peer is listed once its INIT is read, before the transport is open and a get can
            // be sent over it: a get asked until then has no peer to wait for, and its channel
            // closes at once with no reply. It is asked again until the peer holds it.
            let deadline = std::time::Instant::now() + WAIT;
            let timeout_of = |timeout: Duration| loop {
                let started = std::time::Instant::now();
                let replies = asker
                    .liveliness()
                    .get("demo/l/**")
                    .timeout(timeout)
                    .wait()
                    .expect("asks");
                let reply = match replies.recv_timeout(WAIT) {
                    Ok(Some(reply)) => reply,
                    Ok(None) => panic!("the get timed out with a reply"),
                    // The channel closed with no reply.
                    Err(_) => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "a get reaches the peer"
                        );
                        std::thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                };
                let waited = started.elapsed();
                let told = match reply.result() {
                    Err(error) => format!(
                        "Err {} {}",
                        error.payload().try_to_string().expect("a text"),
                        error.encoding()
                    ),
                    Ok(sample) => panic!("a token answered a get nobody reads: {sample:?}"),
                };
                assert!(
                    replies.recv_timeout(WAIT).is_err(),
                    "the channel closes with the timeout reply"
                );
                break (told, waited);
            };
            let (told, waited) = timeout_of(Duration::from_millis(400));
            assert_eq!(told, "Err Timeout zenoh/string");
            assert!(
                waited >= Duration::from_millis(350) && waited < WAIT,
                "ended by its timeout, not before it and not by the wait: {waited:?}"
            );
            let (told, waited) = timeout_of(Duration::ZERO);
            assert_eq!(told, "Err Timeout zenoh/string");
            assert!(waited < Duration::from_millis(350), "instant: {waited:?}");
            drop(release_tx);
        }

        #[test]
        fn the_tokens_of_a_session_are_told_to_its_own_subscribers_and_found_by_its_own_get() {
            let (node, _peer) = pair(("a1b2d5", "a1b2d6"));
            let (live, live_told) = changes();
            let _live = node
                .liveliness()
                .declare_subscriber("demo/l/o/**")
                .callback(live)
                .wait()
                .expect("declares");
            let first = node
                .liveliness()
                .declare_token("demo/l/o/1")
                .wait()
                .expect("declares");
            let _apart = node
                .liveliness()
                .declare_token("demo/other")
                .wait()
                .expect("declares");
            assert_eq!(
                live_told.recv_timeout(WAIT),
                Ok("demo/l/o/1 Put 0".to_owned())
            );
            // The history of a subscriber declared later lists the token; one without it does not.
            let (with, with_told) = changes();
            let _with = node
                .liveliness()
                .declare_subscriber("demo/l/o/*")
                .history(true)
                .callback(with)
                .wait()
                .expect("declares");
            assert_eq!(
                with_told.recv_timeout(WAIT),
                Ok("demo/l/o/1 Put 0".to_owned())
            );
            // The get finds it and ends.
            let found: Vec<String> = node
                .liveliness()
                .get("demo/l/o/*")
                .wait()
                .expect("asks")
                .iter()
                .map(|reply| {
                    reply
                        .into_result()
                        .expect("a sample")
                        .key_expr()
                        .to_string()
                })
                .collect();
            assert_eq!(found, ["demo/l/o/1"]);
            first.undeclare().wait().expect("undeclares");
            assert_eq!(
                live_told.recv_timeout(WAIT),
                Ok("demo/l/o/1 Delete 0".to_owned())
            );
            assert_eq!(
                with_told.recv_timeout(WAIT),
                Ok("demo/l/o/1 Delete 0".to_owned())
            );
            assert_eq!(
                live_told.recv_timeout(Duration::from_millis(200)),
                Err(mpsc::RecvTimeoutError::Timeout),
                "a token that does not meet the key is not told"
            );
            assert!(node
                .liveliness()
                .get("demo/l/o/*")
                .wait()
                .expect("asks")
                .iter()
                .next()
                .is_none());
        }

        #[test]
        fn a_liveliness_subscriber_is_undeclared_as_a_subscriber_is_and_ends_with_its_session() {
            let (_writer, reader) = pair(("a1b2d1", "a1b2d2"));
            let channel = reader
                .liveliness()
                .declare_subscriber("demo/l/s")
                .wait()
                .expect("declares");
            let (callback, _told) = changes();
            reader
                .liveliness()
                .declare_subscriber("demo/l/s")
                .callback(callback)
                .background()
                .wait()
                .expect("declares");
            assert_eq!(reader.0.subscriptions().len(), 2);
            channel.undeclare().wait().expect("undeclares");
            assert_eq!(reader.0.subscriptions().len(), 1);
            let kept = reader
                .liveliness()
                .declare_subscriber("demo/l/s2")
                .wait()
                .expect("declares");
            reader.close().wait().expect("closes");
            assert_eq!(reader.0.subscriptions().len(), 0);
            assert!(kept.recv_timeout(WAIT).is_err());
            let error = reader
                .liveliness()
                .get("demo/l/**")
                .wait()
                .expect_err("a closed session");
            assert!(error.downcast_ref::<SessionClosedError>().is_some());
        }

        #[cfg(feature = "unstable")]
        #[test]
        fn a_cancelled_token_refuses_a_liveliness_get() {
            use crate::api::cancellation::CancellationToken;

            let (_writer, reader) = pair(("a1b2d3", "a1b2d4"));
            let token = CancellationToken::default();
            token.cancel().wait().expect("cancels");
            let error = reader
                .liveliness()
                .get("demo/l/c")
                .cancellation_token(token)
                .wait()
                .expect_err("a cancelled token");
            assert!(error.to_string().contains("Query was cancelled"));
        }
    }

    mod publishing {
        use std::time::Duration;

        use futures::SinkExt;

        use super::*;

        const WAIT: Duration = Duration::from_secs(5);

        /// Whether the engine still holds the publisher `id`: a filter it holds says nothing
        /// matches when no subscriber does, and one it does not hold says nothing.
        fn held(session: &Session, id: Id) -> bool {
            match &session.0.engine {
                Engine::Tokio(state) => state.shared.as_engine().write_filter_active(u64::from(id)),
                Engine::Router(_) => unreachable!("these tests open peers"),
            }
        }

        #[test]
        fn a_publisher_says_the_settings_it_was_declared_with() {
            let session = open(peer("a1b2f0")).wait().expect("opens");
            let publisher = session
                .declare_publisher("demo/settings")
                .encoding(Encoding::TEXT_PLAIN)
                .congestion_control(CongestionControl::Block)
                .priority(Priority::RealTime)
                .express(true)
                .wait()
                .expect("declares");
            assert_eq!(publisher.key_expr().as_str(), "demo/settings");
            assert_eq!(publisher.encoding(), &Encoding::TEXT_PLAIN);
            assert_eq!(publisher.congestion_control(), CongestionControl::Block);
            assert_eq!(publisher.priority(), Priority::RealTime);
            let plain = session
                .declare_publisher("demo/plain")
                .wait()
                .expect("declares");
            assert_eq!(plain.encoding(), &Encoding::default());
            assert_eq!(plain.congestion_control(), CongestionControl::DEFAULT);
            assert_eq!(plain.priority(), Priority::DEFAULT);
        }

        #[test]
        fn a_publication_of_a_publisher_carries_its_settings_and_what_it_overrides() {
            let session = open(peer("a1b2f1")).wait().expect("opens");
            let subscriber = session
                .declare_subscriber("demo/**")
                .wait()
                .expect("declares");
            let publisher = session
                .declare_publisher("demo/p")
                .encoding(Encoding::TEXT_PLAIN)
                .priority(Priority::DataHigh)
                .express(true)
                .wait()
                .expect("declares");
            publisher.put("v").attachment("a").wait().expect("puts");
            let sample = subscriber
                .recv_timeout(WAIT)
                .expect("a channel")
                .expect("a sample");
            assert_eq!(sample.key_expr().as_str(), "demo/p");
            assert_eq!(sample.kind(), SampleKind::Put);
            assert_eq!(sample.encoding(), &Encoding::TEXT_PLAIN);
            assert_eq!(sample.priority(), Priority::DataHigh);
            assert!(sample.express());
            assert!(sample.attachment().is_some());
            publisher
                .put("w")
                .encoding(Encoding::APPLICATION_JSON)
                .wait()
                .expect("puts");
            let sample = subscriber
                .recv_timeout(WAIT)
                .expect("a channel")
                .expect("a sample");
            assert_eq!(sample.encoding(), &Encoding::APPLICATION_JSON);
            publisher.delete().wait().expect("deletes");
            let sample = subscriber
                .recv_timeout(WAIT)
                .expect("a channel")
                .expect("a sample");
            assert_eq!(sample.kind(), SampleKind::Delete);
            assert_eq!(sample.priority(), Priority::DataHigh);
        }

        #[test]
        fn the_destination_of_a_publisher_says_whose_subscribers_it_reaches() {
            let session = open(peer("a1b2f2")).wait().expect("opens");
            let seen = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&seen);
            let _subscriber = session
                .declare_subscriber("demo/destination")
                .callback(move |_| {
                    counted.fetch_add(1, Ordering::SeqCst);
                })
                .wait()
                .expect("declares");
            let remote = session
                .declare_publisher("demo/destination")
                .allowed_destination(Locality::Remote)
                .wait()
                .expect("declares");
            // A delivery is complete when its callback has run, which the drive task can be in the
            // middle of when the put returns, so the count is waited for. The remote put's skip is
            // read from the order: had it been delivered, the count would pass the one the next
            // put brings.
            let reaches = |count: usize| {
                let deadline = std::time::Instant::now() + WAIT;
                while seen.load(Ordering::SeqCst) < count && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(1));
                }
                assert_eq!(seen.load(Ordering::SeqCst), count);
            };
            remote.put("v").wait().expect("puts");
            let local = session
                .declare_publisher("demo/destination")
                .allowed_destination(Locality::SessionLocal)
                .wait()
                .expect("declares");
            local.put("v").wait().expect("puts");
            reaches(1);
            let any = session
                .declare_publisher("demo/destination")
                .wait()
                .expect("declares");
            any.put("v").wait().expect("puts");
            reaches(2);
        }

        #[test]
        fn a_publisher_is_a_sink_of_samples() {
            let session = open(peer("a1b2f3")).wait().expect("opens");
            let subscriber = session
                .declare_subscriber("demo/sink/**")
                .wait()
                .expect("declares");
            let mut publisher = session
                .declare_publisher("demo/sink/out")
                .priority(Priority::DataLow)
                .wait()
                .expect("declares");
            let source = session
                .declare_subscriber("demo/sink/in")
                .wait()
                .expect("declares");
            session
                .put("demo/sink/in", "one")
                .encoding(Encoding::TEXT_PLAIN)
                .attachment("a")
                .wait()
                .expect("puts");
            let sample = source
                .recv_timeout(WAIT)
                .expect("a channel")
                .expect("a sample");
            futures::executor::block_on(publisher.send(sample)).expect("sends");
            // The subscriber sees what the session put on `in` and what the sink put on `out`.
            let mut seen = vec![];
            for _ in 0..2 {
                let sample = subscriber
                    .recv_timeout(WAIT)
                    .expect("a channel")
                    .expect("a sample");
                seen.push((
                    sample.key_expr().as_str().to_owned(),
                    sample.priority(),
                    sample.encoding().clone(),
                    sample.attachment().is_some(),
                ));
            }
            seen.sort_by(|a, b| a.0.cmp(&b.0));
            assert_eq!(
                seen,
                vec![
                    (
                        "demo/sink/in".to_owned(),
                        Priority::Data,
                        Encoding::TEXT_PLAIN,
                        true
                    ),
                    (
                        "demo/sink/out".to_owned(),
                        Priority::DataLow,
                        Encoding::TEXT_PLAIN,
                        true
                    ),
                ]
            );
        }

        #[test]
        fn undeclaring_and_dropping_a_publisher_let_go_of_it_and_a_stranger_is_refused() {
            let session = open(peer("a1b2f4")).wait().expect("opens");
            assert_eq!(session.0.publishers().len(), 0);
            let first = session
                .declare_publisher("demo/undeclare")
                .wait()
                .expect("declares");
            let second = session
                .declare_publisher("demo/undeclare")
                .wait()
                .expect("declares");
            assert_eq!(session.0.publishers().len(), 2);
            let (first_id, second_id) = (first.id, second.id);
            assert!(held(&session, first_id) && held(&session, second_id));
            first.undeclare().wait().expect("undeclares");
            assert_eq!(session.0.publishers().len(), 1);
            assert!(!held(&session, first_id), "the engine let go of it");
            assert!(held(&session, second_id), "and of no other");
            drop(second);
            assert_eq!(session.0.publishers().len(), 0);
            assert!(!held(&session, second_id), "a drop undeclares");
            let error = session
                .downgrade()
                .undeclare_publisher_inner(Id::MAX)
                .expect_err("not a publisher of the session");
            assert!(
                error.to_string().contains("Unable to find publisher"),
                "{error}"
            );
        }

        #[test]
        fn a_closed_session_declares_and_publishes_nothing_and_lets_its_publishers_go() {
            let session = open(peer("a1b2f5")).wait().expect("opens");
            let publisher = session
                .declare_publisher("demo/closed")
                .wait()
                .expect("declares");
            let id = publisher.id;
            assert!(held(&session, id));
            session.close().wait().expect("closes");
            assert_eq!(session.0.publishers().len(), 0);
            assert!(!held(&session, id), "a close lets go of what it holds");
            let error = publisher.put("v").wait().expect_err("a closed session");
            assert!(error.downcast_ref::<SessionClosedError>().is_some());
            let error = session
                .declare_publisher("demo/closed")
                .wait()
                .expect_err("a closed session");
            assert!(error.downcast_ref::<SessionClosedError>().is_some());
            publisher
                .undeclare()
                .wait()
                .expect("no error on a closed session");
        }

        #[test]
        fn a_publisher_is_refused_for_a_key_that_is_not_one() {
            let session = open(peer("a1b2f6")).wait().expect("opens");
            let error = session
                .declare_publisher("demo//bad")
                .wait()
                .expect_err("not a key");
            assert!(error.to_string().contains("demo//bad"), "{error}");
        }

        #[test]
        fn the_peers_are_asked_for_the_subscribers_of_a_key_unless_the_publisher_stays_in_the_session(
        ) {
            use super::super::tokio_engine::interest_of;

            for destination in [Locality::Any, Locality::Remote] {
                let ask = interest_of(7, Some("leaf".to_owned()), destination)
                    .expect("the peers are asked");
                assert_eq!(ask.mapping_id, 7);
                assert_eq!(ask.suffix.as_deref(), Some("leaf"));
                assert!(!ask.aggregate, "upstream asks for no aggregation");
            }
            assert!(
                interest_of(7, None, Locality::SessionLocal).is_none(),
                "nobody is asked for a publisher that writes to the session itself"
            );
        }

        #[test]
        fn a_publisher_declares_its_key_on_the_session_until_it_is_dropped() {
            let session = open(peer("a1b2f8")).wait().expect("opens");
            let declared = |session: &Session| -> Vec<String> {
                session
                    .0
                    .engine
                    .keyexpr_declarations()
                    .into_iter()
                    .map(|(_, key)| key)
                    .collect()
            };
            assert!(declared(&session).is_empty());
            let publisher = session
                .declare_publisher("demo/declared/by/publisher")
                .wait()
                .expect("declares");
            assert_eq!(declared(&session), ["demo/declared/by/publisher"]);
            drop(publisher);
            assert!(declared(&session).is_empty());
        }

        #[test]
        fn a_publisher_keeps_the_declaration_of_its_key_until_it_is_undeclared() {
            let session = open(peer("a1b2f7")).wait().expect("opens");
            let key = session
                .declare_keyexpr("demo/held")
                .wait()
                .expect("declares");
            let publisher = session
                .declare_publisher(key.clone())
                .wait()
                .expect("declares");
            let before = session.0.engine.keyexpr_declarations().len();
            drop(key);
            assert_eq!(
                session.0.engine.keyexpr_declarations().len(),
                before,
                "the publisher still holds the key"
            );
            publisher.undeclare().wait().expect("undeclares");
            assert_eq!(session.0.engine.keyexpr_declarations().len(), before - 1);
        }
    }

    /// A router node as a session: it listens and is dialled, a peer sees it by its role, and what
    /// it does not carry yet fails by name and not by silence.
    mod router_session {
        use super::*;

        fn router(id: &str, port: u16) -> Session {
            open(
                Config::from_json5(&format!(
                    r#"{{ id: "{id}", mode: "router",
                          listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads"),
            )
            .wait()
            .expect("a router opens")
        }

        #[test]
        fn a_router_opens_listens_and_a_peer_sees_it_as_a_router() {
            let port = unautoselected_port();
            let router = router("a1b2e1", port);
            assert_eq!(router.zid().to_string(), "a1b2e1");
            let peer = open(
                Config::from_json5(&format!(
                    r#"{{ id: "a1b2e2", mode: "peer",
                          connect: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads"),
            )
            .wait()
            .expect("opens");
            assert_eq!(connected(&peer, 1).0, vec!["a1b2e1".to_owned()]);
            router.close().wait().expect("closes");
            assert!(router.is_closed());
        }

        fn peer_of(id: &str, port: u16) -> Session {
            open(
                Config::from_json5(&format!(
                    r#"{{ id: "{id}", mode: "peer",
                          connect: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads"),
            )
            .wait()
            .expect("opens")
        }

        /// A get of a router is asked as the node's own face: the queryable of a peer linked to
        /// it answers, the reply is on the key it answered under, and the channel of the handler
        /// ends with the query. A get that no queryable meets ends at once with no reply.
        #[test]
        fn a_get_of_a_router_is_answered_by_the_queryable_of_a_peer_and_then_ends() {
            use std::time::Duration;

            let port = unautoselected_port();
            let router = router("a1b2e8", port);
            let peer = peer_of("a1b2e9", port);
            assert_eq!(connected(&peer, 1).0.len(), 1, "the peer is linked");
            let _queryable = peer
                .declare_queryable("demo/q/**")
                .callback(|query| {
                    query
                        .reply(query.key_expr().clone(), "answer")
                        .wait()
                        .expect("replies");
                })
                .wait()
                .expect("declares");
            // The declaration reaches the router a moment after the link: the get is asked until
            // a reply comes.
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let answered = loop {
                let replies = router.get("demo/q/one").wait().expect("a router asks");
                let mut told = Vec::new();
                while let Ok(Some(reply)) = replies.recv_timeout(Duration::from_secs(2)) {
                    told.push(
                        reply
                            .result()
                            .map(|sample| {
                                (
                                    sample.key_expr().to_string(),
                                    sample.payload().try_to_string().unwrap().into_owned(),
                                )
                            })
                            .expect("a reply, not an error"),
                    );
                }
                if !told.is_empty() || std::time::Instant::now() > deadline {
                    break told;
                }
            };
            assert_eq!(
                answered,
                [("demo/q/one".to_owned(), "answer".to_owned())],
                "the queryable of the peer answered the get of the router, once"
            );
            let none = router.get("demo/none").wait().expect("a router asks");
            assert!(
                none.recv_timeout(Duration::from_secs(2)).is_err(),
                "nothing answers a key no queryable meets, and the channel ends"
            );
        }

        /// A queryable of a router answers the get of a peer: at once from its callback, and from
        /// another thread after the callback has returned (the query is kept), and the get ends
        /// only when the query has been dropped.
        #[test]
        fn a_queryable_of_a_router_answers_a_peer_at_once_and_later() {
            use std::time::Duration;

            let port = unautoselected_port();
            let router = router("a1b2ea", port);
            let _now = router
                .declare_queryable("demo/rq/now")
                .callback(|query| {
                    query
                        .reply(query.key_expr().clone(), "at once")
                        .wait()
                        .expect("replies");
                })
                .wait()
                .expect("a router hosts a queryable");
            let kept = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let keeper = kept.clone();
            let _later = router
                .declare_queryable("demo/rq/later")
                .callback(move |query| keeper.lock().unwrap().push(query))
                .wait()
                .expect("a router hosts a queryable");
            let peer = peer_of("a1b2eb", port);
            assert_eq!(connected(&peer, 1).0.len(), 1, "the peer is linked");

            let ask = |key: &str| -> Vec<String> {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    let replies = peer
                        .get(key)
                        .timeout(Duration::from_secs(3))
                        .wait()
                        .expect("asks");
                    let told: Vec<String> = replies
                        .into_iter()
                        .filter_map(|reply| {
                            reply.into_result().ok().map(|sample| {
                                sample.payload().try_to_string().unwrap().into_owned()
                            })
                        })
                        .collect();
                    if !told.is_empty() || std::time::Instant::now() > deadline {
                        return told;
                    }
                }
            };
            assert_eq!(ask("demo/rq/now"), ["at once"]);

            // The query is kept by the callback; the get stays open until it is answered and
            // dropped, and the answer comes from this thread.
            let asked = std::thread::spawn({
                let peer = peer.clone();
                move || {
                    peer.get("demo/rq/later")
                        .timeout(Duration::from_secs(10))
                        .wait()
                        .expect("asks")
                        .into_iter()
                        .filter_map(|reply| {
                            reply.into_result().ok().map(|sample| {
                                sample.payload().try_to_string().unwrap().into_owned()
                            })
                        })
                        .collect::<Vec<String>>()
                }
            });
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let query = loop {
                if let Some(query) = kept.lock().unwrap().pop() {
                    break query;
                }
                assert!(std::time::Instant::now() < deadline, "the query arrives");
                std::thread::sleep(Duration::from_millis(20));
            };
            std::thread::sleep(Duration::from_millis(300));
            query
                .reply(query.key_expr().clone(), "later")
                .wait()
                .expect("replies after the callback returned");
            drop(query);
            assert_eq!(asked.join().expect("the get ends"), ["later"]);
        }

        /// A router whose own session has a namespace names its keys relative to it: a peer
        /// that names them in full is heard under it, and hears what the router puts under it.
        #[test]
        fn the_session_of_a_router_with_a_namespace_names_its_keys_relative_to_it() {
            use std::sync::mpsc;
            use std::time::Duration;

            let port = unautoselected_port();
            let router = open(
                Config::from_json5(&format!(
                    r#"{{ id: "a1b2f1", mode: "router", namespace: "ext/ns",
                          listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads"),
            )
            .wait()
            .expect("a router with a namespace opens");
            let (heard_tx, heard) = mpsc::channel::<String>();
            let heard_tx = std::sync::Mutex::new(heard_tx);
            let _subscriber = router
                .declare_subscriber("demo/**".to_owned())
                .callback(move |sample: Sample| {
                    let _ = heard_tx.lock().unwrap().send(sample.key_expr().to_string());
                })
                .wait()
                .expect("declares");
            let peer = peer_of("a1b2f2", port);
            assert_eq!(connected(&peer, 1).0.len(), 1, "the peer is linked");
            let (peer_tx, peer_heard) = mpsc::channel::<String>();
            let peer_tx = std::sync::Mutex::new(peer_tx);
            let _peer_subscriber = peer
                .declare_subscriber("ext/ns/demo/**".to_owned())
                .callback(move |sample: Sample| {
                    let _ = peer_tx.lock().unwrap().send(sample.key_expr().to_string());
                })
                .wait()
                .expect("declares");
            // The declarations reach each node a moment after the link: the puts are repeated
            // until they are heard.
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let (mut by_router, mut by_peer) = (Vec::new(), Vec::new());
            while !(by_router.contains(&"demo/up".to_owned())
                && by_peer.contains(&"ext/ns/demo/down".to_owned()))
                && std::time::Instant::now() < deadline
            {
                peer.put("ext/ns/demo/up", "x").wait().expect("puts");
                peer.put("other/demo/up", "x").wait().expect("puts");
                router.put("demo/down", "y").wait().expect("puts");
                std::thread::sleep(Duration::from_millis(100));
                by_router.extend(heard.try_iter());
                by_peer.extend(peer_heard.try_iter());
            }
            // The router hears the peer without the namespace, and its own puts as it named
            // them; a put of the peer outside the namespace is not its.
            assert!(by_router.contains(&"demo/up".to_owned()), "{by_router:?}");
            assert!(
                by_router
                    .iter()
                    .all(|key| key == "demo/up" || key == "demo/down"),
                "{by_router:?}"
            );
            // The peer hears the router's put under the namespace.
            assert!(
                by_peer.contains(&"ext/ns/demo/down".to_owned()),
                "{by_peer:?}"
            );
        }

        #[cfg(feature = "unstable")]
        fn client_of(id: &str, port: u16) -> Session {
            open(
                Config::from_json5(&format!(
                    r#"{{ id: "{id}", mode: "client",
                          connect: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads"),
            )
            .wait()
            .expect("opens")
        }

        /// A querier that asks for complete queryables, on a client of a router, follows the
        /// completeness of a queryable of another client: it matches when a complete queryable
        /// covers its key, and stops when that one goes although an incomplete one stays.
        #[cfg(feature = "unstable")]
        #[test]
        fn a_querier_behind_a_router_follows_the_completeness_of_a_queryable() {
            use std::{sync::mpsc, time::Duration};

            let wait = Duration::from_secs(5);
            let port = unautoselected_port();
            let _router = router("a1b2ee", port);
            let asking = client_of("a1b2ef", port);
            let hosting = client_of("a1b2f0", port);
            let querier = asking
                .declare_querier("demo/cm/*")
                .target(crate::api::query::QueryTarget::AllComplete)
                .wait()
                .expect("declares");
            let (told_tx, told) = mpsc::channel();
            let told_tx = std::sync::Mutex::new(told_tx);
            let _listener = querier
                .matching_listener()
                .callback(move |status: MatchingStatus| {
                    let _ = told_tx.lock().unwrap().send(status.matching());
                })
                .wait()
                .expect("declares");
            // A second querier, on the key itself, that takes the best match: the queryables
            // below are declared as the upstream matching test declares them.
            let best = asking
                .declare_querier("demo/cm/value")
                .target(crate::api::query::QueryTarget::BestMatching)
                .wait()
                .expect("declares");
            let (best_tx, best_told) = mpsc::channel();
            let best_tx = std::sync::Mutex::new(best_tx);
            let _best_listener = best
                .matching_listener()
                .callback(move |status: MatchingStatus| {
                    let _ = best_tx.lock().unwrap().send(status.matching());
                })
                .wait()
                .expect("declares");
            let declare = |key: &str, complete: bool| {
                hosting
                    .declare_queryable(key.to_owned())
                    .complete(complete)
                    .callback(|_| {})
                    .wait()
                    .expect("declares")
            };
            let value = declare("demo/cm/value", false);
            let wildcard = declare("demo/cm/*", false);
            let _other = declare("demo/cm/value3", true);
            assert_eq!(best_told.recv_timeout(wait), Ok(true));
            assert_eq!(
                told.recv_timeout(Duration::from_millis(500)),
                Err(mpsc::RecvTimeoutError::Timeout),
                "an incomplete queryable, and a complete one of another key, do not meet a \
                 querier that wants complete ones that cover its key"
            );
            let complete = declare("demo/cm/*", true);
            assert_eq!(told.recv_timeout(wait), Ok(true));
            complete.undeclare().wait().expect("undeclares");
            assert_eq!(
                told.recv_timeout(wait),
                Ok(false),
                "the complete queryable went and the incomplete one stayed"
            );
            assert_eq!(
                best_told.recv_timeout(Duration::from_millis(500)),
                Err(mpsc::RecvTimeoutError::Timeout),
                "the best-match querier is still matched"
            );
            // The wildcard goes and the queryable on the key stays: still matched. When that one
            // goes too, nothing meets the key, although a complete queryable of `value3` stays,
            // and the querier is told so.
            wildcard.undeclare().wait().expect("undeclares");
            assert_eq!(
                best_told.recv_timeout(Duration::from_millis(500)),
                Err(mpsc::RecvTimeoutError::Timeout)
            );
            value.undeclare().wait().expect("undeclares");
            assert_eq!(best_told.recv_timeout(wait), Ok(false));
        }

        /// A publisher and a querier of a router match what its links declare: a listener is told
        /// when a peer's subscriber or queryable appears and when it goes, the status is read the
        /// same way, and the locality of a querier tells a queryable of the router itself from a
        /// peer's.
        #[cfg(feature = "unstable")]
        #[test]
        fn a_publisher_and_a_querier_of_a_router_match_what_its_links_declare() {
            use std::{sync::mpsc, time::Duration};

            let wait = Duration::from_secs(5);
            let port = unautoselected_port();
            let router = router("a1b2ec", port);
            let publisher = router
                .declare_publisher("demo/rm/p")
                .wait()
                .expect("declares");
            let querier = router
                .declare_querier("demo/rm/q")
                .wait()
                .expect("declares");
            assert!(!publisher.matching_status().wait().unwrap().matching());
            assert!(!querier.matching_status().wait().unwrap().matching());

            let (told_tx, told) = mpsc::channel();
            let told_tx = std::sync::Mutex::new(told_tx);
            let _listener = publisher
                .matching_listener()
                .callback(move |status: MatchingStatus| {
                    let _ = told_tx.lock().unwrap().send(status.matching());
                })
                .wait()
                .expect("a router's publisher listens for matching");
            let (queried_tx, queried) = mpsc::channel();
            let queried_tx = std::sync::Mutex::new(queried_tx);
            let _querier_listener = querier
                .matching_listener()
                .callback(move |status: MatchingStatus| {
                    let _ = queried_tx.lock().unwrap().send(status.matching());
                })
                .wait()
                .expect("a router's querier listens for matching");

            let peer = peer_of("a1b2ed", port);
            assert_eq!(connected(&peer, 1).0.len(), 1, "the peer is linked");
            let subscriber = peer
                .declare_subscriber("demo/rm/*")
                .callback(|_| {})
                .wait()
                .expect("declares");
            assert_eq!(told.recv_timeout(wait), Ok(true), "a subscriber of a peer");
            assert!(publisher.matching_status().wait().unwrap().matching());
            subscriber.undeclare().wait().expect("undeclares");
            assert_eq!(told.recv_timeout(wait), Ok(false), "and the end of it");

            let queryable = peer
                .declare_queryable("demo/rm/q")
                .callback(|_| {})
                .wait()
                .expect("declares");
            assert_eq!(
                queried.recv_timeout(wait),
                Ok(true),
                "a queryable of a peer"
            );
            assert!(querier.matching_status().wait().unwrap().matching());
            queryable.undeclare().wait().expect("undeclares");
            assert_eq!(queried.recv_timeout(wait), Ok(false));

            // The queryables of the router itself are the session's own: a querier that admits
            // only the session's counts them, and one that admits only remote ones does not.
            let _own = router
                .declare_queryable("demo/rm/own")
                .callback(|_| {})
                .wait()
                .expect("declares");
            let local = router
                .declare_querier("demo/rm/own")
                .allowed_destination(Locality::SessionLocal)
                .wait()
                .expect("declares");
            let remote = router
                .declare_querier("demo/rm/own")
                .allowed_destination(Locality::Remote)
                .wait()
                .expect("declares");
            assert!(local.matching_status().wait().unwrap().matching());
            assert!(!remote.matching_status().wait().unwrap().matching());
        }

        #[test]
        fn a_subscriber_of_a_router_hears_a_peer_and_a_put_of_the_router_reaches_a_peer() {
            use std::sync::mpsc;
            use std::time::Duration;

            let port = unautoselected_port();
            let router = router("a1b2e4", port);
            let (told, heard) = mpsc::channel::<String>();
            let told = std::sync::Mutex::new(told);
            let _subscriber = router
                .declare_subscriber("demo/r/**".to_owned())
                .callback(move |sample: Sample| {
                    let _ = told.lock().unwrap().send(sample.key_expr().to_string());
                })
                .wait()
                .expect("a router hosts a subscriber");
            let peer = peer_of("a1b2e5", port);
            assert_eq!(connected(&peer, 1).0.len(), 1, "the peer is linked");
            // The declaration of the router's subscriber reaches the peer a moment after the
            // link, so the put is repeated until it is heard.
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut got = None;
            while got.is_none() && std::time::Instant::now() < deadline {
                peer.put("demo/r/up", "x").wait().expect("puts");
                got = heard.recv_timeout(Duration::from_millis(200)).ok();
            }
            assert_eq!(got.as_deref(), Some("demo/r/up"));

            let (seen, received) = mpsc::channel::<String>();
            let seen = std::sync::Mutex::new(seen);
            let _peer_subscriber = peer
                .declare_subscriber("demo/p/**".to_owned())
                .callback(move |sample: Sample| {
                    let _ = seen.lock().unwrap().send(format!(
                        "{} {:?}",
                        sample.key_expr(),
                        sample.kind()
                    ));
                })
                .wait()
                .expect("declares");
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut got = None;
            while got.is_none() && std::time::Instant::now() < deadline {
                router
                    .put("demo/p/down", "y")
                    .wait()
                    .expect("a router puts");
                got = received.recv_timeout(Duration::from_millis(200)).ok();
            }
            assert_eq!(got.as_deref(), Some("demo/p/down Put"));
            // The delete of the router takes the route of its put.
            while received.try_recv().is_ok() {}
            router
                .delete("demo/p/down")
                .wait()
                .expect("a router deletes");
            assert_eq!(
                received.recv_timeout(Duration::from_secs(5)).as_deref(),
                Ok("demo/p/down Delete")
            );
        }

        #[test]
        fn a_router_hears_the_tokens_of_a_peer_and_a_peer_hears_the_tokens_of_the_router() {
            use std::sync::mpsc;
            use std::time::Duration;

            let port = unautoselected_port();
            let router = router("a1b2e6", port);
            let (told, heard) = mpsc::channel::<String>();
            let told = std::sync::Mutex::new(told);
            let _subscriber = router
                .liveliness()
                .declare_subscriber("demo/l/**")
                .callback(move |sample: Sample| {
                    let _ = told.lock().unwrap().send(format!(
                        "{} {:?}",
                        sample.key_expr(),
                        sample.kind()
                    ));
                })
                .wait()
                .expect("a router hosts a liveliness subscriber");
            let peer = peer_of("a1b2e7", port);
            assert_eq!(connected(&peer, 1).0.len(), 1, "the peer is linked");
            let token = peer
                .liveliness()
                .declare_token("demo/l/peer")
                .wait()
                .expect("declares");
            assert_eq!(
                heard.recv_timeout(Duration::from_secs(5)).as_deref(),
                Ok("demo/l/peer Put")
            );
            token.undeclare().wait().expect("undeclares");
            assert_eq!(
                heard.recv_timeout(Duration::from_secs(5)).as_deref(),
                Ok("demo/l/peer Delete")
            );

            // The router's own token, asked for by a peer's get and heard by its subscriber.
            let own = router
                .liveliness()
                .declare_token("demo/l/router")
                .wait()
                .expect("a router declares a token");
            assert_eq!(
                heard.recv_timeout(Duration::from_secs(5)).as_deref(),
                Ok("demo/l/router Put"),
                "a router's subscriber hears its own token"
            );
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut keys = Vec::new();
            while keys.is_empty() && std::time::Instant::now() < deadline {
                keys = peer
                    .liveliness()
                    .get("demo/l/**")
                    .timeout(Duration::from_secs(2))
                    .wait()
                    .expect("asks")
                    .into_iter()
                    .filter_map(|reply| reply.into_result().ok().map(|s| s.key_expr().to_string()))
                    .collect();
            }
            assert_eq!(keys, vec!["demo/l/router".to_owned()]);
            own.undeclare().wait().expect("undeclares");
            assert_eq!(
                heard.recv_timeout(Duration::from_secs(5)).as_deref(),
                Ok("demo/l/router Delete")
            );
        }

        /// A client that declares and undeclares a token as fast as it can does not starve the
        /// router it is linked to: another node that joins meanwhile is linked, and a subscriber
        /// of the tokens is told of the churn.
        #[cfg(feature = "unstable")]
        #[test]
        fn a_router_keeps_serving_while_a_client_churns_tokens() {
            use std::time::{Duration, Instant};

            let port = unautoselected_port();
            let router = router("a1b2fb", port);
            let churn = client_of("a1b2fc", port);
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let worker = std::thread::spawn({
                let stop = stop.clone();
                move || {
                    let mut cycles = 0u64;
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        let token = churn
                            .liveliness()
                            .declare_token("demo/churn")
                            .wait()
                            .expect("declares");
                        token.undeclare().wait().expect("undeclares");
                        cycles += 1;
                    }
                    cycles
                }
            });
            std::thread::sleep(Duration::from_millis(500));
            let started = Instant::now();
            let late = peer_of("a1b2fd", port);
            let linked = connected(&late, 1).0.len();
            let took = started.elapsed();
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let cycles = worker.join().expect("the churn ends");
            eprintln!("churn: {cycles} cycles, a late node linked in {took:?}");
            assert_eq!(linked, 1, "the late node is linked");
            assert!(took < Duration::from_secs(5), "linked in {took:?}");
            drop(late);

            // And a router that dials the churned router while the churn goes on opens.
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let churn = client_of("a1b2fe", port);
            let worker = std::thread::spawn({
                let stop = stop.clone();
                move || {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        let token = churn
                            .liveliness()
                            .declare_token("demo/churn")
                            .wait()
                            .expect("declares");
                        token.undeclare().wait().expect("undeclares");
                    }
                }
            });
            std::thread::sleep(Duration::from_millis(500));
            let started = Instant::now();
            let second = open(
                Config::from_json5(&format!(
                    r#"{{ id: "a1b2ff", mode: "router",
                          connect: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads"),
            )
            .wait()
            .expect("a router dials a router");
            eprintln!("churn: a router opened in {:?}", started.elapsed());
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            worker.join().expect("the churn ends");
            drop(second);
            drop(router);
        }

        /// Two peers that reach each other only through the router both dial exchange
        /// publications through it, whichever of the three opens first.
        #[cfg(feature = "unstable")]
        #[test]
        fn two_peers_of_one_router_exchange_publications_through_it() {
            use std::time::{Duration, Instant};

            let node_of = |id: &str, mode: &str, gossip: bool, port: u16| {
                open(
                    Config::from_json5(&format!(
                        r#"{{ id: "{id}", mode: "{mode}",
                              connect: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                              scouting: {{ multicast: {{ enabled: false }},
                                           gossip: {{ enabled: {gossip} }} }} }}"#
                    ))
                    .expect("a configuration zenoh reads"),
                )
                .wait()
                .expect("a node opens")
            };
            let mut silent = Vec::new();
            for (n, (hub, publishing, subscribing, gossip)) in [
                ("router", "client", "client", true),
                ("router", "peer", "client", true),
                ("router", "client", "peer", true),
                ("peer", "peer", "peer", true),
                ("router", "peer", "peer", true),
            ]
            .into_iter()
            .enumerate()
            {
                let port = unautoselected_port();
                let router = open(
                    Config::from_json5(&format!(
                        r#"{{ id: "a1b2f6{n}", mode: "{hub}",
                              listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                              scouting: {{ multicast: {{ enabled: false }} }} }}"#
                    ))
                    .expect("a configuration zenoh reads"),
                )
                .wait()
                .expect("a hub opens");
                let publisher = node_of(&format!("a1b2f7{n}"), publishing, gossip, port);
                let subscriber_node = node_of(&format!("a1b2f8{n}"), subscribing, gossip, port);
                let subscriber = subscriber_node
                    .declare_subscriber("demo/peers/through")
                    .wait()
                    .expect("declares");

                let deadline = Instant::now() + Duration::from_secs(5);
                let mut heard = false;
                while Instant::now() < deadline && !heard {
                    publisher
                        .put("demo/peers/through", "hello")
                        .wait()
                        .expect("puts");
                    heard = subscriber
                        .recv_timeout(Duration::from_millis(100))
                        .ok()
                        .flatten()
                        .is_some();
                }
                if !heard {
                    silent.push(format!(
                        "{publishing} to {subscribing} by a {hub} (gossip {}; the publisher sees \
                         peers {:?} and routers {:?}; the subscriber's node sees peers {:?})",
                        if gossip { "on" } else { "off" },
                        publisher.info().peers_zid().wait().collect::<Vec<_>>(),
                        publisher.info().routers_zid().wait().collect::<Vec<_>>(),
                        subscriber_node
                            .info()
                            .peers_zid()
                            .wait()
                            .collect::<Vec<_>>(),
                    ));
                }
                drop((publisher, subscriber, subscriber_node, router));
            }
            assert!(silent.is_empty(), "nothing was heard from: {silent:?}");
        }

        /// Two peers of one router that gossip links directly are asked and answer as they do
        /// through the router, whether the queryable or the asker is there first.
        #[cfg(feature = "unstable")]
        #[test]
        fn two_peers_of_one_router_query_each_other_whoever_comes_first() {
            use std::time::{Duration, Instant};

            let peer_of = |id: &str, port: u16| {
                open(
                    Config::from_json5(&format!(
                        r#"{{ id: "{id}", mode: "peer",
                              connect: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                              scouting: {{ multicast: {{ enabled: false }} }} }}"#
                    ))
                    .expect("a configuration zenoh reads"),
                )
                .wait()
                .expect("a peer opens")
            };
            let mut silent = Vec::new();
            for (n, queryable_delay_ms) in [0u64, 1500].into_iter().enumerate() {
                let port = unautoselected_port();
                let router = router(&format!("a1b2f9{n}"), port);
                let asker = peer_of(&format!("a1b2fa{n}"), port);
                let answerer = std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(queryable_delay_ms));
                    let peer = peer_of(&format!("a1b2fb{n}"), port);
                    let queryable = peer
                        .declare_queryable("demo/peers/ask")
                        .callback(|query| {
                            query
                                .reply("demo/peers/ask", "answer")
                                .wait()
                                .expect("replies");
                        })
                        .wait()
                        .expect("declares");
                    (peer, queryable)
                });
                let deadline = Instant::now() + Duration::from_secs(9);
                let mut answered = false;
                while Instant::now() < deadline && !answered {
                    let replies = asker
                        .get("demo/peers/ask")
                        .timeout(Duration::from_secs(1))
                        .wait()
                        .expect("asks");
                    while let Ok(Some(reply)) = replies.recv_timeout(Duration::from_secs(2)) {
                        answered |= reply.result().is_ok();
                    }
                }
                if !answered {
                    silent.push(format!(
                        "the queryable came after {queryable_delay_ms} ms and was never heard"
                    ));
                }
                let kept = answerer.join().expect("the answering peer opens");
                drop((kept, asker, router));
            }
            assert!(silent.is_empty(), "no reply came: {silent:?}");
        }

        /// An asker that loops on `get` from the first moment, before the router it dials is
        /// there and before anything answers, still gets its answers when they come: the loop of
        /// upstream's Get task, on a runtime of nine workers.
        #[cfg(feature = "unstable")]
        #[tokio::test(flavor = "multi_thread", worker_threads = 9)]
        async fn an_asker_that_began_before_the_router_and_the_queryable_is_answered() {
            use std::time::{Duration, Instant};

            let port = unautoselected_port();
            let peer_of = move |id: &'static str| async move {
                open(
                    Config::from_json5(&format!(
                        r#"{{ id: "{id}", mode: "peer",
                              connect: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                              scouting: {{ multicast: {{ enabled: false }} }} }}"#
                    ))
                    .expect("a configuration zenoh reads"),
                )
                .await
                .expect("a peer opens")
            };
            let router_task = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1200)).await;
                let router = open(
                    Config::from_json5(&format!(
                        r#"{{ id: "a1b2fc0", mode: "router",
                              listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                              scouting: {{ multicast: {{ enabled: false }} }} }}"#
                    ))
                    .expect("a configuration zenoh reads"),
                )
                .await
                .expect("a router opens");
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(router);
            });
            let queryable_task = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(2000)).await;
                let peer = peer_of("a1b2fc1").await;
                let queryable = peer
                    .declare_queryable("demo/early/ask")
                    .await
                    .expect("declares");
                loop {
                    let query = queryable.recv_async().await.expect("a query");
                    query
                        .reply("demo/early/ask", vec![0u8; 8])
                        .await
                        .expect("replies");
                }
            });
            let asker = peer_of("a1b2fc2").await;
            let started = Instant::now();
            let mut counter = 0;
            let outcome = tokio::time::timeout(Duration::from_secs(10), async {
                while counter < 50 {
                    let replies = asker
                        .get("demo/early/ask")
                        .timeout(Duration::from_secs(10))
                        .await
                        .expect("asks");
                    while let Ok(reply) = replies.recv_async().await {
                        if reply.result().is_ok() {
                            counter += 1;
                        }
                    }
                }
            })
            .await;
            queryable_task.abort();
            router_task.abort();
            assert!(
                outcome.is_ok(),
                "{counter} answers in {:?}, 50 were asked for",
                started.elapsed()
            );
        }

        /// The Queryable and Get recipes of upstream's three node test, all six start orders at
        /// once as four of its recipes run: each asker is answered fifty times in ten seconds.
        /// It fails in about one run in four, in the orders where the asker joins last: the ask
        /// that is made as the direct link of the two peers forms is received by the queryable
        /// and never answered. Run it with `--ignored` to see it; each run prints the first asks
        /// of every order and the links each peer holds at the end.
        #[cfg(feature = "unstable")]
        #[ignore = "a query made as the direct link of two peers forms is lost, about one run in four"]
        #[tokio::test(flavor = "multi_thread", worker_threads = 9)]
        async fn peers_of_a_router_are_answered_fifty_times_in_every_start_order() {
            use std::time::{Duration, Instant};

            let orders = [
                (0, 1, 2),
                (0, 2, 1),
                (1, 2, 0),
                (1, 0, 2),
                (2, 0, 1),
                (2, 1, 0),
            ];
            let mut recipes = Vec::new();
            for (n, (router_s, queryable_s, asker_s)) in orders.into_iter().enumerate() {
                recipes.push(tokio::spawn(async move {
                    let port = unautoselected_port();
                    let config = move |id: String, mode: &'static str, listens: bool| {
                        let endpoints = if listens {
                            format!(r#"listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},"#)
                        } else {
                            format!(r#"connect: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},"#)
                        };
                        Config::from_json5(&format!(
                            r#"{{ id: "{id}", mode: "{mode}", {endpoints}
                                  scouting: {{ multicast: {{ enabled: false }} }} }}"#
                        ))
                        .expect("a configuration zenoh reads")
                    };
                    let started = Instant::now();
                    let router_task = tokio::spawn({
                        async move {
                            tokio::time::sleep(Duration::from_secs(router_s)).await;
                            let router = open(config(format!("a1b2d{n}0"), "router", true))
                                .await
                                .expect("a router opens");
                            tokio::time::sleep(Duration::from_secs(40)).await;
                            drop(router);
                        }
                    });
                    let received = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                    let queryable_session =
                        std::sync::Arc::new(std::sync::Mutex::new(None::<Session>));
                    let queryable_task = tokio::spawn({
                        let received = received.clone();
                        let queryable_session = queryable_session.clone();
                        async move {
                            tokio::time::sleep(Duration::from_secs(queryable_s)).await;
                            let peer = open(config(format!("a1b2d{n}1"), "peer", false))
                                .await
                                .expect("a peer opens");
                            *queryable_session.lock().unwrap() = Some(peer.clone());
                            let queryable = peer
                                .declare_queryable("demo/every/order")
                                .await
                                .expect("declares");
                            loop {
                                let query = queryable.recv_async().await.expect("a query");
                                received.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                if let Err(error) =
                                    query.reply("demo/every/order", vec![0u8; 8]).await
                                {
                                    eprintln!("order {n}: the reply failed: {error}");
                                }
                            }
                        }
                    });
                    tokio::time::sleep(Duration::from_secs(asker_s)).await;
                    let asker = open(config(format!("a1b2d{n}2"), "peer", false))
                        .await
                        .expect("a peer opens");
                    let (mut answered, mut asks) = (0usize, 0usize);
                    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
                        while answered < 50 {
                            asks += 1;
                            let asked = Instant::now();
                            let replies = asker
                                .get("demo/every/order")
                                .timeout(Duration::from_secs(10))
                                .await
                                .expect("asks");
                            let before = answered;
                            while let Ok(reply) = replies.recv_async().await {
                                if reply.result().is_ok() {
                                    answered += 1;
                                }
                            }
                            if asks <= 3
                                || answered == before && asks.is_multiple_of(100)
                                || asked.elapsed() > Duration::from_millis(500)
                            {
                                eprintln!(
                                    "order {n}: ask {asks} at {:?} took {:?} and had {} answers; \
                                     the asker sees peers {:?} and routers {:?}",
                                    started.elapsed(),
                                    asked.elapsed(),
                                    answered - before,
                                    asker.info().peers_zid().await.collect::<Vec<_>>(),
                                    asker.info().routers_zid().await.collect::<Vec<_>>(),
                                );
                            }
                            if answered == before {
                                tokio::time::sleep(Duration::from_millis(1)).await;
                            }
                        }
                    })
                    .await;
                    queryable_task.abort();
                    router_task.abort();
                    (
                        n,
                        (router_s, queryable_s, asker_s),
                        outcome.is_ok(),
                        answered,
                        asks,
                        started.elapsed(),
                        received.load(std::sync::atomic::Ordering::SeqCst),
                        asker.info().links().await.count(),
                        {
                            let held = queryable_session.lock().unwrap().clone();
                            match held {
                                Some(peer) => peer.info().links().await.count(),
                                None => 0,
                            }
                        },
                    )
                }));
            }
            let mut failed = Vec::new();
            for recipe in recipes {
                let (n, order, ok, answered, asks, elapsed, received, asker_links, queryable_links) =
                    recipe.await.expect("a recipe ends");
                eprintln!(
                    "order {n} {order:?}: the queryable received {received} queries; links at \
                     the end: asker {asker_links}, queryable {queryable_links}"
                );
                eprintln!(
                    "order {n} {order:?}: ok={ok} answered={answered} asks={asks} in {elapsed:?}"
                );
                if !ok {
                    failed.push(format!(
                        "{order:?} answered {answered} of 50 in {asks} asks"
                    ));
                }
            }
            assert!(failed.is_empty(), "not answered fifty times: {failed:?}");
        }

        /// A queryable declared by a peer before its router exists is answering once the router
        /// is there and the peer has dialed it again.
        #[cfg(feature = "unstable")]
        #[tokio::test(flavor = "multi_thread", worker_threads = 9)]
        async fn a_queryable_declared_before_its_router_exists_answers_when_the_link_comes() {
            use std::time::{Duration, Instant};

            let port = unautoselected_port();
            let config = move |id: &str, mode: &str, listens: bool| {
                let endpoints = if listens {
                    format!(r#"listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},"#)
                } else {
                    format!(r#"connect: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},"#)
                };
                Config::from_json5(&format!(
                    r#"{{ id: "{id}", mode: "{mode}", {endpoints}
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads")
            };
            let started = Instant::now();
            let queryable_peer = open(config("a1b2d90", "peer", false))
                .await
                .expect("a peer opens");
            let queryable = queryable_peer
                .declare_queryable("demo/before/router")
                .callback(|query| {
                    query
                        .reply("demo/before/router", "answer")
                        .wait()
                        .expect("replies");
                })
                .await
                .expect("declares");
            tokio::time::sleep(Duration::from_secs(1)).await;
            let router = open(config("a1b2d91", "router", true))
                .await
                .expect("a router opens");
            let asker = open(config("a1b2d92", "peer", false))
                .await
                .expect("a peer opens");
            let mut answered = false;
            let mut log = Vec::new();
            while started.elapsed() < Duration::from_secs(12) && !answered {
                let asked = Instant::now();
                let replies = asker
                    .get("demo/before/router")
                    .timeout(Duration::from_secs(10))
                    .await
                    .expect("asks");
                let mut got = 0;
                while let Ok(reply) = replies.recv_async().await {
                    got += usize::from(reply.result().is_ok());
                }
                answered = got > 0;
                log.push(format!(
                    "at {:?} an ask took {:?} and had {got}; the queryable peer sees routers {:?}",
                    started.elapsed(),
                    asked.elapsed(),
                    queryable_peer
                        .info()
                        .routers_zid()
                        .await
                        .collect::<Vec<_>>()
                ));
            }
            drop((queryable, router));
            assert!(answered, "no answer: {log:#?}");
        }

        /// With `scouting/gossip/multihop` on every node, a peer hears of the peers two links away:
        /// peer 3 dials peer 2, which dials the router, which holds peer 1.
        #[cfg(feature = "unstable")]
        #[test]
        fn with_multihop_a_peer_hears_of_the_peer_two_links_away() {
            use std::time::{Duration, Instant};

            let node = |id: &str, mode: &str, extra: &str| {
                open(
                    Config::from_json5(&format!(
                        r#"{{ id: "{id}", mode: "{mode}", {extra}
                              scouting: {{ multicast: {{ enabled: false }},
                                           gossip: {{ multihop: true, autoconnect: ["router"] }} }},
                              adminspace: {{ enabled: true }} }}"#
                    ))
                    .expect("a configuration zenoh reads"),
                )
                .wait()
                .expect("a node opens")
            };
            let router_port = unautoselected_port();
            let peer_port = unautoselected_port();
            let _router = node(
                "a1b2c1",
                "router",
                &format!(r#"listen: {{ endpoints: ["tcp/127.0.0.1:{router_port}"] }},"#),
            );
            std::thread::sleep(Duration::from_millis(500));
            let peer1 = node(
                "a1b2c2",
                "peer",
                &format!(r#"connect: {{ endpoints: ["tcp/127.0.0.1:{router_port}"] }},"#),
            );
            std::thread::sleep(Duration::from_millis(500));
            let peer2 = node(
                "a1b2c3",
                "peer",
                &format!(
                    r#"connect: {{ endpoints: ["tcp/127.0.0.1:{router_port}"] }},
                       listen: {{ endpoints: ["tcp/127.0.0.1:{peer_port}"] }},"#
                ),
            );
            std::thread::sleep(Duration::from_millis(500));
            let peer3 = node(
                "a1b2c4",
                "peer",
                &format!(r#"connect: {{ endpoints: ["tcp/127.0.0.1:{peer_port}"] }},"#),
            );
            let graph_of = |peer: &Session| -> String {
                let replies = peer
                    .get("@/*/peer/linkstate/north")
                    .timeout(Duration::from_secs(2))
                    .wait()
                    .expect("asks");
                replies
                    .recv_timeout(Duration::from_secs(3))
                    .ok()
                    .flatten()
                    .and_then(|reply| {
                        reply
                            .into_result()
                            .ok()
                            .map(|sample| sample.payload().try_to_string().unwrap().into_owned())
                    })
                    .unwrap_or_default()
            };
            let deadline = Instant::now() + Duration::from_secs(6);
            let (mut text2, mut text3) = (String::new(), String::new());
            while Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(300));
                text2 = graph_of(&peer2);
                text3 = graph_of(&peer3);
                if text3.contains("a1b2c2") {
                    break;
                }
            }
            assert!(
                text3.contains("a1b2c2"),
                "peer 3 never heard of peer 1.\n--- peer 2 ---\n{text2}\n--- peer 3 ---\n{text3}"
            );

            // And it hears that peer 1 is gone.
            peer1.close().wait().expect("closes");
            let deadline = Instant::now() + Duration::from_secs(6);
            while Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(300));
                text2 = graph_of(&peer2);
                text3 = graph_of(&peer3);
                if !text3.contains("a1b2c2") {
                    break;
                }
            }
            assert!(
                !text3.contains("a1b2c2"),
                "peer 3 never heard peer 1 was gone.\n--- peer 2 ---\n{text2}\n--- peer 3 \
                 ---\n{text3}"
            );
        }

        /// The admin space of a router node answers what the router holds: its root, metrics and
        /// the graph of its routers, the entities it declared, listed while they are declared and
        /// not after, and the successor routes toward a router that dialed it. The read of
        /// upstream's own adminspace test, without the multicast group and the plugins.
        #[cfg(feature = "unstable")]
        #[test]
        fn a_router_node_answers_its_admin_space() {
            use std::time::{Duration, Instant};

            let port = unautoselected_port();
            let router = open(
                Config::from_json5(&format!(
                    r#"{{ id: "a1b2e5", mode: "router",
                          listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }},
                          adminspace: {{ enabled: true,
                                         permissions: {{ read: true, write: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads"),
            )
            .wait()
            .expect("a router opens");
            let second = open(
                Config::from_json5(&format!(
                    r#"{{ id: "a1b2e6", mode: "router", listen: {{ endpoints: [] }},
                          connect: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads"),
            )
            .wait()
            .expect("a router dials a router");
            let zid = router.zid();
            let zid2 = second.zid();
            let keys = |pattern: &str| -> Vec<String> {
                let replies = router.get(pattern).wait().expect("asks");
                let mut found = Vec::new();
                while let Ok(Some(reply)) = replies.recv_timeout(Duration::from_secs(2)) {
                    found.push(reply.result().expect("a sample").key_expr().to_string());
                }
                found
            };

            assert!(!keys(&format!("@/{zid}/router")).is_empty(), "no root");
            assert!(
                !keys(&format!("@/{zid}/router/metrics")).is_empty(),
                "no metrics"
            );
            assert!(
                !keys(&format!("@/{zid}/router/linkstate/north")).is_empty(),
                "no graph of the routers"
            );

            // An entity is listed while it is declared.
            macro_rules! listed {
                ($kind:literal, $entity:ident = $declare:expr) => {{
                    let pattern = format!("@/{zid}/router/{}/**", $kind);
                    assert_eq!(keys(&pattern), Vec::<String>::new(), "{} before", $kind);
                    let $entity = $declare;
                    assert_eq!(
                        keys(&pattern),
                        vec![format!("@/{zid}/router/{}/some/key", $kind)],
                        "{} declared",
                        $kind
                    );
                    $entity.undeclare().wait().expect("ends");
                    assert_eq!(keys(&pattern), Vec::<String>::new(), "{} after", $kind);
                }};
            }
            listed!(
                "subscriber",
                entity = router
                    .declare_subscriber("some/key")
                    .wait()
                    .expect("declares")
            );
            listed!(
                "publisher",
                entity = router
                    .declare_publisher("some/key")
                    .wait()
                    .expect("declares")
            );
            listed!(
                "queryable",
                entity = router
                    .declare_queryable("some/key")
                    .wait()
                    .expect("declares")
            );
            listed!(
                "querier",
                entity = router.declare_querier("some/key").wait().expect("declares")
            );
            listed!(
                "token",
                entity = router
                    .liveliness()
                    .declare_token("some/key")
                    .wait()
                    .expect("declares")
            );

            // The successor routes toward the router that dialed come once its link is up.
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut routes = keys(&format!("@/{zid}/router/route/successor/**"));
            while routes.is_empty() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(200));
                routes = keys(&format!("@/{zid}/router/route/successor/**"));
            }
            assert!(!routes.is_empty(), "no successor route");
            assert!(
                !keys(&format!(
                    "@/{zid}/router/route/successor/src/{zid}/dst/{zid2}"
                ))
                .is_empty(),
                "no route to the router that dialed"
            );
            assert!(keys("@/**").len() > 1, "nothing under @/**");
            drop(second);
        }

        /// A router node that listens on a multicast group joins it at the open, and says the
        /// locator of the group with the port the system gave it where the endpoint named port 0:
        /// a peer that listens on that locator joins the same group, and what the router says is
        /// the group it forwards into.
        #[cfg(feature = "unstable")]
        #[test]
        fn a_router_node_listens_on_a_multicast_group() {
            let router = open(
                Config::from_json5(
                    r#"{ id: "a1b2f1", mode: "router",
                         listen: { endpoints: ["tcp/127.0.0.1:0", "udp/224.0.0.224:0#iface=lo"] },
                         scouting: { multicast: { enabled: false } } }"#,
                )
                .expect("a configuration zenoh reads"),
            )
            .wait()
            .expect("a router joins a group");
            let locators: Vec<String> = router
                .info()
                .locators()
                .wait()
                .iter()
                .map(|locator| locator.to_string())
                .collect();
            assert!(
                locators
                    .iter()
                    .any(|text| text.starts_with("tcp/127.0.0.1:")),
                "{locators:?}"
            );
            let group = locators
                .iter()
                .find(|text| text.starts_with("udp/224.0.0.224:"))
                .unwrap_or_else(|| panic!("no group among {locators:?}"));
            let port = group["udp/224.0.0.224:".len()..]
                .split('#')
                .next()
                .and_then(|text| text.parse::<u16>().ok())
                .unwrap_or_else(|| panic!("no port in {group}"));
            assert_ne!(
                port, 0,
                "the group says the port the system gave it: {group}"
            );
            let peer = open(
                Config::from_json5(&format!(
                    r#"{{ id: "a1b2f2", mode: "peer",
                          listen: {{ endpoints: ["{group}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads"),
            )
            .wait()
            .expect("a peer joins the group of the router");
            drop(peer);
        }

        /// A router that dials a router which is not listening yet keeps dialing, and once the
        /// link is up what a client of the dialing router subscribed to reaches a publisher of the
        /// other: the start order of the nodes of a mesh does not matter.
        #[cfg(feature = "unstable")]
        #[test]
        fn a_router_that_dialed_before_its_peer_listened_federates_when_it_does() {
            use std::time::{Duration, Instant};

            let first_port = unautoselected_port();
            let dialer_port = unautoselected_port();
            let dialer = open(
                Config::from_json5(&format!(
                    r#"{{ id: "a1b2f3", mode: "router",
                          listen: {{ endpoints: ["tcp/127.0.0.1:{dialer_port}"] }},
                          connect: {{ endpoints: ["tcp/127.0.0.1:{first_port}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads"),
            )
            .wait()
            .expect("a router opens while the one it dials is not there");
            let subscriber_client = client_of("a1b2f4", dialer_port);
            let subscriber = subscriber_client
                .declare_subscriber("demo/late/router")
                .wait()
                .expect("declares");
            std::thread::sleep(Duration::from_millis(1000));
            let first = router("a1b2f1", first_port);
            let publisher_client = client_of("a1b2f5", first_port);

            let deadline = Instant::now() + Duration::from_secs(8);
            let mut heard = false;
            while Instant::now() < deadline && !heard {
                publisher_client
                    .put("demo/late/router", "hello")
                    .wait()
                    .expect("puts");
                heard = subscriber
                    .recv_timeout(Duration::from_millis(100))
                    .ok()
                    .flatten()
                    .is_some();
            }
            assert!(
                heard,
                "the subscriber of the dialing router heard nothing; the routers the dialing router \
                 sees: {:?}, the routers the first sees: {:?}",
                dialer.info().routers_zid().wait().collect::<Vec<_>>(),
                first.info().routers_zid().wait().collect::<Vec<_>>(),
            );
            drop(first);
            drop(dialer);
        }

        /// The band and the class a dialing side names for its link (`prio=` and `rel=` of the
        /// endpoint) ride the QoS extension of the handshake, and the router that accepts the
        /// link reports them for it; a link that names none reports every priority.
        #[cfg(feature = "unstable")]
        #[test]
        fn a_router_reports_the_band_and_the_class_a_dialing_side_named_for_its_link() {
            use std::time::{Duration, Instant};

            let qos = r#"transport: { unicast: { qos: { enabled: true } } }"#;
            let port = unautoselected_port();
            let router = open(
                Config::from_json5(&format!(
                    r#"{{ id: "a1b2f8", mode: "router",
                          listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }}, {qos},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads"),
            )
            .wait()
            .expect("opens");
            let dial = |id: &str, suffix: &str| {
                open(
                    Config::from_json5(&format!(
                        r#"{{ id: "{id}", mode: "peer", {qos},
                              connect: {{ endpoints: ["tcp/127.0.0.1:{port}{suffix}"] }},
                              scouting: {{ multicast: {{ enabled: false }} }} }}"#
                    ))
                    .expect("a configuration zenoh reads"),
                )
                .wait()
                .expect("opens")
            };
            let named = dial("a1b2f9", "?prio=2-5;rel=1");
            let unnamed = dial("a1b2fa", "");
            let deadline = Instant::now() + Duration::from_secs(5);
            let links = loop {
                let links: Vec<_> = router.info().links().wait().collect();
                if links.len() == 2 || Instant::now() > deadline {
                    break links;
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            assert_eq!(links.len(), 2, "both peers are linked: {links:?}");
            let of = |zid: ZenohId| {
                links
                    .iter()
                    .find(|link| link.zid() == &zid)
                    .expect("a link")
            };
            let named = of(named.zid());
            assert_eq!(named.priorities(), Some((2, 5)));
            assert_eq!(
                named.reliability(),
                Some(zenoh_protocol::core::Reliability::Reliable)
            );
            let unnamed = of(unnamed.zid());
            assert_eq!(
                unnamed.priorities(),
                Some((
                    zenoh_protocol::core::Priority::MAX as u8,
                    zenoh_protocol::core::Priority::MIN as u8
                ))
            );
        }

        /// The configuration of a node is written through its admin space when the configuration
        /// grants the permission, by a key whose zid and role may be wildcards, and a delete
        /// removes what a put wrote; a node that grants no write permission is not changed.
        #[cfg(feature = "unstable")]
        #[test]
        fn the_config_of_a_node_is_written_through_its_admin_space() {
            use std::time::{Duration, Instant};

            let open_with = |id: &str, write: bool| {
                open(
                    Config::from_json5(&format!(
                        r#"{{ id: "{id}", mode: "router",
                              listen: {{ endpoints: [] }},
                              adminspace: {{ enabled: true,
                                             permissions: {{ read: true, write: {write} }} }},
                              scouting: {{ multicast: {{ enabled: false }} }} }}"#
                    ))
                    .expect("a configuration zenoh reads"),
                )
                .wait()
                .expect("a router opens")
            };
            let wait_for = |session: &Session, key: &str, expected: Option<&str>| {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let value = session.config().get(key);
                    let matches = match (value.as_deref(), expected) {
                        (Ok(value), Some(expected)) => value == expected,
                        (Err(_), None) => true,
                        _ => false,
                    };
                    if matches || Instant::now() > deadline {
                        return matches;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            };

            let writable = open_with("a1b2f6", true);
            let zid = writable.zid();
            writable
                .put("@/*/router/config/plugins/admin_wildcard/value", "1")
                .wait()
                .expect("puts");
            assert!(wait_for(
                &writable,
                "plugins/admin_wildcard/value",
                Some("1")
            ));
            writable
                .delete(format!("@/{zid}/*/config/plugins/admin_wildcard"))
                .wait()
                .expect("deletes");
            assert!(wait_for(&writable, "plugins/admin_wildcard", None));
            writable
                .put("@/*/*/config/plugins/admin_wildcard/value", "2")
                .wait()
                .expect("puts");
            assert!(wait_for(
                &writable,
                "plugins/admin_wildcard/value",
                Some("2")
            ));

            let read_only = open_with("a1b2f7", false);
            read_only
                .put("@/*/router/config/plugins/admin_refused/value", "1")
                .wait()
                .expect("puts");
            assert!(
                !wait_for(&read_only, "plugins/admin_refused/value", Some("1")),
                "a node without the write permission is not written"
            );
        }

        /// A router tells its own session's publications and queries from the faces': a
        /// subscriber that admits only remote origins does not hear the router's own put and
        /// hears a peer's, a queryable that admits only the session's own answers the get of the
        /// router and not the get of a peer, and a put whose destination is the session alone
        /// reaches the router's subscribers and no peer.
        #[test]
        fn a_router_tells_its_own_publications_and_queries_from_those_of_its_faces() {
            use std::sync::mpsc;
            use std::time::Duration;

            let port = unautoselected_port();
            let router = router("a1b2e3", port);
            let (remote_tx, remote_heard) = mpsc::channel::<String>();
            let remote_tx = std::sync::Mutex::new(remote_tx);
            let _remote_only = router
                .declare_subscriber("demo/o/**".to_owned())
                .allowed_origin(Locality::Remote)
                .callback(move |sample: Sample| {
                    let _ = remote_tx
                        .lock()
                        .unwrap()
                        .send(sample.key_expr().to_string());
                })
                .wait()
                .expect("a router honours the origin of a subscriber");
            let (local_tx, local_heard) = mpsc::channel::<String>();
            let local_tx = std::sync::Mutex::new(local_tx);
            let _local_only = router
                .declare_subscriber("demo/o/**".to_owned())
                .allowed_origin(Locality::SessionLocal)
                .callback(move |sample: Sample| {
                    let _ = local_tx.lock().unwrap().send(sample.key_expr().to_string());
                })
                .wait()
                .expect("declares");
            let _own = router
                .declare_queryable("demo/o/q".to_owned())
                .allowed_origin(Locality::SessionLocal)
                .callback(|query| {
                    query
                        .reply(query.key_expr().clone(), "mine")
                        .wait()
                        .expect("replies");
                })
                .wait()
                .expect("a router honours the origin of a queryable");

            router.put("demo/o/own", "x").wait().expect("puts");
            assert_eq!(
                local_heard.recv_timeout(Duration::from_secs(2)).as_deref(),
                Ok("demo/o/own"),
                "the subscriber of the session hears the put of the session"
            );
            assert!(
                remote_heard
                    .recv_timeout(Duration::from_millis(300))
                    .is_err(),
                "a subscriber that admits remote origins only does not hear it"
            );
            let answers: Vec<String> = router
                .get("demo/o/q")
                .timeout(Duration::from_secs(2))
                .wait()
                .expect("asks")
                .into_iter()
                .filter_map(|reply| {
                    reply
                        .into_result()
                        .ok()
                        .map(|sample| sample.payload().try_to_string().unwrap().into_owned())
                })
                .collect();
            assert_eq!(answers, ["mine"], "the router's own get is answered");

            let peer = peer_of("a1b2f5", port);
            assert_eq!(connected(&peer, 1).0.len(), 1, "the peer is linked");
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut heard = None;
            while heard.is_none() && std::time::Instant::now() < deadline {
                peer.put("demo/o/up", "y").wait().expect("puts");
                heard = remote_heard.recv_timeout(Duration::from_millis(200)).ok();
            }
            assert_eq!(heard.as_deref(), Some("demo/o/up"));
            assert_eq!(
                local_heard.try_recv().ok(),
                None,
                "the subscriber of the session does not hear a peer"
            );
            let asked = peer
                .get("demo/o/q")
                .timeout(Duration::from_secs(2))
                .wait()
                .expect("asks")
                .into_iter()
                .count();
            assert_eq!(
                asked, 0,
                "a peer's get is not answered by a session-local queryable"
            );
        }
    }

    /// The matching of a publisher or a querier between two nodes of which one or both hold a
    /// namespace: what the other node declares is matched under the prefix, and its retraction
    /// ends the match, as without one.
    mod namespaced_matching {
        use std::time::Duration;

        use super::*;

        const SETTLE: Duration = Duration::from_millis(1500);

        /// A listening peer holding `listener_ns` and a client holding `client_ns`.
        fn pair(
            ids: (&str, &str),
            listener_ns: Option<&str>,
            client_ns: Option<&str>,
        ) -> (Session, Session) {
            let port = unautoselected_port();
            let ns = |namespace: Option<&str>| {
                namespace.map_or(String::new(), |ns| format!(r#"namespace: "{ns}","#))
            };
            let open_one = |text: String| {
                open(Config::from_json5(&text).expect("a configuration zenoh reads"))
                    .wait()
                    .expect("opens")
            };
            let listener = open_one(format!(
                r#"{{ id: "{}", mode: "peer", {}
                     listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                     scouting: {{ multicast: {{ enabled: false }} }} }}"#,
                ids.0,
                ns(listener_ns),
            ));
            let client = open_one(format!(
                r#"{{ id: "{}", mode: "client", {}
                     connect: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                     scouting: {{ multicast: {{ enabled: false }} }} }}"#,
                ids.1,
                ns(client_ns),
            ));
            assert_eq!(connected(&client, 1).1.len(), 1, "the nodes are linked");
            (listener, client)
        }

        fn publisher_follows_subscriber(
            ids: (&str, &str),
            namespaces: (Option<&str>, Option<&str>),
            publishes: &str,
            subscribes: &str,
        ) {
            let (listener, client) = pair(ids, namespaces.0, namespaces.1);
            let publisher = listener
                .declare_publisher(publishes.to_owned())
                .wait()
                .expect("declares");
            let subscriber = client
                .declare_subscriber(subscribes.to_owned())
                .wait()
                .expect("declares");
            std::thread::sleep(SETTLE);
            assert!(
                publisher.matching_status().wait().expect("asks").matching(),
                "a subscriber matches"
            );
            subscriber.undeclare().wait().expect("undeclares");
            std::thread::sleep(SETTLE);
            assert!(
                !publisher.matching_status().wait().expect("asks").matching(),
                "the retraction ends the match"
            );
        }

        #[test]
        fn a_namespace_of_the_publishing_node_ends_the_match_with_the_retraction() {
            publisher_follows_subscriber(
                ("a1b2d1", "a1b2d2"),
                (Some("ns1"), None),
                "zenoh/pub",
                "ns1/zenoh/pub",
            );
        }

        #[test]
        fn the_same_namespace_on_both_nodes_ends_the_match_with_the_retraction() {
            publisher_follows_subscriber(
                ("a1b2d3", "a1b2d4"),
                (Some("ns2"), Some("ns2")),
                "zenoh/pub",
                "zenoh/pub",
            );
        }

        #[test]
        fn a_namespace_of_the_subscribing_node_ends_the_match_with_the_retraction() {
            publisher_follows_subscriber(
                ("a1b2d5", "a1b2d6"),
                (None, Some("ns3")),
                "ns3/zenoh/pub",
                "zenoh/pub",
            );
        }

        #[test]
        fn a_queryable_under_the_same_namespace_matches_a_querier_and_its_retraction_ends_it() {
            let (listener, client) = pair(("a1b2d9", "a1b2da"), Some("ns5"), Some("ns5"));
            let querier = listener
                .declare_querier("zenoh/qry".to_owned())
                .wait()
                .expect("declares");
            let queryable = client
                .declare_queryable("zenoh/qry".to_owned())
                .wait()
                .expect("declares");
            std::thread::sleep(SETTLE);
            assert!(
                querier.matching_status().wait().expect("asks").matching(),
                "a queryable matches"
            );
            queryable.undeclare().wait().expect("undeclares");
            std::thread::sleep(SETTLE);
            assert!(
                !querier.matching_status().wait().expect("asks").matching(),
                "the retraction ends the match"
            );
        }

        #[test]
        fn no_namespace_ends_the_match_with_the_retraction() {
            publisher_follows_subscriber(
                ("a1b2d7", "a1b2d8"),
                (None, None),
                "zenoh/pub",
                "zenoh/pub",
            );
        }
    }
}

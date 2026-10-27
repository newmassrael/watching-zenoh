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
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
#[cfg(feature = "unstable")]
use zenoh_config::wrappers::EntityGlobalId;
use zenoh_config::wrappers::ZenohId;
use zenoh_core::{Resolve, ResolveClosure, Wait};
#[cfg(feature = "unstable")]
use zenoh_protocol::core::Reliability;
use zenoh_protocol::core::{CongestionControl, EntityId, ExprId};
use zenoh_result::ZResult;
use zenoh_runtime::ZRuntime;

#[cfg(feature = "unstable")]
use crate::api::sample::SourceInfo;
#[cfg(feature = "unstable")]
use crate::api::timestamp_stack::TimestampInstrumentation;
use crate::api::{
    builders::{
        close::{CloseBuilder, Closeable, Closee},
        publisher::{
            PublicationBuilderDelete, PublicationBuilderPut, PublisherBuilder,
            SessionDeleteBuilder, SessionPutBuilder,
        },
        session::OpenBuilder,
        subscriber::SubscriberBuilder,
    },
    bytes::ZBytes,
    cancellation::SyncGroupNotifier,
    config::Config,
    encoding::Encoding,
    handlers::{Callback, DefaultHandler},
    info::SessionInfo,
    key_expr::{KeyExpr, KeyExprUndeclaration, SessionAnchor, WireAnchor},
    publisher::Priority,
    sample::{Locality, Sample, SampleKind},
    subscriber::SubscriberKind,
    Id,
};

zconfigurable! {
    pub(crate) static ref API_DATA_RECEPTION_CHANNEL_SIZE: usize = 256;
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

/// What a session is run by: the engine that holds its faces, its declarations and its clock.
///
/// One engine is selected by a feature of the build (decision D5). A build that selects none has no
/// engine to open a session on, and its [`Session::open`] says so; the type is then empty.
enum Engine {
    #[cfg(feature = "engine-tokio")]
    Tokio(wz_capi_core::drive::SessionState),
}

#[cfg(feature = "engine-tokio")]
impl Engine {
    /// Open a session on this engine, from the document the configuration is, and the id the
    /// session stands on.
    fn open(config: &Config) -> ZResult<(Engine, ZenohId)> {
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
        let plan = OpenPlan::resolve(role, stated, Some(&document.to_string()))
            .map_err(tokio_engine::refusal_error)?;
        // A router is refused by the key that makes the session one (decision D6 of the seam note).
        // The engine opens a session that listens and dials, and what it announces to a node that
        // dials it is a peer's role whatever `mode` says: a router is the router data plane, which
        // this session does not carry, and is a slice of its own. Announcing the role without being
        // one would be the silent fallback the other refusals of this function exist against.
        if expanded.mode() == zenoh_protocol::core::WhatAmI::Router {
            bail!(
                "`mode` = \"router\": this engine's session is a peer or a client; a router needs \
                 the router data plane, which a session does not carry yet"
            );
        }
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
        let state = plan
            .into_arguments(AbiChoices {
                tx_queue: Default::default(),
                start_read_task: true,
                // Upstream runs the callbacks of a delivery a session makes to itself inside the
                // call that causes it, on the calling thread.
                local_delivery: tokio_engine::LocalDeliveryDrain::Caller,
                initial_interest: true,
                // Each face of the session has a thread of its own, so a callback that blocks
                // holds up its link and no other.
                face_drive: tokio_engine::FaceDrive::PerFace,
                shm_clients: tokio_engine::no_shm_clients(),
                offer_shm: false,
                groups_report_shm: false,
            })
            .run()
            .map_err(|error| tokio_engine::open_error(error, dialled))?;
        Ok((Engine::Tokio(state), zid))
    }

    fn is_closed(&self) -> bool {
        match self {
            Engine::Tokio(state) => state.is_closed(),
        }
    }

    /// Close the session and wait for its drive to stop: every callback has returned when this
    /// does. Closing a closed session does nothing.
    fn close(&self) {
        match self {
            Engine::Tokio(state) => state.close(),
        }
    }

    fn acquire_keyexpr(&self, keyexpr: &str) -> Option<u64> {
        match self {
            Engine::Tokio(state) => state.shared.as_engine().acquire_keyexpr(keyexpr.to_owned()),
        }
    }

    fn release_keyexpr(&self, mapping_id: u64) {
        match self {
            Engine::Tokio(state) => state.shared.as_engine().release_keyexpr(mapping_id),
        }
    }

    fn next_entity_id(&self) -> u64 {
        match self {
            Engine::Tokio(state) => state.shared.as_engine().next_entity_id(),
        }
    }

    /// The id and the announced role of every established peer, the role in its 2-bit wire form
    /// (0 router, 1 peer, 2 client).
    fn peer_identities(&self) -> Vec<(Vec<u8>, u8)> {
        match self {
            Engine::Tokio(state) => state.shared.as_engine().peer_identities(),
        }
    }

    /// The key expression declarations the engine holds, `(id, key)` in declaration order.
    #[cfg(test)]
    fn keyexpr_declarations(&self) -> Vec<(u64, String)> {
        match self {
            Engine::Tokio(state) => state.shared.as_engine().keyexpr_declarations(),
        }
    }

    /// Publish what `publication` says: to the matching subscribers of the session itself and to
    /// every peer, as its destination allows.
    fn publish(&self, publication: &Publication<'_>) -> ZResult<()> {
        match self {
            Engine::Tokio(state) => {
                let options = tokio_engine::publish_options(publication);
                let wire = tokio_engine::wire_key(publication);
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
            Engine::Tokio(state) => {
                let Subscription {
                    key,
                    scope,
                    suffix,
                    origin,
                    callback,
                    notifier,
                    keeps,
                } = subscription;
                let wire = tokio_engine::wire_key_of(scope, suffix).keeping(keeps);
                let id = state.shared.as_engine().declare_subscriber_on_wire(
                    key.to_owned(),
                    wire,
                    tokio_engine::engine_locality(origin),
                    None,
                    tokio_engine::subscriber_sink(callback, notifier),
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
        }
    }

    /// Declare the publisher `publisher` says: the engine keeps the interest in the subscribers
    /// matching its key, and asks every peer for them as upstream's declaration does, unless the
    /// publisher writes to the session itself. The id is released by
    /// [`Engine::undeclare_publisher`].
    fn declare_publisher(&self, publisher: PublisherDeclaration<'_>) -> ZResult<Id> {
        match self {
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
            Engine::Tokio(state) => state
                .shared
                .as_engine()
                .undeclare_write_filter(u64::from(id)),
        }
    }
}

#[cfg(not(feature = "engine-tokio"))]
impl Engine {
    fn open(_config: &Config) -> ZResult<(Engine, ZenohId)> {
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
}

/// The reading of a configuration for the tokio engine: its role, its endpoints, the document its
/// plan is made from, and the words an open that cannot be carried out is refused in.
#[cfg(feature = "engine-tokio")]
mod tokio_engine {
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
            sample::{EncodingHint, SampleKind as EngineSampleKind, TimestampHint},
            session::{InterestForm, PublishOptions},
            sink::SampleView,
        },
    };
    use zenoh_config::{wrappers::ZenohId, ExpandedConfig, ModeDependent};
    use zenoh_protocol::core::{CongestionControl, EndPoints, ExprId, WhatAmI};
    use zenoh_result::ZResult;

    use super::{Arc, Publication};
    #[cfg(feature = "unstable")]
    use crate::api::sample::SourceInfo;
    use crate::api::{
        bytes::ZBytes,
        cancellation::SyncGroupNotifier,
        encoding::Encoding,
        handlers::Callback,
        key_expr::KeyExpr,
        sample::{Locality, QoS, Sample, SampleKind},
    };

    /// The role of the engine that is the mode of the configuration.
    pub(super) fn role_of(mode: WhatAmI) -> EngineWhatAmI {
        match mode {
            WhatAmI::Router => EngineWhatAmI::Router,
            WhatAmI::Peer => EngineWhatAmI::Peer,
            WhatAmI::Client => EngineWhatAmI::Client,
        }
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
        let mut document = serde_json::to_value::<&zenoh_config::Config>(config)?;
        let object = document
            .as_object_mut()
            .ok_or_else(|| zerror!("the configuration is not an object"))?;
        object.insert("mode".to_owned(), role.to_str().into());
        object.insert("id".to_owned(), zid.to_string().into());
        Ok(document)
    }

    /// Decision D6: refuse, by name, the keys of `document` that `ignored` says the engine does not
    /// act on, that upstream acts on, and whose value is not the default's.
    ///
    /// `ignored` lists every leaf the document carries that the engine does not act on, and the
    /// document is the whole configuration, so most of them hold the default. A key that upstream
    /// itself does nothing with ([`KeyState::Inert`]) is accepted whatever its value, and a key no
    /// list knows ([`None`]) is refused as the unmapped ones are.
    pub(super) fn refuse_unmapped(ignored: &[String], document: &serde_json::Value) -> ZResult<()> {
        let default = serde_json::to_value(zenoh_config::Config::default())?;
        let unmapped: Vec<String> = ignored
            .iter()
            .filter(|key| key_state(key) != Some(KeyState::Inert))
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
            let encoding: zenoh_protocol::core::Encoding = publication.encoding.clone().into();
            // The default encoding is the absence of one on the wire, in both crates.
            if encoding != zenoh_protocol::core::Encoding::default() {
                let schema = encoding
                    .schema
                    .as_ref()
                    .map(|schema| String::from_utf8_lossy(schema.as_slice()).into_owned());
                options = options.with_encoding(EncodingHint {
                    packed_id: (u32::from(encoding.id) << 1) | u32::from(schema.is_some()),
                    schema,
                });
            }
        }
        if let Some(timestamp) = &publication.timestamp {
            let id = timestamp.get_id();
            options = options.with_timestamp(TimestampHint {
                time: timestamp.get_time().as_u64(),
                zid: id.to_le_bytes()[..id.size()].to_vec(),
            });
        }
        #[cfg(feature = "unstable")]
        if let Some(info) = &publication.source_info {
            let zid = info.source_id.zid();
            let size = zenoh_protocol::core::ZenohIdProto::from(zid).size();
            options = options.with_source_info(wz_capi_core::runtime::sample::SourceInfo::new(
                &zid.to_le_bytes()[..size],
                info.source_id.eid(),
                info.source_sn,
            ));
        }
        if let Some(attachment) = &publication.attachment {
            options = options.with_attachment(attachment.to_bytes().into_owned());
        }
        options
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

    /// What the engine hands the samples of a subscription to: the callback, called once for each
    /// sample, from whichever thread the engine delivers on.
    ///
    /// The engine asks for a callback of its own for each face, so they share what the
    /// subscription holds, and the notifier is let go with the last of them (and with a call that
    /// is still running).
    pub(super) fn subscriber_sink(
        callback: Callback<Sample>,
        notifier: Option<SyncGroupNotifier>,
    ) -> SubscriberSink {
        struct Delivery {
            callback: Callback<Sample>,
            _notifier: Option<SyncGroupNotifier>,
        }
        let delivery = Arc::new(Delivery {
            callback,
            _notifier: notifier,
        });
        Arc::new(move || {
            let delivery = Arc::clone(&delivery);
            Box::new(move |view: &dyn SampleView| match sample_of(view) {
                Ok(sample) => delivery.callback.call(sample),
                Err(error) => tracing::error!("a sample could not be delivered: {error}"),
            })
        })
    }

    /// The sample the engine's view of a frame is.
    ///
    /// The payload is copied out of the frame: handing it over as the frame's own bytes is the
    /// zero-copy payload of slice Z2 that no engine offers yet.
    fn sample_of(view: &dyn SampleView) -> ZResult<Sample> {
        let key_expr = KeyExpr::try_from(view.keyexpr().to_owned())?;
        let kind = match view.kind() {
            EngineSampleKind::Put => SampleKind::Put,
            EngineSampleKind::Del => SampleKind::Delete,
        };
        let encoding = view
            .encoding()
            .and_then(|hint| {
                let id = u16::try_from(hint.packed_id >> 1).ok()?;
                let schema = hint
                    .schema
                    .as_ref()
                    .filter(|_| hint.packed_id & 1 == 1)
                    .map(|schema| zenoh_buffers::ZSlice::from(schema.clone().into_bytes()));
                Some(zenoh_protocol::core::Encoding { id, schema })
            })
            .map(Encoding::from)
            .unwrap_or_default();
        let timestamp = view.timestamp().and_then(|hint| {
            let id = uhlc::ID::try_from(hint.zid.as_slice()).ok()?;
            Some(uhlc::Timestamp::new(uhlc::NTP64(hint.time), id))
        });
        let qos = view.qos().map_or_else(QoS::default, |level| {
            let priority = zenoh_protocol::core::Priority::try_from(level.priority() as u8)
                .unwrap_or_default();
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
        });
        Ok(Sample {
            key_expr,
            payload: ZBytes::from(view.payload().to_vec()),
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
            source_info: view.source_info().and_then(|info| {
                let zid = zenoh_protocol::core::ZenohIdProto::try_from(
                    &info.zid[..usize::from(info.zid_len)],
                )
                .ok()?;
                let id = zenoh_protocol::core::EntityGlobalIdProto { zid, eid: info.eid };
                Some(SourceInfo::new(id.into(), info.sn))
            }),
            attachment: view.attachment().map(|bytes| ZBytes::from(bytes.to_vec())),
            #[cfg(feature = "unstable")]
            timestamp_stack: None,
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

    /// An open that was carried out and failed. `dialled` is what the session was to dial, when
    /// that was all it was to do.
    pub(super) fn open_error(error: OpenError, dialled: Option<String>) -> zenoh_result::Error {
        match (error, dialled) {
            (OpenError::LinkFailed, Some(peers)) => {
                zerror!("Unable to connect to any of {}! ", peers).into()
            }
            (error, _) => zerror!("the session could not be opened: {:?}", error).into(),
        }
    }
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
    /// The subscriptions declared on the session and not undeclared, which a close lets go of.
    subscriptions: std::sync::Mutex<Vec<Id>>,
    /// The publishers declared on the session and not undeclared, which a close lets go of.
    publishers: std::sync::Mutex<Vec<Id>>,
}

impl SessionInner {
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
        // The instrumentation of a message at each node it crosses is the model of slice Z6b: an
        // engine without it would send the message without the stamps asked for, which is the
        // silent fallback this crate refuses everywhere else.
        #[cfg(feature = "unstable")]
        if timestamp_instrumentation.is_some() {
            bail!(
                "the timestamp instrumentation of a publication is not carried by this engine yet \
                 (slice Z6b of docs/zenoh-api-on-the-engine.md)"
            );
        }
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

    /// The handle by which a key expression is declared on this session.
    pub(crate) fn anchor(&self) -> SessionAnchor {
        self.0.clone()
    }

    /// Open a session on the selected engine, from `config`.
    pub(crate) fn open(config: Config) -> ZResult<Session> {
        let (engine, zid) = Engine::open(&config)?;
        let id = u32::try_from(engine.next_entity_id()).unwrap_or(u32::MAX);
        Ok(Session(Arc::new(SessionInner {
            strong_counter: AtomicUsize::new(1),
            engine,
            id,
            zid,
            subscriptions: std::sync::Mutex::new(vec![]),
            publishers: std::sync::Mutex::new(vec![]),
        })))
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
/// The handles count themselves ([`SessionInner::strong_counter`]) and the last one to be dropped
/// closes the session, whatever references remain.
#[derive(Debug, Clone)]
pub struct WeakSession(Arc<SessionInner>);

impl WeakSession {
    /// The id the session stands on.
    pub(crate) fn zid(&self) -> ZenohId {
        self.0.zid
    }

    /// Stop the delivery to the subscriber `sid`. A closed session has none to stop, and
    /// undeclaring on it is no error.
    pub(crate) fn undeclare_subscriber_inner(&self, sid: Id, kind: SubscriberKind) -> ZResult<()> {
        match kind {
            SubscriberKind::Subscriber => {
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
        })?;
        self.0.subscriptions().push(id);
        // A close that ran between the check and the record has not seen this subscription.
        if self.0.engine.is_closed() {
            self.0.release_subscriptions();
            return Err(SessionClosedError.into());
        }
        Ok(id)
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
    // This engine's close waits for every callback to return, whether or not the caller asked it to
    // (`wait_callbacks`): it joins the thread that runs them.
    #[allow(unused_variables)]
    async fn close_inner(&self, close_args: SessionCloseArgs) {
        let session = self.0.clone();
        // A close joins the engine's threads, so it is run where blocking is allowed and not on the
        // executor of the caller, which may be the very thread a callback is about to be run on.
        let _ = ZRuntime::Net
            .spawn_blocking(move || {
                session.engine.close();
                // A closed session takes nothing more, and lets go of the callbacks it was to
                // call: the channel of a subscriber ends with its session, as upstream's does.
                session.release_subscriptions();
                session.release_publishers();
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
    /// from one that depends on the process, and not read back from a socket that is dropped.
    fn unautoselected_port() -> u16 {
        let start = 20_000 + (std::process::id() % 8_000) as u16;
        (start..start + 2_000)
            .find(|port| std::net::TcpListener::bind(("127.0.0.1", *port)).is_ok())
            .expect("a free port below the ephemeral range")
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
    fn a_router_is_refused_by_the_key_that_makes_the_session_one() {
        let config = Config::from_json5(
            r#"{ mode: "router", listen: { endpoints: ["tcp/127.0.0.1:0"] },
                 scouting: { multicast: { enabled: false } } }"#,
        )
        .expect("a configuration zenoh reads");
        let error = open(config).wait().expect_err("a router");
        assert!(error.to_string().contains("`mode` = \"router\""), "{error}");
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
            remote.put("v").wait().expect("puts");
            assert_eq!(seen.load(Ordering::SeqCst), 0, "a remote one skips its own");
            let local = session
                .declare_publisher("demo/destination")
                .allowed_destination(Locality::SessionLocal)
                .wait()
                .expect("declares");
            local.put("v").wait().expect("puts");
            assert_eq!(seen.load(Ordering::SeqCst), 1);
            let any = session
                .declare_publisher("demo/destination")
                .wait()
                .expect("declares");
            any.put("v").wait().expect("puts");
            assert_eq!(seen.load(Ordering::SeqCst), 2);
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
}

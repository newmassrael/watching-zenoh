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
use zenoh_protocol::core::{EntityId, ExprId};
use zenoh_result::ZResult;
use zenoh_runtime::ZRuntime;

use crate::api::{
    builders::{
        close::{CloseBuilder, Closeable, Closee},
        session::OpenBuilder,
    },
    config::Config,
    info::SessionInfo,
    key_expr::{KeyExpr, KeyExprUndeclaration, SessionAnchor, WireAnchor},
};

zconfigurable! {
    pub(crate) static ref API_DATA_RECEPTION_CHANNEL_SIZE: usize = 256;
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
}

/// The reading of a configuration for the tokio engine: its role, its endpoints, the document its
/// plan is made from, and the words an open that cannot be carried out is refused in.
#[cfg(feature = "engine-tokio")]
mod tokio_engine {
    pub(super) use wz_capi_core::runtime::session::LocalDeliveryDrain;
    pub(super) use wz_capi_core::{drive::FaceDrive, faces::no_shm_clients};
    use wz_capi_core::{
        drive::OpenError,
        open_plan::{key_state, KeyState, OpenRefusal},
        runtime::session_glue::WhatAmI as EngineWhatAmI,
    };
    use zenoh_config::{wrappers::ZenohId, ExpandedConfig, ModeDependent};
    use zenoh_protocol::core::{EndPoints, WhatAmI};
    use zenoh_result::ZResult;

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
pub(crate) struct WeakSession(Arc<SessionInner>);

impl WeakSession {
    /// The id the session stands on.
    pub(crate) fn zid(&self) -> ZenohId {
        self.0.zid
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
            .spawn_blocking(move || session.engine.close())
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
}

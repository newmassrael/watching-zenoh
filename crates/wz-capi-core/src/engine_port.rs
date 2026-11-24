// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! This engine as the port's [`SessionEngine`]: every operation is the face registry's own, so
//! an ABI that holds `Arc<dyn SessionEngine>` gets exactly what it got by naming
//! [`SharedSession`] (`docs/capi-pico-on-coop-engine.md`, step 2).

use std::any::Any;

use wz_capi_port::{
    BatchStep, CalledFromReadTask, FanoutError, FilterId, FilterPlane, FilteredPut, MatchId,
    MatchingSink, PeerIdentity, ReadTaskStartRefused, Refusal, SessionClosed, SessionDrive,
    SessionEngine, SubId, SubscriberSink, WireKey,
};
use wz_session_core::declare_form::{InterestAsk, RetractionKey};
use wz_session_core::link_restriction::LinkRestriction;
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::{PlainPutParams, PublishOptions};
use wz_session_core::session_zid::SessionZid;

use std::sync::Arc;

use crate::drive::SessionState;
use crate::faces::SharedSession;

/// This registry as the port's engine, made HERE and handed out.
///
/// Turning an `Arc<SharedSession>` into an `Arc<dyn SessionEngine>` instantiates the trait
/// object's vtable, and with it the registry's whole drop glue, in the crate where the turning
/// happens. Done in an ABI crate, that is a second copy of code this crate already holds:
/// measured on the pico client build, 27 KB of text, every byte of it a duplicate of a function
/// already linked (the registry's maps, dropped twice over). So an ABI asks for the engine and
/// never coerces the registry itself.
///
/// Both are `#[inline(never)]`, and that is what makes the rule hold: a function this small is
/// inlined across crates by default, and inlined into the ABI it builds the vtable there again.
impl SharedSession {
    /// This registry as the engine an ABI keeps.
    #[inline(never)]
    pub fn as_engine(self: &Arc<Self>) -> Arc<dyn SessionEngine> {
        self.clone()
    }

    /// This registry as the engine an ABI borrows for one call.
    #[inline(never)]
    pub fn engine_ref(&self) -> &dyn SessionEngine {
        self
    }
}

/// The session a C handle holds, as the port's [`SessionDrive`]. This engine drives itself on a
/// thread of its own, so pico's single-threaded calls find the work already done and answer as
/// for a live session: the one-directional divergence `docs/capi-pico-on-coop-engine.md`
/// describes, which the cooperative engine removes.
impl SessionDrive for SessionState {
    fn zid(&self) -> [u8; 16] {
        SessionEngine::zid(self.shared.engine_ref())
    }

    fn close(&self) {
        SessionState::close(self)
    }

    fn is_closed(&self) -> bool {
        SessionState::is_closed(self)
    }

    fn start_read_task(&self) -> Result<(), ReadTaskStartRefused> {
        // This engine's read task is a gate on its own runtime and takes no thread to start.
        SessionState::start_read_task(self).map_err(ReadTaskStartRefused::from)
    }

    fn stop_read_task(&self) -> Result<(), CalledFromReadTask> {
        SessionState::stop_read_task(self)
    }

    fn read_task_is_running(&self) -> bool {
        SessionState::read_task_is_running(self)
    }

    fn read(&self, _single: bool) -> Result<(), SessionClosed> {
        // This engine reads continuously on its own runtime: a call processes nothing, so
        // there is no per-call read for `single` to bound.
        self.live()
    }

    fn send_keep_alive(&self) -> Result<(), SessionClosed> {
        self.live()
    }

    fn spin_once(&self) -> bool {
        // pico answers `false` only for a closed session or an idle task queue; this engine
        // has no queue to be empty.
        !SessionState::is_closed(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// The session a C handle holds on this engine: the session as the port's [`SessionDrive`], and
/// the engine its entities keep. The engine is reached through trait objects, so it is this drive
/// that hands the engine out, and not the port's trait, which a build of one engine reaches by the
/// engine's own type.
///
/// It reads as the session's drive ([`Deref`](core::ops::Deref)): the handle closes, steps and
/// asks the session through it.
pub struct CoreDrive {
    session: Box<dyn SessionDrive>,
    engine: Arc<dyn SessionEngine>,
}

impl CoreDrive {
    /// The engine the session's entities keep.
    pub fn engine(&self) -> Arc<dyn SessionEngine> {
        self.engine.clone()
    }

    /// The engine, borrowed for the length of one call.
    pub fn engine_ref(&self) -> &dyn SessionEngine {
        &*self.engine
    }
}

impl core::ops::Deref for CoreDrive {
    type Target = dyn SessionDrive;

    fn deref(&self) -> &Self::Target {
        &*self.session
    }
}

impl SessionState {
    /// This session as the drive a C handle holds, made HERE (out of line) for the reason
    /// [`SharedSession::as_engine`] is: a trait object made in an ABI crate brings the session's
    /// drop glue there a second time. The ABI then frees the session through the drive's vtable
    /// (pico `z_session_drop`), whose drop is this crate's; a `Box<SessionState>` dropped in the
    /// ABI crate measured 35 KB of duplicate text on the pico client build.
    #[inline(never)]
    pub fn into_drive(self) -> CoreDrive {
        let engine = self.shared.as_engine();
        CoreDrive {
            session: Box::new(self),
            engine,
        }
    }

    /// What a single-threaded entry point answers: done, for a live session.
    fn live(&self) -> Result<(), SessionClosed> {
        if SessionState::is_closed(self) {
            Err(SessionClosed)
        } else {
            Ok(())
        }
    }
}

impl SessionEngine for SharedSession {
    fn is_closed(&self) -> bool {
        SharedSession::is_closed(self)
    }

    fn session_zid(&self) -> SessionZid {
        SharedSession::session_zid(self)
    }

    fn now_ms(&self) -> u64 {
        SharedSession::now_ms(self)
    }

    fn next_entity_id(&self) -> Option<wz_session_core::wire_id::EntityId> {
        SharedSession::next_entity_id(self)
    }

    /// A peer's key is its place among the faces, in the order of their ids.
    fn next_peer(&self, from: u64) -> Option<(u64, PeerIdentity)> {
        SharedSession::face_sessions(self)
            .into_iter()
            .enumerate()
            .skip(usize::try_from(from).ok()?)
            .find_map(|(at, session)| {
                let actions = session.actions();
                Some((
                    at as u64,
                    PeerIdentity {
                        zid: SessionZid::new(&actions.peer_zid()?).ok()?,
                        whatami: actions.peer_whatami_wire()?,
                    },
                ))
            })
    }

    /// A member's key is its place in the list of every group's members.
    #[cfg(feature = "multicast-transport")]
    fn next_group_member(&self, from: u64) -> Option<(u64, SessionZid)> {
        SharedSession::group_member_zids(self)
            .into_iter()
            .enumerate()
            .skip(usize::try_from(from).ok()?)
            .find_map(|(at, zid)| Some((at as u64, SessionZid::new(&zid).ok()?)))
    }

    #[cfg(feature = "multicast-transport")]
    fn send_join_on_groups(&self) -> Result<usize, Refusal> {
        if SharedSession::is_closed(self) {
            return Err(Refusal::Closed);
        }
        Ok(SharedSession::send_join_on_groups(self))
    }

    fn listen_locators(&self) -> Vec<String> {
        SharedSession::listen_locators(self)
    }

    fn node_timestamp(&self) -> Option<wz_session_core::sample::TimestampHint> {
        SharedSession::node_timestamp(self)
    }

    fn has_router_peer(&self) -> bool {
        SharedSession::has_router_peer(self)
    }

    #[cfg(feature = "shared-key-ids")]
    fn names_keys_by_link(&self) -> bool {
        SharedSession::names_keys_by_link(self)
    }

    #[cfg(feature = "resource-snapshot")]
    fn message_reading(&self) -> Option<wz_session_core::resource_snapshot::BuildMessageReading> {
        Some(SharedSession::message_reading(self))
    }

    fn face_snapshots(&self) -> Vec<wz_session_core::face::FaceSnapshot> {
        // Each unicast face, then each member of each group the session joined, which pico lists
        // as a multicast transport of its own.
        #[cfg_attr(not(feature = "multicast-transport"), allow(unused_mut))]
        let mut all = SharedSession::face_snapshots(self);
        #[cfg(feature = "multicast-transport")]
        all.extend(self.group_member_snapshots());
        all
    }

    fn watch_faces(&self, sink: wz_session_core::face::FaceEventSink) -> Result<u64, Refusal> {
        if SharedSession::is_closed(self) {
            return Err(Refusal::Closed);
        }
        Ok(SharedSession::watch_faces(self, sink))
    }

    fn unwatch_faces(&self, id: u64) -> bool {
        SharedSession::unwatch_faces(self, id)
    }

    // The registry watches its faces' peers in a build with either capability that reads the
    // watch; without them the provided refusal stands, and the build carries none of the watch.
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    fn declare_decl_watch(
        &self,
        plane: wz_capi_port::DeclPlane,
        sink: wz_capi_port::DeclWatchSink,
    ) -> Result<wz_capi_port::DeclWatchId, Refusal> {
        SharedSession::declare_decl_watch(self, plane, sink)
    }

    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    fn undeclare_decl_watch(&self, id: wz_capi_port::DeclWatchId) -> bool {
        SharedSession::undeclare_decl_watch(self, id)
    }

    fn linkstate_regions(&self) -> Vec<(String, String)> {
        SharedSession::linkstate_regions(self)
    }

    fn publish_on_wire_all(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        SharedSession::publish_on_wire_all(self, keyexpr, wire, payload, opts)
    }

    #[cfg(feature = "transport-shm")]
    fn has_shm_peer(&self) -> bool {
        SharedSession::has_shm_peer(self)
    }

    #[cfg(feature = "transport-shm")]
    fn publish_shm_on_wire_all(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        payload: wz_session_core::extshm::ShmSendHandle,
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        SharedSession::publish_shm_handle_on_wire_all(self, keyexpr, wire, payload, opts)
    }

    fn declare_subscriber_on_wire(
        &self,
        keyexpr: &str,
        wire: WireKey,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> Result<SubId, Refusal> {
        self.declared(|| {
            SharedSession::declare_subscriber_on_wire(
                self,
                keyexpr.to_owned(),
                wire,
                allowed_origin,
                retraction,
                crate::faces::face_sink(sink),
            )
        })
    }

    fn undeclare_subscriber(&self, id: SubId) {
        SharedSession::undeclare_subscriber(self, id)
    }

    fn acquire_keyexpr(&self, keyexpr: &str) -> Result<wz_session_core::wire_id::ExprId, Refusal> {
        self.declared(|| SharedSession::acquire_keyexpr(self, keyexpr.to_owned()))
    }

    fn release_keyexpr(&self, mapping_id: wz_session_core::wire_id::ExprId) {
        SharedSession::release_keyexpr(self, mapping_id)
    }

    fn retain_keyexpr(&self, mapping_id: wz_session_core::wire_id::ExprId) {
        SharedSession::retain_keyexpr(self, mapping_id)
    }
    fn declare_matching_listener(
        &self,
        plane: FilterPlane,
        keyexpr: &str,
        sink: MatchingSink,
        count_local: bool,
    ) -> Result<MatchId, Refusal> {
        Ok(SharedSession::declare_plane_matching_listener(
            self,
            plane,
            keyexpr.to_owned(),
            sink,
            count_local,
        ))
    }

    fn declare_matching_listener_in(
        &self,
        plane: FilterPlane,
        keyexpr: &str,
        sink: MatchingSink,
        locality: Locality,
    ) -> Result<MatchId, Refusal> {
        Ok(SharedSession::declare_matching_listener_in(
            self,
            plane,
            keyexpr.to_owned(),
            sink,
            locality,
        ))
    }

    fn matching_status(
        &self,
        plane: FilterPlane,
        keyexpr: &str,
        locality: Locality,
    ) -> Option<bool> {
        Some(SharedSession::matching_verdict(
            self, plane, keyexpr, locality,
        ))
    }

    fn undeclare_matching_listener(&self, id: MatchId) {
        SharedSession::undeclare_matching_listener(self, id)
    }

    fn declare_write_filter(
        &self,
        plane: FilterPlane,
        keyexpr: &str,
        wire: &WireKey,
        ask: Option<InterestAsk<'_>>,
        count_local: bool,
    ) -> Result<FilterId, Refusal> {
        // A closed session declares nothing: a filter on it would hold every write back for good.
        if SharedSession::is_closed(self) {
            return Err(Refusal::Closed);
        }
        // The registry refuses a filter for want of an entity id alone.
        SharedSession::declare_write_filter(self, plane, keyexpr.to_owned(), wire, ask, count_local)
            .ok_or(Refusal::NoEntityId)
    }

    fn write_filter_active(&self, id: FilterId) -> bool {
        SharedSession::write_filter_active(self, id)
    }

    fn write_filter_holds_back(&self, id: FilterId) -> bool {
        SharedSession::write_filter_holds_back(self, id)
    }

    fn undeclare_write_filter(&self, id: FilterId) {
        SharedSession::undeclare_write_filter(self, id)
    }

    fn put_plain_filtered(
        &self,
        filter: FilterId,
        keyexpr: &str,
        mapping_id: wz_session_core::wire_id::ExprId,
        payload: &[u8],
        params: &PlainPutParams,
    ) -> FilteredPut {
        SharedSession::put_plain_filtered(self, filter, keyexpr, mapping_id, payload, params)
    }

    fn keep_write_filter_plain(
        &self,
        filter: FilterId,
        plain: Option<(PlainPutParams, wz_session_core::wire_id::ExprId)>,
    ) {
        SharedSession::keep_write_filter_plain(self, filter, plain)
    }

    fn publish_filtered(
        &self,
        filter: FilterId,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: Option<&PublishOptions>,
    ) -> FilteredPut {
        match opts {
            // A link that names keys its own way is sent a bare write the general way.
            #[cfg(feature = "shared-key-ids")]
            None if SharedSession::names_keys_by_link(self) => {
                if SharedSession::write_filter_holds_back(self, filter) {
                    FilteredPut::Suppressed
                } else {
                    FilteredPut::NotPlain
                }
            }
            None => SharedSession::put_kept_plain(self, filter, keyexpr, payload),
            Some(opts) => {
                if SharedSession::write_filter_holds_back(self, filter) {
                    return FilteredPut::Suppressed;
                }
                FilteredPut::Sent(SharedSession::publish_on_wire_all(
                    self, keyexpr, wire, payload, opts,
                ))
            }
        }
    }

    fn has_transport(&self) -> bool {
        !self.face_set().is_empty() || !SharedSession::listen_locators(self).is_empty()
    }

    fn batch_all(&self, step: BatchStep) -> usize {
        match step {
            BatchStep::Start => SharedSession::batch_start_all(self),
            BatchStep::Flush => SharedSession::batch_flush_all(self),
            BatchStep::Stop => SharedSession::batch_stop_all(self),
        }
    }

    #[cfg(feature = "queryable")]
    fn declare_queryable_on_wire(
        &self,
        keyexpr: &str,
        wire: WireKey,
        complete: bool,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: wz_capi_port::QueryableSink,
    ) -> Result<wz_capi_port::QblId, Refusal> {
        self.declared(|| {
            self.declare_port_queryable_on_links(
                keyexpr.to_owned(),
                wire,
                complete,
                allowed_origin,
                LinkRestriction::Any,
                retraction,
                sink,
            )
        })
    }

    #[cfg(feature = "queryable")]
    fn undeclare_queryable(&self, id: wz_capi_port::QblId) {
        SharedSession::undeclare_queryable(self, id);
    }

    // One leg per connected face, as the snapshot get always fanned; it asks by the literal key,
    // which the runtime's liveliness get has no other form of, so `wire` is not read.
    #[cfg(feature = "liveliness-get")]
    fn liveliness_get_on_wire(
        &self,
        keyexpr: &str,
        _wire: &WireKey,
        timeout_ms: u32,
        fan: Option<&crate::cancellation::CancellableFan>,
        leg: &mut dyn FnMut() -> wz_capi_port::ReplyCallback,
    ) -> Result<usize, Refusal> {
        self.liveliness_get_on_port(keyexpr, timeout_ms, LinkRestriction::Any, fan, leg)
    }

    // The runtime's token names in its retraction the key it was declared on, which is the key
    // `retraction` names: so whether it names one is all it needs.
    #[cfg(feature = "liveliness")]
    fn declare_liveliness_token_on_wire(
        &self,
        keyexpr: &str,
        wire: WireKey,
        retraction: Option<RetractionKey>,
    ) -> Result<wz_capi_port::TokenId, Refusal> {
        self.declared(|| {
            SharedSession::declare_liveliness_token_on_wire(
                self,
                keyexpr.to_owned(),
                wire,
                crate::runtime::session::LivelinessOptions::new()
                    .with_retraction_naming_the_key(retraction.is_some()),
            )
        })
    }

    #[cfg(feature = "advanced")]
    fn start_ticker(
        &self,
        period_ms: u64,
        tick: wz_capi_port::Tick,
    ) -> Result<wz_capi_port::TickerId, Refusal> {
        self.declared(|| Some(SharedSession::start_ticker(self, period_ms, tick)))
    }

    #[cfg(feature = "advanced")]
    fn stop_ticker(&self, id: wz_capi_port::TickerId) {
        SharedSession::stop_ticker(self, id);
    }

    #[cfg(feature = "liveliness")]
    fn undeclare_liveliness_token(&self, id: wz_capi_port::TokenId) {
        SharedSession::undeclare_liveliness_token(self, id);
    }

    #[cfg(feature = "liveliness")]
    fn declare_liveliness_subscriber_on_wire(
        &self,
        keyexpr: &str,
        wire: WireKey,
        history: bool,
        sink: wz_capi_port::LivelinessSink,
    ) -> Result<SubId, Refusal> {
        // `#[non_exhaustive]`: built from its default and narrowed.
        let mut options = crate::runtime::session::LivelinessSubscriberOptions::default();
        options.history = history;
        self.declared(|| {
            SharedSession::declare_liveliness_subscriber_on_wire(
                self,
                keyexpr.to_owned(),
                wire,
                options,
                crate::faces::face_liveliness_sink(sink),
            )
        })
    }

    #[cfg(feature = "query")]
    fn get_on_wire(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        opts: &wz_session_core::query_options::QueryOptionsOf<'_>,
        fan: Option<&crate::cancellation::CancellableFan>,
        leg: &mut dyn FnMut() -> wz_capi_port::ReplyCallback,
    ) -> Result<usize, Refusal> {
        // A closed session asks nothing; one that is open but reaches nobody issues no leg.
        if SharedSession::is_closed(self) {
            return Err(Refusal::Closed);
        }
        // Each leg keeps its options past the call: the slots the caller lent are copied.
        let opts = &opts.to_owned_options();
        // The registry's fan: one leg per face (and group), and the local plane where the
        // options admit it. A leg whose issue fails (a face mid-teardown, an alias the face was
        // never told) drops its callback with its rolled-back pending entry, so it cannot hold
        // the get open; it is not counted.
        let mut issued = 0;
        self.fan_query(
            opts.allowed_destination,
            crate::faces::QueryReach::of(opts),
            fan,
            |query_leg| {
                let rid = query_leg
                    .query_on_wire(keyexpr, wire, opts.clone(), crate::faces::face_reply(leg()))
                    .ok()
                    .map(|handle| handle.rid());
                issued += usize::from(rid.is_some());
                rid
            },
        );
        Ok(issued)
    }

    #[cfg(all(feature = "transport-shm", feature = "query"))]
    fn get_shm_on_wire(
        &self,
        keyexpr: &str,
        _wire: &WireKey,
        opts: &wz_session_core::query_options::QueryOptionsOf<'_>,
        value: wz_session_core::extshm::ShmSendHandle,
        fan: Option<&crate::cancellation::CancellableFan>,
        leg: &mut dyn FnMut() -> wz_capi_port::ReplyCallback,
    ) -> Result<usize, Refusal> {
        if SharedSession::is_closed(self) {
            return Err(Refusal::Closed);
        }
        // Each leg keeps its options past the call: the slots the caller lent are copied.
        let opts = &opts.to_owned_options();
        // `get_on_wire`'s fan, each leg asking with the chunk (`QueryLeg::query_shm`): a face that
        // negotiated shared memory is sent its descriptor and every other leg the bytes. A query
        // whose value is a chunk names its key literally, as the registry's own getter does, so
        // `wire` is not used.
        let mut issued = 0;
        self.fan_query(
            opts.allowed_destination,
            crate::faces::QueryReach::of(opts),
            fan,
            |query_leg| {
                let rid = query_leg
                    .query_shm(
                        keyexpr,
                        opts.clone(),
                        &value,
                        crate::faces::face_reply(leg()),
                    )
                    .ok()
                    .map(|handle| handle.rid());
                issued += usize::from(rid.is_some());
                rid
            },
        );
        Ok(issued)
    }

    // The registry numbers its links (`faces::link_slot_of_face`) and honours a set on every
    // operation that states one, so none of these refuses.

    fn declare_subscriber_on_link_set(
        &self,
        keyexpr: &str,
        wire: WireKey,
        allowed_origin: Locality,
        links: LinkRestriction,
        retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> Result<SubId, Refusal> {
        self.declared(|| {
            SharedSession::declare_subscriber_on_links(
                self,
                keyexpr.to_owned(),
                wire,
                allowed_origin,
                links,
                retraction,
                crate::faces::face_sink(sink),
            )
        })
    }

    #[cfg(feature = "queryable")]
    #[allow(clippy::too_many_arguments)]
    fn declare_queryable_on_link_set(
        &self,
        keyexpr: &str,
        wire: WireKey,
        complete: bool,
        allowed_origin: Locality,
        links: LinkRestriction,
        retraction: Option<RetractionKey>,
        sink: wz_capi_port::QueryableSink,
    ) -> Result<wz_capi_port::QblId, Refusal> {
        self.declared(|| {
            self.declare_port_queryable_on_links(
                keyexpr.to_owned(),
                wire,
                complete,
                allowed_origin,
                links,
                retraction,
                sink,
            )
        })
    }

    #[cfg(feature = "liveliness")]
    fn declare_liveliness_token_on_link_set(
        &self,
        keyexpr: &str,
        wire: WireKey,
        links: LinkRestriction,
        retraction: Option<RetractionKey>,
    ) -> Result<wz_capi_port::TokenId, Refusal> {
        self.declared(|| {
            SharedSession::declare_liveliness_token_on_links(
                self,
                keyexpr.to_owned(),
                wire,
                crate::runtime::session::LivelinessOptions::new()
                    .with_retraction_naming_the_key(retraction.is_some()),
                links,
            )
        })
    }

    #[cfg(feature = "liveliness")]
    fn declare_liveliness_subscriber_on_link_set(
        &self,
        keyexpr: &str,
        wire: WireKey,
        history: bool,
        links: LinkRestriction,
        sink: wz_capi_port::LivelinessSink,
    ) -> Result<SubId, Refusal> {
        // `#[non_exhaustive]`: built from its default and narrowed.
        let mut options = crate::runtime::session::LivelinessSubscriberOptions::default();
        options.history = history;
        self.declared(|| {
            SharedSession::declare_liveliness_subscriber_on_links(
                self,
                keyexpr.to_owned(),
                wire,
                options,
                links,
                crate::faces::face_liveliness_sink(sink),
            )
        })
    }

    #[cfg(feature = "liveliness-get")]
    fn liveliness_get_on_link_set(
        &self,
        keyexpr: &str,
        _wire: &WireKey,
        timeout_ms: u32,
        links: LinkRestriction,
        fan: Option<&crate::cancellation::CancellableFan>,
        leg: &mut dyn FnMut() -> wz_capi_port::ReplyCallback,
    ) -> Result<usize, Refusal> {
        self.liveliness_get_on_port(keyexpr, timeout_ms, links, fan, leg)
    }
}

impl SharedSession {
    /// A declaration the registry makes, as the port answers it: refused on a closed session,
    /// which declares nothing (`made` is not run, so the sink it holds is let go of), and
    /// refused for want of an id when the registry made none, which on a registry whose tables
    /// grow is the one way it refuses.
    fn declared<T>(&self, made: impl FnOnce() -> Option<T>) -> Result<T, Refusal> {
        if self.is_closed() {
            return Err(Refusal::Closed);
        }
        made().ok_or(Refusal::NoEntityId)
    }

    /// The registry's walk of a liveliness get, as the port answers it: refused on a closed session,
    /// which asks nothing, and the number of legs issued on an open one.
    #[cfg(feature = "liveliness-get")]
    fn liveliness_get_on_port(
        &self,
        keyexpr: &str,
        timeout_ms: u32,
        links: LinkRestriction,
        fan: Option<&crate::cancellation::CancellableFan>,
        leg: &mut dyn FnMut() -> wz_capi_port::ReplyCallback,
    ) -> Result<usize, Refusal> {
        if self.is_closed() {
            return Err(Refusal::Closed);
        }
        let mut leg = || crate::faces::face_reply(leg());
        Ok(self.liveliness_get_on_links(keyexpr, timeout_ms, links, fan, &mut leg))
    }
}

/// One face's session as the port's [`QueryHolder`](wz_capi_port::QueryHolder): a query held
/// through it answers on that face, and the node's latch says whether its session is closed.
#[cfg(feature = "queryable")]
struct FaceHolder {
    face: wz_runtime_tokio::session::TokioQueryHolder,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(feature = "queryable")]
impl wz_capi_port::QueryHolder for FaceHolder {
    fn hold_query(
        &self,
        view: &dyn wz_session_core::query_sink::QueryView,
    ) -> Box<dyn wz_capi_port::HeldQuery> {
        Box::new(FaceHeld {
            held: self.face.hold_query(view),
            closed: self.closed.clone(),
        })
    }

    fn session_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(feature = "queryable")]
impl SharedSession {
    /// The queryable the port declares ([`SessionEngine::declare_queryable_on_wire`]), limited
    /// to the links of `links` (policy `entity-link-restriction`, see
    /// [`Self::declare_queryable_on_links`]). The port has no operation that carries a set of
    /// links, so a caller that holds the registry itself and states one calls this.
    #[allow(clippy::too_many_arguments)]
    pub fn declare_port_queryable_on_links(
        &self,
        keyexpr: String,
        wire: WireKey,
        complete: bool,
        allowed_origin: Locality,
        links: LinkRestriction,
        retraction: Option<RetractionKey>,
        sink: wz_capi_port::QueryableSink,
    ) -> Option<wz_capi_port::QblId> {
        // The registry mints a callback per face with the face's own session; each calls the one
        // sink the port was handed with that session as a `QueryHolder`, beside the node's closed
        // latch, which is what a reply on a kept query checks first.
        let closed = self.closed_latch();
        let sink = Arc::new(sink);
        self.declare_queryable_on_links(
            keyexpr,
            wire,
            complete,
            allowed_origin,
            links,
            retraction,
            Arc::new(move |face: &wz_runtime_tokio::session::TokioQueryHolder| {
                let holder = FaceHolder {
                    face: face.clone(),
                    closed: closed.clone(),
                };
                let sink = Arc::clone(&sink);
                Box::new(
                    move |query: &dyn wz_session_core::query_sink::QueryView,
                          out: &mut dyn wz_session_core::query_sink::ReplyOut| {
                        sink.call(query, out, &holder);
                    },
                ) as Box<_>
            }),
        )
    }
}

/// The runtime's held query as the port's [`HeldQuery`](wz_capi_port::HeldQuery), beside the
/// node's closed latch its face's holder reads; dropping it releases the runtime's hold.
#[cfg(feature = "queryable")]
struct FaceHeld {
    held: wz_runtime_tokio::session::TokioHeldQuery,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(feature = "queryable")]
impl wz_capi_port::HeldQuery for FaceHeld {
    fn reply(&self, answer: &mut dyn FnMut(&mut dyn wz_session_core::query_sink::ReplyOut)) {
        self.held.reply(|out| answer(out));
    }

    fn session_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }
}

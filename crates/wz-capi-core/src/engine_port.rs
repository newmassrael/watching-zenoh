// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! This engine as the port's [`SessionEngine`]: every operation is the face registry's own, so
//! an ABI that holds `Arc<dyn SessionEngine>` gets exactly what it got by naming
//! [`SharedSession`] (`docs/capi-pico-on-coop-engine.md`, step 2).

use std::any::Any;

use wz_capi_port::{
    CalledFromReadTask, FanoutError, FilterId, FilterPlane, FilteredPut, MatchId, MatchingSink,
    SessionClosed, SessionDrive, SessionEngine, SubId, SubscriberSink, WireKey,
};
use wz_session_core::declare_form::{InterestForm, RetractionKey};
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::{PlainPutParams, PublishOptions};

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
    fn engine(&self) -> Arc<dyn SessionEngine> {
        self.shared.as_engine()
    }

    fn engine_ref(&self) -> &dyn SessionEngine {
        self.shared.engine_ref()
    }

    fn zid(&self) -> [u8; 16] {
        SessionState::zid(self)
    }

    fn close(&self) {
        SessionState::close(self)
    }

    fn is_closed(&self) -> bool {
        SessionState::is_closed(self)
    }

    fn start_read_task(&self) -> Result<(), CalledFromReadTask> {
        SessionState::start_read_task(self)
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

impl SessionState {
    /// This session as the port's drive, made HERE (out of line) for the reason
    /// [`SharedSession::as_engine`] is: a trait object made in an ABI crate brings the session's
    /// drop glue there a second time. The ABI then frees the session through the drive's vtable
    /// (pico `z_session_drop`), whose drop is this crate's; a `Box<SessionState>` dropped in the
    /// ABI crate measured 35 KB of duplicate text on the pico client build.
    #[inline(never)]
    pub fn into_drive(self) -> Box<dyn SessionDrive> {
        Box::new(self)
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

    fn zid(&self) -> [u8; 16] {
        SharedSession::zid(self)
    }

    fn next_entity_id(&self) -> u64 {
        SharedSession::next_entity_id(self)
    }

    fn peer_identities(&self) -> Vec<(Vec<u8>, u8)> {
        SharedSession::peer_identities(self)
    }

    fn has_router_peer(&self) -> bool {
        SharedSession::has_router_peer(self)
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

    fn watch_faces(&self, sink: wz_session_core::face::FaceEventSink) -> u64 {
        SharedSession::watch_faces(self, sink)
    }

    fn unwatch_faces(&self, id: u64) -> bool {
        SharedSession::unwatch_faces(self, id)
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

    fn declare_subscriber_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> SubId {
        SharedSession::declare_subscriber_on_wire(
            self,
            keyexpr,
            wire,
            allowed_origin,
            retraction,
            sink,
        )
    }

    fn undeclare_subscriber(&self, id: SubId) {
        SharedSession::undeclare_subscriber(self, id)
    }

    fn acquire_keyexpr(&self, keyexpr: String) -> Option<u64> {
        SharedSession::acquire_keyexpr(self, keyexpr)
    }

    fn release_keyexpr(&self, mapping_id: u64) {
        SharedSession::release_keyexpr(self, mapping_id)
    }

    fn keyexpr_declarations(&self) -> Vec<(u64, String)> {
        SharedSession::keyexpr_declarations(self)
    }

    fn declare_matching_listener(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        sink: MatchingSink,
        count_local: bool,
    ) -> MatchId {
        SharedSession::declare_plane_matching_listener(self, plane, keyexpr, sink, count_local)
    }

    fn undeclare_matching_listener(&self, id: MatchId) {
        SharedSession::undeclare_matching_listener(self, id)
    }

    fn declare_write_filter(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        wire: &WireKey,
        ask: Option<InterestForm>,
        count_local: bool,
    ) -> FilterId {
        SharedSession::declare_write_filter(self, plane, keyexpr, wire, ask, count_local)
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
        mapping_id: u64,
        payload: &[u8],
        params: &PlainPutParams,
    ) -> FilteredPut {
        SharedSession::put_plain_filtered(self, filter, keyexpr, mapping_id, payload, params)
    }

    fn batch_start_all(&self) -> usize {
        SharedSession::batch_start_all(self)
    }

    fn batch_flush_all(&self) -> usize {
        SharedSession::batch_flush_all(self)
    }

    fn batch_stop_all(&self) -> usize {
        SharedSession::batch_stop_all(self)
    }

    #[cfg(feature = "queryable")]
    fn declare_queryable_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        complete: bool,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: wz_capi_port::QueryableSink,
    ) -> Option<wz_capi_port::QblId> {
        // The registry mints a callback per face with the face's own session; the port's
        // callbacks are minted with that session as a `QueryHolder`, beside the node's closed
        // latch, which is what a reply on a kept query checks first.
        let closed = self.closed_latch();
        Some(SharedSession::declare_queryable_on_wire(
            self,
            keyexpr,
            wire,
            complete,
            allowed_origin,
            retraction,
            Arc::new(move |face: &wz_runtime_tokio::session::TokioQueryHolder| {
                sink(Arc::new(FaceHolder {
                    face: face.clone(),
                    closed: closed.clone(),
                }))
            }),
        ))
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
    ) -> Option<usize> {
        let opts =
            crate::runtime::session::LivelinessGetOptions::default().with_timeout_ms(timeout_ms);
        let mut issued = 0;
        for (session, revised) in self.face_sessions_with_wake() {
            let mut reply = leg();
            // Completion is the pending entry's sink being DROPPED, which covers a real final,
            // a timeout sweep and a face death alike, so the final needs no body.
            let got = session.liveliness_get(
                keyexpr.to_owned(),
                opts,
                move |view: &dyn wz_session_core::reply_sink::ReplyView| reply(view),
                |_id| {},
            );
            // The interest id this face registered under, recorded so a later cancel can
            // unregister it. `record` answers `false` when the token cancelled while the fan was
            // running; it has already undone THIS registration, so only the issuing stops.
            let cancelled_mid_fan = match (fan, &got) {
                (Some(fan), Ok(interest_id)) => {
                    let undo = session.clone();
                    let interest_id = *interest_id;
                    !fan.record(move || {
                        undo.cancel_pending_liveliness_get(interest_id);
                    })
                }
                _ => false,
            };
            issued += usize::from(got.is_ok());
            drop(got);
            if cancelled_mid_fan {
                break;
            }
            // Wake this face's drive loop so it re-arms on the deadline just registered;
            // without it a silent session sweeps the snapshot only at the next keepalive wake.
            revised.notify_one();
        }
        Some(issued)
    }

    // The runtime's token names in its retraction the key it was declared on, which is the key
    // `retraction` names: so whether it names one is all it needs.
    #[cfg(feature = "liveliness")]
    fn declare_liveliness_token_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        retraction: Option<RetractionKey>,
    ) -> Option<wz_capi_port::TokenId> {
        SharedSession::declare_liveliness_token_on_wire(
            self,
            keyexpr,
            wire,
            crate::runtime::session::LivelinessOptions::new()
                .with_retraction_naming_the_key(retraction.is_some()),
        )
    }

    fn start_ticker(
        &self,
        period_ms: u64,
        tick: wz_capi_port::Tick,
    ) -> Option<wz_capi_port::TickerId> {
        Some(SharedSession::start_ticker(self, period_ms, tick))
    }

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
        keyexpr: String,
        wire: WireKey,
        history: bool,
        sink: wz_capi_port::LivelinessSink,
    ) -> Option<SubId> {
        // `#[non_exhaustive]`: built from its default and narrowed.
        let mut options = crate::runtime::session::LivelinessSubscriberOptions::default();
        options.history = history;
        Some(SharedSession::declare_liveliness_subscriber_on_wire(
            self, keyexpr, wire, options, sink,
        ))
    }

    #[cfg(feature = "query")]
    fn get_on_wire(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        opts: &wz_session_core::query_options::QueryOptions,
        fan: Option<&crate::cancellation::CancellableFan>,
        leg: &mut dyn FnMut() -> wz_capi_port::ReplyCallback,
    ) -> Option<usize> {
        // The registry's fan: one leg per face (and group), and the local plane where the
        // options admit it. A leg whose issue fails (a face mid-teardown, an alias the face was
        // never told) drops its callback with its rolled-back pending entry, so it cannot hold
        // the get open; it is not counted.
        let mut issued = 0;
        self.fan_query(opts.allowed_destination, fan, |query_leg| {
            let rid = query_leg
                .query_on_wire(keyexpr, wire, opts.clone(), leg())
                .ok()
                .map(|handle| handle.rid());
            issued += usize::from(rid.is_some());
            rid
        });
        Some(issued)
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
        Box::new(FaceHeld(self.face.hold_query(view)))
    }

    fn session_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The runtime's held query as the port's [`HeldQuery`](wz_capi_port::HeldQuery); dropping it
/// releases the runtime's hold.
#[cfg(feature = "queryable")]
struct FaceHeld(wz_runtime_tokio::session::TokioHeldQuery);

#[cfg(feature = "queryable")]
impl wz_capi_port::HeldQuery for FaceHeld {
    fn reply(&self, answer: &mut dyn FnMut(&mut dyn wz_session_core::query_sink::ReplyOut)) {
        self.0.reply(|out| answer(out));
    }
}

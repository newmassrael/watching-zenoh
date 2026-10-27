// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a C ABI asks of a session's engine: [`SessionEngine`].
//!
//! The operations are those a single-threaded zenoh-pico client makes — publish, declare and
//! retract a subscriber, hold and release a key expression declaration, watch whether a peer
//! matches, filter writes nobody would receive, open and flush a batch — spelled in this crate's
//! vocabulary and session-core's types, so the ABI that calls them names no engine. An engine
//! implements the trait; an ABI holds `Arc<dyn SessionEngine>` and reaches the engine through
//! nothing else (`docs/capi-pico-on-coop-engine.md`, decision D1).
//!
//! The queryable joined when the cooperative engine answered queries, the get (over
//! session-core's `QueryOptions`) when it asked them, and the liveliness token and subscriber
//! when it held and heard them, the liveliness get when it asked for the ones alive, and the
//! faces (the snapshot of each and the watch of their coming and going) when a connectivity
//! plane and an admin space read them; a capability no second engine has yet (scouting, the
//! advanced publisher) is not here: an ABI module that needs one still names its engine, and
//! joins this trait when a second engine implements it.

use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::declare_form::{InterestForm, RetractionKey};
use wz_session_core::face::{FaceEventSink, FaceSnapshot};
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::{PlainPutParams, PublishOptions};
use wz_session_core::query_options::QueryOptions;

use crate::cancellation::CancellableFan;
use crate::{
    FanoutError, FilterId, FilterPlane, FilteredPut, LivelinessSink, MatchId, MatchingSink, QblId,
    QueryableSink, ReplyCallback, SubId, SubscriberSink, Tick, TickerId, TokenId, WireKey,
};

/// The operations a C ABI's client surface makes on one session, whatever engine runs it.
///
/// Every method takes `&self`: an engine is shared between the C session handle and every entity
/// declared on it (a publisher, a subscriber, a declared key expression each hold it), and the
/// C program may call in from any thread. Releases run outside the engine's locks, so a C
/// `drop(context)` reached from one may re-enter the session.
pub trait SessionEngine: Send + Sync + 'static {
    /// Whether the session has been closed. Every operation after that answers as a closed
    /// session does: nothing is sent and nothing is declared.
    fn is_closed(&self) -> bool;

    /// The session's own zid, zero-padded to 16 bytes.
    fn zid(&self) -> [u8; 16];

    /// The engine's own clock, in whole milliseconds since an epoch of its choosing: monotonic,
    /// and the one its periodic jobs ([`Self::start_ticker`]) and its deadlines run on. A caller
    /// that measures how long ago it last heard of something (a source's retention, say) reads it
    /// here and compares two readings of this one engine, never with another clock.
    fn now_ms(&self) -> u64;

    /// A fresh entity id, for the source info and the global id of what the C program declares.
    fn next_entity_id(&self) -> u64;

    /// The zid and the announced role of every established peer, the role in its 2-bit wire form
    /// (0 router, 1 peer, 2 client), so the split between zenoh-pico's `z_info_routers_zid` and
    /// `z_info_peers_zid` is made at the ABI, where pico makes it. A link whose handshake has not
    /// completed is not listed.
    fn peer_identities(&self) -> Vec<(Vec<u8>, u8)>;

    /// A snapshot of every established face: the peer's identity and the negotiated booleans of
    /// its transport, and the links under it. One entry for each transport a connectivity plane
    /// lists, a joined group's members included where the engine joins groups. A face whose
    /// handshake has not completed is not listed, as with [`Self::peer_identities`]. An engine
    /// built without the connectivity plane lists none, which is the provided answer.
    fn face_snapshots(&self) -> Vec<FaceSnapshot> {
        Vec::new()
    }

    /// Tell `sink` each time a face comes up or goes down, from now on, and answer the id that
    /// stops it ([`Self::unwatch_faces`]). The sink runs where the session hands out its
    /// callbacks and never under the session's lock, so it may reach back into the session. An
    /// engine built without the connectivity plane tells nobody of anything, which is the
    /// provided answer.
    fn watch_faces(&self, sink: FaceEventSink) -> u64 {
        let _ = sink;
        0
    }

    /// Stop the face watch `id`: `true` when one was registered under it.
    fn unwatch_faces(&self, id: u64) -> bool {
        let _ = id;
        false
    }

    /// Whether any connected peer is a ROUTER — zenoh-pico's `_z_session_has_router_peer`, the
    /// condition under which a peer-mode session sends Interests at all.
    fn has_router_peer(&self) -> bool;

    /// Publish `payload` on `keyexpr`, naming it on the wire as `wire` says, with `opts`. The
    /// count of deliveries, or why nothing could have carried it.
    fn publish_on_wire_all(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError>;

    /// Declare a subscriber on `keyexpr`, announced as `wire`, receiving what `allowed_origin`
    /// admits through callbacks `sink` mints. `retraction` is the key its undeclaration names
    /// beside its id, when the declaring ABI's reference library names one.
    fn declare_subscriber_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> SubId;

    /// Retract subscriber `id`. Retracting one already retracted does nothing.
    fn undeclare_subscriber(&self, id: SubId);

    /// Hold a declaration of `keyexpr`, declaring it if no one holds it yet: its mapping id, or
    /// `None` when the session has no id left to give.
    fn acquire_keyexpr(&self, keyexpr: String) -> Option<u64>;

    /// Let go of one hold on declaration `mapping_id`; the last one retracts it.
    fn release_keyexpr(&self, mapping_id: u64);

    /// The key expression declarations the session holds, `(id, keyexpr)` in declaration order.
    fn keyexpr_declarations(&self) -> Vec<(u64, String)>;

    /// Tell `sink` whether anything a write filter on `plane` counts matches `keyexpr`, now and
    /// each time that changes: a peer's subscriber, or its queryable (only a complete one when
    /// `plane` requires it); with `count_local`, the session's own too. It counts what that
    /// filter counts, because zenoh-pico's matching listener is its entity's write filter's
    /// callback (`vendor/zenoh-pico/src/api/api.c` @
    /// `_z_matching_listener_register(&_listener_id, _Z_RC_IN_VAL(&sess_rc), &querier->_filter.ctx,`)
    /// and zenoh's querier asks for complete queryables when its target is `ALL_COMPLETE`.
    fn declare_matching_listener(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        sink: MatchingSink,
        count_local: bool,
    ) -> MatchId;

    /// [`Self::declare_matching_listener`] for an entity whose `locality` says whose declarations
    /// count: the peers' (`Remote`), the session's own (`SessionLocal`), or both (`Any`), as
    /// upstream's matching status reads an entity by the destination it was declared with. A
    /// listener of the session's own entities alone asks no peer. `None` from an engine with no
    /// such listener in this build, which is the provided answer.
    fn declare_matching_listener_in(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        sink: MatchingSink,
        locality: Locality,
    ) -> Option<MatchId> {
        let _ = (plane, keyexpr, sink, locality);
        None
    }

    /// Whether anything `plane` counts matches `keyexpr`, from the declarations `locality` admits,
    /// read now: the one-shot twin of [`Self::declare_matching_listener_in`], which never says
    /// otherwise than its listener last did. `None` from an engine with no such status in this
    /// build, which is the provided answer.
    fn matching_status(
        &self,
        plane: FilterPlane,
        keyexpr: &str,
        locality: Locality,
    ) -> Option<bool> {
        let _ = (plane, keyexpr, locality);
        None
    }

    /// Stop the matching listener `id`.
    fn undeclare_matching_listener(&self, id: MatchId);

    /// Declare a write filter on `keyexpr` (named on the wire as `wire`) that counts the
    /// declarations `plane` names, asking the peers as `ask` says or not at all; with
    /// `count_local`, the session's own entities count too.
    fn declare_write_filter(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        wire: &WireKey,
        ask: Option<InterestForm>,
        count_local: bool,
    ) -> FilterId;

    /// Whether filter `id` says nothing matches, so a write is not sent (zenoh-pico's
    /// `_z_write_filter_active`).
    fn write_filter_active(&self, id: FilterId) -> bool;

    /// Whether filter `id` holds a write back on this session: it says nothing matches and the
    /// session has no group a write must reach regardless.
    fn write_filter_holds_back(&self, id: FilterId) -> bool;

    /// Drop write filter `id`.
    fn undeclare_write_filter(&self, id: FilterId);

    /// Send a plain Put through write filter `filter` on the declared key `mapping_id` (or the
    /// literal `keyexpr` when it is `0`), sent from `params`.
    fn put_plain_filtered(
        &self,
        filter: FilterId,
        keyexpr: &str,
        mapping_id: u64,
        payload: &[u8],
        params: &PlainPutParams,
    ) -> FilteredPut;

    /// Open a batch window on the session's links (zenoh-pico `zp_batch_start`): how many opened.
    fn batch_start_all(&self) -> usize;

    /// Flush the open batch windows (zenoh-pico `zp_batch_flush`): how many flushed.
    fn batch_flush_all(&self) -> usize;

    /// Close the batch windows, sending what they hold (zenoh-pico `zp_batch_stop`): how many
    /// closed.
    fn batch_stop_all(&self) -> usize;

    /// Declare a queryable on `keyexpr`, announced as `wire` (`complete` as its declaration says),
    /// answering the queries `allowed_origin` admits through callbacks `sink` mints. `retraction`
    /// is the key its undeclaration names beside its id, when the declaring ABI's reference
    /// library names one. `None` from an engine with no queryable in this build, which is the
    /// provided answer.
    fn declare_queryable_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        complete: bool,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: QueryableSink,
    ) -> Option<QblId> {
        let _ = (keyexpr, wire, complete, allowed_origin, retraction, sink);
        None
    }

    /// Retract queryable `id`. Retracting one already retracted, or one never declared, does
    /// nothing.
    fn undeclare_queryable(&self, id: QblId) {
        let _ = id;
    }

    /// Ask which liveliness tokens are alive on `keyexpr` (named on the wire as `wire`): one leg
    /// per peer the engine reaches, each ended by its peer's DeclFinal, `timeout_ms` (`0` is the
    /// platform default, never none) or the loss of its link. Its replies are token
    /// declarations, with the token's key as the reply's. `leg` and `fan` are as
    /// [`Self::get_on_wire`]'s: `leg` mints each leg's [`ReplyCallback`], whose drop is that
    /// leg's end, and `fan` is told of each leg as it is issued. The number of legs issued, or
    /// `None` from an engine with no liveliness get in this build, which is the provided
    /// answer.
    fn liveliness_get_on_wire(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        timeout_ms: u32,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Option<usize> {
        let _ = (keyexpr, wire, timeout_ms, fan, leg);
        None
    }

    /// Declare a liveliness token on `keyexpr`, announced as `wire`, to every peer the session
    /// reaches now and later. `retraction` is the key its undeclaration names beside its id,
    /// when the declaring ABI's reference library names one. `None` from an engine with no
    /// liveliness in this build, which is the provided answer.
    fn declare_liveliness_token_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        retraction: Option<RetractionKey>,
    ) -> Option<TokenId> {
        let _ = (keyexpr, wire, retraction);
        None
    }

    /// Retract token `id`, which tells the peers' liveliness subscribers it is gone. Retracting
    /// one already retracted, or one never declared, does nothing.
    fn undeclare_liveliness_token(&self, id: TokenId) {
        let _ = id;
    }

    /// Subscribe to the liveliness tokens the peers hold on `keyexpr`, asking for them as `wire`
    /// names it, through callbacks `sink` mints; with `history`, the tokens already alive are
    /// delivered first. It is a subscriber like any other to retract
    /// ([`Self::undeclare_subscriber`]): the ids are one space. `None` from an engine with no
    /// liveliness in this build, which is the provided answer.
    fn declare_liveliness_subscriber_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        history: bool,
        sink: LivelinessSink,
    ) -> Option<SubId> {
        let _ = (keyexpr, wire, history, sink);
        None
    }

    /// Ask a query on `keyexpr` (named on the wire as `wire`) with `opts`: one leg per peer the
    /// engine reaches, and one to the session's own queryables where `opts` admits them. `leg`
    /// mints each leg's [`ReplyCallback`], whose drop is that leg's end, so a get is over when
    /// the last callback it minted is dropped. `fan`, when the get can be cancelled, is told of
    /// each leg as it is issued ([`CancellableFan::record`]), and a fan cancelled while the
    /// legs are issued stops the issuing. The number of legs issued, or `None` from an engine
    /// with no requesting end in this build, which is the provided answer.
    fn get_on_wire(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        opts: &QueryOptions,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Option<usize> {
        let _ = (keyexpr, wire, opts, fan, leg);
        None
    }

    /// Run `tick` every `period_ms` on the engine's own clock, until it answers `false` or
    /// [`Self::stop_ticker`] is called with the id returned. At least a millisecond: a shorter
    /// period is raised to it, so a job cannot make the engine spin.
    ///
    /// The first run is one period after the call, and each next one a period after the previous
    /// run ended, so a slow tick is not run again at once to catch up. A tick runs outside the
    /// engine's locks and never alongside itself. WHERE it runs is the engine's: a runtime that
    /// has tasks runs it in one; the cooperative engine runs it from the call that steps the
    /// session, so a tick is as late as the program is slow to step. `None` from an engine with
    /// no periodic jobs in this build, which is the provided answer.
    fn start_ticker(&self, period_ms: u64, tick: Tick) -> Option<TickerId> {
        let _ = (period_ms, tick);
        None
    }

    /// End the periodic job `id`. A tick already running is not interrupted, and none starts
    /// after this returns. Ending one already ended, or one never started, does nothing.
    fn stop_ticker(&self, id: TickerId) {
        let _ = id;
    }
}

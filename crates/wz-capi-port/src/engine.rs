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
//! A capability the client does not have (queries, liveliness, scouting, the connectivity and
//! admin planes, the advanced publisher) is not here yet: an ABI module that needs one still
//! names its engine, and joins this trait when a second engine implements it.

use wz_session_core::declare_form::{InterestForm, RetractionKey};
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::{PlainPutParams, PublishOptions};

use crate::{
    FanoutError, FilterId, FilterPlane, FilteredPut, MatchId, MatchingSink, SubId, SubscriberSink,
    WireKey,
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

    /// A fresh entity id, for the source info and the global id of what the C program declares.
    fn next_entity_id(&self) -> u64;

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

    /// Tell `sink` whether any peer subscribes to `keyexpr`, now and each time that changes; with
    /// `count_local`, the session's own subscribers count too.
    fn declare_matching_listener_counting_local(
        &self,
        keyexpr: String,
        sink: MatchingSink,
        count_local: bool,
    ) -> MatchId;

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
}

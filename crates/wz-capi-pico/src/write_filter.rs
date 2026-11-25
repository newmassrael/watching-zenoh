// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! zenoh-pico's WRITE FILTER, for a publisher and a querier.
//!
//! Every pico publisher and querier creates one at declare
//! (`vendor/zenoh-pico/src/net/filtering.c` @ `_z_write_filter_create`): it asks
//! the peers, through an Interest on the entity's own key, whether anything
//! there would receive what it sends, and from then on its put, delete or get
//! is SENT only while some peer has said yes. It is created in the state
//! ACTIVE, which reads as "nothing matches", so an entity with no peer yet
//! sends nothing and says `Z_OK`.
//!
//! wz's session layer asks the same question through its matching Interest
//! (`SharedSession::declare_write_filter`); this module is the pico half — WHEN
//! to ask and HOW, which are the C library's rules and not the session's:
//!
//! - A CLIENT always asks, and asks for aggregated answers.
//! - A PEER asks only while some peer of its own is a router, and without the
//!   aggregate bit; otherwise it asks nothing and learns what peers volunteer.
//!
//! (`vendor/zenoh-pico/src/net/primitives.c` @ `_z_add_interest`, and the flag
//! composition in `_z_write_filter_create`.) Both are read at DECLARE time and
//! not again, as upstream reads them.
//!
//! ⚠ TWO DIVERGENCES ARE NOT REPRODUCED, both upstream's, both wz doing less,
//! and both measured by the peer legs of `pico_keyexpr_declaration_twice_and_diff`
//! (R2968), which pin each from both sides and compare everything else whole:
//!
//! - A pico peer that asked never sends the `Interest(Final)` —
//!   `_z_remove_interest` sends it for a client (or multicast) only — so the
//!   router keeps the interest until the session closes. wz retracts it, which
//!   no program can observe and which costs the peer nothing to hold. Copying it
//!   would be copying a leak.
//! - A pico peer's filter is opened by ANY matching declaration the session
//!   already holds, of either kind: `_z_interest_replay_declare` replays them
//!   without regard to what the filter counts. A subscriber the peer declared
//!   therefore opens a querier's filter, and pico sends a Query nothing can
//!   answer. wz opens a querier's filter on queryables only, as zenoh does. The
//!   replay is kind-blind for a peer alone: a client's interest is aggregate,
//!   and an aggregate replay matches on key equality.
//!
//! What IS reproduced, and is what a peer's mode changes on the wire: whether it
//! asks at all (above), and that its subscriber and queryable retractions name
//! the key they were held on, which a client's do not
//! (`EntityKey::retraction_naming_in`).

use wz_capi_port::{
    FilterId, FilterPlane, FilteredPut, KeyView, MatchId, MatchingSink, OwnKey, Refusal, WireKey,
};
#[cfg(feature = "advanced")]
use wz_node_time::node_clock::NodeHlc;
use wz_session_core::declare_form::InterestAsk;
use wz_session_core::WhatAmI;

use crate::keyexpr::DeclaredKeyexpr;
use crate::matching::FilterListeners;
// A build of one engine calls the engine through its own type, so the port's trait is in scope.
#[cfg(not(feature = "engine-tokio"))]
use crate::prelude::*;
use crate::refusal::{refusal_code, Door};
use crate::result::{ZResult, Z_ERR_GENERIC};
use crate::session::{EngineHold, PicoSessionHandle};

/// This session's own role: pico's `zn->_mode`, kept in the handle at open
/// ([`crate::session_ext::PicoSessionExt`]) because nothing downstream of the
/// open can recover it.
pub(crate) fn session_mode(handle: &PicoSessionHandle) -> WhatAmI {
    handle.ext.mode
}

/// What an entity needs of the session it is declared on, OWNED: the key table
/// and the role.
///
/// A declaring entry point borrows the session handle out of the C handle for
/// the length of its call, and that is all it needs. A composite that declares
/// more entities later — an advanced publisher beaconing from a task, say — has
/// to keep what it declares them with, and the borrowed state cannot be kept. So
/// the two facts every declaration reads are lifted out: the registry the key
/// declarations and the entities live in, and the role the write filter and the
/// retractions follow.
///
/// The registry is the port's [`Engine`], which is all the client surface (keys,
/// publishers, subscribers, matching, write filters) and the advanced plane may
/// name (`docs/capi-pico-on-coop-engine.md`).
#[derive(Clone)]
pub(crate) struct PicoSession {
    pub(crate) engine: EngineHold,
    pub(crate) mode: WhatAmI,
    /// The session's clock — `NodeHlc::disabled()` for a session this ABI did
    /// not open, which no C entry point can hand it. Read by the advanced plane alone, whose
    /// publisher stamps with it.
    #[cfg(feature = "advanced")]
    pub(crate) hlc: NodeHlc,
    /// Every time the session gives, which the advanced plane's publisher stamps through, as a
    /// program's `z_timestamp_new` does.
    #[cfg(feature = "advanced")]
    pub(crate) time: crate::last_timestamp::SessionTime,
}

impl PicoSession {
    /// The session behind a borrowed handle, as its open made it once: a door that declares on it
    /// borrows it, and one that keeps it clones it where it keeps it.
    pub(crate) fn of(handle: &PicoSessionHandle) -> &Self {
        &handle.pico
    }

    /// The session running on `engine` whose pico-side state is `ext`: made once, by the open.
    pub(crate) fn over(engine: EngineHold, ext: &crate::session_ext::PicoSessionExt) -> Self {
        Self {
            engine,
            mode: ext.mode,
            #[cfg(feature = "advanced")]
            hlc: ext.hlc.clone(),
            #[cfg(feature = "advanced")]
            time: ext.time.clone(),
        }
    }
}

/// A publisher's or querier's write filter, and the matching listeners declared on it.
/// Dropping it retracts the listeners, then the filter, which releases the Interest it took. It
/// lies in its entity's place, and does not move while a listener is on its list.
///
/// A matching listener is the filter's: pico registers its callback on the entity's
/// filter (`vendor/zenoh-pico/src/api/api.c` @
/// `ret = _z_matching_listener_register(&_listener_id, _Z_RC_IN_VAL(&sess_rc), &querier->_filter.ctx,`),
/// so it counts what the filter counts, and goes when the filter goes. A background
/// listener, which has no handle, goes with it too.
///
/// Declared BEFORE the entity's key in the owning struct, so the Interest is
/// retracted while the declaration it names still stands — upstream's order
/// (`_z_undeclare_publisher` clears the filter, then the key).
pub(crate) struct WriteFilter {
    shared: EngineHold,
    /// What the filter counts, on which key and whether the session's own entities count are the
    /// engine's, kept with this id, and its listeners count the same.
    id: FilterId,
    /// The listeners declared on it and not undeclared yet, each linked through its own place,
    /// which the list holds: a listener goes with its entity, and zenoh-pico's entity is gone only
    /// once no callback of its listeners is running and their closures' drops have run.
    listeners: FilterListeners,
}

impl WriteFilter {
    /// Create the filter for an entity whose own key is `keyexpr`. `count_local` is pico's
    /// `ctx->allow_local`: the session's own subscribers or queryables count too, which
    /// they do for an entity whose destination admits session-local traffic in a build
    /// with the local switch (`vendor/zenoh-pico/src/net/filtering.c` @
    /// `_z_write_filter_session_register`).
    ///
    /// `wire` is the key as the entity names it on the wire (`EntityKey::wire`): its own
    /// declaration's id and the rest of the key, or the literal when nothing covers it. The
    /// entity makes it once and keeps it for what it sends. The session's record of the filter
    /// keeps the key and holds that declaration from here on.
    ///
    /// Refused with the code pico's filter answers for the cause ([`Door::WriteFilter`]): the
    /// session holds no more, its table of the entity's filters at the limit it opened under or
    /// no entity id left for the filter's Interest, or the session is closed. Nothing was sent.
    pub(crate) fn declare(
        session: &PicoSession,
        plane: FilterPlane,
        keyexpr: &str,
        wire: &WireKey,
        count_local: bool,
    ) -> Result<Self, ZResult> {
        let shared = session.engine.clone();
        let ask = interest_ask(&shared, session.mode, keyexpr, wire);
        let id = shared
            .declare_write_filter(plane, keyexpr, wire, ask, count_local)
            .map_err(|refused| refusal_code(refused, Door::WriteFilter))?;
        Ok(Self {
            shared,
            id,
            listeners: FilterListeners::default(),
        })
    }

    /// Declare a matching listener on this filter (pico `_z_matching_listener_register` on
    /// the entity's filter): `sink` is told whether what the filter counts matches, now and
    /// each time that changes. The caller puts the listener on the filter's list
    /// ([`Self::listeners`]), which retracts it with the filter.
    ///
    /// A listener the engine refuses is answered by its cause, with `sink` let go of.
    pub(crate) fn declare_matching_listener(&self, sink: MatchingSink) -> Result<MatchId, Refusal> {
        self.shared.declare_filter_matching_listener(self.id, sink)
    }

    /// The session the filter is declared in, where its listeners are declared too.
    pub(crate) fn engine(&self) -> &EngineHold {
        &self.shared
    }

    /// The listeners declared on this filter that its drop retracts.
    pub(crate) fn listeners(&self) -> &FilterListeners {
        &self.listeners
    }

    /// pico `_z_write_filter_active`: `true` when nothing has said it matches,
    /// which is when the entity must send nothing.
    pub(crate) fn active(&self) -> bool {
        self.shared.write_filter_active(self.id)
    }

    /// Whether the filter keeps a get from being sent: [`Self::active`], unless the session
    /// holds a multicast group, where pico sends whatever the filter says (the engine's
    /// `write_filter_holds_back`). A matching status still reads [`Self::active`]; a put and
    /// a delete are judged by the engine in the step that sends them ([`Self::publish`]).
    #[cfg(feature = "query")]
    pub(crate) fn holds_back(&self) -> bool {
        self.shared.write_filter_holds_back(self.id)
    }

    /// State how a write of this filter's entity that brings nothing of its own goes the plain
    /// way, once, at the entity's declare: the filter's row in the engine keeps it.
    pub(crate) fn keep_plain(
        &self,
        plain: Option<(
            wz_session_core::publish_options::PlainPutParams,
            wz_session_core::session_tables::KeyexprRef,
        )>,
    ) {
        self.shared.keep_write_filter_plain(self.id, plain);
    }

    /// A put or a delete of the entity this filter is for, unless the filter holds it back: the
    /// engine's one entry for it (`publish_filtered`). A write with no options of its own goes
    /// the plain way the row keeps ([`Self::keep_plain`]), or comes back `NotPlain`.
    pub(crate) fn publish(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: Option<&wz_session_core::publish_options::PublishOptions>,
    ) -> FilteredPut {
        self.shared
            .publish_filtered(self.id, keyexpr, wire, payload, opts)
    }
}

/// A publisher's or a querier's write filter, its key as the session's record of the filter keeps
/// it and the key as the entity names it on the wire: what both are declared with, in pico's
/// order. The record holds the declaration the key is named by and keeps the key until the filter
/// is undeclared, which retracts the filter's Interest before it lets the declaration go
/// (upstream's `_z_undeclare_publisher` clears the filter, then the key): the entity keeps no
/// copy of its key.
pub(crate) struct FilteredKey {
    pub(crate) filter: WriteFilter,
    /// The key as the record lent it ([`wz_capi_port::SessionEngine::filtered_keyexpr`]).
    key: KeyView,
    pub(crate) wire: WireKey,
    /// The `eid` half of the global id the unstable API reports for the entity.
    #[cfg(feature = "unstable-api")]
    pub(crate) eid: wz_session_core::wire_id::EntityId,
}

impl FilteredKey {
    /// Declare the key `keyexpr` (`existing` when the caller's key is that declaration already),
    /// take the entity's id, then declare its write filter on `plane`, `count_local` as
    /// [`WriteFilter::declare`] reads it. That is pico's order: `_z_declare_publisher` and
    /// `_z_declare_querier` declare the key and take the id
    /// (`vendor/zenoh-pico/src/net/primitives.c` @ `publisher->_id = _z_get_entity_id(_Z_RC_IN_VAL(zn));`)
    /// before the filter is made, whose Interest takes the next id and names the key's
    /// declaration. The id is taken whether or not the build reports it, as a group the Interest
    /// goes to reads the next. A session that has handed out every id refuses the entity with
    /// `Z_ERR_GENERIC`, the code a refused declaration gets here; a refused key or filter answers
    /// its own. One body for the publisher and the querier.
    #[cfg(any(
        feature = "query",
        all(test, not(feature = "engine-tokio"), feature = "peer")
    ))]
    pub(crate) fn declare(
        session: &PicoSession,
        plane: FilterPlane,
        keyexpr: &str,
        existing: Option<&DeclaredKeyexpr>,
        count_local: bool,
    ) -> Result<Self, ZResult> {
        let mut filtered = core::mem::MaybeUninit::<Self>::uninit();
        // SAFETY: room for one, which a refusal leaves holding none.
        unsafe {
            Self::declare_at(
                filtered.as_mut_ptr(),
                session,
                plane,
                keyexpr,
                existing,
                count_local,
            )?;
            Ok(filtered.assume_init())
        }
    }

    /// [`Self::declare`], written at `at`, where its holder keeps it, so a publisher's key and
    /// filter are not moved through the stack on their way to its place. Refused, nothing is
    /// written there.
    ///
    /// # Safety
    /// `at` is valid for the write of a `FilteredKey` and holds none.
    pub(crate) unsafe fn declare_at(
        at: *mut Self,
        session: &PicoSession,
        plane: FilterPlane,
        keyexpr: &str,
        existing: Option<&DeclaredKeyexpr>,
        count_local: bool,
    ) -> Result<(), ZResult> {
        let key = crate::keyexpr::EntityKey::whole(&session.engine, keyexpr, existing)?;
        let eid = session.engine.next_entity_id().ok_or(Z_ERR_GENERIC)?;
        #[cfg(not(feature = "unstable-api"))]
        let _ = eid;
        // The record of the filter holds the declaration: the wire form holds nothing.
        let wire = key.wire();
        let filter = WriteFilter::declare(session, plane, keyexpr, &wire, count_local)?;
        // The door's hold goes with `key`, the record's standing; the key is lent from the record,
        // and an engine that keeps none refuses the entity, its filter undeclared.
        drop(key);
        let lent = session
            .engine
            .filtered_keyexpr(filter.id)
            .ok_or(Z_ERR_GENERIC)?;
        // SAFETY: the caller's: `at` is room for one, written field by field, once each.
        unsafe {
            core::ptr::addr_of_mut!((*at).filter).write(filter);
            core::ptr::addr_of_mut!((*at).key).write(lent);
            core::ptr::addr_of_mut!((*at).wire).write(wire);
            #[cfg(feature = "unstable-api")]
            core::ptr::addr_of_mut!((*at).eid).write(eid);
        }
        Ok(())
    }
}

impl FilteredKey {
    /// The entity's key, where the session's record of its filter keeps it.
    pub(crate) fn keyexpr(&self) -> &str {
        // SAFETY: the record keeps the text, which was a `str` there, at one address until the
        // filter is undeclared, which is when `self.filter` goes, and `self` with it.
        unsafe {
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(
                self.key.start,
                self.key.len,
            ))
        }
    }

    /// The session the entity is on and the declaration its key is lent with: what a key made of
    /// its loan holds, and names on the wire.
    pub(crate) fn record_key(&self) -> (&EngineHold, Option<OwnKey>) {
        (self.filter.engine(), self.key.own)
    }

    /// The loan of the entity's key: the record's text and declaration, named from `self`, which
    /// must stay at its address while the loan is read ([`crate::keyexpr::record_loan`]).
    pub(crate) fn loan(&self) -> crate::abi::z_loaned_keyexpr_t {
        crate::keyexpr::record_loan(self.key, self)
    }

    /// The key as a message sent once names it: the record's declaration and the rest of the key.
    #[cfg(feature = "query")]
    pub(crate) fn wire_once(&self) -> WireKey {
        let shared = self.filter.engine();
        crate::keyexpr::record_wire(
            shared,
            self.key.own,
            self.key.len,
            EngineHold::as_ref(shared),
        )
    }
}

/// Retracting on DROP reaches every path that releases the entity: `z_undeclare_*` and
/// `z_*_drop` alike. A listener its handle undeclared is off the list already. The drop returns
/// once every listener's closure has run its `drop(context)`: a callback still running on
/// another thread is waited for, as zenoh-pico's undeclare waits for it.
impl Drop for WriteFilter {
    fn drop(&mut self) {
        self.listeners
            .retract_all(crate::session::EngineHold::as_ref(&self.shared));
        self.shared.undeclare_write_filter(self.id);
    }
}

/// How the entity's Interest is put, or `None` for none — pico's rules, see the
/// module doc. The key is lent from the entity's key and wire form.
fn interest_ask<'a>(
    shared: &EngineHold,
    mode: WhatAmI,
    keyexpr: &'a str,
    wire: &'a WireKey,
) -> Option<InterestAsk<'a>> {
    let client = mode == WhatAmI::Client;
    if !client && !shared.has_router_peer() {
        return None;
    }
    let (mapping_id, suffix) = wire.names_in(keyexpr);
    Some(InterestAsk {
        mapping_id,
        suffix,
        aggregate: client,
    })
}

#[cfg(all(test, not(feature = "engine-tokio"), feature = "peer"))]
mod tests {
    use super::*;
    use crate::session::{
        engine_held, listening_on_loopback, session_handle, z_session_drop, z_session_loan,
        z_session_move,
    };

    /// A door that declares on a session borrows the one view its open made: the same each time,
    /// over the engine the session's entities keep and in the session's role. Turned red by a view
    /// made per call, or over another engine.
    #[test]
    fn a_door_borrows_the_view_its_session_was_opened_with() {
        let mut session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let handle = unsafe { session_handle(z_session_loan(&session)) }
            .expect("an open session has its handle");
        assert!(
            core::ptr::eq(PicoSession::of(handle), PicoSession::of(handle)),
            "one view, lent each time"
        );
        let kept = engine_held(handle).clone();
        assert!(
            crate::session::EngineHold::ptr_eq(&PicoSession::of(handle).engine, &kept),
            "over the session's engine"
        );
        assert!(PicoSession::of(handle).mode == session_mode(handle));
        drop(kept);
        // SAFETY: the session is live and owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }

    /// An entity's key is declared and named on the wire by its own declaration, its id comes off
    /// the session's counter, and the filter it gets holds back what it sends while nothing on a
    /// session with no peer matches.
    #[test]
    fn a_filtered_key_names_its_declaration_and_starts_held_back() {
        let mut session = listening_on_loopback();
        // SAFETY: the session is live and owned by this frame.
        let handle = unsafe { session_handle(z_session_loan(&session)) }
            .expect("an open session has its handle");
        let pico = PicoSession::of(handle);
        let filtered =
            FilteredKey::declare(pico, FilterPlane::Subscribers, "demo/filtered", None, false)
                .unwrap_or_else(|code| panic!("a session with room declares the key, not {code}"));
        assert_eq!(filtered.keyexpr(), "demo/filtered");
        let (id, rest) = filtered.wire.names_in(filtered.keyexpr());
        assert_ne!(id, 0, "the wire names the key's own declaration");
        assert_eq!(rest, None, "the declaration names the whole key");
        assert!(
            filtered.filter.active(),
            "nothing matches on a session with no peer"
        );
        #[cfg(feature = "unstable-api")]
        {
            let next = wz_capi_port::SessionEngine::next_entity_id(&*pico.engine)
                .expect("the session has ids left");
            assert!(next > filtered.eid, "the entity's id was taken first");
        }
        drop(filtered);
        // SAFETY: the session is live and owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }
}

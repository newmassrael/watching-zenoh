// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's write filters and matching listeners on the cooperative engine. A write filter
//! is a row of the session's tables that holds the Interest its key is asked by; a matching
//! listener is a row owned by its publisher's or querier's filter, whose kind, key and count of
//! the session's own entities it reads (`docs/c-abi-l3-tables.md`, section 3). The engine keeps
//! beside a filter only what the tables do not read ([`FilterRecord`]), and beside a listener
//! only its callback ([`ListenerRow`]).

use core::cell::Cell;
use core::num::NonZeroU32;
use core::ptr::NonNull;

use wz_capi_port::{FilterId, FilterPlane, MatchId, MatchingSink};
use wz_runtime_coop::ClockSource;
use wz_session_core::interest_build::InterestKinds;
use wz_session_core::publish_options::PlainPutParams;
use wz_session_core::row_callback::{CallLatch, RowCallback};
use wz_session_core::session_tables::{
    InterestKind, MatchingListenerHandle, Plane, WireForm, WriteFilterHandle,
};
use wz_session_core::wire_id::{EntityId, ExprId};
use wz_session_mcu::dial::McuActions;

/// What the engine keeps of a write filter beside what the tables read of it.
pub(crate) struct FilterRecord {
    /// How a write of the filter's entity that brings nothing of its own goes the plain way: the
    /// facts it is sent from and the declaration that names its key, stated once by the entity
    /// that declared the filter (`keep_write_filter_plain`). `None` sends it the general way.
    plain: Cell<Option<(PlainPutParams, ExprId)>>,
}

impl FilterRecord {
    /// A filter whose writes go the general way until its entity says otherwise.
    pub(super) fn new() -> Self {
        Self {
            plain: Cell::new(None),
        }
    }

    /// How a write that brings nothing of its own goes the plain way, when its entity said.
    pub(super) fn plain(&self) -> Option<(PlainPutParams, ExprId)> {
        self.plain.get()
    }

    /// State how a write that brings nothing of its own goes the plain way.
    pub(super) fn keep_plain(&self, plain: Option<(PlainPutParams, ExprId)>) {
        self.plain.set(plain);
    }
}

/// The plane of the session's tables a filter of the port's `plane` counts.
pub(super) fn plane_of(plane: FilterPlane) -> Plane {
    match plane {
        FilterPlane::Subscribers => Plane::Subscribers,
        FilterPlane::Queryables { complete_required } => Plane::Queryables { complete_required },
    }
}

/// The port's plane of a filter that counts the tables' `plane`.
pub(super) fn filter_plane(plane: Plane) -> FilterPlane {
    match plane {
        Plane::Subscribers => FilterPlane::Subscribers,
        Plane::Queryables { complete_required } => FilterPlane::Queryables { complete_required },
    }
}

/// Whether the session's own entities of `plane`'s kind count for a filter that asked them to:
/// only in a build that delivers to them locally, as zenoh-pico's default build
/// (`Z_FEATURE_LOCAL_SUBSCRIBER` and `Z_FEATURE_LOCAL_QUERYABLE` 0) counts none.
pub(super) fn counts_local(plane: FilterPlane, count_local: bool) -> bool {
    let delivers_locally = match plane {
        FilterPlane::Subscribers => cfg!(feature = "local-subscriber"),
        FilterPlane::Queryables { .. } => cfg!(feature = "local-queryable"),
    };
    delivers_locally && count_local
}

/// The id the port names the filter `handle` by.
pub(super) fn filter_id(handle: WriteFilterHandle) -> FilterId {
    u64::from(handle.to_bits().get())
}

/// The filter the port's `id` names, when it names one the tables could hold.
pub(super) fn filter_handle(id: FilterId) -> Option<WriteFilterHandle> {
    let bits = NonZeroU32::new(u32::try_from(id).ok()?)?;
    WriteFilterHandle::from_bits(bits)
}

/// The id the port names the listener `handle` by.
pub(super) fn match_id(handle: MatchingListenerHandle) -> MatchId {
    u64::from(handle.to_bits().get())
}

/// The listener the port's `id` names, when it names one the tables could hold.
pub(super) fn match_handle(id: MatchId) -> Option<MatchingListenerHandle> {
    let bits = NonZeroU32::new(u32::try_from(id).ok()?)?;
    MatchingListenerHandle::from_bits(bits)
}

/// What an Interest of `kind` asks the peer to tell.
fn kinds(kind: InterestKind) -> InterestKinds {
    match kind {
        InterestKind::Subscribers => InterestKinds::SUBSCRIBERS,
        InterestKind::Queryables => InterestKinds::QUERYABLES,
    }
}

/// Send Interest `id` of `kind` about `keyexpr` over `actions`, for what is declared now and
/// what is declared later: its key named as `wire`, the form its row keeps, or as the link's
/// key-wire form says where that departs from the declared form (`shared-key-ids`); whether the
/// link took it.
pub(super) fn send_interest<C: ClockSource + 'static>(
    actions: &McuActions<C>,
    id: EntityId,
    kind: InterestKind,
    keyexpr: &str,
    wire: WireForm<'_>,
    aggregate: bool,
) -> bool {
    // The literal names the whole key; a declaration names what follows it, nothing when it
    // covers the key.
    let declared = (
        wire.mapping,
        (wire.mapping == 0 || !wire.suffix.is_empty()).then_some(wire.suffix),
    );
    let (mapping, suffix) = on_link(actions, keyexpr).unwrap_or(declared);
    actions
        .send_interest_kinds(
            u64::from(id),
            kinds(kind),
            /* current */ true,
            /* future */ true,
            aggregate,
            mapping,
            suffix,
        )
        .is_ok()
}

/// `keyexpr` as the link of `actions` names it where its key-wire form departs from the declared
/// form: the literal, or an id of the dictionary every node shares and the rest of the key.
#[cfg(feature = "shared-key-ids")]
fn on_link<'k, C: ClockSource + 'static>(
    actions: &McuActions<C>,
    keyexpr: &'k str,
) -> Option<(ExprId, Option<&'k str>)> {
    use wz_session_core::shared_key_ids::KeyWire;
    match actions.key_wire_on_link(keyexpr) {
        KeyWire::Declared => None,
        KeyWire::Literal => Some((0, Some(keyexpr))),
        KeyWire::Shared { id, suffix } => Some((id, suffix)),
    }
}

/// A build without the shared key ids names every key as the session's tables name it.
#[cfg(not(feature = "shared-key-ids"))]
#[inline(always)]
fn on_link<'k, C: ClockSource + 'static>(
    _actions: &McuActions<C>,
    _keyexpr: &'k str,
) -> Option<(ExprId, Option<&'k str>)> {
    None
}

/// A matching listener's callback, as a row of the session's tables holds it: called where the
/// row lies, after the session's lock, with the latch of its calls, so an undeclared listener is
/// let go of once its last call ended (`docs/c-abi-architecture.md`, P11).
pub(crate) struct ListenerRow {
    sink: MatchingSink,
    latch: CallLatch,
}

impl ListenerRow {
    /// A listener handing each change of its status to `sink`.
    pub(super) fn new(sink: MatchingSink) -> Self {
        Self {
            sink,
            latch: CallLatch::new(),
        }
    }
}

/// A call of a listener's callback, begun on its row's latch: where the row lies.
pub(crate) struct ListenerRowCall(NonNull<ListenerRow>);

impl RowCallback for ListenerRow {
    type Call = ListenerRowCall;

    const READS_ROW_IN_PLACE: bool = true;

    fn begin(&self) -> Option<ListenerRowCall> {
        self.latch
            .begin()
            .then(|| ListenerRowCall(NonNull::from(self)))
    }

    unsafe fn end(call: ListenerRowCall) -> bool {
        // SAFETY: the caller's: the row has not moved since the call began and is still in its
        // table, which keeps it until its last call ended.
        unsafe { call.0.as_ref() }.latch.end()
    }

    fn retire(&self) -> bool {
        self.latch.retire()
    }
}

/// A call of a listener's callback the session began under its lock and makes after it, and the
/// handle its row is let go of by when it ends the last call of an undeclared listener. Each is
/// ended once ([`Self::end`]), or its row would keep its slot for good.
#[must_use = "a call is ended, or its row is never let go of"]
pub(super) struct ListenerCall {
    call: ListenerRowCall,
    handle: MatchingListenerHandle,
}

impl ListenerCall {
    /// `call`, begun on the row `handle` names.
    pub(super) fn new(call: ListenerRowCall, handle: MatchingListenerHandle) -> Self {
        Self { call, handle }
    }

    /// Hand `matching` to the row's callback, unless the listener was undeclared since the call
    /// was begun.
    pub(super) fn hand(&self, matching: bool) {
        // SAFETY: the row lies where the call began until its last call ended, and this one has
        // not; nothing writes a row's sink after it is declared.
        let row = unsafe { self.call.0.as_ref() };
        if !row.latch.retired() {
            (row.sink)(matching);
        }
    }

    /// End the call: the handle of its row when it was the last call of an undeclared listener,
    /// which the caller lets go of (`SessionTables::release_matching_listener`).
    pub(super) fn end(self) -> Option<MatchingListenerHandle> {
        // SAFETY: the row lies where the call began (the tables never move a row) and keeps its
        // slot until its last call ended, which this one is not yet; a call ends with no lock held.
        let last = unsafe { <ListenerRow as RowCallback>::end(self.call) };
        last.then_some(self.handle)
    }
}

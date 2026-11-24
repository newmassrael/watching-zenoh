// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The declaration watch: what the peers of the session's links declare and retract, told to the
//! program ([`wz_capi_port::decl_watch`]).
//!
//! The application layer's observers of what a peer declares are installed once for each kind of
//! entity some watch is of. While a link's frame is dispatched, under the session's lock, they hold
//! each event in the session's round of deliveries as a record of its own, with a call of each
//! watch it reaches, named as the events of the link's peer ([`DeclWatches::hear_link`]); a
//! group's dispatch names no link, and its events are held for no one, as the port says. The key
//! of a declaration lies where the round reads it, in the block of the session's key arena the
//! declaration's row keeps, of which the record holds a count. The round hands the event to the
//! watch's sink with every other record, in order, outside the lock (decision D8).
//!
//! A watch's row lies in a table fixed when the session opens, a row for each watch its
//! `MAX_DECL_WATCHES` admits, its sink in a cell the calls the round owes hold a count of, so the
//! row is not taken by another watch while a call of the last one is owed. An event the round has
//! no room for is counted for each watch it would reach and told as the loss of that many ahead of
//! the watch's next event ([`DeclWatchEvent::Lost`]). A watch is told what the peers hold when it
//! is declared, as records of the same round: at once when the round takes them all, or else as
//! soon as a delivery has emptied it ([`DeclWatches::owes`]), so a watch declared from inside a
//! callback, while the round is handed out, is told them by the next round. Until then it is told
//! no live event, which its catch-up, read off the peers' tables as they stand then, holds. A round
//! of one thread holds the records of one message, so it is told its catch-up a declaration a
//! round, the links read no further until it is whole.

use alloc::sync::Arc;

#[allow(unused_imports)]
use crate::prelude::*;

use wz_capi_port::os::Mutex;
use wz_capi_port::Refusal as Declined;
use wz_capi_port::{DeclPlane, DeclWatchEvent, DeclWatchId, DeclWatchSink};
use wz_session_core::bounded::{LendRefused, Storage};
use wz_session_core::caps;
use wz_session_core::decl_sink::{BoxedDeclSink, DeclSink, DeclView, UndeclSink};
use wz_session_core::declare::MatchingReport;
use wz_session_core::key_arena::KeyRef;
use wz_session_core::limit_binding::Quota;
use wz_session_core::limits::SessionLimits;
use wz_session_core::round::{DeclEvent, DeclEventKind, Owing};
use wz_session_core::row_callback::ThreadForm;
use wz_session_core::session_zid::SessionZid;
use wz_session_core::slot_observer::{ObserverSinks, SlotObserverOf};

use super::lock;
use super::registry::FaceTables;
use crate::round::{CoopForm, Round};

/// Whether a watch is told its catch-up in parts: a round of one thread is handed out after each
/// message and holds the records of one alone, so it takes a catch-up a declaration a round.
const IN_PARTS: bool = !<CoopForm as ThreadForm>::OTHER_THREADS;

/// Whether this build hears what a peer declares of `plane`: subscribers in every build, whose
/// declarations the engine reads for its publishers' write filters, queryables with a querier or a
/// queryable (`query`, `queryable`), which read a peer's queryable declarations, and tokens with
/// the liveliness plane, which reads a peer's token declarations. A watch of a plane the build does
/// not hear is refused by name: the build holds no table of that plane to tell it from.
pub(super) const fn hears(plane: DeclPlane) -> bool {
    match plane {
        DeclPlane::Subscribers => true,
        DeclPlane::Queryables => cfg!(any(feature = "query", feature = "queryable")),
        DeclPlane::Tokens => cfg!(feature = "liveliness"),
    }
}

/// Whether a watch of `watched` is told `kind` of `plane`: a declaration or a retraction of its
/// own kind, and the end of a peer's initial declarations whatever its kind.
fn reaches(kind: DeclEventKind, plane: DeclPlane, watched: DeclPlane) -> bool {
    match kind {
        DeclEventKind::Declared | DeclEventKind::Undeclared => plane == watched,
        DeclEventKind::Synced => true,
        DeclEventKind::Lost => false,
    }
}

/// The event in the port's words, borrowed for the sink's call.
fn port_event(event: DeclEvent<'_>) -> DeclWatchEvent<'_> {
    match event.kind {
        DeclEventKind::Declared => DeclWatchEvent::Declared {
            id: event.id,
            keyexpr: event.keyexpr,
            peer: event.peer,
        },
        DeclEventKind::Undeclared => DeclWatchEvent::Undeclared {
            id: event.id,
            peer: event.peer,
        },
        DeclEventKind::Synced => DeclWatchEvent::Synced { peer: event.peer },
        DeclEventKind::Lost => DeclWatchEvent::Lost { count: event.id },
    }
}

/// The loss of `count` events, which names no declaration and no peer.
fn lost(count: u64) -> DeclEvent<'static> {
    DeclEvent {
        kind: DeclEventKind::Lost,
        id: count,
        keyexpr: "",
        peer: None,
    }
}

/// The peer an event is told as: the zid the link's handshake gave, in a build with
/// `remote-declaration-watch`, and no one without it, whose events name no peer.
pub(super) fn named(peer: impl FnOnce() -> Option<SessionZid>) -> Option<SessionZid> {
    #[cfg(feature = "remote-declaration-watch")]
    {
        peer()
    }
    #[cfg(not(feature = "remote-declaration-watch"))]
    {
        let _ = peer;
        None
    }
}

/// The sink of a watch as its row keeps it: out of the cell while a call of it runs, and gone once
/// the watch is undeclared or the session closed.
#[derive(Default)]
struct Slot {
    sink: Option<DeclWatchSink>,
    gone: bool,
}

/// Where a watch's sink lies for the calls the round owes it, each of which holds a count of the
/// cell: one cell for each row, made when the session opens, so a call allocates nothing.
struct Cell {
    slot: Mutex<Slot>,
}

impl Cell {
    /// The cell of a row that holds no watch.
    fn empty() -> Arc<Self> {
        Arc::new(Self {
            slot: Mutex::new(Slot::default()),
        })
    }
}

/// A call of a watch's sink a record of the round owes ([`wz_session_core::round::WatchCall`]): a
/// count of the cell of the watch's row, which keeps the row from another watch until the call
/// ends. Made under the session's lock as an event reaches the watch, made with no lock held.
#[must_use = "a call is ended, or its row is never let go of"]
pub(crate) struct WatchCall {
    cell: Arc<Cell>,
}

impl WatchCall {
    /// A call of the watch whose sink lies in `cell`.
    fn begun(cell: &Arc<Cell>) -> Self {
        Self {
            cell: Arc::clone(cell),
        }
    }

    /// Whether `other` is a call of the same watch.
    pub(crate) fn same_row(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.cell, &other.cell)
    }

    /// Hand `event` to the watch's sink, taken out of its cell for the call and put back after
    /// it, or let go of here when the watch went during the call (an undeclare from inside it, or
    /// the session's close). A watch undeclared before is handed nothing. No lock is held while
    /// the sink runs, so it may reach back into the session.
    pub(crate) fn hand(&self, event: DeclEvent<'_>) {
        let taken = {
            let mut slot = lock(&self.cell.slot);
            if slot.gone {
                None
            } else {
                slot.sink.take()
            }
        };
        let Some(sink) = taken else {
            return;
        };
        sink.call(port_event(event));
        let gone = {
            let mut slot = lock(&self.cell.slot);
            if slot.gone {
                Some(sink)
            } else {
                slot.sink = Some(sink);
                None
            }
        };
        drop(gone);
    }

    /// End the call: the count of the cell goes with it. No row of the session's tables waits on
    /// it, so the session's walk of them is never owed one (`false`).
    pub(crate) fn end(self) -> bool {
        drop(self.cell);
        false
    }
}

/// One watch: the kind of entity it is of, what it lost, and whether it is still owed what the
/// peers held when it was declared.
struct Watch {
    id: DeclWatchId,
    plane: DeclPlane,
    /// The events the round had no room for since the watch was last told, told ahead of its next.
    lost: u64,
    /// Owed what the peers hold, told before any live event, which it is not told meanwhile.
    catching_up: bool,
    /// How many of the declarations its catch-up reads off the peers' tables, in the order they
    /// hand them, it was already told: what a catch-up told in parts goes on from.
    told: usize,
}

/// A row of the table: the watch it holds, if any, and the cell its sink lies in.
struct Row {
    watch: Option<Watch>,
    cell: Arc<Cell>,
}

impl Row {
    /// Whether a new watch may take the row: it holds none, and no call of the last one is owed,
    /// whose count of the cell would be the only other. Counts are taken under the table's lock
    /// alone, so one read as none stays none.
    fn is_free(&self) -> bool {
        self.watch.is_none() && Arc::strong_count(&self.cell) == 1
    }
}

/// The observers installed in the application layer for one kind of entity, by the ids that
/// remove them again.
struct Observers {
    plane: DeclPlane,
    declared: u64,
    undeclared: u64,
}

/// The observers installed for each kind of entity a watch may be of, one pair a kind.
#[derive(Default)]
struct PlaneObservers {
    subscribers: Option<Observers>,
    queryables: Option<Observers>,
    tokens: Option<Observers>,
}

impl PlaneObservers {
    /// The pair of `plane`, when installed.
    fn of(&mut self, plane: DeclPlane) -> &mut Option<Observers> {
        match plane {
            DeclPlane::Subscribers => &mut self.subscribers,
            DeclPlane::Queryables => &mut self.queryables,
            DeclPlane::Tokens => &mut self.tokens,
        }
    }

    /// Whether no kind has its pair installed.
    #[cfg(all(test, not(any(feature = "query", feature = "queryable"))))]
    fn is_empty(&self) -> bool {
        self.subscribers.is_none() && self.queryables.is_none() && self.tokens.is_none()
    }
}

/// The link whose frame is dispatched now, which the events its observers are told come from.
#[derive(Clone, Copy)]
struct Hearing {
    peer: Option<SessionZid>,
}

/// The watches and the observers they are told through.
struct Table {
    /// A row for each watch the build holds at most, of which the session's limit admits the
    /// first `most`.
    rows: [Row; caps::MAX_DECL_WATCHES],
    most: usize,
    observers: PlaneObservers,
    next_id: DeclWatchId,
    /// The link being dispatched, while one is; none while a group's frame is.
    hearing: Option<Hearing>,
}

impl Table {
    /// A table of no watch, `most` of whose rows hold one (all of them when `most` is more).
    fn holding(most: usize) -> Self {
        Self {
            rows: core::array::from_fn(|_| Row {
                watch: None,
                cell: Cell::empty(),
            }),
            most: most.min(caps::MAX_DECL_WATCHES),
            observers: PlaneObservers::default(),
            next_id: 0,
            hearing: None,
        }
    }

    /// The watches the table holds.
    fn watches(&self) -> impl Iterator<Item = &Watch> + '_ {
        self.rows.iter().filter_map(|row| row.watch.as_ref())
    }
}

/// What the observers and the engine reach: the table, and the round the events are held in.
struct Shared {
    table: Mutex<Table>,
    round: Arc<Round>,
}

/// The session's declaration watches. The registry holds it, so a link's dispatch reaches it, and
/// the engine holds it, so its deliveries do: a clone is the same watches.
#[derive(Clone)]
pub(super) struct DeclWatches {
    shared: Arc<Shared>,
}

/// How many rows the session's value of a limit admits under the build's `ceiling`. A limit past
/// the build's is refused, as the open that lays the ABI's places out refuses it.
fn rows_under(value: Quota, ceiling: usize) -> Result<usize, LendRefused> {
    value
        .lent_under(Quota::at_most(ceiling))
        .map_err(|_| LendRefused::OverCeiling {
            rows: value.most().unwrap_or(usize::MAX),
            ceiling,
        })
}

/// What the peer of `tables` holds of `plane` now, each declaration handed to `each` with its id,
/// its key and the block of the session's key arena its row keeps the key in. Tokens hold none, as
/// the port says.
fn held_of(
    plane: DeclPlane,
    tables: &FaceTables,
    mut each: impl FnMut(u64, &str, Option<&KeyRef>),
) {
    match plane {
        DeclPlane::Subscribers => {
            for (declared, keyexpr, held) in tables.peer.remote_subscribers.iter_declared_held() {
                each(declared, keyexpr, held);
            }
        }
        #[cfg(any(feature = "query", feature = "queryable"))]
        DeclPlane::Queryables => {
            for (declared, keyexpr, held) in tables.peer.remote_queryables.iter_declared_held() {
                each(declared, keyexpr, held);
            }
        }
        // Refused before it is told anything ([`hears`]).
        #[cfg(not(any(feature = "query", feature = "queryable")))]
        DeclPlane::Queryables => {}
        DeclPlane::Tokens => {}
    }
}

/// How many declarations of `plane` the peer of `tables` holds now.
fn held(plane: DeclPlane, tables: &FaceTables) -> usize {
    let mut count: usize = 0;
    held_of(plane, tables, |_, _, _| count = count.saturating_add(1));
    count
}

/// Tell `watch`, whose sink lies in `cell`, the events it lost, as a record of `round` of its own.
/// Still owed when the round has no room for it.
///
/// # Safety
/// The caller holds the session's lock.
unsafe fn tell_lost(round: &Round, watch: &mut Watch, cell: &Arc<Cell>) {
    if watch.lost == 0 {
        return;
    }
    // SAFETY: the caller's contract.
    if unsafe { round.offer_decl_watch(WatchCall::begun(cell), lost(watch.lost), None) } {
        watch.lost = 0;
    }
}

/// Hold in `round`, for `watch` whose sink lies in `cell`, the declarations of its kind the peers
/// of `faces` hold now past the ones it was told, `most` of them at most, each named as its face's
/// peer: whether none is left. One the round takes no record of is counted as lost.
///
/// # Safety
/// The caller holds the session's lock.
unsafe fn tell_held<'f, I>(
    round: &Round,
    watch: &mut Watch,
    cell: &Arc<Cell>,
    faces: &impl Fn() -> I,
    most: usize,
) -> bool
where
    I: Iterator<Item = (&'f FaceTables, Option<SessionZid>)>,
{
    let from = watch.told;
    let mut at: usize = 0;
    for (tables, peer) in faces() {
        held_of(watch.plane, tables, |id, keyexpr, held| {
            let this = at;
            at = at.saturating_add(1);
            if this < from || this.saturating_sub(from) >= most {
                return;
            }
            let event = DeclEvent {
                kind: DeclEventKind::Declared,
                id,
                keyexpr,
                peer: peer.as_deref(),
            };
            // SAFETY: the caller's contract.
            if !unsafe { round.offer_decl_watch(WatchCall::begun(cell), event, held) } {
                watch.lost = watch.lost.saturating_add(1);
            }
            watch.told = watch.told.saturating_add(1);
        });
    }
    watch.told >= at
}

/// Tell `round` whether a watch of `table` is still owed its catch-up, in a round that takes it in
/// parts ([`IN_PARTS`]): while one is, no link is read, so nothing a link brings overtakes it.
fn owe_catch_up(round: &Round, table: &Table) {
    if IN_PARTS {
        round.owe(
            Owing::CatchUp,
            table.watches().any(|watch| watch.catching_up),
        );
    }
}

/// Hold `event` of `plane`, whose key lies in `held` when its row keeps it in the session's key
/// arena, in `round` for every watch of `table` it reaches, each told its losses first: one record
/// the watches join one after the other. A watch still owed its catch-up is told none of it.
///
/// # Safety
/// The caller holds the session's lock.
unsafe fn offer(
    round: &Round,
    table: &mut Table,
    event: DeclEvent<'_>,
    plane: DeclPlane,
    held: Option<&KeyRef>,
) {
    let reached = |watch: &Watch| !watch.catching_up && reaches(event.kind, plane, watch.plane);
    for Row { watch, cell } in &mut table.rows {
        if let Some(watch) = watch.as_mut().filter(|watch| reached(watch)) {
            // SAFETY: the caller's contract.
            unsafe { tell_lost(round, watch, cell) };
        }
    }
    for Row { watch, cell } in &mut table.rows {
        if let Some(watch) = watch.as_mut().filter(|watch| reached(watch)) {
            // SAFETY: the caller's contract.
            if !unsafe { round.offer_decl_watch(WatchCall::begun(cell), event, held) } {
                watch.lost = watch.lost.saturating_add(1);
            }
        }
    }
}

/// Hold `kind` of `plane`, the declaration `id` on `keyexpr`, for the watches it reaches, as an
/// event of the link being dispatched; a group's is held for no one.
///
/// # Safety
/// The caller holds the session's lock: the observers are told as a frame is dispatched.
unsafe fn heard(
    shared: &Shared,
    kind: DeclEventKind,
    plane: DeclPlane,
    id: u64,
    keyexpr: &str,
    held: Option<&KeyRef>,
) {
    let mut table = lock(&shared.table);
    let Some(Hearing { peer }) = table.hearing else {
        return;
    };
    let event = DeclEvent {
        kind,
        id,
        keyexpr,
        peer: peer.as_deref(),
    };
    // SAFETY: the caller's contract.
    unsafe { offer(&shared.round, &mut table, event, plane, held) };
}

impl DeclWatches {
    /// No watch, and room for as many watches as the session's `MAX_DECL_WATCHES` admits under the
    /// build's, their events held in `round`, the session's round of deliveries.
    pub(super) fn under(limits: &SessionLimits, round: &Arc<Round>) -> Result<Self, LendRefused> {
        let watches = rows_under(limits.max_decl_watches(), caps::MAX_DECL_WATCHES)?;
        Ok(Self::holding(watches, round))
    }

    /// No watch, and room for `watches` of them, at most the build's, their events held in `round`.
    fn holding(watches: usize, round: &Arc<Round>) -> Self {
        Self {
            shared: Arc::new(Shared {
                table: Mutex::new(Table::holding(watches)),
                round: Arc::clone(round),
            }),
        }
    }

    /// A watch of `plane` told through `sink` from now on, owed first what the peers hold now
    /// ([`Self::tell_owed`]): its id. The observers of `plane` are installed in `app` with the
    /// first watch of that kind. Refused, with `sink` handed back for the caller to let go of with
    /// no lock held, by [`Declined::TableFull`] when the session holds as many watches as its limit
    /// admits (a row a call of an undeclared watch is still owed on counts as held) or the
    /// application layer's list of observers is at its bound, by [`Declined::NotBuilt`] for a kind
    /// the build does not hear, and by [`Declined::NoEntityId`] once every id was handed out;
    /// nothing is installed then.
    ///
    /// Whatever storage `P` the application's tables have: the session's registry holds them in
    /// rows its arena lent, while the lists of observers are the build's profile's in every
    /// observer. Whatever binding `K` they have, too, as long as its observers are the watches'
    /// own ([`WatchObserver`]).
    pub(super) fn add<
        K: ObserverSinks<Declared = WatchObserver, Undeclared = WatchObserver>,
        P: Storage,
        M: MatchingReport,
    >(
        &self,
        app: &mut SlotObserverOf<K, P, M>,
        plane: DeclPlane,
        sink: DeclWatchSink,
    ) -> Result<DeclWatchId, (Declined, DeclWatchSink)> {
        let mut table = lock(&self.shared.table);
        let Table {
            rows,
            most,
            observers,
            next_id,
            ..
        } = &mut *table;
        let Some(free) = rows.iter_mut().take(*most).find(|row| row.is_free()) else {
            return Err((Declined::TableFull, sink));
        };
        let Some(id) = next_id.checked_add(1) else {
            return Err((Declined::NoEntityId, sink));
        };
        let observers = observers.of(plane);
        if observers.is_none() {
            match install(app, plane, &self.shared) {
                Ok(installed) => *observers = Some(installed),
                Err(refused) => return Err((refused, sink)),
            }
        }
        *next_id = id;
        *lock(&free.cell.slot) = Slot {
            sink: Some(sink),
            gone: false,
        };
        free.watch = Some(Watch {
            id,
            plane,
            lost: 0,
            catching_up: true,
            told: 0,
        });
        Ok(id)
    }

    /// Whether a watch is owed what the round had no room for when it came: its catch-up, or the
    /// events it lost. What a delivery asks once it has emptied the round ([`Self::tell_owed`]).
    pub(super) fn owes(&self) -> bool {
        lock(&self.shared.table)
            .watches()
            .any(|watch| watch.catching_up || watch.lost != 0)
    }

    /// Hold in the round what the watches are owed and it now has room for: to each watch still
    /// owed its catch-up, the declarations of its kind the peers of `faces` hold now, each named as
    /// its face's peer, ahead of any live event, and to each watch the events it lost. A round of
    /// threads takes a catch-up all at once: one it has not the room for waits for a round that
    /// has, and one larger than a whole round is told as the loss of that many declarations. A round
    /// of one thread holds the records of one message ([`IN_PARTS`]), so it takes a catch-up a
    /// declaration a round, in the order the peers' tables hand them, and the links are read no
    /// further until every catch-up is told ([`Owing::CatchUp`]). `faces` is read twice, once
    /// to count and once to hold.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    pub(super) unsafe fn tell_owed<'f, I>(&self, faces: impl Fn() -> I)
    where
        I: Iterator<Item = (&'f FaceTables, Option<SessionZid>)>,
    {
        let round = &self.shared.round;
        let mut table = lock(&self.shared.table);
        // A round of one thread takes one declaration of one catch-up a round, each part a record.
        let mut part_left = IN_PARTS;
        for Row { watch, cell } in &mut table.rows {
            let Some(watch) = watch.as_mut() else {
                continue;
            };
            if watch.catching_up {
                let count = faces()
                    .map(|(tables, _)| held(watch.plane, tables))
                    .fold(0usize, usize::saturating_add);
                let left = count.saturating_sub(watch.told);
                let records = left.saturating_add(usize::from(watch.lost != 0));
                // SAFETY: the caller's contract.
                if unsafe { round.has_room_for(records, records) } {
                    watch.catching_up = false;
                    // SAFETY: the caller's contract.
                    unsafe { tell_lost(round, watch, cell) };
                    // SAFETY: the caller's contract.
                    unsafe { tell_held(round, watch, cell, &faces, usize::MAX) };
                    watch.told = 0;
                    continue;
                }
                if IN_PARTS {
                    // SAFETY: the caller's contract.
                    if part_left && unsafe { round.has_room_for(1, 1) } {
                        part_left = false;
                        // SAFETY: the caller's contract.
                        if unsafe { tell_held(round, watch, cell, &faces, 1) } {
                            watch.catching_up = false;
                            watch.told = 0;
                        }
                    }
                    continue;
                }
                if !round.is_idle() {
                    continue;
                }
                // An empty round with no room for it never has room for it.
                watch.catching_up = false;
                watch.lost = watch
                    .lost
                    .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            }
            // SAFETY: the caller's contract.
            unsafe { tell_lost(round, watch, cell) };
        }
        owe_catch_up(round, &table);
    }

    /// Stop watch `id`: nothing more is told it, and the observers of its kind leave `app` with
    /// the last watch of that kind. Its sink, for the caller to let go of with no lock held, or
    /// `Some(None)` when the sink is out for a call, which the calling thread lets go of as the
    /// call returns ([`WatchCall::hand`]); `None` when no watch is declared under `id`.
    pub(super) fn undeclare<
        K: ObserverSinks<Declared = WatchObserver, Undeclared = WatchObserver>,
        P: Storage,
        M: MatchingReport,
    >(
        &self,
        app: &mut SlotObserverOf<K, P, M>,
        id: DeclWatchId,
    ) -> Option<Option<DeclWatchSink>> {
        let mut table = lock(&self.shared.table);
        let row = table
            .rows
            .iter_mut()
            .find(|row| row.watch.as_ref().is_some_and(|watch| watch.id == id))?;
        let watch = row.watch.take()?;
        let sink = {
            let mut slot = lock(&row.cell.slot);
            slot.gone = true;
            slot.sink.take()
        };
        if !table.watches().any(|held| held.plane == watch.plane) {
            if let Some(observers) = table.observers.of(watch.plane).take() {
                uninstall(app, observers);
            }
        }
        owe_catch_up(&self.shared.round, &table);
        drop(table);
        Some(sink)
    }

    /// The session is closed: every watch goes, and a call of one the round still owes is handed
    /// nothing. The sinks, for the caller to let go of with no lock held; one out for a call is
    /// let go of by the thread that called it. The observers stay in the closed session's
    /// application layer, which dispatches nothing more.
    pub(super) fn close(&self) -> impl Iterator<Item = DeclWatchSink> {
        let mut table = lock(&self.shared.table);
        table.hearing = None;
        let sinks: [Option<DeclWatchSink>; caps::MAX_DECL_WATCHES] = core::array::from_fn(|at| {
            let row = table.rows.get_mut(at)?;
            row.watch.take()?;
            let mut slot = lock(&row.cell.slot);
            slot.gone = true;
            slot.sink.take()
        });
        owe_catch_up(&self.shared.round, &table);
        drop(table);
        sinks.into_iter().flatten()
    }

    /// The frame dispatched from now on is a link's, whose peer's zid `peer` reads: what its
    /// observers are told is held as that peer's events, until [`Self::heard_all`]. Read only when
    /// a watch is declared.
    pub(super) fn hear_link(&self, peer: impl FnOnce() -> Option<SessionZid>) {
        let mut table = lock(&self.shared.table);
        let watched = table.watches().next().is_some();
        table.hearing = watched.then(|| Hearing { peer: named(peer) });
    }

    /// The frame dispatched last is over: what the observers are told until the next link's is a
    /// group's, held for no one.
    pub(super) fn heard_all(&self) {
        lock(&self.shared.table).hearing = None;
    }

    /// The face whose frame was just dispatched told that its peer ended its initial
    /// declarations.
    ///
    /// # Safety
    /// The caller holds the session's lock.
    #[cfg(feature = "declarations-synced-event")]
    pub(super) unsafe fn heard_synced(&self) {
        // SAFETY: the caller's contract.
        unsafe {
            heard(
                &self.shared,
                DeclEventKind::Synced,
                DeclPlane::Subscribers,
                0,
                "",
                None,
            )
        };
    }
}

/// The observer the application layer tells what a peer declares and retracts of one plane, which
/// holds it in the round for the watches: the plane and the watches, held in the row of the
/// observer list it is installed in, so installing a pair of them for a watch allocates nothing.
pub(super) struct WatchObserver {
    plane: DeclPlane,
    shared: Arc<Shared>,
}

// The arena's plan lays the observer lists out for the heap profile's boxed observers
// (`crate::arena`), so this observer takes no more room in a row, nor a stricter alignment.
const _: () = assert!(
    core::mem::size_of::<WatchObserver>() <= core::mem::size_of::<BoxedDeclSink>()
        && core::mem::align_of::<WatchObserver>() <= core::mem::align_of::<BoxedDeclSink>()
);

impl DeclSink for WatchObserver {
    fn on_declared(&mut self, decl: &dyn DeclView) {
        // SAFETY: the application layer tells its observers as a frame is dispatched, under the
        // session's lock.
        unsafe {
            heard(
                &self.shared,
                DeclEventKind::Declared,
                self.plane,
                decl.id(),
                decl.keyexpr(),
                decl.keyexpr_held(),
            )
        };
    }
}

impl UndeclSink for WatchObserver {
    fn on_undeclared(&mut self, id: u64) {
        // SAFETY: as `on_declared`.
        unsafe {
            heard(
                &self.shared,
                DeclEventKind::Undeclared,
                self.plane,
                id,
                "",
                None,
            )
        };
    }
}

/// The observer that holds what a peer declares and retracts of `plane` for the watches.
fn observer(plane: DeclPlane, shared: &Arc<Shared>) -> WatchObserver {
    WatchObserver {
        plane,
        shared: Arc::clone(shared),
    }
}

/// Install in `app` the two observers of `plane`, both or neither.
fn install<
    K: ObserverSinks<Declared = WatchObserver, Undeclared = WatchObserver>,
    P: Storage,
    M: MatchingReport,
>(
    app: &mut SlotObserverOf<K, P, M>,
    plane: DeclPlane,
    shared: &Arc<Shared>,
) -> Result<Observers, Declined> {
    let declared = observer(plane, shared);
    let undeclared = observer(plane, shared);
    let (declared, undeclared) = match plane {
        DeclPlane::Subscribers => {
            let tables = &mut app.remote_subscribers;
            let declared = tables
                .on_subscriber_declared_sink(declared)
                .map_err(|_| Declined::TableFull)?;
            match tables.on_subscriber_undeclared_sink(undeclared) {
                Ok(undeclared) => (declared, undeclared),
                Err(_) => {
                    tables.remove_subscriber_declared_sink(declared);
                    return Err(Declined::TableFull);
                }
            }
        }
        #[cfg(any(feature = "query", feature = "queryable"))]
        DeclPlane::Queryables => {
            let tables = &mut app.remote_queryables;
            let declared = tables
                .on_queryable_declared_sink(declared)
                .map_err(|_| Declined::TableFull)?;
            match tables.on_queryable_undeclared_sink(undeclared) {
                Ok(undeclared) => (declared, undeclared),
                Err(_) => {
                    tables.remove_queryable_declared_sink(declared);
                    return Err(Declined::TableFull);
                }
            }
        }
        #[cfg(not(any(feature = "query", feature = "queryable")))]
        DeclPlane::Queryables => return Err(Declined::NotBuilt),
        #[cfg(feature = "liveliness")]
        DeclPlane::Tokens => {
            let tables = &mut app.liveliness;
            let declared = tables
                .on_token_declared_sink(declared)
                .map_err(|_| Declined::TableFull)?;
            match tables.on_token_undeclared_sink(undeclared) {
                Ok(undeclared) => (declared, undeclared),
                Err(_) => {
                    tables.remove_token_declared_sink(declared);
                    return Err(Declined::TableFull);
                }
            }
        }
        #[cfg(not(feature = "liveliness"))]
        DeclPlane::Tokens => return Err(Declined::NotBuilt),
    };
    Ok(Observers {
        plane,
        declared,
        undeclared,
    })
}

/// Take the two observers `observers` names out of `app`.
fn uninstall<
    K: ObserverSinks<Declared = WatchObserver, Undeclared = WatchObserver>,
    P: Storage,
    M: MatchingReport,
>(
    app: &mut SlotObserverOf<K, P, M>,
    observers: Observers,
) {
    match observers.plane {
        DeclPlane::Subscribers => {
            app.remote_subscribers
                .remove_subscriber_declared_sink(observers.declared);
            app.remote_subscribers
                .remove_subscriber_undeclared_sink(observers.undeclared);
        }
        #[cfg(any(feature = "query", feature = "queryable"))]
        DeclPlane::Queryables => {
            app.remote_queryables
                .remove_queryable_declared_sink(observers.declared);
            app.remote_queryables
                .remove_queryable_undeclared_sink(observers.undeclared);
        }
        #[cfg(not(any(feature = "query", feature = "queryable")))]
        DeclPlane::Queryables => {}
        #[cfg(feature = "liveliness")]
        DeclPlane::Tokens => {
            app.liveliness
                .remove_token_declared_sink(observers.declared);
            app.liveliness
                .remove_token_undeclared_sink(observers.undeclared);
        }
        #[cfg(not(feature = "liveliness"))]
        DeclPlane::Tokens => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(feature = "query", feature = "queryable"))]
    use crate::arena::{AllocatorMemory, SessionArena};
    use wz_session_core::decl_sink::BorrowedDecl;
    #[cfg(any(feature = "query", feature = "queryable"))]
    use wz_session_core::slot_observer::ObserverRows;
    use wz_session_core::slot_observer::SlotObserver;

    #[cfg(any(feature = "query", feature = "queryable"))]
    use super::super::registry::App;

    #[cfg(any(feature = "query", feature = "queryable"))]
    const PEER: [u8; 4] = [0xc3; 4];

    /// A sink that records each event it is told, as the port's event prints.
    fn recording() -> (DeclWatchSink, Arc<Mutex<Vec<String>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let into = Arc::clone(&log);
        let sink = DeclWatchSink::shared(move |event: DeclWatchEvent<'_>| {
            lock(&into).push(format!("{event:?}"));
        });
        (sink, log)
    }

    /// The print of `event`, as a recording sink keeps it.
    fn printed(event: DeclWatchEvent<'_>) -> String {
        format!("{event:?}")
    }

    /// As many watches as the build holds, their events held in a round of `events` records.
    fn over(events: usize) -> (DeclWatches, Arc<Round>) {
        let round = crate::round::leaked(events);
        (DeclWatches::holding(caps::MAX_DECL_WATCHES, &round), round)
    }

    /// No face: a session whose link is not up yet.
    fn no_faces() -> core::iter::Empty<(&'static FaceTables, Option<SessionZid>)> {
        core::iter::empty()
    }

    /// Watch `plane` through `sink` in a table with room for it, caught up on no face.
    fn added<
        K: ObserverSinks<Declared = WatchObserver, Undeclared = WatchObserver>,
        P: Storage,
        M: MatchingReport,
    >(
        watches: &DeclWatches,
        app: &mut SlotObserverOf<K, P, M>,
        plane: DeclPlane,
        sink: DeclWatchSink,
    ) -> DeclWatchId {
        let id = match watches.add(app, plane, sink) {
            Ok(id) => id,
            Err((refused, _)) => panic!("a table with room refused the watch: {refused:?}"),
        };
        // SAFETY: the test is the session's one thread, as a holder of its lock is.
        unsafe { watches.tell_owed(no_faces) };
        id
    }

    /// Seal the round and hand it out: whether it held anything.
    fn hand(round: &Round) -> bool {
        // SAFETY: the test is the session's one thread, as a holder of its lock is.
        unsafe { round.seal() };
        round.deliver()
    }

    /// The declaration `id` of `plane` on `keyexpr`, told as an observer is told it.
    #[cfg(any(feature = "query", feature = "queryable"))]
    fn declared(watches: &DeclWatches, plane: DeclPlane, id: u64, keyexpr: &str) {
        observer(plane, &watches.shared).on_declared(&BorrowedDecl {
            id,
            keyexpr,
            held: None,
        });
    }

    /// The undeclaration of `id` of a subscriber, told as an observer is told it.
    fn undeclared(watches: &DeclWatches, id: u64) {
        observer(DeclPlane::Subscribers, &watches.shared).on_undeclared(id);
    }

    /// An event a link's frame told is held for each watch of its kind and for none of another
    /// kind, named as the link's peer where the build names peers; one a group's frame told is
    /// held for no one.
    #[cfg(any(feature = "query", feature = "queryable"))]
    #[test]
    fn a_links_event_reaches_the_watches_of_its_kind_and_a_groups_none() {
        let (watches, round) = over(4);
        let mut app = SlotObserver::new();
        let (queryables, heard) = recording();
        let (subscribers, unheard) = recording();
        added(&watches, &mut app, DeclPlane::Queryables, queryables);
        added(&watches, &mut app, DeclPlane::Subscribers, subscribers);

        watches.hear_link(|| SessionZid::new(&PEER).ok());
        declared(&watches, DeclPlane::Queryables, 4, "demo/q");
        watches.heard_all();
        assert!(hand(&round), "the event is a record of the round");
        let expected_peer = if cfg!(feature = "remote-declaration-watch") {
            Some(&PEER[..])
        } else {
            None
        };
        assert_eq!(
            *lock(&heard),
            [printed(DeclWatchEvent::Declared {
                id: 4,
                keyexpr: "demo/q",
                peer: expected_peer,
            })]
        );
        assert!(
            lock(&unheard).is_empty(),
            "a subscriber watch hears no queryable"
        );

        declared(&watches, DeclPlane::Queryables, 5, "demo/q2");
        assert!(!hand(&round), "a group's event is held for no one");
        assert_eq!(lock(&heard).len(), 1);
    }

    /// A link's frame reads no peer while no watch is declared, and what it tells is held for no
    /// one.
    #[test]
    fn a_frame_no_watch_hears_reads_no_peer_and_holds_nothing() {
        let (watches, round) = over(2);
        watches.hear_link(|| panic!("no watch, so no peer is read"));
        undeclared(&watches, 1);
        watches.heard_all();
        assert!(!hand(&round));
        assert!(!watches.owes());
    }

    /// One event a frame told takes one record of the round, which every watch it reaches joins.
    #[test]
    fn one_record_holds_an_event_for_every_watch_it_reaches() {
        let (watches, round) = over(2);
        let mut app = SlotObserver::new();
        let (first, first_log) = recording();
        let (second, second_log) = recording();
        added(&watches, &mut app, DeclPlane::Subscribers, first);
        added(&watches, &mut app, DeclPlane::Subscribers, second);
        watches.hear_link(|| None);
        undeclared(&watches, 3);
        watches.heard_all();
        // SAFETY: the test is the session's one thread, as a holder of its lock is.
        unsafe {
            assert!(round.has_room_for(1, 0), "one record of two is taken");
            assert!(!round.has_room_for(2, 0), "and only one");
        }
        assert!(hand(&round));
        let told = [printed(DeclWatchEvent::Undeclared { id: 3, peer: None })];
        assert_eq!(*lock(&first_log), told);
        assert_eq!(*lock(&second_log), told);
    }

    /// An event the round has no room for is told as a loss ahead of the watch's next event, and a
    /// loss no event follows is told by the next round that has room for it.
    #[test]
    fn an_event_with_no_room_is_told_as_a_loss_by_the_next_round() {
        let (watches, round) = over(2);
        let mut app = SlotObserver::new();
        let (sink, log) = recording();
        added(&watches, &mut app, DeclPlane::Subscribers, sink);
        watches.hear_link(|| None);
        for id in [1, 2, 3] {
            undeclared(&watches, id);
        }
        watches.heard_all();
        assert!(watches.owes(), "the third found no room");
        assert!(hand(&round));
        watches.hear_link(|| None);
        undeclared(&watches, 4);
        watches.heard_all();
        assert!(hand(&round));
        let undeclared_as = |id| printed(DeclWatchEvent::Undeclared { id, peer: None });
        assert_eq!(
            *lock(&log),
            [
                undeclared_as(1),
                undeclared_as(2),
                printed(DeclWatchEvent::Lost { count: 1 }),
                undeclared_as(4),
            ]
        );
        assert!(!watches.owes());

        let (watches, round) = over(1);
        let mut app = SlotObserver::new();
        let (sink, log) = recording();
        added(&watches, &mut app, DeclPlane::Subscribers, sink);
        watches.hear_link(|| None);
        undeclared(&watches, 1);
        undeclared(&watches, 2);
        watches.heard_all();
        assert!(hand(&round));
        assert!(watches.owes());
        // SAFETY: the test is the session's one thread, as a holder of its lock is.
        unsafe { watches.tell_owed(no_faces) };
        assert!(hand(&round));
        assert_eq!(
            *lock(&log),
            [undeclared_as(1), printed(DeclWatchEvent::Lost { count: 1 })]
        );
        assert!(!watches.owes());
    }

    /// A watch declared while the round is handed out (from inside a callback) is declared, owed
    /// its catch-up, which the next round that has room for it holds; until then it is told no live
    /// event, which the catch-up, read off the peers' tables then, holds.
    #[test]
    fn a_watch_declared_while_the_round_is_handed_out_is_caught_up_by_the_next() {
        let (watches, round) = over(4);
        let mut app = SlotObserver::new();
        let (first, first_log) = recording();
        added(&watches, &mut app, DeclPlane::Subscribers, first);
        watches.hear_link(|| None);
        undeclared(&watches, 1);
        watches.heard_all();
        // SAFETY: the test is the session's one thread, as a holder of its lock is.
        unsafe { round.seal() };
        let (late, late_log) = recording();
        assert!(
            watches.add(&mut app, DeclPlane::Subscribers, late).is_ok(),
            "a round handed out refuses no watch"
        );
        // SAFETY: as above.
        unsafe { watches.tell_owed(no_faces) };
        assert!(watches.owes(), "the sealed round took no catch-up");
        assert!(round.deliver());

        watches.hear_link(|| None);
        undeclared(&watches, 4);
        // SAFETY: as above.
        unsafe { watches.tell_owed(no_faces) };
        assert!(!watches.owes(), "the next round took the catch-up");
        undeclared(&watches, 5);
        watches.heard_all();
        assert!(hand(&round));
        let undeclared_as = |id| printed(DeclWatchEvent::Undeclared { id, peer: None });
        assert_eq!(
            *lock(&first_log),
            [undeclared_as(1), undeclared_as(4), undeclared_as(5)]
        );
        assert_eq!(
            *lock(&late_log),
            [undeclared_as(5)],
            "told no live event before its catch-up"
        );
    }

    /// An undeclared watch is handed nothing the round still holds for it, the observers of its
    /// kind leave with the last watch of that kind, and a second undeclare finds none.
    #[test]
    fn an_undeclared_watch_is_handed_nothing_and_takes_its_observers_with_it() {
        let (watches, round) = over(2);
        let mut app = SlotObserver::new();
        let (sink, log) = recording();
        let id = added(&watches, &mut app, DeclPlane::Subscribers, sink);
        assert_eq!(app.remote_subscribers.on_decl_len(), 1);
        let (second, _) = recording();
        let other = added(&watches, &mut app, DeclPlane::Subscribers, second);
        assert_eq!(
            app.remote_subscribers.on_decl_len(),
            1,
            "one pair of observers for every watch of the kind"
        );
        assert!(matches!(watches.undeclare(&mut app, other), Some(Some(_))));
        assert_eq!(
            app.remote_subscribers.on_decl_len(),
            1,
            "the other watch of the kind keeps them"
        );
        watches.hear_link(|| None);
        undeclared(&watches, 9);
        watches.heard_all();

        assert!(matches!(watches.undeclare(&mut app, id), Some(Some(_))));
        assert!(hand(&round), "the round held the event");
        assert!(lock(&log).is_empty(), "and handed it to no one");
        assert_eq!(Arc::strong_count(&log), 1, "the sink was let go of");
        assert_eq!(app.remote_subscribers.on_decl_len(), 0);
        assert_eq!(app.remote_subscribers.on_undecl_len(), 0);
        assert!(watches.undeclare(&mut app, id).is_none());
    }

    /// The observers go into and out of the application tables a session's arena lent, which the
    /// session's registry holds, as they do into the heap profile's.
    #[cfg(any(feature = "query", feature = "queryable"))]
    #[test]
    fn the_observers_come_and_go_in_the_application_tables_an_arena_lent() {
        let mut arena =
            SessionArena::of_bytes(1 << 16, &AllocatorMemory).expect("the host has the memory");
        let keys = arena
            .arena_mut()
            .lend_keys(1024, SessionLimits::defaults().max_keyexpr_bytes_held())
            .expect("the arena holds the key arena");
        let mut app = App::lent(
            arena.arena_mut(),
            keys,
            ObserverRows::default(),
            &SessionLimits::defaults(),
        )
        .expect("the arena has the rows");
        let (watches, _round) = over(2);
        let (sink, _log) = recording();
        let id = added(&watches, &mut app, DeclPlane::Queryables, sink);
        assert_eq!(app.remote_queryables.on_decl_len(), 1);
        assert_eq!(app.remote_queryables.on_undecl_len(), 1);

        assert!(watches.undeclare(&mut app, id).is_some());
        assert_eq!(app.remote_queryables.on_decl_len(), 0);
        assert_eq!(app.remote_queryables.on_undecl_len(), 0);
    }

    /// A close hands back every sink, and the round hands nothing it still held to them.
    #[test]
    fn a_close_gives_back_every_sink_and_hands_nothing_more() {
        let (watches, round) = over(2);
        let mut app = SlotObserver::new();
        let (sink, log) = recording();
        added(&watches, &mut app, DeclPlane::Subscribers, sink);
        watches.hear_link(|| None);
        undeclared(&watches, 2);
        assert_eq!(watches.close().count(), 1);
        undeclared(&watches, 3);
        assert!(
            hand(&round),
            "the round held the event told before the close"
        );
        assert!(lock(&log).is_empty());
        assert_eq!(
            Arc::strong_count(&log),
            1,
            "the table holds the sink no more"
        );
    }

    /// A sink is out of its cell for its call: a watch undeclared then hands the undeclare no
    /// sink, and the call lets go of the sink as it returns, since the watch went.
    #[test]
    fn a_watch_undeclared_during_its_call_leaves_its_sink_with_the_caller() {
        let (watches, _round) = over(2);
        let mut app = SlotObserver::new();
        let (sink, log) = recording();
        let id = added(&watches, &mut app, DeclPlane::Subscribers, sink);
        let cell = {
            let table = lock(&watches.shared.table);
            let row = table
                .rows
                .iter()
                .find(|row| row.watch.is_some())
                .expect("the watch's row");
            Arc::clone(&row.cell)
        };
        let out = lock(&cell.slot)
            .sink
            .take()
            .expect("the sink is in its cell");
        assert!(
            matches!(watches.undeclare(&mut app, id), Some(None)),
            "the watch is found, its sink out for a call"
        );
        lock(&cell.slot).sink = Some(out);

        // A call that finds its watch gone hands nothing; one whose watch goes during the call
        // lets go of the sink as it returns.
        let call = WatchCall::begun(&cell);
        call.hand(lost(1));
        assert!(lock(&log).is_empty(), "a gone watch is handed nothing");
        assert!(!call.end());

        let inner = Arc::clone(&cell);
        let (went, went_log) = {
            let log = Arc::new(Mutex::new(Vec::new()));
            let into = Arc::clone(&log);
            let sink = DeclWatchSink::shared(move |_: DeclWatchEvent<'_>| {
                let mut slot = lock(&inner.slot);
                lock(&into).push(slot.sink.is_none());
                slot.gone = true;
            });
            (sink, log)
        };
        *lock(&cell.slot) = Slot {
            sink: Some(went),
            gone: false,
        };
        let call = WatchCall::begun(&cell);
        call.hand(lost(2));
        assert_eq!(
            *lock(&went_log),
            [true],
            "the sink was out of its cell for the call"
        );
        assert!(lock(&cell.slot).sink.is_none(), "the caller let go of it");
        assert!(!call.end());
        assert_eq!(
            Arc::strong_count(&cell),
            2,
            "the row and the test hold the cell; the sink and the calls let it go"
        );
    }

    /// A row a call of its undeclared watch is still owed on is not taken by another watch until
    /// the round has made the call.
    #[test]
    fn a_row_is_not_taken_while_a_call_of_its_last_watch_is_owed() {
        let round = crate::round::leaked(2);
        let watches = DeclWatches::holding(1, &round);
        let mut app = SlotObserver::new();
        let (first, _first_log) = recording();
        let id = added(&watches, &mut app, DeclPlane::Subscribers, first);
        watches.hear_link(|| None);
        undeclared(&watches, 1);
        watches.heard_all();
        assert!(watches.undeclare(&mut app, id).is_some());
        let (second, second_log) = recording();
        let Err((refused, handed_back)) = watches.add(&mut app, DeclPlane::Subscribers, second)
        else {
            panic!("the one row's cell is held by the call the round owes");
        };
        assert_eq!(refused, Declined::TableFull);
        assert!(hand(&round));
        assert!(
            watches
                .add(&mut app, DeclPlane::Subscribers, handed_back)
                .is_ok(),
            "the call ended, so the row is free"
        );
        assert!(lock(&second_log).is_empty());
    }

    /// The watches keep no key of their own: a row is a few words, and the key of an event lies
    /// in the round.
    #[test]
    fn a_watch_row_holds_no_key() {
        assert!(core::mem::size_of::<Row>() <= 6 * core::mem::size_of::<u64>());
    }

    /// Tokens are heard with the liveliness plane only, and queryables with a querier or a
    /// queryable only.
    #[test]
    fn tokens_are_heard_with_the_liveliness_plane_alone() {
        assert!(hears(DeclPlane::Subscribers));
        assert_eq!(
            hears(DeclPlane::Queryables),
            cfg!(any(feature = "query", feature = "queryable"))
        );
        assert_eq!(hears(DeclPlane::Tokens), cfg!(feature = "liveliness"));
    }

    /// A build without a querier or a queryable installs no observer of queryables: it holds no
    /// table of them, so the watch is refused by name and nothing is left installed.
    #[cfg(not(any(feature = "query", feature = "queryable")))]
    #[test]
    fn a_build_without_the_queryables_plane_refuses_their_observers() {
        let (watches, _round) = over(2);
        let mut app = SlotObserver::new();
        let (sink, log) = recording();
        assert!(matches!(
            watches.add(&mut app, DeclPlane::Queryables, sink),
            Err((Declined::NotBuilt, _))
        ));
        assert_eq!(Arc::strong_count(&log), 1, "the refused sink is let go of");
        {
            let table = lock(&watches.shared.table);
            assert!(table.observers.is_empty());
            assert_eq!(table.watches().count(), 0, "no row is taken");
        }
        let (sink, _log) = recording();
        added(&watches, &mut app, DeclPlane::Subscribers, sink);
        assert_eq!(app.remote_subscribers.on_decl_len(), 1);
    }

    /// A watch past the rows the session's limit admits is refused with its sink handed back,
    /// nothing installed for it, and the row an undeclared watch leaves takes the next one.
    #[test]
    fn a_watch_past_the_sessions_limit_is_refused_until_a_row_comes_back() {
        let round = crate::round::leaked(1);
        let watches = DeclWatches::holding(1, &round);
        let mut app = SlotObserver::new();
        let (first, _first_log) = recording();
        let id = added(&watches, &mut app, DeclPlane::Subscribers, first);
        let (second, log) = recording();
        let Err((refused, handed_back)) = watches.add(&mut app, DeclPlane::Subscribers, second)
        else {
            panic!("the session's one row is taken");
        };
        assert_eq!(refused, Declined::TableFull);
        drop(handed_back);
        assert_eq!(
            Arc::strong_count(&log),
            1,
            "the refused sink is the caller's"
        );
        assert_eq!(
            app.remote_subscribers.on_decl_len(),
            1,
            "one watch's observers"
        );
        assert!(watches.undeclare(&mut app, id).is_some());
        let (third, _third_log) = recording();
        added(&watches, &mut app, DeclPlane::Subscribers, third);
        assert_eq!(lock(&watches.shared.table).watches().count(), 1);
    }

    /// A watch past the last id is refused, and installs nothing.
    ///
    /// # Control
    ///
    /// An `add` that wraps `next_id` to zero, or installs the observers before it reads the id,
    /// reds the assertions.
    #[test]
    fn a_watch_past_the_last_id_is_refused_and_installs_nothing() {
        let (watches, _round) = over(2);
        let mut app = SlotObserver::new();
        lock(&watches.shared.table).next_id = DeclWatchId::MAX;
        let (sink, log) = recording();
        let Err((refused, handed_back)) = watches.add(&mut app, DeclPlane::Subscribers, sink)
        else {
            panic!("every id was handed out");
        };
        assert_eq!(refused, Declined::NoEntityId);
        drop(handed_back);
        assert_eq!(
            Arc::strong_count(&log),
            1,
            "the refused sink is the caller's"
        );
        assert_eq!(
            app.remote_subscribers.on_decl_len(),
            0,
            "no observer installed"
        );
        assert_eq!(
            lock(&watches.shared.table).watches().count(),
            0,
            "no row taken"
        );
    }

    /// The session's limit sets the rows a table admits, under the build's.
    #[test]
    fn the_sessions_limit_sets_the_rows_under_the_builds() {
        let round = crate::round::leaked(1);
        let mut limits = SessionLimits::defaults();
        limits
            .select_max_decl_watches(Quota::at_most(1))
            .expect("one watch is within every build's domain");
        let lowered = DeclWatches::under(&limits, &round).expect("limits under the build's");
        assert_eq!(lock(&lowered.shared.table).most, 1);
        let defaults = SessionLimits::defaults();
        let built = DeclWatches::under(&defaults, &round).expect("the build's own");
        let within =
            |value: Quota, ceiling: usize| value.most().map_or(ceiling, |most| most.min(ceiling));
        assert_eq!(
            lock(&built.shared.table).most,
            within(defaults.max_decl_watches(), caps::MAX_DECL_WATCHES)
        );
    }
}

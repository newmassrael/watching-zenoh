// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The declaration watch: what the peers of the session's links declare and retract, told to the
//! program ([`wz_capi_port::decl_watch`]).
//!
//! The application layer's observers of what a peer declares are installed once for each kind of
//! entity some watch is of, and stage what they are told while one face's frame is dispatched. The
//! dispatch of a link then settles what was staged as the events of that link's peer
//! ([`DeclWatches::settle`]), under the session's lock, where the link still knows who its peer
//! is; the events wait in a ring and are handed to each watch's sink with the session's other
//! deliveries, outside the lock (decision D8). A group's dispatch settles nothing, and what it
//! staged is dropped when the next dispatch begins: the members of a group are not watched, as the
//! port says.
//!
//! Everything lies in rows fixed when the session opens: a row for each watch its
//! `MAX_DECL_WATCHES` admits, and a ring of `MAX_DECL_WATCH_EVENTS` events, each held once with
//! the rows of the watches still owed it and its key in bytes of its own. An event that finds the
//! ring full is not held, and each watch it would reach is told how many it lost ahead of its next
//! event ([`DeclWatchEvent::Lost`]). A watch is told what the peers hold when it is declared from
//! the same ring, so a watch whose catch-up does not fit is refused.

use alloc::sync::Arc;

#[allow(unused_imports)]
use crate::prelude::*;

use wz_capi_port::os::Mutex;
use wz_capi_port::Refusal as Declined;
use wz_capi_port::{DeclPlane, DeclWatchEvent, DeclWatchId, DeclWatchSink};
use wz_session_core::bounded::{LendRefused, Storage};
use wz_session_core::caps;
use wz_session_core::decl_sink::{BoxedDeclSink, BoxedUndeclSink, DeclView};
use wz_session_core::declare::MatchingReport;
use wz_session_core::limit_binding::Quota;
use wz_session_core::limits::SessionLimits;
use wz_session_core::session_zid::SessionZid;
use wz_session_core::slot_observer::{ObserverSinks, SlotObserverOf};

use super::lock;
use super::registry::FaceTables;

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

/// What a watch is told of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum What {
    Declared,
    Undeclared,
    /// The face's peer ended its initial declarations, which every watch is told whatever its
    /// kind (`declarations-synced-event`).
    #[cfg(feature = "declarations-synced-event")]
    Synced,
    /// Events the watch was owed and the ring had no room for: `id` counts them.
    Lost,
}

impl What {
    /// Whether a watch of `watched` is told this, of `plane`.
    fn reaches(self, plane: DeclPlane, watched: DeclPlane) -> bool {
        match self {
            Self::Declared | Self::Undeclared => plane == watched,
            #[cfg(feature = "declarations-synced-event")]
            Self::Synced => true,
            Self::Lost => false,
        }
    }
}

/// One event owed to a watch, in bytes of its own: what it says, the id it names, the key of a
/// declaration and the peer it came from.
#[derive(Clone, Copy)]
pub(super) struct Told {
    what: What,
    id: u64,
    key: [u8; caps::MAX_KEYEXPR_BYTES],
    key_len: usize,
    peer: Option<SessionZid>,
}

impl Told {
    /// No event: what a row of the ring holds before its first.
    const NONE: Self = Self {
        what: What::Lost,
        id: 0,
        key: [0; caps::MAX_KEYEXPR_BYTES],
        key_len: 0,
        peer: None,
    };

    /// `what` of the declaration `id` on `keyexpr`, of no peer yet; `None` for a key longer
    /// than a row holds, which the session's own tables never keep.
    fn of(what: What, id: u64, keyexpr: &str) -> Option<Self> {
        let mut told = Self {
            what,
            id,
            ..Self::NONE
        };
        told.key
            .get_mut(..keyexpr.len())?
            .copy_from_slice(keyexpr.as_bytes());
        told.key_len = keyexpr.len();
        Some(told)
    }

    /// The loss of `count` events.
    fn lost(count: u64) -> Self {
        Self {
            what: What::Lost,
            id: count,
            ..Self::NONE
        }
    }

    /// The key of a declaration; empty for the others.
    fn key(&self) -> &str {
        // The bytes are a whole `str`'s, copied by `Self::of`.
        core::str::from_utf8(&self.key[..self.key_len]).unwrap_or_default()
    }

    /// The event in the port's words, borrowed for the sink's call.
    pub(super) fn event(&self) -> DeclWatchEvent<'_> {
        let peer = self.peer.as_deref();
        match self.what {
            What::Declared => DeclWatchEvent::Declared {
                id: self.id,
                keyexpr: self.key(),
                peer,
            },
            What::Undeclared => DeclWatchEvent::Undeclared { id: self.id, peer },
            #[cfg(feature = "declarations-synced-event")]
            What::Synced => DeclWatchEvent::Synced { peer },
            What::Lost => DeclWatchEvent::Lost { count: self.id },
        }
    }
}

/// The peer an event is told as: the zid the link's handshake gave, in a build with
/// `remote-declaration-watch`, and no one without it, whose events name no peer.
fn named(peer: impl FnOnce() -> Option<SessionZid>) -> Option<SessionZid> {
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

/// One watch: the kind of entity it is of, the sink it is told through and what it lost.
struct Watch {
    id: DeclWatchId,
    plane: DeclPlane,
    /// Taken out of the row under the table's lock for each event, called after it and put back
    /// ([`DeclWatches::put_back`]), or let go of by the thread that called it when the watch went
    /// meanwhile. `None` while it is out for a call.
    sink: Option<DeclWatchSink>,
    /// The events the ring had no room for since the watch was last told, told ahead of its next.
    lost: u64,
    /// Those of the dispatch running now, which its settle owes the watch and a group's drop
    /// forgets.
    staged_lost: u64,
}

/// The observers installed in the application layer for one kind of entity, by the ids that
/// remove them again.
struct Observers {
    plane: DeclPlane,
    declared: u64,
    undeclared: u64,
}

/// The kinds of entity a watch may be of, each with one pair of observers ([`plane_row`]).
const PLANES: usize = 3;

/// The row of `plane`'s observers.
const fn plane_row(plane: DeclPlane) -> usize {
    match plane {
        DeclPlane::Subscribers => 0,
        DeclPlane::Queryables => 1,
        DeclPlane::Tokens => 2,
    }
}

/// The watches and the observers they are told through.
struct Table {
    /// A row for each watch the build holds at most, of which the session's limit admits the
    /// first `most`.
    watches: [Option<Watch>; caps::MAX_DECL_WATCHES],
    most: usize,
    observers: [Option<Observers>; PLANES],
    next_id: DeclWatchId,
}

impl Table {
    /// A table of no watch, `most` of whose rows hold one (all of them when `most` is more).
    fn holding(most: usize) -> Self {
        Self {
            watches: [const { None }; caps::MAX_DECL_WATCHES],
            most: most.min(caps::MAX_DECL_WATCHES),
            observers: [const { None }; PLANES],
            next_id: 0,
        }
    }

    /// The watches the table holds.
    fn watches(&self) -> impl Iterator<Item = &Watch> + '_ {
        self.watches.iter().flatten()
    }

    /// Watch `id`, when the table holds it.
    fn watch_mut(&mut self, id: DeclWatchId) -> Option<&mut Watch> {
        self.watches
            .iter_mut()
            .flatten()
            .find(|watch| watch.id == id)
    }

    /// The rows of the watches `what` of `plane` reaches, and whether there is one.
    fn reached(&self, what: What, plane: DeclPlane) -> ([bool; caps::MAX_DECL_WATCHES], bool) {
        let mut owed = [false; caps::MAX_DECL_WATCHES];
        let mut any = false;
        for (row, watch) in self.watches.iter().enumerate() {
            if let Some(watch) = watch {
                if what.reaches(plane, watch.plane) {
                    owed[row] = true;
                    any = true;
                }
            }
        }
        (owed, any)
    }
}

/// One event in the ring and the rows of the watches still owed it.
#[derive(Clone, Copy)]
struct Held {
    told: Told,
    owed: [bool; caps::MAX_DECL_WATCHES],
}

impl Held {
    const NONE: Self = Self {
        told: Told::NONE,
        owed: [false; caps::MAX_DECL_WATCHES],
    };
}

/// The events owed to the watches, oldest first, the first `most` rows of the build's in use.
/// The last `unsettled` are a dispatch's not yet settled; whether a thread is handing them out
/// ([`DeclWatches::begin_handing`]).
struct Ring {
    rows: [Held; caps::MAX_DECL_WATCH_EVENTS],
    most: usize,
    head: usize,
    len: usize,
    unsettled: usize,
    handing: bool,
}

impl Ring {
    /// A ring of no event, `most` of whose rows hold one (all of them when `most` is more).
    fn holding(most: usize) -> Self {
        Self {
            rows: [Held::NONE; caps::MAX_DECL_WATCH_EVENTS],
            most: most.min(caps::MAX_DECL_WATCH_EVENTS),
            head: 0,
            len: 0,
            unsettled: 0,
            handing: false,
        }
    }

    /// The rows no event holds.
    fn free(&self) -> usize {
        self.most - self.len
    }

    /// The row of the `nth` event, oldest first; `nth` below `len`, so `most` is not zero.
    fn row(&self, nth: usize) -> usize {
        (self.head + nth) % self.most
    }

    /// Hold `held` after every event; `false` when the ring is full.
    fn push(&mut self, held: Held) -> bool {
        if self.free() == 0 {
            return false;
        }
        let row = self.row(self.len);
        self.rows[row] = held;
        self.len += 1;
        true
    }

    /// The oldest event, when the ring holds one.
    fn front_mut(&mut self) -> Option<&mut Held> {
        if self.len == 0 {
            return None;
        }
        let row = self.head;
        Some(&mut self.rows[row])
    }

    /// Let the oldest event go.
    fn pop_front(&mut self) {
        if self.len != 0 {
            self.head = (self.head + 1) % self.most;
            self.len -= 1;
        }
    }

    /// Let the events of a dispatch no one settled go: a group's.
    fn drop_unsettled(&mut self) {
        self.len -= self.unsettled;
        self.unsettled = 0;
    }

    /// The settled events no watch is owed any more, oldest first, let go of, so an undeclared
    /// watch leaves no row taken in front of those still owed.
    fn let_go_of_the_told(&mut self) {
        while self.len > self.unsettled && !self.rows[self.head].owed.contains(&true) {
            self.pop_front();
        }
    }

    /// Every watch's row `row` is owed nothing more.
    fn forget_row(&mut self, row: usize) {
        for nth in 0..self.len {
            let at = self.row(nth);
            self.rows[at].owed[row] = false;
        }
    }
}

/// What the observers stage into and the deliveries read: the table and the ring, each under its
/// own lock, the table's taken first where both are.
struct Shared {
    table: Mutex<Table>,
    ring: Mutex<Ring>,
}

/// The session's declaration watches and what is owed to them. The registry holds it, so a
/// link's dispatch reaches it, and the engine holds it, so its deliveries do: a clone is the same
/// watches.
#[derive(Clone)]
pub(super) struct DeclWatches {
    shared: Arc<Shared>,
}

#[cfg(test)]
impl Default for DeclWatches {
    /// As many watches and events as the build holds.
    fn default() -> Self {
        Self::holding(caps::MAX_DECL_WATCHES, caps::MAX_DECL_WATCH_EVENTS)
    }
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

/// What the peer of `tables` holds of `plane` now, each declaration handed to `each` with its id
/// and key. Tokens hold none, as the port says.
fn held_of(plane: DeclPlane, tables: &FaceTables, mut each: impl FnMut(u64, &str)) {
    match plane {
        DeclPlane::Subscribers => {
            for (declared, keyexpr) in tables.peer.remote_subscribers.iter_declared() {
                each(declared, keyexpr);
            }
        }
        #[cfg(any(feature = "query", feature = "queryable"))]
        DeclPlane::Queryables => {
            for (declared, keyexpr) in tables.peer.remote_queryables.iter_declared() {
                each(declared, keyexpr);
            }
        }
        // Refused before it is told anything ([`hears`]).
        #[cfg(not(any(feature = "query", feature = "queryable")))]
        DeclPlane::Queryables => {}
        DeclPlane::Tokens => {}
    }
}

/// How many declarations of `plane` the peer of `tables` holds now: the rows a watch of
/// `plane` declared now takes of the ring for that peer ([`DeclWatches::tell_held`]).
pub(super) fn held(plane: DeclPlane, tables: &FaceTables) -> usize {
    let mut count = 0;
    held_of(plane, tables, |_, _| count += 1);
    count
}

/// Stage `what` of `plane`, the declaration `id` on `keyexpr`, owed to every watch it reaches
/// once the dispatch settles: held in the ring, or counted lost for each of them when the ring is
/// full or the key longer than a row holds.
fn stage(shared: &Shared, what: What, plane: DeclPlane, id: u64, keyexpr: &str) {
    let mut table = lock(&shared.table);
    let (owed, any) = table.reached(what, plane);
    if !any {
        return;
    }
    let mut ring = lock(&shared.ring);
    let kept = Told::of(what, id, keyexpr).is_some_and(|told| ring.push(Held { told, owed }));
    if kept {
        ring.unsettled += 1;
        return;
    }
    for (row, watch) in table.watches.iter_mut().enumerate() {
        if let Some(watch) = watch {
            if owed[row] {
                watch.staged_lost += 1;
            }
        }
    }
}

impl DeclWatches {
    /// No watch, and room for as many watches and events as the session's `MAX_DECL_WATCHES` and
    /// `MAX_DECL_WATCH_EVENTS` admit under the build's.
    pub(super) fn under(limits: &SessionLimits) -> Result<Self, LendRefused> {
        let watches = rows_under(limits.max_decl_watches(), caps::MAX_DECL_WATCHES)?;
        let events = rows_under(limits.max_decl_watch_events(), caps::MAX_DECL_WATCH_EVENTS)?;
        Ok(Self::holding(watches, events))
    }

    /// No watch, and room for `watches` of them and `events` events, at most the build's.
    fn holding(watches: usize, events: usize) -> Self {
        Self {
            shared: Arc::new(Shared {
                table: Mutex::new(Table::holding(watches)),
                ring: Mutex::new(Ring::holding(events)),
            }),
        }
    }

    /// A watch of `plane` told through `sink` from now on, first told `held` declarations the
    /// peers hold now ([`Self::tell_held`]): its id. The observers of `plane` are installed in
    /// `app` with the first watch of that kind. Refused, with `sink` handed back for the caller to
    /// let go of with no lock held, by [`Declined::TableFull`] when the session holds as many
    /// watches as its limit admits, the ring has fewer than `held` rows free, or the application
    /// layer's list of observers is at its bound, and by [`Declined::NotBuilt`] for a kind the
    /// build does not hear; nothing is installed then.
    ///
    /// Called under the session's lock, as every stage is, so the rows found free stay free for
    /// the catch-up that follows; a delivery meanwhile only frees more.
    ///
    /// Whatever storage `P` the application's tables have: the session's registry holds them in
    /// rows its arena lent, while the lists of observers are the build's profile's in every
    /// observer. Whatever binding `K` they have, too, so its observers are the boxed ones: the
    /// engine's tables and the heap profile's alike.
    pub(super) fn add<
        K: ObserverSinks<Declared = BoxedDeclSink, Undeclared = BoxedUndeclSink>,
        P: Storage,
        M: MatchingReport,
    >(
        &self,
        app: &mut SlotObserverOf<K, P, M>,
        plane: DeclPlane,
        sink: DeclWatchSink,
        held: usize,
    ) -> Result<DeclWatchId, (Declined, DeclWatchSink)> {
        let mut table = lock(&self.shared.table);
        let most = table.most;
        let Some(free) = table.watches[..most].iter().position(Option::is_none) else {
            return Err((Declined::TableFull, sink));
        };
        {
            let mut ring = lock(&self.shared.ring);
            // What a group's dispatch staged is owed to no one; it gives its rows back first.
            ring.drop_unsettled();
            if ring.free() < held {
                return Err((Declined::TableFull, sink));
            }
        }
        let observers = &mut table.observers[plane_row(plane)];
        if observers.is_none() {
            match install(app, plane, &self.shared) {
                Ok(installed) => *observers = Some(installed),
                Err(refused) => return Err((refused, sink)),
            }
        }
        table.next_id += 1;
        let id = table.next_id;
        table.watches[free] = Some(Watch {
            id,
            plane,
            sink: Some(sink),
            lost: 0,
            staged_lost: 0,
        });
        Ok(id)
    }

    /// Owe watch `id`, of `plane`, the declarations the peer of `tables` holds now, as declared
    /// by `peer`: what a watch declared after them is told first, in the rows [`Self::add`] found
    /// free for them. A watch of tokens is told none, as the port says.
    pub(super) fn tell_held(
        &self,
        id: DeclWatchId,
        plane: DeclPlane,
        tables: &FaceTables,
        peer: impl FnOnce() -> Option<SessionZid>,
    ) {
        let mut table = lock(&self.shared.table);
        let Some(row) = table
            .watches
            .iter()
            .position(|watch| matches!(watch, Some(watch) if watch.id == id))
        else {
            return;
        };
        let mut owed = [false; caps::MAX_DECL_WATCHES];
        owed[row] = true;
        let mut ring = lock(&self.shared.ring);
        let mut lost = 0;
        let mut peer = Some(peer);
        let mut named_peer = None;
        held_of(plane, tables, |declared, keyexpr| {
            if let Some(peer) = peer.take() {
                named_peer = named(peer);
            }
            let told = Told::of(What::Declared, declared, keyexpr).map(|told| Told {
                peer: named_peer,
                ..told
            });
            if !told.is_some_and(|told| ring.push(Held { told, owed })) {
                lost += 1;
            }
        });
        if let Some(watch) = table.watches[row].as_mut() {
            watch.lost += lost;
        }
    }

    /// Stop watch `id`: nothing more is owed to it, and the observers of its kind leave `app`
    /// with the last watch of that kind. Its sink, for the caller to let go of with no lock held,
    /// or `Some(None)` when the sink is out for a call, which the calling thread lets go of as the
    /// call returns ([`Self::put_back`]); `None` when no watch is declared under `id`.
    pub(super) fn undeclare<
        K: ObserverSinks<Declared = BoxedDeclSink, Undeclared = BoxedUndeclSink>,
        P: Storage,
        M: MatchingReport,
    >(
        &self,
        app: &mut SlotObserverOf<K, P, M>,
        id: DeclWatchId,
    ) -> Option<Option<DeclWatchSink>> {
        let mut table = lock(&self.shared.table);
        let row = table
            .watches
            .iter()
            .position(|watch| matches!(watch, Some(watch) if watch.id == id))?;
        let watch = table.watches[row].take()?;
        if !table.watches().any(|held| held.plane == watch.plane) {
            if let Some(observers) = table.observers[plane_row(watch.plane)].take() {
                uninstall(app, observers);
            }
        }
        {
            let mut ring = lock(&self.shared.ring);
            ring.forget_row(row);
            ring.let_go_of_the_told();
        }
        drop(table);
        Some(watch.sink)
    }

    /// The session is closed: every watch goes, with what was owed to it. The sinks, for the
    /// caller to let go of with no lock held; one out for a call is let go of by the thread that
    /// called it. The observers stay in the closed session's application layer, which dispatches
    /// nothing more.
    pub(super) fn close(&self) -> impl Iterator<Item = DeclWatchSink> {
        let mut table = lock(&self.shared.table);
        let watches =
            core::mem::replace(&mut table.watches, [const { None }; caps::MAX_DECL_WATCHES]);
        {
            let mut ring = lock(&self.shared.ring);
            ring.len = 0;
            ring.unsettled = 0;
        }
        drop(table);
        watches.into_iter().flatten().filter_map(|watch| watch.sink)
    }

    /// Forget what an earlier dispatch staged and nobody settled: a group's.
    pub(super) fn drop_staged(&self) {
        let mut table = lock(&self.shared.table);
        for watch in table.watches.iter_mut().flatten() {
            watch.staged_lost = 0;
        }
        lock(&self.shared.ring).drop_unsettled();
    }

    /// The face whose frame was just dispatched told that its peer ended its initial
    /// declarations.
    #[cfg(feature = "declarations-synced-event")]
    pub(super) fn stage_synced(&self) {
        stage(&self.shared, What::Synced, DeclPlane::Subscribers, 0, "");
    }

    /// Owe each watch what the last dispatch staged of its kind, as the events of the link's peer
    /// `peer`, which is read only when something was staged.
    pub(super) fn settle(&self, peer: impl FnOnce() -> Option<SessionZid>) {
        let mut table = lock(&self.shared.table);
        let mut ring = lock(&self.shared.ring);
        let lost = table.watches().any(|watch| watch.staged_lost != 0);
        if ring.unsettled == 0 && !lost {
            return;
        }
        let peer = named(peer);
        for nth in ring.len - ring.unsettled..ring.len {
            let at = ring.row(nth);
            ring.rows[at].told.peer = peer;
        }
        ring.unsettled = 0;
        for watch in table.watches.iter_mut().flatten() {
            watch.lost += core::mem::take(&mut watch.staged_lost);
        }
    }

    /// This thread's turn to hand the owed events out, or `None` when none is owed or another
    /// thread's turn is running, which hands out what this one owed too. One thread hands them
    /// out at a time, so a sink taken out of its row for a call is out for that call alone and no
    /// event is passed over for a sink that is out.
    pub(super) fn begin_handing(&self) -> Option<HandingTurn<'_>> {
        let table = lock(&self.shared.table);
        let mut ring = lock(&self.shared.ring);
        let owed = ring.len > ring.unsettled || table.watches().any(|watch| watch.lost != 0);
        if !owed || ring.handing {
            return None;
        }
        ring.handing = true;
        Some(HandingTurn {
            watches: self,
            over: false,
        })
    }

    /// Put the sink of watch `id` back in its row after its call; the sink again when the watch
    /// went during the call (an undeclare from inside it, or the session's close), for the caller
    /// to let go of with no lock held.
    pub(super) fn put_back(&self, id: DeclWatchId, sink: DeclWatchSink) -> Option<DeclWatchSink> {
        match lock(&self.shared.table).watch_mut(id) {
            Some(watch) => {
                watch.sink = Some(sink);
                None
            }
            None => Some(sink),
        }
    }
}

/// One thread's turn of handing the owed events out ([`DeclWatches::begin_handing`]): it ends
/// when no event is left, or, should the thread unwind out of a sink, when it is dropped, so the
/// next thread that finds an event owed hands it.
pub(super) struct HandingTurn<'a> {
    watches: &'a DeclWatches,
    /// Whether the turn ended with no event left ([`Self::next`]).
    over: bool,
}

impl HandingTurn<'_> {
    /// The next event to hand out, the id of the watch it is owed to and that watch's sink, taken
    /// out of its row: a watch's loss first, then the events in the order they were owed. `None`
    /// ends the turn, under the locks an event is owed under, so no event owed meanwhile is left
    /// with no thread to hand it. Each lock is let go of before this returns, so the sink may
    /// reach back into the session.
    pub(super) fn next(&mut self) -> Option<(DeclWatchId, DeclWatchSink, Told)> {
        let shared = &self.watches.shared;
        let mut table = lock(&shared.table);
        let mut ring = lock(&shared.ring);
        if let Some(watch) = table
            .watches
            .iter_mut()
            .flatten()
            .find(|watch| watch.lost != 0 && watch.sink.is_some())
        {
            let count = core::mem::take(&mut watch.lost);
            if let Some(sink) = watch.sink.take() {
                return Some((watch.id, sink, Told::lost(count)));
            }
        }
        while ring.len > ring.unsettled {
            let Some(front) = ring.front_mut() else {
                break;
            };
            let Some(row) = front.owed.iter().position(|owed| *owed) else {
                ring.pop_front();
                continue;
            };
            front.owed[row] = false;
            let told = front.told;
            if let Some(watch) = table.watches[row].as_mut() {
                if let Some(sink) = watch.sink.take() {
                    return Some((watch.id, sink, told));
                }
            }
        }
        ring.handing = false;
        self.over = true;
        None
    }
}

impl Drop for HandingTurn<'_> {
    fn drop(&mut self) {
        // A turn that ended itself is another thread's to begin again, and is not ended twice.
        if !self.over {
            lock(&self.watches.shared.ring).handing = false;
        }
    }
}

/// The observer that stages a declaration of `plane`.
fn declared_sink(plane: DeclPlane, shared: &Arc<Shared>) -> BoxedDeclSink {
    let shared = Arc::clone(shared);
    BoxedDeclSink::new(move |view: &dyn DeclView| {
        stage(&shared, What::Declared, plane, view.id(), view.keyexpr());
    })
}

/// The observer that stages an undeclaration of `plane`.
fn undeclared_sink(plane: DeclPlane, shared: &Arc<Shared>) -> BoxedUndeclSink {
    let shared = Arc::clone(shared);
    BoxedUndeclSink::new(move |id: u64| {
        stage(&shared, What::Undeclared, plane, id, "");
    })
}

/// Install in `app` the two observers of `plane`, both or neither.
fn install<
    K: ObserverSinks<Declared = BoxedDeclSink, Undeclared = BoxedUndeclSink>,
    P: Storage,
    M: MatchingReport,
>(
    app: &mut SlotObserverOf<K, P, M>,
    plane: DeclPlane,
    shared: &Arc<Shared>,
) -> Result<Observers, Declined> {
    let declared = declared_sink(plane, shared);
    let undeclared = undeclared_sink(plane, shared);
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
    K: ObserverSinks<Declared = BoxedDeclSink, Undeclared = BoxedUndeclSink>,
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

    /// Watch `plane` through `sink` in a table with room for it, owed nothing held.
    fn added<
        K: ObserverSinks<Declared = BoxedDeclSink, Undeclared = BoxedUndeclSink>,
        P: Storage,
        M: MatchingReport,
    >(
        watches: &DeclWatches,
        app: &mut SlotObserverOf<K, P, M>,
        plane: DeclPlane,
        sink: DeclWatchSink,
    ) -> DeclWatchId {
        match watches.add(app, plane, sink, 0) {
            Ok(id) => id,
            Err((refused, _)) => panic!("a table with room refused the watch: {refused:?}"),
        }
    }

    /// The undeclaration of `id` of a subscriber, staged as an observer stages it.
    fn undeclared(watches: &DeclWatches, id: u64) {
        stage(
            &watches.shared,
            What::Undeclared,
            DeclPlane::Subscribers,
            id,
            "",
        );
    }

    /// How many events the ring holds.
    fn held_events(watches: &DeclWatches) -> usize {
        lock(&watches.shared.ring).len
    }

    fn drain(watches: &DeclWatches) -> usize {
        let mut told = 0;
        if let Some(mut turn) = watches.begin_handing() {
            while let Some((id, sink, event)) = turn.next() {
                sink.call(event.event());
                told += 1;
                assert!(
                    watches.put_back(id, sink).is_none(),
                    "the watch stands, so its sink goes back"
                );
            }
        }
        told
    }

    /// What one dispatch staged is owed to each watch of its kind and to none of another kind,
    /// named as the settling link's peer where the build names peers, and what a group's dispatch
    /// staged is dropped by the next dispatch, owed to no one.
    #[cfg(any(feature = "query", feature = "queryable"))]
    #[test]
    fn a_settled_event_reaches_the_watches_of_its_kind_and_a_dropped_one_none() {
        let watches = DeclWatches::default();
        let mut app = SlotObserver::new();
        let (queryables, heard) = recording();
        let (subscribers, unheard) = recording();
        added(&watches, &mut app, DeclPlane::Queryables, queryables);
        added(&watches, &mut app, DeclPlane::Subscribers, subscribers);

        stage(
            &watches.shared,
            What::Declared,
            DeclPlane::Queryables,
            4,
            "demo/q",
        );
        watches.settle(|| SessionZid::new(&PEER).ok());
        assert_eq!(drain(&watches), 1, "one watch of the kind, one event");
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
        assert_eq!(held_events(&watches), 0, "a told event gives its row back");

        stage(
            &watches.shared,
            What::Undeclared,
            DeclPlane::Queryables,
            4,
            "",
        );
        watches.drop_staged();
        watches.settle(|| panic!("nothing staged, so no peer is read"));
        assert_eq!(drain(&watches), 0, "a dropped stage is owed to no one");
        assert_eq!(held_events(&watches), 0);
    }

    /// What no watch reaches takes no row of the ring.
    #[test]
    fn an_event_no_watch_reaches_takes_no_row() {
        let watches = DeclWatches::default();
        undeclared(&watches, 1);
        assert_eq!(held_events(&watches), 0);
        assert!(watches.begin_handing().is_none(), "nothing is owed");
    }

    /// An undeclared watch is owed nothing more, the observers of its kind leave with the last
    /// watch of that kind, and a second undeclare finds none.
    #[test]
    fn an_undeclared_watch_is_owed_nothing_and_takes_its_observers_with_it() {
        let watches = DeclWatches::default();
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
        undeclared(&watches, 9);
        watches.settle(|| None);

        assert!(matches!(watches.undeclare(&mut app, id), Some(Some(_))));
        assert_eq!(drain(&watches), 0, "what was owed went with the watch");
        assert_eq!(held_events(&watches), 0, "and gave its row back");
        assert!(lock(&log).is_empty());
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
        let watches = DeclWatches::default();
        let (sink, _log) = recording();
        let id = added(&watches, &mut app, DeclPlane::Queryables, sink);
        assert_eq!(app.remote_queryables.on_decl_len(), 1);
        assert_eq!(app.remote_queryables.on_undecl_len(), 1);

        assert!(watches.undeclare(&mut app, id).is_some());
        assert_eq!(app.remote_queryables.on_decl_len(), 0);
        assert_eq!(app.remote_queryables.on_undecl_len(), 0);
    }

    /// A close hands back every sink and leaves nothing owed.
    #[test]
    fn a_close_gives_back_every_sink_and_owes_nothing() {
        let watches = DeclWatches::default();
        let mut app = SlotObserver::new();
        let (sink, log) = recording();
        added(&watches, &mut app, DeclPlane::Subscribers, sink);
        undeclared(&watches, 2);
        watches.settle(|| None);
        assert_eq!(watches.close().count(), 1);
        assert_eq!(drain(&watches), 0);
        assert_eq!(held_events(&watches), 0);
        assert_eq!(
            Arc::strong_count(&log),
            1,
            "the table holds the sink no more"
        );
    }

    /// A sink is out of its row for its call: a watch undeclared from inside the call hands the
    /// undeclare no sink, and the sink comes back to the caller to let go of, since its row went.
    #[test]
    fn a_watch_undeclared_during_its_call_leaves_its_sink_with_the_caller() {
        let watches = DeclWatches::default();
        let mut app = SlotObserver::new();
        let (sink, log) = recording();
        let id = added(&watches, &mut app, DeclPlane::Subscribers, sink);
        undeclared(&watches, 3);
        watches.settle(|| None);
        let mut turn = watches.begin_handing().expect("an event is owed");
        let (told_to, sink, event) = turn.next().expect("the event is handed");
        assert_eq!(told_to, id);
        assert!(
            watches.begin_handing().is_none(),
            "a second thread finds the turn running"
        );
        assert!(
            matches!(watches.undeclare(&mut app, id), Some(None)),
            "the watch is found, its sink out for the call"
        );
        sink.call(event.event());
        let gone = watches.put_back(id, sink);
        assert!(gone.is_some(), "the row went, so the sink is the caller's");
        assert!(turn.next().is_none(), "nothing more is owed");
        drop(turn);
        drop(gone);
        assert_eq!(lock(&log).len(), 1, "told once");
        assert_eq!(Arc::strong_count(&log), 1, "let go of by the caller");
    }

    /// A turn dropped before it ran out, as by a sink that unwound, lets the next thread hand
    /// what is owed.
    #[test]
    fn a_turn_dropped_early_lets_the_next_thread_hand() {
        let watches = DeclWatches::default();
        let mut app = SlotObserver::new();
        let (sink, _log) = recording();
        let id = added(&watches, &mut app, DeclPlane::Subscribers, sink);
        undeclared(&watches, 1);
        undeclared(&watches, 2);
        watches.settle(|| None);
        let mut turn = watches.begin_handing().expect("events are owed");
        let (_, sink, _) = turn.next().expect("the first event is handed");
        drop(turn);
        assert!(watches.put_back(id, sink).is_none());
        assert_eq!(
            drain(&watches),
            1,
            "the second event is handed by the next turn"
        );
    }

    /// An event held once is told to every watch it reaches, in one row of the ring.
    #[test]
    fn one_row_holds_an_event_for_every_watch_it_reaches() {
        let watches = DeclWatches::holding(2, 1);
        let mut app = SlotObserver::new();
        let (first, first_log) = recording();
        let (second, second_log) = recording();
        added(&watches, &mut app, DeclPlane::Subscribers, first);
        added(&watches, &mut app, DeclPlane::Subscribers, second);
        undeclared(&watches, 6);
        watches.settle(|| None);
        assert_eq!(held_events(&watches), 1, "one row for the two watches");
        assert_eq!(drain(&watches), 2);
        let told = [printed(DeclWatchEvent::Undeclared { id: 6, peer: None })];
        assert_eq!(*lock(&first_log), told);
        assert_eq!(*lock(&second_log), told);
    }

    /// An event that finds the ring full is not held, and each watch it would reach is told how
    /// many it lost ahead of what it is told next.
    #[test]
    fn a_full_ring_tells_each_watch_it_reaches_how_many_it_lost() {
        let watches = DeclWatches::holding(2, 2);
        let mut app = SlotObserver::new();
        let (first, first_log) = recording();
        let (second, second_log) = recording();
        added(&watches, &mut app, DeclPlane::Subscribers, first);
        added(&watches, &mut app, DeclPlane::Subscribers, second);
        for id in 1..=4 {
            undeclared(&watches, id);
        }
        watches.settle(|| None);
        assert_eq!(held_events(&watches), 2, "the ring holds two");
        assert_eq!(drain(&watches), 6, "a loss and two events for each watch");
        let told = [
            printed(DeclWatchEvent::Lost { count: 2 }),
            printed(DeclWatchEvent::Undeclared { id: 1, peer: None }),
            printed(DeclWatchEvent::Undeclared { id: 2, peer: None }),
        ];
        assert_eq!(*lock(&first_log), told);
        assert_eq!(*lock(&second_log), told);
        assert!(watches.begin_handing().is_none(), "the loss is told once");
    }

    /// A key longer than a row holds is told as lost, not cut.
    #[test]
    fn a_key_longer_than_a_row_is_told_as_lost() {
        let watches = DeclWatches::default();
        let mut app = SlotObserver::new();
        let (sink, log) = recording();
        added(&watches, &mut app, DeclPlane::Subscribers, sink);
        let long = "k".repeat(caps::MAX_KEYEXPR_BYTES + 1);
        stage(
            &watches.shared,
            What::Declared,
            DeclPlane::Subscribers,
            1,
            &long,
        );
        watches.settle(|| None);
        assert_eq!(drain(&watches), 1);
        assert_eq!(*lock(&log), [printed(DeclWatchEvent::Lost { count: 1 })]);
    }

    /// What a group's dispatch lost is owed to no one, as what it staged.
    #[test]
    fn a_loss_of_a_dropped_stage_is_owed_to_no_one() {
        let watches = DeclWatches::holding(1, 1);
        let mut app = SlotObserver::new();
        let (sink, log) = recording();
        added(&watches, &mut app, DeclPlane::Subscribers, sink);
        undeclared(&watches, 1);
        undeclared(&watches, 2);
        watches.drop_staged();
        watches.settle(|| panic!("nothing staged, so no peer is read"));
        assert_eq!(drain(&watches), 0);
        assert!(lock(&log).is_empty());
        assert_eq!(held_events(&watches), 0);
    }

    /// A watch whose catch-up does not fit in the rows free is refused with its sink handed back
    /// and nothing installed, and one whose catch-up fits is declared; an undeclared watch's rows
    /// come back.
    #[test]
    fn a_watch_whose_catch_up_does_not_fit_is_refused() {
        let watches = DeclWatches::holding(2, 2);
        let mut app = SlotObserver::new();
        let (first, _first_log) = recording();
        let id = added(&watches, &mut app, DeclPlane::Subscribers, first);
        undeclared(&watches, 1);
        watches.settle(|| None);
        let (late, late_log) = recording();
        let Err((refused, handed_back)) = watches.add(&mut app, DeclPlane::Queryables, late, 2)
        else {
            panic!("one row is free and the catch-up takes two");
        };
        assert_eq!(refused, Declined::TableFull);
        drop(handed_back);
        assert_eq!(
            Arc::strong_count(&late_log),
            1,
            "the refused sink is the caller's"
        );
        assert_eq!(lock(&watches.shared.table).watches().count(), 1);
        assert!(watches.undeclare(&mut app, id).is_some());
        let (fits, _fits_log) = recording();
        assert!(
            watches
                .add(&mut app, DeclPlane::Subscribers, fits, 2)
                .is_ok(),
            "the undeclared watch gave its row back"
        );
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
        let watches = DeclWatches::default();
        let mut app = SlotObserver::new();
        let (sink, log) = recording();
        assert!(matches!(
            watches.add(&mut app, DeclPlane::Queryables, sink, 0),
            Err((Declined::NotBuilt, _))
        ));
        assert_eq!(Arc::strong_count(&log), 1, "the refused sink is let go of");
        {
            let table = lock(&watches.shared.table);
            assert!(table.observers.iter().all(Option::is_none));
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
        let watches = DeclWatches::holding(1, 1);
        let mut app = SlotObserver::new();
        let (first, _first_log) = recording();
        let id = added(&watches, &mut app, DeclPlane::Subscribers, first);
        let (second, log) = recording();
        let Err((refused, handed_back)) = watches.add(&mut app, DeclPlane::Subscribers, second, 0)
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

    /// The session's limits set the rows a table and its ring admit, under the build's.
    #[test]
    fn the_sessions_limits_set_the_rows_under_the_builds() {
        let mut limits = SessionLimits::defaults();
        limits
            .select_max_decl_watches(Quota::at_most(1))
            .expect("one watch is within every build's domain");
        limits
            .select_max_decl_watch_events(Quota::at_most(1))
            .expect("one event is within every build's domain");
        let lowered = DeclWatches::under(&limits).expect("limits under the build's");
        assert_eq!(lock(&lowered.shared.table).most, 1);
        assert_eq!(lock(&lowered.shared.ring).most, 1);
        let defaults = SessionLimits::defaults();
        let built = DeclWatches::under(&defaults).expect("the build's own");
        let within =
            |value: Quota, ceiling: usize| value.most().map_or(ceiling, |most| most.min(ceiling));
        assert_eq!(
            lock(&built.shared.table).most,
            within(defaults.max_decl_watches(), caps::MAX_DECL_WATCHES)
        );
        assert_eq!(
            lock(&built.shared.ring).most,
            within(
                defaults.max_decl_watch_events(),
                caps::MAX_DECL_WATCH_EVENTS
            )
        );
    }
}

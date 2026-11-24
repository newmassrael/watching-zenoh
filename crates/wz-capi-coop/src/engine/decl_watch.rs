// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The declaration watch: what the peers of the session's links declare and retract, told to the
//! program ([`wz_capi_port::decl_watch`]).
//!
//! The application layer's observers of what a peer declares are installed once for each kind of
//! entity some watch is of, and stage what they are told while one face's frame is dispatched. The
//! dispatch of a link then settles what was staged as the events of that link's peer
//! ([`DeclWatches::settle`]), under the session's lock, where the link still knows who its peer
//! is; the events wait in a queue and are handed to each watch's sink with the session's other
//! deliveries, outside the lock (decision D8). A group's dispatch settles nothing, and what it
//! staged is dropped when the next dispatch begins: the members of a group are not watched, as the
//! port says.

use alloc::collections::VecDeque;
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

/// What an observer of the application layer was told while one face's frame was dispatched,
/// before it is known whose it is.
enum Staged {
    Declared {
        plane: DeclPlane,
        id: u64,
        keyexpr: String,
    },
    Undeclared {
        plane: DeclPlane,
        id: u64,
    },
    /// The face's peer ended its initial declarations, which every watch is told whatever its
    /// kind (`declarations-synced-event`).
    #[cfg(feature = "declarations-synced-event")]
    Synced,
}

impl Staged {
    /// Whether a watch of `watched` is told this.
    fn reaches(&self, watched: DeclPlane) -> bool {
        match self {
            Self::Declared { plane, .. } | Self::Undeclared { plane, .. } => *plane == watched,
            #[cfg(feature = "declarations-synced-event")]
            Self::Synced => true,
        }
    }

    /// What a watch is told of this as the event of the peer `peer`.
    fn told(&self, peer: Option<&[u8]>) -> Told {
        let peer = peer.map(<[u8]>::to_vec);
        match self {
            Self::Declared { id, keyexpr, .. } => Told::Declared {
                id: *id,
                keyexpr: keyexpr.clone(),
                peer,
            },
            Self::Undeclared { id, .. } => Told::Undeclared { id: *id, peer },
            #[cfg(feature = "declarations-synced-event")]
            Self::Synced => Told::Synced { peer },
        }
    }
}

/// One event owed to one watch, owned until it is handed out.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Told {
    Declared {
        id: u64,
        keyexpr: String,
        peer: Option<Vec<u8>>,
    },
    Undeclared {
        id: u64,
        peer: Option<Vec<u8>>,
    },
    #[cfg(feature = "declarations-synced-event")]
    Synced {
        peer: Option<Vec<u8>>,
    },
}

impl Told {
    /// The event in the port's words, borrowed for the sink's call.
    pub(super) fn event(&self) -> DeclWatchEvent<'_> {
        match self {
            Self::Declared { id, keyexpr, peer } => DeclWatchEvent::Declared {
                id: *id,
                keyexpr: keyexpr.as_str(),
                peer: peer.as_deref(),
            },
            Self::Undeclared { id, peer } => DeclWatchEvent::Undeclared {
                id: *id,
                peer: peer.as_deref(),
            },
            #[cfg(feature = "declarations-synced-event")]
            Self::Synced { peer } => DeclWatchEvent::Synced {
                peer: peer.as_deref(),
            },
        }
    }
}

/// The peer an event is told as: the zid the link's handshake gave, in a build with
/// `remote-declaration-watch`, and no one without it, whose events name no peer.
fn named(peer: impl FnOnce() -> Option<Vec<u8>>) -> Option<Vec<u8>> {
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

/// One watch: the kind of entity it is of and the sink it is told through.
struct Watch {
    id: DeclWatchId,
    plane: DeclPlane,
    /// Taken out of the row under the table's lock for each event, called after it and put back
    /// ([`DeclWatches::put_back`]), or let go of by the thread that called it when the watch went
    /// meanwhile. `None` while it is out for a call.
    sink: Option<DeclWatchSink>,
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
}

/// The session's declaration watches and what is owed to them. The registry holds it, so a
/// link's dispatch reaches it, and the engine holds it, so its deliveries do.
pub(super) struct DeclWatches {
    /// Written by the observers while a frame is dispatched, under the session's lock.
    staged: Arc<Mutex<Vec<Staged>>>,
    table: Mutex<Table>,
    owed: Mutex<Owed>,
}

/// The events owed to the watches, in the order they were owed, and whether a thread is handing
/// them out ([`DeclWatches::begin_handing`]).
#[derive(Default)]
struct Owed {
    queue: VecDeque<(DeclWatchId, Told)>,
    handing: bool,
}

#[cfg(test)]
impl Default for DeclWatches {
    /// As many watches as the build holds.
    fn default() -> Self {
        Self::holding(caps::MAX_DECL_WATCHES)
    }
}

impl DeclWatches {
    /// No watch, and room for as many as the session's `MAX_DECL_WATCHES` admits under the
    /// build's. A limit past the build's is refused, as the open that lays the ABI's places of
    /// the watches out refuses it.
    pub(super) fn under(limits: &SessionLimits) -> Result<Self, LendRefused> {
        let value = limits.max_decl_watches();
        let most = value
            .lent_under(Quota::at_most(caps::MAX_DECL_WATCHES))
            .map_err(|_| LendRefused::OverCeiling {
                rows: value.most().unwrap_or(usize::MAX),
                ceiling: caps::MAX_DECL_WATCHES,
            })?;
        Ok(Self::holding(most))
    }

    /// No watch, and room for `most` of them, at most the build's.
    fn holding(most: usize) -> Self {
        Self {
            staged: Arc::default(),
            table: Mutex::new(Table::holding(most)),
            owed: Mutex::default(),
        }
    }

    /// A watch of `plane` told through `sink` from now on: its id. The observers of `plane` are
    /// installed in `app` with the first watch of that kind. Refused, with `sink` handed back for
    /// the caller to let go of with no lock held, by [`Declined::TableFull`] when the session holds
    /// as many watches as its limit admits or the application layer's list of observers is at
    /// its bound, and by [`Declined::NotBuilt`] for a kind the build does not hear; nothing is
    /// installed then.
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
    ) -> Result<DeclWatchId, (Declined, DeclWatchSink)> {
        let mut table = lock(&self.table);
        let most = table.most;
        let Some(free) = table.watches[..most].iter().position(Option::is_none) else {
            return Err((Declined::TableFull, sink));
        };
        let observers = &mut table.observers[plane_row(plane)];
        if observers.is_none() {
            match install(app, plane, &self.staged) {
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
        });
        Ok(id)
    }

    /// Owe watch `id`, of `plane`, the declarations the peer of `tables` holds now, as declared
    /// by `peer`: what a watch declared after them is told first. A watch of tokens is told none,
    /// as the port says.
    pub(super) fn tell_held(
        &self,
        id: DeclWatchId,
        plane: DeclPlane,
        tables: &FaceTables,
        peer: impl FnOnce() -> Option<Vec<u8>>,
    ) {
        let held: Vec<(u64, String)> = match plane {
            DeclPlane::Subscribers => tables
                .peer
                .remote_subscribers
                .iter_declared()
                .map(|(declared, keyexpr)| (declared, keyexpr.to_owned()))
                .collect(),
            #[cfg(any(feature = "query", feature = "queryable"))]
            DeclPlane::Queryables => tables
                .peer
                .remote_queryables
                .iter_declared()
                .map(|(declared, keyexpr)| (declared, keyexpr.to_owned()))
                .collect(),
            // Refused before it is told anything ([`hears`]).
            #[cfg(not(any(feature = "query", feature = "queryable")))]
            DeclPlane::Queryables => Vec::new(),
            DeclPlane::Tokens => Vec::new(),
        };
        if held.is_empty() {
            return;
        }
        let peer = named(peer);
        let mut owed = lock(&self.owed);
        for (declared, keyexpr) in held {
            owed.queue.push_back((
                id,
                Told::Declared {
                    id: declared,
                    keyexpr,
                    peer: peer.clone(),
                },
            ));
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
        let mut table = lock(&self.table);
        let watch = table
            .watches
            .iter_mut()
            .find(|row| matches!(row, Some(watch) if watch.id == id))?
            .take()?;
        if !table.watches().any(|held| held.plane == watch.plane) {
            if let Some(observers) = table.observers[plane_row(watch.plane)].take() {
                uninstall(app, observers);
            }
        }
        drop(table);
        lock(&self.owed).queue.retain(|(owed, _)| *owed != id);
        Some(watch.sink)
    }

    /// The session is closed: every watch goes, with what was owed to it. The sinks, for the
    /// caller to let go of with no lock held; one out for a call is let go of by the thread that
    /// called it. The observers stay in the closed session's application layer, which dispatches
    /// nothing more.
    pub(super) fn close(&self) -> impl Iterator<Item = DeclWatchSink> {
        let watches = core::mem::replace(
            &mut lock(&self.table).watches,
            [const { None }; caps::MAX_DECL_WATCHES],
        );
        lock(&self.owed).queue.clear();
        lock(&self.staged).clear();
        watches.into_iter().flatten().filter_map(|watch| watch.sink)
    }

    /// Forget what an earlier dispatch staged and nobody settled: a group's.
    pub(super) fn drop_staged(&self) {
        lock(&self.staged).clear();
    }

    /// The face whose frame was just dispatched told that its peer ended its initial
    /// declarations.
    #[cfg(feature = "declarations-synced-event")]
    pub(super) fn stage_synced(&self) {
        lock(&self.staged).push(Staged::Synced);
    }

    /// Owe each watch what the last dispatch staged of its kind, as the events of the link's peer
    /// `peer`, which is read only when something was staged.
    pub(super) fn settle(&self, peer: impl FnOnce() -> Option<Vec<u8>>) {
        let staged = core::mem::take(&mut *lock(&self.staged));
        if staged.is_empty() {
            return;
        }
        let peer = named(peer);
        let table = lock(&self.table);
        let mut owed = lock(&self.owed);
        for event in &staged {
            for watch in table.watches().filter(|watch| event.reaches(watch.plane)) {
                owed.queue
                    .push_back((watch.id, event.told(peer.as_deref())));
            }
        }
    }

    /// This thread's turn to hand the owed events out, or `None` when none is owed or another
    /// thread's turn is running, which hands out what this one owed too. One thread hands them
    /// out at a time, so a sink taken out of its row for a call is out for that call alone and no
    /// event is passed over for a sink that is out.
    pub(super) fn begin_handing(&self) -> Option<HandingTurn<'_>> {
        let mut owed = lock(&self.owed);
        if owed.queue.is_empty() || owed.handing {
            return None;
        }
        owed.handing = true;
        Some(HandingTurn {
            watches: self,
            over: false,
        })
    }

    /// Put the sink of watch `id` back in its row after its call; the sink again when the watch
    /// went during the call (an undeclare from inside it, or the session's close), for the caller
    /// to let go of with no lock held.
    pub(super) fn put_back(&self, id: DeclWatchId, sink: DeclWatchSink) -> Option<DeclWatchSink> {
        match lock(&self.table).watch_mut(id) {
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
    /// out of its row, in the order the events were owed; an event of a watch undeclared since is
    /// passed over. `None` ends the turn, under the lock an event is owed under, so no event owed
    /// meanwhile is left with no thread to hand it. Each lock is let go of before this returns, so
    /// the sink may reach back into the session.
    pub(super) fn next(&mut self) -> Option<(DeclWatchId, DeclWatchSink, Told)> {
        loop {
            let popped = {
                let mut owed = lock(&self.watches.owed);
                let popped = owed.queue.pop_front();
                if popped.is_none() {
                    owed.handing = false;
                }
                popped
            };
            let Some((id, told)) = popped else {
                self.over = true;
                return None;
            };
            let sink = lock(&self.watches.table)
                .watch_mut(id)
                .and_then(|watch| watch.sink.take());
            if let Some(sink) = sink {
                return Some((id, sink, told));
            }
        }
    }
}

impl Drop for HandingTurn<'_> {
    fn drop(&mut self) {
        // A turn that ended itself is another thread's to begin again, and is not ended twice.
        if !self.over {
            lock(&self.watches.owed).handing = false;
        }
    }
}

/// The observer that stages a declaration of `plane` into `staged`.
fn declared_sink(plane: DeclPlane, staged: &Arc<Mutex<Vec<Staged>>>) -> BoxedDeclSink {
    let staged = Arc::clone(staged);
    BoxedDeclSink::new(move |view: &dyn DeclView| {
        lock(&staged).push(Staged::Declared {
            plane,
            id: view.id(),
            keyexpr: view.keyexpr().to_owned(),
        });
    })
}

/// The observer that stages an undeclaration of `plane` into `staged`.
fn undeclared_sink(plane: DeclPlane, staged: &Arc<Mutex<Vec<Staged>>>) -> BoxedUndeclSink {
    let staged = Arc::clone(staged);
    BoxedUndeclSink::new(move |id: u64| {
        lock(&staged).push(Staged::Undeclared { plane, id });
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
    staged: &Arc<Mutex<Vec<Staged>>>,
) -> Result<Observers, Declined> {
    let declared = declared_sink(plane, staged);
    let undeclared = undeclared_sink(plane, staged);
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

    /// A sink that records each event it is told, as its owned form.
    fn recording() -> (DeclWatchSink, Arc<Mutex<Vec<String>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let into = Arc::clone(&log);
        let sink = DeclWatchSink::shared(move |event: DeclWatchEvent<'_>| {
            lock(&into).push(format!(
                "{:?} {:?} {:?}",
                event.declaration_id(),
                event.keyexpr(),
                event.peer()
            ));
        });
        (sink, log)
    }

    /// Watch `plane` through `sink` in a table with room for it.
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
        match watches.add(app, plane, sink) {
            Ok(id) => id,
            Err((refused, _)) => panic!("a table with room refused the watch: {refused:?}"),
        }
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

        lock(&watches.staged).push(Staged::Declared {
            plane: DeclPlane::Queryables,
            id: 4,
            keyexpr: "demo/q".to_owned(),
        });
        watches.settle(|| Some(PEER.to_vec()));
        assert_eq!(drain(&watches), 1, "one watch of the kind, one event");
        let expected_peer = if cfg!(feature = "remote-declaration-watch") {
            format!("{:?}", Some(&PEER[..]))
        } else {
            format!("{:?}", None::<&[u8]>)
        };
        assert_eq!(
            *lock(&heard),
            [format!("Some(4) Some(\"demo/q\") {expected_peer}")]
        );
        assert!(
            lock(&unheard).is_empty(),
            "a subscriber watch hears no queryable"
        );

        lock(&watches.staged).push(Staged::Undeclared {
            plane: DeclPlane::Queryables,
            id: 4,
        });
        watches.drop_staged();
        watches.settle(|| panic!("nothing staged, so no peer is read"));
        assert_eq!(drain(&watches), 0, "a dropped stage is owed to no one");
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
        lock(&watches.staged).push(Staged::Undeclared {
            plane: DeclPlane::Subscribers,
            id: 9,
        });
        watches.settle(|| None);

        assert!(matches!(watches.undeclare(&mut app, id), Some(Some(_))));
        assert_eq!(drain(&watches), 0, "what was owed went with the watch");
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
        lock(&watches.owed)
            .queue
            .push_back((1, Told::Undeclared { id: 2, peer: None }));
        assert_eq!(watches.close().count(), 1);
        assert_eq!(drain(&watches), 0);
        assert_eq!(lock(&watches.table).watches().count(), 0);
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
        lock(&watches.owed)
            .queue
            .push_back((id, Told::Undeclared { id: 3, peer: None }));
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
        for declared in [1, 2] {
            lock(&watches.owed).queue.push_back((
                id,
                Told::Undeclared {
                    id: declared,
                    peer: None,
                },
            ));
        }
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
            watches.add(&mut app, DeclPlane::Queryables, sink),
            Err((Declined::NotBuilt, _))
        ));
        assert_eq!(Arc::strong_count(&log), 1, "the refused sink is let go of");
        {
            let table = lock(&watches.table);
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
        let watches = DeclWatches::holding(1);
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
        assert_eq!(lock(&watches.table).watches().count(), 1);
    }

    /// The session's limit sets the rows a table admits, under the build's.
    #[test]
    fn the_sessions_limit_sets_the_rows_under_the_builds() {
        let mut limits = SessionLimits::defaults();
        limits
            .select_max_decl_watches(Quota::at_most(1))
            .expect("one watch is within every build's domain");
        let lowered = DeclWatches::under(&limits).expect("a limit under the build's");
        assert_eq!(lock(&lowered.table).most, 1);
        let defaults = DeclWatches::under(&SessionLimits::defaults()).expect("the build's own");
        let expected = SessionLimits::defaults()
            .max_decl_watches()
            .most()
            .map_or(caps::MAX_DECL_WATCHES, |most| {
                most.min(caps::MAX_DECL_WATCHES)
            });
        assert_eq!(lock(&defaults.table).most, expected);
    }
}

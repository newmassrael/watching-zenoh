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
use wz_capi_port::{DeclPlane, DeclWatchEvent, DeclWatchId, DeclWatchRefused, DeclWatchSink};
use wz_session_core::bounded::Storage;
use wz_session_core::decl_sink::{BoxedDeclSink, BoxedUndeclSink, DeclView};
use wz_session_core::slot_observer::{HeapSinks, SlotObserverOf};

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
    sink: DeclWatchSink,
}

/// The observers installed in the application layer for one kind of entity, by the ids that
/// remove them again.
struct Observers {
    plane: DeclPlane,
    declared: u64,
    undeclared: u64,
}

/// The watches and the observers they are told through.
#[derive(Default)]
struct Table {
    watches: Vec<Watch>,
    observers: Vec<Observers>,
    next_id: DeclWatchId,
}

/// The session's declaration watches and what is owed to them. The registry holds it, so a
/// link's dispatch reaches it, and the engine holds it, so its deliveries do.
#[derive(Default)]
pub(super) struct DeclWatches {
    /// Written by the observers while a frame is dispatched, under the session's lock.
    staged: Arc<Mutex<Vec<Staged>>>,
    table: Mutex<Table>,
    owed: Mutex<VecDeque<(DeclWatchId, Told)>>,
}

impl DeclWatches {
    /// Have the observers of `plane` installed in `app`, unless a watch of that kind installed
    /// them already. [`DeclWatchRefused::Full`] when the application layer's list of observers
    /// is at its bound; nothing is installed then.
    ///
    /// Whatever storage `P` the application's tables have: the session's registry holds them in
    /// rows its arena lent, while the lists of observers are the build's profile's in every
    /// observer.
    pub(super) fn observe<P: Storage>(
        &self,
        app: &mut SlotObserverOf<HeapSinks, P>,
        plane: DeclPlane,
    ) -> Result<(), DeclWatchRefused> {
        let mut table = lock(&self.table);
        if table.observers.iter().any(|held| held.plane == plane) {
            return Ok(());
        }
        let observers = install(app, plane, &self.staged)?;
        table.observers.push(observers);
        Ok(())
    }

    /// A watch of `plane` told through `sink` from now on, whose observers are installed
    /// ([`Self::observe`]): its id.
    pub(super) fn add(&self, plane: DeclPlane, sink: DeclWatchSink) -> DeclWatchId {
        let mut table = lock(&self.table);
        table.next_id += 1;
        let id = table.next_id;
        table.watches.push(Watch { id, plane, sink });
        id
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
            owed.push_back((
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
    /// with the last watch of that kind. Its sink, for the caller to let go of with no lock held;
    /// `None` when no watch is declared under `id`.
    pub(super) fn undeclare<P: Storage>(
        &self,
        app: &mut SlotObserverOf<HeapSinks, P>,
        id: DeclWatchId,
    ) -> Option<DeclWatchSink> {
        let mut table = lock(&self.table);
        let at = table.watches.iter().position(|watch| watch.id == id)?;
        let watch = table.watches.remove(at);
        if !table.watches.iter().any(|held| held.plane == watch.plane) {
            if let Some(at) = table
                .observers
                .iter()
                .position(|held| held.plane == watch.plane)
            {
                uninstall(app, table.observers.remove(at));
            }
        }
        drop(table);
        lock(&self.owed).retain(|(owed, _)| *owed != id);
        Some(watch.sink)
    }

    /// The session is closed: every watch goes, with what was owed to it. The sinks, for the
    /// caller to let go of with no lock held. The observers stay in the closed session's
    /// application layer, which dispatches nothing more.
    pub(super) fn close(&self) -> Vec<DeclWatchSink> {
        let watches = core::mem::take(&mut lock(&self.table).watches);
        lock(&self.owed).clear();
        lock(&self.staged).clear();
        watches.into_iter().map(|watch| watch.sink).collect()
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
            for watch in table
                .watches
                .iter()
                .filter(|watch| event.reaches(watch.plane))
            {
                owed.push_back((watch.id, event.told(peer.as_deref())));
            }
        }
    }

    /// The next event to hand out and the sink of the watch it is owed to, in the order they were
    /// owed; an event of a watch undeclared since is passed over. Each lock is let go of before
    /// this returns, so the sink may reach back into the session.
    pub(super) fn next(&self) -> Option<(DeclWatchSink, Told)> {
        loop {
            let (id, told) = lock(&self.owed).pop_front()?;
            let sink = lock(&self.table)
                .watches
                .iter()
                .find(|watch| watch.id == id)
                .map(|watch| Arc::clone(&watch.sink));
            if let Some(sink) = sink {
                return Some((sink, told));
            }
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
fn install<P: Storage>(
    app: &mut SlotObserverOf<HeapSinks, P>,
    plane: DeclPlane,
    staged: &Arc<Mutex<Vec<Staged>>>,
) -> Result<Observers, DeclWatchRefused> {
    let declared = declared_sink(plane, staged);
    let undeclared = undeclared_sink(plane, staged);
    let (declared, undeclared) = match plane {
        DeclPlane::Subscribers => {
            let tables = &mut app.remote_subscribers;
            let declared = tables
                .on_subscriber_declared_sink(declared)
                .map_err(|_| DeclWatchRefused::Full)?;
            match tables.on_subscriber_undeclared_sink(undeclared) {
                Ok(undeclared) => (declared, undeclared),
                Err(_) => {
                    tables.remove_subscriber_declared_sink(declared);
                    return Err(DeclWatchRefused::Full);
                }
            }
        }
        #[cfg(any(feature = "query", feature = "queryable"))]
        DeclPlane::Queryables => {
            let tables = &mut app.remote_queryables;
            let declared = tables
                .on_queryable_declared_sink(declared)
                .map_err(|_| DeclWatchRefused::Full)?;
            match tables.on_queryable_undeclared_sink(undeclared) {
                Ok(undeclared) => (declared, undeclared),
                Err(_) => {
                    tables.remove_queryable_declared_sink(declared);
                    return Err(DeclWatchRefused::Full);
                }
            }
        }
        #[cfg(not(any(feature = "query", feature = "queryable")))]
        DeclPlane::Queryables => return Err(DeclWatchRefused::PlaneNotBuilt),
        #[cfg(feature = "liveliness")]
        DeclPlane::Tokens => {
            let tables = &mut app.liveliness;
            let declared = tables
                .on_token_declared_sink(declared)
                .map_err(|_| DeclWatchRefused::Full)?;
            match tables.on_token_undeclared_sink(undeclared) {
                Ok(undeclared) => (declared, undeclared),
                Err(_) => {
                    tables.remove_token_declared_sink(declared);
                    return Err(DeclWatchRefused::Full);
                }
            }
        }
        #[cfg(not(feature = "liveliness"))]
        DeclPlane::Tokens => return Err(DeclWatchRefused::PlaneNotBuilt),
    };
    Ok(Observers {
        plane,
        declared,
        undeclared,
    })
}

/// Take the two observers `observers` names out of `app`.
fn uninstall<P: Storage>(app: &mut SlotObserverOf<HeapSinks, P>, observers: Observers) {
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
    use wz_session_core::limits::SessionLimits;
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
        let sink: DeclWatchSink = Arc::new(move |event: DeclWatchEvent<'_>| {
            lock(&into).push(format!(
                "{:?} {:?} {:?}",
                event.declaration_id(),
                event.keyexpr(),
                event.peer()
            ));
        });
        (sink, log)
    }

    fn drain(watches: &DeclWatches) -> usize {
        let mut told = 0;
        while let Some((sink, event)) = watches.next() {
            sink(event.event());
            told += 1;
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
        watches
            .observe(&mut app, DeclPlane::Queryables)
            .expect("an observer list with room");
        let (queryables, heard) = recording();
        let (subscribers, unheard) = recording();
        watches.add(DeclPlane::Queryables, queryables);
        watches.add(DeclPlane::Subscribers, subscribers);

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
        watches
            .observe(&mut app, DeclPlane::Subscribers)
            .expect("an observer list with room");
        assert_eq!(app.remote_subscribers.on_decl_len(), 1);
        watches
            .observe(&mut app, DeclPlane::Subscribers)
            .expect("installed already");
        assert_eq!(
            app.remote_subscribers.on_decl_len(),
            1,
            "one pair of observers for every watch of the kind"
        );
        let (sink, log) = recording();
        let id = watches.add(DeclPlane::Subscribers, sink);
        lock(&watches.staged).push(Staged::Undeclared {
            plane: DeclPlane::Subscribers,
            id: 9,
        });
        watches.settle(|| None);

        assert!(watches.undeclare(&mut app, id).is_some());
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
            .lend_keys(1024)
            .expect("the arena holds the key arena");
        let mut app = App::lent(
            arena.arena_mut(),
            keys,
            ObserverRows::default(),
            &SessionLimits::defaults(),
        )
        .expect("the arena has the rows");
        let watches = DeclWatches::default();
        watches
            .observe(&mut app, DeclPlane::Queryables)
            .expect("an observer list with room");
        assert_eq!(app.remote_queryables.on_decl_len(), 1);
        assert_eq!(app.remote_queryables.on_undecl_len(), 1);
        let (sink, _log) = recording();
        let id = watches.add(DeclPlane::Queryables, sink);

        assert!(watches.undeclare(&mut app, id).is_some());
        assert_eq!(app.remote_queryables.on_decl_len(), 0);
        assert_eq!(app.remote_queryables.on_undecl_len(), 0);
    }

    /// A close hands back every sink and leaves nothing owed.
    #[test]
    fn a_close_gives_back_every_sink_and_owes_nothing() {
        let watches = DeclWatches::default();
        let (sink, _log) = recording();
        watches.add(DeclPlane::Subscribers, Arc::clone(&sink));
        lock(&watches.owed).push_back((1, Told::Undeclared { id: 2, peer: None }));
        assert_eq!(watches.close().len(), 1);
        assert_eq!(drain(&watches), 0);
        assert_eq!(
            Arc::strong_count(&sink),
            1,
            "the table holds the sink no more"
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
        assert_eq!(
            watches.observe(&mut app, DeclPlane::Queryables),
            Err(DeclWatchRefused::PlaneNotBuilt)
        );
        assert!(lock(&watches.table).observers.is_empty());
        watches
            .observe(&mut app, DeclPlane::Subscribers)
            .expect("CONTROL: the subscribers' plane is built");
        assert_eq!(app.remote_subscribers.on_decl_len(), 1);
    }
}

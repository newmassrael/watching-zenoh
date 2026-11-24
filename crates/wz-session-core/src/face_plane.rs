// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The faces of the session, as the program's watchers of them are told: each face that comes up
//! or goes is an event queued for the watchers ([`FacePlane::happened`]), and the events are handed
//! out where the session hands out its callbacks, with no lock held, so a watcher that reaches back
//! into the session (one that lists the transports) finds it free.
//!
//! An event is queued only while something watches: the face the open brought up is not announced
//! to a watcher that came after it, which reads the faces that stand for its history, as
//! zenoh-pico's listener does.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::face::{FaceEventKind, FaceEventSink, FaceSnapshot};
use crate::plane_lock::LockFamily;

/// The watchers, each under the id that stops it.
struct Watchers {
    /// The id the last watcher was given, `0` before the first.
    last: u64,
    sinks: Vec<(u64, FaceEventSink)>,
}

/// The watchers of the session's faces and the events waiting for them, each under a lock of the
/// engine's ([`LockFamily`]).
pub struct FacePlane<K: LockFamily> {
    watchers: K::Lock<Watchers>,
    events: K::Lock<VecDeque<(FaceEventKind, FaceSnapshot)>>,
}

impl<K: LockFamily> Default for FacePlane<K> {
    fn default() -> Self {
        Self {
            watchers: K::new(Watchers {
                last: 0,
                sinks: Vec::new(),
            }),
            events: K::new(VecDeque::new()),
        }
    }
}

impl<K: LockFamily> FacePlane<K> {
    /// Tell `sink` of each face event from now on, under the id that stops it: from 1, one past
    /// the last watcher's.
    pub fn watch(&self, sink: FaceEventSink) -> u64 {
        K::with(&self.watchers, |watchers| {
            watchers.last = watchers.last.wrapping_add(1);
            watchers.sinks.push((watchers.last, sink));
            watchers.last
        })
    }

    /// Stop watcher `id`: `true` when one was registered under it.
    pub fn unwatch(&self, id: u64) -> bool {
        K::with(&self.watchers, |watchers| {
            let before = watchers.sinks.len();
            watchers.sinks.retain(|(held, _)| *held != id);
            watchers.sinks.len() != before
        })
    }

    /// Whether anything watches, which is whether an event is worth the snapshot it carries.
    pub fn watched(&self) -> bool {
        K::with(&self.watchers, |watchers| !watchers.sinks.is_empty())
    }

    /// Queue a face event for the watchers, to be handed out with the session's other deliveries.
    pub fn happened(&self, kind: FaceEventKind, snapshot: FaceSnapshot) {
        K::with(&self.events, |events| events.push_back((kind, snapshot)));
    }

    /// The next event to hand out, in the order they happened.
    pub fn next_event(&self) -> Option<(FaceEventKind, FaceSnapshot)> {
        K::with(&self.events, VecDeque::pop_front)
    }

    /// The watchers as they stand, cloned out of their lock: a sink may stop a watcher.
    pub fn sinks(&self) -> Vec<FaceEventSink> {
        K::with(&self.watchers, |watchers| {
            watchers
                .sinks
                .iter()
                .map(|(_, sink)| Arc::clone(sink))
                .collect()
        })
    }
}

/// Where a session reports its faces coming up and going: a [`FacePlane`], or `()` for an engine
/// whose build watches no face, which reports nothing and for which no snapshot is made.
pub trait FaceReports {
    /// Whether anything can watch: `false` for a report that is never read, so a snapshot for it
    /// is not made.
    const WATCHES: bool;

    /// Whether anything watches now.
    fn watched(&self) -> bool;

    /// Report that the face `snapshot` came up or went.
    fn happened(&self, kind: FaceEventKind, snapshot: FaceSnapshot);
}

impl FaceReports for () {
    const WATCHES: bool = false;

    #[inline]
    fn watched(&self) -> bool {
        false
    }

    #[inline]
    fn happened(&self, _kind: FaceEventKind, _snapshot: FaceSnapshot) {}
}

impl<K: LockFamily> FaceReports for FacePlane<K> {
    const WATCHES: bool = true;

    fn watched(&self) -> bool {
        FacePlane::watched(self)
    }

    fn happened(&self, kind: FaceEventKind, snapshot: FaceSnapshot) {
        FacePlane::happened(self, kind, snapshot);
    }
}

impl<T: FaceReports> FaceReports for Arc<T> {
    const WATCHES: bool = T::WATCHES;

    fn watched(&self) -> bool {
        T::watched(self)
    }

    fn happened(&self, kind: FaceEventKind, snapshot: FaceSnapshot) {
        T::happened(self, kind, snapshot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// Locks of one thread, which is all a test needs.
    enum CellLocks {}

    impl LockFamily for CellLocks {
        type Lock<T> = RefCell<T>;

        fn new<T>(value: T) -> RefCell<T> {
            RefCell::new(value)
        }

        fn with<T, R>(lock: &RefCell<T>, f: impl FnOnce(&mut T) -> R) -> R {
            f(&mut lock.borrow_mut())
        }
    }

    fn face(zid: u8) -> FaceSnapshot {
        FaceSnapshot {
            zid: [zid; 16],
            whatami: 0,
            is_qos: false,
            is_multicast: false,
            is_shm: false,
            links: Vec::new(),
        }
    }

    /// Watchers are numbered from 1, each stopped by its own id once; the plane is watched while
    /// one is left.
    #[test]
    fn a_watcher_is_stopped_by_its_id_once() {
        let plane = FacePlane::<CellLocks>::default();
        assert!(!plane.watched());
        let sink: FaceEventSink = Arc::new(|_, _| {});
        let first = plane.watch(Arc::clone(&sink));
        let second = plane.watch(sink);
        assert_eq!((first, second), (1, 2));
        assert!(plane.unwatch(first));
        assert!(!plane.unwatch(first), "a stopped watcher is stopped once");
        assert!(plane.watched());
        assert_eq!(plane.sinks().len(), 1);
        assert!(plane.unwatch(second));
        assert!(!plane.watched());
    }

    /// Events are handed out in the order they happened, each once.
    #[test]
    fn events_are_handed_out_in_the_order_they_happened() {
        let plane = FacePlane::<CellLocks>::default();
        plane.happened(FaceEventKind::Up, face(1));
        plane.happened(FaceEventKind::Down, face(2));
        let (kind, first) = plane.next_event().unwrap();
        assert_eq!((kind, first.zid[0]), (FaceEventKind::Up, 1));
        let (kind, second) = plane.next_event().unwrap();
        assert_eq!((kind, second.zid[0]), (FaceEventKind::Down, 2));
        assert!(plane.next_event().is_none());
    }

    /// A report through `()` is never watched and keeps nothing; through a plane it is queued,
    /// whether the plane is held by itself or shared.
    #[test]
    fn a_report_reaches_a_plane_and_nothing_reaches_unit() {
        let watches = [
            <() as FaceReports>::WATCHES,
            <Arc<FacePlane<CellLocks>> as FaceReports>::WATCHES,
        ];
        assert_eq!(watches, [false, true]);
        assert!(!FaceReports::watched(&()));
        FaceReports::happened(&(), FaceEventKind::Up, face(1));
        let plane = Arc::new(FacePlane::<CellLocks>::default());
        let told = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&told);
        plane.watch(Arc::new(move |_, _| {
            count.fetch_add(1, Ordering::Relaxed);
        }));
        assert!(FaceReports::watched(&plane));
        FaceReports::happened(&plane, FaceEventKind::Up, face(3));
        let (kind, snapshot) = plane.next_event().unwrap();
        assert_eq!((kind, snapshot.zid[0]), (FaceEventKind::Up, 3));
        for sink in plane.sinks() {
            sink(kind, &snapshot);
        }
        assert_eq!(told.load(Ordering::Relaxed), 1);
    }
}

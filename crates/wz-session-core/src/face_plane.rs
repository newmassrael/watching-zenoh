// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The faces of the session, as the program's watchers of them are told: each face that comes up
//! or goes is queued for the watchers a row at a time ([`FacePlane::happened`]), and the rows are
//! handed out where the session hands out its callbacks, with no lock held, so a watcher that
//! reaches back into the session (one that lists the transports) finds it free.
//!
//! A row is queued only while something watches: the face the open brought up is not announced
//! to a watcher that came after it, which reads the faces that stand for its history, as
//! zenoh-pico's listener does.
//!
//! The queue's rows are reserved with the first watch, as many as the plane was made to hold, so
//! a face told while it is watched is queued and handed out with nothing allocated. A burst past
//! them, which only a watcher that holds the delivery while the faces turn over reaches, grows
//! the queue rather than lose a row a listener's view of the faces rests on.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::face::{FaceEventKind, FaceLinkRow, FaceRowSink};
use crate::plane_lock::LockFamily;

/// The watchers, each under the id that stops it, in the order of their ids.
struct Watchers {
    /// The id the last watcher was given, `0` before the first.
    last: u64,
    sinks: Vec<(u64, FaceRowSink)>,
}

/// The watchers of the session's faces and the rows waiting for them, each under a lock of the
/// engine's ([`LockFamily`]).
pub struct FacePlane<K: LockFamily> {
    watchers: K::Lock<Watchers>,
    events: K::Lock<VecDeque<(FaceEventKind, FaceLinkRow)>>,
    /// The rows the queue holds without growing, reserved with the first watch.
    room: usize,
}

impl<K: LockFamily> Default for FacePlane<K> {
    /// A plane whose queue reserves no row: each row queued may grow it.
    fn default() -> Self {
        Self::with_room(0)
    }
}

impl<K: LockFamily> FacePlane<K> {
    /// A plane whose queue holds `room` rows without growing, reserved when something first
    /// watches: a session nobody watches holds none of them.
    pub fn with_room(room: usize) -> Self {
        Self {
            watchers: K::new(Watchers {
                last: 0,
                sinks: Vec::new(),
            }),
            events: K::new(VecDeque::new()),
            room,
        }
    }

    /// Tell `sink` each row of a face event from now on, under the id that stops it: from 1, one
    /// past the last watcher's. The queue's rows are reserved here, with the watch.
    pub fn watch(&self, sink: FaceRowSink) -> u64 {
        K::with(&self.events, |events| {
            events.reserve(self.room.saturating_sub(events.len()));
        });
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

    /// Whether anything watches, which is whether a face event is worth its rows.
    pub fn watched(&self) -> bool {
        K::with(&self.watchers, |watchers| !watchers.sinks.is_empty())
    }

    /// Queue a row of a face event for the watchers, to be handed out with the session's other
    /// deliveries.
    pub fn happened(&self, kind: FaceEventKind, row: FaceLinkRow) {
        K::with(&self.events, |events| events.push_back((kind, row)));
    }

    /// The next row to hand out, in the order they happened.
    pub fn next_event(&self) -> Option<(FaceEventKind, FaceLinkRow)> {
        K::with(&self.events, VecDeque::pop_front)
    }

    /// Hand the next row to each watcher that stood when it was taken, in the order they came:
    /// whether there was one. Each watcher is taken out of the lock alone and called with no lock
    /// held, so a sink that stops a watcher, its own or a later one, finds the plane free, and the
    /// watchers after it are still told; the list is not copied for the row.
    pub fn hand_out_next(&self) -> bool {
        let Some((kind, row)) = self.next_event() else {
            return false;
        };
        let last = K::with(&self.watchers, |watchers| watchers.last);
        let mut after = 0;
        while let Some((id, sink)) = self.sink_after(after, last) {
            sink(kind, &row);
            after = id;
        }
        true
    }

    /// The first watcher whose id is past `after` and not past `last`, with its id.
    fn sink_after(&self, after: u64, last: u64) -> Option<(u64, FaceRowSink)> {
        K::with(&self.watchers, |watchers| {
            watchers
                .sinks
                .iter()
                .find(|(id, _)| *id > after && *id <= last)
                .map(|(id, sink)| (*id, Arc::clone(sink)))
        })
    }
}

/// Where a session reports its faces coming up and going: a [`FacePlane`], or `()` for an engine
/// whose build watches no face, which reports nothing and for which no row is read.
pub trait FaceReports {
    /// Whether anything can watch: `false` for a report that is never read, so no row is read
    /// for it.
    const WATCHES: bool;

    /// Whether anything watches now.
    fn watched(&self) -> bool;

    /// Report a row of a face that came up or went.
    fn happened(&self, kind: FaceEventKind, row: FaceLinkRow);
}

impl FaceReports for () {
    const WATCHES: bool = false;

    #[inline]
    fn watched(&self) -> bool {
        false
    }

    #[inline]
    fn happened(&self, _kind: FaceEventKind, _row: FaceLinkRow) {}
}

impl<K: LockFamily> FaceReports for FacePlane<K> {
    const WATCHES: bool = true;

    fn watched(&self) -> bool {
        FacePlane::watched(self)
    }

    fn happened(&self, kind: FaceEventKind, row: FaceLinkRow) {
        FacePlane::happened(self, kind, row);
    }
}

impl<T: FaceReports> FaceReports for Arc<T> {
    const WATCHES: bool = T::WATCHES;

    fn watched(&self) -> bool {
        T::watched(self)
    }

    fn happened(&self, kind: FaceEventKind, row: FaceLinkRow) {
        T::happened(self, kind, row);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::face::RowText;
    // The host's mutex: a plane shared behind an `Arc` is reached from any thread, as an engine's is.
    use crate::plane_lock::StdLocks;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn row(zid: u8) -> FaceLinkRow {
        FaceLinkRow {
            zid: [zid; 16],
            whatami: 0,
            is_qos: false,
            is_multicast: false,
            is_shm: false,
            link: 0,
            links: 1,
            src: RowText::of("tcp/127.0.0.1:1"),
            dst: RowText::of("tcp/127.0.0.1:2"),
            kind: None,
            mtu: 0,
            group_endpoint: None,
        }
    }

    /// A sink that counts the rows it is told.
    fn counting(told: &Arc<AtomicUsize>) -> FaceRowSink {
        let count = Arc::clone(told);
        Arc::new(move |_, _| {
            count.fetch_add(1, Ordering::Relaxed);
        })
    }

    /// Watchers are numbered from 1, each stopped by its own id once; the plane is watched while
    /// one is left, and only that one is told.
    #[test]
    fn a_watcher_is_stopped_by_its_id_once() {
        let plane = FacePlane::<StdLocks>::default();
        assert!(!plane.watched());
        let (first_told, second_told) = (Arc::default(), Arc::default());
        let first = plane.watch(counting(&first_told));
        let second = plane.watch(counting(&second_told));
        assert_eq!((first, second), (1, 2));
        assert!(plane.unwatch(first));
        assert!(!plane.unwatch(first), "a stopped watcher is stopped once");
        assert!(plane.watched());
        plane.happened(FaceEventKind::Up, row(1));
        assert!(plane.hand_out_next());
        assert_eq!(
            (
                first_told.load(Ordering::Relaxed),
                second_told.load(Ordering::Relaxed)
            ),
            (0, 1),
            "only the watcher left is told"
        );
        assert!(plane.unwatch(second));
        assert!(!plane.watched());
    }

    /// Rows are handed out in the order they happened, each once.
    #[test]
    fn rows_are_handed_out_in_the_order_they_happened() {
        let plane = FacePlane::<StdLocks>::default();
        plane.happened(FaceEventKind::Up, row(1));
        plane.happened(FaceEventKind::Down, row(2));
        let (kind, first) = plane.next_event().unwrap();
        assert_eq!((kind, first.zid[0]), (FaceEventKind::Up, 1));
        let (kind, second) = plane.next_event().unwrap();
        assert_eq!((kind, second.zid[0]), (FaceEventKind::Down, 2));
        assert!(plane.next_event().is_none());
        assert!(!plane.hand_out_next(), "nothing to hand out");
    }

    /// A watcher that stops the next one while it is told a row leaves the one after that told,
    /// and a watcher that comes while a row is handed out is not told that row. Turned red by a
    /// walk over the watchers by their place in the list, which skips the one that moved into the
    /// stopped watcher's place, or by one that reads the watchers anew past the row's last.
    #[test]
    fn a_watcher_stopped_or_added_during_a_hand_out_leaves_the_others_told_once() {
        let plane = Arc::new(FacePlane::<StdLocks>::default());
        let told = Arc::new(Mutex::new(Vec::new()));
        let second = Arc::new(AtomicU64::new(0));
        let (into, by, stop) = (Arc::clone(&told), Arc::clone(&plane), Arc::clone(&second));
        plane.watch(Arc::new(move |_, _| {
            into.lock().unwrap().push(1);
            by.unwatch(stop.load(Ordering::Relaxed));
            let into = Arc::clone(&into);
            by.watch(Arc::new(move |_, _| into.lock().unwrap().push(4)));
        }));
        let into = Arc::clone(&told);
        let id = plane.watch(Arc::new(move |_, _| into.lock().unwrap().push(2)));
        second.store(id, Ordering::Relaxed);
        let into = Arc::clone(&told);
        plane.watch(Arc::new(move |_, _| into.lock().unwrap().push(3)));
        plane.happened(FaceEventKind::Up, row(1));
        assert!(plane.hand_out_next());
        assert_eq!(*told.lock().unwrap(), [1, 3]);
    }

    /// The queue's rows are reserved with the first watch, as many as the plane was made to hold,
    /// and rows queued and handed out within them do not grow it: what lets a face told while it
    /// is watched take no memory of the heap. Turned red by a watch that reserves nothing, whose
    /// first row grows the queue.
    #[test]
    fn the_rows_a_plane_holds_are_reserved_with_the_first_watch() {
        let plane = FacePlane::<StdLocks>::with_room(4);
        let reserved = || StdLocks::with(&plane.events, |events| events.capacity());
        assert_eq!(reserved(), 0, "a plane nobody watches holds no row");
        let told = Arc::default();
        plane.watch(counting(&told));
        let room = reserved();
        assert!(room >= 4, "the rows are reserved with the watch: {room}");
        for zid in 0..4 {
            plane.happened(FaceEventKind::Up, row(zid));
        }
        while plane.hand_out_next() {}
        assert_eq!(
            reserved(),
            room,
            "rows within the room do not grow the queue"
        );
        assert_eq!(told.load(Ordering::Relaxed), 4);
    }

    /// A report through `()` is never watched and keeps nothing; through a plane it is queued,
    /// whether the plane is held by itself or shared.
    #[test]
    fn a_report_reaches_a_plane_and_nothing_reaches_unit() {
        let watches = [
            <() as FaceReports>::WATCHES,
            <Arc<FacePlane<StdLocks>> as FaceReports>::WATCHES,
        ];
        assert_eq!(watches, [false, true]);
        assert!(!FaceReports::watched(&()));
        FaceReports::happened(&(), FaceEventKind::Up, row(1));
        let plane = Arc::new(FacePlane::<StdLocks>::default());
        let told = Arc::new(AtomicUsize::new(0));
        plane.watch(counting(&told));
        assert!(FaceReports::watched(&plane));
        FaceReports::happened(&plane, FaceEventKind::Up, row(3));
        assert!(plane.hand_out_next());
        assert_eq!(told.load(Ordering::Relaxed), 1);
        assert!(!plane.hand_out_next());
    }
}

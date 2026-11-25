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
//! The queue's rows are reserved when the plane is made, which an engine does at its open, so a
//! program that watches only after the open is told its faces with nothing allocated. A row that
//! finds every row held is not kept, and the queue does not grow for it: the rows lost are counted
//! on the last row kept ([`FaceLinkRow::lost_after`]), which tells each watcher of them once.
//!
//! [`FacePlane::happened`]: crate::face_plane::FacePlane::happened
//! [`FaceLinkRow::lost_after`]: crate::face::FaceLinkRow::lost_after

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
    /// The rows the queue holds, reserved when the plane was made; it never holds more.
    room: usize,
}

impl<K: LockFamily> Default for FacePlane<K> {
    /// A plane whose queue holds the build's rows ([`crate::caps::MAX_FACE_WATCH_ROWS`]).
    fn default() -> Self {
        Self::with_room(crate::caps::MAX_FACE_WATCH_ROWS)
    }
}

impl<K: LockFamily> FacePlane<K> {
    /// A plane whose queue holds `room` rows, reserved here: a watch that comes after the plane
    /// was made, and every row told within them, allocates nothing for the queue. A plane of no
    /// room keeps no row and has none to tell a loss with, so an engine makes one of at least one.
    pub fn with_room(room: usize) -> Self {
        Self {
            watchers: K::new(Watchers {
                last: 0,
                sinks: Vec::new(),
            }),
            events: K::new(VecDeque::with_capacity(room)),
            room,
        }
    }

    /// The rows the queue holds between two hand-outs.
    pub fn room(&self) -> usize {
        self.room
    }

    /// Tell `sink` each row of a face event from now on, under the id that stops it: from 1, one
    /// past the last watcher's.
    pub fn watch(&self, sink: FaceRowSink) -> u64 {
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
    /// deliveries. A row that finds the queue's room held is let go of and counted on the last
    /// row queued, which tells the watchers of it with that row ([`FaceLinkRow::lost_after`]).
    pub fn happened(&self, kind: FaceEventKind, row: FaceLinkRow) {
        K::with(&self.events, |events| {
            if events.len() < self.room {
                events.push_back((kind, row));
            } else if let Some((_, last)) = events.back_mut() {
                last.lost_after = last.lost_after.saturating_add(1);
            }
        });
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
            lost_after: 0,
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

    /// The queue's rows are reserved when the plane is made, before anything watches, and rows
    /// queued and handed out within them do not grow it: what lets a program that watches only
    /// after the open be told its faces with no memory of the heap. Turned red by rows reserved
    /// with the first watch instead, which a watch after the open would allocate.
    #[test]
    fn the_rows_a_plane_holds_are_reserved_when_it_is_made() {
        let plane = FacePlane::<StdLocks>::with_room(4);
        let reserved = || StdLocks::with(&plane.events, |events| events.capacity());
        let room = reserved();
        assert!(room >= 4, "the rows are reserved with the plane: {room}");
        assert_eq!(plane.room(), 4);
        let told = Arc::default();
        plane.watch(counting(&told));
        assert_eq!(reserved(), room, "the watch reserves nothing more");
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

    /// Rows past the queue's room are let go of, the queue not grown for them, and counted on the
    /// last row kept, which tells each watcher once how many were lost after it; a row queued once
    /// there is room again tells none. Turned red by a queue that grows past its room (every row
    /// told, none lost), by a loss counted on no row, or by a count told again with a later row.
    #[test]
    fn rows_past_the_room_are_lost_and_told_once_with_the_last_row_kept() {
        let plane = FacePlane::<StdLocks>::with_room(2);
        let reserved = || StdLocks::with(&plane.events, |events| events.capacity());
        let room = reserved();
        let told = Arc::new(Mutex::new(Vec::new()));
        let into = Arc::clone(&told);
        plane.watch(Arc::new(move |_, row: &FaceLinkRow| {
            into.lock().unwrap().push((row.zid[0], row.lost_after));
        }));
        for zid in 1..=5 {
            plane.happened(FaceEventKind::Up, row(zid));
        }
        assert_eq!(reserved(), room, "the queue does not grow past its room");
        while plane.hand_out_next() {}
        assert_eq!(
            *told.lock().unwrap(),
            [(1, 0), (2, 3)],
            "the two rows kept, the last telling the three lost after it"
        );
        plane.happened(FaceEventKind::Down, row(6));
        assert!(plane.hand_out_next());
        assert_eq!(
            told.lock().unwrap().last().copied(),
            Some((6, 0)),
            "the loss is told once"
        );
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

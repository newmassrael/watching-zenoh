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
//! The watchers and the queue's rows lie in the plane, as many as the build holds
//! ([`MAX_WATCHERS`], [`crate::caps::MAX_FACE_WATCH_ROWS`]), so a plane placed where the session
//! opened ([`FacePlane::place_in`]) is watched and told its faces with nothing allocated. A watch
//! past the watchers' bound is refused. A row that finds every row held is not kept: the rows
//! lost are counted on the last row kept ([`FaceLinkRow::lost_after`]), which tells each watcher
//! of them once.
//!
//! [`MAX_WATCHERS`]: crate::face_plane::MAX_WATCHERS
//! [`FacePlane::happened`]: crate::face_plane::FacePlane::happened
//! [`FacePlane::place_in`]: crate::face_plane::FacePlane::place_in
//! [`FaceLinkRow::lost_after`]: crate::face::FaceLinkRow::lost_after

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;

use crate::bounded::{Arena, CapacityFull, LendRefused};
use crate::caps::MAX_FACE_WATCH_ROWS;
use crate::face::{FaceEventKind, FaceLinkRow, FaceRowSink};
use crate::placed::Placed;
use crate::plane_lock::{LockFamily, Pending, Queued};

/// The watchers a plane holds at once: one for each connectivity listener the session holds, of
/// transports and of links, which is the most a program that declares a watch for each of its
/// listeners asks for. A watch past them is refused.
pub const MAX_WATCHERS: usize =
    crate::caps::MAX_TRANSPORT_EVENTS_LISTENERS + crate::caps::MAX_LINK_EVENTS_LISTENERS;

/// A row of a face event as the queue holds it.
type Event = (FaceEventKind, FaceLinkRow);
use core::ptr::{addr_of_mut, NonNull};

/// The watchers, each under the id that stops it, in the order of their ids.
struct Watchers {
    /// The id the last watcher was given, `0` before the first.
    last: u64,
    sinks: heapless::Vec<(u64, FaceRowSink), MAX_WATCHERS>,
}

/// Which of the plane's rows wait to be handed out: `len` of them from `first`, the rows taken
/// in a ring.
struct Waiting {
    first: usize,
    len: usize,
}

impl Pending for Waiting {
    fn is_pending(&self) -> bool {
        self.len != 0
    }
}

/// The queue's rows, each holding a value while [`Waiting`] counts it and none otherwise.
struct Rows(UnsafeCell<[MaybeUninit<Event>; MAX_FACE_WATCH_ROWS]>);

// SAFETY: a row is read or written only with the lock of the plane's `events` held
// (`FacePlane::row_at`), so a shared plane hands each row to one thread at a time, as the lock
// would were the rows inside it; a row moved to another thread is `Send`, as `FaceLinkRow` is.
unsafe impl Sync for Rows {}

/// The watchers of the session's faces and the rows waiting for them, each under a lock of the
/// engine's ([`LockFamily`]).
pub struct FacePlane<K: LockFamily> {
    watchers: K::Lock<Watchers>,
    /// Which rows wait, whose emptiness every delivery reads with no lock taken: it looks for a
    /// row on each of its passes and almost never finds one. Its lock is the rows' too.
    events: Queued<K, Waiting>,
    rows: Rows,
    /// The rows the queue holds, at most the build's; it never holds more.
    room: usize,
}

impl<K: LockFamily> FacePlane<K> {
    /// A plane whose queue holds `room` rows, at most the build's, made in `at` with its locks:
    /// the rows lie in the plane, so a watch that comes after the plane was made, and every row
    /// told within them, allocates nothing. A plane of no room keeps no row and has none to tell a
    /// loss with, so an engine makes one of at least one.
    ///
    /// # Safety
    /// `at` is valid for writes of a `Self` and aligned for it, and what it held is overwritten
    /// without being dropped. The plane is not moved from `at` until it is dropped there.
    pub unsafe fn init_at(at: NonNull<Self>, room: usize) {
        let at = at.as_ptr();
        // SAFETY: `at` is valid for writes of a `Self` that stays there (the caller's contract),
        // so each field is too, and each but the rows is written once; the rows hold no value,
        // which a row of `MaybeUninit` is valid as.
        unsafe {
            K::init_at(
                NonNull::new_unchecked(addr_of_mut!((*at).watchers)),
                |watchers| watchers.write(Self::no_watcher()),
            );
            Queued::init_at(
                NonNull::new_unchecked(addr_of_mut!((*at).events)),
                |events| events.write(Waiting { first: 0, len: 0 }),
            );
            addr_of_mut!((*at).room).write(room.min(MAX_FACE_WATCH_ROWS));
        }
    }

    /// A plane as [`Self::init_at`] makes it, built in the next span of `arena`, where it lies
    /// for as long as the owner handed back: its rows, which are most of its bytes, are never in
    /// a frame. Refused, as the arena refuses the span, past what is left.
    pub fn place_in(arena: &mut Arena, room: usize) -> Result<Placed<Self>, LendRefused> {
        // SAFETY: `place_with` hands a place aligned for a plane and valid for writes of one,
        // where it stays, and `init_at` leaves a whole plane there.
        unsafe { arena.place_with(|at: *mut Self| Self::init_at(NonNull::new_unchecked(at), room)) }
    }

    /// The watchers of a plane no one watches yet.
    fn no_watcher() -> Watchers {
        Watchers {
            last: 0,
            sinks: heapless::Vec::new(),
        }
    }

    /// The rows the queue holds between two hand-outs.
    pub fn room(&self) -> usize {
        self.room
    }

    /// Tell `sink` each row of a face event from now on, under the id that stops it: from 1, one
    /// past the last watcher's. Refused, with `sink` handed back to be let go of by the caller
    /// with no lock of the plane held and no id taken, when the plane holds [`MAX_WATCHERS`].
    pub fn watch(&self, sink: FaceRowSink) -> Result<u64, CapacityFull<FaceRowSink>> {
        K::with(&self.watchers, |watchers| {
            let id = watchers.last.wrapping_add(1);
            watchers
                .sinks
                .push((id, sink))
                .map_err(|(_, sink)| CapacityFull(sink))?;
            watchers.last = id;
            Ok(id)
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
        self.events.with(|waiting| {
            if waiting.len < self.room {
                let at = self.row_at(Self::ring(waiting.first, waiting.len));
                // SAFETY: the lock of `events` is held (`Self::row_at`); the row is the one past
                // the last waiting, within the room, so it holds no value.
                unsafe { at.cast::<Event>().write((kind, row)) };
                // Below the room, so one more is still within it.
                waiting.len = waiting.len.saturating_add(1);
            } else if let Some(last) = waiting.len.checked_sub(1) {
                let at = self.row_at(Self::ring(waiting.first, last));
                // SAFETY: the lock of `events` is held; the row is the last waiting, which holds a
                // value.
                let (_, last) = unsafe { &mut *at.cast::<Event>() };
                last.lost_after = last.lost_after.saturating_add(1);
            }
        });
    }

    /// The next row to hand out, in the order they happened.
    pub fn next_event(&self) -> Option<(FaceEventKind, FaceLinkRow)> {
        if !self.events.is_pending() {
            return None;
        }
        self.events.with(|waiting| {
            let left = waiting.len.checked_sub(1)?;
            let at = self.row_at(waiting.first);
            waiting.first = Self::ring(waiting.first, 1);
            waiting.len = left;
            // SAFETY: the lock of `events` is held; the row was the first waiting, so it holds a
            // value, read out once here and no longer counted as waiting.
            Some(unsafe { at.cast::<Event>().read() })
        })
    }

    /// The row `offset` rows after the row `first`, round the ring.
    fn ring(first: usize, offset: usize) -> usize {
        first.wrapping_add(offset) % MAX_FACE_WATCH_ROWS
    }

    /// The row `at` of the queue, which is read or written only with the lock of `events` held:
    /// what lets [`Rows`] be shared.
    fn row_at(&self, at: usize) -> *mut MaybeUninit<Event> {
        let rows = self.rows.0.get().cast::<MaybeUninit<Event>>();
        // `at` is a row of the ring (`Self::ring`), inside the rows; the address is formed with
        // no access.
        rows.wrapping_add(at)
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
            sink.tell(kind, &row);
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
                .map(|(id, sink)| (*id, sink.clone()))
        })
    }
}

impl<K: LockFamily> Drop for FacePlane<K> {
    /// The rows still waiting are let go of with the plane: a row that spilled its text holds it
    /// on the heap.
    fn drop(&mut self) {
        while self.next_event().is_some() {}
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

/// The owner of a plane placed in a session's arena, which the session's state holds.
impl<T: FaceReports> FaceReports for crate::placed::Placed<T> {
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
    use alloc::vec::Vec;
    // The host's mutex: a plane shared behind an `Arc` is reached from any thread, as an engine's is.
    use crate::plane_lock::StdLocks;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// A plane whose queue holds `room` rows, made in a box of its own.
    fn plane<K: LockFamily>(room: usize) -> alloc::boxed::Box<FacePlane<K>> {
        // SAFETY: the box's place is valid for writes of the plane, which stays there.
        crate::plane_lock::boxed_at(|at| unsafe { FacePlane::init_at(at, room) })
    }

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

    /// A watcher in a box of its own, told through `tell`.
    fn shared_sink(
        tell: impl Fn(FaceEventKind, &FaceLinkRow) + Send + Sync + 'static,
    ) -> FaceRowSink {
        FaceRowSink::of_arc(Arc::new(tell))
    }

    /// A sink that counts the rows it is told.
    fn counting(told: &Arc<AtomicUsize>) -> FaceRowSink {
        let count = Arc::clone(told);
        shared_sink(move |_, _| {
            count.fetch_add(1, Ordering::Relaxed);
        })
    }

    /// Watchers are numbered from 1, each stopped by its own id once; the plane is watched while
    /// one is left, and only that one is told.
    #[test]
    fn a_watcher_is_stopped_by_its_id_once() {
        let plane = plane::<StdLocks>(crate::caps::MAX_FACE_WATCH_ROWS);
        assert!(!plane.watched());
        let (first_told, second_told) = (Arc::default(), Arc::default());
        let first = plane.watch(counting(&first_told)).unwrap();
        let second = plane.watch(counting(&second_told)).unwrap();
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

    /// The host's mutex, counting each time a lock of the family is taken.
    enum CountedLocks {}

    static TAKEN: AtomicUsize = AtomicUsize::new(0);

    impl LockFamily for CountedLocks {
        type Lock<T> = Mutex<T>;

        unsafe fn init_at<T>(
            place: NonNull<Mutex<T>>,
            make: impl FnOnce(&mut core::mem::MaybeUninit<T>) -> &mut T,
        ) {
            // SAFETY: `place` is valid for writes of the lock (the caller's contract).
            unsafe {
                place
                    .as_ptr()
                    .write(Mutex::new(crate::plane_lock::made_value(make)))
            }
        }

        fn with<T, R>(lock: &Mutex<T>, f: impl FnOnce(&mut T) -> R) -> R {
            TAKEN.fetch_add(1, Ordering::Relaxed);
            f(&mut lock.lock().unwrap())
        }
    }

    /// Every delivery asks the plane for a row, and almost always finds none: an empty queue is
    /// answered with no lock taken, and a row queued is still found. Turned red by a look for the
    /// next row that takes the queue's lock whether or not it holds one.
    #[test]
    fn an_empty_queue_is_answered_with_no_lock_taken() {
        let plane = plane::<CountedLocks>(crate::caps::MAX_FACE_WATCH_ROWS);
        let before = TAKEN.load(Ordering::Relaxed);
        assert!(plane.next_event().is_none());
        assert!(!plane.hand_out_next());
        assert_eq!(TAKEN.load(Ordering::Relaxed), before, "no lock for no row");
        plane.happened(FaceEventKind::Up, row(1));
        let (kind, held) = plane.next_event().expect("the row queued is found");
        assert_eq!((kind, held.zid[0]), (FaceEventKind::Up, 1));
        let after = TAKEN.load(Ordering::Relaxed);
        assert!(!plane.hand_out_next());
        assert_eq!(
            TAKEN.load(Ordering::Relaxed),
            after,
            "the last row taken leaves it clear"
        );
    }

    /// Rows are handed out in the order they happened, each once.
    #[test]
    fn rows_are_handed_out_in_the_order_they_happened() {
        let plane = plane::<StdLocks>(crate::caps::MAX_FACE_WATCH_ROWS);
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
        let plane =
            Arc::<FacePlane<StdLocks>>::from(plane::<StdLocks>(crate::caps::MAX_FACE_WATCH_ROWS));
        let told = Arc::new(Mutex::new(Vec::new()));
        let second = Arc::new(AtomicU64::new(0));
        let (into, by, stop) = (Arc::clone(&told), Arc::clone(&plane), Arc::clone(&second));
        plane
            .watch(shared_sink(move |_, _| {
                into.lock().unwrap().push(1);
                by.unwatch(stop.load(Ordering::Relaxed));
                let into = Arc::clone(&into);
                assert!(by
                    .watch(shared_sink(move |_, _| into.lock().unwrap().push(4)))
                    .is_ok());
            }))
            .unwrap();
        let into = Arc::clone(&told);
        let id = plane
            .watch(shared_sink(move |_, _| into.lock().unwrap().push(2)))
            .unwrap();
        second.store(id, Ordering::Relaxed);
        let into = Arc::clone(&told);
        plane
            .watch(shared_sink(move |_, _| into.lock().unwrap().push(3)))
            .unwrap();
        plane.happened(FaceEventKind::Up, row(1));
        assert!(plane.hand_out_next());
        assert_eq!(*told.lock().unwrap(), [1, 3]);
    }

    /// The queue's rows lie in the plane itself, as many as the build holds, so a watch and the
    /// rows told within the room take nothing of the heap; a room asked past the build's is the
    /// build's. Turned red by rows kept anywhere but the plane, or by a room left unclamped.
    #[test]
    fn the_rows_a_plane_holds_lie_in_the_plane() {
        assert!(
            core::mem::size_of::<FacePlane<StdLocks>>()
                >= MAX_FACE_WATCH_ROWS * core::mem::size_of::<(FaceEventKind, FaceLinkRow)>()
        );
        assert_eq!(
            plane::<StdLocks>(4).room(),
            4_usize.min(MAX_FACE_WATCH_ROWS)
        );
        assert_eq!(
            plane::<StdLocks>(MAX_FACE_WATCH_ROWS + 1).room(),
            MAX_FACE_WATCH_ROWS
        );
    }

    /// Rows queued and taken round the ring, more of them than it has rows, come out in the order
    /// they happened, each once. Turned red by a ring that reads a row from where another was
    /// written once its first row has moved past the last.
    #[test]
    fn rows_taken_round_the_ring_keep_their_order() {
        let plane = plane::<StdLocks>(MAX_FACE_WATCH_ROWS);
        let mut next = 0_u8;
        let mut taken = Vec::new();
        for _ in 0..3 * MAX_FACE_WATCH_ROWS {
            plane.happened(FaceEventKind::Up, row(next));
            next = next.wrapping_add(1);
            plane.happened(FaceEventKind::Up, row(next));
            next = next.wrapping_add(1);
            taken.push(plane.next_event().unwrap().1.zid[0]);
            taken.push(plane.next_event().unwrap().1.zid[0]);
        }
        assert!(plane.next_event().is_none());
        let told: Vec<u8> = (0..next).collect();
        assert_eq!(taken, told);
    }

    /// A watch past the plane's watchers is refused with its sink handed back and no id taken, so
    /// the watch after a stop is given the id one past the last one given. Turned red by a table
    /// that grows past its bound, or by a refused watch that took an id.
    #[test]
    fn a_watch_past_the_bound_is_refused_and_its_sink_handed_back() {
        let plane = plane::<StdLocks>(MAX_FACE_WATCH_ROWS);
        let told = Arc::default();
        for id in 1..=MAX_WATCHERS {
            assert_eq!(plane.watch(counting(&told)).ok(), Some(id as u64));
        }
        let Err(CapacityFull(refused)) = plane.watch(counting(&told)) else {
            panic!("a watch past the bound is refused");
        };
        drop(refused);
        assert!(plane.unwatch(1));
        assert_eq!(
            plane.watch(counting(&told)).ok(),
            Some(MAX_WATCHERS as u64 + 1)
        );
        plane.happened(FaceEventKind::Up, row(1));
        assert!(plane.hand_out_next());
        assert_eq!(told.load(Ordering::Relaxed), MAX_WATCHERS);
    }

    /// One block of an arena's memory, aligned as an arena's spans start.
    #[derive(Clone, Copy)]
    #[repr(C, align(16))]
    struct Block {
        _bytes: [u8; crate::bounded::ARENA_ALIGN],
    }

    /// A plane placed in an arena is built where it lies, with the room asked, and is watched and
    /// told there; an arena with no span left for it refuses it. Turned red by a placed plane
    /// whose room is not the one asked, or whose rows are read before they were written.
    #[test]
    fn a_plane_placed_in_an_arena_is_watched_where_it_lies() {
        let blocks =
            core::mem::size_of::<FacePlane<StdLocks>>().div_ceil(crate::bounded::ARENA_ALIGN);
        let mut memory = alloc::vec![
            Block {
                _bytes: [0; crate::bounded::ARENA_ALIGN],
            };
            blocks
        ];
        let bytes = core::mem::size_of_val(memory.as_slice());
        // SAFETY: the blocks are aligned to `ARENA_ALIGN`, hold `bytes` bytes and outlive the
        // arena and the plane placed in it, which nothing else uses.
        let mut arena = unsafe {
            Arena::over(
                core::ptr::NonNull::new(memory.as_mut_ptr())
                    .unwrap()
                    .cast::<u8>(),
                bytes,
            )
        };
        let plane = FacePlane::<StdLocks>::place_in(&mut arena, 2).unwrap();
        assert_eq!(plane.room(), 2_usize.min(MAX_FACE_WATCH_ROWS));
        assert!(!plane.watched());
        let told = Arc::default();
        plane.watch(counting(&told)).unwrap();
        plane.happened(FaceEventKind::Up, row(1));
        assert!(plane.hand_out_next());
        assert_eq!(told.load(Ordering::Relaxed), 1);
        assert!(FacePlane::<StdLocks>::place_in(&mut arena, 2).is_err());
        drop(plane);
        drop(memory);
    }

    /// Rows past the queue's room are let go of, the queue not grown for them, and counted on the
    /// last row kept, which tells each watcher once how many were lost after it; a row queued once
    /// there is room again tells none. Turned red by a queue that grows past its room (every row
    /// told, none lost), by a loss counted on no row, or by a count told again with a later row.
    #[test]
    fn rows_past_the_room_are_lost_and_told_once_with_the_last_row_kept() {
        let plane = plane::<StdLocks>(2);
        let told = Arc::new(Mutex::new(Vec::new()));
        let into = Arc::clone(&told);
        plane
            .watch(shared_sink(move |_, row: &FaceLinkRow| {
                into.lock().unwrap().push((row.zid[0], row.lost_after));
            }))
            .unwrap();
        for zid in 1..=5 {
            plane.happened(FaceEventKind::Up, row(zid));
        }
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
        let plane =
            Arc::<FacePlane<StdLocks>>::from(plane::<StdLocks>(crate::caps::MAX_FACE_WATCH_ROWS));
        let told = Arc::new(AtomicUsize::new(0));
        plane.watch(counting(&told)).unwrap();
        assert!(FaceReports::watched(&plane));
        FaceReports::happened(&plane, FaceEventKind::Up, row(3));
        assert!(plane.hand_out_next());
        assert_eq!(told.load(Ordering::Relaxed), 1);
        assert!(!plane.hand_out_next());
    }

    /// A watcher counted by its maker's functions is told through the copy the plane takes out of
    /// its lock, which is let go of after the row, and the plane's own count goes with the watch.
    /// Turned red by a copy that takes no count, or a sink dropped without letting its count go.
    #[test]
    fn a_counted_watcher_is_told_through_its_counts_and_let_go_with_the_watch() {
        /// A watcher with its own counts, and the rows it was told.
        struct Watcher {
            counts: AtomicUsize,
            told: AtomicUsize,
        }
        /// # Safety
        /// `raw` is a `Watcher` that outlives the call.
        unsafe fn tell(raw: *const core::ffi::c_void, _: FaceEventKind, _: &FaceLinkRow) {
            // SAFETY: the caller's.
            unsafe { &*raw.cast::<Watcher>() }
                .told
                .fetch_add(1, Ordering::Relaxed);
        }
        /// # Safety
        /// As `tell`.
        unsafe fn retain(raw: *const core::ffi::c_void) {
            // SAFETY: the caller's.
            unsafe { &*raw.cast::<Watcher>() }
                .counts
                .fetch_add(1, Ordering::Relaxed);
        }
        /// # Safety
        /// As `tell`.
        unsafe fn release(raw: *mut core::ffi::c_void) {
            // SAFETY: the caller's.
            unsafe { &*raw.cast::<Watcher>() }
                .counts
                .fetch_sub(1, Ordering::Relaxed);
        }
        let watcher = Watcher {
            counts: AtomicUsize::new(1),
            told: AtomicUsize::new(0),
        };
        // SAFETY: the watcher is atomics alone and outlives the plane, made after it and so
        // dropped before it; the sink is its one count.
        let sink = unsafe {
            FaceRowSink::counted(
                core::ptr::NonNull::from(&watcher).cast(),
                tell,
                retain,
                release,
            )
        };
        let plane = plane::<StdLocks>(MAX_FACE_WATCH_ROWS);
        let id = plane.watch(sink).unwrap();
        plane.happened(FaceEventKind::Up, row(1));
        assert!(plane.hand_out_next());
        assert_eq!(watcher.told.load(Ordering::Relaxed), 1);
        assert_eq!(
            watcher.counts.load(Ordering::Relaxed),
            1,
            "the copy told the row was let go of"
        );
        assert!(plane.unwatch(id));
        assert_eq!(
            watcher.counts.load(Ordering::Relaxed),
            0,
            "the watch's count went with it"
        );
    }
}

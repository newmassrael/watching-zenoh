// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The two forms a watcher of the faces takes, each made of the other: a watcher of snapshots
//! ([`FaceEventSink`]) and a watcher of rows ([`FaceRowSink`]). An engine tells its faces in one
//! form and answers a watch of the other through these, so each fact of a face is read once, by
//! the engine, in the form it tells.

use core::ffi::c_void;
use core::ptr::{addr_of_mut, NonNull};

use wz_session_core::face::{
    FaceEventKind, FaceEventSink, FaceLinkRow, FaceRowSink, FaceSnapshot, LinkSnapshot,
};

use crate::lodge::{Lent, Strong};
use crate::os::Mutex;

/// A watcher of rows told through a watch of snapshots: each snapshot handed on as its rows
/// ([`FaceLinkRow::each_of_snapshot`]). What an engine that tells snapshots answers a watch of
/// rows with ([`crate::SessionEngine::watch_face_rows`]).
///
/// The watcher of rows lies in `place`, which its holder lent ([`Lent`]) and gets back with the
/// last count of the watch.
pub fn rows_of_snapshots(sink: FaceRowSink, place: Lent<Splitting>) -> FaceEventSink {
    let count = Strong::new_at(place, Splitting { sink });
    // SAFETY: `into_raw` gives up a count of a lodging, which is never null, to the sink; the
    // watcher is reached from any thread (a `FaceRowSink` is `Send + Sync`) and stands while a
    // count of it is held; the three functions tell, take and let go of a count of that lodging's
    // `Splitting`.
    unsafe {
        FaceEventSink::counted(
            NonNull::new_unchecked(Strong::into_raw(count)),
            tell_split,
            crate::lodge::retain_raw::<Splitting>,
            crate::lodge::release_raw::<Splitting>,
        )
    }
}

/// What a watcher of rows told through snapshots holds: the watcher each snapshot's rows are
/// handed on to.
pub struct Splitting {
    sink: FaceRowSink,
}

/// Hand each row of `face` to the watcher of rows lodged at `raw`.
///
/// # Safety
/// `raw` names a lodging of a [`Splitting`] of which the caller holds a count for the call.
unsafe fn tell_split(raw: *const c_void, kind: FaceEventKind, face: &FaceSnapshot) {
    // SAFETY: the caller's count holds the value.
    let split = unsafe { Strong::<Splitting>::value_of(raw) };
    FaceLinkRow::each_of_snapshot(face, |row| split.sink.tell(kind, &row));
}

/// A watcher of rows that lies where its maker put it, counted there ([`Strong`]): what
/// [`row_sink_of`] hands an engine as a [`FaceRowSink`], so a watcher in a place its session lent
/// is told its rows with nothing taken of the heap.
pub trait RowWatcher: Send + Sync {
    /// A row of a face that came up or went.
    fn row(&self, kind: FaceEventKind, row: &FaceLinkRow);
}

/// The sink of the watcher `count` counts: one more count of it for each copy an engine takes,
/// and the watcher let go of with the last, as its place says.
pub fn row_sink_of<T: RowWatcher>(count: Strong<T>) -> FaceRowSink {
    // SAFETY: `into_raw` gives up a count of a lodging, which is never null, to the sink; the
    // watcher is reached from any thread (`RowWatcher: Send + Sync`) and stands while a count of
    // it is held; the three functions tell, take and let go of a count of that lodging's `T`.
    unsafe {
        FaceRowSink::counted(
            NonNull::new_unchecked(Strong::into_raw(count)),
            tell_raw::<T>,
            crate::lodge::retain_raw::<T>,
            crate::lodge::release_raw::<T>,
        )
    }
}

/// Tell the watcher lodged at `raw` a row.
///
/// # Safety
/// `raw` names a lodging of a `T` of which the caller holds a count for the call.
unsafe fn tell_raw<T: RowWatcher>(raw: *const c_void, kind: FaceEventKind, row: &FaceLinkRow) {
    // SAFETY: the caller's count holds the value.
    unsafe { Strong::<T>::value_of(raw) }.row(kind, row);
}

/// A watcher of snapshots told through a watch of rows: the rows of a face gathered into its
/// snapshot, from its first row on, and handed on at its last. What an engine that tells rows
/// answers a watch of snapshots with; what a row does not hold reads as not known in the snapshot
/// ([`LinkSnapshot::of_row`]). A row met with no face begun, whose face's first row was not
/// seen, is let go of, and so is its face. Rows lost after a row ([`FaceLinkRow::lost_after`])
/// are not told: a watcher of snapshots, as zenoh's, has no event that says it missed one.
///
/// The gathering lies in `place`, which its holder lent ([`Lent`]) and gets back with the
/// last count of the watch.
pub fn snapshots_of_rows(sink: FaceEventSink, place: Lent<Gathering>) -> FaceRowSink {
    let make = |at: NonNull<Gathering>| {
        let at = at.as_ptr();
        // SAFETY: the place is the lent one's, valid for one `Gathering` and never moved while it
        // is counted; each field is written once through a pointer to it, not null as it is
        // inside the place.
        unsafe {
            addr_of_mut!((*at).sink).write(sink);
            crate::os::mutex_in(NonNull::new_unchecked(addr_of_mut!((*at).face)), |face| {
                face.write(None)
            });
        }
    };
    // SAFETY: `make` writes both fields of the `Gathering` in the place it is handed.
    row_sink_of(unsafe { Strong::lodge_at(place, make) })
}

/// What a watcher of snapshots told through rows holds between rows: the face whose rows are
/// being gathered, under a lock made in place ([`crate::os::mutex_in`]), and the watcher it is
/// handed on to.
pub struct Gathering {
    face: Mutex<Option<FaceSnapshot>>,
    sink: FaceEventSink,
}

impl RowWatcher for Gathering {
    fn row(&self, kind: FaceEventKind, row: &FaceLinkRow) {
        let whole = {
            let mut held = self.face.lock();
            let face: &mut Option<FaceSnapshot> = &mut held;
            if row.link == 0 {
                *face = Some(FaceSnapshot::of_face_row(row));
            }
            if let (Some(face), Some(link)) = (face.as_mut(), LinkSnapshot::of_row(row)) {
                face.links.push(link);
            }
            if row.is_last_of_face() {
                face.take()
            } else {
                None
            }
        };
        // Called with the gathering let go of: the sink may reach back into the session, whose
        // next face's rows would wait on it.
        if let Some(face) = whole {
            self.sink.tell(kind, &face);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use std::sync::Mutex as StdMutex;
    use wz_session_core::face::GroupLink;
    use wz_session_core::link::LinkKind;

    /// A face of `links` TCP links, each from `tcp/a<n>`.
    fn face(first: u8, links: usize) -> FaceSnapshot {
        FaceSnapshot {
            zid: [first; 16],
            whatami: 1,
            is_qos: false,
            is_multicast: false,
            is_shm: false,
            links: (0..links)
                .map(|at| {
                    let mut link =
                        LinkSnapshot::unicast(&alloc::format!("tcp/a{at}"), "tcp/b", None, 1500);
                    link.kind = Some(LinkKind::Tcp);
                    link
                })
                .collect(),
        }
    }

    /// A place for a gathering, or for a watcher of rows told through snapshots, in a box of its
    /// own.
    fn heap_place<T>() -> Lent<T> {
        Lent::try_boxed().expect("the test's heap")
    }

    /// What a watcher of a test is told, in the order it was told it.
    type Told<T> = Arc<StdMutex<Vec<T>>>;

    /// Rows told through a watch of snapshots are each snapshot's rows, a face with no link one
    /// row; snapshots told through a watch of rows are the faces the rows were made of, each told
    /// once at its last row. Turned red by a snapshot handed on before its last link, or by a face
    /// with no link told as no row.
    #[test]
    fn each_form_of_a_watcher_is_told_what_the_other_is() {
        let rows_told: Told<(FaceEventKind, u8, usize, usize)> = Arc::default();
        let into = Arc::clone(&rows_told);
        let by_snapshot = rows_of_snapshots(
            FaceRowSink::of_arc(Arc::new(move |kind: FaceEventKind, row: &FaceLinkRow| {
                into.lock()
                    .unwrap()
                    .push((kind, row.zid[0], row.link, row.links));
            })),
            heap_place(),
        );
        by_snapshot.tell(FaceEventKind::Up, &face(1, 2));
        by_snapshot.tell(FaceEventKind::Down, &face(2, 0));
        assert_eq!(
            *rows_told.lock().unwrap(),
            [
                (FaceEventKind::Up, 1, 0, 2),
                (FaceEventKind::Up, 1, 1, 2),
                (FaceEventKind::Down, 2, 0, 0),
            ]
        );

        let faces_told: Told<(FaceEventKind, u8, Vec<String>)> = Arc::default();
        let into = Arc::clone(&faces_told);
        let by_row = snapshots_of_rows(
            FaceEventSink::of_arc(Arc::new(move |kind: FaceEventKind, face: &FaceSnapshot| {
                let srcs = face.links.iter().map(|link| link.src.clone()).collect();
                into.lock().unwrap().push((kind, face.zid[0], srcs));
            })),
            heap_place(),
        );
        for (kind, told) in [
            (FaceEventKind::Up, face(3, 2)),
            (FaceEventKind::Down, face(4, 0)),
        ] {
            FaceLinkRow::each_of_snapshot(&told, |row| {
                by_row.tell(kind, &row);
            });
        }
        assert_eq!(
            *faces_told.lock().unwrap(),
            [
                (
                    FaceEventKind::Up,
                    3,
                    alloc::vec![String::from("tcp/a0"), String::from("tcp/a1")]
                ),
                (FaceEventKind::Down, 4, Vec::new()),
            ]
        );
    }

    /// A group member's row makes a link of the group it was joined by, whose locator is the
    /// endpoint without its config; a row whose face's first row was not seen tells nothing.
    #[test]
    fn a_snapshot_made_of_rows_keeps_the_group_and_drops_a_face_begun_unseen() {
        let told: Arc<StdMutex<Vec<FaceSnapshot>>> = Arc::default();
        let into = Arc::clone(&told);
        let by_row = snapshots_of_rows(
            FaceEventSink::of_arc(Arc::new(move |_: FaceEventKind, face: &FaceSnapshot| {
                into.lock().unwrap().push(face.clone());
            })),
            heap_place(),
        );
        let mut member = face(5, 1);
        member.links[0].group = Some(GroupLink {
            locator: String::from("udp/224.0.0.224:7447"),
            endpoint: String::from("udp/224.0.0.224:7447#iface=lo"),
        });
        let mut rows = Vec::new();
        FaceLinkRow::each_of_snapshot(&member, |row| rows.push(row));
        by_row.tell(FaceEventKind::Up, &rows[0]);
        let mut second = rows[0].clone();
        second.link = 1;
        second.links = 2;
        by_row.tell(FaceEventKind::Up, &second);
        let told = told.lock().unwrap();
        assert_eq!(told.len(), 1, "the row with no face begun tells nothing");
        assert_eq!(told[0].links[0].group, member.links[0].group);
    }

    /// A gathering lodged in its place is one watcher however many copies of its sink an engine
    /// takes: the watcher of snapshots it hands on to is let go of with the last of them, not
    /// before. Turned red by a sink whose copy takes no count of the gathering, which lets the
    /// watcher go with the first drop.
    #[test]
    fn a_gathering_is_let_go_of_with_the_last_copy_of_its_sink() {
        let held = Arc::new(());
        let in_watcher = Arc::clone(&held);
        let by_row = snapshots_of_rows(
            FaceEventSink::of_arc(Arc::new(move |_: FaceEventKind, _: &FaceSnapshot| {
                let _ = Arc::strong_count(&in_watcher);
            })),
            heap_place(),
        );
        let copy = by_row.clone();
        drop(by_row);
        assert_eq!(
            Arc::strong_count(&held),
            2,
            "a copy still holds the gathering"
        );
        FaceLinkRow::each_of_snapshot(&face(6, 1), |row| copy.tell(FaceEventKind::Up, &row));
        drop(copy);
        assert_eq!(Arc::strong_count(&held), 1, "the last copy let it go");
    }

    /// A watcher of rows told through snapshots lies in the place it was lent and is one watcher
    /// however many copies of its sink an engine takes: the watcher of rows is let go of with the
    /// last of them, not before. Turned red by a sink whose copy takes no count of the place, which
    /// lets the watcher go with the first drop.
    #[test]
    fn a_watcher_of_rows_told_through_snapshots_is_let_go_of_with_its_last_copy() {
        let held = Arc::new(());
        let in_watcher = Arc::clone(&held);
        let by_snapshot = rows_of_snapshots(
            FaceRowSink::of_arc(Arc::new(move |_: FaceEventKind, _: &FaceLinkRow| {
                let _ = Arc::strong_count(&in_watcher);
            })),
            heap_place(),
        );
        let copy = by_snapshot.clone();
        drop(by_snapshot);
        assert_eq!(
            Arc::strong_count(&held),
            2,
            "a copy still holds the watcher"
        );
        copy.tell(FaceEventKind::Up, &face(7, 1));
        drop(copy);
        assert_eq!(Arc::strong_count(&held), 1, "the last copy let it go");
    }
}

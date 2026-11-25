// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The two forms a watcher of the faces takes, each made of the other: a watcher of snapshots
//! ([`FaceEventSink`]) and a watcher of rows ([`FaceRowSink`]). An engine tells its faces in one
//! form and answers a watch of the other through these, so each fact of a face is read once, by
//! the engine, in the form it tells.

use alloc::sync::Arc;

use wz_session_core::face::{
    FaceEventKind, FaceEventSink, FaceLinkRow, FaceRowSink, FaceSnapshot, LinkSnapshot,
};

use crate::os::Mutex;

/// A watcher of rows told through a watch of snapshots: each snapshot handed on as its rows
/// ([`FaceLinkRow::each_of_snapshot`]). What an engine that tells snapshots answers a watch of
/// rows with ([`crate::SessionEngine::watch_face_rows`]).
pub fn rows_of_snapshots(sink: FaceRowSink) -> FaceEventSink {
    Arc::new(move |kind: FaceEventKind, face: &FaceSnapshot| {
        FaceLinkRow::each_of_snapshot(face, |row| sink(kind, &row));
    })
}

/// A watcher of snapshots told through a watch of rows: the rows of a face gathered into its
/// snapshot, from its first row on, and handed on at its last. What an engine that tells rows
/// answers a watch of snapshots with; what a row does not hold reads as not known in the snapshot
/// ([`LinkSnapshot::of_row`]). A row met with no face begun, whose face's first row was not
/// seen, is let go of, and so is its face. Rows lost after a row ([`FaceLinkRow::lost_after`])
/// are not told: a watcher of snapshots, as zenoh's, has no event that says it missed one.
pub fn snapshots_of_rows(sink: FaceEventSink) -> FaceRowSink {
    let gathering: Mutex<Option<FaceSnapshot>> = Mutex::new(None);
    Arc::new(move |kind: FaceEventKind, row: &FaceLinkRow| {
        let whole = {
            let mut held = gathering.lock();
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
            sink(kind, &face);
        }
    })
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::string::String;
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
        let by_snapshot = rows_of_snapshots(Arc::new(move |kind, row: &FaceLinkRow| {
            into.lock()
                .unwrap()
                .push((kind, row.zid[0], row.link, row.links));
        }));
        by_snapshot(FaceEventKind::Up, &face(1, 2));
        by_snapshot(FaceEventKind::Down, &face(2, 0));
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
        let by_row = snapshots_of_rows(Arc::new(move |kind, face: &FaceSnapshot| {
            let srcs = face.links.iter().map(|link| link.src.clone()).collect();
            into.lock().unwrap().push((kind, face.zid[0], srcs));
        }));
        for (kind, told) in [
            (FaceEventKind::Up, face(3, 2)),
            (FaceEventKind::Down, face(4, 0)),
        ] {
            FaceLinkRow::each_of_snapshot(&told, |row| {
                by_row(kind, &row);
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
        let by_row = snapshots_of_rows(Arc::new(move |_, face: &FaceSnapshot| {
            into.lock().unwrap().push(face.clone());
        }));
        let mut member = face(5, 1);
        member.links[0].group = Some(GroupLink {
            locator: String::from("udp/224.0.0.224:7447"),
            endpoint: String::from("udp/224.0.0.224:7447#iface=lo"),
        });
        let mut rows = Vec::new();
        FaceLinkRow::each_of_snapshot(&member, |row| rows.push(row));
        by_row(FaceEventKind::Up, &rows[0]);
        let mut second = rows[0].clone();
        second.link = 1;
        second.links = 2;
        by_row(FaceEventKind::Up, &second);
        let told = told.lock().unwrap();
        assert_eq!(told.len(), 1, "the row with no face begun tells nothing");
        assert_eq!(told[0].links[0].group, member.links[0].group);
    }
}

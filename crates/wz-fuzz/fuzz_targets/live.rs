// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The live dissection handle (`wz_dissect_live_*`, `wz_dissect_pcap_replay*`)
//! through its whole life: opened one of six ways, fed, asked every question it
//! answers, drained record by record with each record's bytes copied out,
//! ended, asked again and closed.
//!
//! Input: eight bytes of arguments, then a capture file, the same shape as the
//! `pcap` target's, so its seeds serve both.
//!
//! | byte | argument |
//! |------|----------|
//! | 0    | the limits preset of the handle |
//! | 1    | how it is opened and fed (`Feed`) |
//! | 2    | the link type pushed packets are taken from |
//! | 3    | where the first, shorter prefix of the file is cut (of 255) |
//! | 4    | the selector, from `SELECTORS` |
//! | 5    | the declarations, from `DECLARATIONS` |
//! | 6    | after how many progress calls the callback stops the work (0: none) |
//! | 7    | the frame budgets of a bounded handle, a nibble each |

#![no_main]

use core::ffi::{c_int, c_void};
use std::ffi::CString;

use libfuzzer_sys::fuzz_target;
use wz_capi_dissect::live::{LiveDissection, WzDissectRecord};
use wz_capi_dissect::*;
use wz_fuzz::{
    buffer_door, is_dissect_code, limits, link_type, string_door, OnFailure, Reader, DECLARATIONS,
    SELECTORS,
};

/// How a handle is opened and fed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Feed {
    /// `wz_dissect_pcap_replay` over the file.
    Replay,
    /// `wz_dissect_pcap_replay_lent` over the file.
    ReplayLent,
    /// `wz_dissect_live_open`, then `wz_dissect_live_follow` with a prefix and the file.
    Follow,
    /// `wz_dissect_live_open`, then `wz_dissect_live_follow_lent` with a prefix and the file.
    FollowLent,
    /// `wz_dissect_live_open`, then every packet of one link type pushed.
    Push,
    /// `wz_dissect_live_open_bounded`, then every packet of one link type pushed.
    PushBounded,
}

impl Feed {
    fn of(pick: u8) -> Self {
        [
            Self::Replay,
            Self::ReplayLent,
            Self::Follow,
            Self::FollowLent,
            Self::Push,
            Self::PushBounded,
        ][usize::from(pick) % 6]
    }

    /// Whether the handle reads a container, which the field doors then take.
    fn has_container(self) -> bool {
        !matches!(self, Self::Push | Self::PushBounded)
    }
}

/// The progress callback: counts down the calls it lets go on, and stops the
/// work when the count reaches zero.
unsafe extern "C" fn progress(user: *mut c_void, _done: u64, _total: u64) -> c_int {
    // SAFETY: `user` is the countdown `set_progress` was handed, alive for the
    // whole run of the handle.
    let left = unsafe { &mut *user.cast::<u32>() };
    if *left == 0 {
        return 0;
    }
    *left -= 1;
    1
}

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let limits = limits(r.u8());
    let feed = Feed::of(r.u8());
    let link = link_type(r.u8(), 1);
    let cut = usize::from(r.u8());
    let selector = CString::new(SELECTORS[usize::from(r.u8()) % SELECTORS.len()]).unwrap();
    let declarations =
        CString::new(DECLARATIONS[usize::from(r.u8()) % DECLARATIONS.len()]).unwrap();
    let mut countdown = u32::from(r.u8());
    let budgets = r.u8();
    let file = r.rest();
    let (b, n) = (file.as_ptr(), file.len());
    let prefix = n * cut / 255;

    let mut handle: *mut LiveDissection = core::ptr::null_mut();
    // SAFETY (every call in this target): `b` points at `n` readable bytes that
    // outlive the handle, every string is NUL-terminated and outlives its call,
    // every out pointer is a writable local, and `handle` is used only while it
    // is open.
    let rc = unsafe {
        match feed {
            Feed::Replay => wz_dissect_pcap_replay(b, n, limits, &mut handle),
            Feed::ReplayLent => wz_dissect_pcap_replay_lent(b, n, limits, &mut handle),
            Feed::Follow | Feed::FollowLent | Feed::Push => {
                wz_dissect_live_open(limits, &mut handle)
            }
            Feed::PushBounded => wz_dissect_live_open_bounded(
                u64::from(budgets & 0x0f),
                u64::from(budgets >> 4) * 16,
                &mut handle,
            ),
        }
    };
    assert!(is_dissect_code(rc), "open: answered {rc}");
    if rc != WZ_DISSECT_OK {
        assert!(
            handle.is_null(),
            "open: failed with {rc} and handed out a handle"
        );
        return;
    }
    assert!(
        !handle.is_null(),
        "open: answered OK and handed out no handle"
    );

    if countdown > 0 {
        let rc = unsafe {
            wz_dissect_live_set_progress(
                handle,
                Some(progress),
                (&mut countdown as *mut u32).cast(),
            )
        };
        assert_eq!(
            rc, WZ_DISSECT_OK,
            "set_progress: answered {rc} for a live handle"
        );
    }

    match feed {
        Feed::Follow | Feed::FollowLent => {
            let follow = if feed == Feed::Follow {
                wz_dissect_live_follow
            } else {
                wz_dissect_live_follow_lent
            };
            for len in [prefix, n] {
                let rc = unsafe { follow(handle, b, len) };
                assert!(is_dissect_code(rc), "follow: answered {rc}");
            }
            let rc = unsafe { follow(handle, b, prefix.saturating_sub(1)) };
            assert!(
                is_dissect_code(rc),
                "follow of a shorter prefix: answered {rc}"
            );
        }
        Feed::Push | Feed::PushBounded => {
            let mut partial = 0;
            let packets = buffer_door::<WzDissectRawPacket>(
                "packets_of_link_type",
                OnFailure::NeedsZero,
                |out, cap, needed| unsafe {
                    wz_dissect_pcap_packets_of_link_type(b, n, link, out, cap, needed, &mut partial)
                },
            );
            for p in packets.unwrap_or_default() {
                let bytes = &file[p.offset as usize..][..p.len as usize];
                let rc = unsafe {
                    wz_dissect_live_push(handle, link, p.ts_ns, bytes.as_ptr(), bytes.len())
                };
                assert!(is_dissect_code(rc), "push: answered {rc}");
            }
        }
        Feed::Replay | Feed::ReplayLent => {}
    }

    let container = if feed.has_container() {
        (b, n)
    } else {
        (core::ptr::null(), 0)
    };
    question_everything(handle, container, &selector, &declarations);
    drain(handle);
    unsafe { wz_dissect_live_end(handle) };
    question_everything(handle, container, &selector, &declarations);
    drain(handle);
    unsafe { wz_dissect_live_close(handle) };
});

/// Every question a handle answers without being drained.
fn question_everything(
    handle: *mut LiveDissection,
    (b, n): (*const u8, usize),
    selector: &CString,
    declarations: &CString,
) {
    let (sel, dec) = (selector.as_ptr(), declarations.as_ptr());
    unsafe {
        string_door("live_census", |o| wz_dissect_live_census(handle, sel, o));
        string_door("live_session_table", |o| {
            wz_dissect_live_session_table(handle, o)
        });
        string_door("live_selection", |o| {
            wz_dissect_live_selection(handle, sel, o)
        });
        string_door("live_selection_since", |o| {
            wz_dissect_live_selection_since(handle, sel, 1, o)
        });
        string_door("live_fields_where", |o| {
            wz_dissect_live_fields_where(handle, b, n, 4, sel, dec, o)
        });
        string_door("live_fields_since", |o| {
            wz_dissect_live_fields_since(handle, b, n, dec, 0, o)
        });
        string_door("live_fields_since_window", |o| {
            wz_dissect_live_fields_since_window(handle, b, n, dec, 1, 3, o)
        });
        string_door("live_retention", |o| wz_dissect_live_retention(handle, o));
        string_door("live_memory", |o| wz_dissect_live_memory(handle, o));
        string_door("live_health", |o| wz_dissect_live_health(handle, o));
        for flags in [
            WZ_DISSECT_SELECTED_ROWS_ONLY,
            WZ_DISSECT_SELECTED_WITH_CONTEXT,
        ] {
            let mut summary = WzDissectSelectedPackets::default();
            buffer_door::<u64>(
                "live_selected_packets",
                OnFailure::Unstated,
                |out, cap, needed| {
                    wz_dissect_live_selected_packets(
                        handle,
                        sel,
                        flags,
                        out,
                        cap,
                        needed,
                        &mut summary,
                    )
                },
            );
        }
        let mut followed = 0usize;
        let rc = wz_dissect_live_followed(handle, &mut followed);
        assert!(is_dissect_code(rc), "live_followed: answered {rc}");
        let mut kept = 0usize;
        let rc = wz_dissect_live_set_selector_memories(handle, 2, &mut kept);
        assert!(
            is_dissect_code(rc),
            "live_set_selector_memories: answered {rc}"
        );
        let _ = wz_dissect_live_lost(handle);
    }
}

/// Drain every record, copy out each one's bytes, and ask the same of a record
/// the handle never handed out: one field of a drained record moved.
fn drain(handle: *mut LiveDissection) {
    let mut batch = Vec::<WzDissectRecord>::with_capacity(64);
    for _ in 0..1024 {
        let mut written = usize::MAX;
        let rc = unsafe {
            wz_dissect_live_drain(handle, batch.as_mut_ptr(), batch.capacity(), &mut written)
        };
        assert!(is_dissect_code(rc), "live_drain: answered {rc}");
        if rc != WZ_DISSECT_OK || written == 0 {
            return;
        }
        assert!(
            written <= batch.capacity(),
            "live_drain: wrote {written} records into room for {}",
            batch.capacity()
        );
        // SAFETY: the door filled `written` records.
        unsafe { batch.set_len(written) };
        for record in &batch {
            let moved = WzDissectRecord {
                unit_len: record.unit_len.wrapping_mul(3) ^ 0x55,
                ..*record
            };
            for rec in [record, &moved] {
                buffer_door::<u8>(
                    "live_message_bytes",
                    OnFailure::Unstated,
                    |out, cap, needed| unsafe {
                        wz_dissect_live_message_bytes(handle, rec, out, cap, needed)
                    },
                );
                buffer_door::<u8>(
                    "live_reassembled_bytes",
                    OnFailure::Unstated,
                    |out, cap, needed| unsafe {
                        wz_dissect_live_reassembled_bytes(handle, rec, out, cap, needed)
                    },
                );
            }
        }
        batch.clear();
    }
}

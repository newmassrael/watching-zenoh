// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_event_emit`, `wz_ext_event_read`, `wz_ext_event_release` and `wz_ext_event_dropped`: the
//! node's event log, written and read from C (`docs/observation-plane.md` M2).
//!
//! A door wz has and zenoh-pico does not, so each is `wz_ext_*`, declared in `wz_ext.h`
//! (docs/build-configuration.md, decision C10), and part of the unstable surface: a build without
//! `unstable-api` carries none of it.
//!
//! An event is a level, a source and up to `EVENT_RECORD_ARGS` integers. It carries no text: the
//! format it is read with is a constant the reader holds, keyed by the source, so a record costs a
//! few words and nothing is formatted on the node. The log is one ring for the process; what a full
//! one gives up is the build's `event-ring-full` policy.
//!
//! A reader keeps its own cursor, a sequence number, so any number of programs read the same log
//! and none of them takes an event from another. The cursor starts at 0: a log that has wrapped
//! tells the reader how many events it missed before it hands it the oldest one left. Under
//! `drop-newest` nothing is freed by reading; the program says how far it is done with
//! (`wz_ext_event_release`), and that is what makes room.

use crate::result::{ZResult, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK};
use wz_node_time::event_log::{global, LogRead};

/// What a read found: an event.
pub const WZ_EXT_EVENT_RECORD: u8 = 0;
/// What a read found: nothing newer than the cursor.
pub const WZ_EXT_EVENT_EMPTY: u8 = 1;
/// What a read found: events were overwritten before they were read; `sequence` is how many.
pub const WZ_EXT_EVENT_LOST: u8 = 2;

/// One event, as `wz_ext_event_read` gives it.
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct wz_ext_event_t {
    /// `WZ_EXT_EVENT_RECORD`, `WZ_EXT_EVENT_EMPTY` or `WZ_EXT_EVENT_LOST`.
    pub kind: u8,
    /// How serious it is, in the program's own scale.
    pub level: u8,
    /// How many integers the event carries (the ones written into the program's buffer are the
    /// smaller of this and the buffer's size).
    pub arg_count: u8,
    pub reserved: u8,
    /// What said it, in the program's own numbering.
    pub source: u16,
    pub reserved2: u16,
    /// The event's number in the log; for a `WZ_EXT_EVENT_LOST` read, how many events are gone.
    pub sequence: u64,
    /// When, as an NTP64 word, or `0` where the clock did not know the date.
    pub timestamp: u64,
}

/// Write an event: `args` is `arg_count` integers (null when it is 0), of which the log keeps as
/// many as the build's `EVENT_RECORD_ARGS`. The time is the clock's now: the clocks the program
/// registered when `clock-source` is on, the system clock otherwise.
///
/// `Z_ERR_OVERFLOW` when a full log under `drop-newest` refused the event (it was counted);
/// `Z_ERR_NULL` for a null `args` with a count.
///
/// # Safety
/// `args` must be null or point to `arg_count` readable integers.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_event_emit(
    level: u8,
    source: u16,
    args: *const u64,
    arg_count: usize,
) -> ZResult {
    crate::ffi::guarded(|| {
        if args.is_null() && arg_count > 0 {
            return Z_ERR_NULL;
        }
        let args: &[u64] = if arg_count == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(args, arg_count)
        };
        match global().emit_now(level, source, args) {
            wz_session_core::event_ring::Pushed::Stored(_) => Z_OK,
            wz_session_core::event_ring::Pushed::Dropped => Z_ERR_OVERFLOW,
        }
    })
}

/// Read the event at `*cursor`, or say there is none. `*cursor` is the number the program reads
/// next, 0 at the start; it moves past the event read, or past the events that were lost. `out`
/// receives the result; the event's integers go to `args`, up to `args_capacity` of them (`args`
/// may be null when the capacity is 0).
///
/// # Safety
/// `cursor` and `out` must be valid and writable, and `args` null or writable for `args_capacity`
/// integers.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_event_read(
    cursor: *mut u64,
    out: *mut wz_ext_event_t,
    args: *mut u64,
    args_capacity: usize,
) -> ZResult {
    crate::ffi::guarded(|| {
        if cursor.is_null() || out.is_null() || (args.is_null() && args_capacity > 0) {
            return Z_ERR_NULL;
        }
        let mut reader = global().observer().reader_at(*cursor);
        let read = reader.poll();
        if let Some(next) = reader.cursor() {
            *cursor = next;
        }
        *out = match read {
            LogRead::Record(record) => {
                let written = usize::from(record.arg_count).min(args_capacity);
                for (index, value) in record.args.iter().take(written).enumerate() {
                    *args.add(index) = *value;
                }
                wz_ext_event_t {
                    kind: WZ_EXT_EVENT_RECORD,
                    level: record.level,
                    arg_count: record.arg_count,
                    source: record.source,
                    sequence: record.sequence,
                    timestamp: record.timestamp,
                    ..Default::default()
                }
            }
            LogRead::Empty => wz_ext_event_t {
                kind: WZ_EXT_EVENT_EMPTY,
                ..Default::default()
            },
            LogRead::Lost { missed } => wz_ext_event_t {
                kind: WZ_EXT_EVENT_LOST,
                sequence: missed,
                ..Default::default()
            },
        };
        Z_OK
    })
}

/// Say that every event before sequence number `upto` has been read and may be overwritten. Only
/// forward; a number past the last event frees what there is. Under `overwrite-oldest` nothing
/// waits for it, and it changes nothing a reader sees.
#[no_mangle]
pub extern "C" fn wz_ext_event_release(upto: u64) -> ZResult {
    crate::ffi::guarded(|| {
        global().release_to(upto);
        Z_OK
    })
}

/// How many events a full log refused under `drop-newest`. `0` under `overwrite-oldest`.
#[no_mangle]
pub extern "C" fn wz_ext_event_dropped() -> u32 {
    global().dropped()
}

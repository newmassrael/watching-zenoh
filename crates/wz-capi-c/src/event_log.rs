// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_capi_c_event_emit`, `wz_capi_c_event_read`, `wz_capi_c_event_release` and
//! `wz_capi_c_event_dropped`: the node's event log, written and read from C
//! (`docs/observation-plane.md` M2).
//!
//! A door wz has and zenoh-c has not, so each carries the `wz_capi_c_` prefix and is declared in
//! `wz_capi_c.h`. An event is a level, a source and up to `EVENT_RECORD_ARGS` integers. It carries
//! no text: the format it is read with is a constant the reader holds, keyed by the source, so a
//! record costs a few words and nothing is formatted on the node. The log is one ring for the
//! process; what a full one gives up is the build's `event-ring-full` policy.
//!
//! A reader keeps its own cursor, a sequence number, so any number of programs read the same log
//! and none of them takes an event from another. The cursor starts at 0: a log that has wrapped
//! tells the reader how many events it missed before it hands it the oldest one left. Under
//! `drop-newest` nothing is freed by reading; the program says how far it is done with
//! (`wz_capi_c_event_release`), and that is what makes room.
//!
//! What the log does is [`wz_capi_port::observation::events`]'s, which the pico ABI's
//! `wz_ext_event_*` doors act on too; this file is this ABI's names and result codes for it.

use wz_capi_port::observation::events::{self, Read};

use crate::ffi::guarded;
use crate::result::{ZResult, WZ_CAPI_C_E_FULL, Z_ENULL, Z_OK};

/// What a read found: an event.
pub const WZ_CAPI_C_EVENT_RECORD: u8 = 0;
/// What a read found: nothing newer than the cursor.
pub const WZ_CAPI_C_EVENT_EMPTY: u8 = 1;
/// What a read found: events were overwritten before they were read; `sequence` is how many.
pub const WZ_CAPI_C_EVENT_LOST: u8 = 2;

/// The level of every event the library writes (a program's own levels are its own).
pub const WZ_CAPI_C_EVENT_LEVEL_LIBRARY: u8 = events::LEVEL_LIBRARY;
/// The first source number the library uses; a program's sources are below it.
pub const WZ_CAPI_C_EVENT_SOURCE_LIBRARY: u16 = events::SOURCE_LIBRARY;
/// A supervised checkpoint missed its deadline. One integer: the checkpoint's number.
pub const WZ_CAPI_C_EVENT_SOURCE_SUPERVISION_EXPIRED: u16 = events::SOURCE_SUPERVISION_EXPIRED;

/// One event, as `wz_capi_c_event_read` gives it.
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct wz_capi_c_event_t {
    /// `WZ_CAPI_C_EVENT_RECORD`, `WZ_CAPI_C_EVENT_EMPTY` or `WZ_CAPI_C_EVENT_LOST`.
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
    /// The event's number in the log; for a `WZ_CAPI_C_EVENT_LOST` read, how many events are gone.
    pub sequence: u64,
    /// When, as an NTP64 word, or `0` where the clock did not know the date.
    pub timestamp: u64,
}

/// Write an event: `args` is `arg_count` integers (null when it is 0), of which the log keeps as
/// many as the build's `EVENT_RECORD_ARGS`. The time is the clock's now: the clocks the program
/// registered when `clock-source` is on, the system clock otherwise.
///
/// `WZ_CAPI_C_E_FULL` when a full log under `drop-newest` refused the event (it was counted);
/// `Z_ENULL` for a null `args` with a count.
///
/// # Safety
/// `args` must be null or point to `arg_count` readable integers.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_event_emit(
    level: u8,
    source: u16,
    args: *const u64,
    arg_count: usize,
) -> ZResult {
    guarded(|| {
        if args.is_null() && arg_count > 0 {
            return Z_ENULL;
        }
        let args: &[u64] = if arg_count == 0 {
            &[]
        } else {
            // SAFETY: non-null and readable for `arg_count` integers, by the contract.
            unsafe { std::slice::from_raw_parts(args, arg_count) }
        };
        // The only refusal a write has is a full log.
        match events::emit(level, source, args) {
            Ok(()) => Z_OK,
            Err(_) => WZ_CAPI_C_E_FULL,
        }
    })
}

/// Read the event at `*cursor`, or say there is none. `*cursor` is the number the program reads
/// next, 0 at the start; it moves past the event read, or past the events that were lost. `out`
/// receives the result; the event's integers go to `args`, up to `args_capacity` of them (`args`
/// may be null when the capacity is 0). `Z_ENULL` for a null `cursor` or `out`, or a null `args`
/// with a capacity.
///
/// # Safety
/// `cursor` and `out` must be valid and writable, and `args` null or writable for `args_capacity`
/// integers.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_event_read(
    cursor: *mut u64,
    out: *mut wz_capi_c_event_t,
    args: *mut u64,
    args_capacity: usize,
) -> ZResult {
    guarded(|| {
        if cursor.is_null() || out.is_null() || (args.is_null() && args_capacity > 0) {
            return Z_ENULL;
        }
        let args: &mut [u64] = if args_capacity == 0 {
            &mut []
        } else {
            // SAFETY: non-null and writable for `args_capacity` integers, by the contract.
            unsafe { std::slice::from_raw_parts_mut(args, args_capacity) }
        };
        // SAFETY: `cursor` and `out` are non-null and writable, by the contract.
        let (cursor, out) = unsafe { (&mut *cursor, &mut *out) };
        *out = match events::read(cursor, args) {
            Read::Record {
                level,
                arg_count,
                source,
                sequence,
                timestamp,
            } => wz_capi_c_event_t {
                kind: WZ_CAPI_C_EVENT_RECORD,
                level,
                arg_count,
                source,
                sequence,
                timestamp,
                ..Default::default()
            },
            Read::Empty => wz_capi_c_event_t {
                kind: WZ_CAPI_C_EVENT_EMPTY,
                ..Default::default()
            },
            Read::Lost { missed } => wz_capi_c_event_t {
                kind: WZ_CAPI_C_EVENT_LOST,
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
pub extern "C" fn wz_capi_c_event_release(upto: u64) -> ZResult {
    guarded(|| {
        events::release(upto);
        Z_OK
    })
}

/// How many events a full log refused under `drop-newest`. `0` under `overwrite-oldest`.
#[no_mangle]
pub extern "C" fn wz_capi_c_event_dropped() -> u32 {
    events::dropped()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An event written is read back from the cursor with its integers, and a reader that has
    /// caught up is told there is nothing newer. The log is the process's, so the test reads
    /// from the sequence number its own event was given and no earlier.
    #[test]
    fn an_event_written_is_read_back_with_its_integers() {
        let args = [11u64, 22, 33];
        // SAFETY: `args` is three readable integers.
        let rc = unsafe { wz_capi_c_event_emit(3, 7, args.as_ptr(), args.len()) };
        assert_eq!(rc, Z_OK);

        let mut cursor = 0u64;
        let mut found = None;
        let mut buffer = [0u64; 8];
        for _ in 0..4096 {
            let mut out = wz_capi_c_event_t::default();
            // SAFETY: valid writable cursor, event and buffer.
            let rc = unsafe {
                wz_capi_c_event_read(&mut cursor, &mut out, buffer.as_mut_ptr(), buffer.len())
            };
            assert_eq!(rc, Z_OK);
            match out.kind {
                WZ_CAPI_C_EVENT_RECORD if out.source == 7 && out.level == 3 => {
                    found = Some((out, buffer));
                    break;
                }
                WZ_CAPI_C_EVENT_EMPTY => break,
                _ => {}
            }
        }
        let (event, integers) = found.expect("the event written is in the log");
        assert_eq!(event.arg_count, 3);
        assert_eq!(&integers[..3], &args);
    }

    #[test]
    fn a_null_pointer_is_refused_without_a_write() {
        // SAFETY: the nulls are what the doors refuse.
        unsafe {
            assert_eq!(wz_capi_c_event_emit(0, 0, std::ptr::null(), 1), Z_ENULL);
            let mut cursor = 0u64;
            assert_eq!(
                wz_capi_c_event_read(&mut cursor, std::ptr::null_mut(), std::ptr::null_mut(), 0),
                Z_ENULL
            );
            let mut out = wz_capi_c_event_t::default();
            assert_eq!(
                wz_capi_c_event_read(&mut cursor, &mut out, std::ptr::null_mut(), 2),
                Z_ENULL
            );
        }
    }
}

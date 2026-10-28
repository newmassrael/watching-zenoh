// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The node's event log, written and read through the C doors (`docs/observation-plane.md` M2).
//!
//! One test, in a process of its own, because the log is the process's: the arms run in order
//! against it, and a second test in this binary would read what the first wrote.
//!
//! The build here keeps the default policy, `overwrite-oldest`, so the arms that need a full log
//! to refuse (`drop-newest`) are the unit tests of `wz-node-time`, which name that policy.

#![cfg(feature = "event-ring")]

use wz_capi_pico::event_log::{
    wz_ext_event_dropped, wz_ext_event_emit, wz_ext_event_read, wz_ext_event_release,
    wz_ext_event_t, WZ_EXT_EVENT_EMPTY, WZ_EXT_EVENT_LOST, WZ_EXT_EVENT_RECORD,
};
use wz_capi_pico::result::{Z_ERR_NULL, Z_OK};
use wz_session_core::caps::EVENT_RING_SLOTS;

unsafe fn read(cursor: &mut u64, args: &mut [u64]) -> wz_ext_event_t {
    let mut out = wz_ext_event_t::default();
    let args_ptr = if args.is_empty() {
        std::ptr::null_mut()
    } else {
        args.as_mut_ptr()
    };
    assert_eq!(
        wz_ext_event_read(cursor, &mut out, args_ptr, args.len()),
        Z_OK
    );
    out
}

#[test]
fn an_event_written_through_the_door_is_read_back_whole_by_any_number_of_readers() {
    unsafe {
        // ARM 1: nothing written yet.
        let mut cursor = 0u64;
        assert_eq!(read(&mut cursor, &mut []).kind, WZ_EXT_EVENT_EMPTY);
        assert_eq!(cursor, 0, "nothing read, nothing moved");

        // ARM 2: three events, each with its own integers.
        for index in 0..3u64 {
            let args = [index, index * 10, u64::MAX - index];
            assert_eq!(
                wz_ext_event_emit(index as u8 + 1, 0x4200 + index as u16, args.as_ptr(), 3),
                Z_OK
            );
        }
        let mut buffer = [0u64; 4];
        for index in 0..3u64 {
            let event = read(&mut cursor, &mut buffer);
            assert_eq!(event.kind, WZ_EXT_EVENT_RECORD);
            assert_eq!(event.sequence, index);
            assert_eq!(event.level, index as u8 + 1);
            assert_eq!(event.source, 0x4200 + index as u16);
            assert_eq!(event.arg_count, 3);
            assert_eq!(&buffer[..3], &[index, index * 10, u64::MAX - index]);
            assert!(event.timestamp >> 32 > 1_700_000_000, "the clock's now");
            assert_eq!(cursor, index + 1);
        }
        assert_eq!(read(&mut cursor, &mut buffer).kind, WZ_EXT_EVENT_EMPTY);

        // ARM 3: a second reader with a cursor of its own reads the same three.
        let mut other = 0u64;
        assert_eq!(read(&mut other, &mut buffer).sequence, 0);
        assert_eq!(cursor, 3, "the first reader's cursor is its own");

        // ARM 4: a buffer smaller than the event gets only what fits.
        let mut small = [0u64; 1];
        let mut again = 1u64;
        let event = read(&mut again, &mut small);
        assert_eq!((event.arg_count, small[0]), (3, 1));

        // ARM 5: more events than the ring holds. A reader at the start is told how many are
        // gone, and then reads the oldest that are left.
        let total = EVENT_RING_SLOTS as u64 + 10;
        for _ in 3..total {
            assert_eq!(wz_ext_event_emit(0, 1, std::ptr::null(), 0), Z_OK);
        }
        let mut late = 0u64;
        let lost = read(&mut late, &mut buffer);
        assert_eq!(lost.kind, WZ_EXT_EVENT_LOST);
        assert_eq!(
            lost.sequence,
            total - EVENT_RING_SLOTS as u64,
            "how many are gone"
        );
        let first_left = read(&mut late, &mut buffer);
        assert_eq!(first_left.kind, WZ_EXT_EVENT_RECORD);
        assert_eq!(first_left.sequence, lost.sequence);

        // ARM 6: nothing was refused, and releasing changes nothing a reader sees.
        assert_eq!(wz_ext_event_dropped(), 0);
        assert_eq!(wz_ext_event_release(total), Z_OK);
        let mut reread = total - 1;
        assert_eq!(read(&mut reread, &mut buffer).sequence, total - 1);

        // ARM 7: the door refuses what it cannot use.
        assert_eq!(
            wz_ext_event_emit(0, 0, std::ptr::null(), 2),
            Z_ERR_NULL,
            "a count with no integers"
        );
        let mut out = wz_ext_event_t::default();
        assert_eq!(
            wz_ext_event_read(std::ptr::null_mut(), &mut out, std::ptr::null_mut(), 0),
            Z_ERR_NULL
        );
    }
}

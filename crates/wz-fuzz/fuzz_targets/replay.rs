// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The doors of `wz-capi-replay`: `wz_replay_mutate`, which changes a payload
//! a consumer holds, and `wz_replay_plan_delays`, which times a recorded
//! trace.
//!
//! Input: the mutation (one byte), its operand and seed (eight bytes each),
//! the room of the mutated payload (two bytes), the timing (one byte), the
//! gap, the speed's bits, the largest gap and the largest total (eight bytes
//! each), the room of the plan (one byte), how many capture instants follow
//! (one byte) and the instants (eight bytes each), then the payload.
//!
//! Beyond each door's contract: a mutated payload is never longer than the
//! room it was given, `changed` is a yes or a no, and the mutation done in
//! place answers and writes what it does into a buffer of its own.

#![no_main]

use core::ffi::c_int;

use libfuzzer_sys::fuzz_target;
use wz_capi_replay::*;
use wz_fuzz::{is_replay_code, Reader};

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let mutation = c_int::from(r.u8() as i8);
    let operand = r.u64();
    let seed = r.u64();
    let room = usize::from(r.u16());
    let timing = c_int::from(r.u8() as i8);
    let gap = r.u64();
    let speed = f64::from_bits(r.u64());
    let max_gap = r.u64();
    let max_total = r.u64();
    let plan_room = usize::from(r.u8());
    let instants: Vec<u64> = (0..r.u8()).map(|_| r.u64()).collect();
    let payload = r.rest();

    let mut out = vec![0u8; room];
    let (mut len, mut changed) = (usize::MAX, -1);
    // SAFETY: `payload` is readable for its length, `out` writable for `room`,
    // and both counters are writable locals.
    let rc = unsafe {
        wz_replay_mutate(
            mutation,
            operand,
            seed,
            payload.as_ptr(),
            payload.len(),
            out.as_mut_ptr(),
            room,
            &mut len,
            &mut changed,
        )
    };
    assert!(is_replay_code(rc), "replay_mutate: answered {rc}");
    if rc == WZ_REPLAY_OK {
        assert!(
            len <= room,
            "replay_mutate: a payload of {len} bytes in a room of {room}"
        );
        assert!(
            changed == 0 || changed == 1,
            "replay_mutate: changed is {changed}"
        );
    }

    // The same mutation in place: the payload in a buffer of the same room (or
    // its own length, if longer), handed as both `payload` and `out`. It must
    // answer what the call above did, with the same bytes.
    let mut in_place = payload.to_vec();
    in_place.resize(room.max(payload.len()), 0);
    let (mut len_in_place, mut changed_in_place) = (usize::MAX, -1);
    // SAFETY: `in_place` is readable for `payload.len()` and writable for its
    // whole length; the door allows `out` to overlap `payload`.
    let rc_in_place = unsafe {
        wz_replay_mutate(
            mutation,
            operand,
            seed,
            in_place.as_ptr(),
            payload.len(),
            in_place.as_mut_ptr(),
            in_place.len(),
            &mut len_in_place,
            &mut changed_in_place,
        )
    };
    assert_eq!(
        (len_in_place, changed_in_place),
        (len, changed),
        "replay_mutate: in place it states another length or change"
    );
    if rc == WZ_REPLAY_OK {
        assert_eq!(rc_in_place, WZ_REPLAY_OK, "replay_mutate: refused in place");
        assert_eq!(
            in_place[..len],
            out[..len],
            "replay_mutate: in place it wrote other bytes"
        );
    }

    let mut plan = Vec::<WzReplayEmission>::with_capacity(plan_room);
    let mut total = u64::MAX;
    // SAFETY: `instants` holds `count` readable values, `plan` room for
    // `plan_room` emissions, and `total` is a writable local.
    let rc = unsafe {
        wz_replay_plan_delays(
            timing,
            gap,
            speed,
            max_gap,
            max_total,
            instants.as_ptr(),
            instants.len(),
            plan.as_mut_ptr(),
            plan_room,
            &mut total,
        )
    };
    assert!(is_replay_code(rc), "replay_plan_delays: answered {rc}");
});

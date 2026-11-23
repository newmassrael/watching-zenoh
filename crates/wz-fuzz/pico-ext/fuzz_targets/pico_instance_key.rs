// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The instance keys of the pico C ABI (`wz_ext_instance_keyer_*`): a keyer made from a `.proto`
//! file and a description the fuzzer writes, then handed payloads to index, last values to set and
//! read back, and reports to flush.
//!
//! Input: a byte of choices, the file's name and text, the description (each to a NUL), then the
//! operations, each a unit behind its two-byte little-endian length whose first byte chooses it:
//!
//! | op % 4 | operation |
//! |--------|-----------|
//! | 0      | the rest of the unit is a payload to index |
//! | 1      | the drops held since the last report are flushed |
//! | 2      | the rest is set as the last value of instance `op / 4` |
//! | 3      | the last value of instance `op / 4` is read into a buffer of the rest's first byte |
//!
//! Instance numbers run one past the keyer's last. Bit 0 of the choices keeps last values, bits 1
//! to 3 choose the room each has (`ROOMS`); the clock moves by the operation's low bits.
//!
//! Held beside not crashing: each door answers a code its documentation states; a refused making
//! leaves the gravestone and a made one leaves no refusal; an indexed payload names an instance of
//! the keyer, a dropped one none; the last value of an instance is exactly what was last recorded
//! or set for it, a value longer than the room is refused and leaves the one before, and a buffer
//! too small is told the length; a report carries at least one drop, and the reports never carry
//! more drops than were made; the counts by reason are the drops made; a dropped keyer answers
//! like a null one and drops again without harm.

#![no_main]

use std::ffi::CString;

use libfuzzer_sys::fuzz_target;
use wz_capi_pico::instance_key::*;
use wz_capi_pico::proto_file::wz_ext_proto_file_t;
use wz_capi_pico::result::{
    Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK, Z_RES_CHANNEL_NODATA,
};
use wz_fuzz_ingress_common::units;
use wz_fuzz_pico_ext::{empty_string, stated, take_string, Reader};

/// The room each instance's last value has, chosen by bits 1 to 3 of the choices.
const ROOMS: [usize; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

/// What the target has done to the keyer, to hold its answers to.
struct Model {
    instances: usize,
    /// Each instance's last value, when last values are kept.
    last: Option<Vec<Option<Vec<u8>>>>,
    room: usize,
    /// The drops made, by reason: undecodable, absent, not listed.
    drops: [u64; 3],
    /// The drops the reports carried.
    reported: u64,
}

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let choices = r.u8();
    let name = r.c_field();
    let text = r.c_field();
    let description = r.c_field();
    let ops = r.rest();
    let keep = choices & 1 != 0;
    let room = ROOMS[usize::from((choices >> 1) & 7)];

    // The instances are known once a keyer is made, and the storage of the last values is sized
    // from them, so a keyer that keeps them is the second one made from the same text.
    let mut probe = new_keyer(&name, &text, &description, None);
    if !unsafe { wz_ext_internal_instance_keyer_check(&probe) } {
        return;
    }
    let mut instances = usize::MAX;
    // SAFETY: `probe` is a live owned keyer; `instances` is writable.
    let rc = unsafe {
        wz_ext_instance_keyer_instances(wz_ext_instance_keyer_loan(&probe), &mut instances)
    };
    assert_eq!(
        rc, Z_OK,
        "instance_keyer_instances: a live keyer answered {rc}"
    );

    let mut storage: Vec<u8> = Vec::new();
    let mut keyer = if keep {
        drop_keyer(&mut probe);
        storage = vec![0u8; instances * room];
        let mut options: wz_ext_instance_keyer_options_t = unsafe { core::mem::zeroed() };
        // SAFETY: `options` is writable.
        unsafe { wz_ext_instance_keyer_options_default(&mut options) };
        options.storage = storage.as_mut_ptr();
        options.storage_len = storage.len();
        options.value_capacity = room;
        let keyer = new_keyer(&name, &text, &description, Some(&options));
        assert!(
            unsafe { wz_ext_internal_instance_keyer_check(&keyer) },
            "instance_keyer_new: the text it made a keyer of is refused with room for every instance"
        );
        keyer
    } else {
        probe
    };

    let mut model = Model {
        instances,
        last: keep.then(|| vec![None; instances]),
        room,
        drops: [0; 3],
        reported: 0,
    };
    let mut now_ms = 0u64;
    for unit in units(ops) {
        let Some((&op, rest)) = unit.split_first() else {
            continue;
        };
        now_ms += u64::from(op & 3) * 250;
        let instance = usize::from(op >> 2) % (instances + 1);
        match op % 4 {
            0 => index(&keyer, &mut model, rest, now_ms),
            1 => flush(&keyer, &mut model, now_ms),
            2 => set_last(&keyer, &mut model, instance, rest),
            _ => last(
                &keyer,
                &model,
                instance,
                usize::from(rest.first().copied().unwrap_or(0)),
            ),
        }
    }

    let (mut undecodable, mut absent, mut not_listed) = (u64::MAX, u64::MAX, u64::MAX);
    // SAFETY: `keyer` is a live owned keyer; the outs are writable.
    let rc = unsafe {
        wz_ext_instance_keyer_counts(
            wz_ext_instance_keyer_loan(&keyer),
            &mut undecodable,
            &mut absent,
            &mut not_listed,
        )
    };
    assert_eq!(
        rc, Z_OK,
        "instance_keyer_counts: a live keyer answered {rc}"
    );
    assert_eq!(
        [undecodable, absent, not_listed],
        model.drops,
        "instance_keyer_counts: the counts are not the drops made"
    );
    assert!(
        model.reported <= model.drops.iter().sum::<u64>(),
        "the reports carried {} drops of {} made",
        model.reported,
        model.drops.iter().sum::<u64>()
    );

    drop_keyer(&mut keyer);
    let mut out: wz_ext_instance_key_t = unsafe { core::mem::zeroed() };
    // SAFETY: `keyer` holds the gravestone; `out` is writable.
    let rc = unsafe {
        wz_ext_instance_keyer_index(
            wz_ext_instance_keyer_loan(&keyer),
            b"x".as_ptr(),
            1,
            now_ms,
            &mut out,
        )
    };
    assert_eq!(
        rc, Z_ERR_NULL,
        "instance_keyer_index: a dropped keyer answered {rc}"
    );
    // The program's storage outlives the keyer that wrote into it.
    drop(storage);
});

fn new_keyer(
    name: &CString,
    text: &CString,
    description: &CString,
    options: Option<&wz_ext_instance_keyer_options_t>,
) -> wz_ext_owned_instance_keyer_t {
    let files = [wz_ext_proto_file_t {
        name: name.as_ptr(),
        text: text.as_ptr(),
    }];
    let mut this: wz_ext_owned_instance_keyer_t = unsafe { core::mem::zeroed() };
    let mut refusal = empty_string();
    let options = options.map_or(core::ptr::null(), |o| o as *const _);
    // SAFETY: every argument is valid for the call; the storage the options name outlives the keyer.
    let rc = unsafe {
        wz_ext_instance_keyer_new(
            &mut this,
            files.as_ptr(),
            files.len(),
            description.as_ptr(),
            options,
            &mut refusal,
        )
    };
    let why = unsafe { take_string("instance_keyer_new", &mut refusal) };
    stated(
        "instance_keyer_new",
        rc,
        &[Z_OK, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE],
    );
    let holds = unsafe { wz_ext_internal_instance_keyer_check(&this) };
    assert_eq!(
        holds,
        rc == Z_OK,
        "instance_keyer_new: {rc} and a keyer held: {holds}"
    );
    if rc == Z_OK {
        assert!(
            why.is_empty(),
            "instance_keyer_new: a made keyer left a refusal: {why}"
        );
    }
    if rc == Z_ERR_CONFIG_INVALID_VALUE {
        assert!(
            !why.is_empty(),
            "instance_keyer_new: refused with no reason"
        );
    }
    this
}

fn index(keyer: &wz_ext_owned_instance_keyer_t, model: &mut Model, payload: &[u8], now_ms: u64) {
    let mut out: wz_ext_instance_key_t = unsafe { core::mem::zeroed() };
    // SAFETY: `keyer` is a live owned keyer; `payload` is readable; `out` is writable.
    let rc = unsafe {
        wz_ext_instance_keyer_index(
            wz_ext_instance_keyer_loan(keyer),
            payload.as_ptr(),
            payload.len(),
            now_ms,
            &mut out,
        )
    };
    assert_eq!(rc, Z_OK, "instance_keyer_index: a live keyer answered {rc}");
    assert!(out.reported <= 1, "a report flag of {}", out.reported);
    match out.status {
        WZ_EXT_INSTANCE_KEY_INDEXED => {
            assert!(
                out.instance < model.instances,
                "instance {} of {}",
                out.instance,
                model.instances
            );
            assert_eq!(out.reported, 0, "an indexed payload carries a report");
            match &mut model.last {
                None => assert_eq!(
                    out.last, WZ_EXT_INSTANCE_KEY_LAST_NOT_KEPT,
                    "a last value kept by a keyer that keeps none"
                ),
                Some(last) => match out.last {
                    WZ_EXT_INSTANCE_KEY_LAST_RECORDED => {
                        assert!(
                            payload.len() <= model.room,
                            "a value of {} bytes recorded in a room of {}",
                            payload.len(),
                            model.room
                        );
                        last[out.instance] = Some(payload.to_vec());
                    }
                    WZ_EXT_INSTANCE_KEY_LAST_TOO_LONG => assert!(
                        payload.len() > model.room,
                        "a value of {} bytes refused from a room of {}",
                        payload.len(),
                        model.room
                    ),
                    other => panic!("an indexed payload's last value is {other}"),
                },
            }
        }
        WZ_EXT_INSTANCE_KEY_UNDECODABLE
        | WZ_EXT_INSTANCE_KEY_ABSENT
        | WZ_EXT_INSTANCE_KEY_NOT_LISTED => {
            model.drops[usize::from(out.status - 1)] += 1;
            assert_eq!(
                out.instance, 0,
                "a dropped payload names instance {}",
                out.instance
            );
            assert_eq!(
                out.last, WZ_EXT_INSTANCE_KEY_LAST_NOT_KEPT,
                "a dropped payload's last value is {}",
                out.last
            );
            if out.reported == 1 {
                assert!(out.dropped >= 1, "a report of no drop");
                model.reported += out.dropped;
            } else {
                assert_eq!(out.dropped, 0, "a drop count without a report");
            }
        }
        other => panic!("instance_keyer_index: a status of no name: {other}"),
    }
}

fn flush(keyer: &wz_ext_owned_instance_keyer_t, model: &mut Model, now_ms: u64) {
    let mut out: wz_ext_instance_key_t = unsafe { core::mem::zeroed() };
    // SAFETY: `keyer` is a live owned keyer; `out` is writable.
    let due =
        unsafe { wz_ext_instance_keyer_flush(wz_ext_instance_keyer_loan(keyer), now_ms, &mut out) };
    if !due {
        assert_eq!(
            out,
            wz_ext_instance_key_t::default(),
            "no report due, and the out is written"
        );
        return;
    }
    assert_eq!(out.reported, 1, "a flushed report not marked as one");
    assert!(out.dropped >= 1, "a flushed report of no drop");
    assert!(
        matches!(
            out.status,
            WZ_EXT_INSTANCE_KEY_UNDECODABLE
                | WZ_EXT_INSTANCE_KEY_ABSENT
                | WZ_EXT_INSTANCE_KEY_NOT_LISTED
        ),
        "a report says no reason: {}",
        out.status
    );
    model.reported += out.dropped;
}

fn set_last(
    keyer: &wz_ext_owned_instance_keyer_t,
    model: &mut Model,
    instance: usize,
    value: &[u8],
) {
    // SAFETY: `keyer` is a live owned keyer; `value` is readable.
    let rc = unsafe {
        wz_ext_instance_keyer_set_last(
            wz_ext_instance_keyer_loan(keyer),
            instance,
            value.as_ptr(),
            value.len(),
        )
    };
    let Some(last) = &mut model.last else {
        assert_eq!(
            rc, Z_EINVAL,
            "instance_keyer_set_last: a keyer that keeps no last values answered {rc}"
        );
        return;
    };
    if instance >= model.instances {
        assert_eq!(
            rc, Z_EINVAL,
            "instance_keyer_set_last: instance {instance} of {} answered {rc}",
            model.instances
        );
    } else if value.len() > model.room {
        assert_eq!(
            rc,
            Z_ERR_OVERFLOW,
            "instance_keyer_set_last: {} bytes in a room of {} answered {rc}",
            value.len(),
            model.room
        );
    } else {
        assert_eq!(
            rc,
            Z_OK,
            "instance_keyer_set_last: {} bytes in a room of {} answered {rc}",
            value.len(),
            model.room
        );
        last[instance] = Some(value.to_vec());
    }
}

fn last(keyer: &wz_ext_owned_instance_keyer_t, model: &Model, instance: usize, capacity: usize) {
    let mut out = vec![0u8; capacity];
    let mut len = usize::MAX;
    // SAFETY: `keyer` is a live owned keyer; `out` is writable for `capacity` bytes.
    let rc = unsafe {
        wz_ext_instance_keyer_last(
            wz_ext_instance_keyer_loan(keyer),
            instance,
            out.as_mut_ptr(),
            capacity,
            &mut len,
        )
    };
    stated(
        "instance_keyer_last",
        rc,
        &[Z_OK, Z_RES_CHANNEL_NODATA, Z_ERR_OVERFLOW, Z_EINVAL],
    );
    let Some(kept) = &model.last else {
        assert_eq!(
            rc, Z_EINVAL,
            "instance_keyer_last: a keyer that keeps no last values answered {rc}"
        );
        return;
    };
    if instance >= model.instances {
        assert_eq!(
            rc, Z_EINVAL,
            "instance_keyer_last: instance {instance} of {} answered {rc}",
            model.instances
        );
        return;
    }
    match &kept[instance] {
        None => {
            assert_eq!(
                rc, Z_RES_CHANNEL_NODATA,
                "instance_keyer_last: an instance with no value answered {rc}"
            );
            assert_eq!(
                len, 0,
                "instance_keyer_last: no value, and a length of {len}"
            );
        }
        Some(value) if value.len() > capacity => {
            assert_eq!(
                rc,
                Z_ERR_OVERFLOW,
                "instance_keyer_last: {} bytes into {capacity} answered {rc}",
                value.len()
            );
            assert_eq!(
                len,
                value.len(),
                "instance_keyer_last: a buffer too small is told {len}, not {}",
                value.len()
            );
        }
        Some(value) => {
            assert_eq!(
                rc,
                Z_OK,
                "instance_keyer_last: {} bytes into {capacity} answered {rc}",
                value.len()
            );
            assert_eq!(
                &out[..len],
                value.as_slice(),
                "instance_keyer_last: not the value last recorded or set"
            );
        }
    }
}

fn drop_keyer(keyer: &mut wz_ext_owned_instance_keyer_t) {
    // SAFETY: an owned keyer slot, dropped twice; the second is a documented no-op.
    unsafe {
        wz_ext_instance_keyer_drop(wz_ext_instance_keyer_move(keyer));
        assert!(
            !wz_ext_internal_instance_keyer_check(keyer),
            "a dropped keyer is still held"
        );
        wz_ext_instance_keyer_drop(wz_ext_instance_keyer_move(keyer));
    }
}

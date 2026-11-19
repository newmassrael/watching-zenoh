// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The message catalog through the `wz_ext_message_catalog_*` doors, driven as a C program drives
//! them: the catalog text handed over once, each message's entry read back, and the e2e sender,
//! receiver and supervision rows made from an entry, each held to the one the program would make
//! by hand through the capability's own doors from the same values.
//!
//! What the reader judges (every refusal, by name) is the model tests' of `wz-app-frame`'s
//! `message_catalog`. What those cannot show is the part a C program relies on: that an entry's
//! numbers and key are where its `has` bits say, that a refusal is a code and a reason that names
//! the rule, and that the handles a catalog makes are the handles the other doors take. The catalog
//! is the reader's synthetic one, deliberately unlike any deployed one.

#![cfg(feature = "message-catalog")]

use std::ffi::{CStr, CString};

use wz_capi_pico::message_catalog::*;
use wz_capi_pico::result::{
    ZResult, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_INVALID, Z_ERR_NULL, Z_OK,
};
use wz_capi_pico::{
    z_internal_string_check, z_owned_string_t, z_string_data, z_string_drop, z_string_len,
    z_string_loan, z_string_move,
};

const SYNTHETIC: &str = include_str!("../../../../wz-app-frame/catalog/synthetic.json5");

const NORTH: usize = 0;
const SOUTH: usize = 1;
const POSE: usize = 0;
const MAP: usize = 1;

/// The text of a refusal slot a door wrote, which is then dropped; empty for the null state.
unsafe fn take(out: &mut z_owned_string_t) -> String {
    if !z_internal_string_check(out) {
        return String::new();
    }
    let loaned = z_string_loan(out);
    let len = z_string_len(loaned);
    let text = if len == 0 {
        String::new()
    } else {
        let bytes = std::slice::from_raw_parts(z_string_data(loaned).cast::<u8>(), len);
        String::from_utf8_lossy(bytes).into_owned()
    };
    z_string_drop(z_string_move(out));
    text
}

/// A catalog read from `text`, or the code and the reason it was refused with.
fn catalog(text: &str) -> Result<wz_ext_owned_message_catalog_t, (ZResult, String)> {
    let text = CString::new(text).expect("no NUL");
    unsafe {
        let mut this: wz_ext_owned_message_catalog_t = std::mem::zeroed();
        let mut refusal: z_owned_string_t = std::mem::zeroed();
        let rc = wz_ext_message_catalog_new(&mut this, text.as_ptr(), &mut refusal);
        let why = take(&mut refusal);
        if rc == Z_OK {
            assert!(why.is_empty(), "a catalog read leaves no refusal: {why}");
            assert!(wz_ext_internal_message_catalog_check(&this));
            Ok(this)
        } else {
            assert!(
                !wz_ext_internal_message_catalog_check(&this),
                "a refused catalog leaves the null state"
            );
            Err((rc, why))
        }
    }
}

fn release(this: &mut wz_ext_owned_message_catalog_t) {
    unsafe {
        wz_ext_message_catalog_drop(wz_ext_message_catalog_move(this));
        assert!(!wz_ext_internal_message_catalog_check(this));
        wz_ext_message_catalog_drop(wz_ext_message_catalog_move(this));
    }
}

fn entry(this: &wz_ext_owned_message_catalog_t, index: usize) -> (ZResult, wz_ext_message_entry_t) {
    unsafe {
        let mut out: wz_ext_message_entry_t = std::mem::zeroed();
        let rc = wz_ext_message_catalog_entry(wz_ext_message_catalog_loan(this), index, &mut out);
        (rc, out)
    }
}

#[test]
fn each_entry_reads_back_as_the_catalog_states_it() {
    let mut owned = catalog(SYNTHETIC).expect("the synthetic catalog is read");
    let this = unsafe { wz_ext_message_catalog_loan(&owned) };
    unsafe {
        assert_eq!(wz_ext_message_catalog_len(this), 2);
        assert_eq!(wz_ext_message_catalog_supervision_start_delay(this), 750);

        let mut index = usize::MAX;
        let key = CString::new("demo/catalog/map").unwrap();
        assert_eq!(
            wz_ext_message_catalog_find(this, key.as_ptr(), &mut index),
            Z_OK
        );
        assert_eq!(index, MAP);
        assert_eq!(wz_ext_message_catalog_find_id(this, 401, &mut index), Z_OK);
        assert_eq!(index, POSE);
        assert_eq!(
            wz_ext_message_catalog_find_id(this, 999, &mut index),
            Z_ERR_INVALID
        );
        let name = CString::new("south").unwrap();
        assert_eq!(
            wz_ext_message_catalog_node(this, name.as_ptr(), &mut index),
            Z_OK
        );
        assert_eq!(index, SOUTH);
        let nobody = CString::new("east").unwrap();
        assert_eq!(
            wz_ext_message_catalog_node(this, nobody.as_ptr(), &mut index),
            Z_ERR_INVALID
        );

        assert_eq!(
            wz_ext_message_catalog_direction(this, POSE, NORTH),
            WZ_EXT_MESSAGE_PUBLISHES
        );
        assert_eq!(
            wz_ext_message_catalog_direction(this, POSE, SOUTH),
            WZ_EXT_MESSAGE_SUBSCRIBES
        );
        assert_eq!(wz_ext_message_catalog_direction(this, POSE, 7), 0);
        assert_eq!(wz_ext_message_catalog_direction(this, 7, NORTH), 0);
    }

    let (rc, pose) = entry(&owned, POSE);
    assert_eq!(rc, Z_OK);
    let key = unsafe { CStr::from_ptr(pose.key_expr) };
    assert_eq!(key.to_str(), Ok("demo/catalog/pose"));
    assert_eq!(pose.id, 401);
    assert_eq!(
        pose.has,
        WZ_EXT_MESSAGE_HAS_PERIOD | WZ_EXT_MESSAGE_HAS_PROTECTION | WZ_EXT_MESSAGE_HAS_SUPERVISION
    );
    assert_eq!(pose.period_ms, 40);
    assert_eq!((pose.supervision_factor, pose.supervision_awaited), (4, 1));
    assert_eq!((pose.replay_depth, pose.senders), (0, 0));

    let (rc, map) = entry(&owned, MAP);
    assert_eq!(rc, Z_OK);
    assert_eq!(
        map.has,
        WZ_EXT_MESSAGE_HAS_REPLAY | WZ_EXT_MESSAGE_HAS_SEGMENT_PROFILE
    );
    assert_eq!(
        (map.period_ms, map.replay_depth),
        (0, 6),
        "an event message"
    );
    assert_eq!(map.supervision_factor, 0);

    let (rc, none) = entry(&owned, 2);
    assert_eq!(rc, Z_ERR_INVALID);
    assert!(none.key_expr.is_null(), "a refused entry is zeroed");
    release(&mut owned);
    let (rc, _) = entry(&owned, POSE);
    assert_eq!(rc, Z_ERR_NULL, "the gravestone");
}

#[test]
fn a_refused_catalog_is_a_code_and_a_reason_that_names_the_rule() {
    let twice = SYNTHETIC.replace("id: 402", "id: 401");
    let (rc, why) = catalog(&twice).unwrap_err();
    assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
    assert!(why.starts_with("duplicate_id at /messages/1/id"), "{why}");

    let deep = SYNTHETIC.replace(
        "replay_depth: 6",
        &format!(
            "replay_depth: {}",
            wz_session_core::caps::REPLAY_DEPTH_MAX + 1
        ),
    );
    let (rc, why) = catalog(&deep).unwrap_err();
    assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
    assert!(
        why.starts_with("replay_depth_out_of_range at /messages/1/replay_depth"),
        "{why}"
    );

    let (rc, why) = catalog("{nodes: [").unwrap_err();
    assert_eq!(rc, Z_ERR_CONFIG_INVALID_VALUE);
    assert!(why.starts_with("syntax"), "{why}");

    unsafe {
        let mut this: wz_ext_owned_message_catalog_t = std::mem::zeroed();
        assert_eq!(
            wz_ext_message_catalog_new(&mut this, std::ptr::null(), std::ptr::null_mut()),
            Z_ERR_NULL
        );
        let not_utf8 = [0xFFu8, 0];
        assert_eq!(
            wz_ext_message_catalog_new(&mut this, not_utf8.as_ptr().cast(), std::ptr::null_mut()),
            Z_EINVAL
        );
        assert!(!wz_ext_internal_message_catalog_check(&this));
        assert_eq!(wz_ext_message_catalog_len(std::ptr::null()), 0);
    }
}

#[cfg(all(feature = "e2e-sender", feature = "e2e-receiver"))]
mod e2e {
    use super::*;

    use wz_app_frame::message_catalog::{build_limits, Catalog};
    use wz_capi_pico::e2e_receiver::*;
    use wz_capi_pico::e2e_sender::*;

    /// The profile and values texts a program would hand the e2e doors by hand for the pose
    /// message, as the node at `address`.
    fn by_hand(address: u64) -> (CString, CString) {
        let read = Catalog::parse(SYNTHETIC, build_limits()).expect("read");
        let profile = CString::new(read.e2e_profiles()[0].text()).unwrap();
        let values = CString::new(format!(
            r#"{{"ident": {{"group": 21, "msg": 300}}, "cell": {{"kind": 6}}, "@address": {address}}}"#
        ))
        .unwrap();
        (profile, values)
    }

    const NORTH_ADDRESS: u64 = 0x0007_A100;
    const SOUTH_ADDRESS: u64 = 0x0007_B200;

    unsafe fn protect(tx: &wz_ext_owned_e2e_sender_t, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 64];
        let mut written = 0usize;
        let rc = wz_ext_e2e_sender_protect(
            wz_ext_e2e_sender_loan(tx),
            0,
            payload.as_ptr(),
            payload.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut written,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rc, Z_OK);
        out.truncate(written);
        out
    }

    unsafe fn judge(
        rx: &wz_ext_owned_e2e_receiver_t,
        frame: &[u8],
        now: u64,
    ) -> wz_ext_e2e_verdict_t {
        let mut verdict: wz_ext_e2e_verdict_t = std::mem::zeroed();
        let rc = wz_ext_e2e_receiver_judge(
            wz_ext_e2e_receiver_loan(rx),
            0,
            frame.as_ptr(),
            frame.len(),
            now,
            &mut verdict,
        );
        assert_eq!(rc, Z_OK);
        verdict
    }

    #[test]
    fn the_sender_and_receiver_a_catalog_makes_are_those_made_by_hand() {
        let mut owned = catalog(SYNTHETIC).expect("read");
        let this = unsafe { wz_ext_message_catalog_loan(&owned) };
        unsafe {
            let mut from_catalog: wz_ext_owned_e2e_sender_t = std::mem::zeroed();
            assert_eq!(
                wz_ext_message_catalog_e2e_sender_new(
                    this,
                    POSE,
                    NORTH,
                    std::ptr::null(),
                    &mut from_catalog,
                    std::ptr::null_mut()
                ),
                Z_OK
            );
            let (profile, values) = by_hand(NORTH_ADDRESS);
            let mut hand: wz_ext_owned_e2e_sender_t = std::mem::zeroed();
            assert_eq!(
                wz_ext_e2e_sender_new(
                    &mut hand,
                    profile.as_ptr(),
                    values.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null_mut()
                ),
                Z_OK
            );
            let mut frames = Vec::new();
            let payloads: [&[u8]; 3] = [&[0x11, 0x22], &[], &[0x11, 0x22]];
            for payload in payloads {
                let a = protect(&from_catalog, payload);
                assert_eq!(a, protect(&hand, payload));
                frames.push(a);
            }

            let mut rx_catalog: wz_ext_owned_e2e_receiver_t = std::mem::zeroed();
            assert_eq!(
                wz_ext_message_catalog_e2e_receiver_new(
                    this,
                    POSE,
                    SOUTH,
                    &mut rx_catalog,
                    std::ptr::null_mut()
                ),
                Z_OK
            );
            let (profile, expected) = by_hand(SOUTH_ADDRESS);
            let mut rx_hand: wz_ext_owned_e2e_receiver_t = std::mem::zeroed();
            assert_eq!(
                wz_ext_e2e_receiver_new(
                    &mut rx_hand,
                    profile.as_ptr(),
                    expected.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null_mut()
                ),
                Z_OK
            );
            let mut statuses = Vec::new();
            for (n, frame) in frames.iter().enumerate() {
                let now = 40 * n as u64;
                let a = judge(&rx_catalog, frame, now);
                assert_eq!(a, judge(&rx_hand, frame, now));
                statuses.push(a.status);
            }
            assert_eq!(statuses, [WZ_EXT_E2E_FIRST, WZ_EXT_E2E_OK, WZ_EXT_E2E_OK]);

            for tx in [&mut from_catalog, &mut hand] {
                wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(tx));
            }
            for rx in [&mut rx_catalog, &mut rx_hand] {
                wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(rx));
            }
        }
        release(&mut owned);
    }

    #[test]
    fn a_piece_the_entry_does_not_give_is_refused_by_code_and_reason() {
        let mut owned = catalog(SYNTHETIC).expect("read");
        let this = unsafe { wz_ext_message_catalog_loan(&owned) };
        unsafe {
            let mut tx: wz_ext_owned_e2e_sender_t = std::mem::zeroed();
            let mut refusal: z_owned_string_t = std::mem::zeroed();
            let mut sender = |index: usize, node: usize, refusal: &mut z_owned_string_t| {
                wz_ext_message_catalog_e2e_sender_new(
                    this,
                    index,
                    node,
                    std::ptr::null(),
                    &mut tx,
                    refusal,
                )
            };
            assert_eq!(
                sender(POSE, SOUTH, &mut refusal),
                Z_ERR_CONFIG_INVALID_VALUE
            );
            assert!(take(&mut refusal).contains("does not publish"));
            assert_eq!(sender(MAP, SOUTH, &mut refusal), Z_ERR_CONFIG_INVALID_VALUE);
            assert!(take(&mut refusal).contains("not protected"));
            assert_eq!(sender(9, NORTH, &mut refusal), Z_ERR_INVALID);
            assert_eq!(sender(POSE, 9, &mut refusal), Z_ERR_INVALID);
            assert!(
                !wz_ext_internal_e2e_sender_check(&tx),
                "a refusal leaves the null state"
            );

            let mut options: wz_ext_e2e_sender_options_t = std::mem::zeroed();
            wz_ext_e2e_sender_options_default(&mut options);
            options.rollover = 9;
            assert_eq!(
                wz_ext_message_catalog_e2e_sender_new(
                    this,
                    POSE,
                    NORTH,
                    &options,
                    &mut tx,
                    std::ptr::null_mut()
                ),
                Z_EINVAL
            );

            let mut rx: wz_ext_owned_e2e_receiver_t = std::mem::zeroed();
            assert_eq!(
                wz_ext_message_catalog_e2e_receiver_new(this, POSE, NORTH, &mut rx, &mut refusal),
                Z_ERR_CONFIG_INVALID_VALUE
            );
            assert!(take(&mut refusal).contains("does not subscribe"));
            assert_eq!(
                wz_ext_message_catalog_e2e_receiver_new(
                    std::ptr::null(),
                    POSE,
                    SOUTH,
                    &mut rx,
                    std::ptr::null_mut()
                ),
                Z_ERR_NULL
            );
            assert!(!wz_ext_internal_e2e_receiver_check(&rx));
        }
        release(&mut owned);
    }

    /// A message whose two publishers' sender identities the profile derives from their
    /// addresses, bound to a receiver's slots.
    const SENDERS: &str = r#"{
      nodes: [{name: 'east', address: '0x300'}, {name: 'west', address: '0x600'}, {name: 'hub'}],
      e2e_profiles: {
        q: {name: 'q',
            fields: [{name: 'crc', bytes: 1}, {name: 'counter', bytes: 1},
                     {name: 'length', bytes: 1},
                     {name: 'cell', bytes: 2,
                      split: [{name: 'kind', lsb: 12, width: 4},
                              {name: 'sender', lsb: 0, width: 12,
                               derive: {from: 'address', mask: '0xF00', xor: '0x9'}}]}],
            crc: {field: 'crc', width: 8, poly: '0x2F', init: '0xFF', refin: false,
                  refout: false, xorout: '0x00', cover: ['counter', 'length', 'cell', '@payload']},
            length: {field: 'length', counts: 'frame'},
            counter: {field: 'counter', max_gap: 2, timeout_ms: 100},
            cell: {field: 'cell', kind: 'kind', sender: 'sender'}},
      },
      messages: [{key_expr: 'demo/two', id: 7, publishers: ['east', 'west'], subscribers: ['hub'],
                  period_ms: 25, protection: {profile: 'q', values: {cell: {kind: 3}}},
                  senders: [{node: 'east', id: '0x309'}, {node: 'west', id: '0x609'}],
                  supervision: {factor: 2}}],
    }"#;

    #[cfg(feature = "e2e-sender-demux")]
    #[test]
    fn a_receiver_of_listed_senders_judges_each_in_its_bound_slot() {
        let mut owned = catalog(SENDERS).expect("read");
        let this = unsafe { wz_ext_message_catalog_loan(&owned) };
        unsafe {
            let mut rx: wz_ext_owned_e2e_receiver_t = std::mem::zeroed();
            assert_eq!(
                wz_ext_message_catalog_e2e_receiver_new(this, 0, 2, &mut rx, std::ptr::null_mut()),
                Z_OK
            );
            let mut west: wz_ext_owned_e2e_sender_t = std::mem::zeroed();
            assert_eq!(
                wz_ext_message_catalog_e2e_sender_new(
                    this,
                    0,
                    1,
                    std::ptr::null(),
                    &mut west,
                    std::ptr::null_mut()
                ),
                Z_OK
            );
            let verdict = judge(&rx, &protect(&west, b"w"), 0);
            assert_eq!(verdict.status, WZ_EXT_E2E_FIRST);
            assert_ne!(verdict.has & WZ_EXT_E2E_HAS_STREAM, 0);
            assert_eq!(
                (verdict.stream, verdict.sender),
                (1, 0x609),
                "west's bound slot"
            );
            let mut slot_sender = 0u64;
            assert!(wz_ext_e2e_receiver_slot_sender(
                wz_ext_e2e_receiver_loan(&rx),
                0,
                &mut slot_sender
            ));
            assert_eq!(
                slot_sender, 0x309,
                "east's slot is bound before its first frame"
            );
            wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&mut west));
            wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(&mut rx));
        }
        release(&mut owned);
    }

    #[cfg(not(feature = "e2e-sender-demux"))]
    #[test]
    fn a_build_without_sender_slots_refuses_a_receiver_of_listed_senders_by_name() {
        let mut owned = catalog(SENDERS).expect("read");
        let this = unsafe { wz_ext_message_catalog_loan(&owned) };
        unsafe {
            let mut rx: wz_ext_owned_e2e_receiver_t = std::mem::zeroed();
            assert_eq!(
                wz_ext_message_catalog_e2e_receiver_new(this, 0, 2, &mut rx, std::ptr::null_mut()),
                wz_capi_pico::result::WZ_EXT_ERR_UNSUPPORTED
            );
            assert!(!wz_ext_internal_e2e_receiver_check(&rx));
        }
        release(&mut owned);
    }
}

#[cfg(feature = "e2e-supervision")]
mod supervision {
    use super::*;

    use std::ffi::c_void;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    use wz_capi_pico::result::Z_ERR_OVERFLOW;
    use wz_capi_pico::stream_supervision::*;

    struct ModelClock(AtomicU32);

    unsafe extern "C" fn read_clock(context: *mut c_void, now_ms: *mut u32) -> i8 {
        *now_ms = (*(context as *const ModelClock)).0.load(Ordering::SeqCst);
        0
    }

    #[derive(Default)]
    struct Losses(Mutex<Vec<(u32, u32, u8)>>);

    unsafe extern "C" fn on_loss(context: *mut c_void, loss: *const wz_ext_stream_loss_t) {
        let losses = &*(context as *const Losses);
        let loss = &*loss;
        losses
            .0
            .lock()
            .unwrap()
            .push((loss.stream, loss.sender, loss.errors));
    }

    struct Supervisor {
        owned: wz_ext_owned_stream_supervisor_t,
        _slots: Box<[wz_ext_stream_slot_t; 4]>,
        _values: Box<[u8; 64]>,
    }

    fn supervisor(start_delay_ms: u32, clock: &ModelClock, losses: &Losses) -> Supervisor {
        let mut slots: Box<[wz_ext_stream_slot_t; 4]> = Box::new(unsafe { std::mem::zeroed() });
        let mut values = Box::new([0u8; 64]);
        unsafe {
            let mut owned: wz_ext_owned_stream_supervisor_t = std::mem::zeroed();
            assert_eq!(
                wz_ext_stream_supervisor_new(
                    &mut owned,
                    slots.as_mut_ptr(),
                    slots.len(),
                    values.as_mut_ptr(),
                    16,
                    start_delay_ms,
                    Some(read_clock),
                    clock as *const ModelClock as *mut c_void,
                ),
                Z_OK
            );
            assert_eq!(
                wz_ext_stream_supervisor_set_callback(
                    wz_ext_stream_supervisor_loan(&owned),
                    Some(on_loss),
                    losses as *const Losses as *mut c_void,
                ),
                Z_OK
            );
            Supervisor {
                owned,
                _slots: slots,
                _values: values,
            }
        }
    }

    #[test]
    fn the_rows_a_catalog_adds_supervise_as_the_rows_added_by_hand() {
        let mut owned = catalog(SYNTHETIC).expect("read");
        let this = unsafe { wz_ext_message_catalog_loan(&owned) };
        let delay = unsafe { wz_ext_message_catalog_supervision_start_delay(this) };
        let clock = ModelClock(AtomicU32::new(1_000));
        let (by_catalog, by_hand) = (Losses::default(), Losses::default());
        let mut a = supervisor(delay, &clock, &by_catalog);
        let mut b = supervisor(delay, &clock, &by_hand);
        unsafe {
            let (sa, sb) = (
                wz_ext_stream_supervisor_loan(&a.owned),
                wz_ext_stream_supervisor_loan(&b.owned),
            );
            let mut rows = 0usize;
            assert_eq!(
                wz_ext_message_catalog_supervision_rows(
                    this,
                    POSE,
                    SOUTH,
                    &mut rows,
                    std::ptr::null_mut()
                ),
                Z_OK
            );
            assert_eq!(rows, 1);
            let mut streams = [u32::MAX; 1];
            let mut written = usize::MAX;
            assert_eq!(
                wz_ext_message_catalog_supervise(
                    this,
                    POSE,
                    SOUTH,
                    sa,
                    streams.as_mut_ptr(),
                    streams.len(),
                    &mut written,
                    std::ptr::null_mut()
                ),
                Z_OK
            );
            assert_eq!(written, 1);
            let mut by_hand_stream = u32::MAX;
            assert_eq!(
                wz_ext_stream_supervisor_add(sb, 40, 4, NORTH as u32, true, &mut by_hand_stream),
                Z_OK
            );
            assert_eq!(streams[0], by_hand_stream);

            // The first clocked poll starts the delay, the delay's end activates, and a deadline
            // of 40 x 4 ms after it the stream that never arrived is lost, on both.
            for (now, told) in [(1_000, 0), (1_750, 0), (1_910, 0), (1_911, 1)] {
                clock.0.store(now, Ordering::SeqCst);
                for s in [sa, sb] {
                    let mut n = usize::MAX;
                    assert_eq!(wz_ext_stream_supervisor_poll(s, &mut n), Z_OK);
                    assert_eq!(n, told, "at {now}");
                }
            }
            let seen = by_catalog.0.lock().unwrap().clone();
            assert_eq!(seen, *by_hand.0.lock().unwrap());
            assert_eq!(seen, [(streams[0], NORTH as u32, 1)]);

            assert_eq!(
                wz_ext_message_catalog_supervise(
                    this,
                    POSE,
                    SOUTH,
                    sa,
                    streams.as_mut_ptr(),
                    0,
                    &mut written,
                    std::ptr::null_mut()
                ),
                Z_ERR_OVERFLOW,
                "no room for the row"
            );
            assert_eq!(written, 0);
            let mut refusal: z_owned_string_t = std::mem::zeroed();
            assert_eq!(
                wz_ext_message_catalog_supervise(
                    this,
                    MAP,
                    NORTH,
                    sa,
                    streams.as_mut_ptr(),
                    streams.len(),
                    &mut written,
                    &mut refusal
                ),
                Z_ERR_CONFIG_INVALID_VALUE
            );
            assert!(take(&mut refusal).contains("not supervised"));

            wz_ext_stream_supervisor_drop(wz_ext_stream_supervisor_move(&mut a.owned));
            wz_ext_stream_supervisor_drop(wz_ext_stream_supervisor_move(&mut b.owned));
        }
        release(&mut owned);
    }
}

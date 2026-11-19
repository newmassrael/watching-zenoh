// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! Reception supervision per stream through the `wz_ext_stream_supervisor_*` doors, driven as a C
//! program drives them, on a model clock the program registers.
//!
//! The rules themselves (the edge, the re-basing, the start delay, the absent senders, the ceiling)
//! are the unit tests of `wz-session-core`'s `stream_supervisor`. What those cannot show is the
//! part a C program relies on: that the table lives in the program's storage, that the clock it
//! gives is the one judged by (and a clock that cannot say stops the judging), that each loss
//! reaches its callback once with the stream's number and sender, that a refusal comes back as the
//! code the header names, and that a task the library runs polls on its own.

#![cfg(feature = "e2e-supervision")]

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;

use wz_capi_pico::result::{Z_ERR_INVALID, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK};
use wz_capi_pico::stream_supervision::*;

/// The program's model clock: a time it sets, and whether it can say it.
struct ModelClock {
    now: AtomicU32,
    known: AtomicBool,
}

impl ModelClock {
    fn at(now: u32) -> Self {
        Self {
            now: AtomicU32::new(now),
            known: AtomicBool::new(true),
        }
    }

    fn set(&self, now: u32) {
        self.now.store(now, Ordering::SeqCst);
    }
}

unsafe extern "C" fn read_clock(context: *mut c_void, now_ms: *mut u32) -> i8 {
    let clock = &*(context as *const ModelClock);
    if !clock.known.load(Ordering::SeqCst) {
        return 1;
    }
    *now_ms = clock.now.load(Ordering::SeqCst);
    0
}

/// One loss as the callback saw it, owned.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    stream: u32,
    sender: u32,
    errors: u8,
    node_errors: u8,
    value: Option<Vec<u8>>,
}

#[derive(Default)]
struct Losses(Mutex<Vec<Seen>>);

impl Losses {
    fn take(&self) -> Vec<Seen> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

unsafe extern "C" fn on_loss(context: *mut c_void, loss: *const wz_ext_stream_loss_t) {
    let losses = &*(context as *const Losses);
    let loss = &*loss;
    let value = (!loss.value.is_null())
        .then(|| std::slice::from_raw_parts(loss.value, loss.value_len).to_vec());
    losses.0.lock().unwrap().push(Seen {
        stream: loss.stream,
        sender: loss.sender,
        errors: loss.errors,
        node_errors: loss.node_errors,
        value,
    });
}

/// The program's storage for a table of four streams and a cell of eight bytes each.
struct Storage {
    slots: [wz_ext_stream_slot_t; 4],
    values: [u8; 32],
}

/// A supervisor over `storage`, judged by `clock`, telling `losses`; its start delay is
/// `start_delay_ms`.
fn supervisor(
    storage: &mut Storage,
    clock: &ModelClock,
    losses: &Losses,
    start_delay_ms: u32,
) -> wz_ext_owned_stream_supervisor_t {
    unsafe {
        let mut owned = std::mem::zeroed::<wz_ext_owned_stream_supervisor_t>();
        assert_eq!(
            wz_ext_stream_supervisor_new(
                &mut owned,
                storage.slots.as_mut_ptr(),
                storage.slots.len(),
                storage.values.as_mut_ptr(),
                8,
                start_delay_ms,
                Some(read_clock),
                clock as *const ModelClock as *mut c_void,
            ),
            Z_OK
        );
        assert!(wz_ext_internal_stream_supervisor_check(&owned));
        assert_eq!(
            wz_ext_stream_supervisor_set_callback(
                wz_ext_stream_supervisor_loan(&owned),
                Some(on_loss),
                losses as *const Losses as *mut c_void,
            ),
            Z_OK
        );
        owned
    }
}

fn storage() -> Storage {
    // Anything the program left in its storage: the supervisor writes it before it reads it.
    Storage {
        slots: unsafe { std::mem::transmute::<[u8; 80], [wz_ext_stream_slot_t; 4]>([0xA7; 80]) },
        values: [0x3C; 32],
    }
}

fn poll(this: *const wz_ext_loaned_stream_supervisor_t) -> usize {
    let mut told = usize::MAX;
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_poll(this, &mut told) },
        Z_OK
    );
    told
}

fn add(this: *const wz_ext_loaned_stream_supervisor_t, period: u32, sender: u32) -> u32 {
    let mut stream = u32::MAX;
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_add(this, period, 2, sender, true, &mut stream) },
        Z_OK
    );
    stream
}

fn drop_supervisor(owned: &mut wz_ext_owned_stream_supervisor_t) {
    unsafe {
        wz_ext_stream_supervisor_drop(wz_ext_stream_supervisor_move(owned));
        assert!(!wz_ext_internal_stream_supervisor_check(owned));
        wz_ext_stream_supervisor_drop(wz_ext_stream_supervisor_move(owned));
    }
}

#[test]
fn a_stream_that_stops_is_told_once_after_the_start_delay_from_the_first_clocked_poll() {
    let mut storage = storage();
    let clock = ModelClock::at(5_000);
    clock.known.store(false, Ordering::SeqCst);
    let losses = Losses::default();
    let mut owned = supervisor(&mut storage, &clock, &losses, 100);
    let this = unsafe { wz_ext_stream_supervisor_loan(&owned) };
    // A deadline of 15 x 2 = 30 ms.
    let stream = add(this, 15, 0xB0B);

    assert_eq!(poll(this), 0);
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_phase(this) },
        WZ_EXT_STREAM_UNCLOCKED,
        "the clock could not say"
    );
    clock.known.store(true, Ordering::SeqCst);
    assert_eq!(poll(this), 0);
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_phase(this) },
        WZ_EXT_STREAM_DELAYING
    );
    clock.set(5_099);
    assert_eq!(poll(this), 0);
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_phase(this) },
        WZ_EXT_STREAM_DELAYING
    );
    clock.set(5_100);
    assert_eq!(poll(this), 0);
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_phase(this) },
        WZ_EXT_STREAM_ACTIVE
    );

    clock.set(5_130);
    assert_eq!(poll(this), 0, "the deadline, not past it");
    clock.set(5_131);
    assert_eq!(poll(this), 1);
    let seen = losses.take();
    assert_eq!(seen.len(), 1);
    assert_eq!((seen[0].stream, seen[0].sender), (stream, 0xB0B));
    assert_eq!((seen[0].errors, seen[0].node_errors), (1, 1));
    assert_eq!(seen[0].value, None, "nothing was ever received");
    clock.set(9_000);
    assert_eq!(poll(this), 0, "an edge, not a level");

    let payload = [0x6E, 0x01, 0xF2];
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_received(this, stream, payload.as_ptr(), payload.len()) },
        Z_OK
    );
    clock.set(9_031);
    assert_eq!(poll(this), 1);
    let seen = losses.take();
    assert_eq!(seen[0].errors, 2);
    let notify = unsafe { wz_ext_stream_supervisor_notify(this) };
    match notify {
        WZ_EXT_STREAM_NOTIFY_LAST_VALUE => {
            assert_eq!(seen[0].value.as_deref(), Some(&payload[..]))
        }
        WZ_EXT_STREAM_NOTIFY_STATUS_ONLY => assert_eq!(seen[0].value, None),
        other => panic!("the build's policy reads as {other}"),
    }
    let mut errors = 0u8;
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_stream_errors(this, stream, &mut errors) },
        Z_OK
    );
    assert_eq!(errors, 2);
    assert_eq!(unsafe { wz_ext_stream_supervisor_node_errors(this) }, 2);
    drop_supervisor(&mut owned);
}

#[test]
fn an_absent_sender_is_not_judged_and_a_failing_condition_tells_nothing() {
    let mut storage = storage();
    let clock = ModelClock::at(0);
    let losses = Losses::default();
    let mut owned = supervisor(&mut storage, &clock, &losses, 0);
    let this = unsafe { wz_ext_stream_supervisor_loan(&owned) };
    let fitted = add(this, 10, 1);
    let absent = add(this, 10, 2);
    assert_eq!(poll(this), 0);

    assert_eq!(
        unsafe { wz_ext_stream_supervisor_set_sender_present(this, 2, false) },
        Z_OK
    );
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_set_sender_present(this, 77, false) },
        Z_ERR_INVALID,
        "no stream was added with that sender"
    );
    clock.set(21);
    assert_eq!(poll(this), 1);
    assert_eq!(losses.take()[0].stream, fitted);

    clock.set(100);
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_set_sender_present(this, 2, true) },
        Z_OK
    );
    clock.set(121);
    assert_eq!(poll(this), 1);
    assert_eq!(
        losses.take()[0].stream,
        absent,
        "counted from the moment it came back"
    );

    // The condition fails: nothing is told however long the streams are silent, and when it
    // holds again every count starts from 0 and every deadline from that poll.
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_set_condition(this, false) },
        Z_OK
    );
    for now in [200, 1_000, 50_000] {
        clock.set(now);
        assert_eq!(poll(this), 0, "inactive at {now}");
    }
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_phase(this) },
        WZ_EXT_STREAM_INACTIVE
    );
    assert!(losses.take().is_empty());
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_set_condition(this, true) },
        Z_OK
    );
    clock.set(60_000);
    assert_eq!(poll(this), 0);
    assert_eq!(unsafe { wz_ext_stream_supervisor_node_errors(this) }, 0);
    clock.set(60_021);
    assert_eq!(poll(this), 2);
    let seen = losses.take();
    assert!(seen.iter().all(|loss| loss.errors == 1));
    drop_supervisor(&mut owned);
}

#[test]
fn what_the_table_cannot_hold_is_refused_with_the_code_the_header_names() {
    let mut storage = storage();
    let clock = ModelClock::at(0);
    let losses = Losses::default();
    let mut owned = supervisor(&mut storage, &clock, &losses, 0);
    let this = unsafe { wz_ext_stream_supervisor_loan(&owned) };
    unsafe {
        assert_eq!(
            wz_ext_stream_supervisor_add(this, 10, 0, 1, true, std::ptr::null_mut()),
            Z_ERR_INVALID
        );
        assert_eq!(
            wz_ext_stream_supervisor_add(this, 0, 2, 1, true, std::ptr::null_mut()),
            Z_ERR_INVALID
        );
        assert_eq!(
            wz_ext_stream_supervisor_add(this, u32::MAX, 2, 1, true, std::ptr::null_mut()),
            Z_ERR_INVALID
        );
        for _ in 0..4 {
            assert_eq!(
                wz_ext_stream_supervisor_add(this, 10, 2, 1, false, std::ptr::null_mut()),
                Z_OK
            );
        }
        assert_eq!(
            wz_ext_stream_supervisor_add(this, 10, 2, 1, false, std::ptr::null_mut()),
            Z_ERR_OVERFLOW,
            "four rows of storage"
        );
        assert_eq!(
            wz_ext_stream_supervisor_received(this, 4, std::ptr::null(), 0),
            Z_ERR_INVALID
        );
        assert_eq!(
            wz_ext_stream_supervisor_received(this, 0, std::ptr::null(), 3),
            Z_ERR_NULL
        );
        let mut errors = 0u8;
        assert_eq!(
            wz_ext_stream_supervisor_stream_errors(this, 4, &mut errors),
            Z_ERR_INVALID
        );
        assert_eq!(
            wz_ext_stream_supervisor_stream_errors(this, 0, std::ptr::null_mut()),
            Z_ERR_NULL
        );
        if wz_ext_stream_supervisor_notify(this) == WZ_EXT_STREAM_NOTIFY_LAST_VALUE {
            let long = [0u8; 9];
            assert_eq!(
                wz_ext_stream_supervisor_received(this, 0, long.as_ptr(), long.len()),
                Z_ERR_OVERFLOW,
                "a payload longer than the eight-byte cell"
            );
        }
    }
    drop_supervisor(&mut owned);
    let this = unsafe { wz_ext_stream_supervisor_loan(&owned) };
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_set_condition(this, true) },
        Z_ERR_NULL,
        "the gravestone"
    );
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_phase(this) },
        WZ_EXT_STREAM_NO_SUPERVISOR
    );
}

/// The library's own task polls: a loss reaches the callback with no poll of the program's.
#[cfg(feature = "multi-thread")]
#[test]
fn a_task_of_the_library_polls_until_it_is_stopped() {
    use std::time::{Duration, Instant};

    let mut storage = storage();
    let clock = ModelClock::at(0);
    let losses = Losses::default();
    let mut owned = supervisor(&mut storage, &clock, &losses, 0);
    let this = unsafe { wz_ext_stream_supervisor_loan(&owned) };
    let stream = add(this, 10, 4);
    unsafe {
        assert_eq!(wz_ext_stream_supervisor_start_task(this, 0), Z_ERR_INVALID);
        assert_eq!(wz_ext_stream_supervisor_start_task(this, 5), Z_OK);
        assert_eq!(
            wz_ext_stream_supervisor_start_task(this, 5),
            Z_ERR_INVALID,
            "one task polls a supervisor"
        );
    }
    // Wait for the task to have activated the supervisor at time 0, then move past the deadline.
    let until = Instant::now() + Duration::from_secs(10);
    while unsafe { wz_ext_stream_supervisor_phase(this) } != WZ_EXT_STREAM_ACTIVE {
        assert!(Instant::now() < until, "the task never polled");
        std::thread::sleep(Duration::from_millis(5));
    }
    clock.set(21);
    let mut seen = Vec::new();
    while seen.is_empty() {
        assert!(Instant::now() < until, "the task never told the loss");
        std::thread::sleep(Duration::from_millis(5));
        seen = losses.take();
    }
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].stream, stream);

    unsafe {
        assert_eq!(wz_ext_stream_supervisor_stop_task(this), Z_OK);
        assert_eq!(wz_ext_stream_supervisor_stop_task(this), Z_OK, "none runs");
    }
    // Stopped: a new loss waits for a poll of the program's.
    assert_eq!(
        unsafe { wz_ext_stream_supervisor_received(this, stream, std::ptr::null(), 0) },
        Z_OK
    );
    clock.set(100);
    std::thread::sleep(Duration::from_millis(50));
    assert!(losses.take().is_empty());
    assert_eq!(poll(this), 1);
    drop_supervisor(&mut owned);
}

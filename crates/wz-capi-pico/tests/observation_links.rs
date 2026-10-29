// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The links between the instruments of the observation plane, through the C doors
//! (`docs/observation-plane.md`, step 6).
//!
//! One test, in a process of its own, because the clock registry, the event log, the supervisor and
//! the sampler are the process's: the arms run in order against them.
//!
//! * LINK 1, the events carry the time of the clock the program registered.
//! * LINK 2, a supervised checkpoint that misses its deadline writes one event, whatever the
//!   program's hook does.
//! * LINK 3, the snapshot carries the event ring's loss count, marked measured.

#![cfg(all(
    feature = "clock-source",
    feature = "event-ring",
    feature = "supervision",
    feature = "resource-snapshot",
    feature = "peer"
))]

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use wz_capi_pico::clock_source::{wz_ext_clock_source_register, wz_ext_clock_source_unregister};
use wz_capi_pico::event_log::{
    wz_ext_event_emit, wz_ext_event_read, wz_ext_event_t, WZ_EXT_EVENT_LEVEL_LIBRARY,
    WZ_EXT_EVENT_RECORD, WZ_EXT_EVENT_SOURCE_LIBRARY, WZ_EXT_EVENT_SOURCE_SUPERVISION_EXPIRED,
};
use wz_capi_pico::result::Z_OK;
use wz_capi_pico::snapshot::{wz_ext_snapshot_poll, wz_ext_snapshot_read, wz_ext_snapshot_size};
use wz_capi_pico::supervision::{
    wz_ext_supervision_check, wz_ext_supervision_set_hook, wz_ext_supervision_start,
    wz_ext_supervision_stop,
};
use wz_capi_pico::{
    z_close, z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
    z_owned_session_t, z_session_drop, z_session_loan, z_session_loan_mut, z_session_move,
    zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY,
};
use wz_runtime_tokio_test_support::free_port;
use wz_session_core::caps::SNAPSHOT_HISTOGRAM_BUCKETS;
use wz_session_core::resource_snapshot::{feature_bits, Snapshot, HAS_EVENTS};

/// Seconds ahead of the system clock, so an event stamped by the registered clock cannot be
/// mistaken for one stamped by the system's.
const AHEAD: u64 = 4_000_000_000;

unsafe extern "C" fn registered_clock(
    _context: *mut c_void,
    secs: *mut u64,
    nanos: *mut u32,
) -> i8 {
    *secs = AHEAD;
    *nanos = 0;
    0
}

static HOOK_CALLS: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn hook(_context: *mut c_void, _checkpoint: u8) {
    HOOK_CALLS.fetch_add(1, Ordering::SeqCst);
}

unsafe fn open_on(key: u8, port: u16) -> z_owned_session_t {
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK
    );
    session
}

unsafe fn close_session(session: &mut z_owned_session_t) {
    z_close(z_session_loan_mut(session), std::ptr::null());
    z_session_drop(z_session_move(session));
}

/// Every event from `cursor` on, as `(source, level, timestamp, args)`.
unsafe fn read_all(cursor: &mut u64) -> Vec<(u16, u8, u64, Vec<u64>)> {
    let mut all = Vec::new();
    loop {
        let mut out = wz_ext_event_t::default();
        let mut args = [0u64; 8];
        assert_eq!(
            wz_ext_event_read(cursor, &mut out, args.as_mut_ptr(), args.len()),
            Z_OK
        );
        if out.kind != WZ_EXT_EVENT_RECORD {
            return all;
        }
        let kept = usize::from(out.arg_count).min(args.len());
        all.push((out.source, out.level, out.timestamp, args[..kept].to_vec()));
    }
}

#[test]
fn the_instruments_are_linked_through_the_doors() {
    assert_eq!(WZ_EXT_EVENT_LEVEL_LIBRARY, 255);
    assert_eq!(
        WZ_EXT_EVENT_SOURCE_SUPERVISION_EXPIRED,
        WZ_EXT_EVENT_SOURCE_LIBRARY
    );
    // SAFETY: fresh configs and sessions, each closed before the function returns.
    unsafe {
        let mut cursor = 0u64;

        // LINK 1: an event written while a clock is registered carries that clock's seconds.
        let mut handle = 0u32;
        assert_eq!(
            wz_ext_clock_source_register(Some(registered_clock), std::ptr::null_mut(), &mut handle),
            Z_OK
        );
        assert_eq!(wz_ext_event_emit(3, 0x4200, std::ptr::null(), 0), Z_OK);
        let events = read_all(&mut cursor);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].2 >> 32,
            AHEAD,
            "the event is stamped by the registered clock"
        );
        assert_eq!(wz_ext_clock_source_unregister(handle), Z_OK);

        // LINK 2: a checkpoint that misses its deadline writes one event, carrying the library's
        // level and source and the checkpoint's number, and the program's hook still runs.
        assert_eq!(
            wz_ext_supervision_set_hook(Some(hook), std::ptr::null_mut()),
            Z_OK
        );
        assert_eq!(wz_ext_supervision_start(1, 100), Z_OK);
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(wz_ext_supervision_check(), Z_OK);
        assert_eq!(wz_ext_supervision_check(), Z_OK);
        let events = read_all(&mut cursor);
        assert_eq!(events.len(), 1, "one expiry, one event: {events:?}");
        let (source, level, timestamp, args) = &events[0];
        assert_eq!(*source, WZ_EXT_EVENT_SOURCE_SUPERVISION_EXPIRED);
        assert_eq!(*level, WZ_EXT_EVENT_LEVEL_LIBRARY);
        assert_eq!(args, &[1]);
        assert!(
            *timestamp >> 32 > 1_700_000_000,
            "stamped with the time now"
        );
        assert_eq!(HOOK_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(wz_ext_supervision_stop(1), Z_OK);

        // LINK 3: the snapshot says the ring was measured, and that it refused nothing: the build
        // keeps overwrite-oldest, which refuses none (the drop-newest count is `wz-node-time`'s
        // unit test).
        let port = free_port();
        let mut listener = open_on(Z_CONFIG_LISTEN_KEY, port);
        let mut dialler = open_on(Z_CONFIG_CONNECT_KEY, port);
        assert_eq!(wz_ext_snapshot_poll(z_session_loan(&listener)), 1);
        let mut bytes = vec![0u8; wz_ext_snapshot_size()];
        let mut length = 0usize;
        assert_eq!(
            wz_ext_snapshot_read(bytes.as_mut_ptr(), bytes.len(), &mut length),
            Z_OK
        );
        let snapshot =
            Snapshot::<SNAPSHOT_HISTOGRAM_BUCKETS>::from_bytes(&bytes[..length]).unwrap();
        assert_eq!(snapshot.available & HAS_EVENTS, HAS_EVENTS);
        assert_eq!(snapshot.events_dropped, 0);
        let all = feature_bits::CLOCK_SOURCE
            | feature_bits::EVENT_RING
            | feature_bits::SUPERVISION
            | feature_bits::RESOURCE_SNAPSHOT;
        assert_eq!(
            snapshot.features, all,
            "the image says it has all four instruments"
        );
        close_session(&mut dialler);
        close_session(&mut listener);
    }
}

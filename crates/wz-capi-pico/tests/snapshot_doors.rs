// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The node's resource snapshot taken and read through the C doors (`docs/observation-plane.md`
//! M4).
//!
//! One test, in a process of its own, because the sampler is the process's: the arms run in order
//! against it. Two sessions handshake over loopback, so the listening one has received the
//! handshake's messages; the snapshot is taken of that session. The period is the build's
//! (`SNAPSHOT_PERIOD_MS`, 1000 by default), and the arm that waits past it sleeps for it.

#![cfg(all(feature = "resource-snapshot", feature = "peer"))]

use std::ffi::{c_void, CString};
use std::time::Duration;

use wz_capi_pico::result::{Z_ERR_GENERIC, Z_ERR_NULL, Z_ERR_OVERFLOW, Z_OK};
use wz_capi_pico::snapshot::{
    wz_ext_resource_reading_t, wz_ext_snapshot_poll, wz_ext_snapshot_read,
    wz_ext_snapshot_set_source, wz_ext_snapshot_size, WZ_EXT_SNAPSHOT_HAS_CPU,
    WZ_EXT_SNAPSHOT_HAS_HEAP, WZ_EXT_SNAPSHOT_HAS_TASKS,
};
use wz_capi_pico::{
    z_close, z_config_default, z_config_loan_mut, z_config_move, z_open, z_owned_config_t,
    z_owned_session_t, z_session_drop, z_session_loan, z_session_loan_mut, z_session_move,
    zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY,
};
use wz_runtime_tokio_test_support::free_port;
use wz_session_core::caps::{SNAPSHOT_HISTOGRAM_BUCKETS, SNAPSHOT_PERIOD_MS};
use wz_session_core::resource_snapshot::{
    feature_bits, Snapshot, HAS_CPU, HAS_HEAP, HAS_TASKS, LAYOUT_VERSION,
};

type Decoded = Snapshot<SNAPSHOT_HISTOGRAM_BUCKETS>;

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

/// The latest snapshot as the door writes it, decoded.
unsafe fn read_latest() -> Decoded {
    let mut bytes = vec![0u8; wz_ext_snapshot_size()];
    let mut length = 0usize;
    assert_eq!(
        wz_ext_snapshot_read(bytes.as_mut_ptr(), bytes.len(), &mut length),
        Z_OK
    );
    assert_eq!(length, bytes.len(), "the whole record is written");
    Decoded::from_bytes(&bytes[..length]).expect("the record decodes")
}

unsafe extern "C" fn platform(_context: *mut c_void, out: *mut wz_ext_resource_reading_t) -> i8 {
    *out = wz_ext_resource_reading_t {
        available: WZ_EXT_SNAPSHOT_HAS_CPU | WZ_EXT_SNAPSHOT_HAS_HEAP | WZ_EXT_SNAPSHOT_HAS_TASKS,
        cpu_permille: 420,
        tasks: 7,
        heap_in_use: 10_000,
        heap_high_water: 12_000,
        ..Default::default()
    };
    0
}

#[test]
fn a_snapshot_is_taken_on_its_period_and_read_as_bytes() {
    assert_eq!(WZ_EXT_SNAPSHOT_HAS_CPU, HAS_CPU);
    assert_eq!(WZ_EXT_SNAPSHOT_HAS_HEAP, HAS_HEAP);
    assert_eq!(WZ_EXT_SNAPSHOT_HAS_TASKS, HAS_TASKS);
    // SAFETY: fresh configs and sessions, each closed before the function returns; the buffers are
    // sized by the door's own answer.
    unsafe {
        // ARM 1: before the first snapshot there is nothing to read, and the size is the build's.
        assert_eq!(wz_ext_snapshot_size(), Decoded::SIZE);
        let mut one = [0u8; 1];
        let mut length = 0usize;
        assert_eq!(
            wz_ext_snapshot_read(one.as_mut_ptr(), one.len(), &mut length),
            Z_ERR_GENERIC,
            "no snapshot yet"
        );
        assert_eq!(wz_ext_snapshot_poll(std::ptr::null()), Z_ERR_NULL);

        // The listening session receives the handshake of the one that dials it.
        let port = free_port();
        let mut listener = open_on(Z_CONFIG_LISTEN_KEY, port);
        let mut dialler = open_on(Z_CONFIG_CONNECT_KEY, port);

        // ARM 2: with a source set, the first poll takes a snapshot of what the source answered and
        // of the messages the session received; a second poll at once finds none due.
        assert_eq!(
            wz_ext_snapshot_set_source(Some(platform), std::ptr::null_mut()),
            Z_OK
        );
        assert_eq!(wz_ext_snapshot_poll(z_session_loan(&listener)), 1);
        assert_eq!(wz_ext_snapshot_poll(z_session_loan(&listener)), 0);
        let first = read_latest();
        assert_eq!(first.available, HAS_CPU | HAS_HEAP | HAS_TASKS);
        assert_eq!(first.cpu_permille, 420);
        assert_ne!(
            first.features & feature_bits::RESOURCE_SNAPSHOT,
            0,
            "the image says it has the snapshot it just took"
        );
        assert_eq!(
            first.features & feature_bits::SUPERVISION != 0,
            cfg!(feature = "supervision"),
            "and says it has the other instruments exactly when it was built with them"
        );
        assert_eq!(first.tasks, 7);
        assert_eq!((first.heap_in_use, first.heap_high_water), (10_000, 12_000));
        assert!(
            first.messages >= 2,
            "the handshake's messages were received and counted: {first:?}"
        );
        assert!(
            first.intervals.iter().sum::<u64>() < first.messages,
            "the first message has no interval"
        );

        // ARM 3: the record starts with its layout version and size, which is what lets a reader
        // of another build tell what it holds.
        let mut bytes = vec![0u8; wz_ext_snapshot_size()];
        let mut length = 0usize;
        assert_eq!(
            wz_ext_snapshot_read(bytes.as_mut_ptr(), bytes.len(), &mut length),
            Z_OK
        );
        assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), LAYOUT_VERSION);
        assert_eq!(
            usize::from(u16::from_le_bytes([bytes[2], bytes[3]])),
            length
        );

        // ARM 4: the doors refuse what they cannot use.
        assert_eq!(
            wz_ext_snapshot_read(bytes.as_mut_ptr(), bytes.len() - 1, &mut length),
            Z_ERR_OVERFLOW,
            "a buffer smaller than the record gets none of it"
        );
        assert_eq!(
            wz_ext_snapshot_read(std::ptr::null_mut(), bytes.len(), &mut length),
            Z_ERR_NULL
        );
        assert_eq!(
            wz_ext_snapshot_read(bytes.as_mut_ptr(), bytes.len(), std::ptr::null_mut()),
            Z_ERR_NULL
        );

        // ARM 5: past the period the next poll takes another, numbered after the first; with no
        // source the platform's parts are marked unavailable and not read as zero. The dialling
        // session is closed first, and the count of what the node received does not fall with it.
        close_session(&mut dialler);
        std::thread::sleep(Duration::from_millis(SNAPSHOT_PERIOD_MS as u64 + 100));
        assert_eq!(wz_ext_snapshot_set_source(None, std::ptr::null_mut()), Z_OK);
        assert_eq!(wz_ext_snapshot_poll(z_session_loan(&listener)), 1);
        let second = read_latest();
        assert_eq!(second.sequence, first.sequence.wrapping_add(1));
        assert_eq!(second.available, 0, "no source, nothing available");
        assert_eq!(second.cpu_permille, 0);
        assert!(
            second.messages >= first.messages,
            "the count only grows: {} then {}",
            first.messages,
            second.messages
        );
        assert!(second.interval_sum_us >= first.interval_sum_us);

        close_session(&mut listener);
    }
}

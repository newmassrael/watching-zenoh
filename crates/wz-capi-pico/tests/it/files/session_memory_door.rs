// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The worst-case memory of a session through its C doors (`wz_ext_session_memory`,
//! `wz_ext_session_memory_row`): a session that listens and one that dials it.
//!
//! What is held: the total is the sum of the rows that are bounded, and a report is bounded only
//! when every row is; the rows of the tables are the session core's for the limits the session
//! opened under, entry for entry; a session that dials holds one link, whose queue, buffer and
//! reassembly are the numbers its open handed the engine; a listener's links are bounded as its
//! engine bounds them; a row past the last and the null arguments are refused by name. With the
//! document door, a session opened with a document that lowers the batch size reports its link's
//! queue at the lowered size, as its snapshot holds it, and not at the build's.

#![cfg(all(feature = "session-memory", feature = "peer"))]

use std::ffi::{CStr, CString};

use wz_capi_pico::result::Z_EINVAL;
use wz_capi_pico::session_memory::{
    wz_ext_session_memory, wz_ext_session_memory_row, wz_ext_session_memory_row_t,
    wz_ext_session_memory_t,
};
use wz_capi_pico::{
    z_config_default, z_config_loan_mut, z_config_move, z_loaned_session_t, z_open,
    z_owned_config_t, z_owned_session_t, z_session_drop, z_session_loan, z_session_move,
    zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_ERR_NULL, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;
use wz_session_core::limits::SessionLimits;
use wz_session_core::policy::SessionPolicy;
use wz_session_core::session_init_params::TxQueueConf;
use wz_session_core::session_memory::{session_tables, Captures};

unsafe fn open_role(port: u16, key: u8) -> z_owned_session_t {
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    open_config(cfg)
}

unsafe fn open_config(mut cfg: z_owned_config_t) -> z_owned_session_t {
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK
    );
    session
}

/// One row as the door reports it, its strings read back.
#[derive(Debug)]
struct Row {
    part: String,
    basis: String,
    door: wz_ext_session_memory_row_t,
}

unsafe fn report(session: *const z_loaned_session_t) -> (wz_ext_session_memory_t, Vec<Row>) {
    let mut summary = wz_ext_session_memory_t::default();
    assert_eq!(wz_ext_session_memory(session, &mut summary), Z_OK);
    let rows = (0..summary.rows)
        .map(|index| {
            let mut door: wz_ext_session_memory_row_t = std::mem::zeroed();
            assert_eq!(wz_ext_session_memory_row(session, index, &mut door), Z_OK);
            Row {
                part: CStr::from_ptr(door.part).to_str().unwrap().to_owned(),
                basis: CStr::from_ptr(door.basis).to_str().unwrap().to_owned(),
                door,
            }
        })
        .collect();
    (summary, rows)
}

fn row<'a>(rows: &'a [Row], part: &str) -> &'a Row {
    rows.iter()
        .find(|row| row.part == part)
        .unwrap_or_else(|| panic!("the report has no {part:?}"))
}

/// The batches one link's transmit queue holds, every priority's together, for a session that
/// opens under `limits` and the build's policies.
fn queued_batches(limits: &SessionLimits) -> usize {
    TxQueueConf::pico_of_snapshot(&SessionPolicy::defaults(), limits)
        .sizes
        .iter()
        .sum()
}

/// Opens a listener and a session that dials it, runs `check` on both, and lets them go.
fn with_two_sessions(check: impl FnOnce(*const z_loaned_session_t, *const z_loaned_session_t)) {
    unsafe {
        let port = free_port();
        let mut listener = open_role(port, Z_CONFIG_LISTEN_KEY);
        let mut dialer = open_role(port, Z_CONFIG_CONNECT_KEY);
        check(z_session_loan(&listener), z_session_loan(&dialer));
        z_session_drop(z_session_move(&mut dialer));
        z_session_drop(z_session_move(&mut listener));
    }
}

#[test]
fn the_total_is_the_sum_of_the_bounded_rows() {
    with_two_sessions(|listener, dialer| {
        for session in [listener, dialer] {
            let (summary, rows) = unsafe { report(session) };
            assert!(!rows.is_empty(), "a session holds something");
            let mut sum = 0usize;
            for row in &rows {
                let door = &row.door;
                if door.bounded == 1 {
                    assert_eq!(door.total_bytes, door.count * door.entry_bytes, "{row:?}");
                    sum += door.total_bytes;
                } else {
                    assert_eq!((door.count, door.total_bytes, door.enforced), (0, 0, 0));
                }
            }
            assert_eq!(summary.total_bytes, sum);
            assert_eq!(
                summary.bounded,
                u8::from(rows.iter().all(|row| row.door.bounded == 1))
            );
            assert!(summary.enforced <= summary.bounded);
        }
    });
}

#[test]
fn the_tables_are_the_session_cores_rows_for_the_limits_the_session_opened_under() {
    with_two_sessions(|_listener, dialer| {
        let (_, rows) = unsafe { report(dialer) };
        let tables = session_tables(&SessionLimits::defaults(), &Captures::default());
        assert!(
            rows.len() > tables.rows().len(),
            "the ABI adds its own rows"
        );
        for (door, core) in rows.iter().zip(tables.rows()) {
            assert_eq!(door.part.as_bytes(), core.part.to_bytes());
            assert_eq!(door.basis.as_bytes(), core.basis.to_bytes());
            assert_eq!(door.door.entry_bytes, core.entry_bytes, "{door:?}");
            assert_eq!(door.door.count, core.total().and(core.count).unwrap_or(0));
            assert_eq!(door.door.bounded, u8::from(core.total().is_some()));
        }
    });
}

#[test]
fn a_dialling_session_holds_one_link_and_a_listener_its_engines_bound() {
    with_two_sessions(|listener, dialer| {
        let (_, dialled) = unsafe { report(dialer) };
        let handle = row(&dialled, "session handle");
        assert_eq!((handle.door.bounded, handle.door.count), (1, 1));
        assert!(handle.basis.is_empty());

        // A config that states no limit opens under the build's snapshot.
        let limits = SessionLimits::defaults();
        let queue = row(&dialled, "link transmit queues");
        assert_eq!(queue.basis, "PICO_TX_QUEUE_SIZE");
        assert_eq!(
            (queue.door.bounded, queue.door.count, queue.door.entry_bytes),
            (
                1,
                queued_batches(&limits),
                limits.pico_unicast_batch_bytes()
            )
        );
        let reassembly = row(&dialled, "link reassembly");
        assert_eq!(
            (reassembly.door.count, reassembly.door.entry_bytes),
            (
                2,
                limits
                    .pico_frag_max_bytes()
                    .most()
                    .expect("the build bounds a rejoined message")
            )
        );
        let buffer = row(&dialled, "link receive buffers");
        assert_eq!(
            (buffer.door.count, buffer.door.entry_bytes),
            (1, wz_session_core::session_init_params::RX_BUFFER_SIZE)
        );

        let (listening, listened) = unsafe { report(listener) };
        let reassembly = row(&listened, "link reassembly");
        #[cfg(feature = "engine-tokio")]
        {
            assert_eq!(
                reassembly.door.bounded, 0,
                "the tokio engine bounds no accepted link"
            );
            assert_eq!(listening.bounded, 0);
        }
        #[cfg(not(feature = "engine-tokio"))]
        {
            let _ = listening;
            assert_eq!(reassembly.door.bounded, 1);
            assert!(
                reassembly.door.count > 2,
                "a listener holds more links than a dial"
            );
        }
    });
}

#[test]
fn a_row_past_the_last_and_null_arguments_are_refused() {
    with_two_sessions(|_listener, dialer| unsafe {
        let mut summary = wz_ext_session_memory_t::default();
        assert_eq!(wz_ext_session_memory(dialer, &mut summary), Z_OK);
        let mut out: wz_ext_session_memory_row_t = std::mem::zeroed();
        out.entry_bytes = 7;
        assert_eq!(
            wz_ext_session_memory_row(dialer, summary.rows, &mut out),
            Z_EINVAL
        );
        assert_eq!(out.entry_bytes, 7, "a refused row leaves out as it was");
        assert_eq!(
            wz_ext_session_memory(dialer, std::ptr::null_mut()),
            Z_ERR_NULL
        );
        assert_eq!(
            wz_ext_session_memory(std::ptr::null(), &mut summary),
            Z_ERR_NULL
        );
        assert_eq!(
            wz_ext_session_memory_row(dialer, 0, std::ptr::null_mut()),
            Z_ERR_NULL
        );
        assert_eq!(
            wz_ext_session_memory_row(std::ptr::null(), 0, &mut out),
            Z_ERR_NULL
        );
    });
}

/// A batch size no deployment states: under the build's, so the lowered report is told apart.
#[cfg(feature = "config-document")]
const LOWERED_BATCH_BYTES: usize = 1031;

/// A session opened with a document that lowers `PICO_UNICAST_BATCH_BYTES` reports its link's
/// queue at the lowered size, as the snapshot its open resolved holds it; the rest of the report
/// is the build's, and the total is still the sum of the rows. A build whose domain keeps the
/// batch size to its own value refuses the document at the door, by name.
#[cfg(feature = "config-document")]
#[test]
fn a_document_that_lowers_the_batch_size_is_the_batch_the_report_counts() {
    use wz_capi_pico::config_policy::wz_ext_config_document;
    use wz_capi_pico::result::Z_ERR_CONFIG_INVALID_VALUE;
    use wz_capi_pico::z_config_drop;

    let mut lowered = SessionLimits::defaults();
    let selectable = lowered
        .select_pico_unicast_batch_bytes(LOWERED_BATCH_BYTES)
        .is_ok();
    unsafe {
        let port = free_port();
        let mut listener = open_role(port, Z_CONFIG_LISTEN_KEY);
        let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
        let document = CString::new(format!(
            "{{ wz: {{ limits: {{ PICO_UNICAST_BATCH_BYTES: {LOWERED_BATCH_BYTES} }} }} }}"
        ))
        .unwrap();
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut cfg),
                Z_CONFIG_CONNECT_KEY,
                endpoint.as_ptr()
            ),
            Z_OK
        );
        let stated = wz_ext_config_document(z_config_loan_mut(&mut cfg), document.as_ptr());
        if !selectable {
            assert_eq!(stated, Z_ERR_CONFIG_INVALID_VALUE);
            z_config_drop(z_config_move(&mut cfg));
            z_session_drop(z_session_move(&mut listener));
            return;
        }
        assert_eq!(stated, Z_OK);
        let mut dialer = open_config(cfg);
        let (_, at_build) = report(z_session_loan(&listener));
        let (summary, rows) = report(z_session_loan(&dialer));

        let queue = row(&rows, "link transmit queues");
        assert_eq!(
            (queue.door.bounded, queue.door.count, queue.door.entry_bytes),
            (1, queued_batches(&lowered), LOWERED_BATCH_BYTES)
        );
        assert_eq!(
            queue.door.total_bytes,
            queued_batches(&lowered) * LOWERED_BATCH_BYTES
        );
        // The tables are the session core's rows for the lowered snapshot, which states no table
        // other than the build does.
        let tables = session_tables(&lowered, &Captures::default());
        for (door, core) in rows.iter().zip(tables.rows()) {
            assert_eq!(door.door.entry_bytes, core.entry_bytes, "{door:?}");
        }
        // The listener, opened with no document, still counts its queues at the build's size.
        assert_eq!(
            row(&at_build, "link transmit queues").door.entry_bytes,
            SessionLimits::defaults().pico_unicast_batch_bytes()
        );

        let sum: usize = rows
            .iter()
            .filter(|row| row.door.bounded == 1)
            .map(|row| row.door.total_bytes)
            .sum();
        assert_eq!(summary.total_bytes, sum);
        assert_eq!(
            summary.bounded,
            u8::from(rows.iter().all(|row| row.door.bounded == 1))
        );

        z_session_drop(z_session_move(&mut dialer));
        z_session_drop(z_session_move(&mut listener));
    }
}

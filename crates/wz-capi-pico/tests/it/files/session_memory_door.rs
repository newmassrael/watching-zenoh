// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The worst-case memory of a session through its C doors (`zext_session_memory`,
//! `zext_session_memory_row`): a session that listens and one that dials it.
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
    zext_session_memory, zext_session_memory_row, zext_session_memory_row_t, zext_session_memory_t,
};
use wz_capi_pico::{
    z_config_default, z_config_loan_mut, z_config_move, z_loaned_session_t, z_open,
    z_owned_config_t, z_owned_session_t, z_session_drop, z_session_loan, z_session_move,
    zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_ERR_NULL, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;
use wz_session_core::limits::SessionLimits;
#[cfg(feature = "engine-tokio")]
use wz_session_core::policy::SessionPolicy;
#[cfg(feature = "engine-tokio")]
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
    door: zext_session_memory_row_t,
}

unsafe fn report(session: *const z_loaned_session_t) -> (zext_session_memory_t, Vec<Row>) {
    let mut summary = zext_session_memory_t::default();
    assert_eq!(zext_session_memory(session, &mut summary), Z_OK);
    let rows = (0..summary.rows)
        .map(|index| {
            let mut door: zext_session_memory_row_t = std::mem::zeroed();
            door.struct_size = std::mem::size_of::<zext_session_memory_row_t>();
            assert_eq!(zext_session_memory_row(session, index, &mut door), Z_OK);
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
#[cfg(feature = "engine-tokio")]
fn queued_batches(limits: &SessionLimits) -> usize {
    TxQueueConf::pico_of_snapshot(&SessionPolicy::defaults(), limits)
        .sizes
        .iter()
        .sum()
}

/// The batches one link holds to transmit from on the cooperative engine: the slots its arena
/// lends each link, whatever queue sizes `limits` states.
#[cfg(not(feature = "engine-tokio"))]
fn queued_batches(_limits: &SessionLimits) -> usize {
    wz_capi_coop::arena::LINK_TX_SLOTS
}

/// The basis the transmit row names: the queue sizes on the tokio engine, the arena's slots on the
/// cooperative one.
#[cfg(feature = "engine-tokio")]
const TX_BASIS: &str = "PICO_TX_QUEUE_SIZE";
#[cfg(not(feature = "engine-tokio"))]
const TX_BASIS: &str = if wz_capi_coop::arena::LINKS_SHARE_POOLS {
    "TX_POOL_SLOTS"
} else {
    "LINK_TX_SLOTS"
};

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

/// Each row is also printed, so a run with `--nocapture` under a build's limits is the table of
/// what that build's open reserves, row by row, which the heap cells of the parity matrix are read
/// against.
#[test]
fn the_total_is_the_sum_of_the_bounded_rows() {
    let _program = crate::programs::admit();
    with_two_sessions(|listener, dialer| {
        for (role, session) in [("listener", listener), ("dialer", dialer)] {
            let (summary, rows) = unsafe { report(session) };
            assert!(!rows.is_empty(), "a session holds something");
            let mut sum = 0usize;
            for row in &rows {
                let door = &row.door;
                eprintln!(
                    "session memory {role}: {} ({}): {} x {} = {}",
                    row.part, row.basis, door.count, door.entry_bytes, door.total_bytes
                );
                if door.bounded == 1 {
                    assert_eq!(door.total_bytes, door.count * door.entry_bytes, "{row:?}");
                    sum += door.total_bytes;
                } else {
                    assert_eq!((door.count, door.total_bytes, door.enforced), (0, 0, 0));
                }
            }
            eprintln!("session memory {role}: total {}", summary.total_bytes);
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
    let _program = crate::programs::admit();
    with_two_sessions(|_listener, dialer| {
        let (_, rows) = unsafe { report(dialer) };
        // A config that states no limit opens under zenoh-pico's preset, as every session of the
        // ABI does.
        let tables = session_tables(&SessionLimits::PICO_PRESET, &Captures::default());
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
    let _program = crate::programs::admit();
    with_two_sessions(|listener, dialer| {
        let (_, dialled) = unsafe { report(dialer) };
        let handle = row(&dialled, "session handle");
        assert_eq!((handle.door.bounded, handle.door.count), (1, 1));
        assert!(handle.basis.is_empty());

        // A config that states no limit opens under zenoh-pico's preset.
        let limits = SessionLimits::PICO_PRESET;
        let queue = row(&dialled, "link transmit queues");
        assert_eq!(queue.basis, TX_BASIS);
        assert_eq!(
            (queue.door.bounded, queue.door.count, queue.door.entry_bytes),
            (
                1,
                queued_batches(&limits),
                limits.pico_unicast_batch_bytes()
            )
        );
        let message = limits
            .pico_frag_max_bytes()
            .most()
            .expect("the build bounds a rejoined message");
        // The tokio engine rejoins the two reliabilities of its one link apart and reads into the
        // read storage its open states; the cooperative engine stages chains in the session's one
        // table and reads into a buffer of the batch it advertised, which no agreed batch outgrows.
        #[cfg(feature = "engine-tokio")]
        let (chains, rx_bytes) = (2, wz_session_core::session_init_params::RX_BUFFER_SIZE);
        #[cfg(not(feature = "engine-tokio"))]
        let (chains, rx_bytes) = (
            wz_capi_coop::arena::link_buffers(
                1,
                0,
                u16::try_from(limits.pico_unicast_batch_bytes()).expect("a batch is a u16"),
                &limits,
            )
            .expect("the preset's batch and pools")
            .chains,
            limits.pico_unicast_batch_bytes(),
        );
        let reassembly = row(&dialled, "link reassembly");
        assert_eq!(
            (reassembly.door.count, reassembly.door.entry_bytes),
            (chains, message)
        );
        let buffer = row(&dialled, "link receive buffers");
        assert_eq!((buffer.door.count, buffer.door.entry_bytes), (1, rx_bytes));

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
            let batch = limits.pico_unicast_batch_bytes();
            // The listener dials nothing: its links are its faces, and the one table they share
            // holds the session's share for each face read where it lies.
            let faces = wz_capi_coop::arena::admitted_faces(&limits).expect("the preset's faces");
            let shared = wz_capi_coop::arena::link_buffers(
                faces,
                faces,
                u16::try_from(batch).expect("a batch is a u16"),
                &limits,
            )
            .expect("the preset's batch and pools")
            .chains;
            assert!(
                shared >= chains,
                "a share for each face, the dial's at least"
            );
            assert_eq!(
                (reassembly.door.bounded, reassembly.door.count),
                (1, shared),
                "a listener's links share the session's one table"
            );
            // The listener's links read and encode into buffers of the advertised batch; where
            // they share pools, the pools' and not one for each of the ten faces.
            let (receive, transmit) = (
                row(&listened, "link receive buffers"),
                row(&listened, "link transmit queues"),
            );
            assert_eq!(
                (receive.door.entry_bytes, transmit.door.entry_bytes),
                (batch, batch)
            );
            if wz_capi_coop::arena::LINKS_SHARE_POOLS {
                assert!(receive.door.count <= limits.rx_pool_buffers());
                assert!(transmit.door.count <= limits.tx_pool_slots());
                assert!(
                    receive.door.total_bytes + transmit.door.total_bytes
                        <= (limits.rx_pool_buffers() + limits.tx_pool_slots()) * batch,
                    "the links' buffers are the pools' bytes"
                );
            }
        }
    });
}

#[test]
fn a_row_past_the_last_and_null_arguments_are_refused() {
    let _program = crate::programs::admit();
    with_two_sessions(|_listener, dialer| unsafe {
        let mut summary = zext_session_memory_t::default();
        assert_eq!(zext_session_memory(dialer, &mut summary), Z_OK);
        let mut out: zext_session_memory_row_t = std::mem::zeroed();
        out.struct_size = std::mem::size_of::<zext_session_memory_row_t>();
        out.entry_bytes = 7;
        assert_eq!(
            zext_session_memory_row(dialer, summary.rows, &mut out),
            Z_EINVAL
        );
        assert_eq!(out.entry_bytes, 7, "a refused row leaves out as it was");
        assert_eq!(
            zext_session_memory(dialer, std::ptr::null_mut()),
            Z_ERR_NULL
        );
        assert_eq!(
            zext_session_memory(std::ptr::null(), &mut summary),
            Z_ERR_NULL
        );
        assert_eq!(
            zext_session_memory_row(dialer, 0, std::ptr::null_mut()),
            Z_ERR_NULL
        );
        assert_eq!(
            zext_session_memory_row(std::ptr::null(), 0, &mut out),
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
    let _program = crate::programs::admit();
    use wz_capi_pico::config_policy::zext_config_document;
    use wz_capi_pico::result::Z_ERR_CONFIG_INVALID_VALUE;
    use wz_capi_pico::z_config_drop;

    // The document states its limit over the preset the session would open under without it.
    let mut lowered = SessionLimits::PICO_PRESET;
    let selectable = lowered
        .select_pico_unicast_batch_bytes(LOWERED_BATCH_BYTES)
        .is_ok();
    unsafe {
        let port = free_port();
        let mut listener = open_role(port, Z_CONFIG_LISTEN_KEY);
        let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
        let document = CString::new(format!(
            "{{ zext: {{ limits: {{ PICO_UNICAST_BATCH_BYTES: {LOWERED_BATCH_BYTES} }} }} }}"
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
        let stated = zext_config_document(z_config_loan_mut(&mut cfg), document.as_ptr());
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
        // The listener, opened with no document, still counts its queues at the preset's size.
        assert_eq!(
            row(&at_build, "link transmit queues").door.entry_bytes,
            SessionLimits::PICO_PRESET.pico_unicast_batch_bytes()
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

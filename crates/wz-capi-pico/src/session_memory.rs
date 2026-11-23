// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_session_memory` and `wz_ext_session_memory_row`: the most memory a session holds,
//! part by part, computed from the limits it opened under.
//!
//! # The rows
//!
//! Every row is read from the session's own snapshot of its limits: the one its open resolved from
//! the config, a document's `wz/limits` included, and handed the engine. The session's tables are
//! the session core's rows (`wz_session_core::session_memory`) for that snapshot. This ABI adds
//! what it holds itself and what each link of the session holds, each from the value the open
//! handed the engine:
//!
//! - the session's handle, once;
//! - each link's transmit queue: as many batches as the queue sizes the snapshot states, one size
//!   for each priority (`PICO_TX_QUEUE_SIZE`), each batch at most the batch the session advertises
//!   (`PICO_UNICAST_BATCH_BYTES`): no batch the two sides of a link agree on is larger;
//! - each link's receive buffer, the read storage the open states (upstream's default, one buffer
//!   of the widest batch, `RX_BUFFER_SIZE`), which no batch of the session's outgrows;
//! - each link's reassembly: a message of at most `PICO_FRAG_MAX_BYTES` for each of the two
//!   reliabilities a link rejoins apart, as upstream keeps one buffer for each; a snapshot that
//!   states no bound leaves the row without a count.
//!
//! Then the machines the process holds apart from any session, each counted once, from the rows
//! the process's runtime limits lend them (`wz_capi_port::runtime_limits`), in a build with each:
//!
//! - the process's supervisor of checkpoints, whose storage is the build's
//!   `SUPERVISION_CHECKPOINTS` checkpoints however many of them the runtime has it watch;
//! - one message catalog: as many messages as the runtime's `MESSAGE_CATALOG_ENTRIES` lends it,
//!   each the reader's own row, whose texts are beside it and not counted, so the row is not
//!   enforced;
//! - one reception supervisor: the rows of the program's storage it may use, as many as the
//!   runtime's `E2E_SUPERVISED_STREAMS` lends it. The storage is the program's, so this is the
//!   bound of what is used of it.
//!
//! A session that only dials holds one link. A listening session on the tokio engine accepts links
//! to no bound, and a session on a group rejoins the messages of every member, so their link rows
//! have no count; on the cooperative engine a listening session holds at most the faces its open
//! bounds it to and its dial.
//!
//! # What the rows are of
//!
//! The rows are what the limits size. A closure an engine boxes into a table is counted at the
//! box's own layers, as capturing nothing: what it captures is the engine's type. An engine's own
//! state, its runtime, its threads and its tasks, is sized by no limit and is outside the rows, and
//! so are the objects behind the handles a program holds. Whether the build refuses past every
//! row is `wz_ext_session_memory_t::enforced`.

use core::ffi::c_char;

use wz_session_core::limits::SessionLimits;
use wz_session_core::process_limits::ProcessRows;
use wz_session_core::session_memory::{session_tables, Captures, MemoryRow, SessionMemory};

use crate::ffi::guarded;
use crate::result::{ZResult, Z_EINVAL, Z_ERR_NULL, Z_OK};
use crate::session::{session_handle, z_loaned_session_t, PicoSessionHandle};

/// The most memory a session holds, as `wz_ext_session_memory` reports it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct wz_ext_session_memory_t {
    /// The sum of the rows that have a count: the most the session holds when `bounded` is 1.
    pub total_bytes: usize,
    /// How many rows `wz_ext_session_memory_row` reports.
    pub rows: usize,
    /// 1 when every row has a count, so that `total_bytes` is the session's worst case.
    pub bounded: u8,
    /// 1 when, besides, the build refuses past every row's count and entry size.
    pub enforced: u8,
    pub reserved: [u8; 6],
}

/// One part of what a session holds, as `wz_ext_session_memory_row` reports it.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct wz_ext_session_memory_row_t {
    /// What holds the bytes: a static string of the library.
    pub part: *const c_char,
    /// The limit, or the build's value, whose number sizes the row: a static string of the
    /// library, empty for a part every session has once.
    pub basis: *const c_char,
    /// How many items the row counts; 0 when `bounded` is 0.
    pub count: usize,
    /// The bytes of one item.
    pub entry_bytes: usize,
    /// `count` times `entry_bytes`; 0 when `bounded` is 0.
    pub total_bytes: usize,
    /// 1 when the row has a count.
    pub bounded: u8,
    /// 1 when the build refuses past the row's count and entry size.
    pub enforced: u8,
    pub reserved: [u8; 6],
}

/// What a session's open decided that its report is computed from: the limits it opened under, and
/// the numbers its links were opened with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MemoryBasis {
    /// The limits the session runs under.
    pub(crate) limits: SessionLimits,
    /// How many links the session holds at most; `None` where its open bounds them to none.
    pub(crate) links: Option<usize>,
    /// The batches one link's transmit queue holds, every priority's together.
    pub(crate) queue_batches: usize,
    /// The bytes of one batch: the batch the session advertises.
    pub(crate) batch_bytes: usize,
    /// The bytes of one link's receive buffer.
    pub(crate) rx_bytes: usize,
    /// The longest message one link rejoins from fragments; `None` where the limits state no bound.
    pub(crate) message_bytes: Option<usize>,
}

impl Default for MemoryBasis {
    /// A session whose open stated nothing: the build's limits and no bound on its links, so its
    /// report has no total rather than a total too small.
    fn default() -> Self {
        Self {
            limits: SessionLimits::defaults(),
            links: None,
            queue_batches: 0,
            batch_bytes: 0,
            rx_bytes: 0,
            message_bytes: None,
        }
    }
}

/// The rows this ABI adds to the session core's: the handle and the link rows of the module docs.
const ABI_ROWS: usize = 4;

/// The rows of the machines the process holds apart from any session, one for each this build has.
const PROCESS_ROWS: usize = cfg!(feature = "supervision") as usize
    + cfg!(feature = "message-catalog") as usize
    + cfg!(feature = "e2e-supervision") as usize;

const _: () = assert!(
    wz_session_core::session_memory::SESSION_TABLE_ROWS + ABI_ROWS + PROCESS_ROWS
        <= wz_session_core::session_memory::MEMORY_ROWS
);

/// How many links a session whose open listens on `listen` (none for one that only dials) holds
/// at most: one for a dial, and on the tokio engine no bound for a listener, which accepts every
/// link that completes its handshake whatever its limits state.
#[cfg(feature = "engine-tokio")]
pub(crate) fn links_of(
    listen: Option<&str>,
    _dials: bool,
    _limits: &SessionLimits,
) -> Option<usize> {
    match listen {
        None => Some(1),
        Some(_) => None,
    }
}

/// How many links a session whose open listens on `listen` (none for one that only dials) holds
/// at most on the cooperative engine under `limits`: one for a dial; for a listener, the faces
/// besides its dial that its `MAX_FACES` admits (`crate::session::faces_besides_dial`) and the
/// dial's own link only when it `dials`, as the engine's arena lends the dial role a link only
/// to a session that lists an endpoint to dial (its `dials`), so a listener holds its
/// `MAX_FACES` either way; none for a group, which rejoins the messages of every member, nor for
/// a value over the build's, which the open refuses.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) fn links_of(listen: Option<&str>, dials: bool, limits: &SessionLimits) -> Option<usize> {
    let Some(endpoint) = listen else {
        return Some(1);
    };
    #[cfg(feature = "peer")]
    if crate::session::is_group_endpoint(endpoint) {
        return None;
    }
    #[cfg(not(feature = "peer"))]
    let _ = endpoint;
    crate::session::faces_besides_dial(
        Some(wz_capi_coop::arena::admitted_faces(limits).ok()?),
        dials,
    )
    .checked_add(usize::from(dials))
}

impl MemoryBasis {
    /// The session's report: the session core's rows for its limits, this ABI's, and those of the
    /// machines of the process under the rows its runtime limits lend them.
    pub(crate) fn report(&self) -> SessionMemory {
        self.report_with(&wz_capi_port::runtime_limits::held())
    }

    /// [`Self::report`], the process's machines lent `process`.
    fn report_with(&self, process: &ProcessRows) -> SessionMemory {
        let mut memory = session_tables(&self.limits, &Captures::default());
        let per_link = |items: usize| self.links.and_then(|links| links.checked_mul(items));
        let rows = [
            MemoryRow {
                part: c"session handle",
                basis: c"",
                count: Some(1),
                entry_bytes: core::mem::size_of::<PicoSessionHandle>(),
                enforced: true,
            },
            MemoryRow {
                part: c"link transmit queues",
                basis: c"PICO_TX_QUEUE_SIZE",
                count: per_link(self.queue_batches),
                entry_bytes: self.batch_bytes,
                enforced: self.links.is_some(),
            },
            MemoryRow {
                part: c"link receive buffers",
                basis: c"RX_BUFFER_SIZE",
                count: per_link(1),
                entry_bytes: self.rx_bytes,
                enforced: self.links.is_some(),
            },
            MemoryRow {
                part: c"link reassembly",
                basis: c"PICO_FRAG_MAX_BYTES",
                count: self.message_bytes.and(per_link(2)),
                entry_bytes: self.message_bytes.unwrap_or(0),
                enforced: self.links.is_some() && self.message_bytes.is_some(),
            },
        ];
        for row in rows {
            memory
                .push(row)
                .expect("the rows fit: asserted when the build is made");
        }
        push_process_rows(&mut memory, process);
        memory
    }
}

/// Add the rows of the machines the process holds apart from any session to `memory`, `process`
/// the rows its runtime limits lend them (the module docs): one for each machine the build has.
// A build without some of the machines leaves `memory` or `process` unread.
#[allow(unused_variables)]
fn push_process_rows(memory: &mut SessionMemory, process: &ProcessRows) {
    #[cfg(feature = "supervision")]
    memory
        .push(MemoryRow {
            part: c"process supervisor",
            basis: c"SUPERVISION_CHECKPOINTS",
            count: Some(1),
            entry_bytes: core::mem::size_of::<wz_session_core::supervisor::BuildSupervisor>(),
            enforced: true,
        })
        .expect("the rows fit: asserted when the build is made");
    #[cfg(feature = "message-catalog")]
    memory
        .push(MemoryRow {
            part: c"message catalog entries",
            basis: c"MESSAGE_CATALOG_ENTRIES",
            count: Some(process.message_catalog_entries),
            entry_bytes: core::mem::size_of::<wz_app_frame::message_catalog::Message>(),
            enforced: false,
        })
        .expect("the rows fit: asserted when the build is made");
    #[cfg(feature = "e2e-supervision")]
    memory
        .push(MemoryRow {
            part: c"stream supervisor rows",
            basis: c"E2E_SUPERVISED_STREAMS",
            count: Some(process.e2e_supervised_streams),
            entry_bytes: core::mem::size_of::<wz_session_core::stream_supervisor::StreamSlot>(),
            enforced: true,
        })
        .expect("the rows fit: asserted when the build is made");
}

/// `row` as the C door hands it over.
fn row_of(row: &MemoryRow) -> wz_ext_session_memory_row_t {
    let total = row.total();
    wz_ext_session_memory_row_t {
        part: row.part.as_ptr(),
        basis: row.basis.as_ptr(),
        count: total.and(row.count).unwrap_or(0),
        entry_bytes: row.entry_bytes,
        total_bytes: total.unwrap_or(0),
        bounded: u8::from(total.is_some()),
        enforced: u8::from(total.is_some() && row.enforced),
        reserved: [0; 6],
    }
}

/// Write the most memory `session` holds into `*out`: the sum of the rows that have a count,
/// how many rows there are, and whether every row has a count and whether the build refuses past
/// every one. A closed session reports what it held while open.
///
/// Returns `Z_OK`; `Z_ERR_NULL` for a null `out`, a null session or one with no handle.
///
/// # Safety
/// `session` is null or a loaned session of this library; `out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_session_memory(
    session: *const z_loaned_session_t,
    out: *mut wz_ext_session_memory_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ERR_NULL;
        }
        let Some(handle) = session_handle(session) else {
            return Z_ERR_NULL;
        };
        let memory = handle.memory.report();
        let total = memory.total();
        *out = wz_ext_session_memory_t {
            total_bytes: memory.bounded_bytes(),
            rows: memory.rows().len(),
            bounded: u8::from(total.is_some()),
            enforced: u8::from(memory.is_enforced()),
            reserved: [0; 6],
        };
        Z_OK
    })
}

/// Write row `index` of what `session` holds into `*out`, rows counted from 0 in the order
/// `wz_ext_session_memory` sums them.
///
/// Returns `Z_OK`; `Z_ERR_NULL` for a null `out`, a null session or one with no handle;
/// `Z_EINVAL` for an index past the last row, leaving `*out` as it was.
///
/// # Safety
/// `session` is null or a loaned session of this library; `out` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_session_memory_row(
    session: *const z_loaned_session_t,
    index: usize,
    out: *mut wz_ext_session_memory_row_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ERR_NULL;
        }
        let Some(handle) = session_handle(session) else {
            return Z_ERR_NULL;
        };
        let memory = handle.memory.report();
        let Some(row) = memory.rows().get(index) else {
            return Z_EINVAL;
        };
        *out = row_of(row);
        Z_OK
    })
}

#[cfg(test)]
mod tests {
    use core::ffi::CStr;

    use super::*;

    /// A row with no count is handed over as unbounded, with no count and no total, and never as
    /// enforced; a row with one carries its count, its entry and their product.
    #[test]
    fn a_row_is_handed_over_with_its_bound() {
        let unbounded = row_of(&MemoryRow {
            part: c"subscribers",
            basis: c"MAX_SUBSCRIPTIONS",
            count: None,
            entry_bytes: 48,
            enforced: true,
        });
        assert_eq!(
            (
                unbounded.count,
                unbounded.total_bytes,
                unbounded.bounded,
                unbounded.enforced
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(unbounded.entry_bytes, 48);
        let bounded = row_of(&MemoryRow {
            part: c"link reassembly",
            basis: c"PICO_FRAG_MAX_BYTES",
            count: Some(2),
            entry_bytes: 4096,
            enforced: true,
        });
        assert_eq!(
            (
                bounded.count,
                bounded.total_bytes,
                bounded.bounded,
                bounded.enforced
            ),
            (2, 8192, 1, 1)
        );
        // SAFETY: the pointers are the static strings the row names.
        let (part, basis) =
            unsafe { (CStr::from_ptr(bounded.part), CStr::from_ptr(bounded.basis)) };
        assert_eq!((part, basis), (c"link reassembly", c"PICO_FRAG_MAX_BYTES"));
    }

    /// A session that only dials holds one link; a listener on the tokio engine holds links to no
    /// bound, and on the cooperative engine its faces' bound, its dial one of them when it dials
    /// and holding no link when it does not: the build's `MAX_FACES` for a session that states
    /// none, and the value a session lowers it to.
    #[test]
    fn a_dial_holds_one_link_and_a_listener_its_engines_bound() {
        let limits = SessionLimits::defaults();
        assert_eq!(links_of(None, true, &limits), Some(1));
        #[cfg(feature = "engine-tokio")]
        assert_eq!(links_of(Some("tcp/127.0.0.1:7447"), false, &limits), None);
        #[cfg(not(feature = "engine-tokio"))]
        {
            assert_eq!(
                links_of(Some("tcp/127.0.0.1:7447"), false, &limits),
                Some(wz_session_core::caps::MAX_FACES)
            );
            let mut lowered = SessionLimits::defaults();
            if lowered
                .select_max_faces(wz_session_core::limit_binding::Quota::at_most(10))
                .is_ok()
            {
                // A listener that dials nothing lends its dial role no link.
                assert_eq!(
                    links_of(Some("tcp/127.0.0.1:7447"), false, &lowered),
                    Some(10)
                );
                // A listener that dials a peer holds it as one of its ten, as pico's does.
                assert_eq!(
                    links_of(Some("tcp/127.0.0.1:7447"), true, &lowered),
                    Some(10)
                );
                assert_eq!(
                    links_of(None, true, &lowered),
                    Some(1),
                    "a dial holds one link still"
                );
            }
        }
        #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
        assert_eq!(
            links_of(Some("udp/224.0.0.224:7446#iface=lo"), false, &limits),
            None
        );
    }

    /// A session whose open stated nothing reports the session core's rows, this ABI's four and
    /// one for each machine of the process the build has, and no total, as its links have no
    /// bound; its handle is the row of one.
    #[test]
    fn a_basis_with_no_bound_on_its_links_reports_no_total() {
        let memory = MemoryBasis::default().report();
        let tables = session_tables(&SessionLimits::defaults(), &Captures::default());
        assert_eq!(
            memory.rows().len(),
            tables.rows().len() + ABI_ROWS + PROCESS_ROWS
        );
        assert_eq!(&memory.rows()[..tables.rows().len()], tables.rows());
        let handle = memory.rows()[tables.rows().len()];
        assert_eq!(handle.part, c"session handle");
        assert_eq!(
            handle.total(),
            Some(core::mem::size_of::<PicoSessionHandle>())
        );
        assert_eq!(memory.total(), None);
    }

    /// The rows of the process's machines follow the rows its runtime lends them: a runtime that
    /// lends fewer catalog entries and stream rows reports fewer bytes for them, and the
    /// supervisor's storage, which the build's value sizes, stays as it was.
    #[test]
    fn the_process_rows_follow_what_the_runtime_lends() {
        let lowered = ProcessRows {
            supervision_checkpoints: 1,
            message_catalog_entries: 1,
            e2e_supervised_streams: 1,
        };
        let basis = MemoryBasis::default();
        let (build, low) = (
            basis.report_with(&ProcessRows::BUILD),
            basis.report_with(&lowered),
        );
        let row = |memory: &SessionMemory, part: &CStr| {
            memory
                .rows()
                .iter()
                .find(|row| row.part == part)
                .map(|row| (row.count, row.entry_bytes))
        };
        assert_eq!(
            row(&build, c"process supervisor"),
            row(&low, c"process supervisor")
        );
        #[cfg(feature = "message-catalog")]
        {
            let entry = core::mem::size_of::<wz_app_frame::message_catalog::Message>();
            assert_eq!(
                row(&build, c"message catalog entries"),
                Some((Some(ProcessRows::BUILD.message_catalog_entries), entry))
            );
            assert_eq!(
                row(&low, c"message catalog entries"),
                Some((Some(1), entry))
            );
        }
        #[cfg(feature = "e2e-supervision")]
        {
            let entry = core::mem::size_of::<wz_session_core::stream_supervisor::StreamSlot>();
            assert_eq!(
                row(&build, c"stream supervisor rows"),
                Some((Some(ProcessRows::BUILD.e2e_supervised_streams), entry))
            );
            assert_eq!(row(&low, c"stream supervisor rows"), Some((Some(1), entry)));
        }
        assert_eq!(
            low.rows().len(),
            build.rows().len(),
            "a machine's row is there whatever it is lent"
        );
    }

    /// The link rows are each link's queue, buffer and reassembly times the links.
    #[test]
    fn the_link_rows_are_per_link() {
        let basis = MemoryBasis {
            links: Some(3),
            queue_batches: 16,
            batch_bytes: 2048,
            rx_bytes: 65535,
            message_bytes: Some(4096),
            ..MemoryBasis::default()
        };
        let memory = basis.report();
        let link = |part: &CStr| {
            *memory
                .rows()
                .iter()
                .find(|row| row.part == part)
                .expect("the report has the part")
        };
        assert_eq!(link(c"link transmit queues").total(), Some(3 * 16 * 2048));
        assert_eq!(link(c"link receive buffers").total(), Some(3 * 65535));
        assert_eq!(link(c"link reassembly").total(), Some(3 * 2 * 4096));
    }

    /// A reassembly the limits hold to no bound has no count and is not enforced, so the report
    /// has no total; the rows that have one still sum to the bounded bytes, the reassembly's
    /// bytes left out.
    #[test]
    fn a_reassembly_with_no_bound_leaves_the_report_without_a_total() {
        let bounded = MemoryBasis {
            links: Some(1),
            queue_batches: 16,
            batch_bytes: 2048,
            rx_bytes: 65535,
            message_bytes: Some(4096),
            ..MemoryBasis::default()
        };
        let unbounded = MemoryBasis {
            message_bytes: None,
            ..bounded
        };
        let memory = unbounded.report();
        let reassembly = *memory
            .rows()
            .iter()
            .find(|row| row.part == c"link reassembly")
            .expect("the report has the part");
        assert_eq!(
            (reassembly.count, reassembly.total(), reassembly.enforced),
            (None, None, false)
        );
        assert_eq!(memory.total(), None);
        assert!(!memory.is_enforced());
        assert_eq!(
            memory.bounded_bytes(),
            bounded.report().bounded_bytes() - 2 * 4096
        );
    }
}

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

const _: () = assert!(
    wz_session_core::session_memory::SESSION_TABLE_ROWS + ABI_ROWS
        <= wz_session_core::session_memory::MEMORY_ROWS
);

/// How many links a session whose open listens on `listen` (none for one that only dials) holds
/// at most: one for a dial, and on the tokio engine no bound for a listener, which accepts every
/// link that completes its handshake.
#[cfg(feature = "engine-tokio")]
pub(crate) fn links_of(listen: Option<&str>) -> Option<usize> {
    match listen {
        None => Some(1),
        Some(_) => None,
    }
}

/// How many links a session whose open listens on `listen` (none for one that only dials) holds
/// at most on the cooperative engine: one for a dial; for a listener, the faces the open bounds it
/// to and its dial; none for a group, which rejoins the messages of every member.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) fn links_of(listen: Option<&str>) -> Option<usize> {
    let Some(endpoint) = listen else {
        return Some(1);
    };
    #[cfg(feature = "peer")]
    if crate::session::is_group_endpoint(endpoint) {
        return None;
    }
    #[cfg(not(feature = "peer"))]
    let _ = endpoint;
    wz_capi_coop::DEFAULT_MAX_FACES.checked_add(1)
}

impl MemoryBasis {
    /// The session's report: the session core's rows for its limits, and this ABI's.
    pub(crate) fn report(&self) -> SessionMemory {
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
        memory
    }
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
    /// bound, and on the cooperative engine its faces' bound and its dial.
    #[test]
    fn a_dial_holds_one_link_and_a_listener_its_engines_bound() {
        assert_eq!(links_of(None), Some(1));
        #[cfg(feature = "engine-tokio")]
        assert_eq!(links_of(Some("tcp/127.0.0.1:7447")), None);
        #[cfg(not(feature = "engine-tokio"))]
        assert_eq!(
            links_of(Some("tcp/127.0.0.1:7447")),
            Some(wz_capi_coop::DEFAULT_MAX_FACES + 1)
        );
        #[cfg(all(not(feature = "engine-tokio"), feature = "peer"))]
        assert_eq!(links_of(Some("udp/224.0.0.224:7446#iface=lo")), None);
    }

    /// A session whose open stated nothing reports the session core's rows and this ABI's four,
    /// and no total, as its links have no bound; its handle is the row of one.
    #[test]
    fn a_basis_with_no_bound_on_its_links_reports_no_total() {
        let memory = MemoryBasis::default().report();
        let tables = session_tables(&SessionLimits::defaults(), &Captures::default());
        assert_eq!(memory.rows().len(), tables.rows().len() + ABI_ROWS);
        assert_eq!(&memory.rows()[..tables.rows().len()], tables.rows());
        let handle = memory.rows()[tables.rows().len()];
        assert_eq!(handle.part, c"session handle");
        assert_eq!(
            handle.total(),
            Some(core::mem::size_of::<PicoSessionHandle>())
        );
        assert_eq!(memory.total(), None);
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

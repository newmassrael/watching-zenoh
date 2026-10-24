// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The memory gate (design D7): what a replayed capture's handle keeps per row.
//!
//! A consumer reported that a dissection handle held five to six times the
//! capture file it was opened from. A list of rows now keeps a 48-byte entry per
//! message and reads its bytes again from a source (the stream, or a unit log),
//! so the handle's heap per row is a small constant. Nothing but this keeps it
//! so: a change that stores a decoded message beside the entry again would pass
//! every behaviour test and bring the multiple back.
//!
//! The gate opens a capture through the C ABI the consumer uses, does what the
//! consumer does (read every row, take a field window, take the census), and
//! counts the bytes the handle holds, with the strings the calls returned
//! already given back. It is read at two points, because they fail for different
//! reasons:
//!
//! * after the replay, which is the row structure: the entries, the units' bytes
//!   the handle keeps, the index beside them;
//! * after the reads, which adds what the field walk and the census keep for the
//!   next call (their resumable memories).
//!
//! Each is held to a ceiling per row that is the measured value plus 10%, for
//! each transport and each replay door. The doors are separate cases because the
//! owned door copies what it reads and the lent door keeps only where it is in
//! the caller's file, and a stream list and a datagram list keep their rows in
//! different places, so one figure cannot vouch for another. A ceiling that moved
//! is a decision to be recorded where the measured value is, not a number to be
//! raised until the test passes.
//!
//! It also fails when
//!
//! * the figure at twice the size exceeds the ceiling, which is what a cost
//!   growing faster than the row count looks like;
//! * closing the handle leaves bytes behind;
//! * the fixed part of an empty handle outgrows its bound.
//!
//! The judgment is in bytes, not time: a byte count does not move with the host.
//! The counter is per thread, so the test harness's own allocations on other
//! threads cannot disturb it; everything this reads runs on the calling thread.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ffi::{c_char, c_int, CStr};

use wz_capi_dissect::live::LiveDissection;
use wz_capi_dissect::{
    wz_dissect_live_census, wz_dissect_live_close, wz_dissect_live_drain,
    wz_dissect_live_fields_since_window, wz_dissect_pcap_replay, wz_dissect_pcap_replay_lent,
    wz_dissect_string_free, WzDissectRecord, WZ_DISSECT_LIMITS_NONE, WZ_DISSECT_OK,
};
use wz_capture::fixtures::{push_run_capture, RunTransport};

thread_local! {
    /// Bytes this thread has allocated and not yet freed. `const`-initialised, so
    /// reading it never allocates.
    static OUTSTANDING: Cell<isize> = const { Cell::new(0) };
}

struct Counting;

// SAFETY: every call is forwarded to the system allocator unchanged; the counter
// only observes the sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = OUTSTANDING.try_with(|c| c.set(c.get() + layout.size() as isize));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = OUTSTANDING.try_with(|c| c.set(c.get() - layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ =
            OUTSTANDING.try_with(|c| c.set(c.get() + new_size as isize - layout.size() as isize));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn outstanding() -> isize {
    OUTSTANDING.with(Cell::get)
}

/// The handshake's four messages, which a capture of `pushes` messages also holds.
const HANDSHAKE_ROWS: usize = 4;

/// The size the gate measures at, and twice it for the growth.
const ROWS: usize = 20_000;

/// What an empty handle (a handshake and no pushes) may hold. Measured at about
/// 46 KiB; the bound is what keeps a table sized for the largest capture out of
/// the handle every capture pays for.
const FLOOR_BOUND: isize = 64 * 1024;

/// Which replay door opens the capture.
#[derive(Clone, Copy)]
enum Door {
    Owned,
    Lent,
}

/// One capture shape and door, with the ceilings its figures are held to.
///
/// Measured on the generator's fixture at 20 000 and 40 000 pushes (bytes per
/// row, above the empty handle's), each ceiling that value plus 10%, rounded up
/// to an even number:
///
/// | case        | after replay | after reads |
/// |-------------|--------------|-------------|
/// | udp owned   | 82.0         | 183.1       |
/// | udp lent    | 49.2         | 150.3       |
/// | tcp owned   | 130.4        | 251.4       |
/// | tcp lent    | 90.2         | 211.3       |
///
/// The capture file is 90 (udp) and 104 (tcp) bytes per row, so the handle holds
/// about 1.7 to 2.4 times the file after the reads on this fixture, whose packets
/// are the smallest a Push makes. A capture of larger messages shrinks the
/// multiple, because the per-row figures here do not grow with the payload.
struct Case {
    name: &'static str,
    transport: RunTransport,
    door: Door,
    after_replay_ceiling: f64,
    after_reads_ceiling: f64,
}

/// What one measurement found.
struct Measured {
    /// Rows the drain returned.
    rows: usize,
    /// Bytes the capture file is, for the report only.
    file_bytes: usize,
    /// Bytes the handle held after the replay.
    after_replay: isize,
    /// Bytes the handle held after the consumer's reads, strings given back.
    after_reads: isize,
    /// Bytes left over after the handle was closed.
    leaked: isize,
}

fn blank() -> WzDissectRecord {
    WzDissectRecord {
        ts_ns: 0,
        flow_id: 0,
        list_id: 0,
        anchor: 0,
        unit_len: 0,
        batch_index: 0,
        unit_offset: 0,
        direction: 0,
        anchor_space: 0,
        origin: 0,
        kind: 0,
        flags: 0,
    }
}

/// A returned string, copied out and given back. It is returned to be judged and
/// must be dropped before the count is taken: the document is the caller's
/// memory, and a count taken while it is alive would call it the handle's.
fn take_string(rc: c_int, out: *mut c_char, what: &str) -> String {
    assert_eq!(rc, WZ_DISSECT_OK, "{what} rc");
    assert!(!out.is_null(), "{what} returned no string");
    let text = unsafe { CStr::from_ptr(out) }
        .to_string_lossy()
        .into_owned();
    unsafe { wz_dissect_string_free(out) };
    text
}

fn measure(pushes: usize, transport: RunTransport, door: Door) -> Measured {
    let file = push_run_capture(pushes, transport);
    // The consumer's own buffer, sized before the count starts: it is the caller's
    // memory and not the handle's.
    let cap = pushes + HANDSHAKE_ROWS + 8;
    let mut buffer = vec![blank(); cap];

    let base = outstanding();
    let mut handle: *mut LiveDissection = core::ptr::null_mut();
    let rc = unsafe {
        match door {
            Door::Owned => wz_dissect_pcap_replay(
                file.as_ptr(),
                file.len(),
                WZ_DISSECT_LIMITS_NONE,
                &mut handle,
            ),
            // `file` stays alive until after the handle is closed below.
            Door::Lent => wz_dissect_pcap_replay_lent(
                file.as_ptr(),
                file.len(),
                WZ_DISSECT_LIMITS_NONE,
                &mut handle,
            ),
        }
    };
    assert_eq!(rc, WZ_DISSECT_OK, "replay rc");
    assert!(!handle.is_null(), "replay returned no handle");
    let after_replay = outstanding() - base;

    let mut written = usize::MAX;
    let rc = unsafe { wz_dissect_live_drain(handle, buffer.as_mut_ptr(), cap, &mut written) };
    assert_eq!(rc, WZ_DISSECT_OK, "drain rc");

    let mut out: *mut c_char = core::ptr::null_mut();
    let rc = unsafe {
        wz_dissect_live_fields_since_window(
            handle,
            core::ptr::null(),
            0,
            c"".as_ptr(),
            0,
            8192,
            &mut out,
        )
    };
    assert!(
        !take_string(rc, out, "fields window").is_empty(),
        "the field window is empty"
    );

    let mut out: *mut c_char = core::ptr::null_mut();
    let rc = unsafe { wz_dissect_live_census(handle, c"".as_ptr(), &mut out) };
    {
        let census = take_string(rc, out, "census");
        // The population the figures divide by: every push must have been read as
        // a message. A capture whose batches halt keeps rows that are not
        // messages, and the heap per such row says nothing about the rows of a
        // capture that decodes (the first fixture of this gate was one, and its
        // figures were the cost of rows that were never read).
        assert!(
            census.contains("\"halted_batches\":0,") && census.contains("\"unparsed_bytes\":0"),
            "the fixture's batches did not all parse: {}",
            &census[..census.len().min(400)]
        );
        if pushes > 0 {
            assert!(
                !census.contains("\"keyexprs\":{\"rows\":[],"),
                "the census saw no keyexpr, so no push was read as a message"
            );
        }
    }

    let after_reads = outstanding() - base;
    unsafe { wz_dissect_live_close(handle) };
    let leaked = outstanding() - base;

    Measured {
        rows: written,
        file_bytes: file.len(),
        after_replay,
        after_reads,
        leaked,
    }
}

fn gate(case: &Case) {
    let name = case.name;
    let floor = measure(0, case.transport, case.door);
    assert!(
        floor.after_reads <= FLOOR_BOUND,
        "{name}: an empty handle holds {} B, over the bound of {FLOOR_BOUND}",
        floor.after_reads
    );
    assert_eq!(
        floor.leaked, 0,
        "{name}: closing an empty handle left {} byte(s) behind",
        floor.leaked
    );

    for pushes in [ROWS, 2 * ROWS] {
        let m = measure(pushes, case.transport, case.door);
        assert_eq!(
            m.rows,
            pushes + HANDSHAKE_ROWS,
            "{name}: the drain must return every row, or the figures below divide by a \
             population that is not the capture's"
        );
        assert_eq!(
            m.leaked, 0,
            "{name}: closing the handle left {} byte(s) behind",
            m.leaked
        );
        let rows = m.rows as f64;
        let replay = (m.after_replay - floor.after_replay) as f64 / rows;
        let reads = (m.after_reads - floor.after_reads) as f64 / rows;
        eprintln!(
            "{name}: {} rows, file {:.2} B/row, after replay {replay:.2} B/row, \
             after reads {reads:.2} B/row",
            m.rows,
            m.file_bytes as f64 / rows,
        );
        assert!(
            replay <= case.after_replay_ceiling,
            "{name}: the handle holds {replay:.2} B per row after the replay at {} rows, \
             over the ceiling of {}: the row structure grew",
            m.rows,
            case.after_replay_ceiling
        );
        assert!(
            reads <= case.after_reads_ceiling,
            "{name}: the handle holds {reads:.2} B per row after the reads at {} rows, \
             over the ceiling of {}: what the field walk or the census keeps grew",
            m.rows,
            case.after_reads_ceiling
        );
    }
}

#[test]
fn a_datagram_capture_s_handle_holds_a_constant_per_row() {
    gate(&Case {
        name: "udp owned",
        transport: RunTransport::Datagram,
        door: Door::Owned,
        after_replay_ceiling: 90.0,
        after_reads_ceiling: 202.0,
    });
}

#[test]
fn a_lent_datagram_capture_s_handle_holds_a_constant_per_row() {
    gate(&Case {
        name: "udp lent",
        transport: RunTransport::Datagram,
        door: Door::Lent,
        after_replay_ceiling: 54.0,
        after_reads_ceiling: 166.0,
    });
}

#[test]
fn a_stream_capture_s_handle_holds_a_constant_per_row() {
    gate(&Case {
        name: "tcp owned",
        transport: RunTransport::Stream,
        door: Door::Owned,
        after_replay_ceiling: 144.0,
        after_reads_ceiling: 277.0,
    });
}

#[test]
fn a_lent_stream_capture_s_handle_holds_a_constant_per_row() {
    gate(&Case {
        name: "tcp lent",
        transport: RunTransport::Stream,
        door: Door::Lent,
        after_replay_ceiling: 100.0,
        after_reads_ceiling: 233.0,
    });
}

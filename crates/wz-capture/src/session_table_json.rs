// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session table as a document: one row per session, every cell a value or
//! an explicit `null` with the reason beside it.
//!
//! # What a row is
//!
//! See [`crate::session_table`] for the unit and for what is left out. The row's
//! cells are the ones a sessions editor shows, and a consumer maps them without
//! deciding anything:
//!
//! * `initiator`, `acceptor` -- the zid of the end that sent the InitSyn, and of
//!   the end that sent the InitAck;
//! * `link` -- `tcp`, `udp`, `raweth`, `vsock` or `serial`, the same word a
//!   field document's flow carries;
//! * `phase` -- the same words as a field document's `context.phase`;
//! * `encrypted` -- whether the session is in the clear;
//! * `first_seen_ts_ns`, `last_seen_ts_ns` -- the capture instants of the first
//!   and the last packet of the session, so a consumer derives an uptime from a
//!   clock the document states;
//! * `frames`, `bytes` -- the totals, which no retention bound moves;
//! * `flows` -- the flows the row is made of, each with the flow object every
//!   other document carries, for a consumer that joins.
//!
//! # EVERY KEY IS PRESENT, ALWAYS
//!
//! A cell that cannot be stated is `null`, and the row's `unstated` list holds
//! one `{"cell":...,"reason":...}` for it, so a cell is `null` exactly when it is
//! named there. The words a cell can carry are
//! [`crate::session_table::Cell::reasons`].
//!
//! # A refusal is a value
//!
//! A container that does not read is `{"ok":false,"refusal":...,"message":...}`
//! with a word from the closed set [`Refusal`]. It is a successful diagnosis
//! of the bytes, for the reason the other documents that refuse give: an error
//! code means no string, and a string means the library said something.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::session_table::{session_table, Cell, SessionRow, Stated, Unstated, Why};
use crate::{CaptureError, Dissection};

/// Why a container was refused, the closed set.
///
/// Three, and they are what a caller does differently: `not_a_capture` is the
/// wrong file, `truncated` is a file cut short (a download that did not finish,
/// a capture still being written), and `damaged` is a file whose own structure
/// contradicts itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The bytes are not a pcap or a pcapng.
    NotACapture,
    /// The container ends inside a header or a record.
    Truncated,
    /// The container's own lengths or references do not hold together.
    Damaged,
}

impl Refusal {
    /// The word this refusal is written as.
    pub const fn name(self) -> &'static str {
        match self {
            Refusal::NotACapture => "not_a_capture",
            Refusal::Truncated => "truncated",
            Refusal::Damaged => "damaged",
        }
    }

    /// Every refusal, from an exhaustive match.
    pub fn all() -> [Refusal; 3] {
        let one = |r: Refusal| match r {
            Refusal::NotACapture => Refusal::NotACapture,
            Refusal::Truncated => Refusal::Truncated,
            Refusal::Damaged => Refusal::Damaged,
        };
        [
            one(Refusal::NotACapture),
            one(Refusal::Truncated),
            one(Refusal::Damaged),
        ]
    }

    /// Every word, sorted.
    pub fn names() -> alloc::vec::Vec<&'static str> {
        let mut words: alloc::vec::Vec<&'static str> =
            Self::all().iter().map(|r| r.name()).collect();
        words.sort_unstable();
        words
    }

    /// The refusal a reader's error is.
    ///
    /// Exhaustive over both formats' errors, so an error added to either reader
    /// stops this compiling until somebody says which of the three it is.
    pub fn of(error: CaptureError) -> Self {
        use crate::pcap::PcapError;
        use crate::pcapng::PcapngError;
        match error {
            CaptureError::Pcap(e) => match e {
                PcapError::TruncatedFileHeader
                | PcapError::TruncatedRecordHeader { .. }
                | PcapError::TruncatedRecord { .. } => Refusal::Truncated,
                PcapError::BadMagic(_) | PcapError::LooksLikePcapNg => Refusal::NotACapture,
            },
            CaptureError::Pcapng(e) => match e {
                PcapngError::Truncated { .. } => Refusal::Truncated,
                PcapngError::NotPcapng { .. } | PcapngError::BadByteOrderMagic { .. } => {
                    Refusal::NotACapture
                }
                PcapngError::BadBlockLength { .. }
                | PcapngError::LengthMismatch { .. }
                | PcapngError::UnknownInterface { .. }
                | PcapngError::BadCapturedLength { .. }
                | PcapngError::SimplePacketWithoutInterface { .. } => Refusal::Damaged,
            },
        }
    }
}

/// An instant, through the integer door.
///
/// ONE call site for both instants of a row: a nanosecond clock since 1970 is
/// about 1.7e18, past what a reader on doubles holds exactly, so the cell is a
/// number while it is exact and a string of the same digits once it is not.
/// Counts stay bare numbers, as the header's integer paragraph says.
fn push_instant(ns: u64, out: &mut String) {
    wz_session_core::json::u64_into(ns, out);
}

/// One cell: its value, or `null` and a note of why, to be listed under
/// `unstated` when the row closes.
fn push_cell<T>(
    out: &mut String,
    unstated: &mut Vec<(Cell, Unstated)>,
    cell: Cell,
    stated: &Stated<T>,
    write: impl FnOnce(&T, &mut String),
) {
    let _ = write!(out, "\"{}\":", cell.key());
    match stated {
        Ok(value) => write(value, out),
        Err(reason) => {
            debug_assert!(
                cell.reasons().contains(reason),
                "{} cannot carry {}",
                cell.key(),
                reason.name()
            );
            unstated.push((cell, *reason));
            out.push_str("null");
        }
    }
}

fn push_zid(zid: &[u8], out: &mut String) {
    out.push('"');
    out.push_str(&wz_session_core::zid_hex::zid_to_zenoh_hex(zid));
    out.push('"');
}

fn push_row(row: &SessionRow, out: &mut String) {
    let mut unstated: Vec<(Cell, Unstated)> = Vec::new();
    out.push('{');
    push_cell(
        out,
        &mut unstated,
        Cell::Initiator,
        &row.initiator,
        |z, o| {
            push_zid(z, o);
        },
    );
    out.push(',');
    push_cell(out, &mut unstated, Cell::Acceptor, &row.acceptor, |z, o| {
        push_zid(z, o);
    });
    out.push(',');
    push_cell(out, &mut unstated, Cell::Link, &row.link, |k, o| {
        let _ = write!(o, "\"{}\"", k.name());
    });
    out.push(',');
    push_cell(out, &mut unstated, Cell::Phase, &row.phase, |p, o| {
        let _ = write!(o, "\"{}\"", crate::fields_json::phase_word(*p).name());
    });
    let _ = write!(out, ",\"encrypted\":\"{}\",", row.encryption.name());
    push_cell(
        out,
        &mut unstated,
        Cell::FirstSeen,
        &row.first_seen_ns,
        |ns, o| push_instant(*ns, o),
    );
    out.push(',');
    push_cell(
        out,
        &mut unstated,
        Cell::LastSeen,
        &row.last_seen_ns,
        |ns, o| push_instant(*ns, o),
    );
    out.push(',');
    push_cell(out, &mut unstated, Cell::Frames, &row.frames, |n, o| {
        let _ = write!(o, "{n}");
    });
    let _ = write!(out, ",\"bytes\":{},\"unstated\":[", row.bytes);
    for (i, (cell, reason)) in unstated.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"cell\":\"{}\",\"reason\":\"{}\"}}",
            cell.key(),
            reason.name()
        );
    }
    out.push_str("],\"flows\":[");
    for (i, link) in row.links.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"flow\":");
        crate::census_json::push_flow(&link.flow, out);
        let _ = write!(
            out,
            ",\"encrypted\":\"{}\",\"bytes\":{}}}",
            link.encryption.name(),
            link.bytes
        );
    }
    out.push_str("]}");
}

/// The session table of a dissection.
///
/// `dropped_by_limits` is the SAME group every other document carries, from the
/// same emitter: a flow the table's ceiling evicted has no row, so a table made
/// short by it must say so in the one place a consumer already looks.
pub fn session_table_json(d: &Dissection) -> String {
    let table = session_table(d);
    let mut out = String::from("{");
    crate::doc_revision::envelope_into(crate::doc_revision::SESSION_TABLE, &mut out);
    out.push_str(",\"ok\":true,\"sessions\":[");
    for (i, row) in table.rows.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_row(row, &mut out);
    }
    out.push_str("],\"excluded\":[");
    for (i, why) in Why::all().into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"why\":\"{}\",\"count\":{}}}",
            why.name(),
            table.excluded.count(why)
        );
    }
    out.push_str("],\"dropped_by_limits\":");
    out.push_str(&crate::report::dropped_by_limits_json(d));
    out.push('}');
    out
}

/// The document a container that did not read comes to.
///
/// Beside [`session_table_json`] and not folded into a function that takes bytes,
/// so that a door reading a container under a ceiling constructs its own
/// dissection where the bound is chosen, as every other bounded door does: the
/// parity gate that holds every bounded door to saying what its ceiling cost
/// finds a door by that constructor.
pub fn refusal_json(error: CaptureError) -> String {
    let mut out = String::from("{");
    crate::doc_revision::envelope_into(crate::doc_revision::SESSION_TABLE, &mut out);
    let _ = write!(
        out,
        ",\"ok\":false,\"refusal\":\"{}\",\"message\":",
        Refusal::of(error).name()
    );
    wz_session_core::json::escape_into(&alloc::format!("{error:?}"), &mut out);
    out.push('}');
    out
}

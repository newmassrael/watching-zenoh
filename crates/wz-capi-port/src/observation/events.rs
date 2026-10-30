// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The node's event log, written and read from C (`docs/observation-plane.md` M2).
//!
//! An event is a level, a source and up to `EVENT_RECORD_ARGS` integers. It carries no text: the
//! format it is read with is a constant the reader holds, keyed by the source, so a record costs a
//! few words and nothing is formatted on the node. The log is one ring for the process; what a
//! full one gives up is the build's `event-ring-full` policy.
//!
//! A reader keeps its own cursor, a sequence number, so any number of programs read the same log
//! and none of them takes an event from another. The cursor starts at 0: a log that has wrapped
//! tells the reader how many events it missed before it hands it the oldest one left. Under
//! `drop-newest` nothing is freed by reading; the program says how far it is done with
//! ([`release`]), and that is what makes room.

use wz_node_time::event_log::{global, library, process_clock, LogRead};
use wz_session_core::event_ring::Pushed;

use super::Refusal;

/// The level of every event the library writes (a program's own levels are its own).
pub const LEVEL_LIBRARY: u8 = library::LIBRARY_LEVEL;
/// The first source number the library uses; a program's sources are below it.
pub const SOURCE_LIBRARY: u16 = library::LIBRARY_SOURCE_BASE;
/// A supervised checkpoint missed its deadline. One integer: the checkpoint's number.
pub const SOURCE_SUPERVISION_EXPIRED: u16 = library::SUPERVISION_EXPIRED;

/// What a read found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Read {
    /// An event.
    Record {
        /// How serious it is, in the program's own scale.
        level: u8,
        /// How many integers the event carries; the ones written into the program's buffer are
        /// the smaller of this and the buffer's size.
        arg_count: u8,
        /// What said it, in the program's own numbering.
        source: u16,
        /// The event's number in the log.
        sequence: u64,
        /// When, as an NTP64 word, or `0` where the clock did not know the date.
        timestamp: u64,
    },
    /// Nothing newer than the cursor.
    Empty,
    /// Events were overwritten before they were read: how many.
    Lost {
        /// The number of events that are gone.
        missed: u64,
    },
}

/// Write an event: `args` is its integers, of which the log keeps as many as the build's
/// `EVENT_RECORD_ARGS`. The time is the clock's now: the clocks the program registered when
/// `clock-source` is on, the system clock otherwise. [`Refusal::Full`] when a full log under
/// `drop-newest` refused the event (it was counted).
pub fn emit(level: u8, source: u16, args: &[u64]) -> Result<(), Refusal> {
    match global().emit_from(&process_clock(), level, source, args) {
        Pushed::Stored(_) => Ok(()),
        Pushed::Dropped => Err(Refusal::Full),
    }
}

/// Read the event at `*cursor`, or say there is none. `*cursor` is the number the program reads
/// next, 0 at the start; it moves past the event read, or past the events that were lost. The
/// event's integers go to `args`, as many as fit.
pub fn read(cursor: &mut u64, args: &mut [u64]) -> Read {
    let mut reader = global().observer().reader_at(*cursor);
    let read = reader.poll();
    if let Some(next) = reader.cursor() {
        *cursor = next;
    }
    match read {
        LogRead::Record(record) => {
            let written = usize::from(record.arg_count).min(args.len());
            for (slot, value) in args.iter_mut().zip(record.args.iter()).take(written) {
                *slot = *value;
            }
            Read::Record {
                level: record.level,
                arg_count: record.arg_count,
                source: record.source,
                sequence: record.sequence,
                timestamp: record.timestamp,
            }
        }
        LogRead::Empty => Read::Empty,
        LogRead::Lost { missed } => Read::Lost { missed },
    }
}

/// Say that every event before sequence number `upto` has been read and may be overwritten. Only
/// forward; a number past the last event frees what there is. Under `overwrite-oldest` nothing
/// waits for it, and it changes nothing a reader sees.
pub fn release(upto: u64) {
    global().release_to(upto);
}

/// How many events a full log refused under `drop-newest`. `0` under `overwrite-oldest`.
pub fn dropped() -> u32 {
    global().dropped()
}

/// Write the event the library writes when a supervised checkpoint expires. A build without the
/// log has no such door, and the supervisor's caller writes nothing.
#[cfg(feature = "supervision")]
pub(crate) fn emit_supervision_expired(checkpoint: usize) {
    global().emit_from(
        &process_clock(),
        LEVEL_LIBRARY,
        SOURCE_SUPERVISION_EXPIRED,
        &[checkpoint as u64],
    );
}

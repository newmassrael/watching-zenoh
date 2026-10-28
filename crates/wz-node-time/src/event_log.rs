// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The node's event log: one [`EventRing`] that the code of the node writes events into, stamped
//! with the node clock (`docs/observation-plane.md` M2).
//!
//! The ring is written by one producer at a time. A node has many threads that may have something
//! to say, so the producers take a lock between them; nothing waits on a reader, and the lock is
//! held for the few stores of one record. A reader needs no lock: it reads the ring through an
//! [`Observer`], and several can read at once.
//!
//! The ring is sized by the `EVENT_RING_SLOTS` and `EVENT_RECORD_ARGS` limits, and what a full ring
//! gives up is the `event-ring-full` policy.
//!
//! An event is a source, a level and up to `EVENT_RECORD_ARGS` integers. It carries no text: the
//! format it is read with is a constant the reader holds, keyed by the source, so a record costs a
//! few words and nothing is formatted on the node.

use std::sync::{Mutex, OnceLock, PoisonError};

use wz_session_core::caps::{EVENT_RECORD_ARGS, EVENT_RING_SLOTS};
use wz_session_core::event_ring::{EventRing, FullPolicy, Observer, Pushed, Read};
use wz_session_core::policy::{EventRingFull, SessionPolicy};

use crate::node_clock::NodeHlc;

/// The ring type every event log has, sized by the build.
pub type Ring = EventRing<EVENT_RING_SLOTS, EVENT_RECORD_ARGS>;

/// One event as a reader gets it.
pub type Record = wz_session_core::event_ring::Record<EVENT_RECORD_ARGS>;

/// What a read of the log found.
pub type LogRead = Read<EVENT_RECORD_ARGS>;

/// The `event-ring-full` policy as the ring states it.
pub const fn full_policy(policy: EventRingFull) -> FullPolicy {
    match policy {
        EventRingFull::OverwriteOldest => FullPolicy::OverwriteOldest,
        EventRingFull::DropNewest => FullPolicy::DropNewest,
    }
}

/// An event log.
pub struct EventLog {
    ring: Ring,
    /// Orders the producers: at most one writes the ring at a time.
    producers: Mutex<()>,
    /// Orders the consumers, of which the ring may have one.
    consumers: Mutex<()>,
}

impl EventLog {
    /// An empty log whose ring gives up what `policy` says when it is full.
    pub const fn new(policy: FullPolicy) -> Self {
        Self {
            ring: Ring::new(policy),
            producers: Mutex::new(()),
            consumers: Mutex::new(()),
        }
    }

    /// Record an event at `timestamp` (an NTP64 word from the node clock, or `0` where the node
    /// has none). `args` beyond `EVENT_RECORD_ARGS` are ignored.
    pub fn emit_at(&self, level: u8, source: u16, timestamp: u64, args: &[u64]) -> Pushed {
        let _one_at_a_time = self
            .producers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // SAFETY: the lock is held for the whole life of the producer, so there is never another.
        let mut producer = unsafe { self.ring.producer() };
        producer.push(level, source, timestamp, args)
    }

    /// Record an event stamped by `clock`. A node with no clock, or one that does not know the
    /// date, records the event with time `0` and does not lose it.
    pub fn emit(&self, clock: &NodeHlc, level: u8, source: u16, args: &[u64]) -> Pushed {
        let timestamp = clock.stamp().map_or(0, |stamp| stamp.time);
        self.emit_at(level, source, timestamp, args)
    }

    /// A handle to read the log through and to count with.
    pub fn observer(&self) -> Observer<'_, EVENT_RING_SLOTS, EVENT_RECORD_ARGS> {
        self.ring.observer()
    }

    /// Read what is there for the one consumer, freeing it, until nothing is left, and hand each
    /// result to `each`. Under `drop-newest` this is what makes room.
    pub fn drain(&self, mut each: impl FnMut(LogRead)) {
        let _one_at_a_time = self
            .consumers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // SAFETY: the lock is held for the whole life of the consumer.
        let mut consumer = unsafe { self.ring.consumer() };
        loop {
            match consumer.poll() {
                Read::Empty => return,
                read => each(read),
            }
        }
    }

    /// How many events a full ring refused under `drop-newest`.
    pub fn dropped(&self) -> u32 {
        self.observer().dropped()
    }
}

/// The log of this process, built with the build's policy.
pub fn global() -> &'static EventLog {
    static GLOBAL: OnceLock<EventLog> = OnceLock::new();
    GLOBAL.get_or_init(|| EventLog::new(full_policy(SessionPolicy::default().event_ring_full)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_clock::TimestampingEnabled;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wz_session_core::WhatAmI;

    fn log(policy: FullPolicy) -> EventLog {
        EventLog::new(policy)
    }

    fn sequences(log: &EventLog) -> Vec<u64> {
        let mut out = Vec::new();
        let mut reader = log.observer().reader();
        loop {
            match reader.poll() {
                Read::Record(record) => out.push(record.sequence),
                Read::Lost { .. } => {}
                Read::Empty => return out,
            }
        }
    }

    #[test]
    fn the_policy_values_map_to_the_ring_policies() {
        assert_eq!(
            full_policy(EventRingFull::OverwriteOldest),
            FullPolicy::OverwriteOldest
        );
        assert_eq!(
            full_policy(EventRingFull::DropNewest),
            FullPolicy::DropNewest
        );
    }

    #[test]
    fn an_event_is_recorded_with_its_level_source_and_arguments() {
        let log = log(FullPolicy::OverwriteOldest);
        assert_eq!(log.emit_at(2, 0x1234, 99, &[7, 8]), Pushed::Stored(0));
        let mut reader = log.observer().reader();
        let Read::Record(record) = reader.poll() else {
            panic!("an event was recorded");
        };
        assert_eq!(
            (record.level, record.source, record.timestamp),
            (2, 0x1234, 99)
        );
        assert_eq!(&record.args[..2], &[7, 8]);
    }

    #[test]
    fn a_node_with_a_clock_stamps_the_event_and_one_without_records_time_zero() {
        let log = log(FullPolicy::OverwriteOldest);
        let router = NodeHlc::for_node(&[1], WhatAmI::Router, TimestampingEnabled::default());
        let none = NodeHlc::disabled();
        log.emit(&router, 0, 1, &[]);
        log.emit(&none, 0, 2, &[]);
        let mut reader = log.observer().reader();
        let (Read::Record(first), Read::Record(second)) = (reader.poll(), reader.poll()) else {
            panic!("two events were recorded");
        };
        #[cfg(feature = "time-hlc")]
        assert!(first.timestamp > 0, "a router has a clock");
        let _ = first;
        assert_eq!(second.timestamp, 0, "a node with no clock records no time");
    }

    #[test]
    fn under_overwrite_oldest_the_log_keeps_the_latest_and_loses_nothing_it_can_count() {
        let log = log(FullPolicy::OverwriteOldest);
        let total = EVENT_RING_SLOTS as u64 + 10;
        for _ in 0..total {
            log.emit_at(0, 0, 0, &[]);
        }
        let seen = sequences(&log);
        assert_eq!(seen.len(), EVENT_RING_SLOTS);
        assert_eq!(seen.last().copied(), Some(total - 1));
        assert_eq!(log.dropped(), 0, "overwriting refuses nothing");
    }

    #[test]
    fn under_drop_newest_the_log_keeps_the_beginning_counts_and_a_drain_makes_room() {
        let log = log(FullPolicy::DropNewest);
        let total = EVENT_RING_SLOTS as u64 + 5;
        for _ in 0..total {
            log.emit_at(0, 0, 0, &[]);
        }
        assert_eq!(log.dropped(), 5);
        assert_eq!(
            sequences(&log).first().copied(),
            Some(0),
            "the beginning is kept"
        );

        let mut drained = 0;
        log.drain(|read| {
            assert!(matches!(read, Read::Record(_)));
            drained += 1;
        });
        assert_eq!(drained, EVENT_RING_SLOTS);
        assert_eq!(
            log.emit_at(0, 0, 0, &[]),
            Pushed::Stored(EVENT_RING_SLOTS as u64),
            "a drained log has room"
        );
    }

    #[test]
    fn producers_on_several_threads_write_whole_consecutive_records() {
        let log = log(FullPolicy::OverwriteOldest);
        let wrote = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for thread in 0..4u64 {
                let (log, wrote) = (&log, &wrote);
                scope.spawn(move || {
                    for index in 0..2_000u64 {
                        // The arguments name the writer, so a record put together from two of
                        // them is seen as one whose arguments disagree.
                        let pushed = log.emit_at(0, thread as u16, thread, &[thread, index]);
                        assert!(matches!(pushed, Pushed::Stored(_)));
                        wrote.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
            scope.spawn(|| {
                let mut reader = log.observer().reader();
                let mut last = None::<u64>;
                while wrote.load(Ordering::Relaxed) < 8_000 {
                    match reader.poll() {
                        Read::Record(record) => {
                            assert_eq!(record.args[0], u64::from(record.source));
                            assert_eq!(record.args[0], record.timestamp);
                            if let Some(last) = last {
                                assert_eq!(record.sequence, last + 1);
                            }
                            last = Some(record.sequence);
                        }
                        Read::Lost { .. } => last = None,
                        Read::Empty => std::hint::spin_loop(),
                    }
                }
            });
        });
        assert_eq!(log.observer().stored(), 8_000);
    }

    #[test]
    fn the_process_log_is_one_log() {
        assert!(std::ptr::eq(global(), global()));
    }
}

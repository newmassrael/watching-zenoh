// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The clock sources an application registers (`docs/observation-plane.md` M1, `clock-source`).
//!
//! A node reads the time from the system clock. A device that has a better one, a disciplined
//! hardware clock or a time master on its bus, registers it here as an
//! [`EpochSource`], and the node's clock reads that instead.
//!
//! ## Which source answers
//!
//! The sources are read in the order they were registered, and the first that can say what time it
//! is answers. A registered source that cannot (a hardware clock not yet set, a bus master not yet
//! heard) hands the question to the next. When every registered source is unable, the node does
//! not know the date, and it does not fall back to the system clock: an application that
//! registered a clock did so because the system clock is not the one to trust, and stamping with it
//! in the clock's absence would put the very time it meant to replace on the data. With nothing
//! registered the node reads the system clock, as it always has.
//!
//! The registry is read on every stamp, so the empty case costs one atomic load and the others a
//! shared lock. A source may be registered or removed while nodes run: a node reads the registry
//! afresh each time, so the order of `register` and the node's construction does not matter.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{OnceLock, RwLock};

use wz_session_core::epoch::{EpochSource, EpochUnavailable, SinceEpoch};

use crate::standing_cell::StandingCell;
use crate::timestamp_source::SystemEpoch;

/// A registered source, by which it is removed again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceId(u32);

impl SourceId {
    /// The handle as a number, for a caller that cannot hold the type (a C program).
    pub const fn into_raw(self) -> u32 {
        self.0
    }

    /// The source a handle named. A number that was never handed out names no source, and
    /// removing it removes nothing.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }
}

/// The registry holds as many sources as it was built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryFull;

struct Entry {
    id: SourceId,
    source: Box<dyn EpochSource + Send + Sync>,
}

#[derive(Default)]
struct Table {
    next_id: u32,
    entries: Vec<Entry>,
}

/// The sources registered with a node, in registration order, up to a capacity.
pub struct ClockRegistry {
    capacity: usize,
    /// `entries.len()` as of the last change, so the empty registry is read without a lock.
    count: AtomicUsize,
    table: RwLock<Table>,
    /// How far the registered clocks are to be trusted, as the host reports it. The registered
    /// clocks are the process's, and so is what the host knows about them: every node that reads
    /// the registry shares this one standing.
    standing: OnceLock<StandingCell>,
}

impl ClockRegistry {
    /// A registry for `capacity` sources, empty. `0` accepts none.
    pub const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            count: AtomicUsize::new(0),
            table: RwLock::new(Table {
                next_id: 0,
                entries: Vec::new(),
            }),
            standing: OnceLock::new(),
        }
    }

    /// The standing of the clocks registered here, which the host reports through it.
    pub fn standing(&self) -> &StandingCell {
        self.standing.get_or_init(StandingCell::new)
    }

    /// Register `source` after the ones already here.
    pub fn register(
        &self,
        source: Box<dyn EpochSource + Send + Sync>,
    ) -> Result<SourceId, RegistryFull> {
        let mut table = self
            .table
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if table.entries.len() >= self.capacity {
            return Err(RegistryFull);
        }
        let id = SourceId(table.next_id);
        table.next_id = table.next_id.wrapping_add(1);
        table.entries.push(Entry { id, source });
        self.count.store(table.entries.len(), Ordering::Release);
        Ok(id)
    }

    /// Remove a source. Whether it was registered.
    pub fn unregister(&self, id: SourceId) -> bool {
        let mut table = self
            .table
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = table.entries.len();
        table.entries.retain(|entry| entry.id != id);
        self.count.store(table.entries.len(), Ordering::Release);
        table.entries.len() != before
    }

    /// How many sources are registered.
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Whether none is registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The first registered source that can say what time it is. `EpochUnavailable` when none can.
    fn read_registered(&self) -> Result<SinceEpoch, EpochUnavailable> {
        let table = self
            .table
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        table
            .entries
            .iter()
            .find_map(|entry| entry.source.try_since_epoch().ok())
            .ok_or(EpochUnavailable)
    }
}

/// The registry every node of the process reads, sized by the `CLOCK_SOURCES` limit.
pub static GLOBAL: ClockRegistry = ClockRegistry::new(wz_session_core::caps::CLOCK_SOURCES);

/// The time a node reads: the registered sources when there are any, the system clock when there
/// are none.
#[derive(Clone, Copy)]
pub struct RegisteredOrSystem(pub &'static ClockRegistry);

impl EpochSource for RegisteredOrSystem {
    fn try_since_epoch(&self) -> Result<SinceEpoch, EpochUnavailable> {
        if self.0.is_empty() {
            SystemEpoch.try_since_epoch()
        } else {
            self.0.read_registered()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    /// A source that says the time it was given, or that it cannot, as a flag says.
    #[derive(Clone)]
    struct Scripted {
        secs: u64,
        available: Arc<AtomicBool>,
    }

    impl Scripted {
        fn at(secs: u64) -> Self {
            Self {
                secs,
                available: Arc::new(AtomicBool::new(true)),
            }
        }
    }

    impl EpochSource for Scripted {
        fn try_since_epoch(&self) -> Result<SinceEpoch, EpochUnavailable> {
            if self.available.load(Ordering::Relaxed) {
                Ok(SinceEpoch {
                    secs: self.secs,
                    nanos: 0,
                })
            } else {
                Err(EpochUnavailable)
            }
        }
    }

    fn leaked(capacity: usize) -> &'static ClockRegistry {
        Box::leak(Box::new(ClockRegistry::new(capacity)))
    }

    #[test]
    fn with_nothing_registered_the_node_reads_the_system_clock() {
        let reading = RegisteredOrSystem(leaked(2))
            .try_since_epoch()
            .expect("the system clock answers");
        assert!(reading.secs > 1_700_000_000, "a post-2023 system time");
    }

    #[test]
    fn a_registered_source_replaces_the_system_clock() {
        let registry = leaked(2);
        registry.register(Box::new(Scripted::at(42))).expect("room");
        let reading = RegisteredOrSystem(registry)
            .try_since_epoch()
            .expect("the source answers");
        assert_eq!(reading.secs, 42);
    }

    #[test]
    fn the_first_source_that_can_answer_answers() {
        let registry = leaked(3);
        let first = Scripted::at(1);
        registry.register(Box::new(first.clone())).expect("room");
        registry.register(Box::new(Scripted::at(2))).expect("room");
        let node = RegisteredOrSystem(registry);

        assert_eq!(node.try_since_epoch().expect("first").secs, 1);
        first.available.store(false, Ordering::Relaxed);
        assert_eq!(
            node.try_since_epoch().expect("second").secs,
            2,
            "an unable source hands the question to the next"
        );
    }

    #[test]
    fn when_every_registered_source_is_unable_the_node_does_not_know_the_date() {
        let registry = leaked(2);
        let only = Scripted::at(1);
        only.available.store(false, Ordering::Relaxed);
        registry.register(Box::new(only)).expect("room");
        assert_eq!(
            RegisteredOrSystem(registry).try_since_epoch(),
            Err(EpochUnavailable),
            "the system clock is not the fallback of a clock the application chose"
        );
    }

    #[test]
    fn the_registry_holds_its_capacity_and_a_removal_makes_room() {
        let registry = leaked(1);
        let id = registry.register(Box::new(Scripted::at(1))).expect("room");
        assert_eq!(
            registry.register(Box::new(Scripted::at(2))).err(),
            Some(RegistryFull)
        );
        assert!(registry.unregister(id));
        assert!(!registry.unregister(id), "removed once");
        assert!(registry.is_empty());
        assert!(registry.register(Box::new(Scripted::at(3))).is_ok());
    }

    #[test]
    fn a_registry_of_no_capacity_accepts_nothing() {
        assert_eq!(
            leaked(0).register(Box::new(Scripted::at(1))).err(),
            Some(RegistryFull)
        );
    }

    #[test]
    fn removing_the_last_source_returns_to_the_system_clock() {
        let registry = leaked(1);
        let id = registry.register(Box::new(Scripted::at(7))).expect("room");
        let node = RegisteredOrSystem(registry);
        assert_eq!(node.try_since_epoch().expect("source").secs, 7);
        registry.unregister(id);
        assert!(node.try_since_epoch().expect("system").secs > 1_700_000_000);
    }
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a fixed pool says of itself, the same way for every pool (`pool-monitor`,
//! `docs/pool-monitor.md`).
//!
//! A fixed pool is a table or a stage of declared capacity: it holds at most `N` entries and
//! refuses the next one. Each already counts what it refused, and each counted it in a field of
//! its own, so a node could not list its pools, and nothing kept how full any of them had been.
//! A refusal count says a pool was too small; it does not say by how much, or whether a pool that
//! never refused came within one entry of it. The mark that says so is the high-water mark.
//!
//! * [`PoolStat`] is what a pool answers: its name, its capacity, the entries it holds, the most
//!   it has held, and the entries it refused.
//! * [`PoolGauge`] is how a pool answers. The pool does not know its name (a table is the same
//!   type in two places in a session), so its owner gives it.
//! * [`HighWater`] is the mark. It is the one thing a pool stores for this, and it stores
//!   nothing in a build without the `pool-monitor` feature: the type has no field there, so a
//!   table that holds one is the size it was.

/// What one pool says of itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStat {
    /// The name the pool's owner gave it.
    pub name: &'static str,
    /// The most entries the pool holds at once.
    pub capacity: u32,
    /// The entries it holds now.
    pub in_use: u32,
    /// The most entries it has held since it was made, or `None` in a build that keeps no mark
    /// (without `pool-monitor`): a mark that is not kept is not measured, and is not zero.
    pub high_water: Option<u32>,
    /// The entries it refused for want of room since it was made.
    pub refused: u64,
}

impl PoolStat {
    /// Whether the pool has ever been full: it holds `capacity` entries now, or held them.
    /// `None` when the build keeps no mark and the pool is not full now, because the answer is
    /// not known then.
    pub fn has_been_full(&self) -> Option<bool> {
        if self.in_use >= self.capacity {
            return Some(true);
        }
        self.high_water.map(|mark| mark >= self.capacity)
    }
}

/// A pool that can say its state. The name is the owner's: see the module.
pub trait PoolGauge {
    /// The pool's state, under `name`.
    fn pool_stat(&self, name: &'static str) -> PoolStat;
}

/// What owns pools and can list them: a node's host, which holds the tables its sessions live in.
///
/// The owner calls `visit` once per pool, in a fixed order, so a build with no heap lists its pools
/// as one with a heap does, and nothing is collected: the reader decides what to do with each.
pub trait PoolList {
    /// Call `visit` with the state of each pool this owns.
    fn visit_pools(&self, visit: &mut dyn FnMut(PoolStat));
}

/// The version of the document [`write_pool_document`] writes. A reader that does not know a
/// version reads none of it.
pub const POOL_DOCUMENT_VERSION: u32 = 1;

/// Write the document that says a node's pools, as JSON without whitespace:
///
/// ```text
/// {"version":1,"pools":[{"name":"sessions","capacity":4,"in_use":1,"high_water":3,"refused":0}]}
/// ```
///
/// `high_water` is `null` where the build keeps no mark, which is not zero. A name is written as the
/// owner gave it, and an owner gives a name of lower-case letters, digits and `-`: a name with
/// anything else is not a name this document can carry, and is refused with an error, as is a
/// writer that fails.
pub fn write_pool_document(
    pools: &dyn PoolList,
    out: &mut dyn core::fmt::Write,
) -> core::fmt::Result {
    write!(out, "{{\"version\":{POOL_DOCUMENT_VERSION},\"pools\":[")?;
    let mut first = true;
    let mut result = Ok(());
    pools.visit_pools(&mut |pool| {
        if result.is_err() {
            return;
        }
        result = write_pool(out, &pool, core::mem::take(&mut first));
    });
    result?;
    out.write_str("]}")
}

fn write_pool(out: &mut dyn core::fmt::Write, pool: &PoolStat, first: bool) -> core::fmt::Result {
    let plain = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    if pool.name.is_empty() || !pool.name.chars().all(plain) {
        return Err(core::fmt::Error);
    }
    if !first {
        out.write_char(',')?;
    }
    write!(
        out,
        "{{\"name\":\"{}\",\"capacity\":{},\"in_use\":{},\"high_water\":",
        pool.name, pool.capacity, pool.in_use
    )?;
    match pool.high_water {
        Some(mark) => write!(out, "{mark}")?,
        None => out.write_str("null")?,
    }
    write!(out, ",\"refused\":{}}}", pool.refused)
}

/// The most entries a pool has held. Zero-sized without the `pool-monitor` feature.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HighWater {
    #[cfg(feature = "pool-monitor")]
    mark: u32,
}

impl HighWater {
    /// A mark that has seen nothing.
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "pool-monitor")]
            mark: 0,
        }
    }

    /// Record that the pool holds `held` entries now.
    #[inline]
    pub fn note(&mut self, held: usize) {
        #[cfg(feature = "pool-monitor")]
        {
            let held = count(held);
            if held > self.mark {
                self.mark = held;
            }
        }
        #[cfg(not(feature = "pool-monitor"))]
        let _ = held;
    }

    /// The most entries the pool has held, or `None` where no mark is kept.
    pub const fn get(&self) -> Option<u32> {
        #[cfg(feature = "pool-monitor")]
        {
            Some(self.mark)
        }
        #[cfg(not(feature = "pool-monitor"))]
        {
            None
        }
    }
}

/// A count as the 32 bits a [`PoolStat`] holds, saturating: a pool larger than that is not a
/// pool this crate makes, and a count that wrapped would read as a pool nearly empty.
pub(crate) fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mark is kept exactly when the build keeps one, and says so when it does not.
    #[test]
    fn a_mark_is_kept_only_in_a_build_that_asks_for_it() {
        let mut mark = HighWater::new();
        mark.note(3);
        mark.note(1);
        if cfg!(feature = "pool-monitor") {
            assert_eq!(mark.get(), Some(3), "the most, not the latest");
        } else {
            assert_eq!(mark.get(), None, "not measured is not zero");
            assert_eq!(core::mem::size_of::<HighWater>(), 0, "and costs no byte");
        }
    }

    /// The mark never goes down, and a count past 32 bits saturates instead of wrapping to a small
    /// number.
    #[cfg(feature = "pool-monitor")]
    #[test]
    fn the_mark_only_rises_and_saturates() {
        let mut mark = HighWater::new();
        mark.note(7);
        mark.note(0);
        assert_eq!(mark.get(), Some(7));
        mark.note(usize::MAX);
        assert_eq!(mark.get(), Some(u32::MAX));
    }

    /// An owner that lists the pools it was given, in order.
    struct Owner(std::vec::Vec<PoolStat>);

    impl PoolList for Owner {
        fn visit_pools(&self, visit: &mut dyn FnMut(PoolStat)) {
            for pool in &self.0 {
                visit(*pool);
            }
        }
    }

    const fn stat(name: &'static str, high_water: Option<u32>) -> PoolStat {
        PoolStat {
            name,
            capacity: 4,
            in_use: 1,
            high_water,
            refused: 2,
        }
    }

    /// The document is exactly the one the module says, with a mark that is not kept written as
    /// `null` and not as zero, and an owner with no pool written as an empty list.
    #[test]
    fn the_document_says_each_pool_in_order_and_a_missing_mark_as_null() {
        let mut text = std::string::String::new();
        write_pool_document(
            &Owner(std::vec![
                stat("sessions", Some(3)),
                stat("pump-cells", None)
            ]),
            &mut text,
        )
        .unwrap();
        assert_eq!(
            text,
            "{\"version\":1,\"pools\":[\
             {\"name\":\"sessions\",\"capacity\":4,\"in_use\":1,\"high_water\":3,\"refused\":2},\
             {\"name\":\"pump-cells\",\"capacity\":4,\"in_use\":1,\"high_water\":null,\"refused\":2}]}"
        );

        let mut none = std::string::String::new();
        write_pool_document(&Owner(std::vec![]), &mut none).unwrap();
        assert_eq!(none, "{\"version\":1,\"pools\":[]}");
    }

    /// A name the document cannot carry is an error, not a quotation mark let through.
    #[test]
    fn a_name_the_document_cannot_carry_is_refused() {
        for name in ["", "Sessions", "a\"b", "a b"] {
            let mut text = std::string::String::new();
            let owner = Owner(std::vec![stat(name, None)]);
            assert!(
                write_pool_document(&owner, &mut text).is_err(),
                "{name:?} was written"
            );
        }
    }

    #[test]
    fn a_pool_full_now_has_been_full_whatever_the_build_keeps() {
        let full = PoolStat {
            name: "p",
            capacity: 4,
            in_use: 4,
            high_water: None,
            refused: 0,
        };
        assert_eq!(full.has_been_full(), Some(true));
        let not_full = PoolStat { in_use: 1, ..full };
        assert_eq!(
            not_full.has_been_full(),
            None,
            "without a mark the past is not known"
        );
        let marked = PoolStat {
            high_water: Some(4),
            ..not_full
        };
        assert_eq!(marked.has_been_full(), Some(true));
        let never = PoolStat {
            high_water: Some(3),
            ..not_full
        };
        assert_eq!(never.has_been_full(), Some(false));
    }
}

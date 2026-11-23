// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The most memory a session's tables can hold, computed from the limits the session runs under.
//!
//! # What a row is
//!
//! Each table the session holds to a limit of [`SessionLimits`] is two [`MemoryRow`]s: the
//! table's own storage, and what each entry keeps beside that storage on the heap. A row states
//! the limit that sizes it (its `basis`), how many items it counts, the bytes of one, and their
//! product. The bytes of a stored entry are `core::mem::size_of` of the table's own row type, read
//! from the module that keeps the table (`ROW_BYTES` of each registry), so they follow the type as
//! it changes and as each target lays it out. [`session_tables`] gives the rows of the tables
//! this crate keeps; a C ABI adds the rows of what it and its engine hold
//! ([`SessionMemory::push`]).
//!
//! # The bounds used where a size is not known before the session runs
//!
//! - **How many entries.** On a fixed table (the static storage policy) the storage is laid out for
//!   the table's capacity whatever its quota, so the count is the capacity. On a growable one it is
//!   the quota the session's limits state; a quota that states no bound leaves the rows without a
//!   count, and the whole report without a total.
//! - **How much storage a growable table takes for them.** A growable table is a vector that doubles
//!   its storage as it fills, so it may hold storage for up to twice its entries, and never less
//!   than [`GROWN_LEAST_ROWS`] once it holds one. The storage row counts that.
//! - **How long a key is.** A fixed table keeps a key's text in the row, at most
//!   `MAX_KEYEXPR_BYTES` bytes, which the row's size already counts. A growable one keeps it in a
//!   string beside the row; the bound used is the `MAX_KEYEXPR_BYTES` of the session's limits,
//!   which every table that stores keys refuses past, as a string that doubles as it is written
//!   may reach (twice it, and at least [`GROWN_LEAST_TEXT`]).
//! - **What a callback captures.** A table keeps each entry's callback in a box. The box's own
//!   layers are this crate's and are counted; what the closure inside captures is its maker's, and
//!   is counted as the caller states it ([`Captures`]).
//!
//! # What the report says of itself
//!
//! [`SessionMemory::total`] is the sum of every row, and is `None` when a row has no count: the
//! build holds that table to no bound, and the session's worst case is not a number.
//! [`SessionMemory::is_enforced`] says whether the build also refuses past every count and every
//! entry size the rows use, so that the total is a bound the session cannot pass and not only an
//! estimate of one.

use core::ffi::CStr;
use core::fmt;

use crate::bounded::{Profile, ENFORCES_CAPACITY};
use crate::limit_binding::{LimitSpec, Quota};
use crate::limits::{MaxPendingQueries, MaxSubscriptions, SessionLimits};
use crate::pubsub::SubscriberTable;
use crate::reply::ReplyRegistry;
use crate::reply_sink::{BoxedReplySink, ConsolidatingSink};
use crate::sink::BoxedSink;

/// The most rows a [`SessionMemory`] holds: the rows of [`session_tables`] and room for the rows a
/// C ABI adds.
pub const MEMORY_ROWS: usize = 24;

/// The most rows [`session_tables`] gives, in the build with every table: two for each of the six
/// tables it counts.
pub const SESSION_TABLE_ROWS: usize = 12;

const _: () = assert!(SESSION_TABLE_ROWS <= MEMORY_ROWS);

/// The least rows of storage a growable table takes once it holds an entry: the smallest storage
/// the standard library's vector takes for entries of up to a kilobyte, and more than it takes for
/// larger ones.
pub const GROWN_LEAST_ROWS: usize = 4;

/// The least bytes a growable string takes once it holds a byte, as the standard library's string
/// grows.
pub const GROWN_LEAST_TEXT: usize = 8;

/// One part of what a session holds: `count` items of `entry_bytes` each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRow {
    /// What holds the bytes, NUL-terminated so a C door hands it over as it is.
    pub part: &'static CStr,
    /// The limit, or the build's value, whose number sizes the row; empty for a part every session
    /// has once.
    pub basis: &'static CStr,
    /// How many items the row counts; `None` when the build holds them, or the bytes of one, to
    /// no bound.
    pub count: Option<usize>,
    /// The bytes of one item.
    pub entry_bytes: usize,
    /// Whether the build refuses past `count` and past `entry_bytes`, so that the row is a bound
    /// the session cannot pass.
    pub enforced: bool,
}

impl MemoryRow {
    /// The row's bytes: its count times the bytes of one item, `None` without a count or past the
    /// address space.
    pub const fn total(&self) -> Option<usize> {
        match self.count {
            Some(count) => count.checked_mul(self.entry_bytes),
            None => None,
        }
    }
}

/// A row of a report that has none yet.
const NO_ROW: MemoryRow = MemoryRow {
    part: c"",
    basis: c"",
    count: Some(0),
    entry_bytes: 0,
    enforced: true,
};

/// A report has no room for one more row: it holds [`MEMORY_ROWS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRowsFull;

impl fmt::Display for MemoryRowsFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a memory report holds at most {MEMORY_ROWS} rows")
    }
}

impl core::error::Error for MemoryRowsFull {}

/// The most memory a session holds, part by part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionMemory {
    rows: [MemoryRow; MEMORY_ROWS],
    len: usize,
}

impl Default for SessionMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionMemory {
    /// A report of no part.
    pub const fn new() -> Self {
        Self {
            rows: [NO_ROW; MEMORY_ROWS],
            len: 0,
        }
    }

    /// Add `row`; refused, with the report unchanged, when it holds [`MEMORY_ROWS`] already.
    pub fn push(&mut self, row: MemoryRow) -> Result<(), MemoryRowsFull> {
        let slot = self.rows.get_mut(self.len).ok_or(MemoryRowsFull)?;
        *slot = row;
        self.len = self.len.saturating_add(1);
        Ok(())
    }

    /// Add a row of [`session_tables`], which gives fewer than [`MEMORY_ROWS`] (asserted above).
    fn put(&mut self, row: MemoryRow) {
        // The assertion above leaves room for every table's rows.
        let _ = self.push(row);
    }

    /// Add the two rows of `table`.
    fn put_table(&mut self, table: Table) {
        let [first_part, beside_part] = table.parts;
        self.put(MemoryRow {
            part: first_part,
            basis: table.basis,
            count: table.entries.map(storage_rows),
            entry_bytes: table.row_bytes,
            enforced: table.entries.is_some(),
        });
        self.put(MemoryRow {
            part: beside_part,
            basis: table.basis,
            count: table.beside.and(table.entries),
            entry_bytes: table.beside.unwrap_or(0),
            enforced: table.entries.is_some() && table.beside.is_some(),
        });
    }

    /// The rows, in the order they were added.
    pub fn rows(&self) -> &[MemoryRow] {
        self.rows.get(..self.len).unwrap_or_default()
    }

    /// The sum of every row: the most the session holds. `None` when a row has no count, or the
    /// sum is past the address space.
    pub fn total(&self) -> Option<usize> {
        self.rows()
            .iter()
            .try_fold(0usize, |sum, row| sum.checked_add(row.total()?))
    }

    /// The sum of the rows that have a count, saturating: what the session holds in the parts the
    /// build bounds, whether or not every part is bounded.
    pub fn bounded_bytes(&self) -> usize {
        self.rows()
            .iter()
            .filter_map(MemoryRow::total)
            .fold(0, usize::saturating_add)
    }

    /// Whether [`Self::total`] is a bound the session cannot pass: every row has a count and the
    /// build refuses past every row's count and entry size.
    pub fn is_enforced(&self) -> bool {
        self.total().is_some() && self.rows().iter().all(|row| row.enforced)
    }
}

/// The bytes the closures a session's caller registers capture, by the kind of callback: what each
/// box the tables keep holds beside the box's own layers. Zero for a closure that captures nothing,
/// which takes no byte of its own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Captures {
    /// A subscriber's sample callback.
    pub sample: usize,
    /// A queryable's query callback.
    pub query: usize,
    /// The reply and the final callbacks of a pending query or a pending liveliness get, together.
    pub reply: usize,
    /// A liveliness subscriber's callback.
    pub liveliness_sample: usize,
}

/// How many entries a table held to the limit `L` holds at most, by `quota`, the value the
/// session's limits state: on a fixed table the capacity its storage is laid out for, on a growable
/// one the quota, `None` where the quota states no bound.
fn entries<L: LimitSpec<Value = Quota>>(quota: Quota) -> Option<usize> {
    match L::CAPACITY {
        Some(capacity) if ENFORCES_CAPACITY => Some(capacity),
        _ => quota.most(),
    }
}

/// The rows of storage a table of `entries` entries takes: as many on a fixed table, and on a
/// growable one what a vector that doubles as it fills may reach.
pub const fn storage_rows(entries: usize) -> usize {
    if ENFORCES_CAPACITY || entries == 0 {
        entries
    } else if entries.saturating_mul(2) < GROWN_LEAST_ROWS {
        GROWN_LEAST_ROWS
    } else {
        entries.saturating_mul(2)
    }
}

/// The bytes a growable string of up to `bytes` bytes may take, written in pieces: under twice
/// them, and at least [`GROWN_LEAST_TEXT`].
pub const fn grown_text(bytes: usize) -> usize {
    if bytes == 0 {
        0
    } else if bytes.saturating_mul(2) < GROWN_LEAST_TEXT {
        GROWN_LEAST_TEXT
    } else {
        bytes.saturating_mul(2)
    }
}

/// The bytes a key's text takes beside a table's row, `None` where `limits` hold keys to no
/// length. A fixed table keeps the text in its row, so nothing is beside it; a growable one keeps
/// it in a string, and every table that stores keys refuses one longer than the
/// `MAX_KEYEXPR_BYTES` of the snapshot its creator hands it, which is `limits`.
fn key_text(limits: &SessionLimits) -> Option<usize> {
    if ENFORCES_CAPACITY {
        Some(0)
    } else {
        limits.max_keyexpr_bytes().most().map(grown_text)
    }
}

/// What one table puts in a report: its storage and what its entries keep beside it.
struct Table {
    /// The storage's part and the part beside it.
    parts: [&'static CStr; 2],
    basis: &'static CStr,
    entries: Option<usize>,
    row_bytes: usize,
    /// The heap bytes beside each entry's row, which the build refuses past; `None` where they
    /// have no bound.
    beside: Option<usize>,
}

/// The rows of the tables a session keeps to its limits, `limits` being the snapshot it runs
/// under and `captures` what the closures its caller registers capture.
///
/// The tables are the session's subscribers, its pending queries, and in a build with their
/// planes its queryables, its own liveliness tokens, its liveliness subscribers and its pending
/// liveliness gets: each a table its creator holds to a limit of `limits`.
pub fn session_tables(limits: &SessionLimits, captures: &Captures) -> SessionMemory {
    let mut memory = SessionMemory::new();
    let key = key_text(limits);
    memory.put_table(Table {
        parts: [c"subscribers", c"subscriber keys and callbacks"],
        basis: c"MAX_SUBSCRIPTIONS",
        entries: entries::<MaxSubscriptions>(limits.max_subscriptions()),
        row_bytes: <SubscriberTable<BoxedSink, Profile>>::ROW_BYTES,
        beside: key.map(|key| {
            key.saturating_add(BoxedSink::WRAPPER_BYTES)
                .saturating_add(captures.sample)
        }),
    });
    #[cfg(feature = "query-queryable")]
    memory.put_table(Table {
        parts: [c"queryables", c"queryable keys and callbacks"],
        basis: c"MAX_QUERYABLES",
        entries: entries::<crate::limits::MaxQueryables>(limits.max_queryables()),
        row_bytes: <crate::query::QueryableRegistry<crate::query_sink::BoxedQuerySink, Profile>>::ROW_BYTES,
        beside: key.map(|key| key.saturating_add(captures.query)),
    });
    memory.put_table(Table {
        parts: [c"pending queries", c"pending query keys and callbacks"],
        basis: c"MAX_PENDING_QUERIES",
        entries: entries::<MaxPendingQueries>(limits.max_pending_queries()),
        row_bytes: <ReplyRegistry<ConsolidatingSink<BoxedReplySink>, Profile>>::ROW_BYTES,
        beside: key.map(|key| key.saturating_add(captures.reply)),
    });
    #[cfg(feature = "liveliness-token")]
    memory.put_table(Table {
        parts: [c"liveliness tokens", c"liveliness token keys"],
        basis: c"MAX_LOCAL_TOKENS",
        entries: entries::<crate::limits::MaxLocalTokens>(limits.max_local_tokens()),
        row_bytes: <crate::declare::local_token::LocalTokenRegistry<Profile>>::ROW_BYTES,
        beside: key,
    });
    #[cfg(feature = "liveliness-subscriber")]
    memory.put_table(Table {
        parts: [
            c"liveliness subscribers",
            c"liveliness subscriber keys and callbacks",
        ],
        basis: c"MAX_LIVELINESS_SUBSCRIPTIONS",
        entries: entries::<crate::limits::MaxLivelinessSubscriptions>(
            limits.max_liveliness_subscriptions(),
        ),
        row_bytes: <crate::declare::liveliness_subscriber::LivelinessSubscriberTable<
            crate::declare::liveliness_sample::BoxedLivelinessSampleSink,
            Profile,
        >>::ROW_BYTES,
        beside: key.map(|key| key.saturating_add(captures.liveliness_sample)),
    });
    #[cfg(feature = "liveliness-get")]
    memory.put_table(
        Table {
            parts: [
                c"pending liveliness gets",
                c"pending liveliness get callbacks",
            ],
            basis: c"MAX_PENDING_LIVELINESS_GETS",
            entries: entries::<crate::limits::MaxPendingLivelinessGets>(
                limits.max_pending_liveliness_gets(),
            ),
            row_bytes: <crate::declare::liveliness_get::LivelinessGetRegistry<
                BoxedReplySink,
                Profile,
            >>::ROW_BYTES,
            beside: Some(captures.reply),
        },
    );
    memory
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps;

    /// Every table this build has held to a quota of `n`.
    fn stated(n: usize) -> SessionLimits {
        let mut limits = SessionLimits::defaults();
        limits
            .select_max_subscriptions(Quota::at_most(n))
            .expect("a host build's domain holds a small quota");
        limits
            .select_max_pending_queries(Quota::at_most(n))
            .expect("a host build's domain holds a small quota");
        #[cfg(feature = "query-queryable")]
        limits
            .select_max_queryables(Quota::at_most(n))
            .expect("a host build's domain holds a small quota");
        #[cfg(feature = "liveliness-token")]
        limits
            .select_max_local_tokens(Quota::at_most(n))
            .expect("a host build's domain holds a small quota");
        #[cfg(feature = "liveliness-subscriber")]
        limits
            .select_max_liveliness_subscriptions(Quota::at_most(n))
            .expect("a host build's domain holds a small quota");
        #[cfg(feature = "liveliness-get")]
        limits
            .select_max_pending_liveliness_gets(Quota::at_most(n))
            .expect("a host build's domain holds a small quota");
        limits
    }

    fn row<'a>(memory: &'a SessionMemory, part: &CStr) -> &'a MemoryRow {
        memory
            .rows()
            .iter()
            .find(|row| row.part == part)
            .expect("the report has the part")
    }

    /// The total is the sum of the rows, each row its count times its entry, and the bounded bytes
    /// are the same sum when every row is bounded.
    #[test]
    fn the_total_is_the_sum_of_the_rows() {
        let memory = session_tables(&stated(3), &Captures::default());
        let mut sum = 0usize;
        for row in memory.rows() {
            let count = row.count.expect("every table is held to a stated quota");
            assert_eq!(row.total(), Some(count * row.entry_bytes), "{:?}", row.part);
            sum += count * row.entry_bytes;
        }
        assert_eq!(memory.total(), Some(sum));
        assert_eq!(memory.bounded_bytes(), sum);
        assert!(sum > 0, "the tables take memory");
    }

    /// A quota stated one higher moves the total on a growable table by the storage of the rows a
    /// doubling vector reaches and one more entry's key and callback; a fixed table's storage is
    /// laid out for its capacity, so the total does not move there.
    #[test]
    fn a_stated_quota_moves_the_total_on_a_growable_table_only() {
        let captures = Captures::default();
        let two = stated(2);
        let mut three = two;
        three
            .select_max_subscriptions(Quota::at_most(3))
            .expect("a host build's domain holds a small quota");
        let at_two = session_tables(&two, &captures).total().expect("bounded");
        let at_three = session_tables(&three, &captures).total().expect("bounded");
        if ENFORCES_CAPACITY {
            assert_eq!(at_two, at_three);
        } else {
            let storage = (storage_rows(3) - storage_rows(2))
                * <SubscriberTable<BoxedSink, Profile>>::ROW_BYTES;
            let keys = two
                .max_keyexpr_bytes()
                .most()
                .expect("a key's length is bounded");
            let beside = grown_text(keys) + BoxedSink::WRAPPER_BYTES;
            assert_eq!(at_three - at_two, storage + beside);
        }
    }

    /// A growable table whose quota states no bound has rows with no count, and the report no
    /// total; the other rows still sum to the bounded bytes. A fixed table refuses that quota.
    #[test]
    fn a_quota_of_no_bound_leaves_the_report_without_a_total() {
        let mut limits = stated(3);
        let unbounded = limits.select_max_subscriptions(Quota::UNBOUNDED);
        if ENFORCES_CAPACITY {
            assert!(unbounded.is_err(), "a fixed table has a capacity");
            assert!(session_tables(&limits, &Captures::default())
                .total()
                .is_some());
            return;
        }
        unbounded.expect("a growable table admits no bound");
        let memory = session_tables(&limits, &Captures::default());
        assert_eq!(row(&memory, c"subscribers").count, None);
        assert_eq!(row(&memory, c"subscriber keys and callbacks").count, None);
        assert!(!row(&memory, c"subscribers").enforced);
        assert_eq!(memory.total(), None);
        assert!(!memory.is_enforced());
        let others: usize = memory
            .rows()
            .iter()
            .filter(|row| row.basis != c"MAX_SUBSCRIPTIONS")
            .map(|row| row.total().expect("held to a stated quota"))
            .sum();
        assert_eq!(memory.bounded_bytes(), others);
    }

    /// The bytes of a stored subscription are its row type's, which holds the sink inline and, on
    /// a fixed table, the key's text; a growable table keeps the text beside the row, at the
    /// length the session's limits hold keys to. Every table refuses past its quota and a longer
    /// key, so the report is enforced on either.
    #[test]
    fn a_stored_entry_is_sized_by_its_row_type() {
        let limits = stated(3);
        let memory = session_tables(&limits, &Captures::default());
        let stored = row(&memory, c"subscribers").entry_bytes;
        assert_eq!(stored, <SubscriberTable<BoxedSink, Profile>>::ROW_BYTES);
        assert!(stored >= core::mem::size_of::<BoxedSink>());
        let beside = row(&memory, c"subscriber keys and callbacks").entry_bytes;
        if ENFORCES_CAPACITY {
            assert!(
                stored >= caps::MAX_KEYEXPR_BYTES,
                "the key's text is in the row"
            );
            assert_eq!(beside, BoxedSink::WRAPPER_BYTES);
        } else {
            let keys = limits
                .max_keyexpr_bytes()
                .most()
                .expect("a key's length is bounded");
            assert_eq!(beside, grown_text(keys) + BoxedSink::WRAPPER_BYTES);
        }
        assert!(memory.is_enforced());
    }

    /// A key length stated lower moves what each entry of a growable table keeps beside its row
    /// to the text of that length, and the total with it. A fixed table keeps the text in its row,
    /// so its report does not move; a build that holds the length to its own value refuses the
    /// statement.
    #[test]
    fn a_stated_key_length_moves_the_text_beside_a_growable_table() {
        let mut limits = stated(3);
        let at_build = session_tables(&limits, &Captures::default());
        let lowered = 40;
        if let Err(refused) = limits.select_max_keyexpr_bytes(Quota::at_most(lowered)) {
            assert!(refused.domain.is_singleton(), "{refused:?}");
            return;
        }
        let memory = session_tables(&limits, &Captures::default());
        if ENFORCES_CAPACITY {
            assert_eq!(memory, at_build);
            return;
        }
        assert_eq!(
            row(&memory, c"subscriber keys and callbacks").entry_bytes,
            grown_text(lowered) + BoxedSink::WRAPPER_BYTES
        );
        assert_eq!(
            row(&memory, c"subscribers").entry_bytes,
            row(&at_build, c"subscribers").entry_bytes
        );
        assert!(
            memory.total().expect("bounded") < at_build.total().expect("bounded"),
            "a shorter key takes less beside each entry"
        );
    }

    /// A table whose entries keep bytes of no bound beside their rows gives a second row with no
    /// count, not enforced, so the report has no total; its storage row keeps its count, and the
    /// bounded bytes are the storage's.
    #[test]
    fn a_table_with_no_bound_beside_its_rows_leaves_the_report_without_a_total() {
        let mut memory = SessionMemory::new();
        memory.put_table(Table {
            parts: [c"rows", c"beside the rows"],
            basis: c"MAX_SUBSCRIPTIONS",
            entries: Some(3),
            row_bytes: 16,
            beside: None,
        });
        let [storage, beside] = memory.rows() else {
            panic!("two rows a table");
        };
        assert_eq!(
            (storage.count, storage.enforced),
            (Some(storage_rows(3)), true)
        );
        assert_eq!(
            (beside.count, beside.entry_bytes, beside.enforced),
            (None, 0, false)
        );
        assert_eq!(memory.total(), None);
        assert!(!memory.is_enforced());
        assert_eq!(memory.bounded_bytes(), storage_rows(3) * 16);
    }

    /// What the caller's closures capture is counted beside each entry, and nowhere else.
    #[test]
    fn captures_move_only_the_rows_beside_the_storage() {
        let limits = stated(3);
        let none = session_tables(&limits, &Captures::default());
        let some = session_tables(
            &limits,
            &Captures {
                sample: 40,
                reply: 24,
                ..Captures::default()
            },
        );
        let delta = |part: &CStr| row(&some, part).entry_bytes - row(&none, part).entry_bytes;
        assert_eq!(delta(c"subscriber keys and callbacks"), 40);
        assert_eq!(delta(c"pending query keys and callbacks"), 24);
        assert_eq!(delta(c"subscribers"), 0);
        assert_eq!(delta(c"pending queries"), 0);
        // Each changed row moves the total by its own count of entries: the quota on a growable
        // table, the capacity its storage is laid out for on a fixed one, which is not the quota.
        let entries = |part: &CStr| row(&none, part).count.expect("bounded");
        // A pending liveliness get holds a reply sink too, in a build with the plane.
        let gets = if cfg!(feature = "liveliness-get") {
            entries(c"pending liveliness get callbacks") * 24
        } else {
            0
        };
        assert_eq!(
            some.total().expect("bounded") - none.total().expect("bounded"),
            entries(c"subscriber keys and callbacks") * 40
                + entries(c"pending query keys and callbacks") * 24
                + gets
        );
    }

    /// The tables give at most the rows the ABIs leave room beside, and a report refuses the row
    /// past its room, unchanged.
    #[test]
    fn the_rows_fit_and_the_one_past_the_room_is_refused() {
        let mut memory = session_tables(&stated(3), &Captures::default());
        assert!(memory.rows().len() <= SESSION_TABLE_ROWS);
        assert_eq!(memory.rows().len() % 2, 0, "two rows a table");
        while memory.rows().len() < MEMORY_ROWS {
            memory.push(NO_ROW).expect("room is left");
        }
        let full = memory;
        assert_eq!(memory.push(NO_ROW), Err(MemoryRowsFull));
        assert_eq!(memory, full);
    }

    /// A growable table's storage: none for no entry, at least four rows for one, and twice the
    /// entries past that; a fixed table's is its entries. A key's text: at least eight bytes,
    /// twice its length past that.
    #[test]
    fn a_growable_table_counts_what_a_doubling_vector_reaches() {
        for entries in [0usize, 1, 2, 3, 16] {
            let expected = if ENFORCES_CAPACITY {
                entries
            } else {
                match entries {
                    0 => 0,
                    1 | 2 => 4,
                    n => 2 * n,
                }
            };
            assert_eq!(storage_rows(entries), expected, "{entries} entries");
        }
        assert_eq!(grown_text(0), 0);
        assert_eq!(grown_text(3), GROWN_LEAST_TEXT);
        assert_eq!(grown_text(256), 512);
    }
}

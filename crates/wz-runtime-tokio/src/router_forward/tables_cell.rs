// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The cell a router's tables are shared through, in the form the `routing-table-sharing` policy
//! chooses (`docs/router-table-snapshots.md`, section 4).
//!
//! `rwlock`, upstream's: one reader-writer lock round the tables. A reader holds its guard for one
//! message; a writer waits for every reader under way, and the readers that come after it wait
//! for the writer.
//!
//! `snapshot`: the tables are published versions. A reader loads the version published last and
//! holds it by its count for as long as it reads, with no lock. A writer takes the writers' lock,
//! copies the published version into a draft (a path copy: every part the write does not reach
//! stays shared with the version before), writes the draft and publishes it with one store
//! ([`TablesWrite::publish`]). A version is freed when the last reader that loaded it lets it go.
//! A writer that must know a version is gone from every reader (a face that left must be sent
//! nothing more) waits for it with [`TablesCell::synchronize`], read-copy-update's grace period.
//!
//! The router's code is one for both forms: it reads through [`TablesCell::read`] and
//! [`TablesCell::read_behind_a_writer_waiting`], and writes through [`TablesCell::write`], each of
//! which answers a value that derefs to [`Tables`].

use super::Tables;
use crate::sync::{PlainGuard, PlainMutex, PlainReadGuard, PlainRwLock, PlainWriteGuard};
use arc_swap::ArcSwap;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::sync::{Arc, Weak};
use std::time::Duration;
use wz_session_core::policy::RoutingTableSharing;

/// The first pause of a grace period that did not end when the waiter yielded once. A reader
/// holds a version for one message, which is microseconds, so a yield usually finds it gone.
const FIRST_PAUSE: Duration = Duration::from_micros(10);

/// The longest pause of a grace period: the pauses double up to it, so that a reader held up for
/// longer (a send that waits for room) costs the waiter no core and delays it by at most this.
const LONGEST_PAUSE: Duration = Duration::from_millis(1);

/// The router's tables, shared between the faces' threads that route by them and the writers
/// that change them, as the `routing-table-sharing` policy says.
pub(crate) struct TablesCell {
    form: Form,
}

/// The lock holds the tables in place, which makes `Locked` the larger variant by the size of the
/// tables. A router has one cell, so the bytes the smaller variant leaves unused are counted once,
/// while boxing the tables would add a pointer to follow on every read under `rwlock`, the
/// upstream form every preset builds.
#[allow(clippy::large_enum_variant)]
enum Form {
    /// `rwlock`: the tables behind one reader-writer lock, written in place.
    Locked(PlainRwLock<Tables>),
    /// `snapshot`: the tables as published versions.
    Snapshot(Snapshot),
}

/// The `snapshot` form.
struct Snapshot {
    /// The version the readers load: the last a writer published.
    published: ArcSwap<Tables>,
    /// Held by the one writer that drafts the next version, from its copy of the published one to
    /// its publishing, so that no two writers draft from the same version and one's write is lost.
    writer: PlainMutex<()>,
    /// The versions replaced by a publish that some reader may still hold, which a grace period
    /// waits for. Pruned of the versions no reader holds at each publish and each grace period.
    retired: PlainMutex<Vec<Weak<Tables>>>,
}

thread_local! {
    /// The version each `snapshot` cell is read by on this thread, while a read of it is held.
    static PINS: RefCell<Vec<Pin>> = const { RefCell::new(Vec::new()) };
}

/// The version a thread reads a cell by, and how many reads of the cell it holds.
///
/// Under `rwlock` a thread's nested reads see one state, since no writer can enter while the
/// thread holds a read; a method that reads calls another that reads and relies on it. Under
/// `snapshot` a writer can publish between the two reads, so the outermost read loads the version
/// and pins it here, a nested read routes by the pinned one, and the pin goes with the last read.
struct Pin {
    /// The cell, by its address: the pin lives no longer than a read that borrows the cell, so the
    /// address names one cell for as long as it is here.
    cell: usize,
    depth: usize,
    version: Arc<Tables>,
}

impl TablesCell {
    /// The cell over `tables`, in the form `sharing` names.
    pub(crate) fn new(tables: Tables, sharing: RoutingTableSharing) -> Self {
        let form = match sharing {
            RoutingTableSharing::Rwlock => Form::Locked(PlainRwLock::new(tables)),
            RoutingTableSharing::Snapshot => Form::Snapshot(Snapshot {
                published: ArcSwap::from_pointee(tables),
                writer: PlainMutex::new(()),
                retired: PlainMutex::new(Vec::new()),
            }),
        };
        Self { form }
    }

    /// The value of the policy this cell was made with.
    pub(crate) fn sharing(&self) -> RoutingTableSharing {
        match self.form {
            Form::Locked(_) => RoutingTableSharing::Rwlock,
            Form::Snapshot(_) => RoutingTableSharing::Snapshot,
        }
    }

    /// The tables for reading, until the result is dropped.
    ///
    /// Under `rwlock` the recursive read of [`PlainRwLock::read`]: a thread that holds a read may
    /// take another. Under `snapshot` the version this thread already reads the cell by, or, for
    /// its outermost read, the version published last. Loading it costs one increment of the
    /// version's count, and the pin of the outermost read one more; reading through the load's
    /// guard without a count is a measurement of phase 6 of the design, not a guess made here.
    pub(crate) fn read(&self) -> TablesRead<'_> {
        TablesRead(match &self.form {
            Form::Locked(lock) => Read::Locked(lock.read()),
            Form::Snapshot(snapshot) => Read::Pinned(snapshot.pin()),
        })
    }

    /// [`Self::read`] for a thread that holds no read of this cell and takes one per message.
    ///
    /// Under `rwlock` [`PlainRwLock::read_behind_a_writer_waiting`]: the reader queues behind a
    /// writer that has waited `longer_than`, so that the faces' reads cannot keep a writer out for
    /// as long as they route. Under `snapshot` no reader keeps a writer out, and this is
    /// [`Self::read`].
    pub(crate) fn read_behind_a_writer_waiting(&self, longer_than: Duration) -> TablesRead<'_> {
        TablesRead(match &self.form {
            Form::Locked(lock) => Read::Locked(lock.read_behind_a_writer_waiting(longer_than)),
            Form::Snapshot(snapshot) => Read::Pinned(snapshot.pin()),
        })
    }

    /// The tables for writing, alone among the writers, until [`TablesWrite::publish`] or the drop.
    ///
    /// Under `rwlock` the write guard, which waits for every reader. Under `snapshot` the writers'
    /// lock and a draft copied from the published version; the readers go on routing by the
    /// published version, and see the write once it is published.
    pub(crate) fn write(&self) -> TablesWrite<'_> {
        TablesWrite(match &self.form {
            Form::Locked(lock) => Write::Locked(lock.write()),
            Form::Snapshot(snapshot) => {
                let writer = snapshot.writer.guard();
                // The writers' lock is held, so no publish can come between the copy and the
                // publishing of the draft.
                let tables = Arc::new(Tables::clone(&snapshot.published.load()));
                Write::Draft(Draft {
                    snapshot,
                    tables,
                    _writer: writer,
                })
            }
        })
    }

    /// Wait until no reader holds a version of the tables that was replaced before this call: the
    /// grace period of read-copy-update (`docs/router-table-snapshots.md`, section 5 item 3).
    /// What a write took out of the tables is then out of every reader's sight, and a reader that
    /// loads from now on loads a version without it.
    ///
    /// Under `rwlock` there is nothing to wait for: the write guard already waited for every
    /// reader. A thread that holds a read of this cell must not call it under `snapshot`, as it
    /// would wait for itself; it panics instead of hanging.
    pub(crate) fn synchronize(&self) {
        let Form::Snapshot(snapshot) = &self.form else {
            return;
        };
        assert!(
            !snapshot.pinned_here(),
            "a thread that holds a version of the router's tables waited for the readers of the \
             versions before, and would have waited for itself"
        );
        let waited: Vec<Weak<Tables>> = {
            let mut retired = snapshot.retired.guard();
            retired.retain(|version| version.strong_count() > 0);
            retired.clone()
        };
        let mut pause = None;
        while waited.iter().any(|version| version.strong_count() > 0) {
            match pause {
                None => {
                    std::thread::yield_now();
                    pause = Some(FIRST_PAUSE);
                }
                Some(now) => {
                    std::thread::sleep(now);
                    pause = Some((now * 2).min(LONGEST_PAUSE));
                }
            }
        }
    }
}

impl Snapshot {
    /// What the pins of this thread name this cell by.
    fn key(&self) -> usize {
        self as *const Self as usize
    }

    /// A read of the version this thread reads the cell by, pinning the published one for an
    /// outermost read.
    fn pin(&self) -> Pinned<'_> {
        let cell = self.key();
        let version = PINS.with(|pins| {
            let mut pins = pins.borrow_mut();
            if let Some(pin) = pins.iter_mut().find(|pin| pin.cell == cell) {
                pin.depth += 1;
                return Arc::clone(&pin.version);
            }
            let version = self.published.load_full();
            pins.push(Pin {
                cell,
                depth: 1,
                version: Arc::clone(&version),
            });
            version
        });
        Pinned {
            snapshot: self,
            version,
            _thread: PhantomData,
        }
    }

    /// Whether this thread holds a read of the cell.
    fn pinned_here(&self) -> bool {
        let cell = self.key();
        PINS.with(|pins| pins.borrow().iter().any(|pin| pin.cell == cell))
    }

    /// Make `tables` the version the readers load, and keep the one it replaces among the
    /// versions a grace period waits for. Called with the writers' lock held.
    fn publish(&self, tables: Arc<Tables>) {
        let replaced = self.published.swap(tables);
        let mut retired = self.retired.guard();
        retired.retain(|version| version.strong_count() > 0);
        retired.push(Arc::downgrade(&replaced));
    }
}

/// The tables held for reading: [`TablesCell::read`].
pub(crate) struct TablesRead<'a>(Read<'a>);

enum Read<'a> {
    Locked(PlainReadGuard<'a, Tables>),
    Pinned(Pinned<'a>),
}

/// A read of a `snapshot` cell: the version it routes by, held by its count.
struct Pinned<'a> {
    snapshot: &'a Snapshot,
    version: Arc<Tables>,
    /// The count of reads a pin keeps is the thread's own, so a read stays on the thread that
    /// took it (it is not `Send`), as a guard of the lock does.
    _thread: PhantomData<std::sync::MutexGuard<'static, ()>>,
}

impl Drop for Pinned<'_> {
    fn drop(&mut self) {
        let cell = self.snapshot.key();
        // The pin of the last read is taken out of the list and let go after the list is
        // released: freeing a version runs the drops of what it held, which may read again.
        let released = PINS.try_with(|pins| {
            let mut pins = pins.borrow_mut();
            let at = pins.iter().position(|pin| pin.cell == cell)?;
            pins[at].depth -= 1;
            if pins[at].depth == 0 {
                Some(pins.swap_remove(at))
            } else {
                None
            }
        });
        drop(released);
    }
}

impl std::ops::Deref for TablesRead<'_> {
    type Target = Tables;

    fn deref(&self) -> &Tables {
        match &self.0 {
            Read::Locked(guard) => guard,
            Read::Pinned(pinned) => &pinned.version,
        }
    }
}

/// The tables held for writing: [`TablesCell::write`]. [`Self::publish`] ends the write; a write
/// dropped without it is abandoned under `snapshot` (its draft is never seen by a reader), and
/// under `rwlock` its changes stay, as the lock's do.
pub(crate) struct TablesWrite<'a>(Write<'a>);

enum Write<'a> {
    Locked(PlainWriteGuard<'a, Tables>),
    Draft(Draft<'a>),
}

/// The next version of a `snapshot` cell, while its writer writes it.
struct Draft<'a> {
    snapshot: &'a Snapshot,
    /// Allocated where it will be published, so that publishing stores it as it is. The draft is
    /// its only holder until then, so a write through it never copies it again.
    tables: Arc<Tables>,
    /// The writers' lock, held until the draft is published or abandoned.
    _writer: PlainGuard<'a, ()>,
}

impl TablesWrite<'_> {
    /// End the write and make it seen: the guard let go under `rwlock`; under `snapshot` the draft
    /// published with one store, and only then the writers' lock let go, so that the next writer
    /// copies the version this one published.
    pub(crate) fn publish(self) {
        match self.0 {
            Write::Locked(guard) => drop(guard),
            Write::Draft(Draft {
                snapshot,
                tables,
                _writer: writer,
            }) => {
                snapshot.publish(tables);
                drop(writer);
            }
        }
    }
}

impl std::ops::Deref for TablesWrite<'_> {
    type Target = Tables;

    fn deref(&self) -> &Tables {
        match &self.0 {
            Write::Locked(guard) => guard,
            Write::Draft(draft) => &draft.tables,
        }
    }
}

impl std::ops::DerefMut for TablesWrite<'_> {
    fn deref_mut(&mut self) -> &mut Tables {
        match &mut self.0 {
            Write::Locked(guard) => guard,
            Write::Draft(draft) => Arc::make_mut(&mut draft.tables),
        }
    }
}

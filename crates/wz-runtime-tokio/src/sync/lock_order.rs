// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The order the node's locks are taken in, checked on every acquisition of a debug build.
//!
//! A deadlock between locks needs two threads that take the same two locks in opposite orders,
//! at the same moment. A test that runs each order once, at different moments, passes; the
//! deadlock waits for a load that lines the two up, which is how a node stops in the field and
//! never on the bench. What can be seen on the bench is the ORDER: the first time any thread
//! waits for lock B while it holds lock A, the edge A -> B is recorded, and the first edge that
//! closes a cycle is the deadlock, reported then, by whichever test took the second order, with
//! the place each order was taken. This is the kernel's lockdep (validated lock classes, one
//! graph of their order) and the debug-build deadlock detection of Abseil's `Mutex`, applied to
//! [`super::PlainMutex`], [`super::PlainRwLock`] and [`super::PlainCell`].
//!
//! - A lock's CLASS is the place it was made (`#[track_caller]` on its constructor): one lock a
//!   struct holds, made once per instance of the struct, is one class across every instance, so
//!   an order seen between two faces' locks holds for any two faces.
//! - An edge is recorded only for a WAIT. A `try_*` that does not wait cannot be part of a
//!   deadlock, so it records no edge; the lock it took is held all the same, and what is waited
//!   for under it is ordered after it.
//! - The reader-writer lock's recursive read ([`super::PlainRwLock::read`]) waits only for a
//!   writer that HOLDS the lock, never for one that waits. A thread that holds the lock shared
//!   therefore cannot block a recursive reader, and a cycle that enters a lock by a recursive
//!   read and leaves it held shared is broken there: such a cycle is not reported. Every other
//!   junction (an exclusive wait, a read that queues behind a waiting writer, a lock held
//!   exclusive) is not broken. This is lockdep's rule for recursive reads.
//! - The same lock taken again by the thread that holds it is a deadlock of one thread unless it
//!   is a recursive read under a read.
//! - Two locks of one class nested by one thread (a face's lock taken while another face's is
//!   held) are an order between INSTANCES that the class cannot carry, so they are checked by
//!   instance: the pair in one order and then in the other is reported.
//!
//! A cycle panics in the thread that closed it, with every edge of the cycle and where it was
//! first taken, so a test that reaches a second order fails at once and says why.
//! `WZ_LOCK_ORDER=log` writes the report at ERROR and lets the thread go on (for a process that
//! is being debugged for something else); `WZ_LOCK_ORDER=off` turns the checker off. A release
//! build carries none of this: the module is compiled only with debug assertions.

use core::panic::Location;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::OnceLock;

use super::{Held, Wait};

/// A lock class: the place its locks are made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Class {
    file: &'static str,
    line: u32,
    column: u32,
}

impl Class {
    fn of(made_at: &'static Location<'static>) -> Self {
        Self {
            file: made_at.file(),
            line: made_at.line(),
            column: made_at.column(),
        }
    }
}

impl core::fmt::Display for Class {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

/// One recorded order: a thread waited for `to` as `wait` while it held `from` as `held`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Order {
    from: Class,
    held: Held,
    to: Class,
    wait: Wait,
}

/// Where an order was first seen: where the held lock was taken, where the wait was, and the
/// stack of the thread that waited, captured once, when the order was new to the process. The
/// two places name the lock's accessors; the stack names who called them.
#[derive(Clone, Debug)]
struct Witness {
    taken_at: &'static Location<'static>,
    waited_at: &'static Location<'static>,
    stack: Option<std::sync::Arc<std::backtrace::Backtrace>>,
}

/// Whether a cycle that enters a lock by `entered` and leaves it while it is held as `left` can
/// block there. Only a recursive read entering a lock held shared cannot: a shared holder does
/// not block a recursive reader.
fn blocks(entered: Wait, left: Held) -> bool {
    blocks_entered(entered == Wait::Recursive, left)
}

/// Every order seen in the process, by the class it leaves from.
#[derive(Default)]
struct Graph {
    from: HashMap<Class, Vec<(Order, Witness)>>,
    known: HashSet<Order>,
}

impl Graph {
    /// The orders that, with `new`, close a cycle in which every junction can block, in the
    /// order of the cycle starting after `new`; `None` when there is none. A breadth-first walk
    /// over (class, whether it was entered by a recursive read) from `new.to` back to
    /// `new.from`.
    fn cycle_closed_by(&self, new: Order) -> Option<Vec<(Order, Witness)>> {
        let start = (new.to, new.wait == Wait::Recursive);
        let reaches_the_start =
            |at: (Class, bool)| at.0 == new.from && blocks_entered(at.1, new.held);
        if reaches_the_start(start) {
            return Some(Vec::new());
        }
        let mut parent: HashMap<Step, (Step, Order, Witness)> = HashMap::new();
        let mut seen: HashSet<Step> = HashSet::from([start]);
        let mut queue = VecDeque::from([start]);
        while let Some(at) = queue.pop_front() {
            for (order, witness) in self.from.get(&at.0).into_iter().flatten() {
                if !blocks_entered(at.1, order.held) {
                    continue;
                }
                let next = (order.to, order.wait == Wait::Recursive);
                if !seen.insert(next) {
                    continue;
                }
                parent.insert(next, (at, *order, witness.clone()));
                if reaches_the_start(next) {
                    let mut path = Vec::new();
                    let mut step = next;
                    while step != start {
                        let (before, order, witness) = parent[&step].clone();
                        path.push((order, witness));
                        step = before;
                    }
                    path.reverse();
                    return Some(path);
                }
                queue.push_back(next);
            }
        }
        None
    }

    fn record(&mut self, order: Order, witness: Witness) {
        if self.known.insert(order) {
            self.from
                .entry(order.from)
                .or_default()
                .push((order, witness));
        }
    }
}

/// [`blocks`] for a junction whose entering wait is known only as recursive or not.
fn blocks_entered(entered_recursive: bool, left: Held) -> bool {
    !(entered_recursive && left == Held::Shared)
}

/// The orders of the process and the pairs of one class's instances seen nested, under one lock
/// that is not itself checked.
struct Process {
    graph: Graph,
    /// `(class, outer instance, inner instance)` for every nesting of two locks of one class.
    nested: HashMap<(Class, u64, u64), Witness>,
}

fn process() -> &'static parking_lot::Mutex<Process> {
    static PROCESS: OnceLock<parking_lot::Mutex<Process>> = OnceLock::new();
    PROCESS.get_or_init(|| {
        parking_lot::Mutex::new(Process {
            graph: Graph::default(),
            nested: HashMap::new(),
        })
    })
}

/// What the checker does with a cycle.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Panic,
    Log,
    Off,
}

fn mode() -> Mode {
    static MODE: OnceLock<Mode> = OnceLock::new();
    *MODE.get_or_init(|| match std::env::var("WZ_LOCK_ORDER").as_deref() {
        Ok("off") => Mode::Off,
        Ok("log") => Mode::Log,
        _ => Mode::Panic,
    })
}

/// A lock the thread holds.
pub(crate) struct Holding {
    class: Class,
    instance: u64,
    held: Held,
    taken_at: &'static Location<'static>,
    /// A lock its holder may keep across a wait for an event (`PlainMutex::held_across_waits`).
    across_waits: bool,
}

thread_local! {
    /// The locks this thread holds, oldest first.
    static HOLDING: RefCell<Vec<Holding>> = const { RefCell::new(Vec::new()) };
    /// The orders this thread has already handed to the process, so that a thread that takes the
    /// same two locks in the same order again does not take the process's lock to say so.
    static SEEN: RefCell<HashSet<Order>> = RefCell::new(HashSet::new());
    /// The nestings of two locks of one class, `(class, outer, inner)`, this thread has already
    /// handed to the process, for the same reason; with [`SEEN`] it keeps a thread that repeats
    /// what it did from allocating, which the allocation counts of the data path measure.
    static SEEN_NESTED: RefCell<HashSet<(Class, u64, u64)>> = RefCell::new(HashSet::new());
}

/// A walk's place: a class, and whether it was entered by a recursive read.
type Step = (Class, bool);

/// A number for a lock no other lock of the process has had or will have.
pub(crate) fn next_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Whether any nesting of two locks of one class was ever recorded: until one is, a lock that is
/// dropped has nothing to take back and does not take the process's lock to learn so.
static NESTED_ANY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The lock numbered `id` is gone: take back the nestings recorded for it. Its number is never
/// given again, so what is left would never be wrong, only kept.
pub(crate) fn forget(id: u64) {
    if mode() == Mode::Off || !NESTED_ANY.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    process()
        .lock()
        .nested
        .retain(|&(_, outer, inner), _| outer != id && inner != id);
    let _ = SEEN_NESTED.try_with(|seen| {
        if let Ok(mut seen) = seen.try_borrow_mut() {
            seen.retain(|&(_, outer, inner)| outer != id && inner != id);
        }
    });
}

/// A lock this thread is about to wait for: check the order against every lock it holds, and
/// record the new orders. Reports a cycle (see the module) before the wait begins.
pub(crate) fn before_wait(
    made_at: &'static Location<'static>,
    instance: u64,
    wait: Wait,
    waited_at: &'static Location<'static>,
) {
    if mode() == Mode::Off {
        return;
    }
    let to = Class::of(made_at);
    let mut findings: Vec<String> = Vec::new();
    let mut fresh: Vec<(Order, Witness, Option<u64>)> = Vec::new();
    let _ = HOLDING.try_with(|holding| {
        let Ok(holding) = holding.try_borrow() else {
            return;
        };
        for one in holding.iter() {
            if one.instance == instance {
                if !(one.held == Held::Shared && wait == Wait::Recursive) {
                    findings.push(format!(
                        "the thread waits at {waited_at} for the lock made at {made_at}, which it \
                         already holds ({:?}, taken at {}): it waits for itself",
                        one.held, one.taken_at
                    ));
                }
                continue;
            }
            let order = Order {
                from: one.class,
                held: one.held,
                to,
                wait,
            };
            let witness = Witness {
                taken_at: one.taken_at,
                waited_at,
                stack: None,
            };
            if one.class == to {
                let unseen = SEEN_NESTED
                    .try_with(|seen| seen.borrow_mut().insert((to, one.instance, instance)))
                    .unwrap_or(true);
                if unseen {
                    fresh.push((order, witness, Some(one.instance)));
                }
                continue;
            }
            let unseen = SEEN
                .try_with(|seen| seen.borrow_mut().insert(order))
                .unwrap_or(true);
            if unseen {
                fresh.push((order, witness, None));
            }
        }
    });
    if !fresh.is_empty() {
        let mut process = process().lock();
        // This thread's stack, captured at most once and only for an order new to the process.
        let mut here: Option<std::sync::Arc<std::backtrace::Backtrace>> = None;
        let mut stack = || {
            here.get_or_insert_with(|| {
                std::sync::Arc::new(std::backtrace::Backtrace::force_capture())
            })
            .clone()
        };
        for (order, mut witness, outer) in fresh {
            if let Some(outer) = outer {
                // Two locks of one class: ordered by instance, not by class.
                if !blocks(order.wait, order.held) {
                    continue;
                }
                if let Some(other) = process.nested.get(&(to, instance, outer)) {
                    findings.push(format!(
                        "lock order: two locks made at {to} are nested in both orders: here the \
                         one taken at {} is held while the other is waited for at {}, and \
                         earlier the second was held (taken at {}) while the first was waited \
                         for at {}{}",
                        witness.taken_at,
                        witness.waited_at,
                        other.taken_at,
                        other.waited_at,
                        stack_text("the earlier nesting", other.stack.as_deref())
                    ));
                }
                if let std::collections::hash_map::Entry::Vacant(vacant) =
                    process.nested.entry((to, outer, instance))
                {
                    witness.stack = Some(stack());
                    vacant.insert(witness);
                    NESTED_ANY.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                continue;
            }
            if process.graph.known.contains(&order) {
                continue;
            }
            witness.stack = Some(stack());
            if let Some(path) = process.graph.cycle_closed_by(order) {
                findings.push(describe(order, &witness, &path));
            }
            process.graph.record(order, witness);
        }
    }
    for finding in findings {
        report(&finding);
    }
}

/// The lock is now held: remember it until the returned token is dropped with its guard.
pub(crate) fn acquired(
    made_at: &'static Location<'static>,
    instance: u64,
    held: Held,
    across_waits: bool,
    taken_at: &'static Location<'static>,
) -> Token {
    if mode() != Mode::Off {
        let _ = HOLDING.try_with(|holding| {
            if let Ok(mut holding) = holding.try_borrow_mut() {
                holding.push(Holding {
                    class: Class::of(made_at),
                    instance,
                    held,
                    taken_at,
                    across_waits,
                });
            }
        });
    }
    Token {
        instance,
        _not_send: core::marker::PhantomData,
    }
}

/// A held lock's place in its thread's list, carried by the lock's guard. Not `Send`, as the
/// guard is not: it is released by the thread that took it.
pub(crate) struct Token {
    instance: u64,
    _not_send: core::marker::PhantomData<*const ()>,
}

impl Token {
    /// The thread is about to wait on a condition variable with this lock's guard: the wait gives
    /// the lock up until it is woken, so the lock leaves the thread's list for the wait. A thread
    /// that waits for an EVENT while it holds any other lock is reported: the thread that would
    /// make the event happen may need that lock, and then neither goes on. This is the waits
    /// that are not locks (a sender waiting for room on a link), which no order of locks shows.
    /// Returns what [`Self::resume`] puts back.
    pub(crate) fn suspend(&self, waited_at: &'static Location<'static>) -> Option<Holding> {
        if mode() == Mode::Off {
            return None;
        }
        let mut findings = Vec::new();
        let taken = HOLDING
            .try_with(|holding| {
                let mut holding = holding.try_borrow_mut().ok()?;
                let at = holding
                    .iter()
                    .rposition(|one| one.instance == self.instance)?;
                let mine = holding.remove(at);
                // A lock its holders keep across waits for events is the one place a wait is
                // made under a lock: whoever waits for it holds nothing else (checked when it is
                // waited for), and whoever must not wait takes it with a try.
                for other in holding.iter().filter(|other| !other.across_waits) {
                    findings.push(format!(
                        "lock order: the thread waits at {waited_at} for an event (a condition \
                         variable of the lock made at {}) while it holds the lock made at {} \
                         ({:?}, taken at {}): the thread that would make the event happen may \
                         need that lock{}",
                        mine.class,
                        other.class,
                        other.held,
                        other.taken_at,
                        stack_text(
                            "this thread",
                            Some(&std::backtrace::Backtrace::force_capture())
                        )
                    ));
                }
                Some(mine)
            })
            .ok()
            .flatten();
        for finding in findings {
            report(&finding);
        }
        taken
    }

    /// The wait is over and the lock is held again: back on the thread's list.
    pub(crate) fn resume(&self, taken: Option<Holding>) {
        let Some(taken) = taken else {
            return;
        };
        let _ = HOLDING.try_with(|holding| {
            if let Ok(mut holding) = holding.try_borrow_mut() {
                holding.push(taken);
            }
        });
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        let _ = HOLDING.try_with(|holding| {
            if let Ok(mut holding) = holding.try_borrow_mut() {
                if let Some(at) = holding
                    .iter()
                    .rposition(|one| one.instance == self.instance)
                {
                    holding.remove(at);
                }
            }
        });
    }
}

fn describe(order: Order, witness: &Witness, path: &[(Order, Witness)]) -> String {
    let mut text = format!(
        "lock order: a cycle of waits that threads can close into a deadlock.\n  this thread waits \
         at {} for a lock made at {} ({:?}) while it holds one made at {} ({:?}, taken at {})",
        witness.waited_at, order.to, order.wait, order.from, order.held, witness.taken_at
    );
    for (order, witness) in path {
        text.push_str(&format!(
            "\n  and a thread has waited at {} for a lock made at {} ({:?}) while it held one \
             made at {} ({:?}, taken at {})",
            witness.waited_at, order.to, order.wait, order.from, order.held, witness.taken_at
        ));
    }
    text.push_str(&stack_text("this thread", witness.stack.as_deref()));
    for (number, (_, witness)) in path.iter().enumerate() {
        text.push_str(&stack_text(
            &format!("the earlier wait {}", number + 1),
            witness.stack.as_deref(),
        ));
    }
    text
}

/// A captured stack under a heading, or nothing when none was captured.
fn stack_text(whose: &str, stack: Option<&std::backtrace::Backtrace>) -> String {
    stack.map_or_else(String::new, |stack| {
        format!("\n  stack of {whose}:\n{stack}")
    })
}

fn report(finding: &str) {
    let text = format!(
        "{finding}\n  (WZ_LOCK_ORDER=log reports without stopping, WZ_LOCK_ORDER=off does not \
         check)"
    );
    if mode() == Mode::Log || std::thread::panicking() {
        log::error!("{text}");
    } else {
        panic!("{text}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn class(line: u32) -> Class {
        Class {
            file: "test.rs",
            line,
            column: 1,
        }
    }

    fn witness() -> Witness {
        Witness {
            taken_at: Location::caller(),
            waited_at: Location::caller(),
            stack: None,
        }
    }

    fn order(from: u32, held: Held, to: u32, wait: Wait) -> Order {
        Order {
            from: class(from),
            held,
            to: class(to),
            wait,
        }
    }

    /// Two exclusive locks taken in both orders close a cycle; the same two in one order do not.
    #[test]
    fn two_orders_of_two_locks_are_a_cycle_and_one_order_is_not() {
        let mut graph = Graph::default();
        let a_then_b = order(1, Held::Exclusive, 2, Wait::Exclusive);
        assert!(graph.cycle_closed_by(a_then_b).is_none());
        graph.record(a_then_b, witness());
        assert!(
            graph.cycle_closed_by(a_then_b).is_none(),
            "the same order again"
        );
        let b_then_a = order(2, Held::Exclusive, 1, Wait::Exclusive);
        let path = graph.cycle_closed_by(b_then_a).expect("a cycle");
        assert_eq!(path.len(), 1);
        assert_eq!(path[0].0, a_then_b);
    }

    /// A cycle through three classes is found, with each of its other two orders.
    #[test]
    fn a_cycle_through_three_locks_is_found_with_its_orders() {
        let mut graph = Graph::default();
        graph.record(order(1, Held::Exclusive, 2, Wait::Exclusive), witness());
        graph.record(order(2, Held::Exclusive, 3, Wait::Exclusive), witness());
        let path = graph
            .cycle_closed_by(order(3, Held::Exclusive, 1, Wait::Exclusive))
            .expect("a cycle");
        assert_eq!(
            path.iter().map(|(o, _)| (o.from, o.to)).collect::<Vec<_>>(),
            vec![(class(1), class(2)), (class(2), class(3))]
        );
    }

    /// A cycle entered by a recursive read into a lock held shared cannot block there, so it is
    /// not reported; the same cycle with a read that queues behind a waiting writer is.
    #[test]
    fn a_recursive_read_into_a_shared_hold_breaks_a_cycle_and_a_queued_read_does_not() {
        let mut graph = Graph::default();
        // A thread holds the table shared and waits to write the memo.
        graph.record(order(1, Held::Shared, 2, Wait::Exclusive), witness());
        // Another holds the memo and reads the table recursively: nobody can hold the table
        // exclusively while the first holds it shared, so this read gets in.
        assert!(graph
            .cycle_closed_by(order(2, Held::Exclusive, 1, Wait::Recursive))
            .is_none());
        // The same read queued behind a writer that waits for the first thread's read: a cycle.
        assert!(graph
            .cycle_closed_by(order(2, Held::Exclusive, 1, Wait::Shared))
            .is_some());
        // And a table held exclusively by the first thread blocks a recursive read.
        let mut held_exclusive = Graph::default();
        held_exclusive.record(order(1, Held::Exclusive, 2, Wait::Exclusive), witness());
        assert!(held_exclusive
            .cycle_closed_by(order(2, Held::Exclusive, 1, Wait::Recursive))
            .is_some());
    }

    /// What `f` panicked with, or `None` when it returned. The checker panics before the wait it
    /// refuses, so a refused order is read here without the thread ever deadlocking.
    fn refusal(f: impl FnOnce()) -> Option<String> {
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).err()?;
        Some(
            caught
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| caught.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_default(),
        )
    }

    fn checking() -> bool {
        if mode() == Mode::Panic {
            return true;
        }
        eprintln!("skip: WZ_LOCK_ORDER is set, so the checker does not stop the thread");
        false
    }

    /// Two real mutexes taken in both orders by one thread, at two different moments, are
    /// refused at the second order, before it waits, with both places named; taken in the first
    /// order again they are not.
    #[test]
    fn real_mutexes_taken_in_both_orders_are_refused_at_the_second() {
        if !checking() {
            return;
        }
        let a = super::super::PlainMutex::new(0u8);
        let b = super::super::PlainMutex::new(0u8);
        a.with(|_| b.with(|_| ()));
        a.with(|_| b.with(|_| ()));
        let refused = refusal(|| b.with(|_| a.with(|_| ()))).expect("the second order");
        assert!(refused.starts_with("lock order: a cycle"), "{refused}");
        assert!(refused.contains("lock_order.rs"), "{refused}");
        assert!(!a.is_held() && !b.is_held(), "the unwind let both go");
    }

    /// A mutex taken again by the thread that holds it is refused before it waits for itself; a
    /// recursive read under a read of the same lock is not; a write under a read of it is.
    #[test]
    fn a_lock_taken_again_by_its_holder_is_refused_unless_it_is_a_read_under_a_read() {
        if !checking() {
            return;
        }
        let mutex = super::super::PlainMutex::new(0u8);
        let refused = refusal(|| mutex.with(|_| mutex.with(|_| ()))).expect("a self wait");
        assert!(refused.contains("it waits for itself"), "{refused}");

        let table = super::super::PlainRwLock::new(0u8);
        let outer = table.read();
        let inner = table.read();
        assert_eq!(*inner + *outer, 0);
        drop(inner);
        let refused = refusal(|| drop(table.write())).expect("a write under a read");
        assert!(refused.contains("it waits for itself"), "{refused}");
        let refused = refusal(|| drop(table.read_behind_a_writer_waiting(Duration::ZERO)))
            .expect("a queued read under a read");
        assert!(refused.contains("it waits for itself"), "{refused}");
        drop(outer);
    }

    /// A lock taken without waiting orders nothing before it: the other order, waited for, is
    /// not a cycle.
    #[test]
    fn a_lock_taken_without_waiting_orders_nothing_before_it() {
        if !checking() {
            return;
        }
        let a = super::super::PlainMutex::new(0u8);
        let b = super::super::PlainMutex::new(0u8);
        a.with(|_| assert!(b.try_with(|_| ()).is_some()));
        b.with(|_| a.with(|_| ()));
    }

    /// The router's own shape: the tables held shared while a memo is written, and the memo
    /// held while the tables are read recursively. Not a deadlock, and not refused; the same with
    /// the read that queues behind a waiting writer is refused.
    #[test]
    fn a_recursive_read_under_another_lock_is_not_refused_and_a_queued_read_is() {
        if !checking() {
            return;
        }
        let tables = super::super::PlainRwLock::new(0u8);
        let memo = super::super::PlainMutex::new(0u8);
        {
            let _read = tables.read();
            memo.with(|_| ());
        }
        memo.with(|_| drop(tables.read()));
        let refused =
            refusal(|| memo.with(|_| drop(tables.read_behind_a_writer_waiting(Duration::ZERO))))
                .expect("a queued read closes the cycle");
        assert!(refused.starts_with("lock order: a cycle"), "{refused}");
    }

    /// Two locks of one class (one place made them, as one struct's lock is made once per
    /// instance) nested in one order are not refused; nested in the other order they are.
    #[test]
    fn two_locks_of_one_class_are_ordered_by_instance() {
        if !checking() {
            return;
        }
        let make = || super::super::PlainMutex::new(0u8);
        let (first, second) = (make(), make());
        first.with(|_| second.with(|_| ()));
        first.with(|_| second.with(|_| ()));
        let refused = refusal(|| second.with(|_| first.with(|_| ()))).expect("the other order");
        assert!(refused.contains("nested in both orders"), "{refused}");
    }

    /// A wait on a condition variable gives its own lock up and is not refused for it; a wait
    /// made while another lock is held is refused, naming that lock. After a wait the lock is
    /// held again as before: the order of what is waited for under it is still checked.
    #[test]
    fn a_condition_wait_under_another_lock_is_refused_and_under_its_own_is_not() {
        if !checking() {
            return;
        }
        let room = super::super::PlainCondvar::new();
        let lanes = super::super::PlainMutex::new(0u8);
        let (guard, waited) = room
            .wait_timeout(lanes.guard(), Duration::from_millis(1))
            .expect("never poisoned");
        assert!(waited.timed_out());
        drop(guard);

        let tables = super::super::PlainRwLock::new(0u8);
        let read = tables.read();
        let refused = refusal(|| {
            let _ = room.wait_timeout(lanes.guard(), Duration::from_millis(1));
        })
        .expect("a wait for an event under the tables");
        assert!(refused.contains("for an event"), "{refused}");
        drop(read);
    }

    /// A lock held across waits (a sender's conduit) may have a condition variable waited on
    /// under it: the one place a wait for an event is made under a lock.
    #[test]
    fn a_lock_held_across_waits_may_have_an_event_waited_on_under_it() {
        if !checking() {
            return;
        }
        let conduit = super::super::PlainMutex::held_across_waits(0u8);
        let room = super::super::PlainCondvar::new();
        let lanes = super::super::PlainMutex::new(0u8);
        let _sending = conduit.guard();
        let (_lanes, waited) = room
            .wait_timeout(lanes.guard(), Duration::from_millis(1))
            .expect("never poisoned");
        assert!(waited.timed_out(), "the wait was made, not refused");
    }

    /// A lock keeps its number when it moves (a vector that grows moves every lock it holds), so
    /// the order of two moved locks is still theirs: the same order again is not refused, the
    /// other order is.
    #[test]
    fn a_lock_that_moves_is_still_the_same_lock() {
        if !checking() {
            return;
        }
        let make = || super::super::PlainMutex::new(0u8);
        let mut locks = vec![make(), make()];
        locks[0].with(|_| locks[1].with(|_| ()));
        locks.reserve(locks.capacity() * 4);
        locks.extend((0..8).map(|_| make()));
        locks[0].with(|_| locks[1].with(|_| ()));
        let refused =
            refusal(|| locks[1].with(|_| locks[0].with(|_| ()))).expect("the other order");
        assert!(refused.contains("nested in both orders"), "{refused}");
    }

    /// A lock's class is where it was made, so two locks made at one place are one class and two
    /// made at two places are two.
    #[test]
    fn a_class_is_where_its_lock_was_made() {
        #[track_caller]
        fn made() -> &'static Location<'static> {
            Location::caller()
        }
        let one = made();
        let other = made();
        assert_ne!(Class::of(one), Class::of(other));
        let twice: Vec<_> = (0..2).map(|_| Class::of(made())).collect();
        assert_eq!(twice[0], twice[1]);
    }
}

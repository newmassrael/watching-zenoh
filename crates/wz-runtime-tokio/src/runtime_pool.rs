// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Subsystem runtime partitioning — five isolated tokio runtimes.
//!
//! [`runtime_impl::TokioRuntime`](crate::runtime_impl::TokioRuntime) spawns
//! onto whichever runtime is *ambient*, so every wz subsystem competes for one
//! worker pool: a receive path that saturates its workers with decode work
//! also starves the transmit path, and an operator has no dial to separate
//! them. This module is the dial. It gives each subsystem its own runtime with
//! independently tunable worker and blocking-thread counts, mirroring zenoh
//! 1.5.0's `zenoh-runtime` (`commons/zenoh-runtime/src/lib.rs:48-72, 103-127`,
//! read at 49c8a53).
//!
//! ## The five subsystems
//!
//! [`WzRuntime`](crate::runtime_pool::WzRuntime) names them, and the env
//! spellings match upstream's so an
//! operator's tuning knowledge transfers verbatim: `app`, `acc`, `tx`, `rx`,
//! `net`. So do the default worker counts — `rx` gets two workers, everything
//! else one, and all five allow 50 blocking threads.
//!
//! ## Choosing a runtime
//!
//! Nothing is rewired implicitly. `TokioRuntime` keeps spawning onto the
//! ambient runtime, which is what every existing consumer and every
//! `#[tokio::test]` expects. A caller that wants isolation names it:
//!
//! ```no_run
//! use wz_runtime_tokio::runtime_pool::{PartitionedRuntime, WzRuntime};
//! use wz_runtime_core::Runtime;
//!
//! let rx = PartitionedRuntime::new(WzRuntime::Rx);
//! rx.spawn(async { /* decode loop, isolated from TX */ });
//! ```
//!
//! [`PartitionedRuntime`](crate::runtime_pool::PartitionedRuntime) implements
//! the same [`wz_runtime_core::Runtime`] trait as `TokioRuntime`, so it is a drop-in
//! wherever a generic `R: Runtime` is threaded — the MCU profile's
//! single-executor binding is unaffected, since the partition is an AP-profile
//! concern and lives entirely in this crate.
//!
//! ## Tuning
//!
//! [`RUNTIME_ENV`](crate::runtime_pool::RUNTIME_ENV) (`WZ_RUNTIME`) overrides
//! the defaults. wz spells the
//! configuration as `name:key=value,key=value` groups separated by `;` rather
//! than borrowing upstream's RON, which would be a dependency for one string:
//!
//! ```text
//! WZ_RUNTIME='rx:worker_threads=4;tx:max_blocking_threads=8;acc:handover=app'
//! ```
//!
//! A malformed value is REFUSED, never degraded to the default — a node that
//! silently ignores the operator's tuning looks healthy while pacing itself by
//! a schedule nobody asked for.
//! [`RuntimeParams::parse`](crate::runtime_pool::RuntimeParams::parse) is the whole of that
//! accept/reject set and is a pure function on a string, so the set is testable
//! without touching the process environment.
//!
//! ## Blocking bridges
//!
//! [`WzRuntime::block_in_place`](crate::runtime_pool::WzRuntime::block_in_place)
//! is the sync-over-async bridge, and it carries
//! upstream's fail-fast guard: a caller on tokio's current-thread scheduler is
//! told so by name instead of deadlocking, and so is a caller running after
//! tokio's thread-locals have been destroyed (the at-exit handler case).

use core::fmt;
use core::future::Future;
use core::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use tokio::runtime::{Builder, Handle, Runtime as TokioRt, RuntimeFlavor};

use wz_runtime_core::Runtime;

use crate::runtime_impl::TokioJoinHandle;

/// Environment variable that overrides the per-subsystem defaults. Named for
/// wz rather than borrowed from upstream: the two pools are configured
/// independently and a process may host both.
pub const RUNTIME_ENV: &str = "WZ_RUNTIME";

/// The blocking-thread ceiling every subsystem starts with, matching zenoh
/// 1.5.0's `RuntimeParam::default` (`zenoh-runtime/src/lib.rs:60-68`).
const DEFAULT_MAX_BLOCKING_THREADS: usize = 50;

/// The five subsystems wz partitions its async work across — the same split
/// zenoh 1.5.0 makes, under the same names.
///
/// The variants are ordered as upstream declares them, and [`WzRuntime::ALL`]
/// keeps that order so a report over the pool reads the same on both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WzRuntime {
    /// Application-facing work: the session API surface a consumer calls into.
    Application,
    /// Inbound connection acceptance — the listen/accept loops.
    Acceptor,
    /// Transmit path: outbound framing and the link writer tasks.
    Tx,
    /// Receive path: link reads, decode and dispatch. Two workers by default,
    /// because this is the path that saturates first.
    Rx,
    /// Network-tier background work: scouting, gossip and linkstate upkeep.
    Net,
}

impl WzRuntime {
    /// Every subsystem, in upstream's declaration order.
    pub const ALL: [WzRuntime; 5] = [
        WzRuntime::Application,
        WzRuntime::Acceptor,
        WzRuntime::Tx,
        WzRuntime::Rx,
        WzRuntime::Net,
    ];

    /// The configuration and thread-name spelling — `app`, `acc`, `tx`, `rx`,
    /// `net`. These are upstream's `serde` renames verbatim, so a `ZENOH_RUNTIME`
    /// operator names the same subsystem the same way here.
    pub const fn as_str(self) -> &'static str {
        match self {
            WzRuntime::Application => "app",
            WzRuntime::Acceptor => "acc",
            WzRuntime::Tx => "tx",
            WzRuntime::Rx => "rx",
            WzRuntime::Net => "net",
        }
    }

    /// Parse a subsystem out of its configuration spelling.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        WzRuntime::ALL.into_iter().find(|rt| rt.as_str() == s)
    }

    /// Dense index into a per-subsystem array. Private on purpose: the array
    /// layout is an implementation detail of [`RuntimeParams`] and the pool,
    /// and exposing it would freeze the variant order into the public API.
    const fn index(self) -> usize {
        match self {
            WzRuntime::Application => 0,
            WzRuntime::Acceptor => 1,
            WzRuntime::Tx => 2,
            WzRuntime::Rx => 3,
            WzRuntime::Net => 4,
        }
    }

    /// The process-wide pool, built once from [`RUNTIME_ENV`].
    ///
    /// A malformed `WZ_RUNTIME` panics here rather than falling back to the
    /// defaults: the operator asked for a specific partition and a silent
    /// default would answer a question they did not ask.
    ///
    /// Being `'static`, this pool is never dropped, so its runtimes are torn
    /// down by process exit rather than by [`RuntimePool`]'s `Drop` — which is
    /// upstream's shape too, and is why that `Drop` is written for the
    /// caller-owned pools rather than for this one.
    pub fn pool() -> &'static RuntimePool {
        static POOL: OnceLock<RuntimePool> = OnceLock::new();
        POOL.get_or_init(|| {
            let params = match std::env::var(RUNTIME_ENV) {
                Ok(raw) => RuntimeParams::parse(&raw).unwrap_or_else(|e| {
                    panic!("{RUNTIME_ENV} is malformed: {e}");
                }),
                Err(_) => RuntimeParams::defaults(),
            };
            RuntimePool::new(params)
                .unwrap_or_else(|e| panic!("{RUNTIME_ENV} is not a usable partition: {e}"))
        })
    }

    /// Handle of the runtime this subsystem's work lands on — its own, or the
    /// one it was handed over to.
    pub fn handle(self) -> &'static Handle {
        WzRuntime::pool().handle(self)
    }

    /// Spawn onto this subsystem's runtime.
    pub fn spawn<F>(self, fut: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.handle().spawn(fut)
    }

    /// Drive `fut` to completion in this subsystem's runtime context from a
    /// synchronous caller, without stalling the worker the caller occupies.
    ///
    /// The future is polled on the CALLING thread — `Handle::block_on` enters
    /// the target runtime rather than migrating the future onto it — so what
    /// lands on this subsystem's workers is the work the future spawns. The
    /// calling worker is meanwhile released back to its own scheduler by
    /// `tokio::task::block_in_place`, which is what keeps the block from
    /// costing that runtime a worker for the duration.
    ///
    /// This is the sync-over-async bridge, and it is where a mis-configured
    /// consumer is caught. Tokio's current-thread scheduler has no second
    /// worker to make progress while this one blocks, so the call would
    /// deadlock; it panics by name instead. The same holds once tokio's
    /// thread-locals are gone, which is what a wz call from an at-exit handler
    /// looks like.
    ///
    /// Mirrors zenoh 1.5.0 `ZRuntime::block_in_place`
    /// (`zenoh-runtime/src/lib.rs:142-162`), including both guards.
    pub fn block_in_place<F, R>(self, fut: F) -> R
    where
        F: Future<Output = R>,
    {
        match Handle::try_current() {
            Ok(handle) => {
                assert!(
                    handle.runtime_flavor() != RuntimeFlavor::CurrentThread,
                    "wz runtime does not support tokio's current-thread scheduler here: \
                     blocking on it has no second worker to make progress and would \
                     deadlock. Use a multi-thread scheduler, e.g. \
                     #[tokio::main(flavor = \"multi_thread\", worker_threads = 1)]"
                );
            }
            Err(e) => {
                assert!(
                    !e.is_thread_local_destroyed(),
                    "tokio's thread-local state is already destroyed, so no wz runtime \
                     can be reached. This is what calling the wz API at process exit \
                     looks like (an atexit handler, or a static destructor); it is not \
                     supported."
                );
            }
        }

        tokio::task::block_in_place(move || self.handle().block_on(fut))
    }
}

impl fmt::Display for WzRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-subsystem tuning: how many async workers, how many blocking threads,
/// and whether this subsystem's work is handed to another runtime instead of
/// getting one of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeParam {
    /// Async worker threads. At least one.
    pub worker_threads: usize,
    /// Ceiling on threads serving blocking tasks. At least one.
    pub max_blocking_threads: usize,
    /// Run this subsystem's work on another subsystem's runtime — the knob for
    /// collapsing the partition back down on a small host.
    pub handover: Option<WzRuntime>,
}

impl RuntimeParam {
    /// The defaults for one subsystem, matching zenoh 1.5.0's `#[param(..)]`
    /// attributes: two workers for `rx`, one for the rest, 50 blocking threads
    /// throughout.
    pub const fn defaults_for(rt: WzRuntime) -> Self {
        let worker_threads = match rt {
            WzRuntime::Rx => 2,
            _ => 1,
        };
        Self {
            worker_threads,
            max_blocking_threads: DEFAULT_MAX_BLOCKING_THREADS,
            handover: None,
        }
    }
}

/// Tuning for all five subsystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeParams([RuntimeParam; 5]);

impl Default for RuntimeParams {
    fn default() -> Self {
        Self::defaults()
    }
}

impl RuntimeParams {
    /// Every subsystem at its documented default.
    pub const fn defaults() -> Self {
        Self([
            RuntimeParam::defaults_for(WzRuntime::Application),
            RuntimeParam::defaults_for(WzRuntime::Acceptor),
            RuntimeParam::defaults_for(WzRuntime::Tx),
            RuntimeParam::defaults_for(WzRuntime::Rx),
            RuntimeParam::defaults_for(WzRuntime::Net),
        ])
    }

    /// This subsystem's tuning.
    pub fn get(&self, rt: WzRuntime) -> &RuntimeParam {
        &self.0[rt.index()]
    }

    /// Mutable access, for a caller assembling a partition programmatically
    /// rather than through [`RUNTIME_ENV`].
    pub fn get_mut(&mut self, rt: WzRuntime) -> &mut RuntimeParam {
        &mut self.0[rt.index()]
    }

    /// Parse a [`RUNTIME_ENV`] value: `;`-separated `name:key=value,key=value`
    /// groups, each naming one subsystem. Unmentioned subsystems keep their
    /// defaults, and unmentioned keys within a named subsystem keep theirs.
    ///
    /// Everything else is refused. An unknown subsystem, an unknown key, a
    /// non-numeric or zero thread count, and a handover naming a subsystem
    /// that itself hands over are each an error that names what it rejected —
    /// the operator gets told which token was wrong, not that "the variable"
    /// was.
    pub fn parse(raw: &str) -> Result<Self, RuntimeConfigError> {
        let mut params = Self::defaults();

        for group in raw.split(';') {
            let group = group.trim();
            if group.is_empty() {
                continue;
            }
            let (name, fields) = group
                .split_once(':')
                .ok_or_else(|| RuntimeConfigError::MalformedGroup(group.to_string()))?;
            let name = name.trim();
            let rt = WzRuntime::from_str_opt(name)
                .ok_or_else(|| RuntimeConfigError::UnknownRuntime(name.to_string()))?;

            for field in fields.split(',') {
                let field = field.trim();
                if field.is_empty() {
                    continue;
                }
                let (key, value) = field
                    .split_once('=')
                    .ok_or_else(|| RuntimeConfigError::MalformedField(field.to_string()))?;
                let (key, value) = (key.trim(), value.trim());

                match key {
                    "worker_threads" => {
                        params.get_mut(rt).worker_threads = parse_thread_count(key, value)?;
                    }
                    "max_blocking_threads" => {
                        params.get_mut(rt).max_blocking_threads = parse_thread_count(key, value)?;
                    }
                    "handover" => {
                        let target = WzRuntime::from_str_opt(value)
                            .ok_or_else(|| RuntimeConfigError::UnknownRuntime(value.to_string()))?;
                        params.get_mut(rt).handover = Some(target);
                    }
                    other => return Err(RuntimeConfigError::UnknownKey(other.to_string())),
                }
            }
        }

        params.validate()?;
        Ok(params)
    }

    /// Reject the configurations whose meaning would otherwise be decided
    /// silently. Handover resolves in ONE hop, exactly as upstream's
    /// `ZRuntimePool::get` does, so a chain `a -> b -> c` would quietly drop
    /// the second hop; refusing the chain is what keeps the single hop from
    /// being a trap.
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        for rt in WzRuntime::ALL {
            let param = self.get(rt);
            // `get_mut` is public, so a programmatic caller can reach a count
            // `parse` would have refused. Tokio's builder panics on zero; this
            // returns instead, because a caller assembling a partition by hand
            // deserves the same named refusal the operator gets.
            for (key, n) in [
                ("worker_threads", param.worker_threads),
                ("max_blocking_threads", param.max_blocking_threads),
            ] {
                if n == 0 {
                    return Err(RuntimeConfigError::NotAThreadCount {
                        key: key.to_string(),
                        value: n.to_string(),
                    });
                }
            }
            let Some(target) = param.handover else {
                continue;
            };
            if target == rt {
                continue;
            }
            if let Some(next) = self.get(target).handover {
                if next != target {
                    return Err(RuntimeConfigError::HandoverChain {
                        from: rt,
                        via: target,
                        to: next,
                    });
                }
            }
        }
        Ok(())
    }
}

fn parse_thread_count(key: &str, value: &str) -> Result<usize, RuntimeConfigError> {
    let n: usize = value
        .parse()
        .map_err(|_| RuntimeConfigError::NotAThreadCount {
            key: key.to_string(),
            value: value.to_string(),
        })?;
    if n == 0 {
        return Err(RuntimeConfigError::NotAThreadCount {
            key: key.to_string(),
            value: value.to_string(),
        });
    }
    Ok(n)
}

/// Why a partition was refused. Each variant carries the token it rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeConfigError {
    /// A group with no `name:` prefix.
    MalformedGroup(String),
    /// A field with no `key=value` shape.
    MalformedField(String),
    /// A subsystem name that is not one of `app` / `acc` / `tx` / `rx` / `net`.
    UnknownRuntime(String),
    /// A key that is not `worker_threads` / `max_blocking_threads` / `handover`.
    UnknownKey(String),
    /// A thread count that is not a positive integer.
    NotAThreadCount { key: String, value: String },
    /// A handover chain, which single-hop resolution would silently truncate.
    HandoverChain {
        from: WzRuntime,
        via: WzRuntime,
        to: WzRuntime,
    },
    /// Tokio refused to build the runtime.
    Build { runtime: WzRuntime, source: String },
}

impl fmt::Display for RuntimeConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedGroup(g) => {
                write!(f, "expected `<runtime>:<key>=<value>`, got `{g}`")
            }
            Self::MalformedField(field) => write!(f, "expected `<key>=<value>`, got `{field}`"),
            Self::UnknownRuntime(name) => write!(
                f,
                "`{name}` is not a wz runtime; expected one of app, acc, tx, rx, net"
            ),
            Self::UnknownKey(key) => write!(
                f,
                "`{key}` is not a runtime parameter; expected one of worker_threads, \
                 max_blocking_threads, handover"
            ),
            Self::NotAThreadCount { key, value } => {
                write!(f, "`{key}={value}` is not a positive thread count")
            }
            Self::HandoverChain { from, via, to } => write!(
                f,
                "`{from}` hands over to `{via}`, which itself hands over to `{to}`; \
                 handover resolves in one hop, so name the final runtime directly"
            ),
            Self::Build { runtime, source } => {
                write!(
                    f,
                    "tokio refused to build the `{runtime}` runtime: {source}"
                )
            }
        }
    }
}

impl std::error::Error for RuntimeConfigError {}

/// Five runtimes, each built on first use.
///
/// The process-wide instance is [`WzRuntime::pool`]. This type is public and
/// directly constructible so a caller — a test, or a host embedding wz beside
/// another async system — can hold a partition of its own instead of reaching
/// through the environment.
pub struct RuntimePool {
    params: RuntimeParams,
    runtimes: [OnceLock<TokioRt>; 5],
    /// Per-subsystem thread numbering. Shared rather than owned because
    /// tokio's `thread_name_fn` must be `'static`, so the counter cannot be
    /// borrowed out of the pool.
    thread_index: [Arc<AtomicUsize>; 5],
}

impl RuntimePool {
    /// Build a pool over `params`. The runtimes themselves are created lazily,
    /// so a process that never touches `net` never pays for its threads; the
    /// configuration, however, is validated up front.
    pub fn new(params: RuntimeParams) -> Result<Self, RuntimeConfigError> {
        params.validate()?;
        Ok(Self {
            params,
            runtimes: [const { OnceLock::new() }; 5],
            thread_index: core::array::from_fn(|_| Arc::new(AtomicUsize::new(0))),
        })
    }

    /// The tuning this pool was built with.
    pub fn params(&self) -> &RuntimeParams {
        &self.params
    }

    /// Which runtime a subsystem's work actually lands on: itself, unless it
    /// was handed over. One hop, matching upstream; `RuntimeParams::validate`
    /// is what makes the single hop safe (a code span, not a link: it is
    /// private, and the C1bz budget counts a link to a private item).
    pub fn resolve(&self, rt: WzRuntime) -> WzRuntime {
        self.params.get(rt).handover.unwrap_or(rt)
    }

    /// Handle of the runtime serving `rt`, building it on first use.
    pub fn handle(&self, rt: WzRuntime) -> &Handle {
        let target = self.resolve(rt);
        let idx = target.index();
        self.runtimes[idx]
            .get_or_init(|| {
                self.build(target)
                    .unwrap_or_else(|e| panic!("cannot start the wz runtime partition: {e}"))
            })
            .handle()
    }

    /// Spawn onto the runtime serving `rt`.
    pub fn spawn<F>(&self, rt: WzRuntime, fut: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.handle(rt).spawn(fut)
    }

    fn build(&self, rt: WzRuntime) -> Result<TokioRt, RuntimeConfigError> {
        let param = self.params.get(rt);
        let counter = Arc::clone(&self.thread_index[rt.index()]);
        let name = rt.as_str();
        Builder::new_multi_thread()
            .worker_threads(param.worker_threads)
            .max_blocking_threads(param.max_blocking_threads)
            .enable_io()
            .enable_time()
            .thread_name_fn(move || {
                let id = counter.fetch_add(1, Ordering::SeqCst);
                format!("wz-{name}-{id}")
            })
            .build()
            .map_err(|e| RuntimeConfigError::Build {
                runtime: rt,
                source: e.to_string(),
            })
    }
}

impl fmt::Debug for RuntimePool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimePool")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

/// Shutting a runtime down blocks until its tasks release, which tokio refuses
/// to do from inside another runtime. Each shutdown therefore runs on a plain
/// thread, so dropping a pool from an async context is safe — the shape a
/// test-local pool always has.
impl Drop for RuntimePool {
    fn drop(&mut self) {
        let joins: Vec<_> = self
            .runtimes
            .iter_mut()
            .filter_map(|slot| slot.take())
            .map(|rt| std::thread::spawn(move || rt.shutdown_timeout(Duration::from_secs(1))))
            .collect();
        for join in joins {
            let _ = join.join();
        }
    }
}

/// A [`wz_runtime_core::Runtime`] bound to one subsystem of the process-wide
/// partition — the drop-in for
/// [`TokioRuntime`](crate::runtime_impl::TokioRuntime) at a call site that
/// wants isolation rather than the ambient runtime.
///
/// Zero-sized beyond the subsystem tag, `Copy`, and carrying no handle: the
/// runtime is resolved through [`WzRuntime::pool`] at spawn time, so a value of
/// this type can be stored in a struct or threaded through a generic
/// `R: Runtime` without borrowing the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionedRuntime {
    subsystem: WzRuntime,
}

impl PartitionedRuntime {
    /// Bind to one subsystem.
    pub const fn new(subsystem: WzRuntime) -> Self {
        Self { subsystem }
    }

    /// Which subsystem this spawns onto.
    pub const fn subsystem(self) -> WzRuntime {
        self.subsystem
    }
}

impl Runtime for PartitionedRuntime {
    type JoinHandle<T>
        = TokioJoinHandle<T>
    where
        T: Send + 'static;

    type Mutex<T>
        = crate::sync::Mutex<T>
    where
        T: Send + 'static;
    type RwLock<T>
        = crate::sync::RwLock<T>
    where
        T: Send + Sync + 'static;

    fn spawn<F>(&self, fut: F) -> Self::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        TokioJoinHandle::from_tokio(self.subsystem.spawn(fut))
    }

    /// Same poison recovery as the ambient-runtime profile: a panicking task
    /// must not leave shutdown paths unable to unregister their ids. The
    /// partition changes which threads run the work, not what a lock means.
    fn with_mutex_mut<T, U>(mutex: &Self::Mutex<T>, f: impl FnOnce(&mut T) -> U) -> U
    where
        T: Send + 'static,
    {
        let mut guard = match mutex.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut *guard)
    }

    fn new_mutex<T>(value: T) -> Self::Mutex<T>
    where
        T: Send + 'static,
    {
        crate::sync::Mutex::new(value)
    }

    fn new_rwlock<T>(value: T) -> Self::RwLock<T>
    where
        T: Send + Sync + 'static,
    {
        crate::sync::RwLock::new(value)
    }
}

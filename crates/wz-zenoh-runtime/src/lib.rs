//
// Copyright (c) 2024 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-runtime 1.10.1, file
// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! The process-wide tokio runtimes of the zenoh family (`zenoh-runtime` 1.10.1), over watching-zenoh.
//!
//! This crate is upstream's by name, version, library name and public surface (inventory atom
//! `api-compat-rust`), and it is the one crate of the family that owns PROCESS-GLOBAL state: one pool
//! of tokio runtimes, one per [`ZRuntime`] role, in a static. Cargo keeps one crate per package name
//! in a graph, so one pool per process holds exactly while this is the crate every other crate
//! meets; that is why it is a member of the family and not a detail of the crates above it.
//!
//! The pool is configured once, from the [`ZENOH_RUNTIME_ENV`] environment variable, in RON:
//!
//! ```console
//! ZENOH_RUNTIME='(
//!   rx: (handover: app),
//!   acc: (handover: app),
//!   app: (worker_threads: 2),
//!   tx: (max_blocking_threads: 1)
//! )'
//! ```
//!
//! A role not named keeps its defaults, a field not named keeps its role's, an unknown role or field
//! is an error, and the configuration takes effect when the pool is first used and never changes
//! after.
//!
//! Upstream generates the configuration plumbing with two derive macros; here it is written out, so
//! the crate depends on no procedural-macro crate, and the generated items upstream's rustdoc shows
//! (`GlobalRuntimeParam`, the lazy statics, `ZRuntime::iter`, the `Borrow` and `Display` impls) are
//! written by hand under the same names.

use std::{
    borrow::Borrow,
    collections::HashMap,
    env, fmt,
    future::Future,
    ops::Deref,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, OnceLock,
    },
    time::Duration,
};

use lazy_static::lazy_static;
use ron::{extensions::Extensions, options::Options};
use serde::Deserialize;
use tokio::{
    runtime::{Handle, Runtime, RuntimeFlavor},
    task::JoinHandle,
};
use zenoh_result::ZResult as Result;

/// The name of the environment variable that configures the runtimes.
pub const ZENOH_RUNTIME_ENV: &str = "ZENOH_RUNTIME";

/// What one runtime of the pool is built with.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct RuntimeParam {
    /// Number of async worker threads. At least one.
    pub worker_threads: usize,
    /// Number of maximal worker threads for blocking tasks. At least one.
    pub max_blocking_threads: usize,
    /// Hand over one ZRuntime to another one.
    pub handover: Option<ZRuntime>,
}

impl Default for RuntimeParam {
    fn default() -> Self {
        Self {
            worker_threads: 1,
            max_blocking_threads: 50,
            handover: None,
        }
    }
}

impl RuntimeParam {
    /// The tokio runtime of role `zrt` with these parameters. Its threads are named `<role>-<n>`,
    /// `n` counting the threads the role has ever started.
    pub fn build(&self, zrt: ZRuntime) -> Result<Runtime> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(self.worker_threads)
            .max_blocking_threads(self.max_blocking_threads)
            .enable_io()
            .enable_time()
            .thread_name_fn(move || {
                let id = ZRUNTIME_INDEX
                    .get(&zrt)
                    .unwrap()
                    .fetch_add(1, Ordering::SeqCst);
                format!("{zrt}-{id}")
            })
            .build()?;
        Ok(rt)
    }
}

/// The roles of the pool, and the access point to its runtimes. The parameters of every role are
/// configured by the [`ZENOH_RUNTIME_ENV`] environment variable, in RON (see the crate's
/// documentation); they take effect when the pool is first used and no longer change.
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug, Deserialize)]
pub enum ZRuntime {
    /// Renamed to app. Default param: worker_threads = 1.
    #[serde(rename = "app")]
    Application,

    /// Renamed to acc. Default param: worker_threads = 1.
    #[serde(rename = "acc")]
    Acceptor,

    /// Renamed to tx. Default param: worker_threads = 1.
    #[serde(rename = "tx")]
    TX,

    /// Renamed to rx. Default param: worker_threads = 2.
    #[serde(rename = "rx")]
    RX,

    /// Renamed to net. Default param: worker_threads = 1.
    #[serde(rename = "net")]
    Net,
}

impl ZRuntime {
    /// The roles, in declaration order.
    pub fn iter() -> impl Iterator<Item = ZRuntime> {
        [
            ZRuntime::Application,
            ZRuntime::Acceptor,
            ZRuntime::TX,
            ZRuntime::RX,
            ZRuntime::Net,
        ]
        .into_iter()
    }

    /// The runtime of this role, built from its parameters.
    fn init(&self) -> Result<Runtime> {
        let param: &RuntimeParam = self.borrow();
        param.build(*self)
    }

    /// Spawn `future` on the runtime of this role.
    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        #[cfg(feature = "tracing-instrument")]
        let future = tracing::Instrument::instrument(future, tracing::Span::current());

        self.deref().spawn(future)
    }

    /// Run `f` to completion on the runtime of this role, from a thread of a multi-threaded tokio
    /// runtime, which is told it may block. Panics on a current-thread scheduler (it cannot spare the
    /// thread) and when called while the process is exiting (tokio's thread local is gone).
    pub fn block_in_place<F, R>(&self, f: F) -> R
    where
        F: Future<Output = R>,
    {
        match Handle::try_current() {
            Ok(handle) => {
                if handle.runtime_flavor() == RuntimeFlavor::CurrentThread {
                    panic!("Zenoh runtime doesn't support Tokio's current thread scheduler. Please use multi thread scheduler instead, e.g. a multi thread scheduler with one worker thread: `#[tokio::main(flavor = \"multi_thread\", worker_threads = 1)]`");
                }
            }
            Err(e) => {
                if e.is_thread_local_destroyed() {
                    panic!("The Thread Local Storage inside Tokio is destroyed. This might happen when Zenoh API is called at process exit, e.g. in the atexit handler. Calling the Zenoh API at process exit is not supported and should be avoided.");
                }
            }
        }

        #[cfg(feature = "tracing-instrument")]
        let f = tracing::Instrument::instrument(f, tracing::Span::current());

        tokio::task::block_in_place(move || self.block_on(f))
    }
}

impl Deref for ZRuntime {
    type Target = Handle;
    fn deref(&self) -> &Self::Target {
        ZRUNTIME_POOL.get(self)
    }
}

impl fmt::Display for ZRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ZRuntime::Application => "app",
            ZRuntime::Acceptor => "acc",
            ZRuntime::TX => "tx",
            ZRuntime::RX => "rx",
            ZRuntime::Net => "net",
        })
    }
}

// ── configuration ───────────────────────────────────────────────────────────

/// The parameters of every role of the pool.
pub struct GlobalRuntimeParam {
    app: RuntimeParam,
    acc: RuntimeParam,
    tx: RuntimeParam,
    rx: RuntimeParam,
    net: RuntimeParam,
}

impl GlobalRuntimeParam {
    fn of(&self, zrt: ZRuntime) -> &RuntimeParam {
        match zrt {
            ZRuntime::Application => &self.app,
            ZRuntime::Acceptor => &self.acc,
            ZRuntime::TX => &self.tx,
            ZRuntime::RX => &self.rx,
            ZRuntime::Net => &self.net,
        }
    }
}

impl Borrow<RuntimeParam> for ZRuntime {
    fn borrow(&self) -> &RuntimeParam {
        ZRUNTIME_PARAM.of(*self)
    }
}

/// What a role starts from before the environment is read: the defaults of [`RuntimeParam`] with the
/// role's own thread count.
fn default_param(zrt: ZRuntime) -> RuntimeParam {
    RuntimeParam {
        worker_threads: match zrt {
            ZRuntime::RX => 2,
            ZRuntime::Application | ZRuntime::Acceptor | ZRuntime::TX | ZRuntime::Net => 1,
        },
        ..RuntimeParam::default()
    }
}

/// The fields of one role that the environment names. A field it does not name keeps the role's own
/// default, which is why each is an `Option` and the structure is not a [`RuntimeParam`].
#[derive(Deserialize, Default, Clone, Copy)]
#[serde(deny_unknown_fields, default)]
struct RuntimeParamPatch {
    worker_threads: Option<usize>,
    max_blocking_threads: Option<usize>,
    handover: Option<ZRuntime>,
}

impl RuntimeParamPatch {
    fn applied_to(self, mut base: RuntimeParam) -> RuntimeParam {
        if let Some(n) = self.worker_threads {
            base.worker_threads = n;
        }
        if let Some(n) = self.max_blocking_threads {
            base.max_blocking_threads = n;
        }
        if self.handover.is_some() {
            base.handover = self.handover;
        }
        base
    }
}

/// What the environment variable says, role by role. An unknown role is an error.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct AbstractRuntimeParam {
    app: RuntimeParamPatch,
    acc: RuntimeParamPatch,
    tx: RuntimeParamPatch,
    rx: RuntimeParamPatch,
    net: RuntimeParamPatch,
}

impl From<AbstractRuntimeParam> for GlobalRuntimeParam {
    fn from(value: AbstractRuntimeParam) -> Self {
        Self {
            app: value.app.applied_to(default_param(ZRuntime::Application)),
            acc: value.acc.applied_to(default_param(ZRuntime::Acceptor)),
            tx: value.tx.applied_to(default_param(ZRuntime::TX)),
            rx: value.rx.applied_to(default_param(ZRuntime::RX)),
            net: value.net.applied_to(default_param(ZRuntime::Net)),
        }
    }
}

/// The parameters a RON text names (the implicit `Some` extension is on, so `handover: app` is
/// `Some(app)`).
fn parse_global(text: &str) -> std::result::Result<GlobalRuntimeParam, ron::error::SpannedError> {
    Options::default()
        .with_default_extension(Extensions::IMPLICIT_SOME)
        .from_str::<AbstractRuntimeParam>(text)
        .map(Into::into)
}

lazy_static! {
    // The text is held in a static of its own so that what the parameters were read from outlives
    // the function that read it.
    /// The text of [`ZENOH_RUNTIME_ENV`], or the empty configuration when it is not set.
    pub static ref ZENOH_RUNTIME_ENV_STRING: String =
        env::var(ZENOH_RUNTIME_ENV).unwrap_or("()".to_string());
    /// The parameters of every role, read from [`struct@ZENOH_RUNTIME_ENV_STRING`] on first use. An
    /// invalid text is a panic here, at the first use of the pool.
    pub static ref ZRUNTIME_PARAM: GlobalRuntimeParam = parse_global(&ZENOH_RUNTIME_ENV_STRING)
        .unwrap_or_else(|e| panic!("{ZENOH_RUNTIME_ENV} is not a valid runtime configuration: {e}"));
}

// ── the pool ────────────────────────────────────────────────────────────────

lazy_static! {
    /// The runtimes, one per role, each built on first use.
    pub static ref ZRUNTIME_POOL: ZRuntimePool = ZRuntimePool::new();
    /// How many threads each role has started, which numbers the next one's name.
    pub static ref ZRUNTIME_INDEX: HashMap<ZRuntime, AtomicUsize> = ZRuntime::iter()
        .map(|zrt| (zrt, AtomicUsize::new(0)))
        .collect();
}

/// A runtime of the pool with the handle that reaches it. The handle is a copy kept beside the
/// runtime because [`ZRuntimePool::get`] hands out a reference to it for as long as the pool lives,
/// while the runtime itself has to be movable out when the pool is shut down.
struct Slot {
    handle: Handle,
    runtime: Mutex<Option<Runtime>>,
}

impl Slot {
    fn new(runtime: Runtime) -> Self {
        Self {
            handle: runtime.handle().clone(),
            runtime: Mutex::new(Some(runtime)),
        }
    }

    /// The runtime, if it has not been shut down.
    fn take(&self) -> Option<Runtime> {
        self.runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }
}

/// Shut every runtime of `runtimes` down, each on a thread of its own, and wait for them: a runtime
/// that still has blocking tasks is given a second to finish them.
fn shut_down(runtimes: impl IntoIterator<Item = Runtime>) {
    let handles: Vec<_> = runtimes
        .into_iter()
        .map(|rt| std::thread::spawn(move || rt.shutdown_timeout(Duration::from_secs(1))))
        .collect();
    for handle in handles {
        let _ = handle.join();
    }
}

/// A runtime guard used to explicitly shut the pool down at the end of a process, since a static is
/// never dropped. Its drop shuts the runtimes of the pool down; the pool itself is not moved out.
#[derive(Debug)]
pub struct ZRuntimePoolGuard;

impl Drop for ZRuntimePoolGuard {
    fn drop(&mut self) {
        shut_down(
            ZRUNTIME_POOL
                .0
                .values()
                .filter_map(|cell| cell.get()?.take()),
        );
    }
}

/// The runtimes of the pool.
pub struct ZRuntimePool(HashMap<ZRuntime, OnceLock<Slot>>);

impl fmt::Debug for ZRuntimePool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let initialized = self
            .0
            .iter()
            .filter_map(|(runtime, cell)| cell.get().map(|_| runtime))
            .collect::<Vec<_>>();
        f.debug_struct("ZRuntimePool")
            .field("initialized", &initialized)
            .finish_non_exhaustive()
    }
}

impl ZRuntimePool {
    fn new() -> Self {
        Self(ZRuntime::iter().map(|zrt| (zrt, OnceLock::new())).collect())
    }

    /// The handle of the runtime that serves `zrt`, built on first use. A role that the environment
    /// hands over to another is served by that one.
    pub fn get(&self, zrt: &ZRuntime) -> &Handle {
        let param: &RuntimeParam = zrt.borrow();
        let zrt = match param.handover {
            Some(handover) => handover,
            None => *zrt,
        };

        &self
            .0
            .get(&zrt)
            .unwrap_or_else(|| panic!("The hashmap should contains {zrt} after initialization"))
            .get_or_init(|| {
                Slot::new(
                    zrt.init()
                        .unwrap_or_else(|error| panic!("Failed to init {zrt}: {error}")),
                )
            })
            .handle
    }
}

// If there are any blocking tasks spawned by ZRuntimes, the drop will block until they return.
impl Drop for ZRuntimePool {
    fn drop(&mut self) {
        shut_down(
            self.0
                .drain()
                .filter_map(|(_role, cell)| cell.into_inner()?.take()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parameters a text gives, by role, as `(worker_threads, max_blocking_threads, handover)`.
    fn read(text: &str) -> [(usize, usize, Option<ZRuntime>); 5] {
        let g = parse_global(text).expect("a valid configuration");
        [
            ZRuntime::Application,
            ZRuntime::Acceptor,
            ZRuntime::TX,
            ZRuntime::RX,
            ZRuntime::Net,
        ]
        .map(|zrt| {
            let p = g.of(zrt);
            (p.worker_threads, p.max_blocking_threads, p.handover)
        })
    }

    #[test]
    fn the_empty_configuration_gives_each_role_its_default_threads() {
        // app, acc, tx, rx, net: only rx has two.
        let threads: Vec<_> = read("()").iter().map(|p| p.0).collect();
        assert_eq!(threads, [1, 1, 1, 2, 1]);
        assert!(read("()").iter().all(|p| p.1 == 50 && p.2.is_none()));
    }

    #[test]
    fn a_field_the_environment_names_overrides_only_that_field_of_that_role() {
        let got = read("(rx: (handover: app), acc: (handover: app), app: (worker_threads: 2), tx: (max_blocking_threads: 1))");
        assert_eq!(got[0], (2, 50, None));
        assert_eq!(got[1], (1, 50, Some(ZRuntime::Application)));
        assert_eq!(got[2], (1, 1, None));
        // `rx` keeps its own two threads: naming `handover` does not reset the rest.
        assert_eq!(got[3], (2, 50, Some(ZRuntime::Application)));
        assert_eq!(got[4], (1, 50, None));
    }

    #[test]
    fn an_unknown_role_or_field_is_refused() {
        assert!(parse_global("(unknown: ())").is_err());
        assert!(parse_global("(app: (workers: 2))").is_err());
        assert!(parse_global("not ron").is_err());
    }

    #[test]
    fn a_role_displays_as_the_name_the_environment_uses() {
        let names: Vec<_> = ZRuntime::iter().map(|z| z.to_string()).collect();
        assert_eq!(names, ["app", "acc", "tx", "rx", "net"]);
    }

    #[should_panic(expected = "Zenoh runtime doesn't support")]
    #[tokio::test]
    async fn block_in_place_fail_test() {
        ZRuntime::TX.block_in_place(async { println!("Done") });
    }
}

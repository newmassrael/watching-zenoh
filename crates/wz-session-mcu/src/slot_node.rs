// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The application of a client node on the slot profile, written ONCE for every platform: the
//! storage it holds, the factory its sessions are made from, the documents it answers with, and
//! the loop that drives it. A platform (the kit's Zephyr image, the Linux process of
//! `deploy/host-slot-node`) is a [`NodePort`]: the few things the loop cannot know, and nothing
//! of the loop itself.
//!
//! The two nodes this replaces were written twice and had begun to differ in what they said,
//! not in what they did: the same set-up (the runtime, the observer, the host, the dialler), the
//! same handshake parameters, and a loop that does the same four things in the same order. A
//! change to the loop (the wake of a mailbox, a counted refusal) had to be made in both, and a
//! gate could not see that it was not.
//!
//! # What a platform supplies
//!
//! | what | where |
//! | --- | --- |
//! | the clock, the entropy, the stack (sockets) and its link | the types `C`, `E`, `T` of [`ClientNode`] |
//! | the node's identity (the zenoh id, the signing secret) | [`NodeIdentity`], filled from the board |
//! | the console, the sleep between two dials, a per-round check | [`NodePort`] |
//! | what the application does each round (a getter, a status line) | [`NodeApp`] |
//! | what a session reports its iterations to | [`SessionLayer`] ([`Answering`] asks nothing) |
//!
//! # What the loop does
//!
//! Each round: run the tasks that are ready, advance the node to the clock, give the application
//! its turn ([`NodeApp::after_tick`], which may end the run), say what changed
//! ([`RoundWatch`]: a session coming or going, a table that refused, the rounds a second), give
//! the platform its check ([`NodePort::observe`]), and sleep if the node holds no session (a node
//! with a socket sleeps in the socket's wait). The observation is a value-in, value-out type with
//! no console in it, so its rules are tested without a socket.
//!
//! # Storage
//!
//! [`NodeStorage`] is every big table the node holds, in ONE `static` whose initial value is all
//! zero bytes, so the linker places it in `.bss` and not in `.data`: one non-zero byte anywhere
//! in a `static` moves all of it. The image states the numbers as const generics; a
//! `const _: () = assert!(..)` beside the `static` holds them to the deploy file.
//!
//! This module does not link `alloc`.

use core::cell::{Cell, RefCell, UnsafeCell};
use core::fmt;
use core::mem::MaybeUninit;
use core::ops::ControlFlow;

use wz_runtime_coop::session_drive::{Bind, PumpSlots, SlotStack};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};
use wz_session_core::byte_cells::ByteCells;
use wz_session_core::entropy::EntropySource;
use wz_session_core::session_init_params::{
    cookie_bytes, zid_bytes, LinkRxConf, SessionInitParams, TxQueueConf,
};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::slot_observer::{ObserverCell, Requesters};
use wz_session_core::text_out::FixedText;
use wz_session_core::zid_hex::write_zenoh_hex;
use wz_session_core::WhatAmI;

use crate::app_layer::{NoReplies, SessionEvents, SlotApp, SlotDispatch};
use crate::connect_manager::EndpointSource;
use crate::slot_client::{
    register_document, Declaration, DeclarationKind, DocumentSinks, SlotClientNode,
};
use crate::slot_dial::SessionFactory;
use crate::slot_host::SessionHost;

/// The longest zenoh id: 16 bytes.
pub const ZID_MAX: usize = 16;
/// The bytes of the secret the node signs its cookies with.
pub const SIGNING_KEY_BYTES: usize = 32;

// ---------------------------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------------------------

/// The node's big tables, in one `static` whose initial value is ALL ZERO BYTES.
///
/// `T` is the stack the node runs over and `E` the entropy a session owns; the numbers are the
/// image's: the runtime's task table (`TASKS` cells of `TASK_BYTES` bytes) and timer table
/// (`TIMERS`), the sessions the node holds at most (`SESSIONS`), and the bytes of one receive
/// buffer (`RX`) and one frame being sent (`TX`).
pub struct NodeStorage<
    C,
    T,
    E,
    const TASKS: usize,
    const TASK_BYTES: usize,
    const TIMERS: usize,
    const SESSIONS: usize,
    const RX: usize,
    const TX: usize,
> where
    C: ClockSource + 'static,
    T: SlotStack,
    E: EntropySource + Send + 'static,
{
    /// The runtime and the tables its tasks and timers live in.
    pub runtime: RuntimeCell<C, TASKS, TASK_BYTES, TIMERS>,
    /// The session slots.
    pub sessions: SessionSlots<CoopRuntime<C>, CoopTime<C>, T::Driver, E, SESSIONS>,
    /// The pump cells.
    pub pumps: PumpSlots<C, T::Pump, SESSIONS>,
    /// The observer, with the queryables.
    pub app: SlotApp<DocumentSinks>,
    /// The receive buffers the links claim, one batch long each.
    pub rx: ByteCells<RX, SESSIONS>,
    /// The buffers the links' frames are encoded into, one batch long each.
    pub tx: ByteCells<TX, SESSIONS>,
}

// SAFETY: the profile's rule, stated on the type: the node is driven by one cooperative loop on
// one thread, which is the only thing that reaches these tables; each member is `Sync` by the
// same rule.
unsafe impl<
        C,
        T,
        E,
        const TASKS: usize,
        const TASK_BYTES: usize,
        const TIMERS: usize,
        const SESSIONS: usize,
        const RX: usize,
        const TX: usize,
    > Sync for NodeStorage<C, T, E, TASKS, TASK_BYTES, TIMERS, SESSIONS, RX, TX>
where
    C: ClockSource + 'static,
    T: SlotStack,
    E: EntropySource + Send + 'static,
{
}

impl<
        C,
        T,
        E,
        const TASKS: usize,
        const TASK_BYTES: usize,
        const TIMERS: usize,
        const SESSIONS: usize,
        const RX: usize,
        const TX: usize,
    > NodeStorage<C, T, E, TASKS, TASK_BYTES, TIMERS, SESSIONS, RX, TX>
where
    C: ClockSource + 'static,
    T: SlotStack,
    E: EntropySource + Send + 'static,
{
    /// Every table empty; all zero bytes.
    pub const fn new() -> Self {
        Self {
            runtime: RuntimeCell::new(),
            sessions: SessionSlots::new(),
            pumps: PumpSlots::new(),
            app: SlotApp::new(),
            rx: ByteCells::new(),
            tx: ByteCells::new(),
        }
    }
}

impl<
        C,
        T,
        E,
        const TASKS: usize,
        const TASK_BYTES: usize,
        const TIMERS: usize,
        const SESSIONS: usize,
        const RX: usize,
        const TX: usize,
    > Default for NodeStorage<C, T, E, TASKS, TASK_BYTES, TIMERS, SESSIONS, RX, TX>
where
    C: ClockSource + 'static,
    T: SlotStack,
    E: EntropySource + Send + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------------------------
// Documents and declarations
// ---------------------------------------------------------------------------------------------

/// A queryable the node answers: every query under `key` is answered with `body`, a JSON text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Document {
    /// The key the queryable is declared under.
    pub key: &'static str,
    /// What it answers with.
    pub body: &'static str,
}

/// The declarations the node sends on each session, in the order of their registrations: a
/// `&'static [Declaration]` of at most `N`, held in storage the image declares. `N` is the image's
/// number of documents (each is one queryable), so the list is no longer than what it holds.
///
/// The cells start uninitialised, not as a placeholder declaration: a placeholder's key is a
/// pointer, which is not zero, and one non-zero byte would move the `static` from `.bss` to
/// `.data`, which costs its bytes twice (in RAM and in flash).
pub struct Declared<const N: usize> {
    items: UnsafeCell<[MaybeUninit<Declaration>; N]>,
    len: Cell<usize>,
}

// SAFETY: the profile's rule: one thread runs the program, and the list is written only by
// `install_documents`, before the node that reads it exists.
unsafe impl<const N: usize> Sync for Declared<N> {}

impl<const N: usize> Declared<N> {
    /// An empty list.
    pub const fn new() -> Self {
        Self {
            items: UnsafeCell::new([const { MaybeUninit::uninit() }; N]),
            len: Cell::new(0),
        }
    }

    /// Add a declaration. `false` when the list is full.
    fn push(&self, declaration: Declaration) -> bool {
        let at = self.len.get();
        if at == N {
            return false;
        }
        // SAFETY: nothing holds a reference into the list yet (`all` is called after the last
        // push), and one thread runs the program.
        unsafe { (*self.items.get())[at] = MaybeUninit::new(declaration) };
        self.len.set(at + 1);
        true
    }

    /// The declarations made so far, as the node holds them for the life of the process.
    fn all(&'static self) -> &'static [Declaration] {
        // SAFETY: called once, after the last `push`; nothing writes the list afterwards. The
        // first `len` cells (at most `N`) were written by `push`, and `MaybeUninit<Declaration>`
        // has the layout of a `Declaration`.
        unsafe {
            core::slice::from_raw_parts(self.items.get().cast::<Declaration>(), self.len.get())
        }
    }
}

impl<const N: usize> Default for Declared<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Why the node's observer could not be built. The node does not start: it would declare what
/// nothing answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallRefused {
    /// The registry refused a queryable (it is full, or the key does not fit).
    Registry,
    /// More documents than the node can declare.
    TooManyDeclarations,
    /// The observer was built before.
    Twice,
}

impl InstallRefused {
    /// The console line.
    pub const fn message(self) -> &'static str {
        match self {
            Self::Registry => "wz: FAIL - the node's observer refused a queryable",
            Self::TooManyDeclarations => "wz: FAIL - more documents than declarations",
            Self::Twice => "wz: FAIL - the observer was installed twice",
        }
    }
}

/// Build the observer in `app`, where it stays, register a queryable for each of `documents` on
/// it and record its declaration in `declared`.
///
/// Its own function, not inlined into the loop, for the stack: the observer itself is large and
/// is never a value.
#[inline(never)]
pub fn install_documents<const N: usize>(
    app: &'static SlotApp<DocumentSinks>,
    documents: &[Document],
    declared: &Declared<N>,
) -> Result<&'static ObserverCell<DocumentSinks>, InstallRefused> {
    let installed = app.install_with(|observer| {
        for document in documents {
            register_document(&mut observer.queryables, document.key, document.body)
                .map_err(|_| InstallRefused::Registry)?;
            if !declared.push(Declaration {
                kind: DeclarationKind::Queryable,
                key: document.key,
            }) {
                return Err(InstallRefused::TooManyDeclarations);
            }
        }
        Ok(())
    });
    match installed {
        Ok((observer, Ok(()))) => Ok(observer),
        Ok((_, Err(why))) => Err(why),
        Err(_) => Err(InstallRefused::Twice),
    }
}

// ---------------------------------------------------------------------------------------------
// Identity and the factory
// ---------------------------------------------------------------------------------------------

/// Who the node claims to be, and the secret it signs its cookies with.
#[derive(Clone)]
pub struct NodeIdentity {
    zid: [u8; ZID_MAX],
    zid_len: usize,
    key: [u8; SIGNING_KEY_BYTES],
}

impl NodeIdentity {
    /// An identity from `zid` (1 to [`ZID_MAX`] bytes) and the signing secret. `None` when the
    /// zenoh id does not fit.
    pub fn new(zid: &[u8], key: [u8; SIGNING_KEY_BYTES]) -> Option<Self> {
        if zid.is_empty() || zid.len() > ZID_MAX {
            return None;
        }
        let mut bytes = [0u8; ZID_MAX];
        bytes[..zid.len()].copy_from_slice(zid);
        Some(Self {
            zid: bytes,
            zid_len: zid.len(),
            key,
        })
    }

    /// The zenoh id.
    pub fn zid(&self) -> &[u8] {
        &self.zid[..self.zid_len]
    }

    /// The zenoh id in its hex form, in fixed text.
    pub fn zid_hex(&self) -> FixedText<33> {
        let mut text: FixedText<33> = FixedText::new();
        let _ = write_zenoh_hex(self.zid(), &mut text);
        text
    }

    /// zenoh 1.x's handshake shape as a client, with a batch the receive slot holds whole.
    pub fn params(&self, batch_size: u16) -> SessionInitParams {
        SessionInitParams {
            whatami: WhatAmI::Client,
            zid: zid_bytes(self.zid()),
            seq_num_res: 2,
            req_id_res: 2,
            batch_size,
            lease_ms: 10_000,
            initial_sn: 0,
            cookie: cookie_bytes(&[]),
            tx_queue: TxQueueConf::default(),
            link_rx: LinkRxConf::default(),
            cookie_signing_key: SigningKey::from_slice(&self.key).expect("32-byte key"),
        }
    }
}

/// What a session reports its iterations to: the layer the node builds for the session whose
/// handle this is, over the process-wide observer. [`Answering`] is the node that asks nothing; a
/// node that asks (`deploy/host-slot-node`'s getter) wraps the same dispatch in its own.
pub trait SessionLayer<C: ClockSource + 'static> {
    /// The application layer of a session, kept in its task.
    type Events: SessionEvents + 'static;

    /// The layer of the session whose handle this is.
    fn events(
        &mut self,
        observer: &'static ObserverCell<DocumentSinks>,
        handle: &SessionHandle<C>,
    ) -> Self::Events;
}

/// A node that answers queries and asks none, so it keeps no table of pending gets and the
/// application layer its task holds is a few pointers.
#[derive(Debug, Clone, Copy, Default)]
pub struct Answering;

impl<C: ClockSource + 'static> SessionLayer<C> for Answering {
    type Events = SlotDispatch<C, NoReplies, NoReplies, DocumentSinks>;

    fn events(
        &mut self,
        observer: &'static ObserverCell<DocumentSinks>,
        handle: &SessionHandle<C>,
    ) -> Self::Events {
        SlotDispatch::new(
            observer,
            handle.clone(),
            Requesters::<NoReplies, NoReplies>::new(),
        )
    }
}

/// What the node makes its sessions from: the entropy, the parameters and the application layer
/// (the process-wide observer, with the queryables registered on it).
pub struct ClientFactory<E, L> {
    identity: NodeIdentity,
    batch_size: u16,
    entropy: fn() -> E,
    observer: &'static ObserverCell<DocumentSinks>,
    layer: L,
}

impl<C, E, L> SessionFactory<C> for ClientFactory<E, L>
where
    C: ClockSource + 'static,
    E: EntropySource + Send + 'static,
    L: SessionLayer<C>,
{
    type Entropy = E;
    type Events = L::Events;

    fn entropy(&mut self) -> E {
        (self.entropy)()
    }

    fn params(&mut self) -> SessionInitParams {
        self.identity.params(self.batch_size)
    }

    fn events(&mut self, handle: &SessionHandle<C>) -> Self::Events {
        self.layer.events(self.observer, handle)
    }
}

// ---------------------------------------------------------------------------------------------
// The loop's observations
// ---------------------------------------------------------------------------------------------

/// How the loop went, for one report: `rounds` in `ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopReport {
    /// Rounds since the last report.
    pub rounds: u32,
    /// Milliseconds since the last report.
    pub ms: u64,
}

/// What a round changed, for the console. Each field is `None` when nothing moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observed<R> {
    /// The session is now established (`true`) or lost (`false`).
    pub session: Option<bool>,
    /// The refusal counters moved to this.
    pub refused: Option<R>,
    /// The rounds a second, once an interval has passed.
    pub loop_report: Option<LoopReport>,
}

/// What the loop notices from one round to the next, as a value: the session coming and going,
/// the runtime's tables refusing what they cannot hold, and the rounds the loop goes in an
/// interval (the figure that tells a node that sleeps from one that polls).
///
/// `R` is the refusal counters, anything that compares: a table the image sized too small
/// refuses what it cannot hold and counts it, and the count moving is a firmware that is not
/// doing what it was built to.
#[derive(Debug, Clone, Copy)]
pub struct RoundWatch<R: Copy + PartialEq> {
    established: bool,
    refused: R,
    rounds: u32,
    report_every_ms: u64,
    next_report_ms: u64,
    reported_ms: u64,
}

impl<R: Copy + PartialEq> RoundWatch<R> {
    /// A watch that starts with the session lost and `refused` as the counters' value. A
    /// `report_every_ms` of 0 never reports the rounds.
    pub const fn new(refused: R, report_every_ms: u64) -> Self {
        Self {
            established: false,
            refused,
            rounds: 0,
            report_every_ms,
            next_report_ms: 0,
            reported_ms: 0,
        }
    }

    /// One round ended at `now_ms`, with the session `established` or not and the counters at
    /// `refused`.
    pub fn observe(&mut self, now_ms: u64, established: bool, refused: R) -> Observed<R> {
        let mut out = Observed {
            session: None,
            refused: None,
            loop_report: None,
        };
        self.rounds = self.rounds.wrapping_add(1);
        if self.report_every_ms != 0 && now_ms >= self.next_report_ms {
            // The first report only starts the interval; the ones after it say what the node did
            // in it.
            if self.reported_ms != 0 {
                out.loop_report = Some(LoopReport {
                    rounds: self.rounds,
                    ms: now_ms - self.reported_ms,
                });
            }
            self.rounds = 0;
            self.reported_ms = now_ms;
            self.next_report_ms = now_ms + self.report_every_ms;
        }
        if refused != self.refused {
            self.refused = refused;
            out.refused = Some(refused);
        }
        if established != self.established {
            self.established = established;
            out.session = Some(established);
        }
        out
    }
}

// ---------------------------------------------------------------------------------------------
// The platform and the application
// ---------------------------------------------------------------------------------------------

/// What the loop cannot know about the platform it runs on.
pub trait NodePort {
    /// The name the node's console lines carry ("zephyr-wz-client: session established").
    const NAME: &'static str;

    /// Say one line on the console.
    fn log(&mut self, line: fmt::Arguments<'_>);

    /// Give the CPU away for `us` microseconds. Called when the node holds no socket (between two
    /// dials of a router that is not up), which would otherwise spin above the network stack's
    /// threads and starve them.
    fn idle(&mut self, us: u32);

    /// The platform's own check, once a round, after the loop has said what changed (the kit's
    /// stack high-water mark). Throttles itself.
    fn observe(&mut self, _now_ms: u64) {}
}

/// What the loop lets the application do with the node between a round's tick and its
/// observations.
pub trait NodeHandle {
    /// Whether some session is established.
    fn is_established(&self) -> bool;

    /// Ask every session's drive loop to run its next iteration now: for an application that has
    /// just left something for a session's layer (a query in a
    /// [`GetMailbox`](crate::get_mailbox::GetMailbox)).
    #[cfg(feature = "query-get")]
    fn wake(&self);
}

impl<C, T, B, F, const S: usize, const P: usize> NodeHandle for SlotClientNode<'_, C, T, B, F, S, P>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C>,
{
    fn is_established(&self) -> bool {
        SlotClientNode::is_established(self)
    }

    #[cfg(feature = "query-get")]
    fn wake(&self) {
        SlotClientNode::wake(self);
    }
}

/// What the application does each round. The default does nothing, which is a node that only
/// answers.
pub trait NodeApp {
    /// One round, after the node ticked to `now_ms`. `Break(code)` ends the run with that exit
    /// code.
    fn after_tick(&mut self, _now_ms: u64, _node: &dyn NodeHandle) -> ControlFlow<i32> {
        ControlFlow::Continue(())
    }
}

/// A node that only answers.
impl NodeApp for () {}

// ---------------------------------------------------------------------------------------------
// The node
// ---------------------------------------------------------------------------------------------

/// The exit code of a run that could not start because the runtime was started twice.
pub const EXIT_RUNTIME_TWICE: i32 = 3;
/// The exit code of a run that could not start because the observer could not be built.
pub const EXIT_OBSERVER: i32 = 3;

/// A client node: everything the loop needs to run, handed over by the platform once.
///
/// The type parameters are the platform's: the clock `C`, the stack `T`, the entropy `E` a
/// session owns, and the layer `L` its iterations are reported to; the numbers are
/// [`NodeStorage`]'s, and `DOCS` is [`Declared`]'s.
pub struct ClientNode<
    'a,
    C,
    T,
    E,
    L,
    const TASKS: usize,
    const TASK_BYTES: usize,
    const TIMERS: usize,
    const SESSIONS: usize,
    const RX: usize,
    const TX: usize,
    const DOCS: usize,
> where
    C: ClockSource + Copy + 'static,
    T: SlotStack + Bind<T::Driver> + Copy,
    E: EntropySource + Send + 'static,
    L: SessionLayer<C>,
{
    /// The tables.
    pub storage: &'static NodeStorage<C, T, E, TASKS, TASK_BYTES, TIMERS, SESSIONS, RX, TX>,
    /// The declarations [`install_documents`] fills, one for each of `documents`.
    pub declared: &'static Declared<DOCS>,
    /// The clock the runtime and the loop read.
    pub clock: C,
    /// The stack, built over `storage.rx` and `storage.tx`.
    pub stack: T,
    /// Who the node is.
    pub identity: NodeIdentity,
    /// The batch the node advertises.
    pub batch_size: u16,
    /// A fresh entropy source for one session.
    pub entropy: fn() -> E,
    /// The endpoints it dials.
    pub endpoints: &'static dyn EndpointSource,
    /// What it answers.
    pub documents: &'a [Document],
    /// What a session reports to.
    pub layer: L,
    /// How long the loop sleeps between two dials of a router that is not up.
    pub idle_sleep_us: u32,
    /// How often the loop says how many times it went round (0 never).
    pub report_every_ms: u64,
}

impl<
        C,
        T,
        E,
        L,
        const TASKS: usize,
        const TASK_BYTES: usize,
        const TIMERS: usize,
        const SESSIONS: usize,
        const RX: usize,
        const TX: usize,
        const DOCS: usize,
    > ClientNode<'_, C, T, E, L, TASKS, TASK_BYTES, TIMERS, SESSIONS, RX, TX, DOCS>
where
    C: ClockSource + Copy + 'static,
    T: SlotStack + Bind<T::Driver> + Copy,
    E: EntropySource + Send + 'static,
    L: SessionLayer<C>,
{
    /// Set the node up and run it. Returns only when it cannot start or when the application ends
    /// the run; the value is the process's exit code.
    ///
    /// `ready` is called once the node is built and before its first round, with the zenoh id in
    /// its hex form: the line a lab (or a person at the console) waits for.
    pub fn run<P: NodePort, A: NodeApp>(
        self,
        port: &mut P,
        app: &mut A,
        ready: impl FnOnce(&mut P, &str),
    ) -> i32 {
        let Self {
            storage,
            declared,
            clock,
            stack,
            identity,
            batch_size,
            entropy,
            endpoints,
            documents,
            layer,
            idle_sleep_us,
            report_every_ms,
        } = self;

        let Some(runtime) = storage.runtime.start(clock) else {
            port.log(format_args!("wz: FAIL - the runtime was started twice"));
            return EXIT_RUNTIME_TWICE;
        };
        let local = CoopLocalSet::new(&runtime);
        let zid_text = identity.zid_hex();

        // The application's registrations, on the observer the session dispatches to. A node
        // whose registrations were refused would declare what nothing answers: stop instead,
        // with the reason.
        let observer = match install_documents(&storage.app, documents, declared) {
            Ok(observer) => observer,
            Err(why) => {
                port.log(format_args!("{}", why.message()));
                return EXIT_OBSERVER;
            }
        };

        let host: SessionHost<C, T, E, SESSIONS, SESSIONS> = SessionHost::new(
            CoopLocalSet::new(&runtime),
            &storage.sessions,
            &storage.pumps,
            stack,
        );
        let factory = RefCell::new(ClientFactory {
            identity,
            batch_size,
            entropy,
            observer,
            layer,
        });
        let mut node = SlotClientNode::new(
            &host,
            stack,
            &factory,
            endpoints,
            SessionTimeouts::spec_defaults(),
            declared.all(),
        );
        ready(port, zid_text.prefix());

        let counters = || (runtime.task_refusals(), runtime.timer_refusals());
        let mut watch = RoundWatch::new(counters(), report_every_ms);
        loop {
            local.run_until_idle();
            let now_ms = clock.now_us() / 1000;
            node.tick(now_ms);
            if let ControlFlow::Break(code) = app.after_tick(now_ms, &node) {
                return code;
            }
            let seen = watch.observe(now_ms, node.is_established(), counters());
            if let Some(report) = seen.loop_report {
                port.log(format_args!(
                    "{}: loop {} rounds in {} ms",
                    P::NAME,
                    report.rounds,
                    report.ms
                ));
            }
            if let Some((tasks, timers)) = seen.refused {
                port.log(format_args!(
                    "wz: FAIL - the runtime refused a task or a timer: no cell {}, too large {}, timers {}",
                    tasks.no_task_cell, tasks.too_large, timers
                ));
            }
            port.observe(now_ms);
            if let Some(up) = seen.session {
                port.log(format_args!(
                    "{}: session {}",
                    P::NAME,
                    if up { "established" } else { "lost" }
                ));
            }
            // The stack's own wait on a socket is what gives the CPU away while a session is
            // held (its read waits for a datagram). Between two dials of a router that is not up
            // the node holds no socket: it sleeps the tick itself then.
            if !node.holds_session() {
                port.idle(idle_sleep_us);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use wz_session_core::caps::MAX_QUERYABLES;
    use wz_session_core::session_init_params::zid_bytes;

    /// A watch over counters that are one number, with a report every 5 s.
    fn watch() -> RoundWatch<u32> {
        RoundWatch::new(0, 5_000)
    }

    #[test]
    fn a_round_that_changes_nothing_says_nothing() {
        let mut watch = RoundWatch::new(0u32, 0);
        for ms in [0, 1, 2, 10_000] {
            let seen = watch.observe(ms, false, 0);
            assert_eq!(
                seen,
                Observed {
                    session: None,
                    refused: None,
                    loop_report: None
                }
            );
        }
    }

    #[test]
    fn the_session_coming_and_going_is_said_once_each() {
        let mut watch = watch();
        assert_eq!(watch.observe(1, true, 0).session, Some(true));
        assert_eq!(watch.observe(2, true, 0).session, None);
        assert_eq!(watch.observe(3, false, 0).session, Some(false));
        assert_eq!(watch.observe(4, false, 0).session, None);
    }

    #[test]
    fn a_refusal_counter_that_moves_is_said_with_its_new_value_and_only_then() {
        let mut watch = watch();
        assert_eq!(watch.observe(1, false, 0).refused, None);
        assert_eq!(watch.observe(2, false, 3).refused, Some(3));
        assert_eq!(watch.observe(3, false, 3).refused, None);
        assert_eq!(watch.observe(4, false, 4).refused, Some(4));
    }

    #[test]
    fn the_rounds_are_reported_every_interval_and_the_first_only_starts_it() {
        let mut watch = watch();
        // The first report only starts the interval, even though it is due.
        assert_eq!(watch.observe(1_000, false, 0).loop_report, None);
        // Not yet due.
        assert_eq!(watch.observe(1_001, false, 0).loop_report, None);
        assert_eq!(watch.observe(5_999, false, 0).loop_report, None);
        // Due: the rounds since the interval began (this one included) and the time it took.
        assert_eq!(
            watch.observe(6_000, false, 0).loop_report,
            Some(LoopReport {
                rounds: 3,
                ms: 5_000
            })
        );
        // The next interval counts from the report.
        assert_eq!(watch.observe(6_001, false, 0).loop_report, None);
        assert_eq!(
            watch.observe(11_000, false, 0).loop_report,
            Some(LoopReport {
                rounds: 2,
                ms: 5_000
            })
        );
    }

    #[test]
    fn a_report_interval_of_zero_never_reports() {
        let mut watch = RoundWatch::new(0u32, 0);
        for ms in (1..20).map(|n| n * 5_000) {
            assert_eq!(watch.observe(ms, false, 0).loop_report, None);
        }
    }

    #[test]
    fn the_round_counter_wraps_instead_of_failing() {
        let mut watch = RoundWatch::new(0u32, 0);
        watch.rounds = u32::MAX;
        let _ = watch.observe(1, false, 0);
        assert_eq!(watch.rounds, 0);
    }

    #[test]
    fn an_identity_takes_one_to_sixteen_bytes_of_zenoh_id() {
        let key = [7u8; SIGNING_KEY_BYTES];
        assert!(NodeIdentity::new(&[], key).is_none());
        assert!(NodeIdentity::new(&[1; ZID_MAX + 1], key).is_none());
        for len in [1, 8, ZID_MAX] {
            let identity = NodeIdentity::new(&[0xab; ZID_MAX][..len], key).unwrap();
            assert_eq!(identity.zid(), &[0xab; ZID_MAX][..len]);
        }
    }

    #[test]
    fn the_handshake_is_a_client_of_the_batch_the_platform_states() {
        let identity = NodeIdentity::new(&[1, 2, 3, 4], [9u8; SIGNING_KEY_BYTES]).unwrap();
        let params = identity.params(1472);
        assert_eq!(params.whatami, WhatAmI::Client);
        assert_eq!(params.zid, zid_bytes(&[1, 2, 3, 4]));
        assert_eq!(params.batch_size, 1472);
        assert_eq!(params.lease_ms, 10_000);
        assert_eq!(params.seq_num_res, 2);
        assert_eq!(params.req_id_res, 2);
        assert_eq!(params.initial_sn, 0);
    }

    #[test]
    fn the_zid_hex_is_zenoh_s_form() {
        let identity = NodeIdentity::new(&[0x01, 0xab], [0u8; SIGNING_KEY_BYTES]).unwrap();
        let mut expected: FixedText<33> = FixedText::new();
        let _ = write_zenoh_hex(&[0x01, 0xab], &mut expected);
        assert_eq!(identity.zid_hex().prefix(), expected.prefix());
        assert!(!identity.zid_hex().prefix().is_empty());
    }

    fn app() -> &'static SlotApp<DocumentSinks> {
        Box::leak(Box::new(SlotApp::new()))
    }

    fn declared<const N: usize>() -> &'static Declared<N> {
        Box::leak(Box::new(Declared::new()))
    }

    #[test]
    fn each_document_is_registered_and_declared_in_order() {
        let declared = declared::<2>();
        let documents = [
            Document {
                key: "demo/a",
                body: "{}",
            },
            Document {
                key: "demo/b",
                body: "[]",
            },
        ];
        // A build that allows fewer queryables than documents cannot run this test.
        assert!(MAX_QUERYABLES >= documents.len());
        install_documents(app(), &documents, declared).unwrap();
        let all = declared.all();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].key, "demo/a");
        assert_eq!(all[1].key, "demo/b");
        assert!(all.iter().all(|d| d.kind == DeclarationKind::Queryable));
    }

    #[test]
    fn a_node_with_no_documents_declares_nothing() {
        let declared = declared::<2>();
        install_documents(app(), &[], declared).unwrap();
        assert!(declared.all().is_empty());
    }

    #[test]
    fn more_documents_than_the_image_declares_stops_the_node() {
        let documents = [
            Document {
                key: "demo/a",
                body: "{}",
            },
            Document {
                key: "demo/b",
                body: "{}",
            },
        ];
        // The registry takes both, so the refusal is the declarations' own.
        assert!(MAX_QUERYABLES >= documents.len());
        assert_eq!(
            install_documents(app(), &documents, declared::<1>()).err(),
            Some(InstallRefused::TooManyDeclarations)
        );
    }

    #[test]
    fn more_documents_than_the_registry_holds_stops_the_node() {
        let documents: alloc::vec::Vec<Document> = (0..=MAX_QUERYABLES)
            .map(|_| Document {
                key: "demo/k",
                body: "{}",
            })
            .collect();
        // The declarations would hold them all, so the refusal is the registry's.
        assert_eq!(
            install_documents(app(), &documents, declared::<{ MAX_QUERYABLES + 1 }>()).err(),
            Some(InstallRefused::Registry)
        );
    }

    #[test]
    fn the_observer_is_not_built_twice() {
        let shared = app();
        install_documents(shared, &[], declared::<0>()).unwrap();
        assert_eq!(
            install_documents(shared, &[], declared::<0>()).err(),
            Some(InstallRefused::Twice)
        );
    }

    #[test]
    fn every_refusal_has_its_own_console_line() {
        let all = [
            InstallRefused::Registry,
            InstallRefused::TooManyDeclarations,
            InstallRefused::Twice,
        ];
        for (at, a) in all.iter().enumerate() {
            assert!(a.message().starts_with("wz: FAIL - "));
            for b in &all[at + 1..] {
                assert_ne!(a.message(), b.message());
            }
        }
    }
}

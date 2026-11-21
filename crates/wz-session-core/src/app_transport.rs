// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A transport the program supplies, as every engine reads it: the program's calls
//! ([`AppPort`]), the table of its links ([`AppLinkTable`]) behind the lock the ABI gives it
//! ([`TableLock`]), and the calls the program makes into it.
//!
//! The object is the same whichever engine runs the session, so a C ABI makes one, hands its
//! program a handle to it, and gives it to the engine the build has: the tokio engine's links
//! (`wz_runtime_tokio::app_link`) and the cooperative engine's (`wz_runtime_coop::app_link`) both
//! read it here.
//!
//! # Locks and calls
//!
//! The table's lock is held for one table method at a time and for nothing else: no call into the
//! program (`open`, `send`, `close`, `drained`) and no wake is made while it is held. A program
//! call that comes back into the transport (a `close` that reports the link closed, a `send` that
//! hands bytes to another link) therefore finds the lock free. A call of the program's never waits
//! on the session: it copies its bytes into the table, collects what the host must do, and does it
//! after the lock is let go. The lock is the ABI's because only the ABI knows the platform: a
//! host's mutex, or an image's critical section.

use alloc::boxed::Box;
// The links of a session share the transport, and `Arc` needs atomic pointers.
#[cfg(target_has_atomic = "ptr")]
use alloc::sync::Arc;

use crate::app_link_table::{
    AppLinkKind, AppLinkTable, Effects, InboundRefusal, LinkHandle, ProgramEvent, ProgramOpen,
    ProgramSend,
};
use crate::limit_binding::Quota;
#[cfg(target_has_atomic = "ptr")]
use crate::limits::SessionLimits;

/// The program's side of a transport: what the session calls. Each call is made with no lock of
/// the transport held, from a thread of the session's.
pub trait AppPort: Send + Sync {
    /// Open `link`, a link of `kind`, for `locator`.
    fn open(&self, link: LinkHandle, kind: AppLinkKind, locator: &str) -> ProgramOpen;
    /// Send `bytes` on `link`.
    fn send(&self, link: LinkHandle, bytes: &[u8]) -> ProgramSend;
    /// Close `link`. The program reports nothing more of it after this returns.
    fn close(&self, link: LinkHandle);
    /// `link`, which refused the program's bytes for being full, has been read down: the program
    /// may hand bytes in again. A program that does not listen for it retries on its own.
    fn drained(&self, link: LinkHandle) {
        let _ = link;
    }
}

/// The lock a transport's table is held under, which the ABI that makes the transport gives it.
pub trait TableLock: Send + Sync {
    /// Run `f` on the table with the lock held.
    fn lock_with(&self, f: &mut dyn FnMut(&mut AppLinkTable));
}

/// A transport the program supplies: its port and the table of its links.
pub struct AppTransport {
    table: Box<dyn TableLock>,
    port: Box<dyn AppPort>,
}

impl AppTransport {
    /// A transport over `port`, whose table (empty) is held under `table`.
    pub fn new(table: Box<dyn TableLock>, port: Box<dyn AppPort>) -> Self {
        Self { table, port }
    }

    /// Run `f` on the table with the lock held, and hand back what it returns, which is released
    /// after the lock is.
    pub fn with<R>(&self, f: impl FnOnce(&mut AppLinkTable) -> R) -> R {
        let mut f = Some(f);
        let mut out = None;
        self.table.lock_with(&mut |table| {
            if let Some(f) = f.take() {
                out = Some(f(table));
            }
        });
        // A lock that did not run the closure has broken its one promise; there is no table to
        // answer from.
        out.expect("a transport's table lock runs the call it is given")
    }

    /// The program's calls.
    pub fn port(&self) -> &dyn AppPort {
        self.port.as_ref()
    }

    /// Do what a table method asked for, with the lock let go: the program's close of each link
    /// named, the drained links told to the program, then the wakes.
    pub fn perform(&self, effects: Effects) {
        let Effects {
            close,
            drained,
            wake,
        } = effects;
        for link in close {
            self.port.close(link);
            let done = self.with(|table| table.close_done(link));
            self.perform(done);
        }
        for link in drained {
            self.port.drained(link);
        }
        for waker in wake {
            waker.wake();
        }
    }

    /// How many links the transport holds.
    pub fn link_count(&self) -> usize {
        self.with(|table| table.len())
    }

    /// The program hands in `bytes` that arrived on `link`, and the locator a datagram came from.
    /// The bytes are copied before this returns.
    pub fn received(
        &self,
        link: LinkHandle,
        bytes: &[u8],
        source: Option<&str>,
    ) -> Result<(), InboundRefusal> {
        let effects = self.with(|table| table.received(link, bytes, source))?;
        self.perform(effects);
        Ok(())
    }

    /// The program says `event` happened to `link`.
    pub fn event(&self, link: LinkHandle, event: ProgramEvent) -> Result<(), InboundRefusal> {
        let effects = self.with(|table| table.event(link, event))?;
        self.perform(effects);
        Ok(())
    }

    /// The program accepted a stream on `listener`, whose remote end it names `remote`: the
    /// handle of the new link, which it uses for the stream from here on.
    pub fn accepted(
        &self,
        listener: LinkHandle,
        remote: &str,
    ) -> Result<LinkHandle, InboundRefusal> {
        let (link, effects) = self.with(|table| table.accepted(listener, remote))?;
        self.perform(effects);
        Ok(link)
    }

    /// Reserve a link of `kind` for `locator`, which queues at most `queue` bytes in each
    /// direction ([`AppLinkTable::reserve`]), and ask the program to open it, the lock let go
    /// while it does: the link's handle, whose standing [`AppLinkTable::poll_open`] reads.
    pub fn begin_open(&self, kind: AppLinkKind, locator: &str, queue: Quota) -> LinkHandle {
        let handle = self.with(|table| table.reserve(kind, queue));
        let answer = self.port.open(handle, kind, locator);
        let effects = self.with(|table| table.opened(handle, answer));
        self.perform(effects);
        handle
    }

    /// The session lets `link` go: a link that is not closed is closed on the program.
    pub fn release(&self, link: LinkHandle) {
        let effects = self.with(|table| table.release(link));
        self.perform(effects);
    }
}

/// A transport as one session opens its links over it: the transport, and the most bytes each
/// link the session opens queues in either direction, the session's `APP_LINK_QUEUE_BYTES`. One
/// transport may carry the links of several sessions, each link held to its own session's bound.
#[cfg(target_has_atomic = "ptr")]
#[derive(Clone)]
pub struct SessionTransport {
    /// The transport.
    pub transport: Arc<AppTransport>,
    /// The bound of each link the session opens over it.
    pub queue: Quota,
}

#[cfg(target_has_atomic = "ptr")]
impl SessionTransport {
    /// `transport` as a session whose limits are `limits` opens its links over it.
    pub fn new(transport: Arc<AppTransport>, limits: &SessionLimits) -> Self {
        Self {
            transport,
            queue: limits.app_link_queue_bytes(),
        }
    }

    /// [`AppTransport::begin_open`] of a link held to the session's bound.
    pub fn begin_open(&self, kind: AppLinkKind, locator: &str) -> LinkHandle {
        self.transport.begin_open(kind, locator, self.queue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use std::sync::Mutex;

    struct HostLock(Mutex<AppLinkTable>);

    impl TableLock for HostLock {
        fn lock_with(&self, f: &mut dyn FnMut(&mut AppLinkTable)) {
            f(&mut self.0.lock().unwrap());
        }
    }

    #[derive(Default)]
    struct Calls {
        closes: Mutex<Vec<LinkHandle>>,
        drained: Mutex<Vec<LinkHandle>>,
    }

    struct Port(Arc<Calls>);

    impl AppPort for Port {
        fn open(&self, _link: LinkHandle, _kind: AppLinkKind, _locator: &str) -> ProgramOpen {
            ProgramOpen::Up
        }
        fn send(&self, _link: LinkHandle, bytes: &[u8]) -> ProgramSend {
            ProgramSend::Wrote(bytes.len())
        }
        fn close(&self, link: LinkHandle) {
            self.0.closes.lock().unwrap().push(link);
        }
        fn drained(&self, link: LinkHandle) {
            self.0.drained.lock().unwrap().push(link);
        }
    }

    fn transport() -> (Arc<Calls>, AppTransport) {
        let calls = Arc::new(Calls::default());
        let transport = AppTransport::new(
            Box::new(HostLock(Mutex::new(AppLinkTable::new()))),
            Box::new(Port(Arc::clone(&calls))),
        );
        (calls, transport)
    }

    #[test]
    fn an_open_the_program_answers_up_is_open_and_its_release_closes_it_on_the_program() {
        let (calls, transport) = transport();
        let link = transport.begin_open(
            AppLinkKind::StreamDial,
            "tcp/192.0.2.1:7447",
            Quota::at_most(64),
        );
        assert_eq!(
            transport.with(|table| table.state(link)),
            Some(crate::app_link::AppLinkState::Open)
        );
        transport.release(link);
        assert_eq!(calls.closes.lock().unwrap().as_slice(), [link]);
        assert_eq!(transport.link_count(), 0);
    }

    #[test]
    fn a_full_link_refuses_the_program_and_tells_it_once_read_down() {
        let (calls, transport) = transport();
        let link = transport.begin_open(
            AppLinkKind::StreamDial,
            "tcp/192.0.2.1:7447",
            Quota::at_most(4),
        );
        transport.received(link, b"abcd", None).unwrap();
        assert_eq!(
            transport.received(link, b"e", None),
            Err(InboundRefusal::Full)
        );
        let effects = transport.with(|table| {
            let mut buf = [0u8; 4];
            let _ = table.read_stream(link, &mut buf, None);
            table.take_drained()
        });
        assert!(
            calls.drained.lock().unwrap().is_empty(),
            "told only by perform"
        );
        transport.perform(effects);
        assert_eq!(calls.drained.lock().unwrap().as_slice(), [link]);
        transport.received(link, b"e", None).unwrap();
    }
}

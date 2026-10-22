// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — a stop request that arrives as a named event.
//
// WHY. On Unix the demo stops cleanly on SIGTERM and SIGINT (see `shutdown`). On
// Windows its only path was Ctrl-C, and a process started without a console
// receives no console control event at all, so a parent that starts the demo that
// way had nothing to send but `TerminateProcess`, which skips the teardown: the
// liveliness token is not undeclared on the wire and the peer sees a connection
// that just ended. A named event reaches a process whether or not it has a
// console, which is why Windows programs that need a graceful stop use one.
//
// THE CONTRACT, which a parent builds against:
//
//   * the event is named `Local\<prefix><pid>`, `<pid>` being the decimal process
//     id of the demo and `<prefix>` being `wz-stop-` unless the environment
//     variable `WZ_STOP_EVENT_PREFIX` names another one (it must not contain a
//     backslash). `Local\` keeps the event in the logon session of the user who
//     started the demo;
//   * it is a MANUAL-RESET event, not signalled when created. The parent creates
//     it first and keeps its handle, so a request made before the demo has
//     started listening is not lost: the demo opens the same event by name when
//     it begins to listen (`CreateEventW` with an existing name opens it), finds
//     it already signalled, and stops;
//   * a thread of the demo's own waits on it. When it is signalled the thread
//     resets it, so one request is read once, and the demo runs the same graceful
//     path as a Ctrl-C: the tasks are joined, the liveliness token is dropped
//     (`Declare(UndeclToken)` goes out) and the writer drains.
//
// A request is a fact about the process and not about one moment, so once it has
// been read it stays read: every later wait for it resolves at once.
//
// WHY THE PREFIX CAN BE CHOSEN. The name is a convention between the demo and
// whatever starts it, and a program that starts several kinds of children may
// already name its stop events one way. The default is wz's own, and the variable
// lets such a parent keep its one name for all of them without wz carrying a
// consumer's name in its source.

/// The environment variable that names another prefix for the event.
#[cfg(windows)]
pub(crate) const PREFIX_ENV: &str = "WZ_STOP_EVENT_PREFIX";

/// The prefix of the event's name when the environment names none.
#[cfg(any(windows, test))]
pub(crate) const DEFAULT_PREFIX: &str = "wz-stop-";

/// The prefix to use given what the environment held. An unset or empty variable
/// is the default; a prefix with a backslash or a NUL is refused, because a
/// backslash would put the event in another namespace than `Local\` and a NUL
/// would end the name early.
#[cfg(any(windows, test))]
pub(crate) fn prefix_of(env: Option<&str>) -> Result<&str, &'static str> {
    match env {
        None | Some("") => Ok(DEFAULT_PREFIX),
        Some(prefix) if prefix.contains(['\\', '\0']) => Err("it contains a backslash or a NUL"),
        Some(prefix) => Ok(prefix),
    }
}

/// The event's name for a process: `Local\<prefix><pid>`.
#[cfg(any(windows, test))]
pub(crate) fn event_name(prefix: &str, pid: u32) -> String {
    format!("Local\\{prefix}{pid}")
}

#[cfg(windows)]
mod listener {
    use super::{event_name, prefix_of, DEFAULT_PREFIX, PREFIX_ENV};
    use std::sync::OnceLock;
    use tokio::sync::watch;
    use windows_sys::Win32::Foundation::{GetLastError, HANDLE, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        CreateEventW, GetCurrentProcessId, ResetEvent, WaitForSingleObject, INFINITE,
    };

    /// The request, as a value every waiter can read: `true` once the event has
    /// been signalled.
    static REQUESTED: OnceLock<watch::Sender<bool>> = OnceLock::new();

    /// An event handle that the waiting thread may own. A kernel handle is a
    /// token the OS resolves in any thread of the process, so moving it is sound;
    /// the raw pointer type just does not say so.
    struct EventHandle(HANDLE);

    // SAFETY: a Windows event handle is valid in every thread of its process, and
    // this one is used by exactly one thread after it is moved there.
    unsafe impl Send for EventHandle {}

    impl EventHandle {
        /// Block until the event is signalled. `true` when it was.
        fn wait(&self) -> bool {
            // SAFETY: `self.0` is a live event handle this process opened and
            // never closes.
            unsafe { WaitForSingleObject(self.0, INFINITE) == WAIT_OBJECT_0 }
        }

        fn reset(&self) {
            // SAFETY: as in `wait`.
            let _ = unsafe { ResetEvent(self.0) };
        }
    }

    /// Open (or create) the event and start the thread that waits on it. The
    /// returned sender is `true` once a request has been read; if the event
    /// could not be opened it stays `false` for the life of the process, and the
    /// warning says so.
    fn listen() -> watch::Sender<bool> {
        let (tx, _keep) = watch::channel(false);
        let env = std::env::var(PREFIX_ENV).ok();
        let prefix = match prefix_of(env.as_deref()) {
            Ok(prefix) => prefix,
            Err(why) => {
                log::warn!(
                    "wz-ap-demo: {PREFIX_ENV} is not usable ({why}); using {DEFAULT_PREFIX:?}"
                );
                DEFAULT_PREFIX
            }
        };
        // SAFETY: no arguments.
        let pid = unsafe { GetCurrentProcessId() };
        let name = event_name(prefix, pid);
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // Manual reset, not signalled. A parent that made the event first is
        // opened as it is, signalled or not.
        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the
        // call, and a null security descriptor means the default.
        let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, wide.as_ptr()) };
        if handle.is_null() {
            // SAFETY: no arguments.
            let code = unsafe { GetLastError() };
            log::warn!(
                "wz-ap-demo: could not open the stop event {name} (error {code}); \
                 only Ctrl-C will stop the process gracefully"
            );
            return tx;
        }
        let waiter = EventHandle(handle);
        let wake = tx.clone();
        let started = std::thread::Builder::new()
            .name("wz-stop-event".into())
            .spawn(move || {
                // Reset first, then tell: a request that arrives while the demo is
                // already stopping signals the event again and is read, and the
                // same request is not read twice.
                while waiter.wait() {
                    waiter.reset();
                    wake.send_replace(true);
                }
                // SAFETY: no arguments.
                let code = unsafe { GetLastError() };
                log::warn!("wz-ap-demo: waiting on the stop event failed (error {code})");
            });
        match started {
            Ok(_) => log::info!("wz-ap-demo: listening for a stop request on {name}"),
            Err(e) => log::warn!(
                "wz-ap-demo: could not start the stop event thread ({e}); \
                 only Ctrl-C will stop the process gracefully"
            ),
        }
        tx
    }

    /// Resolves when a stop request has been read from the event, and never
    /// resolves if the event could not be opened.
    pub(crate) async fn requested() {
        let mut seen = REQUESTED.get_or_init(listen).subscribe();
        let _ = seen.wait_for(|asked| *asked).await;
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::time::Duration;
        use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
        use windows_sys::Win32::System::Threading::SetEvent;

        /// A parent's side of the contract, end to end on this host: create the
        /// event by the name the contract gives for this process, signal it, and
        /// the demo's wait resolves; the event is reset by then, so the request is
        /// read once; and a later wait resolves at once, because a read request
        /// stays read.
        #[tokio::test]
        async fn a_signalled_named_event_resolves_the_wait_and_is_reset() {
            // SAFETY: no arguments.
            let pid = unsafe { GetCurrentProcessId() };
            let name = event_name(DEFAULT_PREFIX, pid);
            let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            // The parent creates the event first and keeps it.
            // SAFETY: a NUL-terminated name that outlives the call.
            let parent = unsafe { CreateEventW(std::ptr::null(), 1, 0, wide.as_ptr()) };
            assert!(!parent.is_null(), "the parent could not create {name}");

            // Not signalled, so the wait does not resolve.
            let early = tokio::time::timeout(Duration::from_millis(300), requested()).await;
            assert!(early.is_err(), "the wait resolved with no request");

            // The request.
            // SAFETY: `parent` is a live event handle.
            assert_ne!(unsafe { SetEvent(parent) }, 0, "SetEvent failed");
            tokio::time::timeout(Duration::from_secs(10), requested())
                .await
                .expect("the wait did not resolve after the event was signalled");

            // Read once: the thread reset the event before it told.
            // SAFETY: `parent` is a live event handle.
            let state = unsafe { WaitForSingleObject(parent, 0) };
            assert_eq!(state, WAIT_TIMEOUT, "the event was left signalled");

            // A read request stays read.
            tokio::time::timeout(Duration::from_secs(1), requested())
                .await
                .expect("a later wait did not resolve at once");
        }
    }
}

#[cfg(windows)]
pub(crate) use listener::requested;

#[cfg(test)]
mod tests {
    use super::*;

    /// The name is `Local\<prefix><pid>` with the pid in decimal, as the
    /// contract at the top of this file states it, and the default prefix is
    /// wz's own.
    #[test]
    fn the_event_is_named_local_prefix_pid() {
        assert_eq!(DEFAULT_PREFIX, "wz-stop-");
        assert_eq!(event_name(DEFAULT_PREFIX, 4242), "Local\\wz-stop-4242");
        assert_eq!(event_name("other-", 0), "Local\\other-0");
        assert_eq!(event_name("x", u32::MAX), "Local\\x4294967295");
    }

    /// An unset or empty variable is the default, a plain prefix is taken as it
    /// is, and a prefix that would leave the `Local\` namespace or end the name
    /// early is refused.
    #[test]
    fn the_prefix_is_the_default_unless_a_usable_one_is_named() {
        assert_eq!(prefix_of(None), Ok(DEFAULT_PREFIX));
        assert_eq!(prefix_of(Some("")), Ok(DEFAULT_PREFIX));
        assert_eq!(prefix_of(Some("lab-stop-")), Ok("lab-stop-"));
        assert!(prefix_of(Some("Global\\x")).is_err());
        assert!(prefix_of(Some("a\\b")).is_err());
        assert!(prefix_of(Some("a\0b")).is_err());
    }
}

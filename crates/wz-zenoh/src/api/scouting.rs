//
// Copyright (c) 2023 ZettaScale Technology
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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.2, file
// src/api/scouting.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2). A scout is run by the
// engine (`start_scout` of the session module), which scouts on its own thread until what it
// returns is dropped, where upstream spawns a task on its runtime and terminates it; the types and
// the function are upstream's.
use std::{fmt, ops::Deref};

use zenoh_config::wrappers::Hello;
use zenoh_protocol::core::WhatAmIMatcher;
use zenoh_result::ZResult;

use crate::{
    api::{
        builders::scouting::ScoutBuilder,
        handlers::{Callback, CallbackParameter, DefaultHandler},
    },
    Config,
};

impl CallbackParameter for Hello {
    type Message<'a> = Self;

    fn from_message(msg: Self::Message<'_>) -> Self {
        msg
    }
}

/// A scout that returns [`Hello`] messages through a callback.
///
/// # Examples
/// ```
/// # #[tokio::main]
/// # async fn main() {
/// use zenoh::config::WhatAmI;
///
/// let scout = zenoh::scout(WhatAmI::Peer | WhatAmI::Router, zenoh::Config::default())
///     .callback(|hello| { println!("{}", hello); })
///     .await
///     .unwrap();
/// # }
/// ```
pub(crate) struct ScoutInner {
    /// What scouts, until it is dropped; `None` when the engine had no socket to scout with.
    #[allow(dead_code)]
    pub(crate) scout_task: Option<Box<dyn Send>>,
}

impl ScoutInner {
    /// Stop scouting.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    /// use zenoh::config::WhatAmI;
    ///
    /// let scout = zenoh::scout(WhatAmI::Peer | WhatAmI::Router, zenoh::Config::default())
    ///     .callback(|hello| { println!("{}", hello); })
    ///     .await
    ///     .unwrap();
    /// scout.stop();
    /// # }
    /// ```
    pub fn stop(self) {
        std::mem::drop(self);
    }
}

impl fmt::Debug for ScoutInner {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("CallbackScout").finish()
    }
}

/// A scout that returns [`Hello`] messages through a [`Handler`](crate::handlers::IntoHandler).
///
/// # Examples
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// use zenoh::config::WhatAmI;
///
/// let receiver = zenoh::scout(WhatAmI::Peer | WhatAmI::Router, zenoh::Config::default())
///     .with(flume::bounded(32))
///     .await
///     .unwrap();
/// while let Ok(hello) = receiver.recv_async().await {
///     println!("{}", hello);
/// }
/// # }
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub struct Scout<Receiver> {
    pub(crate) scout: ScoutInner,
    pub(crate) receiver: Receiver,
}

impl<Receiver> Deref for Scout<Receiver> {
    type Target = Receiver;

    fn deref(&self) -> &Self::Target {
        &self.receiver
    }
}

impl<Receiver> Scout<Receiver> {
    /// Stop scouting.
    ///
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    /// use zenoh::config::WhatAmI;
    ///
    /// let scout = zenoh::scout(WhatAmI::Router, zenoh::Config::default())
    ///     .with(flume::bounded(32))
    ///     .await
    ///     .unwrap();
    /// let _router = scout.recv_async().await;
    /// scout.stop();
    /// # }
    /// ```
    pub fn stop(self) {
        self.scout.stop()
    }
}

pub(crate) fn _scout(
    what: WhatAmIMatcher,
    config: Config,
    callback: Callback<Hello>,
) -> ZResult<ScoutInner> {
    tracing::trace!("scout({}, {})", what, &config);
    Ok(ScoutInner {
        scout_task: Some(crate::api::session::start_scout(what, &config, callback)?),
    })
}

/// Scout for routers and/or peers.
///
/// [`scout`] spawns a task that periodically sends scout messages and waits for [`Hello`](crate::scouting::Hello) replies.
///
/// Drop the returned [`Scout`] to stop the scouting task.
///
/// # Arguments
///
/// * `what` - The kind of zenoh process to scout for
/// * `config` - The configuration [`crate::Config`] to use for scouting
///
/// # Examples
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// use zenoh::config::WhatAmI;
///
/// let receiver = zenoh::scout(WhatAmI::Peer | WhatAmI::Router, zenoh::Config::default())
///     .await
///     .unwrap();
/// while let Ok(hello) = receiver.recv_async().await {
///     println!("{}", hello);
/// }
/// # }
/// ```
pub fn scout<I: Into<WhatAmIMatcher>, TryIntoConfig>(
    what: I,
    config: TryIntoConfig,
) -> ScoutBuilder<DefaultHandler>
where
    TryIntoConfig: std::convert::TryInto<crate::config::Config> + Send + 'static,
    <TryIntoConfig as std::convert::TryInto<crate::config::Config>>::Error:
        Into<zenoh_result::Error>,
{
    ScoutBuilder {
        what: what.into(),
        config: config.try_into().map_err(|e| e.into()),
        handler: DefaultHandler::default(),
    }
}

#[cfg(all(test, feature = "engine-tokio"))]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Arc,
        },
        time::{Duration, Instant},
    };

    use zenoh_core::Wait;

    use crate::{config::WhatAmI, open, scouting::scout, Config, Session};

    const WAIT: Duration = Duration::from_secs(10);

    /// A group and port of this test's own, so that tests that run side by side, and nodes that
    /// run beside them, do not answer each other's scouts.
    fn group() -> String {
        let port = wz_runtime_tokio_test_support::free_port();
        format!("224.0.0.231:{port}")
    }

    /// A peer that listens on `tcp_port` and answers a Scout sent to `group`.
    fn node(id: &str, tcp_port: u16, group: &str) -> Session {
        open(
            Config::from_json5(&format!(
                r#"{{ id: "{id}", mode: "peer",
                      listen: {{ endpoints: ["tcp/127.0.0.1:{tcp_port}"] }},
                      scouting: {{ multicast: {{ enabled: true, address: "{group}",
                                                 interface: "127.0.0.1" }} }} }}"#
            ))
            .expect("a configuration zenoh reads"),
        )
        .wait()
        .expect("opens")
    }

    fn scouting_config(group: &str, enabled: bool) -> Config {
        Config::from_json5(&format!(
            r#"{{ scouting: {{ multicast: {{ enabled: {enabled}, address: "{group}",
                                            interface: "127.0.0.1" }} }} }}"#
        ))
        .expect("a configuration zenoh reads")
    }

    fn free_tcp_port() -> u16 {
        wz_runtime_tokio_test_support::free_port()
    }

    #[test]
    fn a_scout_is_told_who_answers_and_where_it_listens() {
        let group = group();
        let port = free_tcp_port();
        let found = node("a1b2f0", port, &group);
        let hellos = scout(WhatAmI::Peer, scouting_config(&group, true))
            .wait()
            .expect("scouts");
        let hello = hellos
            .recv_timeout(WAIT)
            .expect("the scout is open")
            .expect("a node answers");
        assert_eq!(hello.zid(), found.zid());
        assert_eq!(hello.whatami(), WhatAmI::Peer);
        assert!(
            hello
                .locators()
                .iter()
                .any(|locator| locator.to_string() == format!("tcp/127.0.0.1:{port}")),
            "the hello names where the node listens: {hello}"
        );
    }

    /// Upstream's scout does not ask whether the configuration enables multicast scouting: that
    /// is a session's question.
    #[test]
    fn a_scout_reads_the_group_and_not_whether_a_session_would_use_it() {
        let group = group();
        let found = node("a1b2f1", free_tcp_port(), &group);
        let hellos = scout(WhatAmI::Peer, scouting_config(&group, false))
            .wait()
            .expect("scouts");
        let hello = hellos
            .recv_timeout(WAIT)
            .expect("the scout is open")
            .expect("a node answers");
        assert_eq!(hello.zid(), found.zid());
    }

    /// A scout asks for the roles it names, and a node of another role does not answer.
    #[test]
    fn a_scout_for_routers_is_not_answered_by_a_peer() {
        let group = group();
        let _peer = node("a1b2f2", free_tcp_port(), &group);
        let hellos = scout(WhatAmI::Router, scouting_config(&group, true))
            .wait()
            .expect("scouts");
        assert!(
            matches!(hellos.recv_timeout(Duration::from_millis(2500)), Ok(None)),
            "a peer is not a router"
        );
    }

    /// The scout goes on: its first Scout leaves at once and the next after a second, and a
    /// node answers each, so a callback is called again for the same node, as upstream's is.
    #[test]
    fn a_scout_asks_again_and_hands_every_answer_to_its_callback() {
        let group = group();
        let _found = node("a1b2f3", free_tcp_port(), &group);
        let (told, heard) = mpsc::channel();
        let told = std::sync::Mutex::new(told);
        let _scout = scout(WhatAmI::Peer, scouting_config(&group, true))
            .callback(move |hello| {
                let _ = told.lock().unwrap().send(hello.zid());
            })
            .wait()
            .expect("scouts");
        let first = heard.recv_timeout(WAIT).expect("a first answer");
        let second = heard.recv_timeout(WAIT).expect("a second answer");
        assert_eq!(first, second, "the same node answers each Scout");
    }

    /// The windows of a scout double, as upstream's do (`SCOUT_INITIAL_PERIOD` of a second, and
    /// the next twice the last): a node that answers each Scout is heard at the start, a second
    /// after, and two seconds after that.
    #[test]
    fn a_scout_asks_in_windows_that_double() {
        let group = group();
        let _found = node("a1b2f5", free_tcp_port(), &group);
        let (told, heard) = mpsc::channel();
        let told = std::sync::Mutex::new(told);
        let _scout = scout(WhatAmI::Peer, scouting_config(&group, true))
            .callback(move |_| {
                let _ = told.lock().unwrap().send(Instant::now());
            })
            .wait()
            .expect("scouts");
        let first = heard.recv_timeout(WAIT).expect("a first answer");
        let second = heard.recv_timeout(WAIT).expect("a second answer");
        let third = heard.recv_timeout(WAIT).expect("a third answer");
        let (one, two) = (second - first, third - second);
        assert!(
            one >= Duration::from_millis(700) && one < Duration::from_millis(1700),
            "the first window is a second: {one:?}"
        );
        assert!(
            two >= Duration::from_millis(1700) && two < Duration::from_millis(3000),
            "the second window is twice the first: {two:?}"
        );
    }

    /// Stopping a scout ends it before the call returns: nothing is handed to the callback
    /// after, and the call does not wait for a window to run out.
    #[test]
    fn a_stopped_scout_hands_nothing_more() {
        let group = group();
        let _found = node("a1b2f4", free_tcp_port(), &group);
        let count = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&count);
        let scouting = scout(WhatAmI::Peer, scouting_config(&group, true))
            .callback(move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
            })
            .wait()
            .expect("scouts");
        let deadline = Instant::now() + WAIT;
        while count.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "a node answers");
            std::thread::sleep(Duration::from_millis(20));
        }
        let stopping = Instant::now();
        scouting.stop();
        assert!(
            stopping.elapsed() < Duration::from_millis(1500),
            "stopping does not wait for a window"
        );
        let at_stop = count.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(2500));
        assert_eq!(count.load(Ordering::SeqCst), at_stop, "nothing after stop");
    }

    /// A configuration that cannot be read is the error of the call, and no scout runs.
    #[test]
    fn a_configuration_that_cannot_be_read_is_the_error_of_the_scout() {
        struct Unreadable;
        impl TryFrom<Unreadable> for Config {
            type Error = zenoh_result::Error;

            fn try_from(_: Unreadable) -> Result<Self, Self::Error> {
                Err(zerror!("not a configuration").into())
            }
        }
        let error = scout(WhatAmI::Peer, Unreadable)
            .wait()
            .expect_err("the configuration is the error of the scout");
        assert!(error.to_string().starts_with("not a configuration"));
    }
}

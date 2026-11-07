//
// Copyright (c) 2023 ZettaScale Technology
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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.2, files
// src/net/runtime/mod.rs and src/api/builders/session.rs (https://github.com/eclipse-zenoh/zenoh,
// tag 1.10.2): the names and the signatures of `Runtime`, `RuntimeBuilder`, `DynamicRuntime`, `init`
// and `InitBuilder`. The bodies are this crate's: upstream's runtime is a transport manager and a
// router, and here it is an engine that sessions share.

//! A started node that several sessions share: upstream's `zenoh::internal::runtime::Runtime`
//! and `zenoh::session::init`, which the plugins of a router and the tests of the suite use.
//!
//! Upstream's `Runtime` is the transport manager and the router of a node, and a session is a
//! view on it. Here the node is an engine ([`RuntimeCore`]): a [`Runtime`] holds one that
//! [`Runtime::start`] opens, and [`init`] makes a [`Session`] that holds a clone of it. The
//! sessions of one runtime share the node, its identity, its configuration and its clocks, and
//! nothing a session declares: the entities, the callbacks and the closing of each are its own.
//! A session made by `init` does not close the node when it closes or is dropped; the runtime
//! does, by [`Runtime::close`], and the sessions on it are then closed with it.
//!
//! Of upstream's builder of an `init` session the two lists of aggregated keys are not here: they
//! name keys a plugin's session is to aggregate, and nothing in this crate reads them.

use std::{
    fmt,
    future::{IntoFuture, Ready},
    sync::{Arc, OnceLock},
};

use async_trait::async_trait;
use zenoh_core::{Resolvable, Wait};
use zenoh_protocol::core::Locator;
use zenoh_result::{bail, ZResult};
use zenoh_runtime::ZRuntime;

use crate::api::{
    builders::close::{CloseBuilder, Closeable, Closee},
    session::{RuntimeCore, Session},
};

/// What [`Runtime::start`] opens a node from.
#[must_use = "A RuntimeBuilder does nothing until it is built"]
pub struct RuntimeBuilder {
    config: zenoh_config::Config,
}

impl fmt::Debug for RuntimeBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeBuilder").finish_non_exhaustive()
    }
}

impl RuntimeBuilder {
    pub fn new(config: zenoh_config::Config) -> Self {
        Self { config }
    }

    /// The runtime, not yet started: it listens and dials nothing until [`Runtime::start`].
    pub async fn build(self) -> ZResult<Runtime> {
        Ok(Runtime(Arc::new(RuntimeInner {
            config: self.config,
            core: OnceLock::new(),
        })))
    }
}

struct RuntimeInner {
    config: zenoh_config::Config,
    /// The node, once started.
    core: OnceLock<RuntimeCore>,
}

/// A node. Cloning it is one more handle to the same node.
#[derive(Clone)]
pub struct Runtime(Arc<RuntimeInner>);

impl fmt::Debug for Runtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Runtime")
            .field("started", &self.0.core.get().is_some())
            .finish()
    }
}

impl Runtime {
    /// Open the node: listen where the configuration says to listen, dial what it says to dial.
    /// A runtime that is started already is not started again.
    pub async fn start(&mut self) -> ZResult<()> {
        if self.0.core.get().is_some() {
            bail!("the runtime is started already")
        }
        let config = crate::config::Config::from(self.0.config.clone());
        let core = crate::api::cancellation::blocking(|| {
            RuntimeCore::open(
                &config,
                #[cfg(feature = "unstable")]
                None,
                #[cfg(feature = "shared-memory")]
                None,
            )
        })?;
        if self.0.core.set(core).is_err() {
            bail!("the runtime is started already")
        }
        Ok(())
    }

    fn core(&self) -> ZResult<&RuntimeCore> {
        match self.0.core.get() {
            Some(core) => Ok(core),
            None => bail!("the runtime is not started"),
        }
    }

    /// Close the node, and with it the sessions that run on it.
    #[allow(private_bounds)]
    pub fn close(&self) -> CloseBuilder<Self> {
        CloseBuilder::new(self)
    }

    pub fn is_closed(&self) -> bool {
        self.0.core.get().is_some_and(RuntimeCore::is_closed)
    }

    /// The locators the node listens on; none before it is started.
    pub fn get_locators(&self) -> Vec<Locator> {
        self.0
            .core
            .get()
            .map(RuntimeCore::locators)
            .unwrap_or_default()
    }

    /// The locators a peer on another host can dial, as upstream lists them. The engine lists the
    /// addresses its listeners are bound to and no other, so this is the same list: a listener
    /// bound to the loopback address is listed, which the connector of a test on one host dials.
    pub fn get_locators_noloopback(&self) -> Vec<Locator> {
        self.get_locators()
    }
}

/// What closes a [`Runtime`].
pub(crate) struct RuntimeCloser(Arc<RuntimeInner>);

#[async_trait]
impl Closee for RuntimeCloser {
    type CloseArgs = ();

    async fn close_inner(&self, _: ()) {
        let inner = self.0.clone();
        // A close joins the threads of the node, so it is run where blocking is allowed.
        let _ = ZRuntime::Net
            .spawn_blocking(move || {
                if let Some(core) = inner.core.get() {
                    core.close();
                }
            })
            .await;
    }
}

impl Closeable for Runtime {
    type TClosee = RuntimeCloser;

    fn get_closee(&self) -> RuntimeCloser {
        RuntimeCloser(self.0.clone())
    }
}

/// A runtime as the plugins of a node see it. Here it is the [`Runtime`].
#[derive(Clone, Debug)]
pub struct DynamicRuntime(Runtime);

impl From<Runtime> for DynamicRuntime {
    fn from(runtime: Runtime) -> Self {
        Self(runtime)
    }
}

/// Initialize a [`Session`] with an existing [`Runtime`].
/// This operation is used by the plugins to share the same runtime as the router.
pub fn init(runtime: DynamicRuntime) -> InitBuilder {
    InitBuilder { runtime }
}

/// A builder returned by [`init`] and used to initialize a session with an existing runtime.
#[must_use = "Resolvables do nothing unless you resolve them using `.await` or `zenoh::Wait::wait`"]
#[doc(hidden)]
pub struct InitBuilder {
    runtime: DynamicRuntime,
}

impl fmt::Debug for InitBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitBuilder").finish_non_exhaustive()
    }
}

impl Resolvable for InitBuilder {
    type To = ZResult<Session>;
}

impl Wait for InitBuilder {
    fn wait(self) -> <Self as Resolvable>::To {
        let runtime = self.runtime.0;
        let core = runtime.core()?;
        if core.is_closed() {
            bail!("the runtime is closed")
        }
        Ok(Session::on(core.clone(), false))
    }
}

impl IntoFuture for InitBuilder {
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use zenoh_core::Wait;

    use super::*;
    use crate::config::Config;

    fn peer(id: &str) -> zenoh_config::Config {
        Config::from_json5(&format!(
            r#"{{ id: "{id}", mode: "peer",
                  listen: {{ endpoints: ["tcp/127.0.0.1:0"] }},
                  scouting: {{ multicast: {{ enabled: false }} }} }}"#
        ))
        .expect("a configuration zenoh reads")
        .into()
    }

    async fn started(id: &str) -> Runtime {
        let mut runtime = RuntimeBuilder::new(peer(id)).build().await.expect("builds");
        runtime.start().await.expect("starts");
        runtime
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn two_sessions_of_a_runtime_share_its_identity_and_hear_each_other() {
        let runtime = started("c1d2e1").await;
        let one = init(runtime.clone().into()).await.expect("a session");
        let other = init(runtime.clone().into()).await.expect("another session");
        assert_eq!(
            one.zid(),
            crate::session::ZenohId::from_str("c1d2e1").expect("an id")
        );
        assert_eq!(one.zid(), other.zid());
        assert_ne!(one, other, "they are two sessions of one node");
        let (sender, received) = std::sync::mpsc::channel();
        let sender = std::sync::Mutex::new(sender);
        let _subscriber = other
            .declare_subscriber("runtime/share")
            .callback(move |sample| {
                let _ = sender.lock().unwrap().send(sample.key_expr().to_string());
            })
            .wait()
            .expect("declares");
        one.put("runtime/share", "v").wait().expect("puts");
        assert_eq!(
            received.recv_timeout(Duration::from_secs(5)).as_deref(),
            Ok("runtime/share"),
            "what one session puts, the subscriber of the other takes"
        );
        runtime.close().await.expect("closes");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn closing_a_session_of_a_runtime_leaves_the_runtime_and_the_other_sessions() {
        let runtime = started("c1d2e2").await;
        let one = init(runtime.clone().into()).await.expect("a session");
        let other = init(runtime.clone().into()).await.expect("another session");
        one.close().await.expect("closes");
        assert!(one.is_closed());
        assert!(!other.is_closed(), "the other session goes on");
        assert!(!runtime.is_closed(), "the runtime goes on");
        other
            .put("runtime/after", "v")
            .wait()
            .expect("a session still puts");
        assert!(
            one.put("runtime/after", "v").wait().is_err(),
            "a closed one does not"
        );
        runtime.close().await.expect("closes");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dropping_the_last_handle_of_a_session_of_a_runtime_leaves_the_runtime() {
        let runtime = started("c1d2e3").await;
        let one = init(runtime.clone().into()).await.expect("a session");
        let other = init(runtime.clone().into()).await.expect("another session");
        drop(one);
        assert!(!runtime.is_closed());
        assert!(!other.is_closed());
        other
            .put("runtime/dropped", "v")
            .wait()
            .expect("a session still puts");
        runtime.close().await.expect("closes");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn closing_the_runtime_closes_the_sessions_on_it() {
        let runtime = started("c1d2e4").await;
        let one = init(runtime.clone().into()).await.expect("a session");
        runtime.close().await.expect("closes");
        assert!(runtime.is_closed());
        assert!(one.is_closed(), "a session cannot outlive its node");
        assert!(
            init(runtime.clone().into()).await.is_err(),
            "no session is made on a closed runtime"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_runtime_not_started_makes_no_session_and_lists_no_locator() {
        let runtime = RuntimeBuilder::new(peer("c1d2e5"))
            .build()
            .await
            .expect("builds");
        assert!(init(runtime.clone().into()).await.is_err());
        assert!(runtime.get_locators().is_empty());
        let mut again = started("c1d2e6").await;
        assert!(again.start().await.is_err(), "a runtime is started once");
        assert!(
            !again.get_locators_noloopback().is_empty(),
            "a started one listens"
        );
        again.close().await.expect("closes");
    }
}

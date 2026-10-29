// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A router node: a node that listens, accepts the sessions of others and forwards between them
//! on the router data plane, as a session a program holds.
//!
//! The other roles of this crate are one session with N peers and no forwarding between them
//! ([`SharedSession`](crate::faces::SharedSession)); a router is the forwarder of the runtime
//! ([`RouterForwarder`]) run by its face loop ([`peer_loop`]), which is what the demo's
//! `--router-hat` runs. This module is that composition without the demo's operator surface, and
//! it is a child of the drive module for the parts it shares with it (the bind of the listeners,
//! the scouting responder, the parameters of the handshake), which are private there.
//!
//! What it carries is the node itself: it binds, answers scouts, accepts and forwards. What a
//! program does *through* it (declaring, publishing, asking) is not here yet, and the shell that
//! holds a [`RouterState`] answers each of those by name (see `docs/zenoh-api-on-the-engine.md`,
//! the router session). A configuration that asks for what this node does not carry is refused
//! at the open, by what it asked for, and not opened as a node without it.

use wz_runtime_tokio::accept_loop::{peer_loop, FaceSources};
use wz_runtime_tokio::linkstate_forward::Zid;
use wz_runtime_tokio::router_forward::RouterForwarder;
use wz_runtime_tokio::session_open::DialConfig;

use super::*;

/// A running router node. Dropping it does not stop it; [`RouterState::close`] does, and joins the
/// thread the node runs on.
pub struct RouterState {
    zid: Vec<u8>,
    listen_locators: Vec<String>,
    shutdown: Arc<Notify>,
    stop: Arc<AtomicBool>,
    driver: StdMutex<Option<JoinHandle<()>>>,
}

impl RouterState {
    /// The identity the node announces, as its wire form.
    pub fn zid(&self) -> &[u8] {
        &self.zid
    }

    /// Where the node listens, as the listeners got their addresses.
    pub fn listen_locators(&self) -> &[String] {
        &self.listen_locators
    }

    /// Whether [`RouterState::close`] has run.
    pub fn is_closed(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Stop the node and wait for its thread. Closing a closed node is no error.
    pub fn close(&self) {
        self.stop.store(true, Ordering::Release);
        self.shutdown.notify_one();
        let handle = self
            .driver
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

/// What a router node is not opened with, by what the configuration asked for: each is a
/// capability the node does not carry yet, and a node opened without it would be the silent
/// fallback the refusals of the open exist against.
pub(crate) fn refused_ask(connect: &[String], stance: &OpenStance) -> Option<&'static str> {
    if !connect.is_empty() {
        return Some("connect endpoints");
    }
    if stance.auth.is_some() {
        return Some("an authentication");
    }
    if stance.namespace.is_some() {
        return Some("a namespace");
    }
    if !stance.groups.is_empty() {
        return Some("a multicast group");
    }
    None
}

/// Open a router node on `listen`: bind the endpoints, answer the scouts that name it and serve
/// the sessions that arrive, on a thread of its own, and return once the listeners are bound.
///
/// `stance` is the rest of the open, as [`open_blocking`] takes it. A node that is asked for what
/// it does not carry (see [`refused_ask`]) is not opened.
pub(crate) fn open_router_blocking(
    connect: Vec<String>,
    listen: Vec<String>,
    tls: CapiTlsConfig,
    stance: OpenStance,
) -> Result<RouterState, OpenError> {
    if let Some(ask) = refused_ask(&connect, &stance) {
        log_open_failure(
            "router node",
            &format_args!("the node does not carry {ask} yet"),
        );
        return Err(OpenError::DriveFailed);
    }
    let OpenStance {
        tx_queue,
        batch_size,
        lease_ms,
        keep_alive,
        sn_resolution,
        link_rx,
        accept,
        offer,
        zid,
        timestamping,
        #[cfg(feature = "scout")]
        scouting,
        listen_phase,
        policy,
        ..
    } = stance;
    let link_conf = LinkConf {
        tx: LinkTx {
            queue: tx_queue,
            batch_size,
            lease_ms,
            keep_alive,
            sn_resolution,
        },
        rx: link_rx,
        accept,
    };
    let (_, wire_zid) = session_zids(zid).ok_or(OpenError::DriveFailed)?;
    let shutdown = Arc::new(Notify::new());
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Result<Vec<String>, OpenError>>();
    let node_zid = wire_zid.clone();
    let node_shutdown = shutdown.clone();
    let node_stop = stop.clone();
    let handle = std::thread::Builder::new()
        .name("wz-capi-router".to_owned())
        .stack_size(DRIVE_THREAD_STACK_BYTES)
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => {
                    let _ = tx.send(Err(OpenError::DriveFailed));
                    return;
                }
            };
            rt.block_on(run_router(
                node_zid,
                listen,
                listen_phase,
                tls,
                link_conf,
                offer,
                timestamping,
                policy,
                #[cfg(feature = "scout")]
                scouting,
                node_shutdown,
                node_stop,
                tx,
            ));
        })
        .map_err(|_| OpenError::DriveFailed)?;
    match rx.recv() {
        Ok(Ok(listen_locators)) => Ok(RouterState {
            zid: wire_zid,
            listen_locators,
            shutdown,
            stop,
            driver: StdMutex::new(Some(handle)),
        }),
        Ok(Err(cause)) => {
            let _ = handle.join();
            Err(cause)
        }
        Err(_) => {
            let _ = handle.join();
            Err(OpenError::DriveFailed)
        }
    }
}

/// The node's own task: bind, answer scouts, serve faces until told to stop.
#[allow(clippy::too_many_arguments)]
async fn run_router(
    zid: Vec<u8>,
    listen: Vec<String>,
    listen_phase: ListenPhase,
    tls: CapiTlsConfig,
    link_conf: LinkConf,
    offer: SessionOffer,
    timestamping: TimestampingEnabled,
    policy: crate::node_policy::NodePolicy,
    #[cfg(feature = "scout")] scouting: Option<ScoutingPlan>,
    shutdown: Arc<Notify>,
    stop: Arc<AtomicBool>,
    tx: mpsc::Sender<Result<Vec<String>, OpenError>>,
) {
    let clock = TokioTime::new();
    let BoundListeners { legs, late } =
        match bind_listeners(&listen, listen_phase, &tls, &zid, link_conf, offer, clock).await {
            Ok(bound) => bound,
            Err(cause) => {
                let _ = tx.send(Err(cause));
                return;
            }
        };
    // A listener that binds later (`listen/exit_on_failure` false) would be served by the other
    // roles from the moment it binds. This node serves the ones bound at the open, and a node
    // that was told to wait for another is not opened as one that does not.
    if !late.pending.is_empty() {
        log_open_failure(
            "router node",
            &"a listener that binds after the open is not carried yet",
        );
        let _ = tx.send(Err(OpenError::DriveFailed));
        return;
    }
    let listeners: Vec<&BoundListener> = legs.iter().map(|leg| &leg.listening.listener).collect();
    let advertised = Advertised::of_all(&listeners);
    let locators = advertised.remote.clone();
    #[cfg(feature = "scout")]
    let responder = match bound_responder(
        scouting.as_ref(),
        WhatAmI::Router,
        &zid,
        &listeners,
        late.locators(),
    )
    .await
    {
        Ok(responder) => responder,
        Err(()) => {
            let _ = tx.send(Err(OpenError::DriveFailed));
            return;
        }
    };
    // Findable from the moment the listeners are bound, as a router answers (upstream starts the
    // responder after its bind, before it connects to anything).
    #[cfg(feature = "scout")]
    let _findable = responder.map(Responder::start);
    let params = match init_params(WhatAmI::Router, zid.clone(), link_conf) {
        Ok(params) => params,
        Err(error) => {
            log_open_failure("session parameters of the router node", &error);
            let _ = tx.send(Err(OpenError::DriveFailed));
            return;
        }
    };
    let forwarder = RouterForwarder::with_timestamping(Zid::from_slice(&zid), timestamping);
    policy.install_on(&forwarder);
    let sources = FaceSources {
        listeners: legs.into_iter().map(|leg| leg.listening.listener).collect(),
        dial_targets: Vec::new(),
        dial_config: Arc::new(DialConfig::default()),
        dial_intents: None,
        mcast_ingress: None,
        mcast_members: None,
        mcast_group_subs: None,
        reconcile: None,
        #[cfg(feature = "transport-multilink")]
        max_links: 1,
        max_sessions: wz_runtime_tokio::config::DEFAULT_MAX_SESSIONS,
        accept: link_conf.accept,
        ceiling: None,
        peer_board: None,
        offer,
        retry: RetryPolicy::ZENOH_DEFAULT,
        stats: None,
    };
    // The open is over once the node is ready to be dialled: the listeners are bound and
    // answering.
    let _ = tx.send(Ok(locators));
    let until_stopped = async move {
        if !stop.load(Ordering::Acquire) {
            shutdown.notified().await;
        }
    };
    let _summary = peer_loop(
        sources,
        params,
        clock,
        DEFAULT_OPEN_TICK_MS,
        until_stopped,
        |_event| {},
        &forwarder,
    )
    .await;
}

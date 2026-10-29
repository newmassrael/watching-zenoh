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
use wz_runtime_tokio::session::QueryOptions;
use wz_runtime_tokio::session_open::DialConfig;

use super::*;

mod local_face;
pub use local_face::{FinalHandler, LivelinessHandler, LocalLiveliness, ReplyHandler};

/// A running router node. Dropping it does not stop it; [`RouterState::close`] does, and joins the
/// thread the node runs on.
pub struct RouterState {
    zid: Vec<u8>,
    forwarder: Arc<RouterForwarder>,
    listen_locators: Vec<String>,
    /// The node's own face, for liveliness: what the program is told of the tokens of the other
    /// faces, and where its own tokens are counted.
    liveliness: LocalLiveliness,
    /// The request ids the node's own face gives its queries, so that the replies the router
    /// tells the face find the query they answer.
    next_request: AtomicU64,
    shutdown: Arc<Notify>,
    stop: Arc<AtomicBool>,
    driver: StdMutex<Option<JoinHandle<()>>>,
}

impl RouterState {
    /// The identity the node announces, as its wire form.
    pub fn zid(&self) -> &[u8] {
        &self.zid
    }

    /// The router data plane the node runs: its entry points take `&self`, so the program that
    /// holds the node declares and publishes through it while the node's thread serves the faces.
    pub fn forwarder(&self) -> &RouterForwarder {
        &self.forwarder
    }

    /// Declare a liveliness token of the node on `keyexpr`: the nodes that asked are told, and so
    /// are the subscribers of the node itself. The id answered retracts it
    /// ([`undeclare_token`](Self::undeclare_token)).
    pub fn declare_token(&self, keyexpr: &str) -> u64 {
        let id = self.forwarder.host_token(keyexpr);
        self.liveliness.own_up(id, keyexpr);
        id
    }

    /// Retract the token `id` the node declared. Retracting one that is gone does nothing.
    pub fn undeclare_token(&self, id: u64) {
        if self.forwarder.unhost_token(id) {
            self.liveliness.own_down(id);
        }
    }

    /// What the queries of a queryable the node hosts are kept through: a handler asks it to keep
    /// the query it is handed and answers it after it has returned. It holds the node weakly, as
    /// the node holds the handler.
    pub fn query_holder(&self) -> Arc<dyn wz_capi_port::QueryHolder> {
        Arc::new(RouterQueryHolder {
            forwarder: Arc::downgrade(&self.forwarder),
            closed: self.stop.clone(),
        })
    }

    /// The node's own face, for liveliness: subscribers, and the keys alive.
    pub fn liveliness(&self) -> &LocalLiveliness {
        &self.liveliness
    }

    /// Ask a query as the node's own face. The router routes it to the queryables of every face
    /// that holds one on `keyexpr`, and each reply is handed to `on_reply` on the face's thread,
    /// then `on_final` is called once, whether the queryables ended, the query timed out or none
    /// was asked. `options` carry what the query asks (its parameters, target, timeout, value and
    /// attachment), as for a get over a link.
    pub fn get(
        &self,
        keyexpr: &str,
        options: &QueryOptions,
        on_reply: ReplyHandler,
        on_final: FinalHandler,
    ) -> Result<(), String> {
        use wz_session_core::request_build::{build_request_query, build_request_query_with_meta};

        let rid = self.next_request.fetch_add(1, Ordering::Relaxed);
        let meta = options.query_metadata();
        let request = if meta.is_empty() {
            build_request_query(rid, 0, Some(keyexpr))
        } else {
            build_request_query_with_meta(rid, 0, Some(keyexpr), &meta)
        }
        .map_err(|error| format!("the query could not be built: {error:?}"))?;
        // Held before the router is asked: the face's thread reads its commands in the order they
        // were sent, and the router tells the face its replies through the same queue.
        self.liveliness.hold_query(
            rid,
            keyexpr,
            options.effective_accept_replies(),
            on_reply,
            on_final,
        );
        self.forwarder.local_get(&request);
        Ok(())
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
        self.liveliness.stop();
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

/// The queries of the queryables a router node hosts, kept through the node's forwarder.
struct RouterQueryHolder {
    forwarder: std::sync::Weak<RouterForwarder>,
    closed: Arc<AtomicBool>,
}

impl wz_capi_port::QueryHolder for RouterQueryHolder {
    fn hold_query(
        &self,
        _view: &dyn wz_session_core::query_sink::QueryView,
    ) -> Box<dyn wz_capi_port::HeldQuery> {
        // The query is the one the handler this thread is inside of was handed; outside one, or
        // for a node that has gone, there is nothing to keep and the query is answered with nothing.
        let held = self
            .forwarder
            .upgrade()
            .and_then(|forwarder| forwarder.hold_current_query());
        Box::new(RouterHeld(held))
    }

    fn session_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// A query kept through the forwarder of a router node.
struct RouterHeld(Option<wz_runtime_tokio::router_forward::HeldRouterQuery>);

impl wz_capi_port::HeldQuery for RouterHeld {
    fn reply(&self, answer: &mut dyn FnMut(&mut dyn wz_session_core::query_sink::ReplyOut)) {
        if let Some(held) = &self.0 {
            held.reply(answer);
        }
    }
}

/// What a router node is not opened with, by what the configuration asked for: each is a
/// capability the node does not carry yet, and a node opened without it would be the silent
/// fallback the refusals of the open exist against.
pub(crate) fn refused_ask(stance: &OpenStance) -> Option<&'static str> {
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
    dial: DialPhase,
    stance: OpenStance,
) -> Result<RouterState, OpenError> {
    if let Some(ask) = refused_ask(&stance) {
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
    // Built here and shared, so that the program holding the node can reach the forwarder's
    // entry points (they take `&self`) while the node's thread runs the face loop over it.
    let forwarder = Arc::new(RouterForwarder::with_timestamping(
        Zid::from_slice(&wire_zid),
        timestamping,
    ));
    policy.install_on(&*forwarder);
    // The node's own face, told of the tokens of the others from the first.
    let (liveliness, face_sink) = LocalLiveliness::start().map_err(|error| {
        log_open_failure("the face of the router node", &error);
        OpenError::DriveFailed
    })?;
    forwarder.attach_local_face(face_sink);
    forwarder.ask_local_tokens();
    let shutdown = Arc::new(Notify::new());
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Result<Vec<String>, OpenError>>();
    let node_zid = wire_zid.clone();
    let node_forwarder = forwarder.clone();
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
                connect,
                dial,
                listen,
                listen_phase,
                tls,
                link_conf,
                offer,
                node_forwarder,
                #[cfg(feature = "scout")]
                scouting,
                node_shutdown,
                node_stop,
                tx,
            ));
        })
        .map_err(|_| OpenError::DriveFailed)?;
    // A router's open is held for `scouting/delay` in full, as the other roles' is (R3125): the
    // nodes it dials have told it what they hold by the time the program can declare anything,
    // so that a subscriber declared right after the open is told of what comes alive after it
    // and not of what was already there.
    let hold = dial.router_hold;
    match rx.recv() {
        Ok(Ok(listen_locators)) => {
            std::thread::sleep(hold);
            Ok(RouterState {
                zid: wire_zid,
                forwarder,
                listen_locators,
                liveliness,
                next_request: AtomicU64::new(1),
                shutdown,
                stop,
                driver: StdMutex::new(Some(handle)),
            })
        }
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
    connect: Vec<String>,
    dial: DialPhase,
    listen: Vec<String>,
    listen_phase: ListenPhase,
    tls: CapiTlsConfig,
    link_conf: LinkConf,
    offer: SessionOffer,
    forwarder: Arc<RouterForwarder>,
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
    // The nodes this router dials (router to router federation), resolved here so the loop never
    // waits on a resolver. A target that is not an address of a node is a refusal of the open by
    // what it was, not a dial that is silently skipped.
    let mut dial_targets = Vec::with_capacity(connect.len());
    for endpoint in &connect {
        match wz_runtime_tokio::session_open::resolve_mesh_dial_target(endpoint).await {
            Ok(target) => dial_targets.push(target),
            Err(error) => {
                log_open_failure(&format!("connect endpoint {endpoint}"), &error);
                let _ = tx.send(Err(OpenError::of_endpoint(
                    endpoint,
                    &std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a dial target"),
                )));
                return;
            }
        }
    }
    let dial_config = match connect.first().map(|endpoint| dial_config(&tls, endpoint)) {
        None => DialConfig::default(),
        Some(Ok(config)) => config,
        Some(Err(error)) => {
            log_open_failure("dial configuration of the router node", &error);
            let _ = tx.send(Err(OpenError::DriveFailed));
            return;
        }
    };
    let params = match init_params(WhatAmI::Router, zid.clone(), link_conf) {
        Ok(params) => params,
        Err(error) => {
            log_open_failure("session parameters of the router node", &error);
            let _ = tx.send(Err(OpenError::DriveFailed));
            return;
        }
    };
    let sources = FaceSources {
        listeners: legs.into_iter().map(|leg| leg.listening.listener).collect(),
        dial_targets,
        dial_config: Arc::new(dial_config),
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
        retry: dial.schedule,
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
        &*forwarder,
    )
    .await;
}

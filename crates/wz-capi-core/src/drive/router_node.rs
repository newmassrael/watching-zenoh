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
pub use local_face::{
    FinalHandler, LivelinessHandler, LocalLiveliness, MatchHandler, ReplyHandler,
};
use wz_runtime_tokio::router_forward::MatchPlane;
use wz_session_core::locality::Locality;

/// What a forwarding node announces itself as, and which hats it builds: the pin builds a peer hat
/// in the north and a broker hat for the clients south of it for a peer, and a router hat in the
/// north with a peer hat and a broker hat south of it for a router
/// (`zenoh/src/net/routing/gateway.rs` @ `GatewaySouthConf::Preset(GatewayPresetConf::Auto) => match mode {`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeRole {
    /// A router.
    Router,
    /// A peer that forwards between the sessions it accepts and dials.
    Peer,
}

impl NodeRole {
    /// The role as the handshake and the scouting answer name it.
    pub(crate) fn whatami(self) -> WhatAmI {
        match self {
            Self::Router => WhatAmI::Router,
            Self::Peer => WhatAmI::Peer,
        }
    }
}

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

    /// Whether anything of `plane` matches `key` among the declarations `origin` admits: the
    /// session's own (the hosted ones) and the remote ones (every other face's).
    pub fn matching_status(&self, plane: MatchPlane, key: &str, origin: Locality) -> bool {
        self.forwarder.matching(plane, key, origin)
    }

    /// Be told whether anything of `plane` matches `key` among the declarations `origin` admits:
    /// `handler` is called with `true` at once if it does, and with the verdict each time it
    /// moves, on the face's thread and outside every lock. The id answered ends the watch
    /// ([`Self::unwatch_matching`]).
    pub fn watch_matching(
        &self,
        plane: MatchPlane,
        key: &str,
        origin: Locality,
        handler: MatchHandler,
    ) -> u64 {
        // Counted before the face first looks, so that no write is missed between its look and
        // the first one it is told of.
        self.forwarder.watch_matching();
        self.liveliness.watch(plane, key, origin, handler)
    }

    /// End the watch `id`.
    pub fn unwatch_matching(&self, id: u64) {
        self.liveliness.unwatch(id);
        self.forwarder.unwatch_matching();
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
            options.effective_timeout_ms(),
            on_reply,
            on_final,
        );
        self.forwarder.local_get(&request);
        Ok(())
    }

    /// Publish a chunk of shared memory as the node's own session: see
    /// [`RouterForwarder::publish_shm_with`].
    #[cfg(feature = "transport-shm")]
    pub fn publish_shm(
        &self,
        keyexpr: &str,
        payload: wz_session_core::extshm::ShmSendHandle,
        options: &wz_session_core::publish_options::PublishOptions,
    ) -> Result<(), String> {
        self.forwarder
            .publish_shm_with(keyexpr, payload, options)
            .map_err(|error| format!("{error:?}"))
    }

    /// Whether some face of the node negotiated shared memory: see
    /// [`RouterForwarder::has_shm_peer`].
    #[cfg(feature = "transport-shm")]
    pub fn has_shm_peer(&self) -> bool {
        self.forwarder.has_shm_peer()
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
    // A namespace is the node's own session's: its face carries it (see
    // `RouterForwarder::with_local_namespace`). A build without the decorator never gets one: the
    // plan refuses the document that states it.
    // The node joins one group: its forwarder holds one multicast face to forward into, as the
    // router host of the demo does.
    if stance.groups.len() > 1 {
        return Some("more than one multicast group");
    }
    None
}

/// The group a router node joined: the locator it reports for it and the face that serves it.
struct JoinedGroup {
    /// `udp/<group>:<port>` with the socket keys of the endpoint, the port being the one the
    /// group is on, which an endpoint that named port 0 did not state.
    locator: String,
    face: wz_runtime_tokio::multicast_glue::RouterMcastGroup,
}

/// Join the group `join` names, as a router joins its group locator: either family, with the
/// socket keys of its metadata, on one socket the node's forwarder sends into and reads the
/// members from. The port is settled before the face binds (a group named with port 0 is given
/// one by the system), so that the locator the node reports is the group every join of the face
/// is on.
async fn join_group(
    join: &GroupJoin,
    zid: &[u8],
    link_conf: LinkConf,
) -> Result<JoinedGroup, OpenError> {
    let Some(ResolvedGroup {
        link: GroupLinkSpec::Udp { group, port, opts },
        ..
    }) = ResolvedGroup::resolve(join, zid, WhatAmI::Router, link_conf.tx.queue, link_conf.rx)
    else {
        log_open_failure(
            &format!("group {}", join.endpoint),
            &"a router node joins a udp multicast group",
        );
        return Err(OpenError::DriveFailed);
    };
    let port =
        wz_runtime_tokio::UdpDriver::multicast_link_port(group, port, opts.as_socket_config())
            .await
            .map_err(|error| {
                log_open_failure(&format!("group {}", join.endpoint), &error);
                OpenError::DriveFailed
            })?;
    let tail = join
        .endpoint
        .find('#')
        .map_or("", |at| &join.endpoint[at..]);
    let locator = format!("udp/{}{tail}", std::net::SocketAddr::new(group, port));
    let face = wz_runtime_tokio::multicast_glue::spawn_router_mcast_group(
        group,
        port,
        wz_runtime_tokio::multicast_glue::RouterGroupProfile {
            zid: zid.to_vec(),
            qos: join.profile.is_qos,
            tx_queue: link_conf.tx.queue,
            link_rx: link_conf.rx,
        },
        opts,
        None,
    );
    Ok(JoinedGroup { locator, face })
}

/// Open a router node on `listen`: bind the endpoints, answer the scouts that name it and serve
/// the sessions that arrive, on a thread of its own, and return once the listeners are bound.
///
/// `stance` is the rest of the open, as [`open_blocking`] takes it. A node that is asked for what
/// it does not carry (see [`refused_ask`]) is not opened.
pub(crate) fn open_router_blocking(
    role: NodeRole,
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
        auth,
        gossip,
        #[cfg(feature = "transport-shm")]
        shm_clients,
        #[cfg(feature = "routing-namespace")]
        namespace,
        gateway_south,
        groups,
        ..
    } = stance;
    // The prefix as the forwarder takes it. The plan validated the text, so one that does not
    // convert came from a caller that built its stance by hand, and the open fails with it.
    #[cfg(feature = "routing-namespace")]
    let namespace = match namespace
        .as_deref()
        .map(wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr::new)
    {
        None => None,
        Some(Ok(prefix)) => Some(prefix),
        Some(Err(error)) => {
            log_open_failure("namespace", &error);
            return Err(OpenError::DriveFailed);
        }
    };
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
    let own_zid = Zid::from_slice(&wire_zid);
    let forwarder = match role {
        NodeRole::Router => RouterForwarder::with_timestamping(own_zid, timestamping),
        NodeRole::Peer => RouterForwarder::peer_with_timestamping(own_zid, timestamping),
    };
    #[cfg(feature = "routing-namespace")]
    let forwarder = match namespace {
        Some(prefix) => forwarder.with_local_namespace(prefix),
        None => forwarder,
    };
    // How the node keeps its south apart: a remote is placed in the first subregion whose
    // filters match it (its role, its zid, its interfaces, the region name it announced), and a
    // remote in a subregion hears of its own region alone. Before any face registers.
    let forwarder = forwarder.with_south_partition(gateway_south);
    // Whether the graphs the router floods carry the nodes past the next hop
    // (`scouting/gossip/multihop`), so that a peer hears of the peers two links away.
    #[cfg(feature = "gossip")]
    if let Some(gossip) = gossip {
        forwarder.set_gossip_multihop(gossip.multihop);
    }
    let forwarder = Arc::new(forwarder);
    policy.install_on(&*forwarder);
    // The program's own reader of shared memory, for the subscribers of the node's session: a
    // descriptor is read into the buffer the program works with.
    #[cfg(feature = "transport-shm")]
    if let Some(crate::faces::ShmReader::Host(make)) = &shm_clients {
        forwarder.set_host_shm_resolver(Arc::from(make()));
    }
    // A peer dials the nodes its neighbours tell it of, as the policy of its gossip admits
    // (upstream's autoconnect): the forwarder emits an intent for each node it learns of from
    // the topology it is flooded, and the face loop dials it. Without it, a peer reaches only
    // the nodes it was told to connect to, and a node that is not directly linked to another
    // one reaches it only through the node between them.
    let dial_intents = match (role, gossip) {
        (NodeRole::Peer, Some(policy)) => Some(forwarder.enable_autoconnect(
            wz_runtime_tokio::linkstate_forward::AutoConnect::with_strategies(
                own_zid,
                policy.autoconnect,
                policy.strategies,
            ),
        )),
        _ => None,
    };
    // The authentication the config states, asked of the sessions the node accepts and offered to
    // the ones it dials, installed before the node is served (the accept loop reads it once).
    #[cfg(any(feature = "access-extauth-usrpwd", feature = "access-extauth-pubkey"))]
    if let Some(auth) = &auth {
        forwarder.set_session_auth(auth.session_auth());
    }
    #[cfg(not(any(feature = "access-extauth-usrpwd", feature = "access-extauth-pubkey")))]
    let _ = auth;
    // The node's own face, told of the tokens of the others from the first.
    let (liveliness, face_sink) =
        LocalLiveliness::start(Arc::downgrade(&forwarder)).map_err(|error| {
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
    // How many nodes the open waits for: each endpoint it connects to is a node that must have
    // connected and told it what it holds (upstream's `start_conditions` counts one connector
    // for each).
    let dials = connect.len();
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
                role,
                node_zid,
                connect,
                dial,
                listen,
                listen_phase,
                tls,
                link_conf,
                offer,
                node_forwarder,
                groups,
                dial_intents,
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
    //
    // A peer's open is not held for the delay but for the endpoints it connects to, up to the
    // window the configuration gives it: it returns once one is connected (upstream's start
    // conditions), and at once when it connects to none.
    let hold = dial.router_hold;
    let window = dial.start_window.unwrap_or_default();
    match rx.recv() {
        Ok(Ok(listen_locators)) => {
            match role {
                NodeRole::Router => std::thread::sleep(hold),
                // The start condition of a peer is met when the node it dialled is connected and
                // has told it what it holds: upstream releases the open when the gossip of a
                // remote that is not a peer arrives, which a router sends after the declarations
                // it replays on the new link (`zenoh/src/net/protocol/gossip.rs` @
                // `terminate_peer_connector_zid(src)`). A subscriber declared right after the open
                // is then told of what comes alive after it and not of what was already there.
                NodeRole::Peer if dials > 0 => {
                    let deadline = std::time::Instant::now() + window;
                    while (forwarder.face_snapshots().len() < dials || forwarder.ingested() < dials)
                        && std::time::Instant::now() < deadline
                    {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                }
                NodeRole::Peer => {}
            }
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
    role: NodeRole,
    zid: Vec<u8>,
    connect: Vec<String>,
    dial: DialPhase,
    listen: Vec<String>,
    listen_phase: ListenPhase,
    tls: CapiTlsConfig,
    link_conf: LinkConf,
    offer: SessionOffer,
    forwarder: Arc<RouterForwarder>,
    groups: Vec<GroupJoin>,
    dial_intents: Option<wz_runtime_tokio::accept_loop::DialIntentReceiver>,
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
    let mut locators = advertised.remote.clone();
    // What a neighbour is told to dial this node by, in its link-state, before the first face
    // registers so that the first flood already carries it. The unicast locators only: a group
    // is not an address a neighbour dials.
    forwarder.set_self_locators(locators.clone());
    // The group the node joins, bound before the open answers, as a listener is: a group that
    // cannot be joined fails the open. Its locator is among the node's own, as the manager of
    // upstream lists its multicast listener beside the unicast ones.
    let group = match groups.first() {
        Some(join) => match join_group(join, &zid, link_conf).await {
            Ok(group) => Some(group),
            Err(cause) => {
                let _ = tx.send(Err(cause));
                return;
            }
        },
        None => None,
    };
    if let Some(group) = &group {
        locators.push(group.locator.clone());
    }
    #[cfg(feature = "scout")]
    let responder = match bound_responder(
        scouting.as_ref(),
        role.whatami(),
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
    let params = match init_params(role.whatami(), zid.clone(), link_conf) {
        Ok(params) => params,
        Err(error) => {
            log_open_failure("session parameters of the router node", &error);
            let _ = tx.send(Err(OpenError::DriveFailed));
            return;
        }
    };
    // What the group's members send the router rides the face loop; what the router forwards
    // into the group goes out through the forwarder, which holds the group's producer.
    let (mcast_ingress, mcast_members, mcast_group_subs, group_stop) = match group {
        Some(JoinedGroup { face, .. }) => {
            forwarder.attach_mcast_group(face.outbound);
            (
                Some(face.ingress),
                Some(face.members),
                Some(face.group_subs),
                Some(face.stop),
            )
        }
        None => (None, None, None, None),
    };
    let sources = FaceSources {
        listeners: legs.into_iter().map(|leg| leg.listening.listener).collect(),
        dial_targets,
        dial_config: Arc::new(dial_config),
        dial_intents,
        mcast_ingress,
        mcast_members,
        mcast_group_subs,
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
    // The node leaves its group as it ends, which announces the departure to the members, where
    // a face dropped with the node would leave it silently and they would hold the router until
    // its lease ran out.
    if let Some(group_stop) = group_stop {
        let _ = group_stop.stop().await;
    }
}

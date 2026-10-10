// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 900 — run every session of a `--sessions` document in this
//! one process.
//!
//! Each session is its own task on one local set: its own link, its own state
//! machine, its own application observer. They share the process's runtime and
//! its process-wide pools, as `wz_client_and_multicast_peer_sessions_in_one_process_zenohd`
//! measured they may. Nothing is routed BETWEEN them: a sample one session
//! receives is that session's, as two upstream sessions in one program do not
//! forward to each other.
//!
//! # What a session prints
//!
//! Every line starts `wz-ap-demo session <name>:` and goes to stderr whatever
//! `RUST_LOG` says, because these are the lines a harness waits on:
//!
//! * `READY <mode> <transport> ...` once the session serves: a dialling session
//!   when it is Established, a listening one when it is bound, a group one when
//!   it has joined;
//! * `peer arrived <zid>` / `peer lost <zid> (<why>)` for a group's members, and
//!   `accepted <zid>` / `accepted <zid> ended` for a listener's sessions;
//! * `link lost (<why>); re-joining in <ms>ms`, `re-join failed (<why>);
//!   retrying in <ms>ms` and `rejoined <endpoint>` while a group session rides
//!   out a lost link: a group session re-joins rather than ending;
//! * `ended (<why>)` when the session stops on its own (its peer went away), or
//!   `failed: <why>` when it never served;
//! * `closed` when the process was told to stop and this session closed.
//!
//! A session that ends does not end the others. The process exits when every
//! session has ended, or when it is signalled (SIGINT / SIGTERM), after every
//! session has closed: status 0, or 1 when any session failed.

use std::io;
use std::sync::Arc;

use tokio::sync::{watch, Semaphore};
use tokio::task::LocalSet;

use wz::runtime_tokio::observer::ApplicationLayerObserver;
use wz::runtime_tokio::runtime_impl::TokioTime;
use wz::runtime_tokio::session::TokioSession;
use wz::runtime_tokio::session_glue::{
    drive_session_until_terminal, CloseReason, DriverOutcome, SessionTimeouts, WhatAmI,
};
use wz::runtime_tokio::session_open::{
    accept_and_open_session, accept_bound_on, bind_endpoint, dial_endpoint,
    initiate_and_open_session, DialConfig, DialedLink, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz::runtime_tokio::sync::Mutex;
use wz::runtime_tokio::zid_hex::{zenoh_hex_to_zid, zid_to_zenoh_hex};

use crate::args::{resolve_node_zid, session_init_params_for, TransportTuning};
use crate::sessions::{Mode, SessionLink, SessionSpec, SessionsPlan};
use crate::shutdown::shutdown_signal;

/// How a session task finished.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SessionEnd {
    /// Told to stop, and closed.
    Closed,
    /// Stopped on its own after serving.
    Ended,
    /// Never served.
    Failed,
}

/// Run every session of `plan` until each has ended, or until the process is
/// signalled and each has closed. `Ok(true)` when no session failed.
pub(crate) async fn run_sessions(plan: SessionsPlan) -> io::Result<bool> {
    let (stop_tx, stop_rx) = watch::channel(false);
    let local = LocalSet::new();
    let ends = local
        .run_until(async move {
            let mut tasks = Vec::new();
            for spec in plan.sessions {
                let zid = session_zid(&spec)?;
                eprintln!(
                    "wz-ap-demo session {}: starting {} {} zid {}",
                    spec.name,
                    spec.mode.as_str(),
                    spec.link.transport(),
                    zid_to_zenoh_hex(&zid)
                );
                tasks.push(tokio::task::spawn_local(run_session(
                    spec,
                    zid,
                    stop_rx.clone(),
                )));
            }
            drop(stop_rx);
            let all = async {
                let mut ends = Vec::new();
                for task in tasks.iter_mut() {
                    ends.push(task.await.unwrap_or(SessionEnd::Failed));
                }
                ends
            };
            tokio::pin!(all);
            let ends = tokio::select! {
                ends = &mut all => ends,
                () = shutdown_signal() => {
                    let _ = stop_tx.send(true);
                    all.await
                }
            };
            Ok::<_, io::Error>(ends)
        })
        .await?;
    eprintln!("wz-ap-demo sessions: all {} session(s) ended", ends.len());
    Ok(!ends.contains(&SessionEnd::Failed))
}

/// The session's identity: its own zid, else the document's, else a random
/// one drawn as upstream draws one when the config names no `id`.
fn session_zid(spec: &SessionSpec) -> io::Result<Vec<u8>> {
    let written = match &spec.zid {
        // The rules admitted the spelling, so this is upstream's own reading
        // of it; a refusal here would be the two disagreeing.
        Some(hex) => Some(zenoh_hex_to_zid(hex).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("session {}: zid {hex:?} did not decode", spec.name),
            )
        })?),
        None => None,
    };
    resolve_node_zid(written)
}

fn whatami(mode: Mode) -> WhatAmI {
    match mode {
        Mode::Client => WhatAmI::Client,
        Mode::Peer => WhatAmI::Peer,
    }
}

/// Resolves once the process has been told to stop (or the sender is gone).
async fn stopped(stop: &mut watch::Receiver<bool>) {
    while !*stop.borrow_and_update() {
        if stop.changed().await.is_err() {
            return;
        }
    }
}

async fn run_session(spec: SessionSpec, zid: Vec<u8>, stop: watch::Receiver<bool>) -> SessionEnd {
    let name = spec.name.clone();
    let end = match spec.link {
        SessionLink::Connect { endpoints } => {
            run_connect(&name, whatami(spec.mode), zid, &endpoints, stop).await
        }
        SessionLink::Listen {
            endpoint,
            max_sessions,
        } => {
            run_listen(
                &name,
                whatami(spec.mode),
                zid,
                &endpoint,
                max_sessions,
                stop,
            )
            .await
        }
        SessionLink::Group {
            endpoint,
            join_interval_ms,
            lease_ms,
        } => run_group(&name, zid, &endpoint, join_interval_ms, lease_ms, stop).await,
    };
    if end == SessionEnd::Closed {
        eprintln!("wz-ap-demo session {name}: closed");
    }
    end
}

/// The session bundle of one unicast open. Built per attempt: it carries a
/// freshly drawn cookie key, which is not a value to reuse across links.
fn unicast_params(
    name: &str,
    whatami: WhatAmI,
    zid: &[u8],
) -> Result<wz::runtime_tokio::session_glue::SessionInitParams, SessionEnd> {
    session_init_params_for(whatami, zid.to_vec(), &TransportTuning::default()).map_err(|e| {
        eprintln!("wz-ap-demo session {name}: failed: {e}");
        SessionEnd::Failed
    })
}

/// A dialling session: try each endpoint in order, hold the first that opens.
async fn run_connect(
    name: &str,
    whatami: WhatAmI,
    zid: Vec<u8>,
    endpoints: &[String],
    mut stop: watch::Receiver<bool>,
) -> SessionEnd {
    let mut why = Vec::new();
    for endpoint in endpoints {
        let params = match unicast_params(name, whatami, &zid) {
            Ok(p) => p,
            Err(end) => return end,
        };
        let open = async {
            let link = dial_endpoint(endpoint, &DialConfig::default())
                .await
                .map_err(|e| e.to_string())?;
            initiate_and_open_session(link, params, TokioTime::new(), None, DEFAULT_OPEN_TICK_MS)
                .await
                .map_err(|e| format!("{e:?}"))
        };
        let opened = tokio::select! {
            opened = open => opened,
            () = stopped(&mut stop) => return SessionEnd::Closed,
        };
        match opened {
            Ok(opened) => {
                eprintln!(
                    "wz-ap-demo session {name}: READY {} unicast connected to {endpoint} \
                     peer {}",
                    whatami_name(whatami),
                    opened
                        .peer_zid()
                        .map(|z| zid_to_zenoh_hex(&z))
                        .unwrap_or_else(|| "unknown".to_string())
                );
                return match serve_unicast(opened, stop).await {
                    None => SessionEnd::Closed,
                    Some(outcome) => {
                        eprintln!("wz-ap-demo session {name}: ended ({outcome:?})");
                        SessionEnd::Ended
                    }
                };
            }
            Err(e) => why.push(format!("{endpoint}: {e}")),
        }
    }
    eprintln!(
        "wz-ap-demo session {name}: failed: no endpoint opened ({})",
        why.join("; ")
    );
    SessionEnd::Failed
}

fn whatami_name(whatami: WhatAmI) -> &'static str {
    match whatami {
        WhatAmI::Client => "client",
        WhatAmI::Router => "router",
        _ => "peer",
    }
}

/// Drive one Established unicast session until its peer ends it (`Some`, why)
/// or the process stops (`None`); on a stop, close it on the wire first.
async fn serve_unicast(
    mut opened: OpenedSession,
    mut stop: watch::Receiver<bool>,
) -> Option<DriverOutcome> {
    let session = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );
    let timeouts = SessionTimeouts::spec_defaults();
    let outcome = {
        let drive = drive_session_until_terminal(
            &mut opened.inbound,
            &opened.actions,
            &mut opened.engine,
            None,
            &opened.clock,
            &timeouts,
            |event| session.dispatch_iteration_event(event),
        );
        tokio::select! {
            outcome = drive => Some(outcome),
            () = stopped(&mut stop) => None,
        }
    };
    drop(session);
    if outcome.is_none() {
        opened.actions.send_close_with_reason(CloseReason::Generic);
    }
    opened.drain_to_close().await;
    outcome
}

/// A listening session: bind one endpoint and hold up to `max_sessions`
/// accepted sessions at once.
async fn run_listen(
    name: &str,
    whatami: WhatAmI,
    zid: Vec<u8>,
    endpoint: &str,
    max_sessions: usize,
    mut stop: watch::Receiver<bool>,
) -> SessionEnd {
    let mut listener = match bind_endpoint(endpoint).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("wz-ap-demo session {name}: failed: cannot listen on {endpoint}: {e}");
            return SessionEnd::Failed;
        }
    };
    let bound = listener
        .local_addr_display()
        .unwrap_or_else(|_| endpoint.to_string());
    eprintln!(
        "wz-ap-demo session {name}: READY {} unicast listening on {bound}",
        whatami_name(whatami)
    );
    let slots = Arc::new(Semaphore::new(max_sessions));
    let mut failed = false;
    let mut accepted = Vec::new();
    loop {
        let slot = tokio::select! {
            slot = slots.clone().acquire_owned() => slot,
            () = stopped(&mut stop) => break,
        };
        let Ok(slot) = slot else { break };
        let link: io::Result<DialedLink> = tokio::select! {
            link = accept_bound_on(&mut listener) => link,
            () = stopped(&mut stop) => break,
        };
        match link {
            Ok(link) => {
                let Ok(params) = unicast_params(name, whatami, &zid) else {
                    failed = true;
                    break;
                };
                let name = name.to_string();
                let stop = stop.clone();
                accepted.push(tokio::task::spawn_local(async move {
                    let opened = match accept_and_open_session(
                        link,
                        params,
                        TokioTime::new(),
                        None,
                        DEFAULT_OPEN_TICK_MS,
                    )
                    .await
                    {
                        Ok(opened) => opened,
                        Err(e) => {
                            eprintln!(
                                "wz-ap-demo session {name}: an accepted link did not open: {e:?}"
                            );
                            drop(slot);
                            return;
                        }
                    };
                    let peer = opened
                        .peer_zid()
                        .map(|z| zid_to_zenoh_hex(&z))
                        .unwrap_or_else(|| "unknown".to_string());
                    eprintln!("wz-ap-demo session {name}: accepted {peer}");
                    match serve_unicast(opened, stop).await {
                        None => eprintln!("wz-ap-demo session {name}: accepted {peer} closed"),
                        Some(outcome) => eprintln!(
                            "wz-ap-demo session {name}: accepted {peer} ended ({outcome:?})"
                        ),
                    }
                    drop(slot);
                }));
            }
            Err(e) => {
                eprintln!("wz-ap-demo session {name}: failed: accept on {bound}: {e}");
                failed = true;
                break;
            }
        }
    }
    for task in accepted {
        let _ = task.await;
    }
    if failed {
        SessionEnd::Failed
    } else {
        SessionEnd::Closed
    }
}

/// How many group members one group session tracks at once: the runtime's own
/// group faces hold the same 32 (`MCAST_MAX_PEERS` in `multicast_glue`).
#[cfg(feature = "transport-multicast")]
const GROUP_PEER_TABLE: usize = 32;

/// A group session: join the group, then serve it for the life of the process
/// (`serve_group`), re-joining whenever the link is lost.
///
/// The FIRST join is the document's own and its failure is the session's
/// (`failed:`), as a router face reports a first bind that fails: a group that
/// never came up is a deploy error. Every later join is a re-join.
#[cfg(feature = "transport-multicast")]
async fn run_group(
    name: &str,
    zid: Vec<u8>,
    endpoint: &str,
    join_interval_ms: u64,
    lease_ms: u64,
    mut stop: watch::Receiver<bool>,
) -> SessionEnd {
    use wz::runtime_tokio::{McastSocketConfig, UdpDriver};

    let Some((group, port, iface)) = group_address(endpoint) else {
        eprintln!("wz-ap-demo session {name}: failed: {endpoint} is not a group endpoint");
        return SessionEnd::Failed;
    };
    // One bind for the first join and every re-join, so a re-join installs
    // exactly the membership the first one did.
    let bind = || {
        UdpDriver::bind_multicast(
            group,
            port,
            McastSocketConfig {
                iface: iface.as_deref(),
                ..Default::default()
            },
        )
    };
    let driver = match bind().await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("wz-ap-demo session {name}: failed: cannot join {endpoint}: {e}");
            return SessionEnd::Failed;
        }
    };
    serve_group(
        endpoint,
        &group_params(zid, join_interval_ms, lease_ms),
        bind,
        driver,
        &mut stop,
        |line| eprintln!("wz-ap-demo session {name}: {line}"),
    )
    .await
}

/// The group profile a router's face advertises (`router_group_params`), as a
/// peer: version 0x09, 2-bit resolutions, a 2048-byte batch, no per-priority
/// offer, the default queue. The two intervals are the document's.
#[cfg(feature = "transport-multicast")]
fn group_params(
    zid: Vec<u8>,
    join_interval_ms: u64,
    lease_ms: u64,
) -> wz::runtime_tokio::multicast_glue::MulticastParams {
    wz::runtime_tokio::multicast_glue::MulticastParams {
        version: crate::args::DEMO_PROTO_VERSION,
        whatami: WhatAmI::Peer,
        zid,
        lease_ms,
        join_interval_ms,
        seq_num_res: 0x02,
        req_id_res: 0x02,
        batch_size: 2_048,
        is_qos: false,
        tx_queue: Default::default(),
    }
}

/// Serve a joined group until the process stops, re-joining after every lost
/// link. `driver` is the first join's link and `bind` makes each later one.
///
/// # Why this loops
///
/// A drive that runs once turns a `LinkLost` — a socket error, an interface
/// going down and coming back — into a session that is gone for the life of
/// the process while its siblings keep serving, and nothing re-joins the group.
/// pico re-arms the same reopen task from a multicast lease failure that its
/// unicast one arms, and a wz router face re-joins too. This session re-joins
/// on the router face's own schedule and wait (`GroupRejoin`,
/// `rejoin_group_driver`), shared rather than copied, so the two cannot drift:
/// zenoh's 1000 / 4000 / x2 retry period, the wait and the re-bind both raced
/// against the stop.
///
/// Each join gets a fresh peer table, as each router-face join does: the
/// members it held were reached over the link that died. The application
/// observer and the send producer are the session's and outlive the joins.
///
/// # What it reports
///
/// Each line goes to `say` without the `wz-ap-demo session <name>:` prefix,
/// which the caller adds: `READY peer multicast joined <endpoint>` once,
/// `peer arrived` / `peer lost` per member, `link lost (<why>); re-joining in
/// <ms>ms` and `re-join failed (<why>); retrying in <ms>ms` while down,
/// `rejoined <endpoint>` when back, and `ended (<why>)` when the drive stops
/// for a reason that is neither a stop nor a lost link.
#[cfg(feature = "transport-multicast")]
async fn serve_group<D, B, Fut>(
    endpoint: &str,
    params: &wz::runtime_tokio::multicast_glue::MulticastParams,
    mut bind: B,
    mut driver: D,
    stop: &mut watch::Receiver<bool>,
    mut say: impl FnMut(&str),
) -> SessionEnd
where
    D: wz::runtime_tokio::multicast_glue::MulticastLinkDriver,
    B: FnMut() -> Fut,
    Fut: std::future::Future<Output = io::Result<D>>,
{
    use wz::runtime_tokio::multicast_glue::{
        drive_multicast_session_with_shutdown, rejoin_group_driver, GroupRejoin, MulticastConfig,
        MulticastDispatcher, MulticastDriveConfig, MulticastOutcome, MulticastTxProducer,
    };
    use wz::runtime_tokio::session::TokioMulticastSession;
    use wz::runtime_tokio::session_glue::IterationEvent;

    let producer = MulticastTxProducer::new();
    let clock = Arc::new(TokioTime::new());
    let session = TokioMulticastSession::new_multicast(
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        clock.clone(),
        producer.clone(),
    );
    let mut rejoin = GroupRejoin::new();
    say(&format!("READY peer multicast joined {endpoint}"));
    loop {
        let mut dispatcher = Box::new(MulticastDispatcher::<GROUP_PEER_TABLE>::new(
            MulticastConfig::new(params.lease_ms),
        ));
        let outcome = drive_multicast_session_with_shutdown(
            &mut dispatcher,
            MulticastDriveConfig {
                params,
                tick_ms: 10,
                max_iters: None,
            },
            &mut driver,
            clock.as_ref(),
            |event| {
                match &event {
                    IterationEvent::MulticastPeerArrived(arrived) => say(&format!(
                        "peer arrived {}",
                        zid_to_zenoh_hex(arrived.peer.as_slice())
                    )),
                    IterationEvent::MulticastPeerLost(lost) => say(&format!(
                        "peer lost {} ({:?})",
                        zid_to_zenoh_hex(lost.peer.as_slice()),
                        lost.reason
                    )),
                    _ => {}
                }
                session.dispatch_multicast_iteration_event(event);
            },
            &producer,
            stop,
        )
        .await;
        let Some(delay) = rejoin.wait_for(&outcome) else {
            return match outcome {
                MulticastOutcome::Stopped if *stop.borrow() => SessionEnd::Closed,
                outcome => {
                    say(&format!("ended ({outcome:?})"));
                    SessionEnd::Ended
                }
            };
        };
        match &outcome {
            MulticastOutcome::LinkLost(cause) => {
                say(&format!("link lost ({cause:?}); re-joining in {delay}ms"))
            }
            outcome => say(&format!("link lost ({outcome:?}); re-joining in {delay}ms")),
        }
        driver = match rejoin_group_driver(
            &mut bind,
            clock.as_ref(),
            &mut rejoin,
            stop,
            delay,
            |err, retry| say(&format!("re-join failed ({err}); retrying in {retry}ms")),
        )
        .await
        {
            Some(driver) => driver,
            // Told to stop while the group was down: there is no link to
            // announce a departure on, and the process is closing.
            None => return SessionEnd::Closed,
        };
        say(&format!("rejoined {endpoint}"));
    }
}

/// The rules admitted multicast documents in every build; this build cannot
/// run one, and `SessionsPlan::build_refusals` refuses it before anything
/// starts, so this arm is reached only if those two disagree.
#[cfg(not(feature = "transport-multicast"))]
async fn run_group(
    name: &str,
    _zid: Vec<u8>,
    _endpoint: &str,
    _join_interval_ms: u64,
    _lease_ms: u64,
    _stop: watch::Receiver<bool>,
) -> SessionEnd {
    eprintln!("wz-ap-demo session {name}: failed: this build has no multicast transport");
    SessionEnd::Failed
}

/// `udp/<group>:<port>[#iface=<name|addr>]` as the address, the port and the
/// interface. The rules have already admitted the text.
#[cfg(feature = "transport-multicast")]
fn group_address(endpoint: &str) -> Option<(std::net::IpAddr, u16, Option<String>)> {
    let (locator, meta) = match endpoint.split_once('#') {
        Some((l, m)) => (l, Some(m)),
        None => (endpoint, None),
    };
    let (host, port) = locator.strip_prefix("udp/")?.rsplit_once(':')?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let iface = meta.and_then(|m| {
        m.split(';')
            .find_map(|pair| pair.strip_prefix("iface="))
            .map(str::to_string)
    });
    Some((host.parse().ok()?, port.parse().ok()?, iface))
}

#[cfg(all(test, feature = "transport-multicast"))]
mod group_address_tests {
    use super::group_address;

    #[test]
    fn a_group_endpoint_splits_into_address_port_and_interface() {
        assert_eq!(
            group_address("udp/224.0.0.224:7446"),
            Some(("224.0.0.224".parse().unwrap(), 7446, None))
        );
        assert_eq!(
            group_address("udp/[ff02::1]:7447#iface=lo"),
            Some(("ff02::1".parse().unwrap(), 7447, Some("lo".to_string())))
        );
    }
}

/// A group session over an in-memory group: the real drive loop, the real
/// re-join schedule and wait, and a link the test can cut. Time is paused, so
/// the 1000 / 2000 / 4000 ms waits are the schedule's and cost nothing.
#[cfg(all(test, feature = "transport-multicast"))]
mod group_rejoin_tests {
    use std::cell::{Cell, RefCell};
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::sync::{mpsc, watch, Notify};

    use wz::runtime_tokio::multicast_glue::{MulticastDatagramSender, MulticastLinkDriver};
    use wz::runtime_tokio::zid_hex::zid_to_zenoh_hex;
    use wz::runtime_tokio::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};

    use super::{group_params, serve_group, SessionEnd};

    const ENDPOINT: &str = "udp/224.0.0.224:7446";

    type Datagram = (Vec<u8>, SocketAddr);

    /// One attached link: its address and where datagrams for it go.
    type Member = (SocketAddr, mpsc::UnboundedSender<Datagram>);

    /// The group: every attached link receives what any OTHER attached link
    /// sends, with the sender's address, as a multicast group delivers.
    #[derive(Clone, Default)]
    struct Bus {
        members: Arc<Mutex<Vec<Member>>>,
    }

    impl Bus {
        fn attach(&self, addr: SocketAddr, carrier: Arc<Notify>) -> BusLink {
            let (tx, inbound) = mpsc::unbounded_channel();
            self.members.lock().unwrap().push((addr, tx));
            BusLink {
                addr,
                bus: self.clone(),
                inbound,
                carrier,
            }
        }

        /// A link that is no longer attached sends nothing: its socket is gone.
        fn deliver(&self, from: SocketAddr, datagram: &[u8]) {
            let members = self.members.lock().unwrap();
            if !members.iter().any(|(addr, _)| *addr == from) {
                return;
            }
            for (addr, tx) in members.iter() {
                if *addr != from {
                    let _ = tx.send((datagram.to_vec(), from));
                }
            }
        }

        fn detach(&self, addr: SocketAddr) {
            self.members.lock().unwrap().retain(|(a, _)| *a != addr);
        }
    }

    /// One join's link. Notifying its `carrier` drops it, as a lost
    /// interface does; it is then detached from the group.
    struct BusLink {
        addr: SocketAddr,
        bus: Bus,
        inbound: mpsc::UnboundedReceiver<Datagram>,
        carrier: Arc<Notify>,
    }

    impl Drop for BusLink {
        fn drop(&mut self) {
            self.bus.detach(self.addr);
        }
    }

    struct BusSender {
        addr: SocketAddr,
        bus: Bus,
    }

    impl MulticastDatagramSender for BusSender {
        fn send(
            &self,
            datagram: &[u8],
        ) -> impl std::future::Future<Output = io::Result<()>> + Send {
            self.bus.deliver(self.addr, datagram);
            std::future::ready(Ok(()))
        }
    }

    impl MulticastLinkDriver for BusLink {
        type Sender = BusSender;

        fn datagram_sender(&self) -> io::Result<BusSender> {
            Ok(BusSender {
                addr: self.addr,
                bus: self.bus.clone(),
            })
        }
    }

    impl LinkDriver for BusLink {
        async fn open(&mut self) -> io::Result<()> {
            Ok(())
        }
        async fn send(&mut self, frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
            self.bus.deliver(self.addr, frame.bytes);
            Ok(())
        }
        async fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
        async fn poll_event(&mut self) -> LinkEvent {
            tokio::select! {
                datagram = self.inbound.recv() => match datagram {
                    Some((bytes, src)) => LinkEvent::Rx(RxFrame::with_src(bytes, src)),
                    None => LinkEvent::Lost { cause: LostCause::OsError },
                },
                () = self.carrier.notified() => {
                    self.bus.detach(self.addr);
                    LinkEvent::Lost { cause: LostCause::OsError }
                }
            }
        }
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    /// What one session said, in order.
    type Lines = Rc<RefCell<Vec<String>>>;

    fn count(lines: &Lines, needle: &str) -> usize {
        lines.borrow().iter().filter(|l| l.contains(needle)).count()
    }

    /// Wait (in paused time) until `lines` holds `n` lines containing
    /// `needle`; fail rather than hang when they never come.
    async fn until(lines: &Lines, needle: &str, n: usize) {
        for _ in 0..6_000 {
            if count(lines, needle) >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "never saw {n} line(s) containing {needle:?}; the session said {:#?}",
            lines.borrow()
        );
    }

    /// Item 900 follow-up — a group session whose link is lost three times
    /// re-joins three times, on the router face's growing schedule, admits the
    /// other member again after every re-join (and is admitted again by it),
    /// and still closes at the host's stop.
    ///
    /// A drive that runs once ends at the first `LinkLost`: no `rejoined`
    /// line, and `until` fails naming what the session did say.
    #[tokio::test(start_paused = true)]
    async fn a_lost_group_link_is_rejoined_and_admits_a_member_again() {
        let bus = Bus::default();
        let (stop_tx, stop_rx) = watch::channel(false);
        let carrier = Arc::new(Notify::new());
        let (a_lines, b_lines) = (Lines::default(), Lines::default());
        let (zid_a, zid_b) = (vec![0xA1, 0x01], vec![0xB2, 0x02]);
        let (hex_a, hex_b) = (zid_to_zenoh_hex(&zid_a), zid_to_zenoh_hex(&zid_b));
        let binds = Cell::new(0u16);
        let bind_a = || {
            binds.set(binds.get() + 1);
            std::future::ready(Ok::<_, io::Error>(
                bus.attach(addr(1_000 + binds.get()), carrier.clone()),
            ))
        };

        let a = {
            let mut stop = stop_rx.clone();
            let lines = a_lines.clone();
            let first = bind_a().await.unwrap();
            async move {
                serve_group(
                    ENDPOINT,
                    &group_params(zid_a, 100, 1_000),
                    bind_a,
                    first,
                    &mut stop,
                    |line| lines.borrow_mut().push(line.to_string()),
                )
                .await
            }
        };
        let b = {
            let mut stop = stop_rx.clone();
            let lines = b_lines.clone();
            let first = bus.attach(addr(2_000), Arc::new(Notify::new()));
            let bind_b =
                || std::future::ready(Err::<BusLink, _>(io::Error::other("b never re-binds")));
            async move {
                serve_group(
                    ENDPOINT,
                    &group_params(zid_b, 100, 1_000),
                    bind_b,
                    first,
                    &mut stop,
                    |line| lines.borrow_mut().push(line.to_string()),
                )
                .await
            }
        };
        let script = async {
            let arrived_b = format!("peer arrived {hex_b}");
            let arrived_a = format!("peer arrived {hex_a}");
            until(&a_lines, &arrived_b, 1).await;
            until(&b_lines, &arrived_a, 1).await;
            for round in 1..=3 {
                carrier.notify_one();
                until(&a_lines, "rejoined", round).await;
                until(&a_lines, &arrived_b, round + 1).await;
                until(&b_lines, &arrived_a, round + 1).await;
            }
            stop_tx.send(true).unwrap();
        };
        let (end_a, end_b, ()) = tokio::join!(a, b, script);

        assert_eq!(end_a, SessionEnd::Closed);
        assert_eq!(end_b, SessionEnd::Closed);
        assert_eq!(binds.get(), 4, "one first join and three re-joins");
        let lost: Vec<String> = a_lines
            .borrow()
            .iter()
            .filter(|l| l.starts_with("link lost"))
            .cloned()
            .collect();
        assert_eq!(
            lost,
            [
                "link lost (OsError); re-joining in 1000ms",
                "link lost (OsError); re-joining in 2000ms",
                "link lost (OsError); re-joining in 4000ms",
            ],
            "the router face's schedule: zenoh's 1000 / 4000 / x2"
        );
        assert_eq!(count(&a_lines, "READY peer multicast joined"), 1);
        assert_eq!(count(&a_lines, &format!("rejoined {ENDPOINT}")), 3);
        assert_eq!(
            count(&b_lines, "link lost"),
            0,
            "the other member was never cut"
        );
    }

    /// A stop that arrives while the group is down — every re-bind failing —
    /// closes the session at the signal, not one backoff later, and each
    /// failed re-bind was reported with its wait.
    #[tokio::test(start_paused = true)]
    async fn a_stop_while_the_group_is_down_closes_at_the_signal() {
        let bus = Bus::default();
        let (stop_tx, stop_rx) = watch::channel(false);
        let carrier = Arc::new(Notify::new());
        let lines = Lines::default();
        let first = bus.attach(addr(3_000), carrier.clone());
        let bind =
            || std::future::ready(Err::<BusLink, _>(io::Error::other("the interface is down")));
        let signalled_at = Cell::new(None);

        let a = {
            let mut stop = stop_rx.clone();
            let lines = lines.clone();
            async move {
                let end = serve_group(
                    ENDPOINT,
                    &group_params(vec![0xC3], 100, 1_000),
                    bind,
                    first,
                    &mut stop,
                    |line| lines.borrow_mut().push(line.to_string()),
                )
                .await;
                (end, tokio::time::Instant::now())
            }
        };
        let script = async {
            until(&lines, "READY", 1).await;
            carrier.notify_one();
            until(&lines, "re-join failed", 2).await;
            signalled_at.set(Some(tokio::time::Instant::now()));
            stop_tx.send(true).unwrap();
        };
        let ((end, ended_at), ()) = tokio::join!(a, script);

        assert_eq!(end, SessionEnd::Closed);
        assert_eq!(
            Some(ended_at),
            signalled_at.get(),
            "the stop must be taken at the signal, not after the pending wait"
        );
        let said = lines.borrow();
        assert!(
            said.iter()
                .any(|l| l == "re-join failed (the interface is down); retrying in 2000ms"),
            "{said:#?}"
        );
        assert_eq!(count(&lines, "rejoined"), 0);
    }
}

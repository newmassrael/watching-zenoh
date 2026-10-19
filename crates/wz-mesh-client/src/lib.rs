// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The watching-zenoh client of SCE Mesh's Zenoh binding.
//!
//! The binding asks a client for four things and nothing else: subscribe to keys, subscribe to
//! presence, declare presence, put (`sce_rust_mesh::inbox::ZenohClient`). [`WzClient`] does them on
//! a wz session. Every decision the binding makes (the key layout, the order a machine is set up
//! in, what a presence change means) stays in `sce-rust-mesh`, which is what lets this client and
//! upstream's be held to one behaviour by the same kit (`sce_rust_mesh::conformance`).
//!
//! ## The thread
//!
//! A wz session is not `Send`: it is driven on one task and its handles are `Rc`-shaped. The
//! trait asks for a client that is, and that its operations are synchronous. So the session lives
//! on a thread of this crate's own, in a current-thread runtime, and [`WzClient`] is a channel to
//! it: each call sends a command and waits for the answer. The callbacks the binding hands over run
//! on that thread, as the trait says they may.
//!
//! What a client holds open is held on that thread too. A [`Held`] returned to the binding is only
//! a number and a way to say "undeclare it"; dropping it sends that. Dropping the client ends the
//! session on the wire first (a close, so the router ends this machine's presence at once and not
//! when a lease runs out) and waits for the thread to finish, so that when the drop returns the
//! other machines have been or are about to be told.
//!
//! ## When the session ends
//!
//! A client is one session and does not reconnect by itself. A session whose link to the router
//! ends is over: every later call answers that it ended, and a put is refused as terminal. What
//! the binding asks of a client in that case is to say so ([`ZenohClient::on_session_end`]): the
//! session thread knows the moment the drive loop returns, because the session machine reached its
//! final state (the router closed it, the lease ran out, the link failed, or a put found no room
//! and the session closed as unresponsive), so no thread has to look for it. The notice is made
//! after what the session held has been let go of, so no sample or presence change is delivered
//! after it. A machine that is to come back opens a new client, which `sce_rust_mesh::reconnect`
//! does for a long-lived one; a device that is on only while its user presses sync opens one each
//! time anyway.

use std::any::Any;
use std::collections::HashMap;
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sce_rust_mesh::inbox::{ClientError, Held, PresenceKind, PutError, ZenohClient};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use wz_runtime_tokio::declare::LivelinessSampleKind;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::sample::SampleKind;
use wz_runtime_tokio::session::{
    LivelinessOptions, LivelinessSubscriberOptions, PublishError, PublishOptions, SubscribeOptions,
    TokioSession,
};
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, CloseReason, EntropySource, OsEntropy, SessionInitParams, WhatAmI,
};
use wz_runtime_tokio::session_open::{
    dial_endpoint, initiate_and_open_session, DialConfig, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_session_core::qos::CongestionControl;
use wz_session_core::session_init_params::TxQueueConf;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::sink::SampleView;

/// What every call after the session ended says.
const SESSION_ENDED: &str = "the session to the router has ended";

/// The Zenoh protocol version byte a client of the 1.x line announces, which is the one the
/// watching-zenoh demo announces to a router of that line.
const PROTOCOL_VERSION: u8 = 0x09;

/// The lease a client announces, in milliseconds: the interval after which a router that has heard
/// nothing ends the session and with it this machine's presence.
const LEASE_MS: u64 = 10_000;

/// The largest batch a client announces, in bytes.
const BATCH_SIZE: u16 = 65_535;

/// Where an answer to a command is sent. Capacity one: the thread answers each command once.
type Reply<T> = std_mpsc::SyncSender<T>;

/// What the binding hands over to hear a put: the full key and the payload bytes.
type SampleCallback = Box<dyn FnMut(&str, &[u8]) + Send>;

/// What the binding hands over to hear presence change: the key of a token and what happened to it.
type PresenceCallback = Box<dyn FnMut(&str, PresenceKind) + Send>;

/// What the binding hands over to hear the session end: the client's own words for why.
type EndCallback = Box<dyn FnOnce(String) + Send>;

/// What the caller asks the session thread to do.
enum Command {
    /// Call `on_end` once the session has ended.
    OnSessionEnd {
        on_end: EndCallback,
        reply: Reply<Result<(), ClientError>>,
    },
    Subscribe {
        filter: String,
        on_sample: SampleCallback,
        reply: Reply<Result<u64, ClientError>>,
    },
    SubscribePresence {
        filter: String,
        history: bool,
        on_change: PresenceCallback,
        reply: Reply<Result<u64, ClientError>>,
    },
    DeclarePresence {
        key: String,
        reply: Reply<Result<u64, ClientError>>,
    },
    Put {
        key: String,
        payload: Vec<u8>,
        reply: Reply<Result<(), PutError>>,
    },
    /// Stop holding what declaration `id` stands for.
    Undeclare(u64),
    /// End the session on the wire and the thread.
    Close,
}

/// What a [`Held`] is: a number the session thread knows a declaration by, and the way back to it.
struct Declaration {
    id: u64,
    commands: UnboundedSender<Command>,
}

impl Drop for Declaration {
    fn drop(&mut self) {
        // The thread may be gone already, when the client was dropped first: then there is
        // nothing left to undeclare.
        let _ = self.commands.send(Command::Undeclare(self.id));
    }
}

/// A client session on a watching-zenoh node, behind the trait SCE Mesh's Zenoh binding asks for.
pub struct WzClient {
    commands: UnboundedSender<Command>,
    thread: Option<JoinHandle<()>>,
}

impl WzClient {
    /// Open a session to the first of `endpoints` (`tcp/<host>:<port>`) that answers, and return
    /// once it is established. The session is a client's: it announces itself as one, with a fresh
    /// random identity of its own.
    pub fn connect(endpoints: &[&str]) -> Result<WzClient, ClientError> {
        if endpoints.is_empty() {
            return Err(ClientError::new("no endpoint to connect to"));
        }
        let endpoints: Vec<String> = endpoints.iter().map(|e| (*e).to_string()).collect();
        let (commands, inbox) = unbounded_channel();
        let (ready_tx, ready_rx) = std_mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("wz-mesh-client".to_string())
            .spawn(move || run(endpoints, inbox, ready_tx))
            .map_err(|e| ClientError::new(format!("the session thread did not start: {e}")))?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(WzClient {
                commands,
                thread: Some(thread),
            }),
            Ok(Err(why)) => {
                let _ = thread.join();
                Err(why)
            }
            Err(_) => {
                let _ = thread.join();
                Err(ClientError::new(
                    "the session thread ended before it opened",
                ))
            }
        }
    }

    /// Send `command` and wait for the id of what it declared.
    fn declare(
        &self,
        command: impl FnOnce(Reply<Result<u64, ClientError>>) -> Command,
    ) -> Result<Held, ClientError> {
        let (reply, answer) = std_mpsc::sync_channel(1);
        self.commands
            .send(command(reply))
            .map_err(|_| ClientError::new(SESSION_ENDED))?;
        let id = answer
            .recv()
            .map_err(|_| ClientError::new(SESSION_ENDED))??;
        Ok(Box::new(Declaration {
            id,
            commands: self.commands.clone(),
        }))
    }
}

impl Drop for WzClient {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Close);
        if let Some(thread) = self.thread.take() {
            // A notice that drops the client runs on the session thread, which cannot wait for
            // itself to finish; it is on its way out already.
            if thread.thread().id() != std::thread::current().id() {
                let _ = thread.join();
            }
        }
    }
}

impl ZenohClient for WzClient {
    fn subscribe<F>(&mut self, filter: &str, on_sample: F) -> Result<Held, ClientError>
    where
        F: FnMut(&str, &[u8]) + Send + 'static,
    {
        self.declare(|reply| Command::Subscribe {
            filter: filter.to_string(),
            on_sample: Box::new(on_sample),
            reply,
        })
    }

    fn subscribe_presence<F>(
        &mut self,
        filter: &str,
        history: bool,
        on_change: F,
    ) -> Result<Held, ClientError>
    where
        F: FnMut(&str, PresenceKind) + Send + 'static,
    {
        self.declare(|reply| Command::SubscribePresence {
            filter: filter.to_string(),
            history,
            on_change: Box::new(on_change),
            reply,
        })
    }

    fn declare_presence(&mut self, key: &str) -> Result<Held, ClientError> {
        self.declare(|reply| Command::DeclarePresence {
            key: key.to_string(),
            reply,
        })
    }

    fn put(&mut self, key: &str, payload: &[u8]) -> Result<(), PutError> {
        let (reply, answer) = std_mpsc::sync_channel(1);
        self.commands
            .send(Command::Put {
                key: key.to_string(),
                payload: payload.to_vec(),
                reply,
            })
            .map_err(|_| PutError::terminal(SESSION_ENDED))?;
        answer
            .recv()
            .map_err(|_| PutError::terminal(SESSION_ENDED))?
    }

    fn on_session_end<F>(&mut self, on_end: F) -> Result<(), ClientError>
    where
        F: FnOnce(String) + Send + 'static,
    {
        let (reply, answer) = std_mpsc::sync_channel(1);
        // A session that ended before this was asked has no thread to answer: that is an error,
        // and the binding fails its open on it, which is the same as the end being told.
        self.commands
            .send(Command::OnSessionEnd {
                on_end: Box::new(on_end),
                reply,
            })
            .map_err(|_| ClientError::new(SESSION_ENDED))?;
        answer.recv().map_err(|_| ClientError::new(SESSION_ENDED))?
    }
}

/// The session thread: one current-thread runtime, and on it the session and everything it holds.
fn run(
    endpoints: Vec<String>,
    commands: UnboundedReceiver<Command>,
    ready: std_mpsc::SyncSender<Result<(), ClientError>>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = ready.send(Err(ClientError::new(format!("no runtime: {e}"))));
            return;
        }
    };
    tokio::task::LocalSet::new().block_on(&runtime, serve(endpoints, commands, ready));
}

/// The parameters a client opens a session with: the shape the watching-zenoh demo opens its client
/// sessions with, and an identity drawn from the operating system's entropy.
fn session_params() -> Result<SessionInitParams, ClientError> {
    let mut zid = [0u8; 16];
    while zid.iter().all(|&b| b == 0) {
        OsEntropy
            .try_fill_bytes(&mut zid)
            .map_err(|_| ClientError::new("no operating system entropy to draw an identity"))?;
    }
    // A zenoh id is the bytes up to its last non-zero one.
    let significant = zid.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    Ok(SessionInitParams {
        version: PROTOCOL_VERSION,
        whatami: WhatAmI::Client,
        zid: zid[..significant].to_vec(),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: BATCH_SIZE,
        lease_ms: LEASE_MS,
        tx_queue: Default::default(),
        initial_sn: 0,
        cookie: Vec::new(),
        cookie_signing_key: SigningKey::from_entropy(&mut OsEntropy).map_err(|e| {
            ClientError::new(format!(
                "no operating system entropy for a signing key: {e}"
            ))
        })?,
    })
}

/// Dial each endpoint in order and open a session on the first that takes it.
async fn open(endpoints: &[String]) -> Result<OpenedSession, ClientError> {
    let mut why = Vec::new();
    for endpoint in endpoints {
        let params = session_params()?;
        let attempt = async {
            let link = dial_endpoint(endpoint, &DialConfig::default())
                .await
                .map_err(|e| e.to_string())?;
            initiate_and_open_session(link, params, TokioTime::new(), None, DEFAULT_OPEN_TICK_MS)
                .await
                .map_err(|e| format!("{e:?}"))
        };
        match attempt.await {
            Ok(opened) => return Ok(opened),
            Err(e) => why.push(format!("{endpoint}: {e}")),
        }
    }
    Err(ClientError::new(format!(
        "no endpoint opened ({})",
        why.join("; ")
    )))
}

/// Open the session, then serve commands while driving it, until the client is dropped or the router
/// ends the session; then say goodbye the way a client does.
async fn serve(
    endpoints: Vec<String>,
    mut commands: UnboundedReceiver<Command>,
    ready: std_mpsc::SyncSender<Result<(), ClientError>>,
) {
    let mut opened = match open(&endpoints).await {
        Ok(opened) => opened,
        Err(why) => {
            let _ = ready.send(Err(why));
            return;
        }
    };
    let observer = Arc::new(wz_runtime_tokio::sync::PlainMutex::new(
        ApplicationLayerObserver::new(),
    ));
    let session = TokioSession::new(opened.actions.clone(), observer, Arc::new(opened.clock));
    let _ = ready.send(Ok(()));

    let mut held: HashMap<u64, Box<dyn Any>> = HashMap::new();
    let mut next_id = 0u64;
    let mut on_end: Option<EndCallback> = None;
    let timeouts = SessionTimeouts::spec_defaults();
    let router_ended = {
        let drive = drive_session_until_terminal(
            &mut opened.inbound,
            &opened.actions,
            &mut opened.engine,
            None,
            &opened.clock,
            &timeouts,
            |event| session.dispatch_iteration_event(event),
        );
        tokio::pin!(drive);
        loop {
            // The session first, then the callers: a put that waited out its room asks the drive
            // loop to close the session as unresponsive, and that request is only seen when the loop
            // is polled. With the two arms picked at random a caller that sends the next put at once
            // could keep the close waiting for many puts, each of which waits again.
            tokio::select! {
                biased;
                _ = &mut drive => break true,
                command = commands.recv() => match command {
                    None | Some(Command::Close) => break false,
                    Some(command) => handle(&session, &mut held, &mut next_id, &mut on_end, command),
                },
            }
        }
    };

    // What the session holds is let go of while it can still say so, and then the session says
    // goodbye. The handles hold clones of the session, so they go first.
    held.clear();
    drop(session);
    if router_ended {
        // Only a session that ended without the client asking is told: a client that was dropped
        // is not one whose binding wants to be told. Nothing the session held can call back after
        // this.
        if let Some(on_end) = on_end.take() {
            on_end(SESSION_ENDED.to_string());
        }
    } else {
        opened.actions.send_close_with_reason(CloseReason::Generic);
    }
    opened.drain_to_close().await;
}

/// Remember `what` under a new id and return the id.
fn keep(held: &mut HashMap<u64, Box<dyn Any>>, next_id: &mut u64, what: Box<dyn Any>) -> u64 {
    let id = *next_id;
    *next_id += 1;
    held.insert(id, what);
    id
}

/// Do one command on the session.
fn handle(
    session: &TokioSession,
    held: &mut HashMap<u64, Box<dyn Any>>,
    next_id: &mut u64,
    on_end: &mut Option<EndCallback>,
    command: Command,
) {
    match command {
        Command::OnSessionEnd {
            on_end: notice,
            reply,
        } => {
            let _ = reply.send(if on_end.is_some() {
                Err(ClientError::new(
                    "the end of this session is already being watched",
                ))
            } else {
                *on_end = Some(notice);
                Ok(())
            });
        }
        Command::Subscribe {
            filter,
            mut on_sample,
            reply,
        } => {
            let declared = session.declare_subscriber(
                filter,
                SubscribeOptions::default(),
                move |sample: &dyn SampleView| {
                    // The binding's inbox carries puts: a delete under it is not an envelope.
                    if sample.kind() == SampleKind::Put {
                        on_sample(sample.keyexpr(), sample.payload());
                    }
                },
            );
            let _ = reply.send(
                declared
                    .map(|subscriber| keep(held, next_id, Box::new(subscriber)))
                    .map_err(ClientError::new),
            );
        }
        Command::SubscribePresence {
            filter,
            history,
            mut on_change,
            reply,
        } => {
            let declared = session.declare_liveliness_subscriber(
                filter,
                LivelinessSubscriberOptions::default().with_history(history),
                move |sample| {
                    on_change(
                        sample.keyexpr,
                        match sample.kind {
                            LivelinessSampleKind::Put => PresenceKind::Put,
                            LivelinessSampleKind::Delete => PresenceKind::Delete,
                        },
                    );
                },
            );
            let _ = reply.send(
                declared
                    .map(|subscriber| keep(held, next_id, Box::new(subscriber)))
                    .map_err(ClientError::new),
            );
        }
        Command::DeclarePresence { key, reply } => {
            let declared = session.declare_token(key, LivelinessOptions::default());
            let _ = reply.send(
                declared
                    .map(|token| keep(held, next_id, Box::new(token)))
                    .map_err(ClientError::new),
            );
        }
        Command::Put {
            key,
            payload,
            reply,
        } => {
            // Block, not drop: the binding counts an envelope as the unit of delivery, and one the
            // network dropped without telling it is one the core would wait for (SCE_MESH.md
            // section 20.2).
            let began = Instant::now();
            let published = session.publish(
                &key,
                &payload,
                PublishOptions::put().with_congestion_control(CongestionControl::Block),
            );
            let _ = reply.send(judge_put(published.map(|_| ()), began.elapsed()));
        }
        Command::Undeclare(id) => {
            held.remove(&id);
        }
        // Handled by the loop that ends the session.
        Command::Close => {}
    }
}

/// How long a blocking put waits for room on a link before the session gives the peer up: the
/// default `wait_before_close`, which is what `session_params` leaves in the session's queue
/// configuration.
fn block_wait() -> Duration {
    Duration::from_micros(TxQueueConf::default().wait_before_close_us)
}

/// What a put's answer means to the binding. A wz session mirrors upstream's: a put that waited its
/// full `wait_before_close` for room and found none ASKS THE SESSION TO CLOSE as unresponsive, and
/// the publish itself answers `Ok`, the closing being the session machinery's to do. The binding
/// asks a client that a put it cannot place is not reported as sent (SCE_MESH.md section 20.2), so
/// a put that waited that long is an error here: the envelope was not placed, and the session is
/// closing. It is retryable, in the sense that the same bytes can be sent once there is a session
/// again.
fn judge_put(published: Result<(), PublishError>, waited: Duration) -> Result<(), PutError> {
    match published {
        Ok(()) if waited >= block_wait() => Err(PutError::retryable(format!(
            "no room on the link within {waited:?}: the session closes as unresponsive"
        ))),
        Ok(()) => Ok(()),
        Err(error) => Err(put_error(error)),
    }
}

/// What a refused publish means to the binding's retry policy: the refusals the same bytes may get
/// past once the link is back are retryable, the ones about the message itself are not.
fn put_error(error: PublishError) -> PutError {
    match error {
        PublishError::TransportUnavailable | PublishError::FragmentChainAbandoned => {
            PutError::retryable(error)
        }
        other => PutError::terminal(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_with_no_endpoint_is_refused_before_a_thread_starts() {
        match WzClient::connect(&[]) {
            Err(why) => assert!(why.message.contains("no endpoint"), "{why}"),
            Ok(_) => panic!("a client opened with nothing to connect to"),
        }
    }

    #[test]
    fn an_endpoint_nothing_listens_on_is_named_in_the_refusal() {
        // Port 1 is reserved and nothing of ours listens there.
        match WzClient::connect(&["tcp/127.0.0.1:1"]) {
            Err(why) => assert!(
                why.message.contains("tcp/127.0.0.1:1") && why.message.contains("no endpoint"),
                "{why}"
            ),
            Ok(_) => panic!("a client opened against a port nothing listens on"),
        }
    }

    #[test]
    fn a_refused_publish_is_retryable_only_where_the_same_bytes_may_get_through() {
        assert!(put_error(PublishError::TransportUnavailable).retryable);
        assert!(put_error(PublishError::FragmentChainAbandoned).retryable);
        assert!(!put_error(PublishError::ExceedsCapacity).retryable);
        assert!(!put_error(PublishError::RequiresUnicast).retryable);
    }

    #[test]
    fn a_put_that_waited_its_whole_room_is_not_reported_as_sent() {
        let limit = block_wait();
        // The publish answers Ok in both cases below: the closing of a session whose peer takes
        // nothing is the session machinery's, and what tells the two apart is the wait.
        assert_eq!(judge_put(Ok(()), Duration::from_millis(1)), Ok(()));
        assert_eq!(judge_put(Ok(()), limit - Duration::from_millis(1)), Ok(()));
        let refused = judge_put(Ok(()), limit).expect_err("a put that waited the whole room");
        assert!(refused.retryable, "{refused}");
        assert!(refused.message.contains("no room"), "{refused}");
        // A refusal the publish itself gives is carried through unchanged, whatever the wait.
        assert!(
            !judge_put(Err(PublishError::ExceedsCapacity), Duration::ZERO)
                .expect_err("refused")
                .retryable
        );
        assert!(
            judge_put(Err(PublishError::TransportUnavailable), limit)
                .expect_err("refused")
                .retryable
        );
    }

    #[test]
    fn each_session_draws_an_identity_of_its_own() {
        let first = session_params().expect("params");
        let second = session_params().expect("params");
        assert_ne!(first.zid, second.zid);
        assert!(!first.zid.is_empty() && first.zid.len() <= 16);
    }
}

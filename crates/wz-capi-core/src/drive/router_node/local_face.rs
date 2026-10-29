// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `Local` face of a router node, as a program uses it for liveliness.
//!
//! Upstream's node has a session of its own among its faces; the tokens the other faces declare
//! are told to it as to any client that asked, and the tokens it declares go out as a client's.
//! Here the forwarder tells its `Local` face what it would send to a client (a token that came
//! alive, one that went) through a sink, and this module is what stands behind the sink: a thread
//! that owns the state of the face, so that no lock is held when a callback runs and a callback
//! may call back into the node.
//!
//! The state is what the face has been told: the tokens of the other faces by the id the router
//! numbers them, the tokens the program declared, and for each key how many of them are alive. A
//! subscriber is told of a key when the first token comes alive on it and of its going when the
//! last is gone, as a client of a router is told by the router's one declaration per key, and the
//! tokens already alive are told first when the subscriber asks for its history.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Mutex, Weak};
use std::thread::JoinHandle;

use wz_runtime_tokio::declare::{LivelinessSample, LivelinessSampleKind};
use wz_runtime_tokio::keyexpr_match::keyexpr_intersects_text;
use wz_runtime_tokio::router_forward::{
    local_face_aliases, LocalFaceEvent, LocalFaceSink, MatchPlane, RouterForwarder,
};
use wz_session_core::locality::Locality;
use wz_session_core::reply::ReplyRegistry;
use wz_session_core::reply_acceptance::{ReplyAcceptance, ReplyKeyExpr};
use wz_session_core::reply_sink::{BoxedReplySink, ConsolidatingSink, ReplyView};

/// What a liveliness subscriber of the face is called with, on the face's thread.
pub type LivelinessHandler = Box<dyn for<'a> FnMut(LivelinessSample<'a>) + Send + 'static>;

/// What a query of the face is handed each reply to, on the face's thread.
pub type ReplyHandler = Box<dyn for<'a> FnMut(&'a dyn ReplyView) + Send + 'static>;

/// What a query of the face is told its end by, on the face's thread: once, after the last reply.
pub type FinalHandler = Box<dyn FnMut() + Send + 'static>;

/// What a watch of the face is called with when its verdict moves, on the face's thread.
pub type MatchHandler = Box<dyn FnMut(bool) + Send + 'static>;

/// What the face's thread is asked to do, in the order it is asked.
enum Command {
    /// The router told the face something.
    Told(LocalFaceEvent),
    Subscribe {
        id: u64,
        pattern: String,
        history: bool,
        handler: LivelinessHandler,
    },
    Unsubscribe(u64),
    /// The program declared the token `id` on `keyexpr`.
    OwnUp {
        id: u64,
        keyexpr: String,
    },
    /// The program retracted its token `id`.
    OwnDown(u64),
    /// The keys of the tokens alive that `pattern` meets.
    Alive {
        pattern: String,
        answer: mpsc::Sender<Vec<String>>,
    },
    /// The program asked a query under the request id `rid`; the router is asked next, so the
    /// replies it tells the face find the query held.
    Get {
        rid: u64,
        /// The key the query asks, which the replies are held to unless `accept` lifts it.
        keyexpr: String,
        accept: ReplyKeyExpr,
        /// How long the query waits for its answer, in milliseconds; `0` is no deadline.
        timeout_ms: u32,
        on_reply: ReplyHandler,
        on_final: FinalHandler,
    },
    /// The program watches whether anything of `plane` matches `key` among the declarations
    /// `origin` admits.
    Watch {
        id: u64,
        plane: MatchPlane,
        key: String,
        origin: Locality,
        handler: MatchHandler,
        /// Told once the verdict that holds at the start has been given to the handler.
        begun: mpsc::Sender<()>,
    },
    Unwatch(u64),
    Stop,
}

struct Subscriber {
    id: u64,
    pattern: String,
    handler: LivelinessHandler,
}

/// A key with tokens alive on it.
struct Alive {
    /// The id of the token that brought the key alive: what every subscriber was told it under,
    /// and what its history and its retraction carry.
    told: u64,
    holders: usize,
}

struct State {
    /// When the face started: the clock the deadlines of its queries are on.
    started: std::time::Instant,
    /// The tokens of the other faces, by the id the router numbers them.
    remote: HashMap<u64, String>,
    /// The tokens the program declared, by the id the router holds them under.
    own: HashMap<u64, String>,
    /// The keys alive, each with the id it was told under and how many tokens, of either, hold it.
    alive: HashMap<String, Alive>,
    subscribers: Vec<Subscriber>,
    /// The queries the program asked that have not ended, by the request id it gave them: a
    /// reply the router tells the face is handed to the query it answers, and the end of the
    /// replies ends it. The face has no alias table, so a key it is told is literal.
    queries: ReplyRegistry<ConsolidatingSink<BoxedReplySink>>,
    /// What the face watches in the router's tables, each with the verdict it last gave. The
    /// face asks the router outside every lock whenever the tables were written, and its
    /// handler is called when the verdict moves.
    watches: Vec<Watch>,
    /// The router the watches are asked of; gone when the node is.
    router: Weak<RouterForwarder>,
}

/// A thing the face watches in the router's tables: whether anything of `plane` matches `key`
/// among the declarations `origin` admits.
struct Watch {
    id: u64,
    plane: MatchPlane,
    key: String,
    origin: Locality,
    last: bool,
    handler: MatchHandler,
}

impl State {
    /// Milliseconds since the face started.
    fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn new(router: Weak<RouterForwarder>) -> Self {
        Self {
            started: std::time::Instant::now(),
            remote: HashMap::new(),
            own: HashMap::new(),
            alive: HashMap::new(),
            subscribers: Vec::new(),
            queries: ReplyRegistry::new(),
            watches: Vec::new(),
            router,
        }
    }

    /// Ask the router what each watch counts, and call the handler of each whose verdict moved.
    fn look(&mut self) {
        let Some(router) = self.router.upgrade() else {
            return;
        };
        // Before the questions, so that a write that comes in while they are asked is told again.
        router.tables_looked_at();
        for watch in &mut self.watches {
            let now = router.matching(watch.plane, &watch.key, watch.origin);
            if now != watch.last {
                watch.last = now;
                (watch.handler)(now);
            }
        }
    }

    fn handle(&mut self, command: Command) -> bool {
        match command {
            Command::Told(LocalFaceEvent::Changed) => self.look(),
            Command::Watch {
                id,
                plane,
                key,
                origin,
                mut handler,
                begun,
            } => {
                // The watch was counted by the router before the face first looks, so a write
                // after this question is told. A verdict that holds when the watch begins is
                // given at once: the listener is told what is, and then what changes.
                let now = self
                    .router
                    .upgrade()
                    .is_some_and(|router| router.matching(plane, &key, origin));
                if now {
                    handler(true);
                }
                self.watches.push(Watch {
                    id,
                    plane,
                    key,
                    origin,
                    last: now,
                    handler,
                });
                let _ = begun.send(());
            }
            Command::Unwatch(id) => self.watches.retain(|watch| watch.id != id),
            Command::Told(LocalFaceEvent::Reply(response)) => {
                self.queries
                    .dispatch_response(&response, &local_face_aliases());
            }
            Command::Told(LocalFaceEvent::ReplyFinal { request_id }) => {
                self.queries.deliver_local_final(request_id);
            }
            Command::Get {
                rid,
                keyexpr,
                accept,
                timeout_ms,
                mut on_reply,
                mut on_final,
            } => {
                // A query that is not answered by its deadline ends with the reply that says
                // so, then its end, as a query of a session does.
                let deadline = (timeout_ms != 0).then(|| self.now_ms() + u64::from(timeout_ms));
                self.queries.register(
                    rid,
                    1,
                    deadline,
                    ReplyAcceptance::for_query(&keyexpr, accept),
                    move |reply| on_reply(reply),
                    move |_| on_final(),
                );
            }
            Command::Told(LocalFaceEvent::TokenUp { id, keyexpr }) => {
                // The first announcement of an id wins, as a session's table of remote tokens
                // does: a repeat neither counts again nor rebinds the id to another key.
                if let std::collections::hash_map::Entry::Vacant(slot) = self.remote.entry(id) {
                    slot.insert(keyexpr.clone());
                    self.up(&keyexpr, id);
                }
            }
            Command::Told(LocalFaceEvent::TokenDown { id, keyexpr }) => {
                if let Some(held) = self.remote.remove(&id) {
                    self.down(&held);
                } else if let Some(keyexpr) = keyexpr {
                    // The router says nothing of the other faces backs the key any more, to a
                    // face it never numbered the token for: every token of theirs on it is gone.
                    let gone: Vec<u64> = self
                        .remote
                        .iter()
                        .filter(|(_, held)| **held == keyexpr)
                        .map(|(id, _)| *id)
                        .collect();
                    for id in gone {
                        self.remote.remove(&id);
                        self.down(&keyexpr);
                    }
                }
            }
            Command::OwnUp { id, keyexpr } => {
                self.own.insert(id, keyexpr.clone());
                self.up(&keyexpr, id);
            }
            Command::OwnDown(id) => {
                if let Some(keyexpr) = self.own.remove(&id) {
                    self.down(&keyexpr);
                }
            }
            Command::Subscribe {
                id,
                pattern,
                history,
                mut handler,
            } => {
                if history {
                    for (keyexpr, key) in self
                        .alive
                        .iter()
                        .filter(|(key, _)| keyexpr_intersects_text(&pattern, key))
                    {
                        handler(LivelinessSample {
                            kind: LivelinessSampleKind::Put,
                            keyexpr,
                            token_id: key.told,
                        });
                    }
                }
                self.subscribers.push(Subscriber {
                    id,
                    pattern,
                    handler,
                });
            }
            Command::Unsubscribe(id) => self.subscribers.retain(|sub| sub.id != id),
            Command::Alive { pattern, answer } => {
                let keys = self
                    .alive
                    .keys()
                    .filter(|key| keyexpr_intersects_text(&pattern, key))
                    .cloned()
                    .collect();
                let _ = answer.send(keys);
            }
            Command::Stop => return false,
        }
        true
    }

    fn up(&mut self, keyexpr: &str, token_id: u64) {
        let key = self.alive.entry(keyexpr.to_owned()).or_insert(Alive {
            told: token_id,
            holders: 0,
        });
        key.holders += 1;
        if key.holders == 1 {
            self.tell(LivelinessSampleKind::Put, keyexpr, token_id);
        }
    }

    /// One token of `keyexpr` is gone. The key is retracted under the id it was told under, which
    /// is not that of the token that was the last to go: a subscriber counts the key alive by that
    /// id, and a retraction under another would leave it alive.
    fn down(&mut self, keyexpr: &str) {
        let Some(key) = self.alive.get_mut(keyexpr) else {
            return;
        };
        key.holders -= 1;
        if key.holders == 0 {
            let told = key.told;
            self.alive.remove(keyexpr);
            self.tell(LivelinessSampleKind::Delete, keyexpr, told);
        }
    }

    fn tell(&mut self, kind: LivelinessSampleKind, keyexpr: &str, token_id: u64) {
        for sub in &mut self.subscribers {
            if keyexpr_intersects_text(&sub.pattern, keyexpr) {
                (sub.handler)(LivelinessSample {
                    kind,
                    keyexpr,
                    token_id,
                });
            }
        }
    }
}

/// The face of a router node for liveliness: the program's side of it.
pub struct LocalLiveliness {
    commands: mpsc::Sender<Command>,
    next_subscriber: AtomicU64,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl LocalLiveliness {
    /// Start the face's thread, and answer the sink the router is to tell the face through.
    ///
    /// `router` is the node's router, which the face asks what it watches in the tables
    /// ([`Self::watch`]); a face started over none watches nothing.
    pub(super) fn start(router: Weak<RouterForwarder>) -> std::io::Result<(Self, LocalFaceSink)> {
        let (commands, received) = mpsc::channel::<Command>();
        let thread = std::thread::Builder::new()
            .name("wz-router-local".to_owned())
            .spawn(move || {
                // The thread of a face, as the thread of any other: it runs inside a
                // single-threaded runtime, which is how a program that is handed an item here
                // knows it must not wait on this thread for anything and queues the item for a
                // worker of its own (see the callback context of the top crate).
                let runtime = tokio::runtime::Builder::new_current_thread().build().ok();
                let _inside = runtime.as_ref().map(tokio::runtime::Runtime::enter);
                let mut state = State::new(router);
                loop {
                    // The next command, or the moment the first query that waits for an answer
                    // runs out of time, whichever comes first.
                    let command = match state.queries.next_deadline_ms() {
                        Some(deadline) => {
                            let wait = deadline.saturating_sub(state.now_ms());
                            match received.recv_timeout(std::time::Duration::from_millis(wait)) {
                                Ok(command) => Some(command),
                                Err(mpsc::RecvTimeoutError::Timeout) => None,
                                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                            }
                        }
                        None => match received.recv() {
                            Ok(command) => Some(command),
                            Err(_) => break,
                        },
                    };
                    match command {
                        Some(command) => {
                            if !state.handle(command) {
                                break;
                            }
                        }
                        None => {
                            let now = state.now_ms();
                            state.queries.sweep_timed_out(now);
                        }
                    }
                }
            })?;
        let told = commands.clone();
        let sink: LocalFaceSink = std::sync::Arc::new(move |event| {
            let _ = told.send(Command::Told(event));
        });
        Ok((
            Self {
                commands,
                next_subscriber: AtomicU64::new(1),
                thread: Mutex::new(Some(thread)),
            },
            sink,
        ))
    }

    /// Be told of the tokens that meet `pattern`: first those already alive when `history` asks,
    /// then each key as its first token comes alive and as its last goes. The handler runs on the
    /// face's thread. The id answered ends the subscription ([`Self::unsubscribe`]).
    pub fn subscribe(&self, pattern: &str, history: bool, handler: LivelinessHandler) -> u64 {
        let id = self.next_subscriber.fetch_add(1, Ordering::Relaxed);
        let _ = self.commands.send(Command::Subscribe {
            id,
            pattern: pattern.to_owned(),
            history,
            handler,
        });
        id
    }

    /// End the subscription `id`. The handler is not called again once this has returned to a
    /// caller that waits on the face (a later [`Self::alive`] does).
    pub fn unsubscribe(&self, id: u64) {
        let _ = self.commands.send(Command::Unsubscribe(id));
    }

    /// The program declared its token `id` on `keyexpr`.
    pub(super) fn own_up(&self, id: u64, keyexpr: &str) {
        let _ = self.commands.send(Command::OwnUp {
            id,
            keyexpr: keyexpr.to_owned(),
        });
    }

    /// The program retracted its token `id`.
    pub(super) fn own_down(&self, id: u64) {
        let _ = self.commands.send(Command::OwnDown(id));
    }

    /// The keys of the tokens alive that `pattern` meets, those of the program among them. It
    /// waits for the face's thread, so it reads what the face has been told up to now.
    pub fn alive(&self, pattern: &str) -> Vec<String> {
        let (answer, answered) = mpsc::channel();
        let asked = self.commands.send(Command::Alive {
            pattern: pattern.to_owned(),
            answer,
        });
        if asked.is_err() {
            return Vec::new();
        }
        answered.recv().unwrap_or_default()
    }

    /// Watch whether anything of `plane` matches `key` among the declarations `origin` admits:
    /// `handler` is called with `true` at once if it does, and with the new verdict each time it
    /// moves, on the face's thread. The router must have been told to tell the face of its
    /// writes ([`RouterForwarder::watch_matching`]) before this is called. The id answered ends
    /// the watch ([`Self::unwatch`]).
    pub(super) fn watch(
        &self,
        plane: MatchPlane,
        key: &str,
        origin: Locality,
        handler: MatchHandler,
    ) -> u64 {
        let id = self.next_subscriber.fetch_add(1, Ordering::Relaxed);
        let (begun, started) = mpsc::channel();
        let _ = self.commands.send(Command::Watch {
            id,
            plane,
            key: key.to_owned(),
            origin,
            handler,
            begun,
        });
        // A watch that begins on what already matches has told its handler so by the time it
        // is answered, as the declaration of a listener does for a session.
        let _ = started.recv();
        id
    }

    /// End the watch `id`.
    pub(super) fn unwatch(&self, id: u64) {
        let _ = self.commands.send(Command::Unwatch(id));
    }

    /// Hold a query under the request id `rid`, to be handed the replies the router tells the
    /// face for it and told their end. Called before the router is asked, so that no reply finds
    /// the query missing: the face's thread reads its commands in the order they were sent.
    pub(super) fn hold_query(
        &self,
        rid: u64,
        keyexpr: &str,
        accept: ReplyKeyExpr,
        timeout_ms: u32,
        on_reply: ReplyHandler,
        on_final: FinalHandler,
    ) {
        let _ = self.commands.send(Command::Get {
            rid,
            keyexpr: keyexpr.to_owned(),
            accept,
            timeout_ms,
            on_reply,
            on_final,
        });
    }

    /// Stop the face's thread and wait for it.
    pub(super) fn stop(&self) {
        let _ = self.commands.send(Command::Stop);
        let handle = self
            .thread
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex as StdMutex};

    use super::*;

    fn recorder() -> (LivelinessHandler, Arc<StdMutex<Vec<String>>>) {
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let written = seen.clone();
        (
            Box::new(move |sample: LivelinessSample<'_>| {
                written
                    .lock()
                    .unwrap()
                    .push(format!("{:?} {}", sample.kind, sample.keyexpr));
            }),
            seen,
        )
    }

    #[test]
    fn a_key_is_retracted_under_the_id_it_was_told_under_whichever_token_goes_last() {
        let (face, sink) = LocalLiveliness::start(Weak::new()).expect("a thread");
        let told = Arc::new(StdMutex::new(Vec::new()));
        let written = told.clone();
        let handler: LivelinessHandler = Box::new(move |sample: LivelinessSample<'_>| {
            written.lock().unwrap().push(format!(
                "{:?} {} {}",
                sample.kind, sample.keyexpr, sample.token_id
            ));
        });
        up(&face, &sink, 5, "k");
        up(&face, &sink, 6, "k");
        // The history carries the id the key came alive under, and so does the retraction, though
        // the token that goes last is the other one.
        face.subscribe("k", true, handler);
        sink(down(5));
        sink(down(6));
        assert!(face.alive("k").is_empty());
        assert_eq!(*told.lock().unwrap(), ["Put k 5", "Delete k 5"]);
        face.stop();
    }

    /// The router tells the face that the token it numbered `id` is gone.
    fn down(id: u64) -> LocalFaceEvent {
        LocalFaceEvent::TokenDown { id, keyexpr: None }
    }

    #[test]
    fn a_retraction_that_names_only_the_key_ends_every_token_of_the_others_on_it() {
        let (face, sink) = LocalLiveliness::start(Weak::new()).expect("a thread");
        let (handler, seen) = recorder();
        face.subscribe("**", false, handler);
        up(&face, &sink, 1, "k");
        face.own_up(100, "k");
        // The router's one-shot form: id 0 and the key. The program's own token still holds it.
        sink(LocalFaceEvent::TokenDown {
            id: 0,
            keyexpr: Some("k".to_owned()),
        });
        assert_eq!(face.alive("**"), vec!["k".to_owned()]);
        face.own_down(100);
        assert!(face.alive("**").is_empty());
        assert_eq!(*seen.lock().unwrap(), ["Put k", "Delete k"]);
        face.stop();
    }

    /// The router tells the face that a token came alive. The face is passed to name whose sink
    /// it is.
    fn up(_face: &LocalLiveliness, sink: &LocalFaceSink, id: u64, keyexpr: &str) {
        sink(LocalFaceEvent::TokenUp {
            id,
            keyexpr: keyexpr.to_owned(),
        });
    }

    #[test]
    fn a_key_is_told_when_its_first_token_comes_alive_and_its_last_goes() {
        let (face, sink) = LocalLiveliness::start(Weak::new()).expect("a thread");
        let (handler, seen) = recorder();
        face.subscribe("a/**", false, handler);
        up(&face, &sink, 1, "a/b");
        up(&face, &sink, 2, "a/b");
        sink(down(1));
        // Not told: another token holds the key.
        assert_eq!(face.alive("a/**"), vec!["a/b".to_owned()]);
        sink(down(2));
        assert!(face.alive("a/**").is_empty());
        assert_eq!(*seen.lock().unwrap(), ["Put a/b", "Delete a/b"]);
        face.stop();
    }

    #[test]
    fn the_tokens_of_the_program_count_with_the_others_and_history_lists_them() {
        let (face, sink) = LocalLiveliness::start(Weak::new()).expect("a thread");
        up(&face, &sink, 7, "k/remote");
        face.own_up(100, "k/own");
        let (handler, seen) = recorder();
        face.subscribe("k/*", true, handler);
        assert_eq!(face.alive("k/*").len(), 2);
        let mut told = seen.lock().unwrap().clone();
        told.sort();
        assert_eq!(told, ["Put k/own", "Put k/remote"]);
        face.own_down(100);
        assert_eq!(face.alive("k/*"), vec!["k/remote".to_owned()]);
        face.stop();
    }

    #[test]
    fn a_repeated_announcement_of_an_id_counts_once_and_a_retraction_of_a_stranger_does_nothing() {
        let (face, sink) = LocalLiveliness::start(Weak::new()).expect("a thread");
        let (handler, seen) = recorder();
        face.subscribe("**", false, handler);
        up(&face, &sink, 1, "x");
        up(&face, &sink, 1, "x");
        sink(down(99));
        sink(down(1));
        assert!(face.alive("**").is_empty());
        assert_eq!(*seen.lock().unwrap(), ["Put x", "Delete x"]);
        face.stop();
    }

    #[test]
    fn an_unsubscribed_handler_is_not_called_again() {
        let (face, sink) = LocalLiveliness::start(Weak::new()).expect("a thread");
        let (handler, seen) = recorder();
        let id = face.subscribe("**", false, handler);
        up(&face, &sink, 1, "x");
        face.unsubscribe(id);
        up(&face, &sink, 2, "y");
        assert_eq!(face.alive("**").len(), 2);
        assert_eq!(*seen.lock().unwrap(), ["Put x"]);
        face.stop();
    }
}

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
//! Each subscriber is an interest of the face in the router's tables, as the session of a client
//! sends one for each liveliness subscriber it declares: the router answers the tokens alive when
//! the interest is made, if it asks for history, and pushes the ones that come alive after. Which
//! of the two a token is is decided by the router, under the lock its tables are written under,
//! and the face tells a subscriber what the router told it for its interest.
//!
//! The state is what the face has been told: the tokens of the other faces by the id the router
//! numbers them, the tokens the program declared (the router is not told of them for the face),
//! and for each subscriber the keys it counts alive and the tokens it counts on each. A subscriber
//! is told of a key when the first token it counts comes alive on it and of its going when the
//! last is gone, as a client of a router is told by the router's one declaration per key.

use std::collections::{HashMap, HashSet};
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

/// What is done to a reply as the router hands it to the face, before the face's thread reads it:
/// the arrival of a reply is recorded as it is handed over, as upstream's session records it when
/// the dispatcher gives it the reply, and not when the thread of the face gets to it.
pub type ReplyIngress =
    std::sync::Arc<dyn Fn(&mut wz_session_core::wire::ResponseOwned) + Send + Sync + 'static>;

/// The hooks of the queries the face holds, by request id.
type Ingresses = std::sync::Arc<Mutex<HashMap<u64, ReplyIngress>>>;

/// A query the face is asked to hold: what it asks, how its replies are accepted and when it runs
/// out of time, the hook its replies pass through as the router hands them over, and the
/// handlers it is told its replies and its end with.
pub(super) struct QueryHold {
    /// The request id the router is asked under.
    pub(super) rid: u64,
    pub(super) keyexpr: String,
    pub(super) accept: ReplyKeyExpr,
    pub(super) timeout_ms: u32,
    pub(super) ingress: Option<ReplyIngress>,
    pub(super) on_reply: ReplyHandler,
    pub(super) on_final: FinalHandler,
}

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

/// A token the face knows of: one the router told it, by the id the router numbers it, or one the
/// program declared, by the id the router holds it under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Token {
    Remote(u64),
    Own(u64),
}

impl Token {
    fn id(self) -> u64 {
        match self {
            Self::Remote(id) | Self::Own(id) => id,
        }
    }
}

/// A key a subscriber counts alive.
struct Alive {
    /// The id of the token that brought the key alive to the subscriber: what it was told the key
    /// under, and what its retraction carries.
    told: u64,
    /// The tokens the subscriber counts on the key. The key goes when the last of them does.
    tokens: HashSet<Token>,
}

struct Subscriber {
    id: u64,
    pattern: String,
    /// Whether the subscriber asked to be told the tokens that were alive when it asked.
    history: bool,
    handler: LivelinessHandler,
    /// The keys the subscriber counts alive, each with the tokens it counts on it. The tokens
    /// that were alive when it asked are counted whether or not it asked to be told them: a key
    /// that was alive then is not one that comes alive when another token is declared on it.
    alive: HashMap<String, Alive>,
}

impl Subscriber {
    /// `token` is alive on `key`, which the subscriber meets: it counts it, and is told of the key
    /// when this is the first token it counts on it and `tell` is set (the tokens alive when it
    /// asked are told only to a subscriber that asked for them).
    fn learn(&mut self, token: Token, key: &str, tell: bool) {
        let held = self.alive.entry(key.to_owned()).or_insert_with(|| Alive {
            told: token.id(),
            tokens: HashSet::new(),
        });
        let first = held.tokens.is_empty();
        if held.tokens.insert(token) && first && tell {
            let told = held.told;
            (self.handler)(LivelinessSample {
                kind: LivelinessSampleKind::Put,
                keyexpr: key,
                token_id: told,
            });
        }
    }

    /// `gone` are no longer alive on `key`, which the subscriber meets: it is told the key is gone
    /// when it counts no token on it any more, under the id it was told the key under. A
    /// subscriber that was never told of the key is told it is gone all the same, under
    /// `fallback`: it asked for no history, so the token went that it never heard of, which is
    /// what a session is told by upstream's retraction of a token it was never declared.
    fn forget(&mut self, gone: &[Token], key: &str, fallback: u64) {
        let (kind, told) = match self.alive.get_mut(key) {
            Some(held) => {
                for token in gone {
                    held.tokens.remove(token);
                }
                if !held.tokens.is_empty() {
                    return;
                }
                let told = held.told;
                self.alive.remove(key);
                (LivelinessSampleKind::Delete, told)
            }
            None => (LivelinessSampleKind::Delete, fallback),
        };
        (self.handler)(LivelinessSample {
            kind,
            keyexpr: key,
            token_id: told,
        });
    }
}

struct State {
    /// When the face started: the clock the deadlines of its queries are on.
    started: std::time::Instant,
    /// The tokens of the other faces the router has told, by the id it numbers them: the key a
    /// retraction by id is about.
    remote: HashMap<u64, String>,
    /// The tokens the program declared, by the id the router holds them under.
    own: HashMap<u64, String>,
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
            Command::Told(LocalFaceEvent::TokenUp {
                id,
                keyexpr,
                interest,
            }) => {
                // The first announcement of an id wins, as a session's table of remote tokens
                // does: a repeat neither rebinds the id to another key nor is counted twice (a
                // subscriber counts a token once).
                let bound = self.remote.entry(id).or_insert_with(|| keyexpr.clone());
                if *bound == keyexpr {
                    self.learn(Token::Remote(id), &keyexpr, interest);
                }
            }
            Command::Told(LocalFaceEvent::TokenDown { id, keyexpr }) => {
                if let Some(held) = self.remote.remove(&id) {
                    self.forget(&[Token::Remote(id)], &held, id);
                } else if let Some(keyexpr) = keyexpr {
                    // The router says nothing of the other faces backs the key any more, to a
                    // face it never numbered the token for: every token of theirs on it is gone.
                    let gone: Vec<u64> = self
                        .remote
                        .iter()
                        .filter(|(_, held)| **held == keyexpr)
                        .map(|(id, _)| *id)
                        .collect();
                    for id in &gone {
                        self.remote.remove(id);
                    }
                    let gone: Vec<Token> = gone.into_iter().map(Token::Remote).collect();
                    self.forget(&gone, &keyexpr, id);
                }
            }
            Command::OwnUp { id, keyexpr } => {
                self.own.insert(id, keyexpr.clone());
                self.learn(Token::Own(id), &keyexpr, None);
            }
            Command::OwnDown(id) => {
                if let Some(keyexpr) = self.own.remove(&id) {
                    self.forget(&[Token::Own(id)], &keyexpr, id);
                }
            }
            Command::Subscribe {
                id,
                pattern,
                history,
                handler,
            } => {
                let mut sub = Subscriber {
                    id,
                    pattern,
                    history,
                    handler,
                    alive: HashMap::new(),
                };
                // The tokens of the program are the face's own to tell: the router answers the
                // history of the others'. The subscriber counts them, and is told them if it
                // asked for history.
                let mut own: Vec<(&u64, &String)> = self.own.iter().collect();
                own.sort();
                for (token, key) in own {
                    if keyexpr_intersects_text(&sub.pattern, key) {
                        sub.learn(Token::Own(*token), key, history);
                    }
                }
                self.subscribers.push(sub);
            }
            Command::Unsubscribe(id) => {
                self.subscribers.retain(|sub| sub.id != id);
                // The router forgets what it told the face when the face has no interest left,
                // and numbers what it tells it again from the start: a token it told before is
                // not one it will retract.
                if self.subscribers.is_empty() {
                    self.remote.clear();
                }
            }
            Command::Alive { pattern, answer } => {
                let mut keys = self
                    .router
                    .upgrade()
                    .map(|router| router.local_tokens_alive(&pattern))
                    .unwrap_or_default();
                keys.extend(
                    self.own
                        .values()
                        .filter(|key| keyexpr_intersects_text(&pattern, key))
                        .cloned(),
                );
                keys.sort();
                keys.dedup();
                let _ = answer.send(keys);
            }
            Command::Stop => return false,
        }
        true
    }

    /// `token` is alive on `key`. A token the router pushes, or the program declares, is counted
    /// and told by every subscriber that meets the key. One the router answers the current
    /// tokens of an interest with (`interest`) is the answer of that subscriber alone, which
    /// counts it and is told it only if it asked for history: it was alive before the
    /// subscriber, whoever asks.
    fn learn(&mut self, token: Token, key: &str, interest: Option<u64>) {
        for sub in &mut self.subscribers {
            if !keyexpr_intersects_text(&sub.pattern, key) {
                continue;
            }
            match interest {
                None => sub.learn(token, key, true),
                Some(asked) if asked == sub.id => sub.learn(token, key, sub.history),
                Some(_) => {}
            }
        }
    }

    /// `gone` are no longer alive on `key`: each subscriber that meets the key stops counting them.
    /// A key is retracted under the id it was told under, which is not that of the token that was
    /// the last to go: a subscriber counts the key alive by that id, and a retraction under
    /// another would leave it alive.
    fn forget(&mut self, gone: &[Token], key: &str, fallback: u64) {
        for sub in &mut self.subscribers {
            if keyexpr_intersects_text(&sub.pattern, key) {
                sub.forget(gone, key, fallback);
            }
        }
    }
}

/// The face of a router node for liveliness: the program's side of it.
pub struct LocalLiveliness {
    commands: mpsc::Sender<Command>,
    /// What is done to the reply of a held query as the router hands it over.
    ingresses: Ingresses,
    /// The router the subscribers ask for the tokens they are told: each subscriber is an
    /// interest of the face in the router's tables, as the session of a client sends one for each
    /// liveliness subscriber it declares. Gone when the node is.
    router: Weak<RouterForwarder>,
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
        let asked = router.clone();
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
        let ingresses = Ingresses::default();
        let ingressing = std::sync::Arc::clone(&ingresses);
        let sink: LocalFaceSink = std::sync::Arc::new(move |event| {
            // A reply of a query that asked for it is completed here, on the thread that hands it
            // over, before it waits in the queue of the face.
            let event = match event {
                LocalFaceEvent::Reply(mut response) => {
                    let hook = ingressing
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .get(&response.request_id)
                        .cloned();
                    if let Some(hook) = hook {
                        hook(&mut response);
                    }
                    LocalFaceEvent::Reply(response)
                }
                other => other,
            };
            let _ = told.send(Command::Told(event));
        });
        Ok((
            Self {
                commands,
                ingresses,
                router: asked,
                next_subscriber: AtomicU64::new(1),
                thread: Mutex::new(Some(thread)),
            },
            sink,
        ))
    }

    /// Be told of the tokens that meet `pattern`: first those already alive when `history` asks,
    /// then each key as its first token comes alive and as its last goes. The handler runs on the
    /// face's thread. The id answered ends the subscription ([`Self::unsubscribe`]).
    ///
    /// The subscriber is held by the face first, and the router is asked for its tokens after:
    /// what the router then tells arrives behind the subscriber on the face's queue, and which of
    /// the tokens are history and which come after is decided by the router's tables, where the
    /// interest is stored and answered under one lock, and not by the order two queues are read.
    /// A token declared before the call that returns is history: the subscriber counts it, and is
    /// told it only when `history` asks. One declared after is told. The router is asked for the
    /// current tokens whatever `history` says, so that the subscriber knows which keys were alive
    /// when it asked: a token declared on one of them by another node later is not a key that
    /// comes alive.
    pub fn subscribe(&self, pattern: &str, history: bool, handler: LivelinessHandler) -> u64 {
        let id = self.next_subscriber.fetch_add(1, Ordering::Relaxed);
        let _ = self.commands.send(Command::Subscribe {
            id,
            pattern: pattern.to_owned(),
            history,
            handler,
        });
        if let Some(router) = self.router.upgrade() {
            router.ask_local_tokens(id, pattern, true);
        }
        id
    }

    /// End the subscription `id`. The handler is not called again once this has returned to a
    /// caller that waits on the face (a later [`Self::alive`] does).
    ///
    /// The router is told first: it tells the face nothing for the interest from then on, so what
    /// it told before is ahead of the subscriber's end on the face's queue.
    pub fn unsubscribe(&self, id: u64) {
        if let Some(router) = self.router.upgrade() {
            router.forget_local_tokens(id);
        }
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
    pub(super) fn hold_query(&self, hold: QueryHold) {
        let QueryHold {
            rid,
            keyexpr,
            accept,
            timeout_ms,
            ingress,
            on_reply,
            mut on_final,
        } = hold;
        // The hook is held from here to the end of the query, and is in place before the router
        // is asked, so that no reply is handed over without it.
        let on_final: FinalHandler = match ingress {
            Some(ingress) => {
                self.ingresses
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(rid, ingress);
                let ingresses = std::sync::Arc::clone(&self.ingresses);
                Box::new(move || {
                    ingresses
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&rid);
                    on_final();
                })
            }
            None => on_final,
        };
        let _ = self.commands.send(Command::Get {
            rid,
            keyexpr,
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
        face.subscribe("k", false, handler);
        up(&face, &sink, 5, "k");
        up(&face, &sink, 6, "k");
        // The key was told under the id it came alive under, and so is its retraction, though
        // the token that goes last is the other one.
        sink(down(5));
        sink(down(6));
        settle(&face);
        assert_eq!(*told.lock().unwrap(), ["Put k 5", "Delete k 5"]);
        face.stop();
    }

    /// The hook of a query runs on the thread that hands the reply over, ahead of the face's
    /// thread reading it, and goes with the query's end: a reply the router tells afterwards is
    /// not passed through it.
    #[test]
    fn a_reply_is_completed_on_the_thread_that_hands_it_over_until_the_query_ends() {
        let (face, sink) = LocalLiveliness::start(Weak::new()).expect("a thread");
        let log = Arc::new(StdMutex::new(Vec::<String>::new()));
        let caller = std::thread::current().id();
        let hooked = log.clone();
        let ingress: ReplyIngress = Arc::new(move |_response| {
            hooked.lock().unwrap().push(format!(
                "hook on the caller: {}",
                std::thread::current().id() == caller
            ));
        });
        let replied = log.clone();
        let finished = log.clone();
        face.hold_query(QueryHold {
            rid: 7,
            keyexpr: "demo/q".to_owned(),
            accept: ReplyKeyExpr::MatchingQuery,
            timeout_ms: 0,
            ingress: Some(ingress),
            on_reply: Box::new(move |_view| replied.lock().unwrap().push("reply".to_owned())),
            on_final: Box::new(move || finished.lock().unwrap().push("final".to_owned())),
        });
        let response =
            wz_session_core::response_build::build_response_reply_literal(7, "demo/q", b"hi")
                .expect("build a response");
        sink(LocalFaceEvent::Reply(Box::new(response.clone())));
        sink(LocalFaceEvent::ReplyFinal { request_id: 7 });
        settle(&face);
        sink(LocalFaceEvent::Reply(Box::new(response)));
        settle(&face);
        assert_eq!(
            *log.lock().unwrap(),
            ["hook on the caller: true", "reply", "final"]
        );
        face.stop();
    }

    /// Wait for the face's thread to have read what it was sent so far.
    fn settle(face: &LocalLiveliness) {
        let _ = face.alive("**");
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
            interest: None,
        });
    }

    /// The router answers the history of the interest `interest` with a token.
    fn answer(sink: &LocalFaceSink, interest: u64, id: u64, keyexpr: &str) {
        sink(LocalFaceEvent::TokenUp {
            id,
            keyexpr: keyexpr.to_owned(),
            interest: Some(interest),
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
        settle(&face);
        assert_eq!(*seen.lock().unwrap(), ["Put a/b"]);
        sink(down(2));
        settle(&face);
        assert_eq!(*seen.lock().unwrap(), ["Put a/b", "Delete a/b"]);
        face.stop();
    }

    #[test]
    fn the_tokens_of_the_program_count_with_the_others_and_history_lists_them() {
        let (face, sink) = LocalLiveliness::start(Weak::new()).expect("a thread");
        face.own_up(100, "k/own");
        let (handler, seen) = recorder();
        let asked = face.subscribe("k/*", true, handler);
        // The router answers the history of the others' tokens, to the subscriber that asked.
        answer(&sink, asked, 7, "k/remote");
        assert_eq!(face.alive("k/*"), vec!["k/own".to_owned()]);
        let mut told = seen.lock().unwrap().clone();
        told.sort();
        assert_eq!(told, ["Put k/own", "Put k/remote"]);
        face.own_down(100);
        settle(&face);
        assert_eq!(seen.lock().unwrap().last().unwrap(), "Delete k/own");
        face.stop();
    }

    #[test]
    fn a_key_the_program_and_the_router_both_hold_is_told_once() {
        let (face, sink) = LocalLiveliness::start(Weak::new()).expect("a thread");
        face.own_up(100, "k");
        let (handler, seen) = recorder();
        let asked = face.subscribe("k", true, handler);
        answer(&sink, asked, 7, "k");
        face.own_down(100);
        settle(&face);
        // The router's token still holds the key.
        assert_eq!(*seen.lock().unwrap(), ["Put k"]);
        sink(down(7));
        settle(&face);
        assert_eq!(*seen.lock().unwrap(), ["Put k", "Delete k"]);
        face.stop();
    }

    #[test]
    fn the_answer_to_an_interest_is_history_told_only_to_a_subscriber_that_asked_for_it() {
        let (face, sink) = LocalLiveliness::start(Weak::new()).expect("a thread");
        let (without, seen_without) = recorder();
        let (with, seen_with) = recorder();
        let plain = face.subscribe("**", false, without);
        let asked = face.subscribe("**", true, with);
        // Each subscriber is its own interest, and the router answers each of them with what was
        // alive when it asked.
        answer(&sink, plain, 1, "x");
        answer(&sink, asked, 1, "x");
        up(&face, &sink, 2, "y");
        // Another token on a key that was alive when the subscribers asked does not bring it alive.
        up(&face, &sink, 3, "x");
        settle(&face);
        assert_eq!(*seen_without.lock().unwrap(), ["Put y"]);
        assert_eq!(*seen_with.lock().unwrap(), ["Put x", "Put y"]);
        face.stop();
    }

    #[test]
    fn an_answer_to_one_interest_is_not_the_answer_of_another() {
        let (face, sink) = LocalLiveliness::start(Weak::new()).expect("a thread");
        let (first, seen_first) = recorder();
        let (second, seen_second) = recorder();
        let one = face.subscribe("**", true, first);
        face.subscribe("**", true, second);
        answer(&sink, one, 1, "x");
        settle(&face);
        assert_eq!(*seen_first.lock().unwrap(), ["Put x"]);
        assert!(seen_second.lock().unwrap().is_empty());
        face.stop();
    }

    #[test]
    fn a_key_alive_when_a_subscriber_asked_is_told_gone_to_it_whatever_its_history() {
        let (face, sink) = LocalLiveliness::start(Weak::new()).expect("a thread");
        let (without, seen_without) = recorder();
        let (with, seen_with) = recorder();
        let plain = face.subscribe("**", false, without);
        let asked = face.subscribe("**", true, with);
        answer(&sink, plain, 1, "x");
        answer(&sink, asked, 1, "x");
        sink(down(1));
        settle(&face);
        assert_eq!(*seen_without.lock().unwrap(), ["Delete x"]);
        assert_eq!(*seen_with.lock().unwrap(), ["Put x", "Delete x"]);
        face.stop();
    }

    #[test]
    fn a_retraction_by_key_reaches_a_subscriber_that_never_counted_the_token() {
        let (face, sink) = LocalLiveliness::start(Weak::new()).expect("a thread");
        let (handler, seen) = recorder();
        face.subscribe("**", false, handler);
        // Upstream tells a session that a token it was never declared is gone.
        sink(LocalFaceEvent::TokenDown {
            id: 0,
            keyexpr: Some("x".to_owned()),
        });
        settle(&face);
        assert_eq!(*seen.lock().unwrap(), ["Delete x"]);
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
        settle(&face);
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
        settle(&face);
        assert_eq!(*seen.lock().unwrap(), ["Put x"]);
        face.stop();
    }

    #[test]
    fn a_face_with_no_subscriber_left_binds_the_ids_the_router_numbers_afresh() {
        let (face, sink) = LocalLiveliness::start(Weak::new()).expect("a thread");
        let (first, _seen_first) = recorder();
        let id = face.subscribe("**", false, first);
        up(&face, &sink, 1, "old");
        face.unsubscribe(id);
        // The router numbers from the start again once the face has no interest: an id it used
        // for one key is a later key's, and the face does not hold the earlier binding to it.
        let (second, seen_second) = recorder();
        face.subscribe("**", false, second);
        up(&face, &sink, 1, "new");
        settle(&face);
        assert_eq!(*seen_second.lock().unwrap(), ["Put new"]);
        face.stop();
    }
}

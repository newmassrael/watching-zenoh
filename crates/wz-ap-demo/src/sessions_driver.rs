// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `driver` key of a `--sessions` session: the traffic one session of the
//! process generates, attached to the session the document names.
//!
//! # What it is for
//!
//! `--sessions` starts several sessions and, until this key, none of them did
//! anything once it was up: a harness that wanted traffic on `to_router` had to
//! start a second process. A session that carries a `driver` runs its roles on
//! that session, in the same process, under the name the document gave it:
//!
//! ```text
//! sessions: [
//!   { name: "to_router", mode: "client", transport: "unicast",
//!     connect: { endpoints: ["tcp/192.0.2.10:7447"] },
//!     driver: [
//!       { role: "subscribe", key: "demo/in/**" },
//!       { role: "answer",    key: "demo/q",   reply: "pong" },
//!       { role: "publish",   key: "demo/out", payload: "tick", period_ms: 1000, count: 5 },
//!       { role: "put",       key: "demo/one", payload: "x" },
//!       { role: "delete",    key: "demo/one" },
//!       { role: "get",       key: "demo/q",   timeout_ms: 2000, after_ms: 500 },
//!       // `after_ms`, on any role: hold it that long once the session is up.
//!     ] },
//! ]
//! ```
//!
//! The roles of this version are `publish`, `put`, `delete`, `subscribe`, `get`
//! and `answer`. The others a consumer drives (scouting, liveliness, groups,
//! pull, forwarding, the advanced publisher and subscriber) are not here, and a
//! document that names one is refused by its key path rather than ignored.
//!
//! # Why it is not one of the deploy keys
//!
//! `scripts/lib/deploy_sessions.py` describes a deploy machine, and a driver is
//! not part of one: it is what a test harness asks this process to do. The key is
//! therefore stripped before the shared rules run (see [`without_local_keys`]), so
//! the rule set and its parity with the validator are exactly what they were, and
//! the validator keeps refusing a deploy document that carries one.
//!
//! # What a role prints
//!
//! One line each, to stderr whatever `RUST_LOG` says, beginning
//! `wz-ap-demo session <name>: DRIVER <role>`, so a harness waits on them as it
//! waits on `READY`. Nothing is routed between sessions: a sample one session's
//! driver publishes reaches another session only through whatever the links carry.

#[cfg(test)]
use std::collections::BTreeSet;
use std::time::Duration;

use wz::runtime_tokio::json5::Json5Value;
use wz::runtime_tokio::sample::SampleKind;
use wz::runtime_tokio::session::{
    PublishOptions, QueryOptions, QueryableOptions, SubscribeOptions, TokioSession,
};
use wz::runtime_tokio::Reliability;

use crate::sessions::{as_str, field, has, key_set, positive_int, Refusal};

/// How long a role waits for its session to be Established before it gives up.
const ESTABLISHED_WAIT: Duration = Duration::from_secs(10);
/// How often a role looks at whether its session is Established yet.
const ESTABLISHED_POLL: Duration = Duration::from_millis(10);

/// The keys a driver entry may carry, over every role.
const DRIVER_KEYS: &[&str] = &[
    "role",
    "key",
    "payload",
    "period_ms",
    "count",
    "reply",
    "timeout_ms",
    "after_ms",
];

/// How long a `get` waits for its replies when the document names no timeout.
pub(crate) const DEFAULT_GET_TIMEOUT_MS: u64 = 3_000;

/// One role a session's driver plays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DriverRole {
    /// Put `payload` under `key` every `period_ms`, `count` times (until the
    /// process stops when `count` is absent).
    Publish {
        key: String,
        payload: String,
        period_ms: u64,
        count: Option<u64>,
    },
    /// Put `payload` under `key` once.
    Put { key: String, payload: String },
    /// Delete `key` once.
    Delete { key: String },
    /// Hold a subscriber on `key`, printing each sample.
    Subscribe { key: String },
    /// Ask `key` once and print each reply, waiting at most `timeout_ms`.
    Get { key: String, timeout_ms: u64 },
    /// Hold a queryable on `key` that answers every query with `reply`.
    Answer { key: String, reply: String },
}

/// One entry of a session's `driver`: a role and when it starts.
///
/// `after_ms` holds the role that long after the session is Established (0 starts
/// it at once), and it is common to every role. The declarations a peer makes are
/// still arriving when the session opens, so a put, a delete or a question issued
/// at that instant goes to a peer whose subscriber or queryable it has not yet
/// heard of, and is lost without anyone being told: the hold is the document's
/// form of `--query-after-ms`. A harness that drives a node it has just connected
/// to says how long it lets the link settle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DriverEntry {
    pub(crate) role: DriverRole,
    pub(crate) after_ms: u64,
}

impl DriverRole {
    /// The word the document names this role by, and a line names it by.
    pub(crate) fn word(&self) -> &'static str {
        match self {
            DriverRole::Publish { .. } => "publish",
            DriverRole::Put { .. } => "put",
            DriverRole::Delete { .. } => "delete",
            DriverRole::Subscribe { .. } => "subscribe",
            DriverRole::Get { .. } => "get",
            DriverRole::Answer { .. } => "answer",
        }
    }
}

/// The keys each role takes beside `role` and `key`, and `after_ms`, which every
/// role takes (see [`DriverEntry`]).
fn role_keys(role: &str) -> Option<&'static [&'static str]> {
    Some(match role {
        "publish" => &["payload", "period_ms", "count", "after_ms"],
        "put" => &["payload", "after_ms"],
        "delete" => &["after_ms"],
        "subscribe" => &["after_ms"],
        "get" => &["timeout_ms", "after_ms"],
        "answer" => &["reply", "after_ms"],
        _ => return None,
    })
}

/// The session keys only this process knows: the validator has neither.
const LOCAL_KEYS: &[&str] = &["driver", "scouting"];

/// The document with every session's local keys (`driver`, and `scouting` of
/// [`crate::sessions_scouting`]) removed: what the shared rules read.
///
/// The rules are the validator's and the two are held to one case file, so a key
/// only this process knows is taken out before they run and judged here instead.
pub(crate) fn without_local_keys(doc: &Json5Value) -> Json5Value {
    let Json5Value::Object(top) = doc else {
        return doc.clone();
    };
    Json5Value::Object(
        top.iter()
            .map(|(key, value)| match (key.as_str(), value) {
                ("sessions", Json5Value::Array(items)) => (
                    key.clone(),
                    Json5Value::Array(
                        items
                            .iter()
                            .map(|item| match item {
                                Json5Value::Object(entries) => Json5Value::Object(
                                    entries
                                        .iter()
                                        .filter(|(k, _)| !LOCAL_KEYS.contains(&k.as_str()))
                                        .cloned()
                                        .collect(),
                                ),
                                other => other.clone(),
                            })
                            .collect(),
                    ),
                ),
                _ => (key.clone(), value.clone()),
            })
            .collect(),
    )
}

/// Every refusal the `driver` keys of a document earn, by key path.
pub(crate) fn driver_refusals(doc: &Json5Value) -> Vec<Refusal> {
    let mut out = Vec::new();
    let Json5Value::Object(top) = doc else {
        return out;
    };
    let Some(Json5Value::Array(sessions)) = field(top, "sessions") else {
        return out;
    };
    for (i, session) in sessions.iter().enumerate() {
        let Json5Value::Object(entries) = session else {
            continue;
        };
        if !has(entries, "driver") {
            continue;
        }
        let path = format!("sessions[{i}].driver");
        if field(entries, "transport").and_then(as_str) == Some("multicast") {
            out.push(Refusal::new(
                path,
                "a multicast session takes no driver in this version; the roles run on a \
                 unicast session",
            ));
            continue;
        }
        let Some(Json5Value::Array(roles)) = field(entries, "driver") else {
            out.push(Refusal::new(path, "must be a list of roles"));
            continue;
        };
        for (j, role) in roles.iter().enumerate() {
            role_refusals(&format!("{path}[{j}]"), role, &mut out);
        }
    }
    out
}

fn role_refusals(path: &str, role: &Json5Value, out: &mut Vec<Refusal>) {
    let Json5Value::Object(entry) = role else {
        out.push(Refusal::new(path, "must be a mapping"));
        return;
    };
    for key in key_set(entry) {
        if !DRIVER_KEYS.contains(&key) {
            out.push(Refusal::new(format!("{path}.{key}"), "unknown key"));
        }
    }
    let word = field(entry, "role").and_then(as_str);
    let Some(allowed) = word.and_then(role_keys) else {
        out.push(Refusal::new(
            format!("{path}.role"),
            "required: publish, put, delete, subscribe, get or answer",
        ));
        return;
    };
    let word = word.unwrap_or_default();
    for key in key_set(entry) {
        if DRIVER_KEYS.contains(&key) && !["role", "key"].contains(&key) && !allowed.contains(&key)
        {
            out.push(Refusal::new(
                format!("{path}.{key}"),
                format!("not a key of the `{word}` role"),
            ));
        }
    }
    match field(entry, "key").and_then(as_str) {
        Some(k) if !k.is_empty() && !k.contains(char::is_whitespace) => {}
        _ => out.push(Refusal::new(
            format!("{path}.key"),
            "required, a keyexpr with no whitespace",
        )),
    }
    let needs_text = |name: &str, out: &mut Vec<Refusal>| {
        if field(entry, name).and_then(as_str).is_none() {
            out.push(Refusal::new(format!("{path}.{name}"), "required, a string"));
        }
    };
    let optional_int = |name: &str, out: &mut Vec<Refusal>| {
        if has(entry, name) && field(entry, name).and_then(positive_int).is_none() {
            out.push(Refusal::new(
                format!("{path}.{name}"),
                "must be a positive integer",
            ));
        }
    };
    match word {
        "publish" => {
            needs_text("payload", out);
            if field(entry, "period_ms").and_then(positive_int).is_none() {
                out.push(Refusal::new(
                    format!("{path}.period_ms"),
                    "required, a positive integer of milliseconds",
                ));
            }
            optional_int("count", out);
        }
        "put" => needs_text("payload", out),
        "answer" => needs_text("reply", out),
        "get" => optional_int("timeout_ms", out),
        _ => {}
    }
    optional_int("after_ms", out);
}

/// The roles a session's `driver` names. Only called for a document the rules and
/// [`driver_refusals`] passed, so a malformed entry is skipped and never reached.
pub(crate) fn roles_of(session: &[(String, Json5Value)]) -> Vec<DriverEntry> {
    let Some(Json5Value::Array(items)) = field(session, "driver") else {
        return Vec::new();
    };
    let mut roles = Vec::new();
    for item in items {
        let Json5Value::Object(entry) = item else {
            continue;
        };
        let text = |name: &str| {
            field(entry, name)
                .and_then(as_str)
                .unwrap_or_default()
                .to_string()
        };
        let int = |name: &str| field(entry, name).and_then(positive_int);
        let key = text("key");
        let role = match field(entry, "role").and_then(as_str) {
            Some("publish") => DriverRole::Publish {
                key,
                payload: text("payload"),
                period_ms: int("period_ms").unwrap_or(1),
                count: int("count"),
            },
            Some("put") => DriverRole::Put {
                key,
                payload: text("payload"),
            },
            Some("delete") => DriverRole::Delete { key },
            Some("subscribe") => DriverRole::Subscribe { key },
            Some("get") => DriverRole::Get {
                key,
                timeout_ms: int("timeout_ms").unwrap_or(DEFAULT_GET_TIMEOUT_MS),
            },
            Some("answer") => DriverRole::Answer {
                key,
                reply: text("reply"),
            },
            _ => continue,
        };
        roles.push(DriverEntry {
            role,
            after_ms: int("after_ms").unwrap_or(0),
        });
    }
    roles
}

/// Start every role of `roles` on `session`, each as its own task of the local
/// set, and hand back the tasks so the caller can end them.
///
/// The caller MUST end them (abort, then await) before it drops the session's
/// last clone: a role holds a clone, and the writer's last-sender invariant
/// (`crate::teardown`) is that the session outlives nothing that sends on it.
pub(crate) fn start(
    name: &str,
    session: &TokioSession,
    roles: &[DriverEntry],
) -> Vec<tokio::task::JoinHandle<()>> {
    roles
        .iter()
        .cloned()
        .map(|entry| {
            let (name, session) = (name.to_string(), session.clone());
            tokio::task::spawn_local(async move { play(&name, &session, entry).await })
        })
        .collect()
}

/// One line of a role, in the shape a harness waits on.
fn say(name: &str, role: &str, what: &str) {
    eprintln!("wz-ap-demo session {name}: DRIVER {role} {what}");
}

/// Wait until the session is Established, or say why the role never ran.
async fn established(name: &str, role: &str, session: &TokioSession) -> bool {
    let waited = tokio::time::timeout(ESTABLISHED_WAIT, async {
        while !session.actions().is_established() {
            tokio::time::sleep(ESTABLISHED_POLL).await;
        }
    })
    .await;
    if waited.is_err() {
        say(
            name,
            role,
            &format!(
                "gave up: the session was not Established within {}s",
                ESTABLISHED_WAIT.as_secs()
            ),
        );
    }
    waited.is_ok()
}

/// One put or delete on `key`, said in a line.
fn emit(name: &str, session: &TokioSession, role: &str, key: &str, kind: SampleKind, bytes: &[u8]) {
    let mut options = PublishOptions::default().with_reliability(Reliability::Reliable);
    options.kind = kind;
    match session.publish(key, bytes, options) {
        Ok(_) => say(name, role, &format!("sent key={key} bytes={}", bytes.len())),
        Err(e) => say(name, role, &format!("refused key={key}: {e}")),
    }
}

/// Play one role to its end. A role that holds something (a subscriber, a
/// queryable) holds it until the task is aborted at the session's end.
async fn play(name: &str, session: &TokioSession, entry: DriverEntry) {
    let DriverEntry { role, after_ms } = entry;
    let word = role.word();
    if !established(name, word, session).await {
        return;
    }
    // The hold the entry asked for, after the session is up: see [`DriverEntry`].
    if after_ms > 0 {
        tokio::time::sleep(Duration::from_millis(after_ms)).await;
    }
    match role {
        DriverRole::Publish {
            key,
            payload,
            period_ms,
            count,
        } => {
            let mut sent = 0u64;
            while count.map_or(true, |n| sent < n) {
                emit(
                    name,
                    session,
                    word,
                    &key,
                    SampleKind::Put,
                    payload.as_bytes(),
                );
                sent += 1;
                tokio::time::sleep(Duration::from_millis(period_ms)).await;
            }
            say(name, word, &format!("done key={key} count={sent}"));
        }
        DriverRole::Put { key, payload } => {
            emit(
                name,
                session,
                word,
                &key,
                SampleKind::Put,
                payload.as_bytes(),
            );
        }
        DriverRole::Delete { key } => {
            emit(name, session, word, &key, SampleKind::Del, &[]);
        }
        DriverRole::Subscribe { key } => {
            let seen = name.to_string();
            let declared = session.declare_subscriber(
                key.clone(),
                SubscribeOptions::default(),
                move |sample| {
                    say(
                        &seen,
                        "subscribe",
                        &format!(
                            "sample key={} kind={:?} bytes={}",
                            sample.keyexpr(),
                            sample.kind(),
                            sample.payload().len()
                        ),
                    );
                },
            );
            match declared {
                Ok(_held) => {
                    say(name, word, &format!("declared key={key}"));
                    std::future::pending::<()>().await;
                }
                Err(e) => say(name, word, &format!("refused key={key}: {e}")),
            }
        }
        DriverRole::Answer { key, reply } => {
            let seen = name.to_string();
            let declared = session.declare_queryable(
                key.clone(),
                QueryableOptions::default(),
                move |query, responder| {
                    responder.reply(reply.as_bytes());
                    say(
                        &seen,
                        "answer",
                        &format!("replied key={} bytes={}", query.keyexpr(), reply.len()),
                    );
                },
            );
            match declared {
                Ok(_held) => {
                    say(name, word, &format!("declared key={key}"));
                    std::future::pending::<()>().await;
                }
                Err(e) => say(name, word, &format!("refused key={key}: {e}")),
            }
        }
        DriverRole::Get { key, timeout_ms } => {
            let (replies, finals) = (name.to_string(), name.to_string());
            let timeout = u32::try_from(timeout_ms).unwrap_or(u32::MAX);
            let asked = session.query(
                &key,
                QueryOptions::default().with_timeout_ms(timeout),
                move |reply| {
                    say(
                        &replies,
                        "get",
                        &format!(
                            "reply key={} kind={:?} bytes={}",
                            reply.keyexpr(),
                            reply.kind(),
                            reply.payload().len()
                        ),
                    );
                },
                move |_rid| say(&finals, "get", "final"),
            );
            match asked {
                Ok(_) => {
                    say(name, word, &format!("asked key={key}"));
                    std::future::pending::<()>().await;
                }
                Err(e) => say(name, word, &format!("refused key={key}: {e}")),
            }
        }
    }
}

/// The names of the roles this version plays, for a refusal or a usage line.
#[cfg(test)]
pub(crate) fn role_words() -> BTreeSet<&'static str> {
    ["publish", "put", "delete", "subscribe", "get", "answer"]
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz::runtime_tokio::json5;

    fn refused(text: &str) -> Vec<String> {
        let doc = json5::parse(text).expect("the document parses");
        driver_refusals(&doc)
            .into_iter()
            .map(|r| r.to_string())
            .collect()
    }

    const ONE: &str = r#"{ sessions: [ { name: "a", mode: "client", transport: "unicast",
        connect: { endpoints: ["tcp/127.0.0.1:7447"] }, driver: [ ROLE ] } ] }"#;

    fn with_role(role: &str) -> String {
        ONE.replace("ROLE", role)
    }

    /// Every role this version plays is accepted in its full form and read into
    /// the role it names.
    #[test]
    fn every_role_is_accepted_and_read_into_itself() {
        let doc = json5::parse(&with_role(
            r#"{ role: "publish", key: "d/p", payload: "x", period_ms: 5, count: 3 },
               { role: "put", key: "d/u", payload: "y", after_ms: 7 },
               { role: "delete", key: "d/u" },
               { role: "subscribe", key: "d/**" },
               { role: "get", key: "d/q", timeout_ms: 9, after_ms: 4 },
               { role: "answer", key: "d/q", reply: "z" }"#,
        ))
        .expect("parses");
        assert_eq!(driver_refusals(&doc), Vec::new());
        let Json5Value::Object(top) = &doc else {
            panic!("an object");
        };
        let Some(Json5Value::Array(sessions)) = field(top, "sessions") else {
            panic!("sessions");
        };
        let Json5Value::Object(session) = &sessions[0] else {
            panic!("a session");
        };
        let roles = roles_of(session);
        let words: BTreeSet<&str> = roles.iter().map(|e| e.role.word()).collect();
        assert_eq!(words, role_words());
        assert_eq!(
            roles[0],
            DriverEntry {
                role: DriverRole::Publish {
                    key: "d/p".into(),
                    payload: "x".into(),
                    period_ms: 5,
                    count: Some(3),
                },
                after_ms: 0,
            }
        );
        // The hold is common to every role, and absent means none.
        assert_eq!(roles[1].after_ms, 7, "a put takes it");
        assert_eq!(
            roles[2].after_ms, 0,
            "and a role that names none starts at once"
        );
        assert_eq!(
            roles[4],
            DriverEntry {
                role: DriverRole::Get {
                    key: "d/q".into(),
                    timeout_ms: 9,
                },
                after_ms: 4,
            }
        );
    }

    /// A refusal names the key it is about, and a role that is not played here is
    /// refused rather than skipped.
    #[test]
    fn a_refusal_names_the_key_and_an_unplayed_role_is_refused() {
        assert_eq!(
            refused(&with_role(r#"{ role: "liveliness_token", key: "d/t" }"#)),
            vec!["sessions[0].driver[0].role: required: publish, put, delete, subscribe, get or answer"]
        );
        assert_eq!(
            refused(&with_role(
                r#"{ role: "publish", key: "d/p", payload: "x" }"#
            )),
            vec!["sessions[0].driver[0].period_ms: required, a positive integer of milliseconds"]
        );
        assert_eq!(
            refused(&with_role(
                r#"{ role: "delete", key: "d/u", payload: "x" }"#
            )),
            vec!["sessions[0].driver[0].payload: not a key of the `delete` role"]
        );
        assert_eq!(
            refused(&with_role(
                r#"{ role: "put", key: "", payload: "x", color: 1 }"#
            )),
            vec![
                "sessions[0].driver[0].color: unknown key",
                "sessions[0].driver[0].key: required, a keyexpr with no whitespace",
            ]
        );
        assert_eq!(
            refused(&with_role(r#"{ role: "answer", key: "d/q" }"#)),
            vec!["sessions[0].driver[0].reply: required, a string"]
        );
        assert_eq!(
            refused(&with_role(r#"{ role: "get", key: "d/q", timeout_ms: 0 }"#)),
            vec!["sessions[0].driver[0].timeout_ms: must be a positive integer"]
        );
        // The hold before a question is optional, and a zero is spelled by leaving
        // it out.
        assert_eq!(
            refused(&with_role(r#"{ role: "get", key: "d/q", after_ms: 0 }"#)),
            vec!["sessions[0].driver[0].after_ms: must be a positive integer"]
        );
        assert!(refused(&with_role(r#"{ role: "get", key: "d/q", after_ms: 5 }"#)).is_empty());
    }

    /// A multicast session takes no driver, and a `driver` that is not a list is
    /// refused at the key.
    #[test]
    fn a_multicast_session_and_a_non_list_driver_are_refused() {
        assert_eq!(
            refused(
                r#"{ sessions: [ { name: "g", mode: "peer", transport: "multicast",
                    group: { endpoint: "udp/224.0.0.224:7446" },
                    driver: [ { role: "delete", key: "d/u" } ] } ] }"#
            ),
            vec![
                "sessions[0].driver: a multicast session takes no driver in this version; \
                 the roles run on a unicast session"
            ]
        );
        assert_eq!(
            refused(
                r#"{ sessions: [ { name: "a", mode: "client", transport: "unicast",
                    connect: { endpoints: ["tcp/127.0.0.1:7447"] }, driver: "put" } ] }"#
            ),
            vec!["sessions[0].driver: must be a list of roles"]
        );
    }

    /// `without_local_keys` leaves everything else of the document alone, which is
    /// what keeps the shared rules and the validator's case file the same.
    #[test]
    fn removing_the_drivers_changes_nothing_else() {
        let with = json5::parse(&with_role(r#"{ role: "delete", key: "d/u" }"#)).expect("parses");
        let without = json5::parse(
            r#"{ sessions: [ { name: "a", mode: "client", transport: "unicast",
                connect: { endpoints: ["tcp/127.0.0.1:7447"] } } ] }"#,
        )
        .expect("parses");
        assert_eq!(without_local_keys(&with), without);
    }
}

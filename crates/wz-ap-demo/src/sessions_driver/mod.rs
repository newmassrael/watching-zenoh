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
//! The roles are the words of [`roles::ROLES`], one module each under `roles/`.
//! A role that needs a build feature the binary was built without is refused by
//! key path rather than skipped.
//!
//! # A role is a key table and a function
//!
//! Every role is one [`RoleDef`]: the word the document names it by, the keys it
//! takes ([`KeyDef`], each with its kind and whether it is required), the build
//! feature it needs, an optional cross-key rule, and the function that plays it.
//! The rules below are written once for all of them, so a role adds no
//! validation code of its own:
//!
//! * a key no role knows is `unknown key`; a key some other role knows is
//!   `not a key of the (role) role`, with the role's word in the parentheses;
//! * each key is read by its kind and refused with the sentence of that kind;
//! * `after_ms` is every role's: the hold after the session is Established;
//! * a role's own rule ([`RoleDef::check`]) runs only once every key read well.
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

pub(crate) mod roles;

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use wz::runtime_tokio::json5::Json5Value;
use wz::runtime_tokio::sample::SampleKind;
use wz::runtime_tokio::session::{PublishOptions, TokioSession};
use wz::runtime_tokio::Reliability;

use crate::sessions::{as_str, field, has, key_set, positive_int, Refusal};

use roles::ROLES;

/// How long a role waits for its session to be Established before it gives up.
const ESTABLISHED_WAIT: Duration = Duration::from_secs(10);
/// How often a role looks at whether its session is Established yet.
const ESTABLISHED_POLL: Duration = Duration::from_millis(10);

/// The key every role takes beside its own: how long to hold it once the session
/// is up. The declarations a peer makes are still arriving when the session
/// opens, so a put, a delete or a question issued at that instant goes to a peer
/// whose subscriber or queryable it has not yet heard of, and is lost without
/// anyone being told: the hold is the document's form of `--query-after-ms`. A
/// harness that drives a node it has just connected to says how long it lets the
/// link settle. Absent means none.
const AFTER_MS: &str = "after_ms";

/// How a key is read, and so how a refusal about it is worded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyKind {
    /// A keyexpr with no whitespace.
    Keyexpr,
    /// Any string.
    Text,
    /// A positive integer of milliseconds.
    Millis,
    /// A positive integer.
    Count,
    /// `true` or `false`.
    Flag,
    /// One of these words.
    Word(&'static [&'static str]),
}

/// One key a role takes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KeyDef {
    pub(crate) name: &'static str,
    pub(crate) kind: KeyKind,
    pub(crate) required: bool,
    /// The value an integer key takes when the document names none.
    pub(crate) default: Option<u64>,
}

impl KeyDef {
    /// A key the document must name.
    pub(crate) const fn required(name: &'static str, kind: KeyKind) -> Self {
        KeyDef {
            name,
            kind,
            required: true,
            default: None,
        }
    }

    /// A key the document may leave out.
    pub(crate) const fn optional(name: &'static str, kind: KeyKind) -> Self {
        KeyDef {
            name,
            kind,
            required: false,
            default: None,
        }
    }

    /// An integer key that reads as `default` when the document names none.
    pub(crate) const fn defaulted(name: &'static str, kind: KeyKind, default: u64) -> Self {
        KeyDef {
            name,
            kind,
            required: false,
            default: Some(default),
        }
    }

    /// The sentence a value that is not of this key's kind earns.
    fn refusal(&self) -> String {
        match (self.required, self.kind) {
            (true, KeyKind::Keyexpr) => "required, a keyexpr with no whitespace".to_string(),
            (false, KeyKind::Keyexpr) => "must be a keyexpr with no whitespace".to_string(),
            (true, KeyKind::Text) => "required, a string".to_string(),
            (false, KeyKind::Text) => "must be a string".to_string(),
            (true, KeyKind::Millis) => "required, a positive integer of milliseconds".to_string(),
            (true, KeyKind::Count) => "required, a positive integer".to_string(),
            (false, KeyKind::Millis | KeyKind::Count) => "must be a positive integer".to_string(),
            (true, KeyKind::Flag) => "required, true or false".to_string(),
            (false, KeyKind::Flag) => "must be true or false".to_string(),
            (true, KeyKind::Word(words)) => format!("required: {}", join_or(words)),
            (false, KeyKind::Word(words)) => format!("must be one of: {}", words.join(", ")),
        }
    }
}

/// `a, b or c`.
fn join_or(words: &[&str]) -> String {
    match words {
        [] => String::new(),
        [only] => (*only).to_string(),
        [head @ .., last] => format!("{} or {last}", head.join(", ")),
    }
}

/// One value a document gave a key, read by its kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Text(String),
    Int(u64),
    Flag(bool),
}

/// The keys of one driver entry that read well, in the order the role's key table
/// lists them, with the table's defaults applied. A key the document did not name
/// and the table gives no default is absent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Args(Vec<(&'static str, Value)>);

impl Args {
    fn get(&self, name: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| *k == name).map(|(_, v)| v)
    }

    /// A text or word key.
    pub(crate) fn text(&self, name: &str) -> Option<&str> {
        match self.get(name) {
            Some(Value::Text(t)) => Some(t),
            _ => None,
        }
    }

    /// An integer key (milliseconds or a count).
    pub(crate) fn int(&self, name: &str) -> Option<u64> {
        match self.get(name) {
            Some(Value::Int(n)) => Some(*n),
            _ => None,
        }
    }

    /// A flag key.
    pub(crate) fn flag(&self, name: &str) -> Option<bool> {
        match self.get(name) {
            Some(Value::Flag(b)) => Some(*b),
            _ => None,
        }
    }

    /// A key's value as written back for a refusal of a cross-key rule or a test.
    #[cfg(test)]
    pub(crate) fn of(pairs: &[(&'static str, Value)]) -> Self {
        Args(pairs.to_vec())
    }
}

/// What a role's function plays: one task of the local set, not `Send`.
pub(crate) type Play = Pin<Box<dyn Future<Output = ()>>>;

/// A role's own rule over keys that each read well: `(key, why)` per refusal.
pub(crate) type Check = fn(&Args) -> Vec<(&'static str, String)>;

fn no_check(_: &Args) -> Vec<(&'static str, String)> {
    Vec::new()
}

/// One role the driver can play.
pub(crate) struct RoleDef {
    /// The word the document names the role by, and a line names it by.
    pub(crate) word: &'static str,
    /// The keys it takes beside `role` and `after_ms`, in the order they are judged.
    pub(crate) keys: &'static [KeyDef],
    /// The build feature it needs, named for the refusal of a build without it.
    pub(crate) feature: Option<&'static str>,
    /// Whether THIS build plays it: the role's own `cfg!` for its feature.
    pub(crate) available: bool,
    /// Its rule across keys.
    pub(crate) check: Check,
    /// It, played.
    pub(crate) play: fn(Ctx) -> Play,
}

impl RoleDef {
    /// A role every build plays.
    pub(crate) const fn played(
        word: &'static str,
        keys: &'static [KeyDef],
        play: fn(Ctx) -> Play,
    ) -> Self {
        RoleDef {
            word,
            keys,
            feature: None,
            available: true,
            check: no_check,
            play,
        }
    }

    /// A role that needs `feature`; `available` is `cfg!(feature = "...")` in the
    /// role's own module, so a build without it still compiles and refuses the
    /// role by key path.
    pub(crate) const fn gated(
        word: &'static str,
        keys: &'static [KeyDef],
        feature: &'static str,
        available: bool,
        play: fn(Ctx) -> Play,
    ) -> Self {
        RoleDef {
            word,
            keys,
            feature: Some(feature),
            available,
            check: no_check,
            play,
        }
    }

    /// The same role with a rule across its keys.
    pub(crate) const fn checked(mut self, check: Check) -> Self {
        self.check = check;
        self
    }
}

/// The role a document word names.
pub(crate) fn find(word: &str) -> Option<&'static RoleDef> {
    ROLES.iter().copied().find(|r| r.word == word)
}

/// Every role word, in the order the document language lists them.
pub(crate) fn all_words() -> Vec<&'static str> {
    ROLES.iter().map(|r| r.word).collect()
}

/// The role words THIS build plays.
pub(crate) fn available_words() -> Vec<&'static str> {
    ROLES
        .iter()
        .filter(|r| r.available)
        .map(|r| r.word)
        .collect()
}

/// One entry of a session's `driver`: a role, the keys it was given and when it
/// starts. `after_ms` is common to every role (see [`AFTER_MS`]); 0 starts it at
/// once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DriverEntry {
    pub(crate) word: &'static str,
    pub(crate) after_ms: u64,
    pub(crate) args: Args,
}

/// Every key some role takes, and the two every role takes.
fn known_keys() -> BTreeSet<&'static str> {
    let mut keys: BTreeSet<&'static str> = ["role", AFTER_MS].into_iter().collect();
    keys.extend(ROLES.iter().flat_map(|r| r.keys.iter().map(|k| k.name)));
    keys
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

/// What the document wrote under `name`, read by `def`'s kind; `None` when it is
/// absent or not of the kind.
fn read_value(entry: &[(String, Json5Value)], def: &KeyDef) -> Option<Value> {
    let value = field(entry, def.name)?;
    match def.kind {
        KeyKind::Keyexpr => as_str(value)
            .filter(|k| !k.is_empty() && !k.contains(char::is_whitespace))
            .map(|k| Value::Text(k.to_string())),
        KeyKind::Text => as_str(value).map(|t| Value::Text(t.to_string())),
        KeyKind::Millis | KeyKind::Count => positive_int(value).map(Value::Int),
        KeyKind::Flag => match value {
            Json5Value::Bool(b) => Some(Value::Flag(*b)),
            _ => None,
        },
        KeyKind::Word(words) => as_str(value)
            .filter(|w| words.contains(w))
            .map(|w| Value::Text(w.to_string())),
    }
}

/// The keys of `entry` that read well under `role`, with its defaults applied.
fn read_args(role: &RoleDef, entry: &[(String, Json5Value)]) -> Args {
    Args(
        role.keys
            .iter()
            .filter_map(|def| {
                read_value(entry, def)
                    .or_else(|| def.default.map(Value::Int))
                    .map(|v| (def.name, v))
            })
            .collect(),
    )
}

fn role_refusals(path: &str, role: &Json5Value, out: &mut Vec<Refusal>) {
    let Json5Value::Object(entry) = role else {
        out.push(Refusal::new(path, "must be a mapping"));
        return;
    };
    let known = known_keys();
    let before = out.len();
    for key in key_set(entry) {
        if !known.contains(key) {
            out.push(Refusal::new(format!("{path}.{key}"), "unknown key"));
        }
    }
    let word = field(entry, "role").and_then(as_str);
    let Some(def) = word.and_then(find) else {
        out.push(Refusal::new(
            format!("{path}.role"),
            format!("required: {}", join_or(&all_words())),
        ));
        return;
    };
    for key in key_set(entry) {
        if known.contains(key)
            && !["role", AFTER_MS].contains(&key)
            && !def.keys.iter().any(|k| k.name == key)
        {
            out.push(Refusal::new(
                format!("{path}.{key}"),
                format!("not a key of the `{}` role", def.word),
            ));
        }
    }
    for key in def.keys {
        let named = has(entry, key.name);
        if (named || key.required) && read_value(entry, key).is_none() {
            out.push(Refusal::new(format!("{path}.{}", key.name), key.refusal()));
        }
    }
    if has(entry, AFTER_MS) && field(entry, AFTER_MS).and_then(positive_int).is_none() {
        out.push(Refusal::new(
            format!("{path}.{AFTER_MS}"),
            "must be a positive integer",
        ));
    }
    // The role's own rule reads keys that each read well, so it runs last and only
    // when nothing above refused this entry.
    if out.len() == before {
        for (key, why) in (def.check)(&read_args(def, entry)) {
            out.push(Refusal::new(format!("{path}.{key}"), why));
        }
    }
}

/// The roles a session's `driver` names. Only called for a document the rules and
/// [`driver_refusals`] passed, so a malformed entry is skipped and never reached.
pub(crate) fn roles_of(session: &[(String, Json5Value)]) -> Vec<DriverEntry> {
    let Some(Json5Value::Array(items)) = field(session, "driver") else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let Json5Value::Object(entry) = item else {
                return None;
            };
            let def = field(entry, "role").and_then(as_str).and_then(find)?;
            Some(DriverEntry {
                word: def.word,
                after_ms: field(entry, AFTER_MS)
                    .and_then(positive_int)
                    .unwrap_or_default(),
                args: read_args(def, entry),
            })
        })
        .collect()
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
            tokio::task::spawn_local(async move { play(name, session, entry).await })
        })
        .collect()
}

/// A role's way to say a line, cloneable into a callback.
#[derive(Debug, Clone)]
pub(crate) struct Say {
    name: String,
    word: &'static str,
}

impl Say {
    /// One line of the role, in the shape a harness waits on.
    pub(crate) fn line(&self, what: &str) {
        eprintln!(
            "wz-ap-demo session {}: DRIVER {} {what}",
            self.name, self.word
        );
    }
}

/// What a role's function is handed: where to say things, the session it runs on
/// and the keys its entry carried.
pub(crate) struct Ctx {
    pub(crate) say: Say,
    pub(crate) session: TokioSession,
    args: Args,
}

impl Ctx {
    /// The keys as read, for a role that builds one value out of several. Only the
    /// group roles do, and they sit behind a feature, so a build without it never
    /// calls this.
    #[cfg_attr(not(feature = "group"), allow(dead_code))]
    pub(crate) fn args(&self) -> &Args {
        &self.args
    }

    /// A text key, empty when absent (a required key is never absent here).
    pub(crate) fn text(&self, name: &str) -> String {
        self.args.text(name).unwrap_or_default().to_string()
    }

    pub(crate) fn int(&self, name: &str) -> Option<u64> {
        self.args.int(name)
    }

    pub(crate) fn flag(&self, name: &str) -> Option<bool> {
        self.args.flag(name)
    }

    /// One put or delete on `key`, said in a line.
    pub(crate) fn emit(&self, key: &str, kind: SampleKind, bytes: &[u8]) {
        let mut options = PublishOptions::default().with_reliability(Reliability::Reliable);
        options.kind = kind;
        match self.session.publish(key, bytes, options) {
            Ok(_) => self
                .say
                .line(&format!("sent key={key} bytes={}", bytes.len())),
            Err(e) => self.say.line(&format!("refused key={key}: {e}")),
        }
    }

    /// The role holds what it declared until its task is aborted at the session's
    /// end: it never returns.
    pub(crate) async fn hold(&self) {
        std::future::pending::<()>().await;
    }
}

/// Wait until the session is Established, or say why the role never ran.
async fn established(say: &Say, session: &TokioSession) -> bool {
    let waited = tokio::time::timeout(ESTABLISHED_WAIT, async {
        while !session.actions().is_established() {
            tokio::time::sleep(ESTABLISHED_POLL).await;
        }
    })
    .await;
    if waited.is_err() {
        say.line(&format!(
            "gave up: the session was not Established within {}s",
            ESTABLISHED_WAIT.as_secs()
        ));
    }
    waited.is_ok()
}

/// Play one role to its end. A role that holds something (a subscriber, a
/// queryable) holds it until the task is aborted at the session's end.
async fn play(name: String, session: TokioSession, entry: DriverEntry) {
    let Some(def) = find(entry.word) else {
        return;
    };
    let say = Say {
        name,
        word: def.word,
    };
    if !established(&say, &session).await {
        return;
    }
    // The hold the entry asked for, after the session is up: see [`AFTER_MS`].
    if entry.after_ms > 0 {
        tokio::time::sleep(Duration::from_millis(entry.after_ms)).await;
    }
    (def.play)(Ctx {
        say,
        session,
        args: entry.args,
    })
    .await;
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

    fn entries_of(text: &str) -> Vec<DriverEntry> {
        let doc = json5::parse(text).expect("parses");
        let Json5Value::Object(top) = &doc else {
            panic!("an object");
        };
        let Some(Json5Value::Array(sessions)) = field(top, "sessions") else {
            panic!("sessions");
        };
        let Json5Value::Object(session) = &sessions[0] else {
            panic!("a session");
        };
        roles_of(session)
    }

    /// The six first roles are accepted in their full form and read into the keys
    /// they were given; the hold is every role's.
    #[test]
    fn the_first_roles_are_accepted_and_read_into_their_keys() {
        let text = with_role(
            r#"{ role: "publish", key: "d/p", payload: "x", period_ms: 5, count: 3 },
               { role: "put", key: "d/u", payload: "y", after_ms: 7 },
               { role: "delete", key: "d/u" },
               { role: "subscribe", key: "d/**" },
               { role: "get", key: "d/q", timeout_ms: 9, after_ms: 4 },
               { role: "answer", key: "d/q", reply: "z" }"#,
        );
        assert_eq!(
            driver_refusals(&json5::parse(&text).expect("parses")),
            Vec::new()
        );
        let roles = entries_of(&text);
        let words: Vec<&str> = roles.iter().map(|e| e.word).collect();
        assert_eq!(
            words,
            ["publish", "put", "delete", "subscribe", "get", "answer"]
        );
        assert_eq!(
            roles[0],
            DriverEntry {
                word: "publish",
                after_ms: 0,
                args: Args::of(&[
                    ("key", Value::Text("d/p".into())),
                    ("payload", Value::Text("x".into())),
                    ("period_ms", Value::Int(5)),
                    ("count", Value::Int(3)),
                ]),
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
                word: "get",
                after_ms: 4,
                args: Args::of(&[
                    ("key", Value::Text("d/q".into())),
                    ("timeout_ms", Value::Int(9)),
                ]),
            }
        );
        // A key the document left out takes the table's default.
        let bare = entries_of(&with_role(r#"{ role: "get", key: "d/q" }"#));
        assert_eq!(
            bare[0].args.int("timeout_ms"),
            Some(roles::get::DEFAULT_TIMEOUT_MS)
        );
    }

    /// A refusal names the key it is about, and a role that does not exist is
    /// refused rather than skipped.
    #[test]
    fn a_refusal_names_the_key_and_an_unknown_role_is_refused() {
        let words = join_or(&all_words());
        assert_eq!(
            refused(&with_role(r#"{ role: "teleport", key: "d/t" }"#)),
            vec![format!("sessions[0].driver[0].role: required: {words}")]
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

    /// The registry is a table the rules read, so its own shape is held: one word
    /// per role, each a document word, no key twice in a role, and a role that is
    /// not played in this build says which feature it needs or that it is not
    /// played at all.
    #[test]
    fn the_registry_is_well_formed() {
        let mut seen = BTreeSet::new();
        for role in ROLES {
            assert!(seen.insert(role.word), "{} is listed twice", role.word);
            assert!(
                role.word
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_'),
                "{} is not a document word",
                role.word
            );
            let names: BTreeSet<&str> = role.keys.iter().map(|k| k.name).collect();
            assert_eq!(names.len(), role.keys.len(), "{} repeats a key", role.word);
            assert!(
                !names.contains("role") && !names.contains(AFTER_MS),
                "{} names a key every role has",
                role.word
            );
            for key in role.keys {
                assert!(
                    key.default.is_none() || matches!(key.kind, KeyKind::Millis | KeyKind::Count),
                    "{}.{} has a default but is not an integer",
                    role.word,
                    key.name
                );
            }
            if role.feature.is_some() {
                assert!(
                    !role.keys.is_empty(),
                    "{} needs a feature and takes no key",
                    role.word
                );
            }
        }
        assert_eq!(seen.len(), 17, "the document language has 17 roles");
        for word in available_words() {
            assert!(find(word).is_some_and(|r| r.available));
        }
    }
}

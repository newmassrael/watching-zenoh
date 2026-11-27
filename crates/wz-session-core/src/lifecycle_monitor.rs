// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The reference monitor of the lifecycle verbs (decision D16 of
//! `docs/session-lifecycle-intent.md`): one function judges every request to open, close, reset
//! or read a session with a peer, or to write the node's configuration, on both profiles, and
//! refuses by default.
//!
//! A request is the access matrix's triple and its context (Lampson, 1971): the subject is the
//! [`Commander`] that asks, the verb is the [`Verb`], the object is what the verb acts on (the
//! peer, a reset's generation and the key the request arrived on), and the context is the
//! [`Channel`] it came over. [`decide`] reads the request against a [`Policy`] and answers a
//! [`Decision`] that names its reason; [`Monitor`] is that function with the
//! [`DecisionRecord`] every decision is written to. Every transport reaches a verb through it
//! (`lifecycle_node::lifecycle_verdict` and the heap profile's Push ingress), and no transport
//! judges a request apart from it (complete mediation, Anderson, 1972).
//!
//! The policy is data: who may command which verb, read from the node's declaration. The fixed
//! profile compiles it into the image; the heap profile reads the same shape at run time
//! (`HeapGrants`). Neither profile writes a predicate of its own.

use crate::lifecycle_node::{Commander, Verb, Zid};

/// The channel a request came over: the context of a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// The node's control pipe, out of band.
    Pipe,
    /// A lifecycle query the node serves in band.
    Query,
    /// A command pushed on a switchboard row of a session.
    Push,
    /// A write of the node's configuration through its admin space.
    AdminWrite,
}

/// What a request acts on, as the request spelled it: nothing here is parsed before the decision,
/// so a refusal never depends on what else is wrong with the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Object<'a> {
    /// The peer the verb acts on, spelled as a key carries a zid; for [`Verb::Configure`], the
    /// node whose configuration the key names.
    pub peer: &'a str,
    /// The generation of a reset, as the text the request carried; `None` for every other verb.
    pub generation: Option<&'a str>,
    /// The key expression the request arrived on, when it came as one: what a grant narrowed to
    /// a key expression is judged by. `None` on the pipe. For [`Verb::Configure`] it is the key
    /// written, so a grant of the verb narrowed to a key expression names the keys it may write.
    pub key: Option<&'a str>,
}

/// One request to the monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'a> {
    /// Who asks.
    pub subject: Commander<'a>,
    /// What is asked.
    pub verb: Verb,
    /// What it is asked of.
    pub object: Object<'a>,
    /// Over what it was asked.
    pub channel: Channel,
}

impl<'a> Request<'a> {
    /// A write of the node's configuration, asked by `asker` on the key it carries: the verb
    /// [`Verb::Configure`], whose object is the node that key names (its zid chunk, as the key
    /// spells it) and the key itself. The value written is no part of the object: no grant is
    /// narrowed to a value and a record of fixed size could not keep one, and the admin write reads
    /// it only once the monitor has permitted the write.
    pub fn configure(asker: Asker<'a>) -> Self {
        Self {
            subject: asker.commander,
            verb: Verb::Configure,
            object: Object {
                peer: asker.key.map_or("", configured_node),
                generation: None,
                key: asker.key,
            },
            channel: asker.channel,
        }
    }
}

/// The zid chunk of a key of the admin space (`@/<zid>/<whatami>/config/...`), or the empty text
/// for a key that does not start with one.
fn configured_node(key: &str) -> &str {
    key.strip_prefix("@/")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("")
}

/// Who asks and over what, as a transport knows it before it reads the command: the part of a
/// [`Request`] that is not the verb and its object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asker<'a> {
    /// Who asks.
    pub commander: Commander<'a>,
    /// Over what.
    pub channel: Channel,
    /// The key expression the request arrived on, or `None` for a channel that carries none.
    pub key: Option<&'a str>,
}

impl<'a> Asker<'a> {
    /// The owner of the node's control pipe: the pipe proves no zid and carries no key.
    pub const PIPE: Asker<'static> = Asker {
        commander: Commander::Pipe,
        channel: Channel::Pipe,
        key: None,
    };

    /// A query in band on `key`, asked by whom the link's key proved (`requester`), or by
    /// nobody shown.
    pub const fn query(requester: Option<&'a Zid>, key: &'a str) -> Self {
        Self {
            commander: Commander::of_requester(requester),
            channel: Channel::Query,
            key: Some(key),
        }
    }

    /// A query in band on `key` that carried a sealed command, verified as signed by the key
    /// whose zid is `commander` (decision D17): the commander is that zid, whatever link the
    /// query arrived on.
    pub const fn sealed(commander: &'a Zid, key: &'a str) -> Self {
        Self {
            commander: Commander::Sealed(commander),
            channel: Channel::Query,
            key: Some(key),
        }
    }

    /// A write of the node's configuration that arrived in its admin space on `key`. A write
    /// arrives as a sample, and a sample carries no proof of who wrote it, so it is asked by
    /// nobody shown, whatever link it came over.
    pub const fn admin_write(key: &'a str) -> Self {
        Self {
            commander: Commander::Unproven,
            channel: Channel::AdminWrite,
            key: Some(key),
        }
    }
}

/// Why a request was permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grounds {
    /// The node's own statement gives the owner of its control pipe this verb.
    PipeOwner,
    /// A grant names the subject for this verb, whatever the object.
    Granted,
    /// A grant names the subject for this verb, narrowed to a key expression that includes the
    /// key the request arrived on.
    GrantedForKey,
    /// A grant of this verb to every subject, proven or not, which the node's policy states: the
    /// grant of a node that holds no channel to prove a subject, for the verbs it cannot judge
    /// otherwise. The write permission of a node's configuration is one
    /// ([`WritePermission`]): it grants [`Verb::Configure`] to anyone, as upstream's
    /// `adminspace.permissions.write` does.
    GrantedToAnyone,
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The node does not bind the verb: the build compiled it out, or the host has no means to
    /// carry it out.
    NotBound,
    /// The owner of the pipe asked a verb the node's statement does not give its pipe.
    PipeNotPermitted,
    /// Nobody was shown: the channel proved no zid, and a claimed one proves nothing.
    Unproven,
    /// The subject is named by no grant of this verb.
    NotListed,
    /// The subject's grants of this verb are each narrowed to a key expression, and the request
    /// arrived on no key any of them includes.
    OutsideGrant,
    /// A grant permits the commander of a sealed command, and the command's counter was not taken:
    /// a replay, a window with no room, or a monitor that holds no window to take it in.
    NotFresh,
}

/// What the monitor decided, with its reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request may run.
    Permit(Grounds),
    /// The request may not run, and nothing past the decision is asked of the node.
    Deny(Refusal),
}

impl Decision {
    /// Whether the request may run.
    pub const fn permits(self) -> bool {
        matches!(self, Self::Permit(_))
    }
}

/// One grant of a verb: the zid it names, and the key expression it is narrowed to, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant<'a> {
    /// The commander the grant names: a zid a key proved, by a channel or a sealed command.
    pub commander: &'a Zid,
    /// The key expression the grant is narrowed to: it permits a request only when this includes
    /// the key the request arrived on. `None` permits every object.
    pub key: Option<&'a str>,
}

/// The policy of a node, as data: what it grants, per verb. It answers what the declaration
/// says and judges nothing; [`decide`] does.
pub trait Policy {
    /// Whether the node's own statement gives the owner of its control pipe `verb`. A pipe proves
    /// no zid, so this is what a node says about whoever started it, and no list. Refused by
    /// default.
    fn pipe_commands(&self, _verb: Verb) -> bool {
        false
    }

    /// Whether the policy grants `verb` to every subject, proven or not. A grant as the others
    /// are, stated per verb and read after them, and refused by default: only a node with no
    /// channel that proves its subjects states it, for the verbs it takes from them.
    fn grants_anyone(&self, _verb: Verb) -> bool {
        false
    }

    /// Call `visit` with each grant of `verb`, in order, until it answers `true`.
    fn each_grant(&self, verb: Verb, visit: &mut dyn FnMut(Grant<'_>) -> bool);
}

impl<P: Policy + ?Sized> Policy for &P {
    fn pipe_commands(&self, verb: Verb) -> bool {
        (**self).pipe_commands(verb)
    }

    fn grants_anyone(&self, verb: Verb) -> bool {
        (**self).grants_anyone(verb)
    }

    fn each_grant(&self, verb: Verb, visit: &mut dyn FnMut(Grant<'_>) -> bool) {
        (**self).each_grant(verb, visit);
    }
}

/// The policy of a write of a node's configuration: its write permission
/// (`adminspace.permissions.write`), which grants [`Verb::Configure`] to anyone and no other
/// verb. A write proves no writer (it arrives as a sample), so a grant to anyone is the one grant
/// that can permit it; with the permission off, every write is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WritePermission(pub bool);

impl Policy for WritePermission {
    fn grants_anyone(&self, verb: Verb) -> bool {
        self.0 && verb == Verb::Configure
    }

    fn each_grant(&self, _verb: Verb, _visit: &mut dyn FnMut(Grant<'_>) -> bool) {}
}

/// The policy that grants nothing: every request is refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoGrants;

impl Policy for NoGrants {
    fn each_grant(&self, _verb: Verb, _visit: &mut dyn FnMut(Grant<'_>) -> bool) {}
}

/// Decide `request` against `policy`, for a node that binds the verb when `bound`.
///
/// The one function every lifecycle verb of every profile is judged by, in this order: a verb the
/// node does not bind is refused; the pipe's owner is what the node says of its pipe; a zid a key
/// proved, by a channel or by a sealed command, is looked for in the grants of the verb, and a
/// grant narrowed to a key expression permits only a request that arrived on a key it includes;
/// what no grant names its subject for, a grant of the verb to anyone may permit; everything else
/// is refused, with the reason.
pub fn decide<P: Policy + ?Sized>(policy: &P, bound: bool, request: &Request<'_>) -> Decision {
    if !bound {
        return Decision::Deny(Refusal::NotBound);
    }
    let verb = request.verb;
    let refusal = match request.subject {
        Commander::Pipe => {
            if policy.pipe_commands(verb) {
                return Decision::Permit(Grounds::PipeOwner);
            }
            Refusal::PipeNotPermitted
        }
        Commander::Verified(zid) | Commander::Sealed(zid) => {
            match granted(policy, verb, zid, request.object.key) {
                Some(grounds) => return Decision::Permit(grounds),
                None if listed(policy, verb, zid) => Refusal::OutsideGrant,
                None => Refusal::NotListed,
            }
        }
        Commander::Unproven => Refusal::Unproven,
    };
    if policy.grants_anyone(verb) {
        return Decision::Permit(Grounds::GrantedToAnyone);
    }
    Decision::Deny(refusal)
}

/// The grounds on which a grant of `verb` permits `zid` to act on the object that arrived on
/// `key`, or `None`.
fn granted<P: Policy + ?Sized>(
    policy: &P,
    verb: Verb,
    zid: &Zid,
    key: Option<&str>,
) -> Option<Grounds> {
    let mut grounds = None;
    policy.each_grant(verb, &mut |grant| {
        if grant.commander != zid {
            return false;
        }
        grounds = match (grant.key, key) {
            (None, _) => Some(Grounds::Granted),
            (Some(narrowed), Some(asked)) if within(narrowed, asked) => {
                Some(Grounds::GrantedForKey)
            }
            _ => None,
        };
        grounds.is_some()
    });
    grounds
}

/// Whether any grant of `verb` names `zid`, whatever it is narrowed to.
fn listed<P: Policy + ?Sized>(policy: &P, verb: Verb, zid: &Zid) -> bool {
    let mut named = false;
    policy.each_grant(verb, &mut |grant| {
        named = grant.commander == zid;
        named
    });
    named
}

/// Whether the key a request arrived on is one `narrowed` matches. The asked key is a literal: a
/// key that is a pattern names no single object, and is outside every grant.
fn within(narrowed: &str, asked: &str) -> bool {
    !asked.contains(['*', '$']) && crate::keyexpr_match::keyexpr_intersects(narrowed, asked)
}

/// What the proof of a sealed command still asks once a grant permits its commander: that its
/// counter is taken (decision D17). Asked after the policy and before any effect, so a command no
/// grant permits takes no counter and a command whose counter is refused has no effect.
pub trait Admission {
    /// Take what the request's proof asks to be taken, or say why it cannot be.
    fn admit(&self, request: &Request<'_>) -> Result<(), Refusal>;
}

/// Where the monitor writes every decision, permit and refusal alike, with its request.
pub trait DecisionRecord {
    /// Keep `decision` on `request`.
    fn record(&self, request: &Request<'_>, decision: Decision);
}

impl<R: DecisionRecord + ?Sized> DecisionRecord for &R {
    fn record(&self, request: &Request<'_>, decision: Decision) {
        (**self).record(request, decision);
    }
}

/// The record of a node that binds no lifecycle verb: every request it is asked is refused as not
/// bound before any policy is read, so it has nothing of its own to keep. A node that binds a verb
/// keeps its decisions in a record of its own.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRecord;

impl DecisionRecord for NoRecord {
    fn record(&self, _request: &Request<'_>, _decision: Decision) {}
}

/// The reference monitor: a node's policy and the record its decisions are written to. Both
/// profiles judge every lifecycle request through this type, and a request reaches no effect
/// except through [`Self::decide`].
#[derive(Clone, Copy)]
pub struct Monitor<'a> {
    policy: &'a dyn Policy,
    record: &'a dyn DecisionRecord,
    admission: Option<&'a dyn Admission>,
}

impl<'a> Monitor<'a> {
    /// The monitor of a node whose policy is `policy` and whose decisions are kept in `record`.
    pub fn new(policy: &'a dyn Policy, record: &'a dyn DecisionRecord) -> Self {
        Self {
            policy,
            record,
            admission: None,
        }
    }

    /// This monitor for a request that carried a sealed command: a permit of its commander stands
    /// only once `admission` has taken the command's counter.
    pub fn with_admission(self, admission: &'a dyn Admission) -> Self {
        Self {
            admission: Some(admission),
            ..self
        }
    }

    /// Decide `request` for a node that binds its verb when `bound` ([`decide`]), and record the
    /// decision before it is answered.
    ///
    /// A permit of a sealed command's commander is then admitted: its counter taken, or the request
    /// refused as [`Refusal::NotFresh`]. A monitor given no admission refuses every sealed
    /// commander so, since nothing took its counter (fail-safe).
    pub fn decide(&self, bound: bool, request: &Request<'_>) -> Decision {
        let mut decision = decide(self.policy, bound, request);
        if let (Decision::Permit(_), Commander::Sealed(_)) = (decision, request.subject) {
            let admitted = match self.admission {
                Some(admission) => admission.admit(request),
                None => Err(Refusal::NotFresh),
            };
            if let Err(refusal) = admitted {
                decision = Decision::Deny(refusal);
            }
        }
        self.record.record(request, decision);
        decision
    }
}

/// A subject as a record keeps it: a [`Commander`] with its zid copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    /// The owner of the control pipe.
    Pipe,
    /// A zid a link's key proved.
    Verified(Zid),
    /// A zid a sealed command proved.
    Sealed(Zid),
    /// Nobody shown.
    Unproven,
}

impl From<Commander<'_>> for Subject {
    fn from(commander: Commander<'_>) -> Self {
        match commander {
            Commander::Pipe => Self::Pipe,
            Commander::Verified(zid) => Self::Verified(*zid),
            Commander::Sealed(zid) => Self::Sealed(*zid),
            Commander::Unproven => Self::Unproven,
        }
    }
}

/// One decision as a record of fixed size keeps it: the subject, the verb, the object as far as
/// it reads (the peer's zid, a reset's generation), the channel and the decision with its reason.
/// A peer or a generation that does not read is kept as `None`; the key the request arrived on
/// is not kept, since its length has no bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decided {
    /// Who asked.
    pub subject: Subject,
    /// What was asked.
    pub verb: Verb,
    /// The peer, when its text spells a zid.
    pub peer: Option<Zid>,
    /// A reset's generation, when its text is a number.
    pub generation: Option<u64>,
    /// Over what.
    pub channel: Channel,
    /// The decision and its reason.
    pub decision: Decision,
}

impl Decided {
    /// The row of `decision` on `request`.
    pub fn of(request: &Request<'_>, decision: Decision) -> Self {
        Self {
            subject: request.subject.into(),
            verb: request.verb,
            peer: crate::credential_identity::zid_from_key_text(request.object.peer),
            generation: request
                .object
                .generation
                .and_then(|text| text.parse::<u64>().ok()),
            channel: request.channel,
            decision,
        }
    }
}

/// A zid as a key spells it: the lowercase hex of the number its bytes are, least significant
/// first.
struct ZidText<'a>(&'a Zid);

impl core::fmt::Display for ZidText<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x}", u128::from_le_bytes(*self.0))
    }
}

impl core::fmt::Display for Commander<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pipe => f.write_str("pipe"),
            Self::Verified(zid) => write!(f, "verified:{}", ZidText(zid)),
            Self::Sealed(zid) => write!(f, "sealed:{}", ZidText(zid)),
            Self::Unproven => f.write_str("unproven"),
        }
    }
}

/// The record of a heap node: each decision is a line of the process's log, a refusal as a
/// warning and a permit as a debug note, with the whole request, the key included.
#[derive(Debug, Clone, Copy, Default)]
pub struct LogRecord;

impl DecisionRecord for LogRecord {
    fn record(&self, request: &Request<'_>, decision: Decision) {
        let Request {
            subject,
            verb,
            object,
            channel,
        } = request;
        match decision {
            Decision::Permit(grounds) => crate::diag_debug!(
                "lifecycle monitor: permit {verb:?} by {subject} over {channel:?} on peer {} \
                 generation {:?} key {:?}: {grounds:?}",
                object.peer,
                object.generation,
                object.key
            ),
            Decision::Deny(refusal) => crate::diag_warn!(
                "lifecycle monitor: deny {verb:?} by {subject} over {channel:?} on peer {} \
                 generation {:?} key {:?}: {refusal:?}",
                object.peer,
                object.generation,
                object.key
            ),
        }
    }
}

/// The verbs of one grant, as a set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerbSet(u8);

impl VerbSet {
    /// No verb.
    pub const NONE: Self = Self(0);

    /// The bit of `verb`.
    const fn bit(verb: Verb) -> u8 {
        match verb {
            Verb::Open => 0b0001,
            Verb::Close => 0b0010,
            Verb::Reset => 0b0100,
            Verb::Status => 0b1000,
            Verb::Configure => 0b1_0000,
        }
    }

    /// This set with `verb` in it.
    pub const fn with(self, verb: Verb) -> Self {
        Self(self.0 | Self::bit(verb))
    }

    /// Whether `verb` is in the set.
    pub const fn has(self, verb: Verb) -> bool {
        self.0 & Self::bit(verb) != 0
    }

    /// The verb a declaration spells `word` (`open`, `close`, `reset`, `status`).
    pub fn verb_of(word: &str) -> Option<Verb> {
        use crate::lifecycle_wire::{CLOSE_VERB, OPEN_VERB, RESET_VERB, STATUS_VERB};
        match word {
            OPEN_VERB => Some(Verb::Open),
            CLOSE_VERB => Some(Verb::Close),
            RESET_VERB => Some(Verb::Reset),
            STATUS_VERB => Some(Verb::Status),
            _ => None,
        }
    }
}

#[cfg(feature = "alloc")]
pub use heap::{CommanderGrant, GrantError, HeapGrants};

/// The policy of a heap node: the grants of its declaration, read when the node starts.
#[cfg(feature = "alloc")]
mod heap {
    use super::{Grant, Policy, VerbSet};
    use crate::lifecycle_node::{Verb, Zid};
    use alloc::string::String;
    use alloc::vec::Vec;

    /// One `commander` grant, as a declaration states it: a zid, the verbs it may command, and
    /// optionally the key expression the grant is narrowed to.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CommanderGrant {
        /// The commander's zid.
        pub commander: Zid,
        /// The verbs it may command.
        pub verbs: VerbSet,
        /// The key expression the grant is narrowed to; `None` for every object.
        pub key: Option<String>,
    }

    /// Why the text of a grant is no grant.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum GrantError {
        /// The text has no `=` between the zid and the verbs.
        NoVerbs,
        /// The zid is not lowercase hex with no leading zero, of at most thirty-two digits.
        NotAZid,
        /// A verb is not `open`, `close`, `reset` or `status`, or is empty.
        UnknownVerb,
        /// A verb is named twice in one grant.
        RepeatedVerb,
        /// The text names a key expression, and it is empty.
        EmptyKey,
        /// A grant of the same zid, verb and key expression is stated twice.
        Repeated,
    }

    impl GrantError {
        /// What is wrong, in words.
        pub const fn words(self) -> &'static str {
            match self {
                Self::NoVerbs => "a grant is <zid>=<verb>[,<verb>...][=<key expression>]",
                Self::NotAZid => "the zid is not lowercase hex with no leading zero",
                Self::UnknownVerb => "a verb is not one of open, close, reset, status",
                Self::RepeatedVerb => "a verb is named twice in one grant",
                Self::EmptyKey => "the key expression of a grant is empty",
                Self::Repeated => "a zid, verb and key expression are granted twice",
            }
        }
    }

    impl CommanderGrant {
        /// Read one grant: `<zid>=<verb>[,<verb>...]`, then optionally `=<key expression>`. The
        /// zid is spelled as a key carries one, and the verbs as the declaration spells them.
        pub fn parse(text: &str) -> Result<Self, GrantError> {
            let mut parts = text.splitn(3, '=');
            let zid = parts.next().unwrap_or_default();
            let verbs = parts.next().ok_or(GrantError::NoVerbs)?;
            let key = parts.next();
            let commander =
                crate::credential_identity::zid_from_key_text(zid).ok_or(GrantError::NotAZid)?;
            let mut set = VerbSet::NONE;
            for word in verbs.split(',') {
                let verb = VerbSet::verb_of(word).ok_or(GrantError::UnknownVerb)?;
                if set.has(verb) {
                    return Err(GrantError::RepeatedVerb);
                }
                set = set.with(verb);
            }
            let key = match key {
                Some("") => return Err(GrantError::EmptyKey),
                Some(key) => Some(String::from(key)),
                None => None,
            };
            Ok(Self {
                commander,
                verbs: set,
                key,
            })
        }
    }

    /// The grants of a heap node. Empty, it grants nothing, which is where a node starts.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct HeapGrants {
        grants: Vec<CommanderGrant>,
    }

    impl HeapGrants {
        /// The grants `grants` states, refused when one zid, verb and key expression are granted
        /// twice: a declaration states a grant once.
        pub fn new(grants: Vec<CommanderGrant>) -> Result<Self, GrantError> {
            for (at, grant) in grants.iter().enumerate() {
                let repeated = grants.iter().take(at).any(|earlier| {
                    earlier.commander == grant.commander
                        && earlier.key == grant.key
                        && [
                            Verb::Open,
                            Verb::Close,
                            Verb::Reset,
                            Verb::Status,
                            Verb::Configure,
                        ]
                        .into_iter()
                        .any(|verb| earlier.verbs.has(verb) && grant.verbs.has(verb))
                });
                if repeated {
                    return Err(GrantError::Repeated);
                }
            }
            Ok(Self { grants })
        }

        /// The grants the texts state, one grant each ([`CommanderGrant::parse`]).
        pub fn parse<'t>(texts: impl IntoIterator<Item = &'t str>) -> Result<Self, GrantError> {
            let grants = texts
                .into_iter()
                .map(CommanderGrant::parse)
                .collect::<Result<Vec<_>, _>>()?;
            Self::new(grants)
        }

        /// The grants, in the order they were stated.
        pub fn grants(&self) -> &[CommanderGrant] {
            &self.grants
        }
    }

    impl Policy for HeapGrants {
        fn each_grant(&self, verb: Verb, visit: &mut dyn FnMut(Grant<'_>) -> bool) {
            for grant in self.grants.iter().filter(|grant| grant.verbs.has(verb)) {
                let stop = visit(Grant {
                    commander: &grant.commander,
                    key: grant.key.as_deref(),
                });
                if stop {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::cell::RefCell;
    use std::vec::Vec;

    const ADMIN: Zid = [0x1f; 16];
    const READER: Zid = [0x2e; 16];
    const STRANGER: Zid = [0x3d; 16];
    const EVERY: [Verb; 5] = [
        Verb::Open,
        Verb::Close,
        Verb::Reset,
        Verb::Status,
        Verb::Configure,
    ];

    /// A policy of fixed lists, a pipe statement and the verbs granted to anyone, as a test
    /// states them.
    #[derive(Default)]
    struct Table {
        pipe: bool,
        anyone: &'static [Verb],
        grants: Vec<(Verb, Zid, Option<&'static str>)>,
    }

    impl Policy for Table {
        fn pipe_commands(&self, _verb: Verb) -> bool {
            self.pipe
        }
        fn grants_anyone(&self, verb: Verb) -> bool {
            self.anyone.contains(&verb)
        }
        fn each_grant(&self, verb: Verb, visit: &mut dyn FnMut(Grant<'_>) -> bool) {
            for (granted, commander, key) in &self.grants {
                if *granted == verb
                    && visit(Grant {
                        commander,
                        key: *key,
                    })
                {
                    return;
                }
            }
        }
    }

    /// Keeps every decision it is handed.
    #[derive(Default)]
    struct Kept(RefCell<Vec<Decided>>);

    impl DecisionRecord for Kept {
        fn record(&self, request: &Request<'_>, decision: Decision) {
            self.0.borrow_mut().push(Decided::of(request, decision));
        }
    }

    fn request<'a>(subject: Commander<'a>, verb: Verb, key: Option<&'a str>) -> Request<'a> {
        Request {
            subject,
            verb,
            object: Object {
                peer: "c3d4",
                generation: None,
                key,
            },
            channel: Channel::Query,
        }
    }

    /// Default deny: a policy that states nothing refuses every subject every verb, and says why.
    #[test]
    fn a_policy_that_states_nothing_refuses_everyone() {
        for verb in EVERY {
            for (subject, refusal) in [
                (Commander::Pipe, Refusal::PipeNotPermitted),
                (Commander::Verified(&ADMIN), Refusal::NotListed),
                (Commander::Sealed(&ADMIN), Refusal::NotListed),
                (Commander::Unproven, Refusal::Unproven),
            ] {
                assert_eq!(
                    decide(&NoGrants, true, &request(subject, verb, None)),
                    Decision::Deny(refusal),
                    "{verb:?} by {subject}"
                );
            }
        }
    }

    /// A listed zid commands only the verbs it is listed for; an unlisted one and nobody shown
    /// command none, and the pipe is what the node says of it. Red if `decide` read another verb's
    /// list or let an unproven subject through.
    #[test]
    fn a_listed_zid_commands_only_its_verbs() {
        let table = Table {
            grants: Vec::from([
                (Verb::Status, READER, None),
                (Verb::Close, ADMIN, None),
                (Verb::Status, ADMIN, None),
            ]),
            ..Table::default()
        };
        for verb in EVERY {
            let reader = decide(
                &table,
                true,
                &request(Commander::Verified(&READER), verb, None),
            );
            assert_eq!(reader.permits(), verb == Verb::Status, "{verb:?}");
            let admin = decide(
                &table,
                true,
                &request(Commander::Verified(&ADMIN), verb, None),
            );
            assert_eq!(
                admin.permits(),
                matches!(verb, Verb::Close | Verb::Status),
                "{verb:?}"
            );
            assert_eq!(
                decide(
                    &table,
                    true,
                    &request(Commander::Verified(&STRANGER), verb, None)
                ),
                Decision::Deny(Refusal::NotListed)
            );
            assert_eq!(
                decide(&table, true, &request(Commander::Unproven, verb, None)),
                Decision::Deny(Refusal::Unproven)
            );
        }
        assert_eq!(
            decide(
                &table,
                true,
                &request(Commander::Verified(&READER), Verb::Open, None)
            ),
            Decision::Deny(Refusal::NotListed)
        );
        // A sealed command's commander is judged by the same lists.
        assert_eq!(
            decide(
                &table,
                true,
                &request(Commander::Sealed(&ADMIN), Verb::Close, None)
            ),
            Decision::Permit(Grounds::Granted)
        );
    }

    /// A verb the node does not bind is refused before the policy is read, even to the pipe.
    #[test]
    fn an_unbound_verb_is_refused_to_everyone() {
        let table = Table {
            pipe: true,
            anyone: &[Verb::Open],
            grants: Vec::from([(Verb::Open, ADMIN, None)]),
        };
        for subject in [
            Commander::Pipe,
            Commander::Verified(&ADMIN),
            Commander::Unproven,
        ] {
            assert_eq!(
                decide(&table, false, &request(subject, Verb::Open, None)),
                Decision::Deny(Refusal::NotBound)
            );
        }
    }

    /// The pipe is the node's own statement, and a statement about the pipe grants no zid.
    #[test]
    fn the_pipe_is_the_nodes_own_statement() {
        let table = Table {
            pipe: true,
            ..Table::default()
        };
        for verb in EVERY {
            assert_eq!(
                decide(&table, true, &request(Commander::Pipe, verb, None)),
                Decision::Permit(Grounds::PipeOwner)
            );
            assert_eq!(
                decide(
                    &table,
                    true,
                    &request(Commander::Verified(&ADMIN), verb, None)
                ),
                Decision::Deny(Refusal::NotListed)
            );
        }
    }

    /// A grant narrowed to a key expression permits only a literal key it includes; the same zid
    /// asking outside it is told so, apart from a zid that is on no list.
    #[test]
    fn a_grant_narrowed_to_a_key_permits_only_keys_inside_it() {
        let table = Table {
            grants: Vec::from([(Verb::Close, ADMIN, Some("@/a1b2/peer/session/close/c3d4"))]),
            ..Table::default()
        };
        let asked = |key| {
            decide(
                &table,
                true,
                &request(Commander::Verified(&ADMIN), Verb::Close, key),
            )
        };
        assert_eq!(
            asked(Some("@/a1b2/peer/session/close/c3d4")),
            Decision::Permit(Grounds::GrantedForKey)
        );
        assert_eq!(
            asked(Some("@/a1b2/peer/session/close/e5f6")),
            Decision::Deny(Refusal::OutsideGrant)
        );
        // A pattern names no single object.
        assert_eq!(
            asked(Some("@/a1b2/peer/session/close/*")),
            Decision::Deny(Refusal::OutsideGrant)
        );
        // The pipe carries no key, so a narrowed grant does not reach it.
        assert_eq!(asked(None), Decision::Deny(Refusal::OutsideGrant));
        let wide = Table {
            grants: Vec::from([(Verb::Close, ADMIN, Some("@/a1b2/peer/session/close/*"))]),
            ..Table::default()
        };
        assert_eq!(
            decide(
                &wide,
                true,
                &request(
                    Commander::Verified(&ADMIN),
                    Verb::Close,
                    Some("@/a1b2/peer/session/close/e5f6")
                )
            ),
            Decision::Permit(Grounds::GrantedForKey)
        );
    }

    /// A grant to anyone names no subject: it permits the verbs it is stated for to every
    /// subject, after the grants that name one, and no other verb.
    #[test]
    fn a_grant_to_anyone_permits_what_no_named_grant_does() {
        let table = Table {
            anyone: &[Verb::Open],
            ..Table::default()
        };
        for subject in [
            Commander::Pipe,
            Commander::Verified(&STRANGER),
            Commander::Unproven,
        ] {
            assert_eq!(
                decide(&table, true, &request(subject, Verb::Open, None)),
                Decision::Permit(Grounds::GrantedToAnyone)
            );
            assert!(!decide(&table, true, &request(subject, Verb::Close, None)).permits());
        }
    }

    /// A write of the node's configuration is one more verb of the same function: its object is
    /// the node the written key names and the key, it is asked by nobody shown, and only a grant
    /// of [`Verb::Configure`] permits it. Red if `Request::configure` read another node or key,
    /// or if the write permission granted any other verb.
    #[test]
    fn a_configuration_write_is_judged_as_every_verb_is() {
        const KEY: &str = "@/a1b2/peer/config/connect/endpoints";
        let write = Request::configure(Asker::admin_write(KEY));
        assert_eq!(
            write,
            Request {
                subject: Commander::Unproven,
                verb: Verb::Configure,
                object: Object {
                    peer: "a1b2",
                    generation: None,
                    key: Some(KEY),
                },
                channel: Channel::AdminWrite,
            }
        );
        // Default deny, and the write permission off is no grant.
        assert_eq!(
            decide(&NoGrants, true, &write),
            Decision::Deny(Refusal::Unproven)
        );
        assert_eq!(
            decide(&WritePermission(false), true, &write),
            Decision::Deny(Refusal::Unproven)
        );
        // The write permission on grants the write to anyone, and grants nothing else.
        assert_eq!(
            decide(&WritePermission(true), true, &write),
            Decision::Permit(Grounds::GrantedToAnyone)
        );
        for verb in [Verb::Open, Verb::Close, Verb::Reset, Verb::Status] {
            assert!(
                !decide(
                    &WritePermission(true),
                    true,
                    &request(Commander::Unproven, verb, None)
                )
                .permits(),
                "{verb:?}"
            );
        }
        // A node that does not host the write refuses it before the policy is read.
        assert_eq!(
            decide(&WritePermission(true), false, &write),
            Decision::Deny(Refusal::NotBound)
        );
        // A grant of the verb to a zid, narrowed to one key, permits that key and no other.
        let table = Table {
            grants: Vec::from([(Verb::Configure, ADMIN, Some(KEY))]),
            ..Table::default()
        };
        let by_admin = |key| Request {
            subject: Commander::Verified(&ADMIN),
            ..Request::configure(Asker::admin_write(key))
        };
        assert_eq!(
            decide(&table, true, &by_admin(KEY)),
            Decision::Permit(Grounds::GrantedForKey)
        );
        assert_eq!(
            decide(
                &table,
                true,
                &by_admin("@/a1b2/peer/config/adminspace/permissions/write")
            ),
            Decision::Deny(Refusal::OutsideGrant)
        );
        // A key outside the admin space names no node.
        assert_eq!(
            Request::configure(Asker::admin_write("demo/a")).object.peer,
            ""
        );
    }

    /// The monitor records every decision it makes, permit and refusal alike, with the subject,
    /// the verb, the object and the reason. Red if `Monitor::decide` skipped the record on
    /// either arm.
    #[test]
    fn the_record_carries_every_decision() {
        let table = Table {
            grants: Vec::from([(Verb::Reset, ADMIN, None)]),
            ..Table::default()
        };
        let kept = Kept::default();
        let monitor = Monitor::new(&table, &kept);
        let mut reset = request(Commander::Verified(&ADMIN), Verb::Reset, None);
        reset.object.generation = Some("7");
        assert!(monitor.decide(true, &reset).permits());
        assert!(!monitor
            .decide(true, &request(Commander::Unproven, Verb::Close, None))
            .permits());
        assert!(!monitor
            .decide(false, &request(Commander::Pipe, Verb::Open, None))
            .permits());
        let peer = crate::credential_identity::zid_from_key_text("c3d4");
        assert_eq!(
            *kept.0.borrow(),
            [
                Decided {
                    subject: Subject::Verified(ADMIN),
                    verb: Verb::Reset,
                    peer,
                    generation: Some(7),
                    channel: Channel::Query,
                    decision: Decision::Permit(Grounds::Granted),
                },
                Decided {
                    subject: Subject::Unproven,
                    verb: Verb::Close,
                    peer,
                    generation: None,
                    channel: Channel::Query,
                    decision: Decision::Deny(Refusal::Unproven),
                },
                Decided {
                    subject: Subject::Pipe,
                    verb: Verb::Open,
                    peer,
                    generation: None,
                    channel: Channel::Query,
                    decision: Decision::Deny(Refusal::NotBound),
                },
            ]
        );
    }

    /// A grant's text reads as the declaration states it, and what is not one is refused by name.
    #[cfg(feature = "alloc")]
    #[test]
    fn a_grant_reads_as_the_declaration_states_it() {
        let grant = CommanderGrant::parse("1f=close,status").expect("a grant");
        assert_eq!(
            grant.commander,
            crate::credential_identity::zid_from_key_text("1f").expect("a zid")
        );
        for verb in EVERY {
            assert_eq!(
                grant.verbs.has(verb),
                matches!(verb, Verb::Close | Verb::Status)
            );
        }
        assert_eq!(grant.key, None);
        let narrowed =
            CommanderGrant::parse("1f=open=@/a1b2/peer/session/open/*").expect("a grant");
        assert_eq!(narrowed.key.as_deref(), Some("@/a1b2/peer/session/open/*"));
        for (text, error) in [
            ("1f", GrantError::NoVerbs),
            ("01f=open", GrantError::NotAZid),
            ("1F=open", GrantError::NotAZid),
            ("=open", GrantError::NotAZid),
            ("1f=", GrantError::UnknownVerb),
            ("1f=open,", GrantError::UnknownVerb),
            ("1f=shutdown", GrantError::UnknownVerb),
            ("1f=open,open", GrantError::RepeatedVerb),
            ("1f=open=", GrantError::EmptyKey),
        ] {
            assert_eq!(CommanderGrant::parse(text), Err(error), "{text}");
        }
        assert_eq!(
            HeapGrants::parse(["1f=open", "2e=open", "1f=close,open"]),
            Err(GrantError::Repeated)
        );
        assert!(HeapGrants::parse(["1f=open", "1f=open=@/a1b2/**"]).is_ok());
    }

    /// The heap policy is the same mechanism over grants read at run time: an unproven or unlisted
    /// commander is refused, and a listed one commands only its verbs.
    #[cfg(feature = "alloc")]
    #[test]
    fn the_heap_grants_are_judged_by_the_same_function() {
        let grants = HeapGrants::parse(["1f=close"]).expect("grants");
        let admin = crate::credential_identity::zid_from_key_text("1f").expect("a zid");
        for verb in EVERY {
            assert_eq!(
                decide(
                    &grants,
                    true,
                    &request(Commander::Verified(&admin), verb, None)
                )
                .permits(),
                verb == Verb::Close,
                "{verb:?}"
            );
            assert_eq!(
                decide(&grants, true, &request(Commander::Unproven, verb, None)),
                Decision::Deny(Refusal::Unproven)
            );
            assert_eq!(
                decide(
                    &grants,
                    true,
                    &request(Commander::Verified(&STRANGER), verb, None)
                ),
                Decision::Deny(Refusal::NotListed)
            );
            assert!(!decide(&grants, true, &request(Commander::Pipe, verb, None)).permits());
        }
    }
    /// An admission that takes a sealed command's counter, or refuses as it is told, and counts
    /// how often it is asked.
    struct Counter {
        refuse: bool,
        asked: core::cell::Cell<u32>,
    }

    impl Admission for Counter {
        fn admit(&self, _request: &Request<'_>) -> Result<(), Refusal> {
            self.asked.set(self.asked.get() + 1);
            if self.refuse {
                Err(Refusal::NotFresh)
            } else {
                Ok(())
            }
        }
    }

    /// A sealed command's counter is taken only after a grant permits its commander: an unlisted
    /// commander and an ungranted verb are refused without asking, a channel's commander is never
    /// asked, a refused take refuses the request, and a monitor with no admission permits no sealed
    /// commander. Red if `Monitor::decide` admitted before deciding or permitted a sealed
    /// commander with nothing to take its counter.
    #[test]
    fn a_sealed_commander_is_admitted_only_after_a_grant_permits_it() {
        let table = Table {
            grants: Vec::from([(Verb::Close, ADMIN, None)]),
            ..Table::default()
        };
        let kept = Kept::default();
        let taking = Counter {
            refuse: false,
            asked: core::cell::Cell::new(0),
        };
        let monitor = Monitor::new(&table, &kept).with_admission(&taking);
        let sealed_close = |zid| request(Commander::Sealed(zid), Verb::Close, None);
        assert_eq!(
            monitor.decide(true, &sealed_close(&ADMIN)),
            Decision::Permit(Grounds::Granted)
        );
        assert_eq!(taking.asked.get(), 1);
        assert_eq!(
            monitor.decide(true, &sealed_close(&STRANGER)),
            Decision::Deny(Refusal::NotListed)
        );
        assert_eq!(
            monitor.decide(true, &request(Commander::Sealed(&ADMIN), Verb::Open, None)),
            Decision::Deny(Refusal::NotListed)
        );
        assert_eq!(
            monitor.decide(
                true,
                &request(Commander::Verified(&ADMIN), Verb::Close, None)
            ),
            Decision::Permit(Grounds::Granted)
        );
        assert_eq!(taking.asked.get(), 1, "only the permitted sealed command");

        let refusing = Counter {
            refuse: true,
            asked: core::cell::Cell::new(0),
        };
        let monitor = Monitor::new(&table, &kept).with_admission(&refusing);
        assert_eq!(
            monitor.decide(true, &sealed_close(&ADMIN)),
            Decision::Deny(Refusal::NotFresh)
        );
        assert_eq!(refusing.asked.get(), 1);

        let bare = Monitor::new(&table, &kept);
        assert_eq!(
            bare.decide(true, &sealed_close(&ADMIN)),
            Decision::Deny(Refusal::NotFresh)
        );
        let last = *kept.0.borrow().last().expect("recorded");
        assert_eq!(last.subject, Subject::Sealed(ADMIN));
        assert_eq!(last.decision, Decision::Deny(Refusal::NotFresh));
    }
}

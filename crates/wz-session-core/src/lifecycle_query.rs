// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session lifecycle as a QUERY: close a session and be told what happened,
//! and ask a node which lifecycle verbs it has.
//!
//! The close verb has always been a Push on a switchboard row
//! (`@/<zid>/<whatami>/session/close/<peer-zid>`, [`crate::drive::LifecycleKey`]):
//! a matched sample becomes a close request on the session it is bound to, gated
//! by a [`crate::drive::SessionLifecycleAuthority`], and nothing comes back. A
//! Push has no reply path, so a caller could not tell a close that ran from one
//! that was refused or aimed at nobody. This is the same verb asked as a GET, which has one.
//!
//! # The two queries
//!
//! * `GET @/<zid>/<whatami>/session/close/<peer-zid>` orders EVERY session this
//!   node holds with that peer closed and answers one JSON object:
//!   `{"verdict":"closing","links":N}`, `{"verdict":"already_closed"}`,
//!   `{"verdict":"not_found"}` or `{"verdict":"refused","reason":"..."}`.
//! * `GET @/<zid>/<whatami>/session/verbs` answers `{"verbs":["close"]}`: the
//!   verbs this node has bound. It says what the node KNOWS, not whether this
//!   caller may use it; permission is judged by `refused` on the close query.
//!
//! A node that binds neither answers nothing, which a querier reads as "no
//! surface". That is the honest answer for a node that has no lifecycle ingress.
//!
//! # What "closing" promises
//!
//! The reply is sent when the close is ORDERED, not when the session is gone,
//! because the query can arrive over the very session it closes and the reply has
//! to leave before the link does. So `closing` means: the drive loop has been told,
//! and the session is on its way to Closed through the ordinary Closing path. A
//! caller that wants completion watches the transport close, as it would for a
//! close from either side.
//!
//! # Whole session, every link
//!
//! A peer may be joined by several links. A close ends the SESSION with that peer,
//! not one link: every link to the peer's zid is ordered closed, and `links` is how
//! many this call ordered. A close that finds the peer's links all already ordered
//! answers `already_closed`.
//!
//! # Why the close query is exact-key only
//!
//! A GET may carry a wildcard, and a wildcard close is "close everything that
//! matches". The close query is answered only for a literal key that names this
//! node, this role, the `close` verb and one peer. A wildcard that merely
//! intersects it gets no reply, so a destructive verb is never reached by a pattern
//! the caller did not mean as a target. The capability query has no such risk, so
//! it answers any key that intersects it.

use alloc::string::String;

// Re-exported: the two types a host binds the queries with, so it names one module.
pub use crate::drive::{LifecycleKey, SessionLifecycleAuthority};
use crate::query_sink::{QueryView, ReplyError, ReplyOut};
use crate::text_out::{FixedText, TextOut};
use crate::zid_hex::{same_zid, zenoh_hex_to_zid};

/// The verb the close query carries in its key.
const CLOSE_VERB: &str = "close";

/// What a node's sessions did when told to close: how many links to the peer were
/// ordered closed by this call, and how many had been ordered before it.
///
/// Two counts rather than one verdict because the node that holds the sessions
/// knows them and the verdict is this module's: `newly_ordered` is the number a
/// reply reports as `links`, and the sum says whether the peer was there at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CloseOrder {
    /// Links to the peer that this call ordered closed.
    pub newly_ordered: u32,
    /// Links to the peer that a close had already been ordered for.
    pub already_ordered: u32,
}

/// The node's table of sessions, as the close query needs it: told a peer's zid,
/// it orders closed every session it holds with that peer.
///
/// A port, for the reason [`SessionLifecycleAuthority`] is one: the sessions live
/// in a host's face table, which this crate cannot name. The host implements it
/// over that table (`request_close` on each face's session bundle), and the same
/// answerer serves every host.
pub trait SessionDirectory {
    /// Order every session with the peer whose zid is `peer_zid` (wire bytes, any
    /// trailing zero bytes) closed, and say how many it ordered and how many had
    /// been ordered already. An unknown peer is the default: both zero.
    fn order_close(&self, peer_zid: &[u8]) -> CloseOrder;
}

impl<D: SessionDirectory + ?Sized> SessionDirectory for &D {
    fn order_close(&self, peer_zid: &[u8]) -> CloseOrder {
        (**self).order_close(peer_zid)
    }
}

/// Why a close was refused, as one of a closed set of reasons.
///
/// The words are the implementation's own and a querier shows them as written, so
/// each is a sentence that stands alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedReason {
    /// The node's authority does not admit closing the session this key names.
    NotPermitted,
    /// The key's last chunk is not a zid in the spelling a key carries.
    PeerNotAZid,
}

impl RefusedReason {
    /// Every reason this module can give, for the declared set to be held to.
    pub const ALL: [Self; 2] = [Self::NotPermitted, Self::PeerNotAZid];

    /// The sentence a querier is shown. Plain ASCII with no quote or backslash, so
    /// it is written into the JSON as it stands.
    pub const fn words(self) -> &'static str {
        match self {
            Self::NotPermitted => "this node does not permit closing the session with that peer",
            Self::PeerNotAZid => "the last chunk of the key is not a zid",
        }
    }
}

/// The answer to a close query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseVerdict {
    /// The close was ordered on `links` links; the sessions are on their way out.
    Closing {
        /// Links this call ordered closed.
        links: u32,
    },
    /// Every session with that peer had already been ordered closed.
    AlreadyClosed,
    /// This node holds no session with that peer.
    NotFound,
    /// The close was not attempted.
    Refused(RefusedReason),
}

impl CloseVerdict {
    /// The verdict a [`CloseOrder`] amounts to.
    pub fn of(order: CloseOrder) -> Self {
        if order.newly_ordered > 0 {
            Self::Closing {
                links: order.newly_ordered,
            }
        } else if order.already_ordered > 0 {
            Self::AlreadyClosed
        } else {
            Self::NotFound
        }
    }

    /// Write the reply document: one JSON object. The words of `verdict` are the
    /// closed set `closing`, `already_closed`, `not_found`, `refused`; `links`
    /// appears only on `closing` and `reason` only on `refused`.
    pub fn write_json<W: TextOut + ?Sized>(&self, out: &mut W) {
        match self {
            Self::Closing { links } => {
                let _ = write!(out, "{{\"verdict\":\"closing\",\"links\":{links}}}");
            }
            Self::AlreadyClosed => out.push_str("{\"verdict\":\"already_closed\"}"),
            Self::NotFound => out.push_str("{\"verdict\":\"not_found\"}"),
            Self::Refused(reason) => {
                out.push_str("{\"verdict\":\"refused\",\"reason\":\"");
                out.push_str(reason.words());
                out.push_str("\"}");
            }
        }
    }

    /// The `verdict` word, for a declared set to be held to.
    pub const fn word(&self) -> &'static str {
        match self {
            Self::Closing { .. } => "closing",
            Self::AlreadyClosed => "already_closed",
            Self::NotFound => "not_found",
            Self::Refused(_) => "refused",
        }
    }

    /// Every `verdict` word, for a declared set to be held to.
    pub const WORDS: [&'static str; 4] = ["closing", "already_closed", "not_found", "refused"];
}

/// The lifecycle verbs a node has bound, in the order the capability query lists
/// them. One today.
pub const VERBS: [&str; 1] = [CLOSE_VERB];

/// Write the capability document `{"verbs":["close"]}`.
pub fn write_verbs_json<W: TextOut + ?Sized>(out: &mut W) {
    out.push_str("{\"verbs\":[");
    for (i, verb) in VERBS.iter().enumerate() {
        if i > 0 {
            out.push_str(",");
        }
        out.push_str("\"");
        out.push_str(verb);
        out.push_str("\"");
    }
    out.push_str("]}");
}

/// The queryables a node hosts to serve the lifecycle queries, as the key
/// patterns to register them on. The first answers the close query for any peer,
/// the second the capability query.
pub fn query_patterns(zid_hex: &str, whatami: &str) -> [String; 2] {
    let root = alloc::format!("@/{zid_hex}/{whatami}/session");
    [
        alloc::format!("{root}/close/*"),
        alloc::format!("{root}/verbs"),
    ]
}

/// Answers the lifecycle queries of one node.
///
/// Holds nothing it does not borrow from the host: the node's identity, the
/// authority that says who may close and the directory that holds the sessions.
/// [`Self::answer`] is the body of the queryable handler the host registers on
/// [`query_patterns`].
pub struct LifecycleQueries<A, D> {
    zid_hex: String,
    whatami: String,
    authority: A,
    directory: D,
}

/// What [`LifecycleQueries::answer`] did with a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answered {
    /// A reply was staged: the close query's verdict.
    Close(CloseVerdict),
    /// A reply was staged: the capability document.
    Verbs,
    /// The query is neither lifecycle query this node serves, or is a close query
    /// that is not an exact key; nothing was replied.
    Unserved,
}

impl<A: SessionLifecycleAuthority, D: SessionDirectory> LifecycleQueries<A, D> {
    /// The queries of the node `zid_hex` (zenoh's spelling) of role `whatami`.
    pub fn new(zid_hex: &str, whatami: &str, authority: A, directory: D) -> Self {
        Self {
            zid_hex: String::from(zid_hex),
            whatami: String::from(whatami),
            authority,
            directory,
        }
    }

    /// The patterns to register this on.
    pub fn patterns(&self) -> [String; 2] {
        query_patterns(&self.zid_hex, &self.whatami)
    }

    fn verbs_key(&self) -> String {
        alloc::format!("@/{}/{}/session/verbs", self.zid_hex, self.whatami)
    }

    /// Answer one query: the close query with its verdict, the capability query
    /// with the verb list, or nothing.
    pub fn answer(&self, view: &dyn QueryView, out: &mut dyn ReplyOut) -> Answered {
        let key = view.keyexpr();

        let verbs_key = self.verbs_key();
        let verbs_chunks: alloc::vec::Vec<&str> = verbs_key.split('/').collect();
        if crate::keyexpr_match::keyexpr_intersects_target(key, &verbs_chunks) {
            let mut body: FixedText<64> = FixedText::new();
            write_verbs_json(&mut body);
            return match body.finish() {
                Ok(text) if reply_json(out, &verbs_key, text).is_ok() => Answered::Verbs,
                _ => Answered::Unserved,
            };
        }

        // The close query: an exact key naming this node and one peer. A pattern
        // is never a target (module docs).
        let Some(parsed) = LifecycleKey::parse(key) else {
            return Answered::Unserved;
        };
        if parsed.verb != CLOSE_VERB
            || parsed.node_zid != self.zid_hex
            || parsed.whatami != self.whatami
            || parsed.peer_zid.contains(['*', '$'])
        {
            return Answered::Unserved;
        }

        let verdict = if !self.authority.admits_close(&parsed) {
            CloseVerdict::Refused(RefusedReason::NotPermitted)
        } else if let Some(peer) = zenoh_hex_to_zid(parsed.peer_zid) {
            CloseVerdict::of(self.directory.order_close(&peer))
        } else {
            CloseVerdict::Refused(RefusedReason::PeerNotAZid)
        };

        let mut body: FixedText<192> = FixedText::new();
        verdict.write_json(&mut body);
        match body.finish() {
            Ok(text) if reply_json(out, key, text).is_ok() => Answered::Close(verdict),
            // A reply the stage refused still happened as an order: the verdict is
            // what the node did, and the host's reply-stage counters say the rest.
            Ok(_) => Answered::Close(verdict),
            Err(_) => Answered::Unserved,
        }
    }
}

/// Stage one JSON reply under `key`.
fn reply_json(out: &mut dyn ReplyOut, key: &str, body: &str) -> Result<(), ReplyError> {
    // The PACKED id (`id << 1`): its low bit says a schema string follows, so the
    // bare id of `application/json` (5) would announce a schema that is not there
    // and the querier would read the reply as malformed and close the session.
    out.reply_keyed_encoded_parts(
        key,
        body.as_bytes(),
        crate::sample::EncodingHint::APPLICATION_JSON.packed_id,
        None,
    )
}

/// One session a host holds, as the close query reads it. Implemented for the
/// session bundle itself, so a host's face table is a list of these and its
/// directory is one call to [`order_close_over`].
pub trait SessionTarget {
    /// The zid of the peer this session is with, once the handshake named it.
    fn peer_zid(&self) -> Option<alloc::vec::Vec<u8>>;
    /// Whether a close has already been ordered for this session.
    fn close_ordered(&self) -> bool;
    /// Order this session closed.
    fn order_close(&self);
}

impl<R: crate::link::SessionRuntime, T: wz_runtime_core::TimeSource> SessionTarget
    for crate::session_actions::SessionLinkActions<R, T>
{
    fn peer_zid(&self) -> Option<alloc::vec::Vec<u8>> {
        crate::session_actions::SessionLinkActions::peer_zid(self)
    }

    fn close_ordered(&self) -> bool {
        crate::session_actions::SessionLinkActions::close_ordered(self)
    }

    fn order_close(&self) {
        self.request_close();
    }
}

/// Order closed every session of `sessions` that is with `peer_zid`, once each.
///
/// The one place "count the links, order the ones not yet ordered, never order one
/// twice" is decided, so that every host's [`SessionDirectory`] is the enumeration
/// of its own face table and nothing more. Zids are compared as values
/// ([`same_zid`]), so a peer that pads its id with trailing zero bytes is the peer
/// its key names.
pub fn order_close_over<'a, S, I>(sessions: I, peer_zid: &[u8]) -> CloseOrder
where
    S: SessionTarget + ?Sized + 'a,
    I: IntoIterator<Item = &'a S>,
{
    let mut order = CloseOrder::default();
    for session in sessions {
        let Some(zid) = session.peer_zid() else {
            continue;
        };
        if !same_zid(&zid, peer_zid) {
            continue;
        }
        if session.close_ordered() {
            order.already_ordered = order.already_ordered.saturating_add(1);
        } else {
            session.order_close();
            order.newly_ordered = order.newly_ordered.saturating_add(1);
        }
    }
    order
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query_sink::BorrowedQuery;
    use crate::sample::{EncodingHint, QosLevel};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::{Cell, RefCell};

    const ME: &str = "a1b2";
    const PEER_A: &str = "c3d4";
    const PEER_B: &str = "e5f6";

    /// A reply sink that keeps what it was given.
    #[derive(Default)]
    struct Recorder {
        /// `(key, body, packed encoding id)` per reply.
        replies: Vec<(String, String, u32)>,
    }

    impl ReplyOut for Recorder {
        fn reply(&mut self, _payload: &[u8]) {}
        fn reply_del(&mut self) {}
        fn reply_keyed_encoded(
            &mut self,
            keyexpr: &str,
            payload: &[u8],
            encoding: Option<&EncodingHint>,
        ) -> Result<(), ReplyError> {
            self.replies.push((
                String::from(keyexpr),
                String::from_utf8(payload.to_vec()).expect("a lifecycle reply is text"),
                encoding.expect("a lifecycle reply is typed").packed_id,
            ));
            Ok(())
        }
        fn reply_err(&mut self, _id: Option<u32>, _schema: Option<&str>, _payload: &[u8]) {}
        fn with_responder(&mut self, _zid: &[u8], _eid: u32) {}
        fn clear_responder(&mut self) {}
        fn responder(&self) -> Option<(&[u8], u32)> {
            None
        }
    }

    fn query(keyexpr: &str) -> impl QueryView + '_ {
        BorrowedQuery {
            keyexpr,
            parameters: None,
            attachment: None,
            source_info: None,
            payload: None,
            encoding: None,
            rid: 1,
            is_local: false,
            qos: QosLevel::DEFAULT,
        }
    }

    /// An authority with one answer for every key, counting how often it is asked.
    struct Authority {
        admits: bool,
        asked: Cell<u32>,
    }

    impl SessionLifecycleAuthority for Authority {
        fn admits_close(&self, _key: &LifecycleKey<'_>) -> bool {
            self.asked.set(self.asked.get() + 1);
            self.admits
        }
    }

    /// Sessions that remember being ordered closed.
    struct Fake {
        zid: Option<Vec<u8>>,
        ordered: Cell<bool>,
    }

    impl SessionTarget for Fake {
        fn peer_zid(&self) -> Option<Vec<u8>> {
            self.zid.clone()
        }
        fn close_ordered(&self) -> bool {
            self.ordered.get()
        }
        fn order_close(&self) {
            self.ordered.set(true);
        }
    }

    struct Table(RefCell<Vec<Fake>>);

    impl SessionDirectory for Table {
        fn order_close(&self, peer_zid: &[u8]) -> CloseOrder {
            order_close_over(self.0.borrow().iter(), peer_zid)
        }
    }

    fn fake(zid: &str) -> Fake {
        Fake {
            zid: zenoh_hex_to_zid(zid),
            ordered: Cell::new(false),
        }
    }

    fn node(admits: bool, sessions: Vec<Fake>) -> LifecycleQueries<Authority, Table> {
        LifecycleQueries::new(
            ME,
            "peer",
            Authority {
                admits,
                asked: Cell::new(0),
            },
            Table(RefCell::new(sessions)),
        )
    }

    fn ask(
        node: &LifecycleQueries<Authority, Table>,
        key: &str,
    ) -> (Answered, Vec<(String, String)>) {
        let mut out = Recorder::default();
        let answered = node.answer(&query(key), &mut out);
        for (_, _, encoding) in &out.replies {
            // The PACKED id of application/json, 5 << 1: the bare 5 has its
            // schema-present bit set, and a querier reads it as a malformed reply.
            assert_eq!(*encoding, 10);
        }
        (
            answered,
            out.replies.into_iter().map(|(k, b, _)| (k, b)).collect(),
        )
    }

    /// The four verdicts are four different documents, each a single JSON object
    /// with only the keys its word carries, under the key that was asked.
    #[test]
    fn each_verdict_is_its_own_document_under_the_asked_key() {
        let key = alloc::format!("@/{ME}/peer/session/close/{PEER_A}");
        let node = node(true, vec![fake(PEER_A), fake(PEER_B)]);

        let (answered, replies) = ask(&node, &key);
        assert_eq!(
            answered,
            Answered::Close(CloseVerdict::Closing { links: 1 })
        );
        assert_eq!(
            replies,
            vec![(
                key.clone(),
                String::from("{\"verdict\":\"closing\",\"links\":1}")
            )]
        );

        // The same peer again: nothing new to order, and it says so.
        let (answered, replies) = ask(&node, &key);
        assert_eq!(answered, Answered::Close(CloseVerdict::AlreadyClosed));
        assert_eq!(
            replies,
            vec![(
                key.clone(),
                String::from("{\"verdict\":\"already_closed\"}")
            )]
        );

        // A peer this node has no session with.
        let nobody = alloc::format!("@/{ME}/peer/session/close/1f0e");
        let (answered, replies) = ask(&node, &nobody);
        assert_eq!(answered, Answered::Close(CloseVerdict::NotFound));
        assert_eq!(
            replies,
            vec![(nobody, String::from("{\"verdict\":\"not_found\"}"))]
        );

        // The other peer was not touched by any of it.
        assert!(!node.directory.0.borrow()[1].ordered.get());
    }

    /// A close ends the WHOLE session: every link to the peer, counted, each
    /// ordered once. The control is the peer's neighbour, which stays open.
    #[test]
    fn a_close_orders_every_link_to_the_peer_and_counts_them() {
        let key = alloc::format!("@/{ME}/peer/session/close/{PEER_A}");
        let one_already = fake(PEER_A);
        one_already.ordered.set(true);
        let node = node(
            true,
            vec![fake(PEER_A), fake(PEER_A), one_already, fake(PEER_B)],
        );

        let (answered, _) = ask(&node, &key);
        assert_eq!(
            answered,
            Answered::Close(CloseVerdict::Closing { links: 2 }),
            "two links were ordered by this call; the third had been ordered before"
        );
        let table = node.directory.0.borrow();
        assert!(table[..3].iter().all(|s| s.ordered.get()));
        assert!(!table[3].ordered.get(), "CONTROL: another peer's session");
    }

    /// A session whose peer zid is padded with trailing zero bytes is the peer its
    /// key names: ids are compared as values.
    #[test]
    fn a_peer_with_a_padded_zid_is_the_peer_its_key_names() {
        let mut padded = fake(PEER_A);
        padded
            .zid
            .as_mut()
            .expect("a zid")
            .extend_from_slice(&[0, 0]);
        let node = node(true, vec![padded]);
        let key = alloc::format!("@/{ME}/peer/session/close/{PEER_A}");
        assert_eq!(
            ask(&node, &key).0,
            Answered::Close(CloseVerdict::Closing { links: 1 })
        );
    }

    /// A refusal asks the directory nothing: the sessions are not touched, and the
    /// reply carries the reason in the implementation's own words.
    #[test]
    fn a_refused_close_touches_no_session_and_says_why() {
        let key = alloc::format!("@/{ME}/peer/session/close/{PEER_A}");
        let node = node(false, vec![fake(PEER_A)]);
        let (answered, replies) = ask(&node, &key);
        assert_eq!(
            answered,
            Answered::Close(CloseVerdict::Refused(RefusedReason::NotPermitted))
        );
        assert_eq!(
            replies,
            vec![(
                key,
                String::from(
                    "{\"verdict\":\"refused\",\"reason\":\"this node does not permit closing \
                     the session with that peer\"}"
                )
            )]
        );
        assert!(!node.directory.0.borrow()[0].ordered.get());

        // A last chunk that is not a zid is refused, after the authority has spoken.
        let node = node_for_bad_peer();
        let bad = alloc::format!("@/{ME}/peer/session/close/not-a-zid");
        let (answered, replies) = ask(&node, &bad);
        assert_eq!(
            answered,
            Answered::Close(CloseVerdict::Refused(RefusedReason::PeerNotAZid))
        );
        assert!(replies[0]
            .1
            .contains("\"reason\":\"the last chunk of the key is not a zid\""));
    }

    fn node_for_bad_peer() -> LifecycleQueries<Authority, Table> {
        node(true, vec![fake(PEER_A)])
    }

    /// A destructive verb is reached only by a key that names its target. A pattern,
    /// another node's key, another role's key and a key of another verb get no reply,
    /// and the authority is not even asked.
    #[test]
    fn a_close_is_reached_only_by_a_key_that_names_one_peer_of_this_node() {
        let node = node(true, vec![fake(PEER_A)]);
        for key in [
            alloc::format!("@/{ME}/peer/session/close/*"),
            alloc::format!("@/{ME}/peer/session/close/**"),
            alloc::format!("@/{ME}/peer/session/close/$*"),
            alloc::format!("@/{ME}/peer/session/cl$*/{PEER_A}"),
            alloc::format!("@/ffff/peer/session/close/{PEER_A}"),
            alloc::format!("@/{ME}/router/session/close/{PEER_A}"),
            alloc::format!("@/{ME}/peer/session/open/{PEER_A}"),
            alloc::format!("@/{ME}/peer/session/close"),
            String::from("demo/anything"),
        ] {
            let (answered, replies) = ask(&node, &key);
            assert_eq!(answered, Answered::Unserved, "{key}");
            assert!(replies.is_empty(), "{key}");
        }
        assert_eq!(
            node.authority.asked.get(),
            0,
            "no key above reached the authority"
        );
        assert!(!node.directory.0.borrow()[0].ordered.get());

        // A pattern that covers the capability key is answered with the capability
        // and nothing else: it is a question about the verbs, never a target.
        for pattern in [
            alloc::format!("@/{ME}/peer/session/**"),
            alloc::format!("@/{ME}/peer/**"),
        ] {
            let (answered, _) = ask(&node, &pattern);
            assert_eq!(answered, Answered::Verbs, "{pattern}");
        }
        assert_eq!(node.authority.asked.get(), 0);
        assert!(!node.directory.0.borrow()[0].ordered.get());
    }

    /// The capability query names the verbs the node has bound, to a literal key and
    /// to a pattern that covers it; and it does not depend on the authority.
    #[test]
    fn the_capability_query_lists_the_bound_verbs() {
        let verbs = alloc::format!("@/{ME}/peer/session/verbs");
        for admits in [true, false] {
            let node = node(admits, Vec::new());
            for asked in [
                verbs.clone(),
                alloc::format!("@/{ME}/peer/session/*"),
                alloc::format!("@/{ME}/peer/**"),
            ] {
                let (answered, replies) = ask(&node, &asked);
                assert_eq!(answered, Answered::Verbs, "{asked}");
                assert_eq!(
                    replies,
                    vec![(verbs.clone(), String::from("{\"verbs\":[\"close\"]}"))],
                    "{asked}"
                );
            }
            assert_eq!(node.authority.asked.get(), 0);
        }
        // Another node's capability is not this node's to answer.
        let node = node(true, Vec::new());
        assert_eq!(
            ask(&node, "@/ffff/peer/session/verbs").0,
            Answered::Unserved
        );
    }

    /// The patterns a host registers are the two keys the queries are asked on.
    #[test]
    fn the_registered_patterns_cover_exactly_the_two_queries() {
        let [close, verbs] = query_patterns(ME, "peer");
        assert_eq!(close, "@/a1b2/peer/session/close/*");
        assert_eq!(verbs, "@/a1b2/peer/session/verbs");
    }

    /// The words a querier switches on are one closed set, each its own document.
    #[test]
    fn the_verdict_words_are_the_declared_set() {
        let all = [
            CloseVerdict::Closing { links: 3 },
            CloseVerdict::AlreadyClosed,
            CloseVerdict::NotFound,
            CloseVerdict::Refused(RefusedReason::NotPermitted),
        ];
        let words: Vec<&str> = all.iter().map(CloseVerdict::word).collect();
        assert_eq!(words, CloseVerdict::WORDS);
        for verdict in all {
            let mut text: FixedText<192> = FixedText::new();
            verdict.write_json(&mut text);
            let doc = text.finish().expect("fits");
            assert!(
                doc.starts_with(&alloc::format!("{{\"verdict\":\"{}\"", verdict.word())),
                "{doc}"
            );
            assert_eq!(
                doc.contains("\"links\""),
                matches!(verdict, CloseVerdict::Closing { .. })
            );
            assert_eq!(
                doc.contains("\"reason\""),
                matches!(verdict, CloseVerdict::Refused(_))
            );
        }
        for reason in RefusedReason::ALL {
            assert!(
                !reason.words().contains(['"', '\\']),
                "a reason is written into the JSON as it stands"
            );
        }
    }
}

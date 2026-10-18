// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The buffers an admin reply is built in, and what refusing one means
//! (fixed-memory step S9b).
//!
//! An admin reply is a document of up to a few hundred bytes, written by hand
//! ([`crate::adminspace`]) and handed to the session's reply stage as one payload.
//! On the AP the document is a `String` that grows, as it always was. A node with
//! no allocator builds it in a buffer whose size is a number its deploy file
//! states (`session_pool.process.admin_reply_bytes`, [`crate::caps::MAX_ADMIN_REPLY_BYTES`]),
//! and a document that does not fit is not cut to fit: it is REFUSED, COUNTED, and
//! the querier is told, in a typed error reply, that its answer was too large for
//! this node. [`crate::admin_reply::AdminBuffer`] is the one trait both buffers are
//! written through, and [`crate::admin_reply::AdminReplyError`] is what a refusal is called.
//!
//! The refusal is per leg. A GET that intersects the node's root document and its
//! config document gets each of them or the typed error for each, and one leg's
//! refusal never takes another's reply with it.

use crate::adminspace::{
    answer_admin_query_in, serve_one_leg, AdminAnswerOutcome, AdminDeclaration, AdminLegEncoding,
    AdminMulticastPeerRef, AdminNodeFacts, AdminPlugin, AdminSessionRef,
};
use crate::query_sink::ReplyError;
use crate::text_out::{FixedText, Overflow, TextOut};

/// A buffer an admin reply is written into: a [`TextOut`] that can be emptied
/// for the next document and read back as a result.
///
/// `String` never refuses and is what the AP writes into; [`FixedText`] holds `N`
/// bytes, refuses what does not fit and says so from [`Self::contents`], which is
/// the only way the answerer reads a document back, so it cannot deliver a cut one.
pub trait AdminBuffer: TextOut {
    /// Empty the buffer, and forget any refusal, ready for the next document.
    fn reset(&mut self);

    /// The document written since the last [`Self::reset`], or the refusal that
    /// means it is not the whole one.
    fn contents(&self) -> Result<&str, Overflow>;
}

#[cfg(feature = "alloc")]
impl AdminBuffer for alloc::string::String {
    fn reset(&mut self) {
        self.clear();
    }

    fn contents(&self) -> Result<&str, Overflow> {
        Ok(self.as_str())
    }
}

impl<const N: usize> AdminBuffer for FixedText<N> {
    fn reset(&mut self) {
        self.clear();
    }

    fn contents(&self) -> Result<&str, Overflow> {
        self.finish()
    }
}

/// Why an admin reply was not delivered whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminReplyError {
    /// The reply body did not fit its buffer: [`Overflow::needed`] is the size the
    /// document has, [`Overflow::capacity`] the size the deploy file allows. The
    /// leg is answered with a typed error and counted, never cut short.
    TooLarge(Overflow),
    /// The keyexpr the reply is stamped with did not fit its buffer. The leg is not
    /// answered (its key cannot be matched against the query) and it is counted.
    KeyTooLong(Overflow),
    /// The document was built, and the session's reply stage refused it. The stage
    /// has counted that refusal in its own tables
    /// ([`crate::reply_stage::ReplyRefusals`]); this carries which.
    Refused(ReplyError),
}

impl core::fmt::Display for AdminReplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge(o) => write!(f, "admin reply too large: {o}"),
            Self::KeyTooLong(o) => write!(f, "admin reply key too long: {o}"),
            Self::Refused(e) => write!(f, "admin reply refused by the reply stage: {e}"),
        }
    }
}

/// What the admin answerer refused since it was made, by why.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AdminReplyRefusals {
    /// Legs whose body did not fit [`crate::caps::MAX_ADMIN_REPLY_BYTES`] (or the
    /// size the arena was made with).
    pub too_large: u32,
    /// Legs whose reply key did not fit [`crate::caps::MAX_ADMIN_KEY_BYTES`].
    pub key_too_long: u32,
    /// Replies built whole that the session's reply stage then refused.
    pub refused_by_stage: u32,
}

impl AdminReplyRefusals {
    /// Count one refusal.
    pub fn note(&mut self, error: &AdminReplyError) {
        let count = match error {
            AdminReplyError::TooLarge(_) => &mut self.too_large,
            AdminReplyError::KeyTooLong(_) => &mut self.key_too_long,
            AdminReplyError::Refused(_) => &mut self.refused_by_stage,
        };
        *count = count.saturating_add(1);
    }

    /// Add what another set of counts holds, as a node adds each GET's refusals to
    /// its running total.
    pub fn add(&mut self, other: &Self) {
        self.too_large = self.too_large.saturating_add(other.too_large);
        self.key_too_long = self.key_too_long.saturating_add(other.key_too_long);
        self.refused_by_stage = self.refused_by_stage.saturating_add(other.refused_by_stage);
    }
}

/// The scratch a node with no allocator builds its admin replies in: one reply key
/// buffer, one body buffer and one config buffer, sized by the deploy file
/// (`session_pool.process.admin_reply_bytes`, [`crate::caps::MAX_ADMIN_REPLY_BYTES`])
/// and a running count of what it refused.
///
/// # Per process, not per session, and why that is not the isolation hole it looks like
///
/// There is ONE arena for the node, and every session's admin GET is answered in
/// it. That is correct here where the peer tables are per session (decision Q7)
/// because the arena is SCRATCH, not state: a GET is answered to completion, the
/// reply copied into the asking session's own reply stage, before the next one
/// starts, and nothing a peer can write is kept in it. What a peer can exhaust is
/// the stage it asks into ([`crate::reply_stage`]), which is the session's. A
/// per-session arena would multiply the buffers by the number of sessions to hold
/// bytes no session holds at the same time.
///
/// The arena is borrowed mutably for the length of one answer
/// ([`Self::answer`]), so a handler cannot re-enter it; a host that keeps it behind
/// a lock and finds the lock taken has a re-entrant call and refuses it itself.
///
/// `BODY` is the body buffer's size and the config buffer's, the one number the
/// deploy file states; the key buffer is [`crate::caps::MAX_ADMIN_KEY_BYTES`].
pub struct AdminReplyArena<const BODY: usize> {
    key: FixedText<{ crate::caps::MAX_ADMIN_KEY_BYTES }>,
    body: FixedText<BODY>,
    config: FixedText<BODY>,
    refusals: AdminReplyRefusals,
}

impl<const BODY: usize> AdminReplyArena<BODY> {
    /// An empty arena. `const`, so a node places it in a `static`.
    pub const fn new() -> Self {
        Self {
            key: FixedText::new(),
            body: FixedText::new(),
            config: FixedText::new(),
            refusals: AdminReplyRefusals {
                too_large: 0,
                key_too_long: 0,
                refused_by_stage: 0,
            },
        }
    }

    /// What this arena has refused since it was made, by why. The counts a node's
    /// status report reads.
    pub fn refusals(&self) -> AdminReplyRefusals {
        self.refusals
    }

    /// Answer one admin GET from the node's facts, in this arena's buffers, with
    /// nothing allocated: [`crate::adminspace::answer_admin_query_in`] over fixed
    /// buffers.
    ///
    /// `write_config` renders the node's config document into the buffer it is
    /// given; it runs for every GET (a host's config can change between them) and
    /// a document that does not fit refuses the `config` leg only. `Ok` means every
    /// leg the GET reached was replied to whole; `Err` is the FIRST refusal, and
    /// every refusal of this call is counted in [`Self::refusals`] either way, so
    /// the caller that ignores the `Err` has still lost nothing from the count.
    #[allow(clippy::too_many_arguments)]
    pub fn answer<'a, S, M, L>(
        &mut self,
        view: &dyn crate::query_sink::QueryView,
        out: &mut dyn crate::query_sink::ReplyOut,
        node: AdminNodeFacts<'a, S, M, L>,
        declarations: &[AdminDeclaration],
        plugins: &[AdminPlugin],
        write_config: impl FnOnce(&mut FixedText<BODY>),
    ) -> Result<AdminAnswerOutcome, AdminReplyError>
    where
        S: Iterator<Item = AdminSessionRef<'a>>,
        M: Iterator<Item = AdminMulticastPeerRef<'a>>,
        L: Iterator<Item = &'a str>,
    {
        let Self {
            key,
            body,
            config,
            refusals,
        } = self;
        config.clear();
        write_config(config);
        let report = answer_admin_query_in(
            key,
            body,
            view,
            out,
            node,
            declarations,
            plugins,
            config.finish(),
        );
        refusals.add(&report.refusals);
        report.into_result()
    }

    /// Serve ONE leg the host owns, `@/<zid>/<whatami>/<tail>` (a wz-native key
    /// beside upstream's, such as a node's connection status), in this arena's
    /// buffers: the key is matched against the GET and the body `write_body` writes is
    /// replied as `encoding`, and a key or body that does not fit is refused and
    /// counted as an upstream leg's is. `Ok` also when the GET does not reach the leg.
    #[allow(clippy::too_many_arguments)]
    pub fn serve_leg(
        &mut self,
        view: &dyn crate::query_sink::QueryView,
        out: &mut dyn crate::query_sink::ReplyOut,
        zid_hex: &str,
        whatami: &str,
        tail: &str,
        encoding: AdminLegEncoding,
        write_body: impl FnOnce(&mut FixedText<BODY>),
    ) -> Result<(), AdminReplyError> {
        let report = serve_one_leg(
            &mut self.key,
            &mut self.body,
            view,
            out,
            zid_hex,
            whatami,
            tail,
            encoding,
            write_body,
        );
        self.refusals.add(&report.refusals);
        report.first_error.map_or(Ok(()), Err)
    }
}

impl<const BODY: usize> Default for AdminReplyArena<BODY> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adminspace::{
        answer_admin_query, AdminAnswerCtx, AdminLink, AdminMulticastPeerRef, AdminSession,
    };
    use crate::query_sink::{BorrowedQuery, QueryView, ReplyOut};
    use crate::sample::{EncodingHint, QosLevel};
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    /// A reply sink that keeps what it was given, for a test to read.
    #[derive(Default)]
    struct Recorder {
        /// `(key, body, packed encoding id, encoding schema)` per reply, in order.
        replies: Vec<(String, String, u32, Option<String>)>,
        /// `(encoding id, body)` per Err reply, in order.
        errors: Vec<(Option<u32>, String)>,
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
            let encoding = encoding.expect("an admin reply is typed");
            self.replies.push((
                String::from(keyexpr),
                String::from_utf8(payload.to_vec()).expect("an admin reply is text"),
                encoding.packed_id,
                encoding.schema.clone(),
            ));
            Ok(())
        }
        fn reply_err(&mut self, encoding_id: Option<u32>, _schema: Option<&str>, payload: &[u8]) {
            self.errors.push((
                encoding_id,
                String::from_utf8(payload.to_vec()).expect("an error body is text"),
            ));
        }
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

    /// The node every test here asks about: zid `a1b2`, a peer, one locator.
    macro_rules! facts {
        ($locators:expr, $sessions:expr) => {
            AdminNodeFacts {
                zid_hex: "a1b2",
                whatami: "peer",
                version: "v1",
                metadata_json: "null",
                read: true,
                stats: None,
                locators: $locators.iter().copied(),
                sessions: $sessions.iter().map(AdminSession::view),
                multicast_peers: core::iter::empty::<AdminMulticastPeerRef<'_>>(),
            }
        };
    }

    const LOCATORS: [&str; 1] = ["udp/10.0.0.1:7447"];

    /// The bytes of `{"locators":["udp/10.0.0.1:7447"],"metadata":null,"plugins":null,
    /// "sessions":[],"version":"v1","zid":"a1b2"}`, the root document of the node
    /// above with no session: counted off the document itself, with `plugins` the
    /// two bytes shorter (`{}` for `null`) that a build with the plugin legs writes.
    const ROOT_BYTES: usize = if cfg!(feature = "adminspace-plugins-handlers") {
        105
    } else {
        107
    };

    fn root_only<const N: usize>(
        arena: &mut AdminReplyArena<N>,
        out: &mut Recorder,
        config_bytes: usize,
    ) -> Result<AdminAnswerOutcome, AdminReplyError> {
        arena.answer(
            &query("@/a1b2/peer"),
            out,
            facts!(LOCATORS, Vec::<AdminSession>::new()),
            &[],
            &[],
            |config| {
                for _ in 0..config_bytes {
                    config.push('c');
                }
            },
        )
    }

    /// The fixed arena's replies ARE the `String` path's, byte for byte, for every
    /// leg a wildcard reaches: one writer, two sinks, so the node with no allocator
    /// is not a second implementation that could drift.
    #[test]
    fn a_fixed_arena_replies_with_the_bytes_the_string_path_does() {
        let sessions = vec![AdminSession {
            peer_zid_hex: String::from("c3d4"),
            whatami: Some(String::from("router")),
            links: vec![AdminLink {
                src: String::from("udp/10.0.0.1:7447"),
                dst: String::from("udp/10.0.0.9:50000"),
            }],
            ..AdminSession::default()
        }];
        let locators = vec![String::from("udp/10.0.0.1:7447")];
        for keyexpr in [
            "@/a1b2/peer/**",
            "@/a1b2/peer",
            "@/a1b2/peer/config",
            "@/a1b2/peer/wz/surface",
            "@/ffff/peer/**",
        ] {
            let mut heap = Recorder::default();
            let outcome = answer_admin_query(
                &query(keyexpr),
                &mut heap,
                &AdminAnswerCtx {
                    zid_hex: "a1b2",
                    whatami: "peer",
                    version: "v1",
                    locators: &locators,
                    metadata_json: "null",
                    read: true,
                    stats: None,
                    multicast_peers: &[],
                },
                &sessions,
                &[],
                &[],
                "{\"k\":1}",
            );
            assert_eq!(outcome, AdminAnswerOutcome::Served);

            let mut fixed = Recorder::default();
            let mut arena: AdminReplyArena<2048> = AdminReplyArena::new();
            let locator_refs: Vec<&str> = locators.iter().map(String::as_str).collect();
            let result = arena.answer(
                &query(keyexpr),
                &mut fixed,
                facts!(locator_refs, sessions),
                &[],
                &[],
                |config| config.push_str("{\"k\":1}"),
            );
            assert_eq!(result, Ok(AdminAnswerOutcome::Served), "GET {keyexpr}");
            assert_eq!(fixed.replies, heap.replies, "GET {keyexpr}");
            assert_eq!(arena.refusals(), AdminReplyRefusals::default());
        }
    }

    /// A reply of exactly the bound fits and is delivered whole; one byte more is
    /// refused, counted, answered to the querier as a typed error and never cut.
    #[test]
    fn a_body_of_exactly_the_bound_fits_and_one_byte_more_is_refused_and_counted() {
        let mut out = Recorder::default();
        let mut exact: AdminReplyArena<ROOT_BYTES> = AdminReplyArena::new();
        assert_eq!(
            root_only(&mut exact, &mut out, 0),
            Ok(AdminAnswerOutcome::Served)
        );
        assert_eq!(out.replies.len(), 1);
        assert_eq!(out.replies[0].1.len(), ROOT_BYTES);
        assert!(out.replies[0].1.ends_with("\"zid\":\"a1b2\"}"));
        assert!(out.errors.is_empty());
        assert_eq!(exact.refusals(), AdminReplyRefusals::default());

        let mut out = Recorder::default();
        let mut short: AdminReplyArena<{ ROOT_BYTES - 1 }> = AdminReplyArena::new();
        let result = root_only(&mut short, &mut out, 0);
        assert_eq!(
            result,
            Err(AdminReplyError::TooLarge(Overflow {
                needed: ROOT_BYTES,
                capacity: ROOT_BYTES - 1
            }))
        );
        assert!(out.replies.is_empty(), "nothing is delivered cut short");
        assert_eq!(out.errors.len(), 1, "the querier gets a typed refusal");
        assert_eq!(
            out.errors[0].0,
            Some(u32::from(crate::encoding::ID_APPLICATION_JSON))
        );
        assert_eq!(
            out.errors[0].1,
            alloc::format!(
                "{{\"error\":\"admin_reply_too_large\",\"needed\":{},\"capacity\":{}}}",
                ROOT_BYTES,
                ROOT_BYTES - 1
            )
        );
        assert_eq!(
            short.refusals(),
            AdminReplyRefusals {
                too_large: 1,
                ..AdminReplyRefusals::default()
            }
        );
    }

    /// One leg's refusal takes no other leg's reply with it, and the arena serves the
    /// next GET after a refusal.
    #[test]
    fn a_refused_leg_leaves_the_other_legs_served_and_the_arena_reusable() {
        // Root and manifest are over 100 bytes, the config document is not.
        let mut out = Recorder::default();
        let mut arena: AdminReplyArena<100> = AdminReplyArena::new();
        let result = arena.answer(
            &query("@/a1b2/peer/**"),
            &mut out,
            facts!(LOCATORS, Vec::<AdminSession>::new()),
            &[],
            &[],
            |config| config.push_str("{}"),
        );
        assert!(matches!(result, Err(AdminReplyError::TooLarge(_))));
        let config: Vec<_> = out
            .replies
            .iter()
            .filter(|reply| reply.0 == "@/a1b2/peer/config")
            .collect();
        assert_eq!(config.len(), 1, "the config leg is served");
        assert_eq!(config[0].1, "{}");
        // The root document and the manifest are refused (a build with more legs
        // refuses more of them), each counted once and each answered with an error.
        assert!(out.errors.len() >= 2);
        assert_eq!(arena.refusals().too_large as usize, out.errors.len());

        // The next GET is served by the same arena, and the count is kept.
        let mut next = Recorder::default();
        let result = arena.answer(
            &query("@/a1b2/peer/config"),
            &mut next,
            facts!(LOCATORS, Vec::<AdminSession>::new()),
            &[],
            &[],
            |config| config.push_str("{}"),
        );
        assert_eq!(result, Ok(AdminAnswerOutcome::Served));
        assert_eq!(next.replies.len(), 1);
        assert_eq!(arena.refusals().too_large as usize, out.errors.len());
    }

    /// A config document that does not fit refuses the config leg alone.
    #[test]
    fn a_config_that_does_not_fit_refuses_the_config_leg_only() {
        let mut out = Recorder::default();
        let mut arena: AdminReplyArena<ROOT_BYTES> = AdminReplyArena::new();
        let result = root_only(&mut arena, &mut out, ROOT_BYTES + 1);
        // The GET names the root only, so the config document is not asked for and
        // is not a refusal: nothing intersects the config key.
        assert_eq!(result, Ok(AdminAnswerOutcome::Served));
        assert_eq!(out.replies.len(), 1);

        let mut out = Recorder::default();
        let result = arena.answer(
            &query("@/a1b2/peer/config"),
            &mut out,
            facts!(LOCATORS, Vec::<AdminSession>::new()),
            &[],
            &[],
            |config| {
                for _ in 0..=ROOT_BYTES {
                    config.push('c');
                }
            },
        );
        assert_eq!(
            result,
            Err(AdminReplyError::TooLarge(Overflow {
                needed: ROOT_BYTES + 1,
                capacity: ROOT_BYTES
            }))
        );
        assert!(out.replies.is_empty());
        assert_eq!(out.errors.len(), 1);
        assert_eq!(arena.refusals().too_large, 1);
    }

    /// A reply key that does not fit its buffer is counted and the leg is not
    /// answered: its key cannot even be matched against the query.
    #[test]
    fn a_key_that_does_not_fit_is_counted_and_the_leg_is_not_answered() {
        let mut key: FixedText<8> = FixedText::new();
        let mut body: FixedText<256> = FixedText::new();
        let mut out = Recorder::default();
        let answer = answer_admin_query_in(
            &mut key,
            &mut body,
            &query("@/a1b2/peer"),
            &mut out,
            facts!(LOCATORS, Vec::<AdminSession>::new()),
            &[],
            &[],
            Ok("{}"),
        );
        assert!(out.replies.is_empty());
        assert!(out.errors.is_empty());
        assert!(answer.refusals.key_too_long >= 1);
        assert_eq!(answer.refusals.too_large, 0);
        assert!(matches!(
            answer.first_error,
            Some(AdminReplyError::KeyTooLong(Overflow { capacity: 8, .. }))
        ));
    }

    /// A reply the session's stage refuses is counted and handed back as the
    /// stage's own refusal.
    #[test]
    fn a_reply_the_stage_refuses_is_counted_as_the_stages() {
        struct Refusing;
        impl ReplyOut for Refusing {
            fn reply(&mut self, _payload: &[u8]) {}
            fn reply_del(&mut self) {}
            fn reply_keyed_encoded(
                &mut self,
                _keyexpr: &str,
                _payload: &[u8],
                _encoding: Option<&EncodingHint>,
            ) -> Result<(), ReplyError> {
                Err(ReplyError::StagingFull)
            }
            fn reply_err(&mut self, _id: Option<u32>, _schema: Option<&str>, _payload: &[u8]) {}
            fn with_responder(&mut self, _zid: &[u8], _eid: u32) {}
            fn clear_responder(&mut self) {}
            fn responder(&self) -> Option<(&[u8], u32)> {
                None
            }
        }
        let mut arena: AdminReplyArena<256> = AdminReplyArena::new();
        let result = arena.answer(
            &query("@/a1b2/peer"),
            &mut Refusing,
            facts!(LOCATORS, Vec::<AdminSession>::new()),
            &[],
            &[],
            |_| {},
        );
        assert_eq!(
            result,
            Err(AdminReplyError::Refused(ReplyError::StagingFull))
        );
        assert_eq!(
            arena.refusals(),
            AdminReplyRefusals {
                refused_by_stage: 1,
                ..AdminReplyRefusals::default()
            }
        );
    }

    #[test]
    fn a_fixed_buffer_reads_back_only_a_whole_document() {
        let mut b: FixedText<4> = FixedText::new();
        b.push_str("abcd");
        assert_eq!(AdminBuffer::contents(&b), Ok("abcd"));
        b.push('e');
        assert_eq!(
            AdminBuffer::contents(&b),
            Err(Overflow {
                needed: 5,
                capacity: 4
            })
        );
        AdminBuffer::reset(&mut b);
        b.push_str("ab");
        assert_eq!(AdminBuffer::contents(&b), Ok("ab"));
    }

    #[test]
    fn each_refusal_is_counted_under_its_own_name() {
        let o = Overflow {
            needed: 2,
            capacity: 1,
        };
        let mut r = AdminReplyRefusals::default();
        r.note(&AdminReplyError::TooLarge(o));
        r.note(&AdminReplyError::TooLarge(o));
        r.note(&AdminReplyError::KeyTooLong(o));
        r.note(&AdminReplyError::Refused(ReplyError::StagingFull));
        assert_eq!(
            r,
            AdminReplyRefusals {
                too_large: 2,
                key_too_long: 1,
                refused_by_stage: 1
            }
        );
    }
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What an observer owes its peer, taken out of it so that it is sent after the observer is let
//! go.
//!
//! The drain of an [`ApplicationLayerObserver`](crate::observer::ApplicationLayerObserver) sends
//! the replies a queryable staged and the declarations that answer a peer's interests. A send may
//! wait for room on its link, for as long as the link stays full, and the thread that holds the
//! observer meanwhile stops everything that needs it: the drive thread delivers nothing, and a
//! teardown cannot retire what it retracts. So the drain is split in two. Under the observer the
//! host decides what to send: the staged replies are moved out whole
//! ([`ApplicationLayerObserver::take_owed_replies`](crate::observer::ApplicationLayerObserver::take_owed_replies)),
//! and each declaration is resolved against the registries it answers from, as the drain always
//! resolved it, and kept here. With the observer let go, the host sends what it took
//! ([`OwedReplies::send`]), in the order the drain would have sent it.
//!
//! The decision and the send are one step against a retraction: a declaration resolved here must
//! reach the link before a retraction of the same entity that is retired after it. The host holds
//! one lock across both halves, and the teardown of an entity takes the same lock around its
//! retirement and its retraction; this value is what that lock guards, so the lock and what it
//! orders cannot be told apart.

#[cfg(any(
    feature = "liveliness-token",
    feature = "declare-subscriber",
    feature = "declare-queryable"
))]
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::reply_stage::ReplyStage;
#[cfg(feature = "query-queryable")]
use crate::reply_stage::ReplyStaging;
use crate::response_sink::{DeclareReplySink, ResponseSink};

/// One declaration owed to the peer, resolved when it was decided: what a
/// [`DeclareReplySink`] call carries, owned. One variant per method of the sink, gated as the
/// method is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OwedDeclaration {
    #[cfg(feature = "liveliness-token")]
    Token {
        token_id: u64,
        keyexpr: String,
        interest_id: u64,
    },
    #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
    Final { interest_id: u64 },
    #[cfg(feature = "declare-subscriber")]
    Subscriber {
        subscriber_id: u64,
        keyexpr: String,
        interest_id: u64,
    },
    #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
    UndeclareSubscriber { subscriber_id: u64 },
    #[cfg(feature = "declare-queryable")]
    Queryable {
        queryable_id: u64,
        keyexpr: String,
        complete: bool,
        interest_id: u64,
    },
}

/// The replies and declarations an observer's drain decided to send, held until they are sent.
///
/// Empty between two drains: a host that takes from the observer sends what it took before it
/// takes again, and the stage it hands back to the observer is then the empty one, whose storage
/// the next replies reuse.
pub struct OwedReplies {
    /// The replies a queryable staged, exchanged out of the observer whole: the rows and the
    /// arena they lie in, written to the link from where they lie, as the drain wrote them.
    replies: ReplyStage,
    /// The declarations, in the order the drain resolved them. A cell because the drain hands a
    /// sink by shared reference.
    declarations: RefCell<Vec<OwedDeclaration>>,
}

impl OwedReplies {
    /// Nothing owed.
    pub const fn new() -> Self {
        Self {
            replies: ReplyStage::new(),
            declarations: RefCell::new(Vec::new()),
        }
    }

    /// Whether nothing is owed.
    pub fn is_empty(&self) -> bool {
        self.replies.is_empty() && self.declarations.borrow().is_empty()
    }

    /// How many declarations are owed.
    pub fn declarations_owed(&self) -> usize {
        self.declarations.borrow().len()
    }

    /// Take the replies `stage` holds, and leave it the empty rows this value held. The counts of
    /// what each stage refused stay with it.
    pub(crate) fn take_replies_from(&mut self, stage: &mut ReplyStage) {
        debug_assert!(
            self.replies.is_empty(),
            "the replies taken last were sent before more are taken"
        );
        self.replies.exchange_staged(stage);
    }

    /// Send what is owed through `sink`, the replies first and then the declarations, in the
    /// order the drain decided them, and owe nothing after.
    pub fn send<S: ResponseSink + DeclareReplySink>(&mut self, sink: &S) {
        self.send_replies(sink);
        self.send_declarations(sink);
    }

    /// Send the owed replies through `sink`, from where they lie, and owe none after.
    pub fn send_replies<S: ResponseSink>(&mut self, sink: &S) {
        #[cfg(feature = "query-queryable")]
        self.replies
            .drain_parts(|parts| sink.send_reply_parts(parts));
        // Without `query-queryable` nothing stages a reply; the stage is emptied all the same.
        #[cfg(not(feature = "query-queryable"))]
        {
            let _ = sink;
            self.replies.clear();
        }
    }

    /// Send the owed declarations through `sink`, in order, and owe none after.
    pub fn send_declarations<S: DeclareReplySink>(&mut self, sink: &S) {
        for owed in self.declarations.get_mut().drain(..) {
            match owed {
                #[cfg(feature = "liveliness-token")]
                OwedDeclaration::Token {
                    token_id,
                    keyexpr,
                    interest_id,
                } => sink.send_declare_token_reply(token_id, &keyexpr, interest_id),
                #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
                OwedDeclaration::Final { interest_id } => {
                    sink.send_declare_final_reply(interest_id)
                }
                #[cfg(feature = "declare-subscriber")]
                OwedDeclaration::Subscriber {
                    subscriber_id,
                    keyexpr,
                    interest_id,
                } => sink.send_declare_subscriber_reply(subscriber_id, &keyexpr, interest_id),
                #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
                OwedDeclaration::UndeclareSubscriber { subscriber_id } => {
                    sink.send_undeclare_subscriber_reply(subscriber_id)
                }
                #[cfg(feature = "declare-queryable")]
                OwedDeclaration::Queryable {
                    queryable_id,
                    keyexpr,
                    complete,
                    interest_id,
                } => {
                    sink.send_declare_queryable_reply(queryable_id, &keyexpr, complete, interest_id)
                }
            }
        }
    }

    #[cfg(any(
        feature = "liveliness-token",
        feature = "declare-subscriber",
        feature = "declare-queryable"
    ))]
    fn owe(&self, declaration: OwedDeclaration) {
        self.declarations.borrow_mut().push(declaration);
    }
}

impl Default for OwedReplies {
    fn default() -> Self {
        Self::new()
    }
}

/// The drain's sink while the host decides: each declaration is kept, resolved as the drain
/// resolved it, and nothing is sent.
impl DeclareReplySink for OwedReplies {
    #[cfg(feature = "liveliness-token")]
    fn send_declare_token_reply(&self, token_id: u64, keyexpr: &str, interest_id: u64) {
        self.owe(OwedDeclaration::Token {
            token_id,
            keyexpr: String::from(keyexpr),
            interest_id,
        });
    }

    #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
    fn send_declare_final_reply(&self, interest_id: u64) {
        self.owe(OwedDeclaration::Final { interest_id });
    }

    #[cfg(feature = "declare-subscriber")]
    fn send_declare_subscriber_reply(&self, subscriber_id: u64, keyexpr: &str, interest_id: u64) {
        self.owe(OwedDeclaration::Subscriber {
            subscriber_id,
            keyexpr: String::from(keyexpr),
            interest_id,
        });
    }

    #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
    fn send_undeclare_subscriber_reply(&self, subscriber_id: u64) {
        self.owe(OwedDeclaration::UndeclareSubscriber { subscriber_id });
    }

    #[cfg(feature = "declare-queryable")]
    fn send_declare_queryable_reply(
        &self,
        queryable_id: u64,
        keyexpr: &str,
        complete: bool,
        interest_id: u64,
    ) {
        self.owe(OwedDeclaration::Queryable {
            queryable_id,
            keyexpr: String::from(keyexpr),
            complete,
            interest_id,
        });
    }
}

#[cfg(all(test, feature = "declare-subscriber", feature = "declare-undeclare"))]
mod tests {
    use super::*;
    use alloc::vec;

    /// A sink that writes down, in order, each declaration it is handed.
    #[derive(Default)]
    struct Written(RefCell<Vec<OwedDeclaration>>);

    impl DeclareReplySink for Written {
        #[cfg(feature = "liveliness-token")]
        fn send_declare_token_reply(&self, token_id: u64, keyexpr: &str, interest_id: u64) {
            self.0.borrow_mut().push(OwedDeclaration::Token {
                token_id,
                keyexpr: String::from(keyexpr),
                interest_id,
            });
        }
        #[cfg(any(feature = "liveliness-token", feature = "declare-subscriber"))]
        fn send_declare_final_reply(&self, interest_id: u64) {
            self.0
                .borrow_mut()
                .push(OwedDeclaration::Final { interest_id });
        }
        #[cfg(feature = "declare-subscriber")]
        fn send_declare_subscriber_reply(
            &self,
            subscriber_id: u64,
            keyexpr: &str,
            interest_id: u64,
        ) {
            self.0.borrow_mut().push(OwedDeclaration::Subscriber {
                subscriber_id,
                keyexpr: String::from(keyexpr),
                interest_id,
            });
        }
        #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
        fn send_undeclare_subscriber_reply(&self, subscriber_id: u64) {
            self.0
                .borrow_mut()
                .push(OwedDeclaration::UndeclareSubscriber { subscriber_id });
        }
    }

    /// What is owed is sent in the order it was decided, through the sink the host hands, and
    /// nothing is sent while it is only owed.
    #[test]
    fn owed_declarations_leave_in_the_order_they_were_decided_and_only_when_sent() {
        let mut owed = OwedReplies::new();
        owed.send_declare_subscriber_reply(3, "home/temp", 7);
        owed.send_undeclare_subscriber_reply(4);
        owed.send_declare_final_reply(7);
        assert_eq!(owed.declarations_owed(), 3, "decided, and kept");
        let written = Written::default();
        owed.send_declarations(&written);
        assert_eq!(
            written.0.into_inner(),
            vec![
                OwedDeclaration::Subscriber {
                    subscriber_id: 3,
                    keyexpr: String::from("home/temp"),
                    interest_id: 7,
                },
                OwedDeclaration::UndeclareSubscriber { subscriber_id: 4 },
                OwedDeclaration::Final { interest_id: 7 },
            ],
            "sent in the order decided"
        );
        assert!(owed.is_empty(), "nothing is owed once sent");
    }
}

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y616 (§1.1f) — the FILTER LANGUAGE: the selector a reader types, turned
//! into a predicate over the records the aggregation planes fold.
//!
//! Every plane before this one answers "what is in this capture". The question
//! a reader actually arrives with is narrower — *what is in this capture ABOUT
//! `demo/**`*, *which queries took longer than a second*, *what is B sending
//! that A is not* — and until now the only way to ask it was to write the fold
//! by hand, which is the same reason [`crate::agg`] exists one layer down.
//!
//! ## The rule this module exists to enforce
//!
//! **A filter that cannot decide says so. It never answers `false`.**
//!
//! A capture is a partial observation by construction: a keyexpr may reference
//! an id whose declaration went past before the tap started, and a capture
//! format may carry no clock at all. A predicate over such a record has three
//! answers, not two, and collapsing the third into "no match" is the exact
//! fabrication this crate refuses everywhere else — the reader would see a
//! filtered total that is quietly short and indistinguishable from one that is
//! whole.
//!
//! So evaluation is Kleene's strong three-valued logic ([`Truth`]), and the
//! undecidable records are COUNTED ([`Selection::undecided`]) rather than
//! silently dropped. Three-valued and not merely "propagate unknown": `unknown
//! AND no` is `no`, because a record that fails the decidable half of a
//! conjunction is out whatever the missing field held. Only where the missing
//! field could still change the answer does the record become undecidable.
//!
//! ## The language
//!
//! ```text
//! filter := or
//! or     := and (("or" | "||") and)*
//! and    := unary (("and" | "&&") unary)*
//! unary  := ("not" | "!") unary | atom
//! atom   := "(" filter ")" | term
//! term   := field op value
//! ```
//!
//! | field | values | operators | undecidable when |
//! |---|---|---|---|
//! | `key` | a keyexpr pattern (`demo/**`) | `==` `!=` | the reference did not resolve |
//! | `dir` | `a` / `b` | `==` `!=` | never |
//! | `kind` | `put` `del` `query` `reply` `err` | `==` `!=` | never |
//! | `bytes` | an integer | `==` `!=` `<` `<=` `>` `>=` | never |
//! | `time` | an integer, ms | `==` `!=` `<` `<=` `>` `>=` | the capture carried no clock |
//!
//! `dir` is `a` / `b` and not `a2b` / `b2a` because
//! [`Direction`](wz_session_core::passive::Direction) is what the rest of the
//! crate says and a second vocabulary for one axis is a second thing to get
//! wrong.
//!
//! `key` matching is zenoh's own — [`keyexpr_pattern_matches`], the matcher the
//! subscriber and queryable registries use — rather than a glob written here.
//! A filter language for zenoh traffic that did not speak zenoh's keyexpr
//! dialect would be a second dialect a reader has to learn, and it would
//! disagree with the router about `**` at exactly the interesting cases.
//!
//! ## Wildcards are a feature, and their absence is a REFUSAL
//!
//! `keyexpr_pattern_matches`' wildcard arms are per-capability features of
//! `wz-session-core`, and with them off a `**` token DEGRADES TO A LITERAL
//! CHUNK — `demo/**` quietly stops matching `demo/a` and matches the literal
//! chunk `**` instead. That degradation is right for an MCU client composing
//! its own matcher and catastrophic for a filter language, where it turns a
//! reader's selector into a silently empty answer.
//!
//! So this module refuses instead: with `filter-wildcards` off, a pattern
//! carrying `*` is a PARSE ERROR ([`FilterErrorKind::WildcardUnsupported`]).
//! The reader is told the build cannot answer their question, which is the one
//! outcome that is never a wrong answer.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use wz_session_core::keyexpr_match::keyexpr_pattern_matches;
use wz_session_core::passive::Direction;

/// Which counter a record moves — the record's kind as a filter can ask about
/// it.
///
/// Deliberately the NETWORK-level kinds and not the wire message names: a
/// reader asks for "the puts", and whether a put arrived inside a `Push` or
/// inside a `Request` is a routing detail of the sender's, not a property of
/// the traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// A `MsgPut`, in a `Push` or a `Request`.
    Put,
    /// A `MsgDel`.
    Del,
    /// A `Query`.
    Query,
    /// A `Reply`, whatever it carries — including one carrying a `MsgPut`.
    ///
    /// The kinds partition records exactly as
    /// [`KeyexprCounts`](crate::agg::KeyexprCounts) does, so `kind == reply`
    /// and the `replies` counter can never disagree about the same record. A
    /// reader after reply payloads asks `kind == reply and bytes > 0`.
    Reply,
    /// An `Err`.
    Err,
}

impl RecordKind {
    fn parse(word: &str) -> Option<Self> {
        Some(match word {
            "put" => Self::Put,
            "del" => Self::Del,
            "query" => Self::Query,
            "reply" => Self::Reply,
            "err" => Self::Err,
            _ => return None,
        })
    }
}

/// One record, as a filter sees it.
///
/// Both optional fields are optional for a REASON rather than for convenience,
/// and the reason is the same in each: the capture may not carry the fact. A
/// `None` here is what makes a term over that field undecidable instead of
/// false.
#[derive(Debug, Clone, Copy)]
pub struct RecordView<'a> {
    /// The direction the record travelled.
    pub direction: Direction,
    /// The resolved keyexpr, or `None` when the reference named an id no space
    /// had bound (see [`crate::agg::UnresolvedAlias`]).
    pub keyexpr: Option<&'a str>,
    /// What the record is.
    pub kind: RecordKind,
    /// Application payload bytes present in it.
    pub payload_bytes: u64,
    /// The capture clock as of the frame that carried it, or `None` when the
    /// capture format carried no timestamp
    /// ([`PassiveFrame::observed_at_ms`](wz_session_core::passive::PassiveFrame::observed_at_ms)).
    pub observed_at_ms: Option<u64>,
}

/// A three-valued answer.
///
/// [`Self::Unknown`] is not "probably not". It is "this capture does not carry
/// the fact this predicate needs", and it is a distinct outcome all the way out
/// to [`Selection::undecided`] so a reader can see how much of the capture the
/// filter could not speak about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Truth {
    /// The record matches.
    Yes,
    /// The record does not match.
    No,
    /// The capture does not carry what deciding would need.
    Unknown,
}

impl Truth {
    fn of(b: bool) -> Self {
        if b {
            Self::Yes
        } else {
            Self::No
        }
    }

    /// Kleene negation: the unknown stays unknown.
    fn not(self) -> Self {
        match self {
            Self::Yes => Self::No,
            Self::No => Self::Yes,
            Self::Unknown => Self::Unknown,
        }
    }
}

/// How the six comparisons are spelled, once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl Op {
    fn apply(self, lhs: u64, rhs: u64) -> bool {
        match self {
            Self::Eq => lhs == rhs,
            Self::Ne => lhs != rhs,
            Self::Lt => lhs < rhs,
            Self::Le => lhs <= rhs,
            Self::Gt => lhs > rhs,
            Self::Ge => lhs >= rhs,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
        }
    }
}

/// One comparison, already validated against its field's admissible operators.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Term {
    /// Pattern chunks, pre-split so evaluation does no parsing.
    Key {
        chunks: Vec<String>,
        negated: bool,
    },
    Dir {
        want: Direction,
        negated: bool,
    },
    Kind {
        want: RecordKind,
        negated: bool,
    },
    Bytes {
        op: Op,
        value: u64,
    },
    Time {
        op: Op,
        value: u64,
    },
}

impl Term {
    fn eval(&self, record: &RecordView<'_>) -> Truth {
        match self {
            Self::Key { chunks, negated } => match record.keyexpr {
                // The undecidable case, and the one this module exists for: the
                // record HAS a keyexpr, the capture just never carried the
                // declaration that names it. Answering `no` would drop it from
                // the reader's total silently.
                None => Truth::Unknown,
                Some(target) => {
                    let refs: Vec<&str> = chunks.iter().map(|c| c.as_str()).collect();
                    Truth::of(keyexpr_pattern_matches(&refs, target) != *negated)
                }
            },
            Self::Dir { want, negated } => {
                Truth::of((dir_index(record.direction) == dir_index(*want)) != *negated)
            }
            Self::Kind { want, negated } => Truth::of((record.kind == *want) != *negated),
            Self::Bytes { op, value } => Truth::of(op.apply(record.payload_bytes, *value)),
            Self::Time { op, value } => match record.observed_at_ms {
                // The second undecidable case: pcap carries a timestamp per
                // packet and a raw byte-stream fixture carries none, so a
                // `time` term over a clockless capture is a question this
                // observation cannot answer. R311y615 made this representable
                // by keeping the clock an `Option` all the way up.
                None => Truth::Unknown,
                Some(at) => Truth::of(op.apply(at, *value)),
            },
        }
    }
}

fn dir_index(d: Direction) -> usize {
    match d {
        Direction::A => 0,
        Direction::B => 1,
    }
}

/// The parsed expression tree.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    /// The empty filter — every record matches, nothing is undecidable.
    Any,
    Or(Vec<Node>),
    And(Vec<Node>),
    Not(alloc::boxed::Box<Node>),
    Term(Term),
}

impl Node {
    fn eval(&self, record: &RecordView<'_>) -> Truth {
        match self {
            Self::Any => Truth::Yes,
            Self::Term(t) => t.eval(record),
            Self::Not(inner) => inner.eval(record).not(),
            // Kleene conjunction: one decided `No` settles it whatever the rest
            // could not decide. Short-circuiting on `No` is not an optimisation
            // here, it is the semantics — `unknown AND no` must be `no`.
            Self::And(nodes) => {
                let mut unknown = false;
                for n in nodes {
                    match n.eval(record) {
                        Truth::No => return Truth::No,
                        Truth::Unknown => unknown = true,
                        Truth::Yes => {}
                    }
                }
                if unknown {
                    Truth::Unknown
                } else {
                    Truth::Yes
                }
            }
            // The dual: one decided `Yes` settles a disjunction.
            Self::Or(nodes) => {
                let mut unknown = false;
                for n in nodes {
                    match n.eval(record) {
                        Truth::Yes => return Truth::Yes,
                        Truth::Unknown => unknown = true,
                        Truth::No => {}
                    }
                }
                if unknown {
                    Truth::Unknown
                } else {
                    Truth::No
                }
            }
        }
    }
}

/// A compiled selector.
///
/// Parsed once and evaluated per record — the pattern chunk split, the operator
/// dispatch and every value conversion happen at [`Filter::parse`], so the
/// per-record path is a tree walk with no text handling in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    root: Node,
}

impl Default for Filter {
    fn default() -> Self {
        Self::any()
    }
}

impl Filter {
    /// The filter that selects everything.
    ///
    /// The identity the unfiltered entry points pass, so there is ONE fold in
    /// the aggregation planes rather than a filtered one and an unfiltered copy
    /// that drift.
    pub fn any() -> Self {
        Self { root: Node::Any }
    }

    /// `true` when this filter selects everything — an empty selector, or the
    /// literal [`Filter::any`].
    pub fn is_any(&self) -> bool {
        self.root == Node::Any
    }

    /// Compile a selector.
    ///
    /// An empty (or all-whitespace) selector is [`Filter::any`]: the natural
    /// reading of "no filter given", and it keeps a caller wiring a command-line
    /// flag from having to special-case the empty string into a different code
    /// path.
    pub fn parse(source: &str) -> Result<Self, FilterError> {
        let tokens = lex(source)?;
        if tokens.is_empty() {
            return Ok(Self::any());
        }
        let mut parser = Parser {
            tokens: &tokens,
            at: 0,
        };
        let root = parser.expression()?;
        if let Some(tok) = parser.peek() {
            return Err(FilterError {
                at: tok.at,
                kind: FilterErrorKind::TrailingInput,
            });
        }
        Ok(Self { root })
    }

    /// Decide one record.
    pub fn matches(&self, record: &RecordView<'_>) -> Truth {
        self.root.eval(record)
    }
}

/// What a filter did to the records it was shown.
///
/// The accounting is the point rather than a diagnostic: `matched` alone is a
/// number a reader would take for "the traffic about `demo/**`", and it is only
/// that if `undecided` is zero. Carried on the table so the export plane can
/// put it in the document beside the totals it qualifies.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    /// Records the filter said yes to. These are the ones in the rows.
    pub matched: usize,
    /// Records the filter said no to.
    pub rejected: usize,
    /// Records the capture did not carry enough to decide.
    ///
    /// NOT in the rows, and not in `rejected` either: a reader asking "is this
    /// total the whole answer" has to be able to see the difference between a
    /// record that was excluded and a record that could not be judged.
    pub undecided: usize,
}

impl Selection {
    /// Every record the filter was shown.
    pub fn seen(&self) -> usize {
        self.matched + self.rejected + self.undecided
    }

    /// `true` when the filter decided every record it was shown.
    pub fn is_decisive(&self) -> bool {
        self.undecided == 0
    }

    /// Fold one verdict in.
    pub fn record(&mut self, truth: Truth) {
        match truth {
            Truth::Yes => self.matched += 1,
            Truth::No => self.rejected += 1,
            Truth::Unknown => self.undecided += 1,
        }
    }
}

/// Why a selector did not compile.
///
/// Carries the byte offset so a caller can point at the character rather than
/// reprinting the whole selector and leaving the reader to find it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterError {
    /// Byte offset into the source where the problem is.
    pub at: usize,
    /// What went wrong.
    pub kind: FilterErrorKind,
}

/// The failure kinds, named rather than stringly-typed so a caller can branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterErrorKind {
    /// A character that cannot begin any token.
    UnexpectedChar(char),
    /// A quoted value with no closing quote.
    UnterminatedQuote,
    /// A field name this language does not have.
    UnknownField(String),
    /// A value this field does not admit (`kind == frobnicate`).
    UnknownValue { field: &'static str, value: String },
    /// An operator this field does not admit (`key >= x`).
    OperatorNotAdmitted {
        field: &'static str,
        op: &'static str,
    },
    /// An integer that did not parse, or overflowed `u64`.
    NotAnInteger(String),
    /// The selector ended in the middle of something.
    UnexpectedEnd,
    /// An operator was expected and something else was found.
    ExpectedOperator,
    /// A `(` with no `)`.
    UnclosedGroup,
    /// Input after the expression ended.
    TrailingInput,
    /// A wildcard pattern in a build whose matcher does not wildcard.
    ///
    /// A refusal and NOT a degraded match, for the reason this module's header
    /// gives: the alternative is a selector that silently means something else.
    WildcardUnsupported,
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at byte {}: ", self.at)?;
        match &self.kind {
            FilterErrorKind::UnexpectedChar(c) => write!(f, "unexpected character {c:?}"),
            FilterErrorKind::UnterminatedQuote => write!(f, "unterminated quoted value"),
            FilterErrorKind::UnknownField(name) => write!(
                f,
                "unknown field {name:?} (known: key, dir, kind, bytes, time)"
            ),
            FilterErrorKind::UnknownValue { field, value } => {
                write!(f, "{field} does not admit the value {value:?}")
            }
            FilterErrorKind::OperatorNotAdmitted { field, op } => {
                write!(f, "{field} does not admit the operator {op}")
            }
            FilterErrorKind::NotAnInteger(v) => write!(f, "{v:?} is not an unsigned integer"),
            FilterErrorKind::UnexpectedEnd => write!(f, "the selector ends here, unfinished"),
            FilterErrorKind::ExpectedOperator => write!(f, "expected a comparison operator"),
            FilterErrorKind::UnclosedGroup => write!(f, "unclosed ("),
            FilterErrorKind::TrailingInput => write!(f, "unexpected input after the expression"),
            FilterErrorKind::WildcardUnsupported => write!(
                f,
                "this build's keyexpr matcher has no wildcards, so a pattern \
                 containing '*' cannot be answered (feature `filter-wildcards`)"
            ),
        }
    }
}

/// One lexical token plus where it started.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    at: usize,
    kind: TokenKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Word(String),
    /// A quoted value — never re-read as a keyword, so `key == "or"` works.
    Quoted(String),
    Op(Op),
    Not,
    And,
    Or,
    Open,
    Close,
}

/// Characters that may appear unquoted in a word.
///
/// A superset of what a keyexpr chunk admits (`$*` for the substring DSL, `@`
/// for the admin prefix, `#`/`?` because a selector value is not always a
/// keyexpr) minus everything the grammar itself uses. Anything outside it is
/// still expressible — in quotes.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric()
        || matches!(
            c,
            '/' | '*' | '$' | '-' | '_' | '.' | '@' | '#' | '?' | '%' | '+' | ':' | ','
        )
}

fn lex(source: &str) -> Result<Vec<Token>, FilterError> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let at = i;
        match c {
            '(' => {
                tokens.push(Token {
                    at,
                    kind: TokenKind::Open,
                });
                i += 1;
            }
            ')' => {
                tokens.push(Token {
                    at,
                    kind: TokenKind::Close,
                });
                i += 1;
            }
            '"' | '\'' => {
                let quote = c;
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && bytes[j] as char != quote {
                    j += 1;
                }
                if j >= bytes.len() {
                    return Err(FilterError {
                        at,
                        kind: FilterErrorKind::UnterminatedQuote,
                    });
                }
                tokens.push(Token {
                    at,
                    kind: TokenKind::Quoted(source[start..j].to_string()),
                });
                i = j + 1;
            }
            '=' | '!' | '<' | '>' | '&' | '|' => {
                let two = source.get(i..i + 2).unwrap_or("");
                let (kind, width) = match (c, two) {
                    (_, "==") => (TokenKind::Op(Op::Eq), 2),
                    (_, "!=") => (TokenKind::Op(Op::Ne), 2),
                    (_, "<=") => (TokenKind::Op(Op::Le), 2),
                    (_, ">=") => (TokenKind::Op(Op::Ge), 2),
                    (_, "&&") => (TokenKind::And, 2),
                    (_, "||") => (TokenKind::Or, 2),
                    ('<', _) => (TokenKind::Op(Op::Lt), 1),
                    ('>', _) => (TokenKind::Op(Op::Gt), 1),
                    ('!', _) => (TokenKind::Not, 1),
                    // A lone `=`, `&` or `|`: named as the character it is
                    // rather than silently taken for the two-character form,
                    // which would make `a = b` mean something the reader did
                    // not write.
                    _ => {
                        return Err(FilterError {
                            at,
                            kind: FilterErrorKind::UnexpectedChar(c),
                        })
                    }
                };
                tokens.push(Token { at, kind });
                i += width;
            }
            c if is_word_char(c) => {
                let mut j = i;
                while j < bytes.len() && is_word_char(bytes[j] as char) {
                    j += 1;
                }
                let word = &source[i..j];
                let kind = match word {
                    "and" => TokenKind::And,
                    "or" => TokenKind::Or,
                    "not" => TokenKind::Not,
                    _ => TokenKind::Word(word.to_string()),
                };
                tokens.push(Token { at, kind });
                i = j;
            }
            _ => {
                return Err(FilterError {
                    at,
                    kind: FilterErrorKind::UnexpectedChar(c),
                })
            }
        }
    }
    Ok(tokens)
}

struct Parser<'a> {
    tokens: &'a [Token],
    at: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a Token> {
        self.tokens.get(self.at)
    }

    fn next(&mut self) -> Option<&'a Token> {
        let t = self.tokens.get(self.at);
        if t.is_some() {
            self.at += 1;
        }
        t
    }

    fn end_offset(&self) -> usize {
        self.tokens.last().map(|t| t.at).unwrap_or(0)
    }

    fn expression(&mut self) -> Result<Node, FilterError> {
        let mut nodes = alloc::vec![self.conjunction()?];
        while matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Or)) {
            self.at += 1;
            nodes.push(self.conjunction()?);
        }
        Ok(if nodes.len() == 1 {
            nodes.pop().expect("just checked length")
        } else {
            Node::Or(nodes)
        })
    }

    fn conjunction(&mut self) -> Result<Node, FilterError> {
        let mut nodes = alloc::vec![self.unary()?];
        while matches!(self.peek().map(|t| &t.kind), Some(TokenKind::And)) {
            self.at += 1;
            nodes.push(self.unary()?);
        }
        Ok(if nodes.len() == 1 {
            nodes.pop().expect("just checked length")
        } else {
            Node::And(nodes)
        })
    }

    fn unary(&mut self) -> Result<Node, FilterError> {
        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Not)) {
            self.at += 1;
            return Ok(Node::Not(alloc::boxed::Box::new(self.unary()?)));
        }
        self.atom()
    }

    fn atom(&mut self) -> Result<Node, FilterError> {
        let open_at = match self.peek() {
            None => {
                return Err(FilterError {
                    at: self.end_offset(),
                    kind: FilterErrorKind::UnexpectedEnd,
                })
            }
            Some(t) => t.at,
        };
        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Open)) {
            self.at += 1;
            let inner = self.expression()?;
            match self.next() {
                Some(Token {
                    kind: TokenKind::Close,
                    ..
                }) => Ok(inner),
                _ => Err(FilterError {
                    at: open_at,
                    kind: FilterErrorKind::UnclosedGroup,
                }),
            }
        } else {
            self.term()
        }
    }

    fn term(&mut self) -> Result<Node, FilterError> {
        let (field_at, field) = match self.next() {
            Some(Token {
                at,
                kind: TokenKind::Word(w),
            }) => (*at, w.clone()),
            Some(t) => {
                return Err(FilterError {
                    at: t.at,
                    kind: FilterErrorKind::UnknownField(describe_token(&t.kind)),
                })
            }
            None => {
                return Err(FilterError {
                    at: self.end_offset(),
                    kind: FilterErrorKind::UnexpectedEnd,
                })
            }
        };

        let (op_at, op) = match self.next() {
            Some(Token {
                at,
                kind: TokenKind::Op(op),
            }) => (*at, *op),
            Some(t) => {
                return Err(FilterError {
                    at: t.at,
                    kind: FilterErrorKind::ExpectedOperator,
                })
            }
            None => {
                return Err(FilterError {
                    at: self.end_offset(),
                    kind: FilterErrorKind::UnexpectedEnd,
                })
            }
        };

        let (value_at, value) = match self.next() {
            Some(Token {
                at,
                kind: TokenKind::Word(w) | TokenKind::Quoted(w),
            }) => (*at, w.clone()),
            Some(t) => {
                return Err(FilterError {
                    at: t.at,
                    kind: FilterErrorKind::UnknownValue {
                        field: static_field_name(&field).unwrap_or("value"),
                        value: describe_token(&t.kind),
                    },
                })
            }
            None => {
                return Err(FilterError {
                    at: self.end_offset(),
                    kind: FilterErrorKind::UnexpectedEnd,
                })
            }
        };

        let term = match field.as_str() {
            "key" => {
                let negated = equality_negation(op, "key", op_at)?;
                Term::Key {
                    chunks: compile_pattern(&value, value_at)?,
                    negated,
                }
            }
            "dir" => {
                let negated = equality_negation(op, "dir", op_at)?;
                let want = match value.as_str() {
                    "a" | "A" => Direction::A,
                    "b" | "B" => Direction::B,
                    _ => {
                        return Err(FilterError {
                            at: value_at,
                            kind: FilterErrorKind::UnknownValue {
                                field: "dir",
                                value,
                            },
                        })
                    }
                };
                Term::Dir { want, negated }
            }
            "kind" => {
                let negated = equality_negation(op, "kind", op_at)?;
                let want = RecordKind::parse(&value).ok_or(FilterError {
                    at: value_at,
                    kind: FilterErrorKind::UnknownValue {
                        field: "kind",
                        value: value.clone(),
                    },
                })?;
                Term::Kind { want, negated }
            }
            "bytes" => Term::Bytes {
                op,
                value: integer(&value, value_at)?,
            },
            "time" => Term::Time {
                op,
                value: integer(&value, value_at)?,
            },
            _ => {
                return Err(FilterError {
                    at: field_at,
                    kind: FilterErrorKind::UnknownField(field),
                })
            }
        };
        Ok(Node::Term(term))
    }
}

/// `==` / `!=` only, answering whether the term is negated.
fn equality_negation(op: Op, field: &'static str, at: usize) -> Result<bool, FilterError> {
    match op {
        Op::Eq => Ok(false),
        Op::Ne => Ok(true),
        other => Err(FilterError {
            at,
            kind: FilterErrorKind::OperatorNotAdmitted {
                field,
                op: other.as_str(),
            },
        }),
    }
}

fn integer(value: &str, at: usize) -> Result<u64, FilterError> {
    value.parse::<u64>().map_err(|_| FilterError {
        at,
        kind: FilterErrorKind::NotAnInteger(value.to_string()),
    })
}

/// Split a keyexpr pattern into the chunks [`keyexpr_pattern_matches`] wants,
/// refusing what this build's matcher cannot answer.
fn compile_pattern(pattern: &str, at: usize) -> Result<Vec<String>, FilterError> {
    // The refusal, and it is deliberately at PARSE time rather than at match
    // time: a reader who typed a wildcard learns immediately that this build
    // cannot answer, instead of reading an empty table and concluding the
    // traffic was not there.
    #[cfg(not(feature = "filter-wildcards"))]
    if pattern.contains('*') {
        return Err(FilterError {
            at,
            kind: FilterErrorKind::WildcardUnsupported,
        });
    }
    let _ = at;
    Ok(pattern.split('/').map(|c| c.to_string()).collect())
}

fn describe_token(kind: &TokenKind) -> String {
    match kind {
        TokenKind::Word(w) | TokenKind::Quoted(w) => w.clone(),
        TokenKind::Op(op) => op.as_str().to_string(),
        TokenKind::Not => "not".to_string(),
        TokenKind::And => "and".to_string(),
        TokenKind::Or => "or".to_string(),
        TokenKind::Open => "(".to_string(),
        TokenKind::Close => ")".to_string(),
    }
}

fn static_field_name(field: &str) -> Option<&'static str> {
    Some(match field {
        "key" => "key",
        "dir" => "dir",
        "kind" => "kind",
        "bytes" => "bytes",
        "time" => "time",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view<'a>(
        direction: Direction,
        keyexpr: Option<&'a str>,
        kind: RecordKind,
        payload_bytes: u64,
        observed_at_ms: Option<u64>,
    ) -> RecordView<'a> {
        RecordView {
            direction,
            keyexpr,
            kind,
            payload_bytes,
            observed_at_ms,
        }
    }

    fn put(keyexpr: Option<&str>) -> RecordView<'_> {
        view(Direction::A, keyexpr, RecordKind::Put, 10, Some(100))
    }

    /// The empty selector is the identity, and it decides everything —
    /// including the records every other filter would have to call
    /// undecidable.
    #[test]
    fn an_empty_selector_selects_everything_and_decides_it() {
        for source in ["", "   ", "\t\n"] {
            let f = Filter::parse(source).expect("empty parses");
            assert!(f.is_any(), "{source:?}");
            assert_eq!(f.matches(&put(Some("demo/a"))), Truth::Yes);
            // No keyexpr, no clock: still decided, because nothing is asked.
            assert_eq!(f.matches(&put(None)), Truth::Yes);
        }
        assert!(Filter::any().is_any());
    }

    /// THE RULE. A record whose keyexpr the capture never bound is UNKNOWN, not
    /// `No` — and the difference is visible in the accounting rather than only
    /// in the enum.
    #[test]
    fn a_record_whose_keyexpr_never_resolved_is_undecided_rather_than_rejected() {
        let f = Filter::parse("key == demo/a").expect("parses");
        assert_eq!(f.matches(&put(Some("demo/a"))), Truth::Yes);
        assert_eq!(f.matches(&put(Some("other/b"))), Truth::No);
        assert_eq!(f.matches(&put(None)), Truth::Unknown);

        let mut sel = Selection::default();
        sel.record(f.matches(&put(Some("demo/a"))));
        sel.record(f.matches(&put(Some("other/b"))));
        sel.record(f.matches(&put(None)));
        assert_eq!(sel.matched, 1);
        assert_eq!(sel.rejected, 1);
        assert_eq!(sel.undecided, 1);
        assert_eq!(sel.seen(), 3);
        assert!(!sel.is_decisive());
    }

    /// A capture with no clock cannot answer a `time` question, and says so.
    /// The consumer of R311y615's decision to keep the clock an `Option`.
    #[test]
    fn a_clockless_capture_cannot_decide_a_time_term() {
        let f = Filter::parse("time >= 500").expect("parses");
        assert_eq!(
            f.matches(&view(
                Direction::A,
                Some("k"),
                RecordKind::Put,
                0,
                Some(500)
            )),
            Truth::Yes
        );
        assert_eq!(
            f.matches(&view(
                Direction::A,
                Some("k"),
                RecordKind::Put,
                0,
                Some(499)
            )),
            Truth::No
        );
        assert_eq!(
            f.matches(&view(Direction::A, Some("k"), RecordKind::Put, 0, None)),
            Truth::Unknown
        );
    }

    /// Kleene, exhaustively, in the shape that makes it more than
    /// "unknown infects everything": a decided `No` beside an unknown is `No`,
    /// and a decided `Yes` beside an unknown in a disjunction is `Yes`.
    ///
    /// Written as a table over the THREE inputs each connective can see, so a
    /// future short-circuit that reorders the walk cannot change an answer
    /// without a red here.
    #[test]
    fn the_three_valued_connectives_follow_kleene_rather_than_infecting() {
        // `key == demo/a` is unknown on an unresolved record; `bytes` is always
        // decided. The pair gives every combination without a mock evaluator.
        let unresolved = put(None);
        let resolved_match = put(Some("demo/a"));

        // unknown AND no => No: the decided half settles it.
        let f = Filter::parse("key == demo/a and bytes > 1000").expect("parses");
        assert_eq!(f.matches(&unresolved), Truth::No);
        // unknown AND yes => Unknown: the missing half could still say no.
        let f = Filter::parse("key == demo/a and bytes > 1").expect("parses");
        assert_eq!(f.matches(&unresolved), Truth::Unknown);
        // unknown OR yes => Yes.
        let f = Filter::parse("key == demo/a or bytes > 1").expect("parses");
        assert_eq!(f.matches(&unresolved), Truth::Yes);
        // unknown OR no => Unknown.
        let f = Filter::parse("key == demo/a or bytes > 1000").expect("parses");
        assert_eq!(f.matches(&unresolved), Truth::Unknown);
        // NOT unknown => Unknown. A negation cannot manufacture a decision.
        let f = Filter::parse("not key == demo/a").expect("parses");
        assert_eq!(f.matches(&unresolved), Truth::Unknown);
        assert_eq!(f.matches(&resolved_match), Truth::No);
        // And the decided cases stay ordinary two-valued logic.
        let f = Filter::parse("bytes > 1 and bytes < 100").expect("parses");
        assert_eq!(f.matches(&resolved_match), Truth::Yes);
        let f = Filter::parse("bytes > 1 and bytes < 5").expect("parses");
        assert_eq!(f.matches(&resolved_match), Truth::No);
    }

    /// `and` binds tighter than `or`, and parentheses override it. Without this
    /// `a or b and c` is ambiguous and two readers get two different answers.
    #[test]
    fn conjunction_binds_tighter_than_disjunction_and_groups_override_it() {
        let a = view(Direction::A, Some("x"), RecordKind::Put, 5, Some(1));
        // `dir == b and bytes > 100` is false; the `or` arm decides.
        let f = Filter::parse("kind == put or dir == b and bytes > 100").expect("parses");
        assert_eq!(f.matches(&a), Truth::Yes);
        // Grouped the other way the whole thing is false.
        let f = Filter::parse("(kind == put or dir == b) and bytes > 100").expect("parses");
        assert_eq!(f.matches(&a), Truth::No);
        // `&&` / `||` / `!` are the same operators spelled differently.
        let f = Filter::parse("kind == put && !(dir == b)").expect("parses");
        assert_eq!(f.matches(&a), Truth::Yes);
    }

    /// Every field's vocabulary, driven rather than described.
    #[test]
    fn each_field_reads_the_axis_it_names() {
        let r = view(
            Direction::B,
            Some("demo/temp"),
            RecordKind::Query,
            42,
            Some(7),
        );
        for (source, expected) in [
            ("dir == b", Truth::Yes),
            ("dir == a", Truth::No),
            ("dir != a", Truth::Yes),
            ("kind == query", Truth::Yes),
            ("kind == put", Truth::No),
            ("kind != put", Truth::Yes),
            ("bytes == 42", Truth::Yes),
            ("bytes != 42", Truth::No),
            ("bytes <= 42", Truth::Yes),
            ("bytes < 42", Truth::No),
            ("bytes >= 42", Truth::Yes),
            ("bytes > 42", Truth::No),
            ("time == 7", Truth::Yes),
            ("key == demo/temp", Truth::Yes),
            ("key != demo/temp", Truth::No),
            ("key == demo/other", Truth::No),
        ] {
            assert_eq!(
                Filter::parse(source).expect(source).matches(&r),
                expected,
                "{source}"
            );
        }
    }

    /// A quoted value is never re-read as a keyword, so a keyexpr chunk called
    /// `or` is expressible. The one thing a bare-word lexer gets wrong.
    #[test]
    fn a_quoted_value_is_not_reread_as_a_keyword() {
        let f = Filter::parse("key == \"and\"").expect("parses");
        assert_eq!(f.matches(&put(Some("and"))), Truth::Yes);
        assert_eq!(f.matches(&put(Some("or"))), Truth::No);
        // Single quotes too, for the shell case.
        let f = Filter::parse("key == 'not'").expect("parses");
        assert_eq!(f.matches(&put(Some("not"))), Truth::Yes);
    }

    /// Malformed selectors are REFUSED with a position and a named reason —
    /// never accepted with a guessed meaning. Each row is a different failure
    /// path through the lexer and the parser.
    #[test]
    fn a_malformed_selector_is_refused_by_name_rather_than_guessed() {
        for (source, expected) in [
            (
                "frob == 1",
                FilterErrorKind::UnknownField("frob".to_string()),
            ),
            (
                "kind == frobnicate",
                FilterErrorKind::UnknownValue {
                    field: "kind",
                    value: "frobnicate".to_string(),
                },
            ),
            (
                "dir == c",
                FilterErrorKind::UnknownValue {
                    field: "dir",
                    value: "c".to_string(),
                },
            ),
            (
                "key >= demo",
                FilterErrorKind::OperatorNotAdmitted {
                    field: "key",
                    op: ">=",
                },
            ),
            (
                "bytes > many",
                FilterErrorKind::NotAnInteger("many".to_string()),
            ),
            ("bytes >", FilterErrorKind::UnexpectedEnd),
            ("bytes", FilterErrorKind::UnexpectedEnd),
            ("(bytes > 1", FilterErrorKind::UnclosedGroup),
            ("bytes > 1)", FilterErrorKind::TrailingInput),
            ("key == \"open", FilterErrorKind::UnterminatedQuote),
            ("bytes = 1", FilterErrorKind::UnexpectedChar('=')),
            ("bytes ~ 1", FilterErrorKind::UnexpectedChar('~')),
            ("bytes 1", FilterErrorKind::ExpectedOperator),
        ] {
            let err = Filter::parse(source).expect_err(source);
            assert_eq!(err.kind, expected, "{source}");
            assert!(err.at <= source.len(), "{source}: position out of range");
            // The rendering names the position, so a caller need not.
            let shown = alloc::format!("{err}");
            assert!(shown.starts_with("at byte "), "{shown}");
        }
    }

    /// An integer beyond `u64` is refused rather than wrapped — a filter that
    /// silently compared against a wrapped bound would be a wrong answer with
    /// no error attached.
    #[test]
    fn an_out_of_range_bound_is_refused_rather_than_wrapped() {
        let err = Filter::parse("bytes > 18446744073709551616").expect_err("overflows u64");
        assert!(matches!(err.kind, FilterErrorKind::NotAnInteger(_)));
    }

    /// The wildcard arm, in the build that HAS wildcards: `demo/**` speaks
    /// zenoh's dialect, matching the matcher the routers use rather than a
    /// second glob written here.
    #[cfg(feature = "filter-wildcards")]
    #[test]
    fn a_wildcard_pattern_matches_the_way_zenohs_own_matcher_does() {
        let f = Filter::parse("key == demo/**").expect("parses");
        assert_eq!(f.matches(&put(Some("demo/a"))), Truth::Yes);
        assert_eq!(f.matches(&put(Some("demo/a/b/c"))), Truth::Yes);
        assert_eq!(f.matches(&put(Some("demo"))), Truth::Yes);
        assert_eq!(f.matches(&put(Some("other/a"))), Truth::No);

        let f = Filter::parse("key == sensors/*/temp").expect("parses");
        assert_eq!(f.matches(&put(Some("sensors/1/temp"))), Truth::Yes);
        // A single `*` is exactly one chunk, as zenoh defines it.
        assert_eq!(f.matches(&put(Some("sensors/1/2/temp"))), Truth::No);
        // Unresolved is STILL unknown under a wildcard: a pattern that would
        // match everything does not get to decide a keyexpr nobody knows.
        assert_eq!(f.matches(&put(None)), Truth::Unknown);
    }

    /// The negative arm, and it is the whole justification for the feature: in
    /// a build whose matcher degrades `**` to a literal chunk, a wildcard
    /// selector is REFUSED. Without this the same selector would parse and
    /// quietly answer about a keyexpr literally named `**`.
    #[cfg(not(feature = "filter-wildcards"))]
    #[test]
    fn a_wildcard_pattern_is_refused_where_the_matcher_cannot_honour_it() {
        let err = Filter::parse("key == demo/**").expect_err("must refuse");
        assert_eq!(err.kind, FilterErrorKind::WildcardUnsupported);
        // A literal pattern still works — the refusal is scoped to what the
        // build cannot answer, not to the field.
        let f = Filter::parse("key == demo/a").expect("literals still parse");
        assert_eq!(f.matches(&put(Some("demo/a"))), Truth::Yes);
    }
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE SENTENCE A NODE OFFERS: the selector that filters by, adds or excludes
//! the field a document's node shows, written by the grammar that reads it.
//!
//! # Why the library writes it
//!
//! A node of a field document carries its `selector_path`, its `kind` and its
//! `value`. Turning those into `<path> == <value>` is the selector grammar's
//! work: which tail of the path to write, how a value of each kind is spelled
//! (quotes and their escapes, bytes as hex, a zid in zenoh's spelling, a flag
//! as `yes`), and how the sentence joins a selector already typed. A consumer
//! that did it would hold a second copy of the grammar, and the two would part
//! the first time either moved.
//!
//! # What a sentence says
//!
//! * A node with a value: `<tail> == <value>`. Over the record whose tree holds
//!   the node it is `yes`, and its exclusion is `no` there.
//! * A group (`nested`) or a body this build does not walk (`opaque`) has no
//!   value to compare: the sentence is the PRESENCE test, `<tail>`, which is
//!   `yes` over the record that carries the field.
//!
//! The tail is the shortest that names the node's field and no other field of
//! the declared shape ([`crate::field_path`]'s naming rule): `Frame.sn` stays
//! whole because `sn` ends `Fragment.sn` too, and a record's field under
//! `Frame.payload` is written from where it is one field. The sentence is
//! parsed back before it is handed out, so a sentence this returns compiles.
//!
//! # What it does not write
//!
//! A node whose `selector_path` is `null` (the extension chain, a body folded
//! into its entry) names no field. A node of a scouting datagram names one the
//! selector never judges: no row of the scouting group is asked. A value the
//! grammar cannot spell is named as such. Each is a refusal with its reason and
//! never an empty or a guessed sentence.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Write as _;

/// The soundness property of the sentences, as one oracle every population is
/// held to (the library's tests, and the fuzz target over the C doors).
#[cfg(all(feature = "dissect", feature = "network-codecs"))]
pub mod soundness;

use crate::field_path::{naming_tail, TailRefusal};
use crate::filter::{conjunct, is_keyword, is_word_char, names_a_fixed_field, Filter, FilterError};
use wz_session_core::json5::{self, Json5Value};

/// What a consumer does with a node's sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// The sentence alone, in place of any selector.
    Filter,
    /// The selector typed, and the sentence.
    Add,
    /// The selector typed, and not the sentence.
    Exclude,
}

impl Verb {
    /// Every verb, in the order of their C ABI numbers.
    pub const ALL: [Self; 3] = [Self::Filter, Self::Add, Self::Exclude];

    /// The verb of a C ABI number: 0, 1, 2 in the order of [`Self::ALL`].
    pub fn from_code(code: i32) -> Option<Self> {
        usize::try_from(code)
            .ok()
            .and_then(|i| Self::ALL.get(i).copied())
    }

    /// The verb's C ABI number, which [`Self::from_code`] reads back.
    pub const fn code(self) -> i32 {
        match self {
            Self::Filter => 0,
            Self::Add => 1,
            Self::Exclude => 2,
        }
    }
}

/// A node's value as the field document shows it: what the sentence compares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShownValue {
    /// `bits`.
    Bits(u64),
    /// `flag`.
    Flag(bool),
    /// `uint`.
    Uint(u64),
    /// `bytes`.
    Bytes(Vec<u8>),
    /// `zid`, in zenoh's spelling as the document prints it.
    Zid(String),
    /// `text`.
    Text(String),
    /// `label`.
    Label(String),
    /// `nested`: a group, which has no value of its own.
    Nested,
    /// `opaque`: a body whose interior this build does not walk.
    Opaque,
}

impl ShownValue {
    /// The value of a walked node, as the document prints it.
    #[cfg(feature = "dissect")]
    pub fn of(value: &wz_session_core::dissect::FieldValue) -> Self {
        use wz_session_core::dissect::FieldValue as V;
        match value {
            V::Bits(v) => Self::Bits(*v),
            V::Flag(v) => Self::Flag(*v),
            V::Uint(v) => Self::Uint(*v),
            V::Bytes(v) => Self::Bytes(v.clone()),
            V::Zid(v) => Self::Zid(wz_session_core::zid_hex::zid_to_zenoh_hex(v)),
            V::Text(v) => Self::Text(v.clone()),
            V::Label(v) => Self::Label(String::from(&**v)),
            V::Nested(_) => Self::Nested,
            V::Opaque => Self::Opaque,
        }
    }
}

/// A sentence, and the selector it makes with the one typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sentence {
    /// The node's sentence alone: `Frame.sn == 9`, `qos`.
    pub term: String,
    /// What to hand the doors: the sentence joined to the selector typed as the
    /// verb says.
    pub selector: String,
}

/// Why a node offers no sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TermRefusal {
    /// The node text is not a field object: not JSON, not an object, no
    /// `selector_path` or `kind`, or a `value` that is not its kind's.
    Node(String),
    /// `selector_path` is `null`: the node names no field.
    Unnamed,
    /// The path names a field of a scouting datagram, which the selector does
    /// not judge.
    Unjudged {
        /// The node's path.
        path: String,
    },
    /// The grammar cannot spell the path or the value.
    Unwritable {
        /// The node's path.
        path: String,
        /// What could not be spelled.
        why: String,
    },
    /// The selector typed does not compile.
    Selector(FilterError),
}

impl fmt::Display for TermRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(why) => write!(f, "the node is not a field object: {why}"),
            Self::Unnamed => f.write_str(
                "the node names no field (its selector_path is null): it is the \
                 extension chain or a body shown under its entry",
            ),
            Self::Unjudged { path } => write!(
                f,
                "{path} is a field of a scouting datagram, and the selector judges no \
                 scouting row"
            ),
            Self::Unwritable { path, why } => write!(f, "{path}: {why}"),
            Self::Selector(e) => write!(f, "the selector typed does not compile: {e}"),
        }
    }
}

/// The `refusal` words of the `selector_term` document. A closed set, written
/// once, which the declared family is held to through [`term_refusal_words`].
#[derive(Clone, Copy)]
enum RefusalWord {
    Node,
    Selector,
    Unjudged,
    Unnamed,
    Unwritable,
}

impl RefusalWord {
    const ALL: [Self; 5] = [
        Self::Node,
        Self::Selector,
        Self::Unjudged,
        Self::Unnamed,
        Self::Unwritable,
    ];

    const fn word(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Selector => "selector",
            Self::Unjudged => "unjudged",
            Self::Unnamed => "unnamed",
            Self::Unwritable => "unwritable",
        }
    }

    fn of(refusal: &TermRefusal) -> Self {
        match refusal {
            TermRefusal::Node(_) => Self::Node,
            TermRefusal::Unnamed => Self::Unnamed,
            TermRefusal::Unjudged { .. } => Self::Unjudged,
            TermRefusal::Unwritable { .. } => Self::Unwritable,
            TermRefusal::Selector(_) => Self::Selector,
        }
    }
}

impl TermRefusal {
    /// The word [`term_json`] writes as `refusal` for this refusal.
    pub fn word(&self) -> &'static str {
        RefusalWord::of(self).word()
    }
}

/// Every word [`term_json`] can write as `refusal`.
pub fn term_refusal_words() -> Vec<&'static str> {
    RefusalWord::ALL.iter().map(|w| w.word()).collect()
}

/// The sentence for the node at `path` showing `value`, joined to `selector`
/// (the text typed; empty for none) as `verb` says.
pub fn term_for(
    path: Option<&str>,
    value: &ShownValue,
    verb: Verb,
    selector: &str,
) -> Result<Sentence, TermRefusal> {
    let path = path.ok_or(TermRefusal::Unnamed)?;
    let unwritable = |why: String| TermRefusal::Unwritable {
        path: String::from(path),
        why,
    };
    #[cfg(feature = "dissect")]
    if path
        .split('.')
        .next()
        .is_some_and(wz_session_core::dissect_schema::is_scouting_root)
    {
        return Err(TermRefusal::Unjudged {
            path: String::from(path),
        });
    }
    let tail = naming_tail(path, &names_a_fixed_field).map_err(|why| {
        unwritable(String::from(match why {
            TailRefusal::Undeclared => "this build's declared shape holds no such path",
            TailRefusal::Unspellable => "a segment holds a character a selector word cannot",
        }))
    })?;
    let mut term = tail;
    if let Some(literal) = literal(value) {
        term.push_str(" == ");
        term.push_str(&literal);
    }
    // Read back by the parser every door uses: what this hands out compiles,
    // and a value the grammar refuses is named here rather than at the door.
    Filter::parse(&term).map_err(|e| unwritable(alloc::format!("{e}")))?;
    let typed = conjunct(selector).map_err(TermRefusal::Selector)?;
    let selector = match (verb, typed) {
        (Verb::Filter, _) | (Verb::Add, None) => term.clone(),
        (Verb::Exclude, None) => alloc::format!("not {term}"),
        (Verb::Add, Some(typed)) => alloc::format!("{typed} and {term}"),
        (Verb::Exclude, Some(typed)) => alloc::format!("{typed} and not {term}"),
    };
    Ok(Sentence { term, selector })
}

/// How `value` is written after `==`, or `None` for a kind that has no value
/// (the sentence is then the presence test).
fn literal(value: &ShownValue) -> Option<String> {
    Some(match value {
        ShownValue::Bits(v) | ShownValue::Uint(v) => alloc::format!("{v}"),
        ShownValue::Flag(v) => String::from(if *v { "yes" } else { "no" }),
        // An empty run has no hex spelling (`0x` needs a digit), and the empty
        // quote is the same bytes.
        ShownValue::Bytes(v) if v.is_empty() => String::from("\"\""),
        ShownValue::Bytes(v) => {
            let mut out = String::from("0x");
            for b in v {
                let _ = write!(out, "{b:02x}");
            }
            out
        }
        ShownValue::Zid(v) | ShownValue::Text(v) | ShownValue::Label(v) => word_or_quoted(v),
        ShownValue::Nested | ShownValue::Opaque => return None,
    })
}

/// `text` unquoted where the lexer reads it back as one word, and quoted with
/// its `"` and `\` escaped everywhere else.
fn word_or_quoted(text: &str) -> String {
    if !text.is_empty() && text.chars().all(is_word_char) && !is_keyword(text) {
        return String::from(text);
    }
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        if matches!(c, '"' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// A field object of a field document, as [`term_for`] reads it: its path and
/// its value. Every other key (`name`, the span, `fields`) is ignored.
pub fn read_node(text: &str) -> Result<(Option<String>, ShownValue), TermRefusal> {
    let refuse = |why: &str| TermRefusal::Node(String::from(why));
    let doc = json5::parse(text)
        .map_err(|e| TermRefusal::Node(alloc::format!("the text is not JSON, {e}")))?;
    let Json5Value::Object(entries) = &doc else {
        return Err(refuse("the text is not a JSON object"));
    };
    let key = |name: &str| entries.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    let path = match key("selector_path") {
        Some(Json5Value::String(p)) => Some(p.clone()),
        Some(Json5Value::Null) => None,
        Some(_) => return Err(refuse("`selector_path` is neither a string nor null")),
        None => {
            return Err(refuse(
                "there is no `selector_path` (field documents carry it from revision 56)",
            ))
        }
    };
    let Some(Json5Value::String(kind)) = key("kind") else {
        return Err(refuse("there is no `kind` string"));
    };
    let value = key("value");
    let integer = || match value {
        Some(Json5Value::Number(n)) => json5::number_as_u64(n),
        Some(Json5Value::String(s)) => s.parse::<u64>().ok(),
        _ => None,
    };
    let string = || match value {
        Some(Json5Value::String(s)) => Some(s.clone()),
        _ => None,
    };
    let bad_value = || refuse("its `value` is not one its `kind` carries");
    let shown = match kind.as_str() {
        "bits" => ShownValue::Bits(integer().ok_or_else(bad_value)?),
        "uint" => ShownValue::Uint(integer().ok_or_else(bad_value)?),
        "flag" => match value {
            Some(Json5Value::Bool(b)) => ShownValue::Flag(*b),
            _ => return Err(bad_value()),
        },
        "bytes" => ShownValue::Bytes(string().and_then(|s| hex(&s)).ok_or_else(bad_value)?),
        "zid" => ShownValue::Zid(string().ok_or_else(bad_value)?),
        "text" => ShownValue::Text(string().ok_or_else(bad_value)?),
        "label" => ShownValue::Label(string().ok_or_else(bad_value)?),
        "nested" => ShownValue::Nested,
        "opaque" => ShownValue::Opaque,
        _ => {
            return Err(refuse(
                "its `kind` is not a kind word of the field document",
            ))
        }
    };
    Ok((path, shown))
}

/// The bytes an even run of hex digits spells.
fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some((high * 16 + low) as u8)
        })
        .collect()
}

/// The `selector_term` document: [`term_for`] over a field object of a field
/// document.
///
/// `{envelope,"ok":true,"term":"…","selector":"…"}`, or
/// `{envelope,"ok":false,"refusal":"…","message":"…"}` with `path` for
/// `unjudged` and `unwritable`, and `start` and `end` (the caret
/// `selector_diagnose` gives, a span of no width) for `selector`.
pub fn term_json(node: &str, verb: Verb, selector: &str) -> String {
    let mut out = String::from("{");
    crate::doc_revision::envelope_into(crate::doc_revision::SELECTOR_TERM, &mut out);
    match read_node(node)
        .and_then(|(path, value)| term_for(path.as_deref(), &value, verb, selector))
    {
        Ok(sentence) => {
            out.push_str(",\"ok\":true,\"term\":");
            wz_session_core::json::escape_into(&sentence.term, &mut out);
            out.push_str(",\"selector\":");
            wz_session_core::json::escape_into(&sentence.selector, &mut out);
        }
        Err(refusal) => {
            let word = refusal.word();
            let _ = write!(out, ",\"ok\":false,\"refusal\":\"{word}\",\"message\":");
            wz_session_core::json::escape_into(&alloc::format!("{refusal}"), &mut out);
            match &refusal {
                TermRefusal::Unjudged { path } | TermRefusal::Unwritable { path, .. } => {
                    out.push_str(",\"path\":");
                    wz_session_core::json::escape_into(path, &mut out);
                }
                TermRefusal::Selector(e) => {
                    let _ = write!(out, ",\"start\":{at},\"end\":{at}", at = e.at);
                }
                TermRefusal::Node(_) | TermRefusal::Unnamed => {}
            }
        }
    }
    out.push('}');
    out
}

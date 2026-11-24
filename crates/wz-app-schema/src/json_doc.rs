// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A JSON DOCUMENT a node is handed: read under a bound on its nesting, walked with a pointer to
//! where the reader stands, and refused with that pointer.
//!
//! The profiles of the application frame and the message catalog are documents of this kind, each
//! read once, when a node is handed it. Their readers share what this module holds: the bounded
//! reader ([`read_json`]), the place a reader stands ([`Pointer`]), written out only for a
//! refusal, the refusal ([`DocError`]) and the typed reads that refuse at that place.
//! `wz-app-frame` re-exports them at the paths they had in its `e2e_profile`.

use alloc::format;
use alloc::string::String;

use wz_session_core::json5::{self, Json5Value};
use wz_session_core::json5_lex::{Json5Error, Lexer};

/// Deepest nesting a profile or a values text may have. The deepest legitimate
/// profile has five levels (the document, `fields`, a field, `split`, a part);
/// a values text has three.
pub const MAX_JSON_DEPTH: usize = 8;

/// Why a document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocError {
    /// The text is not JSON, and this is the byte where reading stopped.
    Syntax {
        /// Offset into the text.
        offset: usize,
        /// What the reader expected there.
        expected: &'static str,
    },
    /// The text is JSON and not what was asked for.
    Invalid {
        /// An RFC 6901 JSON pointer to the place: empty for the document
        /// itself, `/fields/2/split/0/lsb` for a value inside it.
        path: String,
        /// The reason, as a sentence.
        reason: String,
    },
}

impl DocError {
    pub fn invalid(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Invalid {
            path: path.into(),
            reason: reason.into(),
        }
    }
}

impl core::fmt::Display for DocError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Syntax { offset, expected } => {
                write!(f, "not JSON at byte {offset}: expected {expected}")
            }
            Self::Invalid { path, reason } if path.is_empty() => f.write_str(reason),
            Self::Invalid { path, reason } => write!(f, "{path}: {reason}"),
        }
    }
}

/// The workspace's JSON reader, with its refusal in this module's terms.
///
/// The document is first walked by the lexer's bounded skip, which checks the
/// whole grammar and refuses nesting past [`MAX_JSON_DEPTH`] without recursing
/// beyond it; only then is the tree built, by a parser that has no bound of its
/// own. Both refusals carry the byte they stopped at.
#[inline(never)]
pub fn read_json(text: &str) -> Result<Json5Value, DocError> {
    let syntax = |e: Json5Error| DocError::Syntax {
        offset: e.offset,
        expected: e.expected,
    };
    let mut lexer = Lexer::new(text);
    lexer.skip_trivia().map_err(syntax)?;
    lexer.skip_value(MAX_JSON_DEPTH).map_err(syntax)?;
    json5::parse(text).map_err(syntax)
}

/// Where a reader stands in a document: an RFC 6901 JSON pointer that is
/// written out only when a refusal names it. A reader descends by borrowing
/// the step above, so a document that is accepted builds no path at all.
#[derive(Debug, Clone, Copy)]
pub struct Pointer<'a> {
    parent: Option<&'a Pointer<'a>>,
    step: Step<'a>,
}

#[derive(Debug, Clone, Copy)]
enum Step<'a> {
    /// A pointer already written out.
    Text(&'a str),
    /// A member of an object, by its key.
    Key(&'a str),
    /// An item of an array, by its index.
    Index(usize),
}

// The readers below are out of line: each kind of document calls them at many
// places, and every inlined copy carried the member search, the comparison of
// its text and the building of the refusal. A document is read once, when it is
// handed over, so the call costs nothing a sample pays.
impl<'a> Pointer<'a> {
    /// A pointer already written out: `""` is the document itself.
    pub const fn text(text: &'a str) -> Self {
        Self {
            parent: None,
            step: Step::Text(text),
        }
    }

    /// The member `key` of the object this points at.
    pub fn key<'b>(&'b self, key: &'b str) -> Pointer<'b> {
        Pointer {
            parent: Some(self),
            step: Step::Key(key),
        }
    }

    /// The item `index` of the array this points at.
    pub fn index(&self, index: usize) -> Pointer<'_> {
        Pointer {
            parent: Some(self),
            step: Step::Index(index),
        }
    }

    /// The pointer written out, a key's `~` and `/` escaped as RFC 6901 says.
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write_into(&mut out);
        out
    }

    fn write_into(&self, out: &mut String) {
        use core::fmt::Write as _;
        if let Some(parent) = self.parent {
            parent.write_into(out);
        }
        match self.step {
            Step::Text(text) => out.push_str(text),
            Step::Key(key) => {
                out.push('/');
                for c in key.chars() {
                    match c {
                        '~' => out.push_str("~0"),
                        '/' => out.push_str("~1"),
                        c => out.push(c),
                    }
                }
            }
            // Writing into a `String` does not fail.
            Step::Index(index) => {
                let _ = write!(out, "/{index}");
            }
        }
    }

    /// The refusal of what stands here, for `reason`.
    #[inline(never)]
    pub fn refuse(&self, reason: impl Into<String>) -> DocError {
        DocError::Invalid {
            path: self.render(),
            reason: reason.into(),
        }
    }

    /// The object this points at.
    #[inline(never)]
    pub fn object<'v>(&self, value: &'v Json5Value) -> Result<&'v Entries, DocError> {
        match value {
            Json5Value::Object(entries) => Ok(entries),
            other => Err(self.refuse(format!("expected an object, found {}", describe(other)))),
        }
    }

    /// The array this points at.
    #[inline(never)]
    pub fn array<'v>(&self, value: &'v Json5Value) -> Result<&'v [Json5Value], DocError> {
        match value {
            Json5Value::Array(items) => Ok(items),
            other => Err(self.refuse(format!("expected an array, found {}", describe(other)))),
        }
    }

    /// Refuse a key outside `allowed` and a key that appears twice. The reader
    /// keeps every member, and resolving a repeat silently (last one wins) would
    /// make a typo in a profile read as a choice.
    #[inline(never)]
    pub fn check_keys(&self, entries: &Entries, allowed: &[&str]) -> Result<(), DocError> {
        for (key, _) in entries {
            if !allowed.contains(&key.as_str()) {
                return Err(self.key(key).refuse(format!(
                    "unknown key `{key}` (allowed here: {})",
                    allowed.join(", ")
                )));
            }
        }
        self.check_distinct(entries)
    }

    /// Refuse a key that appears twice, for an object whose keys are the
    /// caller's own names rather than a fixed list.
    #[inline(never)]
    pub fn check_distinct(&self, entries: &Entries) -> Result<(), DocError> {
        for (i, (key, _)) in entries.iter().enumerate() {
            if entries[..i].iter().any(|(earlier, _)| earlier == key) {
                return Err(self
                    .key(key)
                    .refuse(format!("the key `{key}` appears twice")));
            }
        }
        Ok(())
    }

    /// The member `key` of `entries`, which this points at, refused here when
    /// it is missing.
    #[inline(never)]
    pub fn required<'v>(
        &self,
        entries: &'v Entries,
        key: &str,
    ) -> Result<&'v Json5Value, DocError> {
        optional(entries, key).ok_or_else(|| self.refuse(format!("the key `{key}` is required")))
    }

    /// An unsigned integer as a profile or a values document writes one: a
    /// plain decimal JSON number, or a string of decimal or `0x` hex digits.
    #[inline(never)]
    pub fn read_uint(&self, value: &Json5Value) -> Result<u64, DocError> {
        let result = match value {
            Json5Value::Number(text) => {
                if is_plain_decimal(text) {
                    uint_from_text(text)
                } else {
                    Err(format!(
                        "`{text}` is not a plain unsigned decimal number: write hexadecimal \
                         as a string such as \"0x1f\""
                    ))
                }
            }
            Json5Value::String(text) => uint_from_text(text),
            other => Err(format!(
                "expected an unsigned integer (a number, or a string of decimal or 0x hex \
                 digits), found {}",
                describe(other)
            )),
        };
        result.map_err(|reason| self.refuse(reason))
    }

    /// The boolean this points at.
    #[inline(never)]
    pub fn read_bool(&self, value: &Json5Value) -> Result<bool, DocError> {
        match value {
            Json5Value::Bool(b) => Ok(*b),
            other => Err(self.refuse(format!("expected true or false, found {}", describe(other)))),
        }
    }

    /// The string this points at.
    #[inline(never)]
    pub fn read_string<'v>(&self, value: &'v Json5Value) -> Result<&'v str, DocError> {
        match value {
            Json5Value::String(s) => Ok(s),
            other => Err(self.refuse(format!("expected a string, found {}", describe(other)))),
        }
    }
}

/// `path` with the member `key` below it, written out. A reader holds a
/// [`Pointer`] instead, which is written out only for a refusal.
pub fn child(path: &str, key: &str) -> String {
    Pointer::text(path).key(key).render()
}

/// `path` with the item `index` below it, written out.
pub fn at(path: &str, index: usize) -> String {
    Pointer::text(path).index(index).render()
}

/// The kind of `value`, as a refusal names what it found.
#[inline(never)]
pub fn describe(value: &Json5Value) -> &'static str {
    match value {
        Json5Value::Null => "null",
        Json5Value::Bool(_) => "a boolean",
        Json5Value::Number(_) => "a number",
        Json5Value::String(_) => "a string",
        Json5Value::Array(_) => "an array",
        Json5Value::Object(_) => "an object",
    }
}

pub type Entries = [(String, Json5Value)];

pub fn object<'a>(value: &'a Json5Value, path: &str) -> Result<&'a Entries, DocError> {
    Pointer::text(path).object(value)
}

pub fn array<'a>(value: &'a Json5Value, path: &str) -> Result<&'a [Json5Value], DocError> {
    Pointer::text(path).array(value)
}

/// [`Pointer::check_keys`] at a pointer already written out.
pub fn check_keys(entries: &Entries, allowed: &[&str], path: &str) -> Result<(), DocError> {
    Pointer::text(path).check_keys(entries, allowed)
}

/// [`Pointer::check_distinct`] at a pointer already written out.
pub fn check_distinct(entries: &Entries, path: &str) -> Result<(), DocError> {
    Pointer::text(path).check_distinct(entries)
}

#[inline(never)]
pub fn optional<'a>(entries: &'a Entries, key: &str) -> Option<&'a Json5Value> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

pub fn required<'a>(
    entries: &'a Entries,
    key: &str,
    path: &str,
) -> Result<&'a Json5Value, DocError> {
    Pointer::text(path).required(entries, key)
}

/// Whether `text` is `0` or digits with no leading zero.
fn is_plain_decimal(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text.len() == 1 || !text.starts_with('0'))
}

fn uint_from_text(text: &str) -> Result<u64, String> {
    let does_not_fit = || format!("`{text}` does not fit in 64 bits");
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("`{text}` is not hexadecimal digits after `0x`"));
        }
        return u64::from_str_radix(hex, 16).map_err(|_| does_not_fit());
    }
    if !is_plain_decimal(text) {
        return Err(format!(
            "`{text}` is not an unsigned integer: write decimal digits with no sign or \
             leading zero, or `0x` and hex digits"
        ));
    }
    text.parse().map_err(|_| does_not_fit())
}

/// [`Pointer::read_uint`] at a pointer already written out.
pub fn read_uint(value: &Json5Value, path: &str) -> Result<u64, DocError> {
    Pointer::text(path).read_uint(value)
}

pub fn read_bool(value: &Json5Value, path: &str) -> Result<bool, DocError> {
    Pointer::text(path).read_bool(value)
}

pub fn read_string<'a>(value: &'a Json5Value, path: &str) -> Result<&'a str, DocError> {
    Pointer::text(path).read_string(value)
}
#[cfg(test)]
mod tests {
    use alloc::string::String;

    use super::{at, child, Pointer};

    #[test]
    fn a_pointer_is_written_out_as_the_eager_path_was() {
        let fields = Pointer::text("/fields");
        let here = fields.index(2);
        let split = here.key("split");
        let part = split.index(0);
        assert_eq!(part.key("lsb").render(), "/fields/2/split/0/lsb");
        assert_eq!(
            part.key("lsb").render(),
            child(&at(&child(&at("/fields", 2), "split"), 0), "lsb")
        );

        let doc = Pointer::text("");
        assert_eq!(doc.render(), "");
        assert_eq!(doc.key("name").render(), "/name");
        // RFC 6901: `~` is written `~0` and `/` is written `~1`, in that order.
        assert_eq!(doc.key("a~/b").render(), "/a~0~1b");
        assert_eq!(doc.key("a~/b").render(), child("", "a~/b"));
        assert_eq!(doc.key("").render(), "/");
        assert_eq!(doc.index(10).render(), "/10");

        let refused = doc.key("x").index(1).refuse("why");
        assert_eq!(
            refused,
            super::DocError::Invalid {
                path: String::from("/x/1"),
                reason: String::from("why"),
            }
        );
    }
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `matches` operator's pattern: a regular expression the selector
//! compiles once and asks of every record.
//!
//! # A feature, and its absence is a REFUSAL
//!
//! This crate is `no_std` and reads every format with no third-party code. A
//! regular expression engine is not something to write a second time, so
//! `matches` is the one operator that borrows one (`regex-automata`, with only
//! `alloc`), and it does so behind the `filter-regex` feature. With the
//! feature off a selector that writes `matches` is refused at the operator
//! ([`crate::filter::FilterErrorKind::PatternUnsupported`]), on the rule the
//! wildcard refusal states: a build that cannot answer says so, rather than
//! answering a different question.
//!
//! # What a pattern is
//!
//! The syntax is `regex-automata`'s, which is the Rust `regex` crate's. The
//! match is a SEARCH, unanchored, as a display filter's `matches` is: `"^a"`
//! and `"a$"` anchor where the reader writes them. It runs over BYTES, so a
//! payload that is not text is still searched, and a `.` matches any byte that
//! is not a newline.

use alloc::string::String;

/// A compiled pattern, compared by the text it was compiled from: two
/// selectors that wrote the same pattern are the same selector.
#[derive(Debug, Clone)]
pub(crate) struct Pattern {
    source: String,
    #[cfg(feature = "filter-regex")]
    regex: regex_automata::meta::Regex,
}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Eq for Pattern {}

/// Why a pattern did not compile.
///
/// Each build constructs one of the two: a build with the engine never refuses
/// for want of one, and a build without it never compiles a text it could
/// refuse. Both stay declared so the one `match` over them reads the same in
/// either build.
pub(crate) enum PatternRefusal {
    /// The build has no engine (`filter-regex` is off).
    #[cfg_attr(feature = "filter-regex", allow(dead_code))]
    Unsupported,
    /// The engine refused the text; its own words.
    #[cfg_attr(not(feature = "filter-regex"), allow(dead_code))]
    Invalid(String),
}

impl Pattern {
    /// Compile `source` as a byte pattern.
    pub(crate) fn compile(source: &str) -> Result<Self, PatternRefusal> {
        #[cfg(feature = "filter-regex")]
        {
            use regex_automata::meta::Regex;
            use regex_automata::util::syntax;
            // Bytes and not text: `utf8(false)` lets `.` and the classes match
            // any byte, which is what a payload that is not UTF-8 needs, and
            // `utf8_empty(false)` lets an empty match sit between the bytes of
            // a multi-byte character instead of being refused there.
            let regex = Regex::builder()
                .syntax(syntax::Config::new().utf8(false))
                .configure(Regex::config().utf8_empty(false))
                .build(source)
                .map_err(|e| PatternRefusal::Invalid(alloc::format!("{e}")))?;
            Ok(Self {
                source: source.into(),
                regex,
            })
        }
        #[cfg(not(feature = "filter-regex"))]
        {
            let _ = source;
            Err(PatternRefusal::Unsupported)
        }
    }

    /// Whether the pattern is found anywhere in `haystack`.
    pub(crate) fn is_match(&self, haystack: &[u8]) -> bool {
        #[cfg(feature = "filter-regex")]
        {
            self.regex.is_match(haystack)
        }
        #[cfg(not(feature = "filter-regex"))]
        {
            // A `Pattern` cannot be built without the engine, so no selector
            // holding one reaches this arm.
            let _ = haystack;
            false
        }
    }

    /// Whether this build compiles patterns: what the field list reports, so a
    /// consumer offers `matches` only where it will be accepted.
    pub(crate) const fn supported() -> bool {
        cfg!(feature = "filter-regex")
    }
}

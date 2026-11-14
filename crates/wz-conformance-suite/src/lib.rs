// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The front half of the zenoh conformance test suite, as data a test system reads
//! (docs/conformance-suite.md).
//!
//! ISO/IEC 9646 builds a conformance test suite in a chain: the conformance requirements, the
//! test purposes drawn from them, the abstract test suite that realises the purposes, and beside
//! them two proformas an implementation and a test environment fill in, the PICS (what the
//! implementation is) and the PIXIT (where it is tested). This crate holds the parts of that
//! chain that do not depend on how the test suite is executed: the requirements, the two
//! proformas, wz's answers to the PICS, and the structure the abstract test suite is written to
//! (its test configurations and purposes, the service primitives and the test management
//! protocol, [`structure`]). They are TOML files in `conformance/suite/`, read here into
//! [`Suite`], [`AnswerFile`] and [`structure::Structure`] and held to their formats by
//! [`check()`], [`check_answers()`] and [`structure::check_structure()`]. How each id is spelled
//! where the abstract test suite reads it is [`names`].
//!
//! The checks are the static ones a test system makes before it selects any test: every
//! selection expression names a PICS item that exists and can be answered yes or no, every
//! PICS item names requirements that exist, every requirement says where it comes from, and a
//! requirement that rests on an implementation's behaviour alone says so in an `issue`. Whether
//! each cited source still says what the requirement claims is the upstream citation gate's
//! (each source is an anchor it resolves at the pin), so this crate checks only the form.
//!
//! [`answer()`] reads a wz build's PICS from its conformance statement, the way the test system's
//! first exchange with an upper tester will: the statement names capabilities, limits, policies
//! and protocol facts, and `conformance/suite/answers/wz.toml` says which of them answers which
//! item; an item the implementation reads from its configuration is answered from the PIXIT
//! ([`resolve()`]).

mod answer;
mod check;
pub mod names;
mod selection;
pub mod structure;

use std::collections::BTreeMap;

use serde::Deserialize;

pub use answer::{
    answer, check_facts_pin, facts_canonical, facts_digest, resolve, Catalogue,
    CatalogueCapability, CatalogueFact, CataloguePolicy, PicsAnswer, Statement, FACTS_PIN,
};
pub use check::{check, check_answers};
pub use selection::Selection;

/// The requirement files of the list, by their path under `conformance/suite/`.
pub const REQUIREMENT_FILES: &[(&str, &str)] = &[
    (
        "requirements/base-transport.toml",
        include_str!("../../../conformance/suite/requirements/base-transport.toml"),
    ),
    (
        "requirements/base-network.toml",
        include_str!("../../../conformance/suite/requirements/base-network.toml"),
    ),
];

/// The PICS proforma, `conformance/suite/pics.toml`.
pub const PICS: &str = include_str!("../../../conformance/suite/pics.toml");

/// The PIXIT proforma, `conformance/suite/pixit.toml`.
pub const PIXIT: &str = include_str!("../../../conformance/suite/pixit.toml");

/// wz's answers to the PICS proforma, `conformance/suite/answers/wz.toml`.
pub const WZ_ANSWERS: &str = include_str!("../../../conformance/suite/answers/wz.toml");

/// The build declaration the answers are read against, `deploy/wz-config.toml`.
pub const WZ_CONFIG: &str = include_str!("../../../deploy/wz-config.toml");

/// The format names and the one version of each this crate reads.
pub const REQUIREMENTS_FORMAT: &str = "wz-conformance-requirements";
pub const PICS_FORMAT: &str = "wz-conformance-pics-proforma";
pub const PIXIT_FORMAT: &str = "wz-conformance-pixit-proforma";
pub const ANSWERS_FORMAT: &str = "wz-conformance-pics-answers";
pub const FORMAT_VERSION: u32 = 1;

/// The layer of the requirements a file belongs to: the base specification, or a profile
/// that selects, adds to and departs from it (ISO/IEC TR 10000, ISO/IEC 9646-6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Base,
    Profile,
}

/// How strongly a requirement binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Strength {
    Must,
    Should,
    May,
}

/// ISO/IEC 9646-1's two kinds of conformance requirement: static (which capabilities an
/// implementation has and how they combine) and dynamic (what it does when it communicates,
/// the encoding of what it sends included).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Static,
    Dynamic,
}

/// What a requirement is about: the form of a message, or a procedure. The encoding
/// requirements are what a codec is written from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Aspect {
    Encoding,
    Procedure,
}

/// Whom a requirement binds: what an implementation sends, what it accepts, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Binds {
    Sender,
    Receiver,
    Both,
}

/// How a profile's requirement stands to the base: it selects an option or fixes a value the
/// base leaves open, it adds what the base does not say without contradicting it, or it departs
/// from the base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    Selection,
    Addition,
    Deviation,
}

/// One file of the requirements.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementFile {
    pub format: String,
    pub format_version: u32,
    pub layer: Layer,
    pub part: String,
    pub base: String,
    #[serde(rename = "requirement")]
    pub requirements: Vec<Requirement>,
}

/// One requirement.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub id: String,
    pub strength: Strength,
    pub kind: Kind,
    pub aspect: Aspect,
    pub binds: Binds,
    /// The PICS selection under which the requirement applies; absent, it always does.
    pub applies: Option<String>,
    pub text: String,
    pub sources: Vec<String>,
    /// Why the requirement's sources do not settle it. A test of it is inconclusive while this
    /// is present.
    pub issue: Option<String>,
    /// A profile requirement's standing to the base; a base requirement has none.
    pub class: Option<Class>,
    /// The base requirements a profile's deviation departs from.
    #[serde(default)]
    pub deviates_from: Vec<String>,
}

/// The kind of answer a PICS item takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnswerKind {
    Support,
    Value,
}

/// The PICS proforma.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PicsProforma {
    pub format: String,
    pub format_version: u32,
    #[serde(rename = "item")]
    pub items: Vec<PicsItem>,
}

/// One question of the PICS proforma.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PicsItem {
    pub id: String,
    pub question: String,
    /// ISO/IEC 9646-7's status notation: `m`, `o`, `o.<n>`, `x` or `c`.
    pub status: String,
    /// For status `c`: the selection that decides between `then` and `else`.
    pub condition: Option<String>,
    pub then: Option<String>,
    #[serde(rename = "else")]
    pub otherwise: Option<String>,
    pub answer: AnswerKind,
    /// A value item's admitted values, when they are a list.
    #[serde(default)]
    pub values: Vec<String>,
    /// A value item's admitted range, when its values are integers.
    pub min: Option<u64>,
    pub max: Option<u64>,
    pub unit: Option<String>,
    pub reference: Vec<String>,
}

impl PicsItem {
    /// Whether `value` is an answer this value item admits.
    pub fn admits(&self, value: &str) -> bool {
        if !self.values.is_empty() {
            return self.values.iter().any(|v| v == value);
        }
        match (value.parse::<u64>(), self.min) {
            (Ok(v), Some(min)) => v >= min && !matches!(self.max, Some(max) if v > max),
            _ => false,
        }
    }
}

/// The kind of answer a PIXIT item takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PixitKind {
    Text,
    Integer,
    Choice,
}

/// The PIXIT proforma.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PixitProforma {
    pub format: String,
    pub format_version: u32,
    #[serde(rename = "item")]
    pub items: Vec<PixitItem>,
}

/// One question of the PIXIT proforma.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PixitItem {
    pub id: String,
    pub question: String,
    pub answer: PixitKind,
    #[serde(default)]
    pub values: Vec<String>,
    pub unit: Option<String>,
    /// Another item whose answer this one's must differ from.
    pub distinct_from: Option<String>,
}

/// An implementation's answers to the PICS proforma, read from its conformance statement.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerFile {
    pub format: String,
    pub format_version: u32,
    pub implementation: String,
    #[serde(rename = "answer")]
    pub answers: Vec<AnswerRow>,
}

/// How one PICS item is answered for one ABI: by exactly one of `capability`, `limit`,
/// `policy` (with `map`), `fact` (with `map` when the fact's words are not the item's), `pixit`,
/// `fixed` (with `why`) and `unanswered`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerRow {
    pub abi: String,
    pub item: String,
    pub capability: Option<String>,
    pub limit: Option<String>,
    pub policy: Option<String>,
    /// A protocol fact of the declaration, read from the statement for the row's ABI.
    pub fact: Option<String>,
    /// A PIXIT item: the implementation reads the value from its configuration when a session
    /// opens, so the test environment states it.
    pub pixit: Option<String>,
    #[serde(default)]
    pub map: BTreeMap<String, String>,
    pub fixed: Option<String>,
    pub why: Option<String>,
    pub unanswered: Option<String>,
}

/// The requirements and the two proformas.
#[derive(Debug, Clone)]
pub struct Suite {
    /// Each requirement file with the name it was read under.
    pub requirements: Vec<(String, RequirementFile)>,
    pub pics: PicsProforma,
    pub pixit: PixitProforma,
}

impl Suite {
    /// Reads a suite from the texts of its files; `requirement_files` pairs each file's name with
    /// its text. A text that is not of its format's shape is refused with the file's name.
    pub fn parse(
        requirement_files: &[(&str, &str)],
        pics: &str,
        pixit: &str,
    ) -> Result<Suite, String> {
        let mut requirements = Vec::new();
        for (name, text) in requirement_files {
            let file: RequirementFile = toml::from_str(text).map_err(|e| format!("{name}: {e}"))?;
            requirements.push(((*name).to_string(), file));
        }
        Ok(Suite {
            requirements,
            pics: toml::from_str(pics).map_err(|e| format!("pics.toml: {e}"))?,
            pixit: toml::from_str(pixit).map_err(|e| format!("pixit.toml: {e}"))?,
        })
    }

    /// The suite as committed in `conformance/suite/`.
    pub fn committed() -> Result<Suite, String> {
        Suite::parse(REQUIREMENT_FILES, PICS, PIXIT)
    }

    /// Every requirement of every file, in file order.
    pub fn all_requirements(&self) -> impl Iterator<Item = &Requirement> {
        self.requirements
            .iter()
            .flat_map(|(_, file)| file.requirements.iter())
    }

    /// The requirements a codec is written from: those about the form of a message. This is
    /// the whole of what an independent codec's author is handed.
    pub fn encoding_requirements(&self) -> impl Iterator<Item = &Requirement> {
        self.all_requirements()
            .filter(|r| r.aspect == Aspect::Encoding)
    }

    /// The PICS item of `id`.
    pub fn pics_item(&self, id: &str) -> Option<&PicsItem> {
        self.pics.items.iter().find(|item| item.id == id)
    }
}

impl AnswerFile {
    /// Reads an answer file from its text.
    pub fn parse(text: &str) -> Result<AnswerFile, String> {
        toml::from_str(text).map_err(|e| format!("answers: {e}"))
    }

    /// wz's answers as committed in `conformance/suite/answers/wz.toml`.
    pub fn committed_wz() -> Result<AnswerFile, String> {
        AnswerFile::parse(WZ_ANSWERS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committed_files_read() {
        let suite = Suite::committed().expect("the committed suite reads");
        assert_eq!(suite.requirements.len(), REQUIREMENT_FILES.len());
        assert!(suite.all_requirements().next().is_some());
        AnswerFile::committed_wz().expect("the committed answers read");
    }

    #[test]
    fn the_codec_input_is_the_encoding_requirements_only() {
        let suite = Suite::committed().unwrap();
        let ids: Vec<&str> = suite
            .encoding_requirements()
            .map(|r| r.id.as_str())
            .collect();
        assert!(ids.contains(&"B-ENC-1"), "{ids:?}");
        assert!(ids.contains(&"B-JOIN-1"), "{ids:?}");
        assert!(
            !ids.contains(&"B-INIT-5"),
            "a procedure is not codec input: {ids:?}"
        );
    }

    #[test]
    fn a_value_item_admits_its_list_or_its_range() {
        let suite = Suite::committed().unwrap();
        let res = suite.pics_item("T-FSN-RES").unwrap();
        assert!(res.admits("32"));
        assert!(!res.admits("12"));
        let batch = suite.pics_item("T-BATCH-UNICAST").unwrap();
        assert!(batch.admits("1"));
        assert!(batch.admits("65535"));
        assert!(!batch.admits("0"));
        assert!(!batch.admits("65536"));
        assert!(!batch.admits("a lot"));
        let lease = suite.pics_item("T-LEASE").unwrap();
        assert!(
            lease.admits("18446744073709551615"),
            "no max is no upper bound"
        );
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let text = PICS.replacen("question =", "questoin =", 1);
        assert_ne!(text, PICS);
        let err = Suite::parse(REQUIREMENT_FILES, &text, PIXIT).unwrap_err();
        assert!(err.starts_with("pics.toml:"), "{err}");
    }
}

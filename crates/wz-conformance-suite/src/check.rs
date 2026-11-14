// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The static checks of the suite's files: each against its format, and each against the others.
//!
//! Every check returns every violation it finds, each a sentence that names the file and the
//! entry, so one run lists all that is wrong.

use std::collections::{BTreeMap, BTreeSet};

use crate::selection::{is_item_id, Selection};
use crate::{
    AnswerFile, AnswerKind, Aspect, Catalogue, Class, Layer, PixitKind, Requirement, Suite,
    ANSWERS_FORMAT, FORMAT_VERSION, PICS_FORMAT, PIXIT_FORMAT, REQUIREMENTS_FORMAT,
};

/// The top-level directories of the pinned upstream checkout, the ones a base requirement's
/// source may cite. The upstream citation gate keeps the same list and resolves each anchor at
/// the pin; this list only refuses a source that could never resolve.
const UPSTREAM_ROOTS: &[&str] = &[
    "io",
    "commons",
    "zenoh",
    "plugins",
    "zenoh-ext",
    "zenohd",
    "examples",
];

/// Where the protocol's message definitions are, and where its codec is. A definition is a
/// source for every requirement; the codec only for the form of a message.
const DEFINITION: &str = "commons/zenoh-protocol/";
const CODEC: &str = "commons/zenoh-codec/";

/// Where the base states the contract of a service rather than a message: the key expression
/// library, which defines what a key expression is and means, and the public Rust API's
/// documentation. A contract is a source for a procedure, and the key expression library for the
/// form of a key expression too.
const KEYEXPR: &str = "commons/zenoh-keyexpr/";
const API: &str = "zenoh/src/api/";

/// The ABIs whose libraries carry their statement's digest, so whose PICS can be read from it.
const ANSWERED_ABIS: &[&str] = &["pico", "c"];

/// The longest needle the upstream citation gate admits.
const NEEDLE_MAX: usize = 200;

/// The path of a source written as an anchor, `` `<path>` @ `<needle>` ``, or `None` when the
/// source is not of that form.
fn anchored_path(source: &str) -> Option<&str> {
    let (path, rest) = source.strip_prefix('`')?.split_once("` @ `")?;
    let needle = rest.strip_suffix('`')?;
    let well_formed = path.ends_with(".rs")
        && !path.contains('`')
        && !needle.is_empty()
        && needle.len() <= NEEDLE_MAX
        && !needle.contains(['`', '\n']);
    well_formed.then_some(path)
}

fn is_upstream(path: &str) -> bool {
    path.split_once('/')
        .is_some_and(|(root, rest)| UPSTREAM_ROOTS.contains(&root) && !rest.is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Mandatory,
    Optional,
    Group(u32),
    Excluded,
    Conditional,
    NotApplicable,
}

/// ISO/IEC 9646-7's status notation; `o.<n>` with `n` a positive number written without
/// leading zeros.
fn status(text: &str) -> Option<Status> {
    match text {
        "m" => Some(Status::Mandatory),
        "o" => Some(Status::Optional),
        "x" => Some(Status::Excluded),
        "c" => Some(Status::Conditional),
        "n/a" => Some(Status::NotApplicable),
        _ => {
            let n = text.strip_prefix("o.")?;
            let group = n
                .parse::<u32>()
                .ok()
                .filter(|g| *g > 0 && g.to_string() == n)?;
            Some(Status::Group(group))
        }
    }
}

/// Every violation of the requirements and the two proformas.
pub fn check(suite: &Suite) -> Vec<String> {
    let mut out = Vec::new();
    check_requirements(suite, &mut out);
    check_pics(suite, &mut out);
    check_pixit(suite, &mut out);
    out
}

fn check_requirements(suite: &Suite, out: &mut Vec<String>) {
    let base: BTreeSet<&str> = suite
        .requirements
        .iter()
        .filter(|(_, file)| file.layer == Layer::Base)
        .flat_map(|(_, file)| file.requirements.iter().map(|r| r.id.as_str()))
        .collect();
    let mut seen = BTreeSet::new();
    for (name, file) in &suite.requirements {
        if file.format != REQUIREMENTS_FORMAT || file.format_version != FORMAT_VERSION {
            out.push(format!(
                "{name}: format {} version {}, not {REQUIREMENTS_FORMAT} version {FORMAT_VERSION}",
                file.format, file.format_version
            ));
        }
        if file.requirements.is_empty() {
            out.push(format!("{name}: holds no requirement"));
        }
        for r in &file.requirements {
            let at = format!("{name}: {}", r.id);
            if !is_item_id(&r.id) {
                out.push(format!(
                    "{at}: the id is not upper-case letters, digits and hyphens"
                ));
            }
            if !seen.insert(r.id.as_str()) {
                out.push(format!("{at}: the id is stated twice"));
            }
            if r.text.trim().is_empty() {
                out.push(format!("{at}: the text is empty"));
            }
            if r.sources.is_empty() {
                out.push(format!("{at}: names no source"));
            }
            if r.issue
                .as_deref()
                .is_some_and(|issue| issue.trim().is_empty())
            {
                out.push(format!("{at}: the issue is empty"));
            }
            match file.layer {
                Layer::Base => check_base(&at, r, out),
                Layer::Profile => check_profile(&at, r, &base, out),
            }
            if let Some(applies) = &r.applies {
                check_selection(&at, "applies", applies, None, suite, out);
            }
        }
    }
}

fn check_base(at: &str, r: &Requirement, out: &mut Vec<String>) {
    if r.class.is_some() || !r.deviates_from.is_empty() {
        out.push(format!(
            "{at}: a base requirement has no class and departs from nothing"
        ));
    }
    let mut paths = Vec::new();
    for source in &r.sources {
        match anchored_path(source) {
            None => out.push(format!(
                "{at}: source {source:?} is not an anchor `<path>` @ `<needle>`"
            )),
            Some(path) if !is_upstream(path) => out.push(format!(
                "{at}: source {path} is not under a top-level directory of the pinned upstream"
            )),
            Some(path) => paths.push(path),
        }
    }
    let (normative, defining) = match r.aspect {
        Aspect::Encoding => (
            paths.iter().any(|p| {
                p.starts_with(DEFINITION) || p.starts_with(CODEC) || p.starts_with(KEYEXPR)
            }),
            "the protocol definition, its codec or the key expression library",
        ),
        Aspect::Procedure => (
            paths
                .iter()
                .any(|p| p.starts_with(DEFINITION) || p.starts_with(KEYEXPR) || p.starts_with(API)),
            "the protocol definition or a service contract",
        ),
    };
    if !normative && r.issue.is_none() {
        out.push(format!(
            "{at}: no source is {defining}, so the requirement carries an issue"
        ));
    }
}

fn check_profile(at: &str, r: &Requirement, base: &BTreeSet<&str>, out: &mut Vec<String>) {
    match r.class {
        None => out.push(format!(
            "{at}: a profile requirement states its class: selection, addition or deviation"
        )),
        Some(Class::Deviation) => {
            if r.deviates_from.is_empty() {
                out.push(format!(
                    "{at}: a deviation names the base requirements it departs from"
                ));
            }
        }
        Some(Class::Selection | Class::Addition) => {
            if !r.deviates_from.is_empty() {
                out.push(format!(
                    "{at}: only a deviation departs from base requirements"
                ));
            }
        }
    }
    for id in &r.deviates_from {
        if !base.contains(id.as_str()) {
            out.push(format!(
                "{at}: departs from {id}, which is no base requirement"
            ));
        }
    }
}

fn check_selection(
    at: &str,
    field: &str,
    text: &str,
    own: Option<&str>,
    suite: &Suite,
    out: &mut Vec<String>,
) {
    let selection = match Selection::parse(text) {
        Ok(selection) => selection,
        Err(e) => {
            out.push(format!("{at}: {field} {text:?} does not parse: {e}"));
            return;
        }
    };
    for id in selection.items() {
        if Some(id) == own {
            out.push(format!("{at}: {field} names the item itself"));
            continue;
        }
        match suite.pics_item(id) {
            None => out.push(format!("{at}: {field} names {id}, which is no PICS item")),
            Some(item) if item.answer != AnswerKind::Support => out.push(format!(
                "{at}: {field} names {id}, which is answered with a value, not yes or no"
            )),
            Some(_) => {}
        }
    }
}

fn check_pics(suite: &Suite, out: &mut Vec<String>) {
    let pics = &suite.pics;
    if pics.format != PICS_FORMAT || pics.format_version != FORMAT_VERSION {
        out.push(format!(
            "pics.toml: format {} version {}, not {PICS_FORMAT} version {FORMAT_VERSION}",
            pics.format, pics.format_version
        ));
    }
    let requirements: BTreeSet<&str> = suite.all_requirements().map(|r| r.id.as_str()).collect();
    let mut seen = BTreeSet::new();
    let mut groups: BTreeMap<u32, usize> = BTreeMap::new();
    for item in &pics.items {
        let at = format!("pics.toml: {}", item.id);
        if !is_item_id(&item.id) {
            out.push(format!(
                "{at}: the id is not upper-case letters, digits and hyphens"
            ));
        }
        if !seen.insert(item.id.as_str()) {
            out.push(format!("{at}: the id is stated twice"));
        }
        if item.question.trim().is_empty() {
            out.push(format!("{at}: the question is empty"));
        }
        match status(&item.status) {
            None | Some(Status::NotApplicable) => out.push(format!(
                "{at}: status {:?} is not m, o, o.<n>, x or c",
                item.status
            )),
            Some(Status::Conditional) => {
                match &item.condition {
                    None => out.push(format!("{at}: a conditional item states its condition")),
                    Some(condition) => check_selection(
                        &at,
                        "condition",
                        condition,
                        Some(item.id.as_str()),
                        suite,
                        out,
                    ),
                }
                for (field, value) in [("then", &item.then), ("else", &item.otherwise)] {
                    match value.as_deref().map(status) {
                        None => out.push(format!(
                            "{at}: a conditional item states its {field} status"
                        )),
                        Some(None | Some(Status::Conditional)) => out.push(format!(
                            "{at}: {field} status {:?} is not m, o, o.<n>, x or n/a",
                            value.as_deref().unwrap_or_default()
                        )),
                        Some(Some(Status::Group(n))) => *groups.entry(n).or_default() += 1,
                        Some(Some(_)) => {}
                    }
                }
            }
            Some(other) => {
                if item.condition.is_some() || item.then.is_some() || item.otherwise.is_some() {
                    out.push(format!(
                        "{at}: only a conditional item states a condition, then and else"
                    ));
                }
                if let Status::Group(n) = other {
                    *groups.entry(n).or_default() += 1;
                }
            }
        }
        match item.answer {
            AnswerKind::Support => {
                if !item.values.is_empty()
                    || item.min.is_some()
                    || item.max.is_some()
                    || item.unit.is_some()
                {
                    out.push(format!(
                        "{at}: a support item is answered yes or no, so it has no values, range or unit"
                    ));
                }
            }
            AnswerKind::Value => match (item.values.is_empty(), item.min, item.max) {
                (false, None, None) => {}
                (true, Some(min), max) => {
                    if max.is_some_and(|max| max < min) {
                        out.push(format!("{at}: its max is below its min"));
                    }
                }
                (true, None, Some(_)) => out.push(format!("{at}: states a max without a min")),
                (true, None, None) => out.push(format!(
                    "{at}: a value item states its values, or its range as min and max"
                )),
                (false, _, _) => {
                    out.push(format!("{at}: states both a list of values and a range"))
                }
            },
        }
        if item.reference.is_empty() {
            out.push(format!("{at}: names no requirement it decides"));
        }
        for id in &item.reference {
            if !requirements.contains(id.as_str()) {
                out.push(format!("{at}: names {id}, which is no requirement"));
            }
        }
    }
    for (n, count) in groups {
        if count < 2 {
            out.push(format!(
                "pics.toml: group o.{n} has one item, and a group has two at least"
            ));
        }
    }
}

fn check_pixit(suite: &Suite, out: &mut Vec<String>) {
    let pixit = &suite.pixit;
    if pixit.format != PIXIT_FORMAT || pixit.format_version != FORMAT_VERSION {
        out.push(format!(
            "pixit.toml: format {} version {}, not {PIXIT_FORMAT} version {FORMAT_VERSION}",
            pixit.format, pixit.format_version
        ));
    }
    let ids: BTreeSet<&str> = pixit.items.iter().map(|i| i.id.as_str()).collect();
    let mut seen = BTreeSet::new();
    for item in &pixit.items {
        let at = format!("pixit.toml: {}", item.id);
        if !is_item_id(&item.id) {
            out.push(format!(
                "{at}: the id is not upper-case letters, digits and hyphens"
            ));
        }
        if !seen.insert(item.id.as_str()) {
            out.push(format!("{at}: the id is stated twice"));
        }
        if item.question.trim().is_empty() {
            out.push(format!("{at}: the question is empty"));
        }
        match item.answer {
            PixitKind::Choice => {
                if item.values.is_empty() {
                    out.push(format!("{at}: a choice item states its values"));
                }
            }
            PixitKind::Text | PixitKind::Integer => {
                if !item.values.is_empty() {
                    out.push(format!("{at}: only a choice item states values"));
                }
            }
        }
        if let Some(other) = &item.distinct_from {
            if *other == item.id {
                out.push(format!("{at}: distinct_from names the item itself"));
            } else if !ids.contains(other.as_str()) {
                out.push(format!(
                    "{at}: distinct_from names {other}, which is no PIXIT item"
                ));
            }
        }
    }
}

/// Every violation of an answer file against the PICS proforma and the build declaration's
/// catalogue: each row answers an item of the proforma in exactly one way, with a capability
/// the ABI exports, a limit or policy the declaration has, or a fixed answer the item admits,
/// and each item is answered exactly once for each ABI that carries a statement.
pub fn check_answers(suite: &Suite, answers: &AnswerFile, catalogue: &Catalogue) -> Vec<String> {
    let mut out = Vec::new();
    if answers.format != ANSWERS_FORMAT || answers.format_version != FORMAT_VERSION {
        out.push(format!(
            "answers: format {} version {}, not {ANSWERS_FORMAT} version {FORMAT_VERSION}",
            answers.format, answers.format_version
        ));
    }
    let mut answered: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for row in &answers.answers {
        let at = format!("answers {} {}", row.abi, row.item);
        if !ANSWERED_ABIS.contains(&row.abi.as_str()) {
            out.push(format!(
                "{at}: {} is not an ABI whose library carries its statement (pico, c)",
                row.abi
            ));
            continue;
        }
        *answered
            .entry((row.abi.as_str(), row.item.as_str()))
            .or_default() += 1;
        let Some(item) = suite.pics_item(&row.item) else {
            out.push(format!("{at}: {} is no PICS item", row.item));
            continue;
        };
        let ways = [
            row.capability.is_some(),
            row.limit.is_some(),
            row.policy.is_some(),
            row.fact.is_some(),
            row.pixit.is_some(),
            row.fixed.is_some(),
            row.unanswered.is_some(),
        ]
        .into_iter()
        .filter(|way| *way)
        .count();
        if ways != 1 {
            out.push(format!(
                "{at}: answers in {ways} ways, and a row answers in exactly one of capability, limit, policy, fact, pixit, fixed and unanswered"
            ));
        }
        if row.why.is_some() != row.fixed.is_some() {
            out.push(format!(
                "{at}: a fixed answer, and only a fixed answer, says why"
            ));
        }
        if !row.map.is_empty() && row.policy.is_none() && row.fact.is_none() {
            out.push(format!("{at}: only a policy or a fact answer has a map"));
        }
        if let Some(fact) = &row.fact {
            match catalogue
                .facts
                .get(fact)
                .and_then(|f| f.values.get(&row.abi))
            {
                None => out.push(format!(
                    "{at}: {fact} is no protocol fact of the declaration for the {} ABI",
                    row.abi
                )),
                Some(value) => {
                    let word = if row.map.is_empty() {
                        Some(value)
                    } else {
                        row.map.get(value)
                    };
                    let admitted = word.is_some_and(|w| match item.answer {
                        AnswerKind::Support => w == "yes" || w == "no",
                        AnswerKind::Value => item.admits(w),
                    });
                    if !admitted {
                        out.push(format!(
                            "{at}: {fact} = {value} gives no answer the item admits"
                        ));
                    }
                    for (from, to) in &row.map {
                        let fits = match item.answer {
                            AnswerKind::Support => to == "yes" || to == "no",
                            AnswerKind::Value => item.admits(to),
                        };
                        if !fits {
                            out.push(format!(
                                "{at}: maps {from} to {to:?}, which the item does not admit"
                            ));
                        }
                    }
                }
            }
        }
        if let Some(pixit) = &row.pixit {
            match suite.pixit.items.iter().find(|p| p.id == *pixit) {
                None => out.push(format!("{at}: {pixit} is no PIXIT item")),
                Some(p) => {
                    let fits = match item.answer {
                        AnswerKind::Value => p.answer == PixitKind::Integer,
                        AnswerKind::Support => {
                            p.answer == PixitKind::Choice
                                && p.values.iter().all(|v| v == "yes" || v == "no")
                        }
                    };
                    if !fits {
                        out.push(format!(
                            "{at}: {pixit} does not answer in the item's kind (an integer for a value, yes or no for a support item)"
                        ));
                    }
                }
            }
        }
        if let Some(cap) = &row.capability {
            match catalogue.capabilities.get(cap) {
                None => out.push(format!("{at}: {cap} is no capability of the declaration")),
                Some(c) if !c.abis.contains(&row.abi) => out.push(format!(
                    "{at}: {cap} is not a capability of the {} ABI",
                    row.abi
                )),
                Some(_) => {}
            }
            if item.answer != AnswerKind::Support {
                out.push(format!(
                    "{at}: a capability answers yes or no, and the item takes a value"
                ));
            }
        }
        if let Some(limit) = &row.limit {
            if !catalogue.limits.contains_key(limit) {
                out.push(format!("{at}: {limit} is no limit of the declaration"));
            }
            if item.answer != AnswerKind::Value {
                out.push(format!(
                    "{at}: a limit answers with a value, and the item takes yes or no"
                ));
            }
        }
        if let Some(policy) = &row.policy {
            if item.answer != AnswerKind::Value {
                out.push(format!(
                    "{at}: a policy answers with a value, and the item takes yes or no"
                ));
            }
            match catalogue.policies.get(policy) {
                None => out.push(format!("{at}: {policy} is no policy of the declaration")),
                Some(declared) => {
                    let keys: BTreeSet<&str> = row.map.keys().map(String::as_str).collect();
                    let values: BTreeSet<&str> =
                        declared.values.iter().map(String::as_str).collect();
                    if keys != values {
                        out.push(format!(
                            "{at}: the map names {keys:?}, and {policy} takes {values:?}"
                        ));
                    }
                    for (value, mapped) in &row.map {
                        if !item.admits(mapped) {
                            out.push(format!(
                                "{at}: maps {value} to {mapped:?}, which the item does not admit"
                            ));
                        }
                    }
                }
            }
        }
        if let Some(fixed) = &row.fixed {
            let admitted = match item.answer {
                AnswerKind::Support => fixed == "yes" || fixed == "no",
                AnswerKind::Value => item.admits(fixed),
            };
            if !admitted {
                out.push(format!(
                    "{at}: the fixed answer {fixed:?} is not one the item admits"
                ));
            }
        }
        if row
            .unanswered
            .as_deref()
            .is_some_and(|text| text.trim().is_empty())
        {
            out.push(format!("{at}: says nothing of what the statement lacks"));
        }
    }
    for abi in ANSWERED_ABIS {
        for item in &suite.pics.items {
            match answered
                .get(&(*abi, item.id.as_str()))
                .copied()
                .unwrap_or(0)
            {
                1 => {}
                0 => out.push(format!("answers {abi} {}: no row answers it", item.id)),
                n => out.push(format!("answers {abi} {}: {n} rows answer it", item.id)),
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PICS, PIXIT, REQUIREMENT_FILES};

    const REQUIREMENTS: &str = r#"
format = "wz-conformance-requirements"
format_version = 1
layer = "base"
part = "fixture"
base = "zenoh 1.10.2"

[[requirement]]
id = "B-FIX-1"
strength = "MUST"
kind = "dynamic"
aspect = "encoding"
binds = "both"
applies = "T-ONE"
text = "The version byte is 0x09."
sources = ['`commons/zenoh-protocol/src/lib.rs` @ `pub const VERSION: u8 = 0x09;`']
"#;

    const PROFILE: &str = r#"
format = "wz-conformance-requirements"
format_version = 1
layer = "profile"
part = "fixture"
base = "zenoh 1.10.2"

[[requirement]]
id = "P-FIX-1"
strength = "MUST"
kind = "dynamic"
aspect = "procedure"
binds = "sender"
class = "deviation"
deviates_from = ["B-FIX-1"]
text = "The profile's own rule."
sources = ["clause 4.2 of the profile"]
"#;

    const PICS_FIXTURE: &str = r#"
format = "wz-conformance-pics-proforma"
format_version = 1

[[item]]
id = "T-ONE"
question = "One?"
status = "o"
answer = "support"
reference = ["B-FIX-1"]

[[item]]
id = "T-VAL"
question = "Which value?"
status = "m"
answer = "value"
values = ["9"]
reference = ["B-FIX-1"]
"#;

    const PIXIT_FIXTURE: &str = r#"
format = "wz-conformance-pixit-proforma"
format_version = 1

[[item]]
id = "X-A"
question = "Which interface?"
answer = "text"

[[item]]
id = "X-B"
question = "Which other interface?"
answer = "text"
distinct_from = "X-A"
"#;

    /// `base` with the first `from` replaced by `to`; a fixture that does not hold `from` would
    /// make the test it serves vacuous, so it panics instead.
    fn edit(base: &str, from: &str, to: &str) -> String {
        assert!(base.contains(from), "the fixture holds no {from:?}");
        base.replacen(from, to, 1)
    }

    fn violations(requirements: &[&str], pics: &str, pixit: &str) -> Vec<String> {
        let files: Vec<(String, &str)> = requirements
            .iter()
            .enumerate()
            .map(|(i, text)| (format!("fixture-{i}.toml"), *text))
            .collect();
        let named: Vec<(&str, &str)> = files.iter().map(|(n, t)| (n.as_str(), *t)).collect();
        check(&Suite::parse(&named, pics, pixit).expect("the fixture reads"))
    }

    fn refused(found: &[String], needle: &str) {
        assert!(
            found.iter().any(|v| v.contains(needle)),
            "no violation says {needle:?}: {found:?}"
        );
    }

    #[test]
    fn the_committed_suite_holds() {
        let suite = Suite::committed().unwrap();
        let found = check(&suite);
        assert!(found.is_empty(), "{found:#?}");
    }

    #[test]
    fn the_committed_answers_hold() {
        let suite = Suite::committed().unwrap();
        let answers = AnswerFile::committed_wz().unwrap();
        let catalogue = Catalogue::committed().unwrap();
        let found = check_answers(&suite, &answers, &catalogue);
        assert!(found.is_empty(), "{found:#?}");
    }

    #[test]
    fn the_fixture_holds() {
        let found = violations(&[REQUIREMENTS, PROFILE], PICS_FIXTURE, PIXIT_FIXTURE);
        assert!(found.is_empty(), "{found:#?}");
    }

    #[test]
    fn an_id_stated_twice_is_refused() {
        let found = violations(&[REQUIREMENTS, REQUIREMENTS], PICS_FIXTURE, PIXIT_FIXTURE);
        refused(&found, "B-FIX-1: the id is stated twice");
    }

    #[test]
    fn a_source_that_is_no_upstream_anchor_is_refused() {
        let plain = edit(
            REQUIREMENTS,
            "sources = ['`commons/zenoh-protocol/src/lib.rs` @ `pub const VERSION: u8 = 0x09;`']",
            "sources = ['the protocol definition']",
        );
        let found = violations(&[plain.as_str()], PICS_FIXTURE, PIXIT_FIXTURE);
        refused(&found, "is not an anchor");
        refused(&found, "carries an issue");

        let ours = edit(
            REQUIREMENTS,
            "sources = ['`commons/zenoh-protocol/src/lib.rs` @ `pub const VERSION: u8 = 0x09;`']",
            "sources = ['`crates/wz/x.rs` @ `y`']",
        );
        let found = violations(&[ours.as_str()], PICS_FIXTURE, PIXIT_FIXTURE);
        refused(
            &found,
            "is not under a top-level directory of the pinned upstream",
        );
    }

    #[test]
    fn an_implementation_source_alone_needs_an_issue() {
        let implementation = edit(
            REQUIREMENTS,
            "sources = ['`commons/zenoh-protocol/src/lib.rs` @ `pub const VERSION: u8 = 0x09;`']",
            "sources = ['`io/zenoh-transport/src/common/batch.rs` @ `const COMPRESSION: u8 = 1; // 1 << 0`']",
        );
        let found = violations(&[implementation.as_str()], PICS_FIXTURE, PIXIT_FIXTURE);
        refused(
            &found,
            "no source is the protocol definition, its codec or the key expression library",
        );

        let with_issue = format!("{implementation}issue = \"Only an implementation says so.\"\n");
        let found = violations(&[with_issue.as_str()], PICS_FIXTURE, PIXIT_FIXTURE);
        assert!(found.is_empty(), "{found:#?}");
    }

    #[test]
    fn a_procedure_is_not_defined_by_the_codec() {
        let procedure = edit(
            &edit(REQUIREMENTS, "aspect = \"encoding\"", "aspect = \"procedure\""),
            "sources = ['`commons/zenoh-protocol/src/lib.rs` @ `pub const VERSION: u8 = 0x09;`']",
            "sources = ['`commons/zenoh-codec/src/core/zint.rs` @ `const VLE_LEN_MAX: usize = vle_len(u64::MAX);`']",
        );
        let found = violations(&[procedure.as_str()], PICS_FIXTURE, PIXIT_FIXTURE);
        refused(
            &found,
            "no source is the protocol definition or a service contract, so",
        );
    }

    #[test]
    fn the_key_expression_library_is_a_contract_source() {
        let procedure = edit(
            &edit(REQUIREMENTS, "aspect = \"encoding\"", "aspect = \"procedure\""),
            "sources = ['`commons/zenoh-protocol/src/lib.rs` @ `pub const VERSION: u8 = 0x09;`']",
            "sources = ['`commons/zenoh-keyexpr/src/key_expr/borrowed.rs` @ `These chunks are not allowed to be empty.`']",
        );
        let found = violations(&[procedure.as_str()], PICS_FIXTURE, PIXIT_FIXTURE);
        assert!(found.is_empty(), "{found:#?}");
    }

    #[test]
    fn an_id_is_words_joined_by_single_hyphens() {
        for bad in ["B--FIX", "B-FIX-", "1-FIX", "B-fix"] {
            let text = edit(REQUIREMENTS, "id = \"B-FIX-1\"", &format!("id = \"{bad}\""));
            let found = violations(&[text.as_str()], PICS_FIXTURE, PIXIT_FIXTURE);
            refused(
                &found,
                "the id is not upper-case letters, digits and hyphens",
            );
        }
    }

    #[test]
    fn a_selection_must_name_support_items_that_exist() {
        let unknown = edit(REQUIREMENTS, "applies = \"T-ONE\"", "applies = \"T-NONE\"");
        let found = violations(&[unknown.as_str()], PICS_FIXTURE, PIXIT_FIXTURE);
        refused(&found, "applies names T-NONE, which is no PICS item");

        let value = edit(REQUIREMENTS, "applies = \"T-ONE\"", "applies = \"T-VAL\"");
        let found = violations(&[value.as_str()], PICS_FIXTURE, PIXIT_FIXTURE);
        refused(&found, "answered with a value");

        let broken = edit(
            REQUIREMENTS,
            "applies = \"T-ONE\"",
            "applies = \"T-ONE and\"",
        );
        let found = violations(&[broken.as_str()], PICS_FIXTURE, PIXIT_FIXTURE);
        refused(&found, "does not parse");
    }

    #[test]
    fn the_layers_hold_their_classes() {
        let base_with_class = format!("{REQUIREMENTS}class = \"addition\"\n");
        let found = violations(&[base_with_class.as_str()], PICS_FIXTURE, PIXIT_FIXTURE);
        refused(&found, "a base requirement has no class");

        let no_class = edit(PROFILE, "class = \"deviation\"\n", "");
        let found = violations(
            &[REQUIREMENTS, no_class.as_str()],
            PICS_FIXTURE,
            PIXIT_FIXTURE,
        );
        refused(&found, "states its class");

        let bare = edit(PROFILE, "deviates_from = [\"B-FIX-1\"]\n", "");
        let found = violations(&[REQUIREMENTS, bare.as_str()], PICS_FIXTURE, PIXIT_FIXTURE);
        refused(&found, "a deviation names the base requirements");

        let stray = edit(PROFILE, "[\"B-FIX-1\"]", "[\"B-FIX-9\"]");
        let found = violations(&[REQUIREMENTS, stray.as_str()], PICS_FIXTURE, PIXIT_FIXTURE);
        refused(&found, "departs from B-FIX-9, which is no base requirement");

        let selection = edit(PROFILE, "class = \"deviation\"", "class = \"selection\"");
        let found = violations(
            &[REQUIREMENTS, selection.as_str()],
            PICS_FIXTURE,
            PIXIT_FIXTURE,
        );
        refused(&found, "only a deviation departs");
    }

    #[test]
    fn an_unknown_strength_does_not_read() {
        let text = edit(
            REQUIREMENTS,
            "strength = \"MUST\"",
            "strength = \"MUST NOT\"",
        );
        let err = Suite::parse(
            &[("fixture.toml", text.as_str())],
            PICS_FIXTURE,
            PIXIT_FIXTURE,
        )
        .unwrap_err();
        assert!(err.starts_with("fixture.toml:"), "{err}");
    }

    #[test]
    fn a_pics_item_names_requirements_that_exist() {
        let pics = edit(
            PICS_FIXTURE,
            "reference = [\"B-FIX-1\"]",
            "reference = [\"B-FIX-7\"]",
        );
        let found = violations(&[REQUIREMENTS], &pics, PIXIT_FIXTURE);
        refused(&found, "T-ONE: names B-FIX-7, which is no requirement");

        let pics = edit(PICS_FIXTURE, "reference = [\"B-FIX-1\"]", "reference = []");
        let found = violations(&[REQUIREMENTS], &pics, PIXIT_FIXTURE);
        refused(&found, "T-ONE: names no requirement it decides");
    }

    #[test]
    fn a_status_is_of_the_notation() {
        let pics = edit(PICS_FIXTURE, "status = \"o\"", "status = \"q\"");
        refused(
            &violations(&[REQUIREMENTS], &pics, PIXIT_FIXTURE),
            "status \"q\" is not",
        );

        let pics = edit(PICS_FIXTURE, "status = \"o\"", "status = \"o.01\"");
        refused(
            &violations(&[REQUIREMENTS], &pics, PIXIT_FIXTURE),
            "status \"o.01\" is not",
        );

        let pics = edit(PICS_FIXTURE, "status = \"o\"", "status = \"c\"");
        let found = violations(&[REQUIREMENTS], &pics, PIXIT_FIXTURE);
        refused(&found, "a conditional item states its condition");
        refused(&found, "a conditional item states its then status");

        let pics = edit(
            PICS_FIXTURE,
            "status = \"o\"",
            "status = \"c\"\ncondition = \"T-ONE\"\nthen = \"m\"\nelse = \"c\"",
        );
        let found = violations(&[REQUIREMENTS], &pics, PIXIT_FIXTURE);
        refused(&found, "condition names the item itself");
        refused(&found, "else status \"c\" is not");

        let pics = edit(
            PICS_FIXTURE,
            "status = \"o\"",
            "status = \"o\"\nthen = \"m\"",
        );
        refused(
            &violations(&[REQUIREMENTS], &pics, PIXIT_FIXTURE),
            "only a conditional item states a condition",
        );
    }

    #[test]
    fn a_group_has_two_items() {
        let pics = edit(PICS_FIXTURE, "status = \"o\"", "status = \"o.1\"");
        refused(
            &violations(&[REQUIREMENTS], &pics, PIXIT_FIXTURE),
            "group o.1 has one item",
        );
    }

    #[test]
    fn an_answer_shape_fits_its_kind() {
        let pics = edit(
            PICS_FIXTURE,
            "status = \"o\"\nanswer = \"support\"",
            "status = \"o\"\nanswer = \"support\"\nvalues = [\"1\"]",
        );
        refused(
            &violations(&[REQUIREMENTS], &pics, PIXIT_FIXTURE),
            "a support item is answered yes or no",
        );

        let pics = edit(PICS_FIXTURE, "values = [\"9\"]\n", "");
        refused(
            &violations(&[REQUIREMENTS], &pics, PIXIT_FIXTURE),
            "a value item states its values",
        );

        let pics = edit(PICS_FIXTURE, "values = [\"9\"]", "min = 5\nmax = 4");
        refused(
            &violations(&[REQUIREMENTS], &pics, PIXIT_FIXTURE),
            "its max is below its min",
        );

        let pics = edit(
            PICS_FIXTURE,
            "values = [\"9\"]",
            "values = [\"9\"]\nmin = 1",
        );
        refused(
            &violations(&[REQUIREMENTS], &pics, PIXIT_FIXTURE),
            "states both a list of values and a range",
        );
    }

    #[test]
    fn a_pixit_item_is_well_formed() {
        let pixit = edit(
            PIXIT_FIXTURE,
            "distinct_from = \"X-A\"",
            "distinct_from = \"X-Q\"",
        );
        refused(
            &violations(&[REQUIREMENTS], PICS_FIXTURE, &pixit),
            "distinct_from names X-Q, which is no PIXIT item",
        );

        let pixit = edit(
            PIXIT_FIXTURE,
            "distinct_from = \"X-A\"",
            "distinct_from = \"X-B\"",
        );
        refused(
            &violations(&[REQUIREMENTS], PICS_FIXTURE, &pixit),
            "distinct_from names the item itself",
        );

        let pixit = edit(PIXIT_FIXTURE, "answer = \"text\"", "answer = \"choice\"");
        refused(
            &violations(&[REQUIREMENTS], PICS_FIXTURE, &pixit),
            "a choice item states its values",
        );
    }

    fn answer_violations(answers: &str) -> Vec<String> {
        let suite = Suite::parse(REQUIREMENT_FILES, PICS, PIXIT).unwrap();
        let catalogue = Catalogue::committed().unwrap();
        check_answers(&suite, &AnswerFile::parse(answers).unwrap(), &catalogue)
    }

    #[test]
    fn an_answer_names_what_the_declaration_has() {
        let wz = crate::WZ_ANSWERS;
        let text = edit(
            wz,
            "capability = \"multicast-transport\"",
            "capability = \"no-such-plane\"",
        );
        refused(
            &answer_violations(&text),
            "no-such-plane is no capability of the declaration",
        );

        let text = edit(wz, "limit = \"PICO_LEASE_MS\"", "limit = \"NO_SUCH_LIMIT\"");
        refused(
            &answer_violations(&text),
            "NO_SUCH_LIMIT is no limit of the declaration",
        );

        let text = edit(
            wz,
            "capability = \"link-udp\"",
            "capability = \"router-node\"",
        );
        refused(
            &answer_violations(&text),
            "router-node is not a capability of the pico ABI",
        );

        let text = edit(
            wz,
            "policy = \"sn-resolution\"",
            "policy = \"no-such-policy\"",
        );
        refused(
            &answer_violations(&text),
            "no-such-policy is no policy of the declaration",
        );
    }

    #[test]
    fn a_policy_map_covers_every_value_with_an_admitted_answer() {
        let wz = crate::WZ_ANSWERS;
        let text = edit(wz, ", \"bits-64\" = \"64\" }", " }");
        refused(&answer_violations(&text), "the map names");

        let text = edit(wz, "\"bits-8\" = \"8\"", "\"bits-8\" = \"12\"");
        refused(&answer_violations(&text), "maps bits-8 to \"12\"");
    }

    #[test]
    fn an_answer_takes_one_way_that_fits_the_item() {
        let wz = crate::WZ_ANSWERS;
        let text = edit(wz, "fixed = \"9\"", "fixed = \"10\"");
        refused(
            &answer_violations(&text),
            "the fixed answer \"10\" is not one the item admits",
        );

        let text = edit(
            wz,
            "capability = \"multicast-transport\"",
            "capability = \"multicast-transport\"\nlimit = \"PICO_LEASE_MS\"",
        );
        let found = answer_violations(&text);
        refused(&found, "answers in 2 ways");
        refused(
            &found,
            "a limit answers with a value, and the item takes yes or no",
        );

        let text = edit(wz, "limit = \"PICO_LEASE_MS\"", "capability = \"peer\"");
        refused(
            &answer_violations(&text),
            "a capability answers yes or no, and the item takes a value",
        );

        let text = edit(wz, "why = \"The client role needs no capability.\"", "");
        refused(
            &answer_violations(&text),
            "a fixed answer, and only a fixed answer, says why",
        );

        let text = edit(wz, "abi = \"pico\"", "abi = \"core\"");
        refused(
            &answer_violations(&text),
            "core is not an ABI whose library carries its statement",
        );
    }

    #[test]
    fn every_item_is_answered_once_per_abi() {
        let wz = crate::WZ_ANSWERS;
        let text = edit(wz, "item = \"T-PATCH\"", "item = \"T-RID-RES\"");
        let found = answer_violations(&text);
        refused(&found, "answers pico T-PATCH: no row answers it");
        refused(&found, "answers pico T-RID-RES: 2 rows answer it");
    }

    #[test]
    fn a_fact_answer_names_a_fact_of_the_abi_that_gives_an_admitted_answer() {
        let wz = crate::WZ_ANSWERS;
        let text = edit(wz, "fact = \"patch\"", "fact = \"no-such-fact\"");
        refused(
            &answer_violations(&text),
            "no-such-fact is no protocol fact of the declaration for the pico ABI",
        );

        let text = edit(
            wz,
            "item = \"T-COMPRESSION\"\nfact = \"batch-compression\"",
            "item = \"T-COMPRESSION\"\nfact = \"patch\"",
        );
        refused(
            &answer_violations(&text),
            "patch = 1 gives no answer the item admits",
        );

        let text = edit(
            wz,
            "map = { \"0\" = \"no\", \"1\" = \"yes\" }",
            "map = { \"0\" = \"no\" }",
        );
        refused(
            &answer_violations(&text),
            "patch = 1 gives no answer the item admits",
        );

        let text = edit(
            wz,
            "map = { \"0\" = \"no\", \"1\" = \"yes\" }",
            "map = { \"0\" = \"maybe\", \"1\" = \"yes\" }",
        );
        refused(&answer_violations(&text), "maps 0 to \"maybe\"");
    }

    #[test]
    fn a_pixit_answer_names_a_pixit_item_of_the_item_s_kind() {
        let wz = crate::WZ_ANSWERS;
        let text = edit(wz, "pixit = \"X-IUT-LEASE\"", "pixit = \"X-IUT-NONE\"");
        refused(&answer_violations(&text), "X-IUT-NONE is no PIXIT item");

        let text = edit(wz, "pixit = \"X-IUT-LEASE\"", "pixit = \"X-TMP-CHANNEL\"");
        refused(
            &answer_violations(&text),
            "X-TMP-CHANNEL does not answer in the item's kind",
        );

        let text = edit(
            wz,
            "item = \"T-MCAST\"\ncapability = \"multicast-transport\"",
            "item = \"T-MCAST\"\npixit = \"X-IUT-LEASE\"",
        );
        refused(
            &answer_violations(&text),
            "X-IUT-LEASE does not answer in the item's kind",
        );
    }

    #[test]
    fn an_anchor_is_read_by_its_form() {
        assert_eq!(anchored_path("`a/b.rs` @ `x y`"), Some("a/b.rs"));
        assert_eq!(anchored_path("`a/b.rs` @ ``"), None);
        assert_eq!(anchored_path("`a/b.txt` @ `x`"), None);
        assert_eq!(anchored_path("a/b.rs @ x"), None);
        let long = format!("`a/b.rs` @ `{}`", "n".repeat(NEEDLE_MAX + 1));
        assert_eq!(anchored_path(&long), None);
        assert!(is_upstream("commons/a"));
        assert!(!is_upstream("crates/a"));
        assert!(!is_upstream("commons/"));
    }
}

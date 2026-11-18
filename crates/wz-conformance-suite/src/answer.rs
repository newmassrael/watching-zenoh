// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A wz build's PICS, read from its conformance statement.
//!
//! The statement, which a build derives from the configuration it was built with, lists every
//! capability of the build's ABI with whether the build has it, every limit and policy with its
//! value, and the ABI's protocol facts. The answer file says which of those answers which PICS
//! item; [`answer()`] applies it. An item whose value the implementation reads from its
//! configuration when a session opens is answered by the test environment's PIXIT instead
//! ([`resolve()`]).
//! The catalogue is what the answer file is checked against: the capabilities, limits, policies
//! and protocol facts `deploy/wz-config.toml` declares.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::{AnswerFile, AnswerKind, PicsProforma, WZ_CONFIG};

/// The committed pin of the protocol facts, `crates/wz-conformance-suite/facts_pin.toml`.
pub const FACTS_PIN: &str = include_str!("../facts_pin.toml");

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinFile {
    pin: Vec<Pin>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    catalog_version: u64,
    facts_digest: String,
}

/// Every violation of the facts pin against a declaration: the pin's versions increase, and its
/// last row is the declaration's catalogue version with the digest of the declaration's facts.
/// The facts moving while the version stays is the violation the pin exists for.
pub fn check_facts_pin(pin_text: &str, declaration: &str) -> Vec<String> {
    let mut out = Vec::new();
    let pins: PinFile = match toml::from_str(pin_text) {
        Ok(pins) => pins,
        Err(e) => return vec![format!("facts_pin.toml: {e}")],
    };
    let catalogue = match Catalogue::parse(declaration) {
        Ok(catalogue) => catalogue,
        Err(e) => return vec![e],
    };
    let version = toml::from_str::<toml::Table>(declaration)
        .ok()
        .and_then(|t| t.get("catalog_version").and_then(toml::Value::as_integer))
        .and_then(|v| u64::try_from(v).ok());
    let Some(version) = version else {
        return vec!["the declaration has no catalog_version that is a count".to_string()];
    };
    for pair in pins.pin.windows(2) {
        if pair[1].catalog_version <= pair[0].catalog_version {
            out.push(format!(
                "facts_pin.toml: catalogue version {} follows {}; the rows increase",
                pair[1].catalog_version, pair[0].catalog_version
            ));
        }
    }
    let digest = facts_digest(&catalogue.facts);
    match pins.pin.last() {
        None => out.push("facts_pin.toml: pins nothing".to_string()),
        Some(last) if last.catalog_version == version && last.facts_digest != digest => {
            out.push(format!(
                "the protocol facts changed and catalog_version is still {version}: raise it, \
                 and pin the facts at the new version with {digest}"
            ))
        }
        Some(last) if last.catalog_version < version => out.push(format!(
            "catalog_version is {version} and the facts are pinned at {}: add the row \
             catalog_version = {version}, facts_digest = {digest}",
            last.catalog_version
        )),
        Some(last) if last.catalog_version > version => out.push(format!(
            "facts_pin.toml pins catalogue version {}, which the declaration ({version}) has not \
             reached",
            last.catalog_version
        )),
        Some(_) => {}
    }
    out
}

/// A capability of the declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogueCapability {
    /// The ABIs whose statements list it.
    pub abis: Vec<String>,
    /// Whether a build that names nothing has it.
    pub default_on: bool,
}

/// A policy of the declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CataloguePolicy {
    /// Every value it can take: its choices, or `off` and `on` for a bool.
    pub values: Vec<String>,
    pub default: String,
}

/// A protocol fact of the declaration: what a session of an ABI states that no switch moves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogueFact {
    /// The fact's value for each ABI that has it.
    pub values: BTreeMap<String, String>,
    /// Each file of this tree, with a text that must occur in it.
    pub holds: Vec<(String, String)>,
    /// Each file of this tree, with a text that must not occur in it.
    pub lacks: Vec<(String, String)>,
}

/// A `holds` or `lacks` entry, `<file of this tree> @ <text>`, as its two halves.
fn fact_entry(id: &str, entry: &str) -> Result<(String, String), String> {
    match entry.split_once(" @ ") {
        Some((path, text)) if !path.is_empty() && !text.is_empty() && !path.starts_with('/') => {
            Ok((path.to_string(), text.to_string()))
        }
        _ => Err(format!(
            "protocol fact {id}: {entry:?} is not <file of this tree> @ <text>"
        )),
    }
}

/// The canonical form of the facts' values: each fact by id, each with its ABIs' values by ABI,
/// as `id:abi=value,abi=value` joined by `;`. What holds a fact is evidence and is left out; a
/// change of it is not a change of the fact.
pub fn facts_canonical(facts: &BTreeMap<String, CatalogueFact>) -> String {
    facts
        .iter()
        .map(|(id, fact)| {
            let values: Vec<String> = fact
                .values
                .iter()
                .map(|(abi, value)| format!("{abi}={value}"))
                .collect();
            format!("{id}:{}", values.join(","))
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// `sha256:` and the lowercase hex SHA-256 of [`facts_canonical`].
pub fn facts_digest(facts: &BTreeMap<String, CatalogueFact>) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    let hash = Sha256::digest(facts_canonical(facts).as_bytes());
    let mut out = String::from("sha256:");
    for byte in hash {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The ABIs a protocol fact can name, the ones whose libraries carry their statement.
const FACT_ABIS: &[&str] = &["pico", "c"];

/// The capabilities, limits, policies and protocol facts of the build declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalogue {
    pub capabilities: BTreeMap<String, CatalogueCapability>,
    /// Each limit with its default.
    pub limits: BTreeMap<String, u64>,
    pub policies: BTreeMap<String, CataloguePolicy>,
    pub facts: BTreeMap<String, CatalogueFact>,
}

fn rows<'a>(table: &'a toml::Table, key: &str) -> Result<&'a [toml::Value], String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("the declaration has no [[{key}]] rows"))
}

fn text<'a>(row: &'a toml::Value, kind: &str, key: &str) -> Result<&'a str, String> {
    row.get(key)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("a [[{kind}]] row has no text `{key}`"))
}

fn optional_text(row: &toml::Value, key: &str) -> Option<String> {
    row.get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_string)
}

fn texts(row: &toml::Value, kind: &str, key: &str) -> Result<Vec<String>, String> {
    let list = row
        .get(key)
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("a [[{kind}]] row has no list `{key}`"))?;
    list.iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("a [[{kind}]] row's `{key}` holds a value that is no text"))
        })
        .collect()
}

impl Catalogue {
    /// Reads the catalogue from a declaration's text. A declaration without protocol facts has
    /// none; one with a fact that names no ABI's value, names nothing that holds it, or has an
    /// entry that is not `<file> @ <text>`, is refused.
    pub fn parse(declaration: &str) -> Result<Catalogue, String> {
        let table: toml::Table =
            toml::from_str(declaration).map_err(|e| format!("the declaration: {e}"))?;
        let mut capabilities = BTreeMap::new();
        for row in rows(&table, "capability")? {
            let id = text(row, "capability", "id")?;
            let default_on = row.get("default").and_then(toml::Value::as_str) != Some("off");
            let abis = texts(row, "capability", "abis")?;
            capabilities.insert(id.to_string(), CatalogueCapability { abis, default_on });
        }
        let mut limits = BTreeMap::new();
        for row in rows(&table, "limit")? {
            let id = text(row, "limit", "id")?;
            let default = row
                .get("default")
                .and_then(toml::Value::as_integer)
                .and_then(|v| u64::try_from(v).ok())
                .ok_or_else(|| format!("limit {id} has no default that is a count"))?;
            limits.insert(id.to_string(), default);
        }
        let mut policies = BTreeMap::new();
        for row in rows(&table, "policy")? {
            let id = text(row, "policy", "id")?;
            let values = match text(row, "policy", "kind")? {
                "bool" => vec!["off".to_string(), "on".to_string()],
                "choice" => texts(row, "policy", "choices")?,
                other => {
                    return Err(format!(
                        "policy {id} is of kind {other}, not bool or choice"
                    ))
                }
            };
            let default = text(row, "policy", "default")?.to_string();
            policies.insert(id.to_string(), CataloguePolicy { values, default });
        }
        let mut facts = BTreeMap::new();
        let fact_rows = match table.get("protocol_fact") {
            None => &[][..],
            Some(_) => rows(&table, "protocol_fact")?,
        };
        for row in fact_rows {
            let id = text(row, "protocol_fact", "id")?;
            let values: BTreeMap<String, String> = FACT_ABIS
                .iter()
                .filter_map(|abi| optional_text(row, abi).map(|v| ((*abi).to_string(), v)))
                .collect();
            if values.is_empty() {
                return Err(format!("protocol fact {id} names a value for no ABI"));
            }
            let entries = |key: &str| -> Result<Vec<(String, String)>, String> {
                if row.get(key).is_none() {
                    return Ok(Vec::new());
                }
                texts(row, "protocol_fact", key)?
                    .iter()
                    .map(|entry| fact_entry(id, entry))
                    .collect()
            };
            let fact = CatalogueFact {
                values,
                holds: entries("holds")?,
                lacks: entries("lacks")?,
            };
            if fact.holds.is_empty() && fact.lacks.is_empty() {
                return Err(format!(
                    "protocol fact {id} names nothing of this tree that holds it"
                ));
            }
            facts.insert(id.to_string(), fact);
        }
        Ok(Catalogue {
            capabilities,
            limits,
            policies,
            facts,
        })
    }

    /// The catalogue of the committed `deploy/wz-config.toml`.
    pub fn committed() -> Result<Catalogue, String> {
        Catalogue::parse(WZ_CONFIG)
    }
}

/// The part of a conformance statement the PICS is answered from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub abi: String,
    /// Each capability of the ABI with whether the build has it.
    pub capabilities: BTreeMap<String, bool>,
    pub limits: BTreeMap<String, u64>,
    pub policies: BTreeMap<String, String>,
    /// Each protocol fact of the ABI with its value.
    pub facts: BTreeMap<String, String>,
}

impl Statement {
    /// The statement of a build of `abi` that states nothing: each capability the ABI exports at
    /// its default, each limit and policy at its default, and the ABI's protocol facts.
    pub fn defaults(catalogue: &Catalogue, abi: &str) -> Statement {
        Statement {
            abi: abi.to_string(),
            capabilities: catalogue
                .capabilities
                .iter()
                .filter(|(_, cap)| cap.abis.iter().any(|a| a == abi))
                .map(|(id, cap)| (id.clone(), cap.default_on))
                .collect(),
            limits: catalogue.limits.clone(),
            policies: catalogue
                .policies
                .iter()
                .map(|(id, pol)| (id.clone(), pol.default.clone()))
                .collect(),
            facts: catalogue
                .facts
                .iter()
                .filter_map(|(id, fact)| fact.values.get(abi).map(|v| (id.clone(), v.clone())))
                .collect(),
        }
    }
}

/// One PICS item's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PicsAnswer {
    Support(bool),
    Value(String),
    /// The implementation reads it from its configuration; the PIXIT item named here states it
    /// for one test environment.
    Configured(String),
    /// The statement cannot answer it; the text says what it lacks.
    Unanswered(String),
}

/// An item's answer in the item's own words: a support item's `yes` or `no`, a value item's
/// value. `None` for a word a support item does not take.
fn worded(kind: AnswerKind, word: &str) -> Option<PicsAnswer> {
    match kind {
        AnswerKind::Support => match word {
            "yes" => Some(PicsAnswer::Support(true)),
            "no" => Some(PicsAnswer::Support(false)),
            _ => None,
        },
        AnswerKind::Value => Some(PicsAnswer::Value(word.to_string())),
    }
}

/// The PICS of the build `statement` describes, by item id, read through `answers`.
///
/// Refused: an answer row the proforma has no item for, a statement that lacks a capability,
/// limit, policy or protocol fact a row reads, a policy or fact value the row's map does not
/// name, and a row that answers in none of the ways. [`crate::check_answers`] refuses all of
/// these for the committed rows before any statement is read; here they are refused again
/// because a statement is an input.
pub fn answer(
    proforma: &PicsProforma,
    answers: &AnswerFile,
    statement: &Statement,
) -> Result<BTreeMap<String, PicsAnswer>, String> {
    let mut out = BTreeMap::new();
    for row in answers.answers.iter().filter(|r| r.abi == statement.abi) {
        let item = proforma
            .items
            .iter()
            .find(|i| i.id == row.item)
            .ok_or_else(|| format!("{} is no PICS item", row.item))?;
        let value = if let Some(cap) = &row.capability {
            let supported = statement
                .capabilities
                .get(cap)
                .ok_or_else(|| format!("the statement has no capability {cap}"))?;
            PicsAnswer::Support(*supported)
        } else if let Some(limit) = &row.limit {
            let value = statement
                .limits
                .get(limit)
                .ok_or_else(|| format!("the statement has no limit {limit}"))?;
            PicsAnswer::Value(value.to_string())
        } else if let Some(policy) = &row.policy {
            let value = statement
                .policies
                .get(policy)
                .ok_or_else(|| format!("the statement has no policy {policy}"))?;
            let mapped = row.map.get(value).ok_or_else(|| {
                format!(
                    "{}: the map names no answer for {policy} = {value}",
                    row.item
                )
            })?;
            PicsAnswer::Value(mapped.clone())
        } else if let Some(fact) = &row.fact {
            let value = statement
                .facts
                .get(fact)
                .ok_or_else(|| format!("the statement has no protocol fact {fact}"))?;
            let word = if row.map.is_empty() {
                value
            } else {
                row.map.get(value).ok_or_else(|| {
                    format!("{}: the map names no answer for {fact} = {value}", row.item)
                })?
            };
            worded(item.answer, word).ok_or_else(|| {
                format!("{}: {fact} = {value} is no answer the item takes", row.item)
            })?
        } else if let Some(pixit) = &row.pixit {
            PicsAnswer::Configured(pixit.clone())
        } else if let Some(fixed) = &row.fixed {
            worded(item.answer, fixed)
                .ok_or_else(|| format!("{}: {fixed} is no answer the item takes", row.item))?
        } else if let Some(why) = &row.unanswered {
            PicsAnswer::Unanswered(why.clone())
        } else {
            return Err(format!("{}: the row answers in none of the ways", row.item));
        };
        out.insert(row.item.clone(), value);
    }
    Ok(out)
}

/// `pics` with each configured answer replaced by the value one test environment's PIXIT states
/// for it (`pixit`, by PIXIT item id).
///
/// Refused: a configured answer whose PIXIT item the environment does not state, and a stated
/// value the PICS item does not admit. The other answers pass unchanged.
pub fn resolve(
    proforma: &PicsProforma,
    pics: &BTreeMap<String, PicsAnswer>,
    pixit: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, PicsAnswer>, String> {
    let mut out = BTreeMap::new();
    for (id, answer) in pics {
        let resolved = match answer {
            PicsAnswer::Configured(from) => {
                let value = pixit.get(from).ok_or_else(|| {
                    format!("{id} is configured, and the environment states no {from}")
                })?;
                let item = proforma
                    .items
                    .iter()
                    .find(|i| i.id == *id)
                    .ok_or_else(|| format!("{id} is no PICS item"))?;
                let admitted = match item.answer {
                    AnswerKind::Support => value == "yes" || value == "no",
                    AnswerKind::Value => item.admits(value),
                };
                if !admitted {
                    return Err(format!("{id}: {from} = {value} is not an answer it admits"));
                }
                worded(item.answer, value).ok_or_else(|| format!("{id}: {value} is no answer"))?
            }
            other => other.clone(),
        };
        out.insert(id.clone(), resolved);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::Suite;

    fn committed() -> (PicsProforma, AnswerFile, Catalogue) {
        (
            Suite::committed().unwrap().pics,
            AnswerFile::committed_wz().unwrap(),
            Catalogue::committed().unwrap(),
        )
    }

    #[test]
    fn the_catalogue_reads_the_declaration() {
        let catalogue = Catalogue::committed().unwrap();
        let mcast = &catalogue.capabilities["multicast-transport"];
        assert!(mcast.abis.iter().any(|a| a == "pico"));
        assert!(mcast.default_on);
        assert!(!catalogue.capabilities["admin-space"].default_on);
        assert_eq!(catalogue.limits["PICO_UNICAST_BATCH_BYTES"], 2048);
        let sn = &catalogue.policies["sn-resolution"];
        assert_eq!(sn.default, "bits-32");
        assert!(sn.values.iter().any(|v| v == "bits-8"));
        assert_eq!(
            catalogue.policies["targeted-query"].values,
            ["off".to_string(), "on".to_string()]
        );
        assert_eq!(catalogue.facts["patch"].values["pico"], "1");
        assert!(!catalogue.facts["batch-compression"]
            .values
            .contains_key("c"));
    }

    #[test]
    fn every_protocol_fact_is_held_by_the_files_it_names() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let catalogue = Catalogue::committed().unwrap();
        assert!(!catalogue.facts.is_empty());
        let read = |id: &str, path: &str| {
            std::fs::read_to_string(root.join(path)).unwrap_or_else(|e| panic!("{id}: {path}: {e}"))
        };
        for (id, fact) in &catalogue.facts {
            for (path, text) in &fact.holds {
                assert!(
                    read(id, path).contains(text.as_str()),
                    "{id}: {text:?} is gone from {path}"
                );
            }
            for (path, text) in &fact.lacks {
                assert!(
                    !read(id, path).contains(text.as_str()),
                    "{id}: {text:?} is in {path}"
                );
            }
        }
    }

    #[test]
    fn a_malformed_protocol_fact_is_refused() {
        let base = crate::WZ_CONFIG;
        let no_check = base.replacen(
            "holds = [\"crates/wz-session-core/src/extpatch.rs @ pub const CURRENT_PATCH: u8 = 1;\"]\n",
            "",
            1,
        );
        assert_ne!(no_check, base);
        let err = Catalogue::parse(&no_check).unwrap_err();
        assert!(
            err.contains("names nothing of this tree that holds it"),
            "{err}"
        );

        let no_at = base.replacen(
            "crates/wz-session-core/src/extpatch.rs @ pub const",
            "crates/wz-session-core/src/extpatch.rs pub const",
            1,
        );
        assert_ne!(no_at, base);
        let err = Catalogue::parse(&no_at).unwrap_err();
        assert!(err.contains("is not <file of this tree> @ <text>"), "{err}");

        let no_abi = base.replacen("pico = \"1\"\nc = \"1\"\n", "", 1);
        assert_ne!(no_abi, base);
        let err = Catalogue::parse(&no_abi).unwrap_err();
        assert!(err.contains("names a value for no ABI"), "{err}");
    }

    #[test]
    fn the_facts_are_pinned_at_the_catalogue_version() {
        let found = check_facts_pin(FACTS_PIN, crate::WZ_CONFIG);
        assert!(found.is_empty(), "{found:#?}");
    }

    #[test]
    fn a_fact_that_moves_without_the_catalogue_version_is_refused() {
        let base = crate::WZ_CONFIG;
        let moved = base.replacen(
            "id = \"patch\"\npico = \"1\"",
            "id = \"patch\"\npico = \"0\"",
            1,
        );
        assert_ne!(moved, base);
        let found = check_facts_pin(FACTS_PIN, &moved);
        assert!(
            found
                .iter()
                .any(|v| v.contains("the protocol facts changed and catalog_version is still 2")),
            "{found:#?}"
        );

        let raised = moved.replacen("catalog_version = 2\n", "catalog_version = 3\n", 1);
        assert_ne!(raised, moved);
        let found = check_facts_pin(FACTS_PIN, &raised);
        assert!(
            found
                .iter()
                .any(|v| v.contains("add the row catalog_version = 3")),
            "{found:#?}"
        );

        let digest = facts_digest(&Catalogue::parse(&raised).unwrap().facts);
        let pinned =
            format!("{FACTS_PIN}\n[[pin]]\ncatalog_version = 3\nfacts_digest = \"{digest}\"\n");
        let found = check_facts_pin(&pinned, &raised);
        assert!(
            found.is_empty(),
            "a new row for the new version settles it: {found:#?}"
        );

        let backwards =
            format!("{FACTS_PIN}\n[[pin]]\ncatalog_version = 1\nfacts_digest = \"{digest}\"\n");
        let found = check_facts_pin(&backwards, base);
        assert!(
            found.iter().any(|v| v.contains("the rows increase")),
            "{found:#?}"
        );
    }

    #[test]
    fn the_facts_canonical_form_is_by_id_then_abi() {
        let catalogue = Catalogue::committed().unwrap();
        let canonical = facts_canonical(&catalogue.facts);
        assert!(
            canonical.starts_with("batch-compression:pico=no;patch:c=1,pico=1;"),
            "{canonical}"
        );
        let mut moved = catalogue.facts.clone();
        moved
            .get_mut("patch")
            .unwrap()
            .values
            .insert("c".into(), "0".into());
        assert_ne!(facts_digest(&moved), facts_digest(&catalogue.facts));
        let mut evidence = catalogue.facts.clone();
        evidence.get_mut("patch").unwrap().holds.clear();
        assert_eq!(
            facts_digest(&evidence),
            facts_digest(&catalogue.facts),
            "what holds a fact is not the fact"
        );
    }

    #[test]
    fn a_default_pico_build_answers_from_its_statement() {
        let (pics, answers, catalogue) = committed();
        let pico = answer(&pics, &answers, &Statement::defaults(&catalogue, "pico")).unwrap();
        assert_eq!(pico.len(), pics.items.len(), "every item answered once");
        assert_eq!(pico["T-FSN-RES"], PicsAnswer::Value("32".into()));
        assert_eq!(pico["T-BATCH-UNICAST"], PicsAnswer::Value("2048".into()));
        assert_eq!(pico["T-LEASE"], PicsAnswer::Value("10000".into()));
        assert_eq!(pico["T-MCAST"], PicsAnswer::Support(true));
        assert_eq!(pico["T-UNICAST"], PicsAnswer::Support(true));
        assert_eq!(pico["T-VERSION"], PicsAnswer::Value("9".into()));
        assert_eq!(pico["T-PATCH"], PicsAnswer::Support(true));
        assert_eq!(pico["T-COMPRESSION"], PicsAnswer::Support(false));
        assert_eq!(pico["N-QUERY"], PicsAnswer::Support(true));
        assert_eq!(pico["T-ROLE-ROUTER"], PicsAnswer::Support(false));
        assert_eq!(pico["T-STREAM-LINK"], PicsAnswer::Support(true));
        assert_eq!(pico["T-RID-RES"], PicsAnswer::Value("32".into()));
        assert!(
            !pico
                .values()
                .any(|a| matches!(a, PicsAnswer::Unanswered(_))),
            "every item of a default pico build is answered: {pico:#?}"
        );
    }

    #[test]
    fn a_default_zenoh_c_build_answers_from_its_statement() {
        let (pics, answers, catalogue) = committed();
        let c = answer(&pics, &answers, &Statement::defaults(&catalogue, "c")).unwrap();
        assert_eq!(c.len(), pics.items.len(), "every item answered once");
        assert_eq!(c["T-ROLE-ROUTER"], PicsAnswer::Support(true));
        assert_eq!(c["T-COMPRESSION"], PicsAnswer::Support(true));
        assert_eq!(c["T-PATCH"], PicsAnswer::Support(true));
        assert_eq!(
            c["T-BATCH-UNICAST"],
            PicsAnswer::Configured("X-IUT-BATCH-UNICAST".into())
        );
    }

    #[test]
    fn a_configured_answer_is_resolved_from_the_environment() {
        let (pics, answers, catalogue) = committed();
        let c = answer(&pics, &answers, &Statement::defaults(&catalogue, "c")).unwrap();
        let env: BTreeMap<String, String> = [
            ("X-IUT-BATCH-UNICAST", "2048"),
            ("X-IUT-BATCH-MCAST", "8192"),
            ("X-IUT-LEASE", "10000"),
            ("X-IUT-KA-PER-LEASE", "4"),
            ("X-IUT-FRAG-MAX", "1048576"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let resolved = resolve(&pics, &c, &env).unwrap();
        assert_eq!(
            resolved["T-BATCH-UNICAST"],
            PicsAnswer::Value("2048".into())
        );
        assert_eq!(resolved["T-ROLE-ROUTER"], c["T-ROLE-ROUTER"]);
        assert!(!resolved
            .values()
            .any(|a| matches!(a, PicsAnswer::Configured(_))));

        let mut missing = env.clone();
        missing.remove("X-IUT-LEASE");
        let err = resolve(&pics, &c, &missing).unwrap_err();
        assert!(err.contains("states no X-IUT-LEASE"), "{err}");

        let mut wide = env;
        wide.insert("X-IUT-BATCH-UNICAST".into(), "70000".into());
        let err = resolve(&pics, &c, &wide).unwrap_err();
        assert!(err.contains("X-IUT-BATCH-UNICAST = 70000"), "{err}");
    }

    #[test]
    fn a_stated_value_moves_the_answer() {
        let (pics, answers, catalogue) = committed();
        let mut st = Statement::defaults(&catalogue, "pico");
        st.policies.insert("sn-resolution".into(), "bits-8".into());
        st.limits.insert("PICO_UNICAST_BATCH_BYTES".into(), 512);
        st.capabilities.insert("multicast-transport".into(), false);
        st.facts.insert("patch".into(), "0".into());
        let pico = answer(&pics, &answers, &st).unwrap();
        assert_eq!(pico["T-FSN-RES"], PicsAnswer::Value("8".into()));
        assert_eq!(pico["T-BATCH-UNICAST"], PicsAnswer::Value("512".into()));
        assert_eq!(pico["T-MCAST"], PicsAnswer::Support(false));
        assert_eq!(pico["T-PATCH"], PicsAnswer::Support(false));
    }

    #[test]
    fn a_statement_that_lacks_what_a_row_reads_is_refused() {
        let (pics, answers, catalogue) = committed();
        let mut st = Statement::defaults(&catalogue, "pico");
        st.capabilities.remove("multicast-transport");
        let err = answer(&pics, &answers, &st).unwrap_err();
        assert!(err.contains("no capability multicast-transport"), "{err}");

        let mut st = Statement::defaults(&catalogue, "pico");
        st.limits.remove("PICO_LEASE_MS");
        let err = answer(&pics, &answers, &st).unwrap_err();
        assert!(err.contains("no limit PICO_LEASE_MS"), "{err}");

        let mut st = Statement::defaults(&catalogue, "pico");
        st.policies.insert("sn-resolution".into(), "bits-12".into());
        let err = answer(&pics, &answers, &st).unwrap_err();
        assert!(err.contains("sn-resolution = bits-12"), "{err}");

        let mut st = Statement::defaults(&catalogue, "pico");
        st.facts.remove("patch");
        let err = answer(&pics, &answers, &st).unwrap_err();
        assert!(err.contains("no protocol fact patch"), "{err}");

        let mut st = Statement::defaults(&catalogue, "pico");
        st.facts.insert("patch".into(), "2".into());
        let err = answer(&pics, &answers, &st).unwrap_err();
        assert!(err.contains("patch = 2"), "{err}");

        let mut st = Statement::defaults(&catalogue, "pico");
        st.facts.insert("batch-compression".into(), "maybe".into());
        let err = answer(&pics, &answers, &st).unwrap_err();
        assert!(
            err.contains("batch-compression = maybe is no answer"),
            "{err}"
        );
    }

    #[test]
    fn a_statement_of_another_abi_answers_nothing() {
        let (pics, answers, catalogue) = committed();
        let none = answer(&pics, &answers, &Statement::defaults(&catalogue, "core")).unwrap();
        assert!(none.is_empty());
    }
}

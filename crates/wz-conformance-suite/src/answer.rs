// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A wz build's PICS, read from its conformance statement.
//!
//! The statement (decision C15 of docs/build-configuration.md) lists every capability of the
//! build's ABI with whether the build has it, and every limit and policy with its value. The
//! answer file says which of those answers which PICS item; [`answer()`] applies it. The
//! catalogue is what the answer file is checked against: the capabilities, limits and policies
//! `deploy/wz-config.toml` declares, with the ABIs each capability is exported by.

use std::collections::BTreeMap;

use crate::{AnswerFile, AnswerKind, PicsProforma, WZ_CONFIG};

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

/// The capabilities, limits and policies of the build declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalogue {
    pub capabilities: BTreeMap<String, CatalogueCapability>,
    /// Each limit with its default.
    pub limits: BTreeMap<String, u64>,
    pub policies: BTreeMap<String, CataloguePolicy>,
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
    /// Reads the catalogue from a declaration's text.
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
        Ok(Catalogue {
            capabilities,
            limits,
            policies,
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
}

impl Statement {
    /// The statement of a build of `abi` that states nothing: each capability the ABI exports at
    /// its default, each limit and policy at its default.
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
        }
    }
}

/// One PICS item's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PicsAnswer {
    Support(bool),
    Value(String),
    /// The statement cannot answer it; the text says what it lacks.
    Unanswered(String),
}

/// The PICS of the build `statement` describes, by item id, read through `answers`.
///
/// Refused: an answer row the proforma has no item for, a statement that lacks a capability,
/// limit or policy a row reads, a policy value the row's map does not name, and a row that
/// answers in none of the five ways. [`crate::check_answers`] refuses all of these for the
/// committed rows before any statement is read; here they are refused again because a
/// statement is an input.
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
        } else if let Some(fixed) = &row.fixed {
            match item.answer {
                AnswerKind::Support => PicsAnswer::Support(fixed == "yes"),
                AnswerKind::Value => PicsAnswer::Value(fixed.clone()),
            }
        } else if let Some(why) = &row.unanswered {
            PicsAnswer::Unanswered(why.clone())
        } else {
            return Err(format!(
                "{}: the row answers in none of the five ways",
                row.item
            ));
        };
        out.insert(row.item.clone(), value);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
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
        assert!(matches!(pico["T-ROLE-ROUTER"], PicsAnswer::Unanswered(_)));
    }

    #[test]
    fn a_default_zenoh_c_build_answers_from_its_statement() {
        let (pics, answers, catalogue) = committed();
        let c = answer(&pics, &answers, &Statement::defaults(&catalogue, "c")).unwrap();
        assert_eq!(c.len(), pics.items.len(), "every item answered once");
        assert_eq!(c["T-ROLE-ROUTER"], PicsAnswer::Support(true));
        assert_eq!(c["T-COMPRESSION"], PicsAnswer::Support(true));
        assert!(matches!(c["T-BATCH-UNICAST"], PicsAnswer::Unanswered(_)));
    }

    #[test]
    fn a_stated_value_moves_the_answer() {
        let (pics, answers, catalogue) = committed();
        let mut st = Statement::defaults(&catalogue, "pico");
        st.policies.insert("sn-resolution".into(), "bits-8".into());
        st.limits.insert("PICO_UNICAST_BATCH_BYTES".into(), 512);
        st.capabilities.insert("multicast-transport".into(), false);
        let pico = answer(&pics, &answers, &st).unwrap();
        assert_eq!(pico["T-FSN-RES"], PicsAnswer::Value("8".into()));
        assert_eq!(pico["T-BATCH-UNICAST"], PicsAnswer::Value("512".into()));
        assert_eq!(pico["T-MCAST"], PicsAnswer::Support(false));
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
    }

    #[test]
    fn a_statement_of_another_abi_answers_nothing() {
        let (pics, answers, catalogue) = committed();
        let none = answer(&pics, &answers, &Statement::defaults(&catalogue, "core")).unwrap();
        assert!(none.is_empty());
    }
}

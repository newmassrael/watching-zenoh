// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a config's access control would decide for a list of messages,
//! reachable from C.
//!
//! # Why this library and not the dissect one
//!
//! The question takes a zenoh config document, and the reader of that document
//! and the compile of its `access_control` subtree live in `wz-runtime-tokio`'s
//! `zenoh_config`, behind `access-acl`, which this library already links for
//! the open and for the config verdict. The analysis surfaces reach no
//! configuration at all (`scripts/lib/analysis_surface_config_free.py`), so a
//! door there would either pull the runtime in or read the document a second
//! way. Here the verdict is the router's by construction: the document goes
//! through `ZenohNodeConfig::from_json5` (as every other door of this crate
//! that reads a config), the subtree through
//! `zenoh_config::acl_config_with_origins` (the compile a node's enforcer is
//! built from), and every question through `AclPolicy::judge`, which asks
//! `AclPolicy::decide`, the body of the enforcer's own `decision`.
//!
//! # A refusal is the config verdict's row
//!
//! A config this door cannot judge is refused as `wz_capi_c_config_validate_rows`
//! refuses it: the same code and the same row, in the same owned verdict type,
//! so a caller reads it with the accessors it already has. An `access_control`
//! subtree that was read and cannot become a policy (a policy naming a rule no
//! rule defines, and the rest of `AclCompileError`) is a row too, with the list
//! at fault as its key: a node would not open on it. A question that cannot be
//! read is a row naming its position, as a node name the topology door cannot
//! read is. Every refusal in the call is reported, and no answer is written
//! while there is one.
//!
//! # What an unknown attribute means
//!
//! A question states only the subject attributes its caller knows. An absent
//! one is tried with every value the applicable rules can tell apart
//! (`AclPolicy::judge` says which), and an answer that differs between those
//! values names the attribute in `needs`. A stated `null` is a KNOWN absence:
//! no username, no certificate name, or for the zid a face the router could not
//! attribute to any peer.
//!
//! # Which layout the answers read, said in the answers
//!
//! The answers document opens with its own name and revision, the envelope
//! every document a wz door hands out carries (`wz_capture::doc_revision` states
//! the rule and the tests here hold this one to it), and then `zenoh_layout`:
//! the zenoh release whose config layout the question was put to,
//! `zenoh_config::ZENOH_LAYOUT_VERSION`, the one constant that states it. A gate
//! holds that constant to the pinned upstream version, so the document cannot
//! name a layout the tree no longer reads.

#![allow(non_camel_case_types)]

use std::ffi::{c_char, CStr};

use wz_runtime_tokio::interceptor::{
    AclDecision, AclFlow, AclJudgement, AclMessage, AclPolicy, Attribute, DecidedBy,
    PartialSubject, Permission, Zid,
};
use wz_runtime_tokio::json5::{self, Json5Value};
use wz_runtime_tokio::zenoh_config::{
    acl_config_with_origins, AclRuleOrigin, CompiledAcl, ZENOH_LAYOUT_VERSION,
};
use wz_runtime_tokio::zenoh_config_finding::{BlamedSite, Finding};
use wz_runtime_tokio::zid_hex::zenoh_hex_to_zid;
use wz_session_core::json::escape_into;
use wz_session_core::keyexpr_canon::validate_keyexpr;
use wz_session_core::link::InterceptorLink;

use crate::abi::{z_loaned_config_t, z_owned_string_t};
use crate::config_verdict::node_config;
use crate::config_verdict_rows::{publish, wz_capi_c_owned_config_verdict_t};
use crate::ffi::guarded;
use crate::result::{ZResult, Z_ENULL, Z_EPARSE, Z_OK};
use crate::string::{null_string, owned_string_from};

/// Why the questions argument, or one question in it, cannot be read.
///
/// The variant name is the row's stable half, taken from `Debug` as every
/// other row's is; the sentence is its prose.
#[derive(Debug)]
enum QuestionRefusal {
    /// The questions pointer was null.
    NoQuestions,
    /// The questions text is not UTF-8.
    QuestionsNotUtf8,
    /// The questions text is not JSON5.
    QuestionsNotJson5 {
        /// The parser's own words.
        reason: String,
    },
    /// The questions text is not a list.
    QuestionsNotAList,
    /// One question is not an object.
    QuestionNotAnObject {
        /// Its position in the list.
        index: usize,
    },
    /// A question leaves out a member every question states.
    QuestionMemberMissing {
        /// Its position in the list.
        index: usize,
        /// The member.
        member: &'static str,
    },
    /// A question states a member this door does not read.
    QuestionMemberUnknown {
        /// Its position in the list.
        index: usize,
        /// The member as spelled.
        member: String,
    },
    /// A member holds a value of the wrong type, or a word outside its set.
    QuestionMemberInvalid {
        /// Its position in the list.
        index: usize,
        /// The member.
        member: &'static str,
    },
}

impl std::fmt::Display for QuestionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuestionRefusal::NoQuestions => f.write_str("no questions"),
            QuestionRefusal::QuestionsNotUtf8 => f.write_str("questions: not UTF-8"),
            QuestionRefusal::QuestionsNotJson5 { reason } => {
                write!(f, "questions: not a JSON5 document: {reason}")
            }
            QuestionRefusal::QuestionsNotAList => f.write_str("questions: not a list"),
            QuestionRefusal::QuestionNotAnObject { index } => {
                write!(f, "question {index}: not an object")
            }
            QuestionRefusal::QuestionMemberMissing { index, member } => {
                write!(f, "question {index}: {member} is missing")
            }
            QuestionRefusal::QuestionMemberUnknown { index, member } => {
                write!(f, "question {index}: {member:?} is not a question member")
            }
            QuestionRefusal::QuestionMemberInvalid { index, member } => {
                let expected = words_of(member);
                write!(f, "question {index}: {member} must be {expected}")
            }
        }
    }
}

impl QuestionRefusal {
    /// The code the door returns when this is the first refusal: `Z_ENULL`
    /// for nothing to read, `Z_EPARSE` for text that could not be read, the
    /// split `Refusal::code` makes.
    fn code(&self) -> ZResult {
        match self {
            QuestionRefusal::NoQuestions => Z_ENULL,
            _ => Z_EPARSE,
        }
    }

    /// This refusal as a row: about no node and no config key.
    fn finding(&self) -> Finding {
        Finding::describing(self, None, vec![BlamedSite::at(None, None)])
    }
}

/// What a member of a question has to be, for the refusal that names it.
fn words_of(member: &str) -> &'static str {
    match member {
        "flow" => "\"ingress\" or \"egress\"",
        "message" => "one of upstream's nine access control message names",
        "key_expr" => "a key expression",
        "zid" => "a zid in lowercase hex, or null",
        "link_protocol" => "one of upstream's link protocol names",
        "interfaces" => "a list of interface names",
        _ => "a string, or null",
    }
}

/// The refusal of a member that holds the wrong type or a word outside its
/// set.
fn invalid<T>(index: usize, member: &'static str) -> Result<T, QuestionRefusal> {
    Err(QuestionRefusal::QuestionMemberInvalid { index, member })
}

/// One question, read.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Question {
    flow: AclFlow,
    message: AclMessage,
    key_expr: String,
    subject: PartialSubject,
}

/// Read the questions text: every question, or every refusal in it.
fn read_questions(text: &str) -> Result<Vec<Question>, Vec<QuestionRefusal>> {
    let doc = match json5::parse(text) {
        Ok(doc) => doc,
        Err(e) => {
            let reason = e.to_string();
            return Err(vec![QuestionRefusal::QuestionsNotJson5 { reason }]);
        }
    };
    let Json5Value::Array(items) = doc else {
        return Err(vec![QuestionRefusal::QuestionsNotAList]);
    };
    let mut questions = Vec::with_capacity(items.len());
    let mut refused = Vec::new();
    for (index, item) in items.iter().enumerate() {
        match read_question(index, item) {
            Ok(question) => questions.push(question),
            Err(refusal) => refused.push(refusal),
        }
    }
    if refused.is_empty() {
        Ok(questions)
    } else {
        Err(refused)
    }
}

/// Read one question at `index`.
fn read_question(index: usize, item: &Json5Value) -> Result<Question, QuestionRefusal> {
    let Json5Value::Object(members) = item else {
        return Err(QuestionRefusal::QuestionNotAnObject { index });
    };
    let (mut flow, mut message, mut key_expr) = (None, None, None);
    let mut subject = PartialSubject::UNKNOWN;
    for (name, value) in members {
        match name.as_str() {
            "flow" => match text_of(value).and_then(AclFlow::from_upstream_str) {
                Some(parsed) => flow = Some(parsed),
                None => return invalid(index, "flow"),
            },
            "message" => match text_of(value).and_then(AclMessage::from_upstream_str) {
                Some(parsed) => message = Some(parsed),
                None => return invalid(index, "message"),
            },
            "key_expr" => match text_of(value).filter(|t| validate_keyexpr(t).is_ok()) {
                Some(text) => key_expr = Some(String::from(text)),
                None => return invalid(index, "key_expr"),
            },
            "zid" => subject.zid = Attribute::Known(zid_of(index, value)?),
            "link_protocol" => match text_of(value).and_then(InterceptorLink::from_upstream_str) {
                Some(link) => subject.link_protocol = Attribute::Known(link),
                None => return invalid(index, "link_protocol"),
            },
            "interfaces" => subject.interfaces = Attribute::Known(interfaces_of(index, value)?),
            "username" => {
                let name = name_of(index, value, "username")?;
                subject.username = Attribute::Known(name);
            }
            "cert_common_name" => {
                let name = name_of(index, value, "cert_common_name")?;
                subject.cert_common_name = Attribute::Known(name);
            }
            other => {
                return Err(QuestionRefusal::QuestionMemberUnknown {
                    index,
                    member: String::from(other),
                })
            }
        }
    }
    let missing = |member: &'static str| QuestionRefusal::QuestionMemberMissing { index, member };
    Ok(Question {
        flow: flow.ok_or_else(|| missing("flow"))?,
        message: message.ok_or_else(|| missing("message"))?,
        key_expr: key_expr.ok_or_else(|| missing("key_expr"))?,
        subject,
    })
}

/// A JSON5 string's text, or `None` for any other value.
fn text_of(value: &Json5Value) -> Option<&str> {
    match value {
        Json5Value::String(text) => Some(text),
        _ => None,
    }
}

/// A question's `zid`: a zid, or `None` for a stated `null`.
fn zid_of(index: usize, value: &Json5Value) -> Result<Option<Zid>, QuestionRefusal> {
    match value {
        Json5Value::Null => Ok(None),
        Json5Value::String(hex) => match zenoh_hex_to_zid(hex) {
            Some(bytes) => Ok(Some(Zid::from_slice(&bytes))),
            None => invalid(index, "zid"),
        },
        _ => invalid(index, "zid"),
    }
}

/// A question's `interfaces`: a list of names, which may be empty.
fn interfaces_of(index: usize, value: &Json5Value) -> Result<Vec<String>, QuestionRefusal> {
    let Json5Value::Array(items) = value else {
        return invalid(index, "interfaces");
    };
    let mut names = Vec::with_capacity(items.len());
    for item in items {
        match text_of(item) {
            Some(name) => names.push(String::from(name)),
            None => return invalid(index, "interfaces"),
        }
    }
    Ok(names)
}

/// A name or a stated absence: `Some(name)` for a string, `None` for
/// `null`.
fn name_of(
    index: usize,
    value: &Json5Value,
    member: &'static str,
) -> Result<Option<String>, QuestionRefusal> {
    match value {
        Json5Value::String(text) => Ok(Some(text.clone())),
        Json5Value::Null => Ok(None),
        _ => invalid(index, member),
    }
}

/// What decided one answer, in the document's words: a document entry, the
/// default, or no enforcer at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decider {
    /// `access_control/enabled` is false, so no rule and no default applies.
    Disabled,
    /// The default permission.
    Default,
    /// The rule of `origins[i]`, the first compiled rule with that origin.
    Origin(usize),
}

/// The answers document's name, as its envelope writes it.
const ANSWERS_DOCUMENT: &str = "acl_verdicts";

/// The answers document's revision. A key renamed or removed moves it, and
/// the history the tests hold the document to records each shape.
const ANSWERS_REVISION: u32 = 1;

/// The answers document for `questions` under the compiled policy, or under
/// none when the access control is disabled.
fn answers_document(
    compiled: Option<&CompiledAcl>,
    default_permission: &str,
    questions: &[Question],
) -> String {
    let mut answers: Vec<AclJudgement<Decider>> = Vec::with_capacity(questions.len());
    match compiled {
        None => {
            let disabled = AclJudgement {
                permission: Some(Permission::Allow),
                decided_by: vec![Decider::Disabled],
                needs: Vec::new(),
                exhaustive: true,
            };
            answers.resize(questions.len(), disabled);
        }
        Some(compiled) => {
            // Rules one document entry fans out into (a zid each, a flow each)
            // are one answer to a caller that names entries.
            let origins = &compiled.origins;
            let mut canonical: Vec<usize> = Vec::with_capacity(origins.len());
            for origin in origins {
                let first = origins.iter().position(|o| o == origin);
                canonical.push(first.unwrap_or_default());
            }
            let policy = AclPolicy::new(compiled.config.clone());
            let key = |decision: AclDecision| match decision.decided_by {
                DecidedBy::Default => Decider::Default,
                DecidedBy::Rule(i) => Decider::Origin(canonical.get(i).copied().unwrap_or(i)),
            };
            for q in questions {
                let answer = policy.judge(&q.subject, q.flow, q.message, &q.key_expr, key);
                answers.push(answer);
            }
        }
    }

    let origins: &[AclRuleOrigin] = match compiled {
        Some(compiled) => &compiled.origins,
        None => &[],
    };
    let mut out = format!(
        "{{\"document\":{{\"name\":\"{ANSWERS_DOCUMENT}\",\"revision\":{ANSWERS_REVISION}}},\
         \"zenoh_layout\":"
    );
    escape_into(ZENOH_LAYOUT_VERSION, &mut out);
    out.push_str(",\"enabled\":");
    out.push_str(bool_word(compiled.is_some()));
    out.push_str(",\"default_permission\":");
    escape_into(default_permission, &mut out);
    out.push_str(",\"answers\":[");
    for (n, judgement) in answers.iter().enumerate() {
        if n > 0 {
            out.push(',');
        }
        out.push_str("{\"permission\":");
        match judgement.permission {
            Some(permission) => escape_into(permission.as_str(), &mut out),
            None => out.push_str("null"),
        }
        out.push_str(",\"decided_by\":[");
        for (m, decider) in judgement.decided_by.iter().enumerate() {
            if m > 0 {
                out.push(',');
            }
            write_decider(*decider, origins, &mut out);
        }
        out.push_str("],\"needs\":[");
        for (m, attribute) in judgement.needs.iter().enumerate() {
            if m > 0 {
                out.push(',');
            }
            escape_into(attribute.as_str(), &mut out);
        }
        out.push_str("],\"exhaustive\":");
        out.push_str(bool_word(judgement.exhaustive));
        out.push('}');
    }
    out.push_str("]}");
    out
}

/// `true` or `false`, as JSON spells them.
fn bool_word(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

/// One `decided_by` entry.
fn write_decider(decider: Decider, origins: &[AclRuleOrigin], out: &mut String) {
    match decider {
        Decider::Disabled => out.push_str("{\"kind\":\"disabled\"}"),
        Decider::Default => out.push_str("{\"kind\":\"default\"}"),
        Decider::Origin(i) => {
            let Some(origin) = origins.get(i) else {
                out.push_str("{\"kind\":\"rule\"}");
                return;
            };
            out.push_str("{\"kind\":\"rule\",\"rule\":");
            escape_into(&origin.rule, out);
            out.push_str(",\"subject\":");
            escape_into(&origin.subject, out);
            out.push_str(",\"policy\":");
            match &origin.policy {
                Some(id) => escape_into(id, out),
                None => out.push_str("null"),
            }
            out.push_str(",\"policy_index\":");
            out.push_str(&origin.policy_index.to_string());
            out.push('}');
        }
    }
}

/// What a config's access control decides for each of a list of messages.
///
/// `config` is read as `wz_capi_c_config_validate_rows` reads it, and its
/// `access_control` compiled as a node's enforcer compiles it. `questions_json`
/// is a NUL-terminated JSON5 list of questions; `wz_capi_c.h` gives their shape
/// and the answers document's.
///
/// `out_answers` and `out_refusals` are both written on every path that can
/// write them, a gravestone first. `Z_OK` with the answers document and an
/// empty verdict; otherwise the first refusal's code, an empty string and one
/// row per refusal.
///
/// # Safety
/// `config` null or a valid loaned config; `questions_json` null or a
/// NUL-terminated string; `out_answers` and `out_refusals` null or valid and
/// writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_acl_verdicts(
    config: *const z_loaned_config_t,
    questions_json: *const c_char,
    out_answers: *mut z_owned_string_t,
    out_refusals: *mut wz_capi_c_owned_config_verdict_t,
) -> ZResult {
    guarded(|| {
        if !out_answers.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *out_answers = null_string() };
        }
        if !out_refusals.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *out_refusals = wz_capi_c_owned_config_verdict_t::null_value() };
        }
        if out_answers.is_null() || out_refusals.is_null() {
            return Z_ENULL;
        }

        let mut findings: Vec<Finding> = Vec::new();
        let mut code = Z_OK;
        let mut refuse = |finding: Finding, refusal_code: ZResult| {
            if code == Z_OK {
                code = refusal_code;
            }
            findings.push(finding);
        };

        // SAFETY: the caller's contract.
        let compiled = match unsafe { node_config(config) } {
            Err(refusal) => {
                refuse(refusal.finding(None), refusal.code());
                None
            }
            Ok(node) => match acl_config_with_origins(&node.access_control) {
                Err(why) => {
                    refuse(why.finding(None), Z_EPARSE);
                    None
                }
                Ok(compiled) => Some((compiled, node.access_control.default_permission)),
            },
        };

        let questions = if questions_json.is_null() {
            let refusal = QuestionRefusal::NoQuestions;
            refuse(refusal.finding(), refusal.code());
            None
        } else {
            // SAFETY: a NUL-terminated string, by the caller's contract.
            match unsafe { CStr::from_ptr(questions_json) }.to_str() {
                Err(_) => {
                    let refusal = QuestionRefusal::QuestionsNotUtf8;
                    refuse(refusal.finding(), refusal.code());
                    None
                }
                Ok(text) => match read_questions(text) {
                    Ok(questions) => Some(questions),
                    Err(refusals) => {
                        for refusal in &refusals {
                            refuse(refusal.finding(), refusal.code());
                        }
                        None
                    }
                },
            }
        };

        let (Some((compiled, default_permission)), Some(questions)) = (compiled, questions) else {
            // SAFETY: checked non-null above.
            return unsafe { publish(out_refusals, findings, code) };
        };
        let document = answers_document(compiled.as_ref(), &default_permission, &questions);
        // SAFETY: checked non-null above.
        unsafe { *out_answers = owned_string_from(document.as_bytes()) };
        // SAFETY: checked non-null above.
        unsafe { publish(out_refusals, Vec::new(), Z_OK) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;

    use wz_capture::doc_revision::{audit, key_set, DocumentShape};

    use crate::abi::z_view_string_t;
    use crate::config::z_config_loan;
    use crate::config_verdict::tests::{config_of, take_text};
    use crate::config_verdict_rows::{
        wz_capi_c_config_validate_rows, wz_capi_c_config_verdict_drop,
        wz_capi_c_config_verdict_len, wz_capi_c_config_verdict_loan,
        wz_capi_c_config_verdict_row_key, wz_capi_c_config_verdict_row_message,
        wz_capi_c_config_verdict_row_variant, wz_capi_c_internal_config_verdict_check,
        wz_capi_c_moved_config_verdict_t,
    };

    /// One refusal row as a C caller reads it.
    #[derive(Debug, PartialEq)]
    struct Row {
        variant: String,
        message: String,
        key: Option<String>,
    }

    unsafe fn empty_view() -> z_view_string_t {
        // SAFETY: a zeroed view is a placeholder every reader below overwrites
        // before anything reads it.
        unsafe { std::mem::zeroed() }
    }

    unsafe fn view_text(view: &z_view_string_t) -> String {
        // SAFETY: a view this crate wrote over live text `len` bytes long.
        let bytes = unsafe { std::slice::from_raw_parts(view.ptr, view.len) };
        String::from_utf8(bytes.to_vec()).expect("wz emits UTF-8")
    }

    /// Every row of `verdict`, then the verdict dropped.
    unsafe fn take_rows(verdict: &mut wz_capi_c_owned_config_verdict_t) -> Vec<Row> {
        // SAFETY: a live owned verdict or its gravestone.
        let loaned = unsafe { wz_capi_c_config_verdict_loan(verdict) };
        // SAFETY: as above.
        let len = unsafe { wz_capi_c_config_verdict_len(loaned) };
        let rows = (0..len)
            .map(|index| {
                // SAFETY: `index` is below the length the verdict reported.
                unsafe {
                    let mut variant = empty_view();
                    let mut message = empty_view();
                    let mut key = empty_view();
                    assert_eq!(
                        wz_capi_c_config_verdict_row_variant(loaned, index, &mut variant),
                        Z_OK
                    );
                    assert_eq!(
                        wz_capi_c_config_verdict_row_message(loaned, index, &mut message),
                        Z_OK
                    );
                    let has_key = wz_capi_c_config_verdict_row_key(loaned, index, &mut key);
                    Row {
                        variant: view_text(&variant),
                        message: view_text(&message),
                        key: has_key.then(|| view_text(&key)),
                    }
                }
            })
            .collect();
        // SAFETY: a live owned verdict; the moved shape is the same slot.
        unsafe {
            wz_capi_c_config_verdict_drop(
                (verdict as *mut wz_capi_c_owned_config_verdict_t)
                    .cast::<wz_capi_c_moved_config_verdict_t>(),
            )
        };
        rows
    }

    /// Ask the door as a C caller does: the code, the answers text and the
    /// refusal rows, both outputs freed.
    unsafe fn ask(
        entries: &[(&str, &str)],
        questions: Option<&str>,
    ) -> (ZResult, String, Vec<Row>) {
        // SAFETY: the caller's fixture.
        let cfg = unsafe { config_of(entries) };
        let questions = questions.map(|q| CString::new(q).expect("no NUL"));
        // SAFETY: zeroed owned slots are this ABI's gravestones.
        let mut answers: z_owned_string_t = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let mut refusals: wz_capi_c_owned_config_verdict_t = unsafe { std::mem::zeroed() };
        // SAFETY: a live config, a NUL-terminated string or null, and two
        // writable slots.
        let rc = unsafe {
            wz_capi_c_config_acl_verdicts(
                z_config_loan(&cfg),
                questions.as_ref().map_or(std::ptr::null(), |q| q.as_ptr()),
                &mut answers,
                &mut refusals,
            )
        };
        // SAFETY: the door wrote a verdict on every path that reaches here.
        assert!(unsafe { wz_capi_c_internal_config_verdict_check(&refusals) });
        // SAFETY: both slots hold what the door wrote.
        let (text, rows) = unsafe { (take_text(&mut answers), take_rows(&mut refusals)) };
        (rc, text, rows)
    }

    /// A policy with an allow, a deny narrowed by username, and an allow the
    /// deny is checked before, under a deny default.
    const POLICY: &[(&str, &str)] = &[
        ("access_control/enabled", "true"),
        ("access_control/default_permission", "\"deny\""),
        (
            "access_control/rules",
            r#"[ { id: "allow_metrics", key_exprs: ["metrics/**"], messages: ["put"],
                   flows: ["ingress"], permission: "allow" },
                 { id: "deny_admin", key_exprs: ["admin/**"], messages: ["put"],
                   permission: "deny" },
                 { id: "allow_admin", key_exprs: ["admin/**"], messages: ["put"],
                   permission: "allow" } ]"#,
        ),
        (
            "access_control/subjects",
            r#"[ { id: "everyone" }, { id: "alice", usernames: ["alice"] } ]"#,
        ),
        (
            "access_control/policies",
            r#"[ { id: "open_metrics", rules: ["allow_metrics"], subjects: ["everyone"] },
                 { rules: ["deny_admin"], subjects: ["alice"] },
                 { id: "ops", rules: ["allow_admin"], subjects: ["everyone"] } ]"#,
        ),
    ];

    /// One `decided_by` entry naming a rule; `policy` is the JSON value.
    fn rule_entry(rule: &str, subject: &str, policy: &str, index: usize) -> String {
        let head = format!(r#"{{"kind":"rule","rule":"{rule}","subject":"{subject}""#);
        format!(r#"{head},"policy":{policy},"policy_index":{index}}}"#)
    }

    /// The answers document around `body`: its envelope and the layout it
    /// read, then the members `body` writes.
    fn document(body: &str) -> String {
        let head = r#"{"document":{"name":"acl_verdicts","revision":1}"#;
        format!(r#"{head},"zenoh_layout":"{ZENOH_LAYOUT_VERSION}",{body}}}"#)
    }

    /// One answer, as the door writes it; `permission` is the JSON value.
    fn answer(permission: &str, decided_by: &[&str], needs: &[&str]) -> String {
        let decided_by = decided_by.join(",");
        let needs: Vec<String> = needs.iter().map(|n| format!("\"{n}\"")).collect();
        let needs = needs.join(",");
        let head = format!(r#"{{"permission":{permission},"decided_by":[{decided_by}]"#);
        format!(r#"{head},"needs":[{needs}],"exhaustive":true}}"#)
    }

    /// The four answers the door exists for: an allow and a deny a rule
    /// decided, a deny the default decided, and an answer that waits on an
    /// attribute the question did not state; each names the document entries
    /// that decided it.
    #[test]
    fn each_question_gets_the_verdict_and_what_decided_it() {
        let questions = r#"[
            { flow: "ingress", message: "put", key_expr: "metrics/cpu" },
            { flow: "egress", message: "put", key_expr: "metrics/cpu" },
            { flow: "ingress", message: "put", key_expr: "admin/cfg", username: "alice" },
            { flow: "ingress", message: "put", key_expr: "admin/cfg" },
            { flow: "ingress", message: "put", key_expr: "admin/cfg", username: null }
        ]"#;
        // SAFETY: the fixtures and the door are this test's own.
        let (rc, text, rows) = unsafe { ask(POLICY, Some(questions)) };
        assert_eq!(rc, Z_OK);
        assert_eq!(rows, Vec::new(), "nothing refused");
        let allow_metrics = rule_entry("allow_metrics", "everyone", "\"open_metrics\"", 0);
        let deny_admin = rule_entry("deny_admin", "alice", "null", 1);
        let allow_admin = rule_entry("allow_admin", "everyone", "\"ops\"", 2);
        let by_default = r#"{"kind":"default"}"#;
        let split = answer(
            "null",
            &[deny_admin.as_str(), allow_admin.as_str()],
            &["username"],
        );
        let all = [
            answer("\"allow\"", &[allow_metrics.as_str()], &[]),
            answer("\"deny\"", &[by_default], &[]),
            answer("\"deny\"", &[deny_admin.as_str()], &[]),
            split,
            answer("\"allow\"", &[allow_admin.as_str()], &[]),
        ]
        .join(",");
        let want = document(&format!(
            r#""enabled":true,"default_permission":"deny","answers":[{all}]"#
        ));
        assert_eq!(text, want);
        assert!(json5::parse(&text).is_ok(), "the document is JSON");
    }

    /// `enabled: false` installs no enforcer upstream, so nothing is refused
    /// and no default applies; the answer says so rather than reading the
    /// rules.
    #[test]
    fn a_disabled_access_control_admits_everything_and_says_why() {
        let mut entries: Vec<(&str, &str)> = POLICY.to_vec();
        entries[0] = ("access_control/enabled", "false");
        let questions = r#"[ { flow: "ingress", message: "put", key_expr: "admin/cfg",
                               username: "alice" } ]"#;
        // SAFETY: the fixtures and the door are this test's own.
        let (rc, text, rows) = unsafe { ask(&entries, Some(questions)) };
        assert_eq!(rc, Z_OK);
        assert!(rows.is_empty());
        let one = answer("\"allow\"", &[r#"{"kind":"disabled"}"#], &[]);
        let want = document(&format!(
            r#""enabled":false,"default_permission":"deny","answers":[{one}]"#
        ));
        assert_eq!(text, want);
    }

    /// A config the reader refuses is refused here with the code and the row
    /// `wz_capi_c_config_validate_rows` gives it, and a bad question in the same
    /// call is reported beside it.
    #[test]
    fn an_unreadable_config_is_refused_as_the_validation_door_refuses_it() {
        let entries = [("mode", "\"gateway\"")];
        // SAFETY: the fixtures and the doors are this test's own.
        let (rc, text, rows) = unsafe {
            ask(
                &entries,
                Some(r#"[ { flow: "sideways", message: "put", key_expr: "a" } ]"#),
            )
        };
        assert_eq!(rc, Z_EPARSE);
        assert_eq!(text, "", "no answer while anything is refused");
        assert_eq!(rows.len(), 2, "{rows:?}");

        // SAFETY: as above.
        let (validate_rc, validate_rows) = unsafe {
            let cfg = config_of(&entries);
            let mut out: wz_capi_c_owned_config_verdict_t = std::mem::zeroed();
            let rc = wz_capi_c_config_validate_rows(z_config_loan(&cfg), &mut out);
            (rc, take_rows(&mut out))
        };
        assert_eq!(rc, validate_rc);
        assert_eq!(
            rows[0], validate_rows[0],
            "the same row as the validation door"
        );
        assert_eq!(rows[0].variant, "UnknownMode");
        assert_eq!(rows[0].key.as_deref(), Some("mode"));

        assert_eq!(rows[1].variant, "QuestionMemberInvalid");
        assert_eq!(rows[1].key, None);
        assert!(
            rows[1].message.starts_with("question 0: flow"),
            "{}",
            rows[1].message
        );
    }

    /// An `access_control` subtree that reads and cannot become a policy is a
    /// row blaming the list at fault, as a node would refuse to open on it.
    #[test]
    fn an_access_control_that_cannot_compile_is_refused_by_its_list() {
        let mut entries: Vec<(&str, &str)> = POLICY.to_vec();
        entries[4].1 = r#"[ { rules: ["ghost"], subjects: ["everyone"] } ]"#;
        // SAFETY: the fixtures and the door are this test's own.
        let (rc, text, rows) = unsafe {
            ask(
                &entries,
                Some(r#"[ { flow: "ingress", message: "put", key_expr: "a" } ]"#),
            )
        };
        assert_eq!(rc, Z_EPARSE);
        assert_eq!(text, "");
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].variant, "UnknownRule");
        assert_eq!(rows[0].key.as_deref(), Some("access_control/policies"));
    }

    /// Every question that cannot be read is a row naming its position, and
    /// none is answered while one is refused.
    #[test]
    fn every_unreadable_question_is_refused_by_position() {
        let cases: &[(&str, &[&str])] = &[
            ("{ flow: \"ingress\" }", &["QuestionsNotAList"]),
            ("[ { flow: ", &["QuestionsNotJson5"]),
            (
                r#"[ 5, { flow: "ingress", message: "put" } ]"#,
                &["QuestionNotAnObject", "QuestionMemberMissing"],
            ),
            (
                r#"[ { flow: "ingress", message: "put", key_expr: "a", colour: "red" } ]"#,
                &["QuestionMemberUnknown"],
            ),
            (
                r#"[ { flow: "ingress", message: "publish", key_expr: "a" } ]"#,
                &["QuestionMemberInvalid"],
            ),
            (
                r#"[ { flow: "ingress", message: "put", key_expr: "a//b" } ]"#,
                &["QuestionMemberInvalid"],
            ),
            (
                r#"[ { flow: "ingress", message: "put", key_expr: "a", zid: "ABC" } ]"#,
                &["QuestionMemberInvalid"],
            ),
            (
                r#"[ { flow: "ingress", message: "put", key_expr: "a", link_protocol: null } ]"#,
                &["QuestionMemberInvalid"],
            ),
            (
                r#"[ { flow: "ingress", message: "put", key_expr: "a", interfaces: [1] } ]"#,
                &["QuestionMemberInvalid"],
            ),
        ];
        for (questions, variants) in cases {
            // SAFETY: the fixtures and the door are this test's own.
            let (rc, text, rows) = unsafe { ask(POLICY, Some(*questions)) };
            assert_eq!(rc, Z_EPARSE, "{questions}");
            assert_eq!(text, "", "{questions}");
            let got: Vec<&str> = rows.iter().map(|r| r.variant.as_str()).collect();
            assert_eq!(&got, variants, "{questions}");
            assert!(rows.iter().all(|r| r.key.is_none()), "{questions}");
        }

        // The well-formed spellings of every optional member are accepted.
        let full = r#"[ { flow: "egress", message: "liveliness_token", key_expr: "a/*",
                          zid: "1a2b", link_protocol: "unixsock-stream", interfaces: [],
                          username: "bob", cert_common_name: null } ]"#;
        // SAFETY: as above.
        let (rc, _, rows) = unsafe { ask(POLICY, Some(full)) };
        assert_eq!(rc, Z_OK, "{rows:?}");
    }

    /// No questions is `Z_ENULL` with a row, and an output with nowhere to
    /// write is `Z_ENULL` with a gravestone in the other one.
    #[test]
    fn missing_arguments_are_z_enull() {
        // SAFETY: the fixtures and the door are this test's own.
        let (rc, text, rows) = unsafe { ask(POLICY, None) };
        assert_eq!(rc, Z_ENULL);
        assert_eq!(text, "");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].variant, "NoQuestions");

        let questions = CString::new("[]").expect("no NUL");
        // SAFETY: a null output slot is the case under test; the other is
        // writable.
        unsafe {
            let cfg = config_of(POLICY);
            let mut refusals: wz_capi_c_owned_config_verdict_t = std::mem::zeroed();
            let rc = wz_capi_c_config_acl_verdicts(
                z_config_loan(&cfg),
                questions.as_ptr(),
                std::ptr::null_mut(),
                &mut refusals,
            );
            assert_eq!(rc, Z_ENULL);
            assert!(!wz_capi_c_internal_config_verdict_check(&refusals));
        }

        // An empty list is a question set with no answers, not a refusal.
        // SAFETY: as above.
        let (rc, text, rows) = unsafe { ask(POLICY, Some("[]")) };
        assert_eq!(rc, Z_OK);
        assert!(rows.is_empty());
        assert_eq!(
            text,
            document(r#""enabled":true,"default_permission":"deny","answers":[]"#)
        );
    }

    /// Every shape the answers document has been written in, oldest first.
    const ANSWERS_HISTORY: &[DocumentShape] = &[DocumentShape {
        document: ANSWERS_DOCUMENT,
        revision: 1,
        keys: &[
            "answers",
            "decided_by",
            "default_permission",
            "document",
            "enabled",
            "exhaustive",
            "kind",
            "name",
            "needs",
            "permission",
            "policy",
            "policy_index",
            "revision",
            "rule",
            "subject",
            "zenoh_layout",
        ],
        retiring: &[],
        families: &[],
        planes: &[],
        carries: &[],
    }];

    /// THE ANSWERS DOCUMENT SAYS WHICH IT IS AND WHICH LAYOUT IT READ: it opens
    /// with its name and revision, then `zenoh_layout`, the one constant the
    /// layout is stated by; and its key set over every shape it is written in
    /// (a rule, the default and a disabled enforcer deciding, an empty list) is
    /// the newest of the history, which keeps the rules a rename is made by.
    #[test]
    fn the_answers_document_names_its_revision_and_the_zenoh_layout_it_read() {
        audit(ANSWERS_HISTORY).expect("the history keeps the revision rules");
        let newest = ANSWERS_HISTORY.last().expect("a revision");
        assert_eq!(newest.revision, ANSWERS_REVISION);

        let mut disabled: Vec<(&str, &str)> = POLICY.to_vec();
        disabled[0] = ("access_control/enabled", "false");
        let question = r#"[ { flow: "ingress", message: "put", key_expr: "admin/cfg",
                              username: "alice" },
                            { flow: "egress", message: "put", key_expr: "metrics/cpu" } ]"#;
        let mut union: Vec<String> = Vec::new();
        for (entries, questions) in [
            (POLICY, question),
            (disabled.as_slice(), question),
            (POLICY, "[]"),
        ] {
            // SAFETY: the fixtures and the door are this test's own.
            let (rc, text, rows) = unsafe { ask(entries, Some(questions)) };
            assert_eq!(rc, Z_OK, "{rows:?}");
            let (name, revision) = (ANSWERS_DOCUMENT, ANSWERS_REVISION);
            let head = format!(
                r#"{{"document":{{"name":"{name}","revision":{revision}}},"zenoh_layout":"#
            );
            assert!(text.starts_with(&head), "{text}");
            assert!(
                text.contains(&format!(r#""zenoh_layout":"{ZENOH_LAYOUT_VERSION}""#)),
                "{text}"
            );
            union.extend(key_set(&text).into_iter().map(String::from));
        }
        union.sort_unstable();
        union.dedup();
        let pinned: Vec<String> = newest.keys.iter().map(|k| String::from(*k)).collect();
        assert_eq!(
            union, pinned,
            "the key set moved: append a revision to ANSWERS_HISTORY and move \
             ANSWERS_REVISION, announcing a key that goes away first"
        );
    }
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The roles of a session's `driver`, one module each.
//!
//! A module holds one `pub(crate) static ROLE: RoleDef` and the function that
//! plays it, and nothing else: the key rules, the refusal sentences, the hold
//! (`after_ms`) and the wait for Established are written once in the parent. To
//! add a role, add its module here and its line to [`ROLES`]; the order of
//! [`ROLES`] is the order the refusal of an unknown role lists them in.
//!
//! A role that sits behind a build feature declares it with `RoleDef::gated` and
//! gates its function body with the same `cfg`, so a build without the feature
//! compiles and refuses the role by key path (`BuildCapabilities` in
//! `crate::sessions`).

pub(crate) mod advanced_publish;
pub(crate) mod advanced_subscribe;
pub(crate) mod answer;
pub(crate) mod delete;
pub(crate) mod forward;
pub(crate) mod get;
pub(crate) mod group_member;
pub(crate) mod group_view;
pub(crate) mod liveliness_get;
pub(crate) mod liveliness_subscribe;
pub(crate) mod liveliness_token;
pub(crate) mod publish;
pub(crate) mod pull;
pub(crate) mod put_once;
pub(crate) mod query;
pub(crate) mod replay;
pub(crate) mod scout;
pub(crate) mod subscribe;

use super::RoleDef;

/// Every role the document language has, in listing order.
pub(crate) static ROLES: &[&RoleDef] = &[
    &publish::ROLE,
    &put_once::ROLE,
    &delete::ROLE,
    &subscribe::ROLE,
    &get::ROLE,
    &answer::ROLE,
    &query::ROLE,
    &scout::ROLE,
    &advanced_publish::ROLE,
    &advanced_subscribe::ROLE,
    &liveliness_token::ROLE,
    &liveliness_subscribe::ROLE,
    &liveliness_get::ROLE,
    &pull::ROLE,
    &group_member::ROLE,
    &group_view::ROLE,
    &forward::ROLE,
    &replay::ROLE,
];

/// How many roles THIS build plays: those whose `available` is on.
#[allow(dead_code)]
const fn available_count() -> usize {
    let mut count = 0;
    let mut i = 0;
    while i < ROLES.len() {
        if ROLES[i].available {
            count += 1;
        }
        i += 1;
    }
    count
}

#[allow(dead_code)]
const AVAILABLE_COUNT: usize = available_count();

/// The words of the roles THIS build plays, in [`ROLES`] order, computed at compile time from the
/// table itself. The build's facts note carries it (`crate::surface`), so a tool that describes the
/// executable without running it reads the list from the file and keeps no second copy of the table.
#[allow(dead_code)]
pub(crate) const AVAILABLE_WORDS: [&str; AVAILABLE_COUNT] = {
    let mut words = [""; AVAILABLE_COUNT];
    let mut i = 0;
    let mut n = 0;
    while i < ROLES.len() {
        if ROLES[i].available {
            words[n] = ROLES[i].word;
            n += 1;
        }
        i += 1;
    }
    words
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_available_words_are_the_roles_the_table_marks_available() {
        let at_run_time: Vec<&str> = ROLES
            .iter()
            .filter(|r| r.available)
            .map(|r| r.word)
            .collect();
        assert_eq!(AVAILABLE_WORDS.to_vec(), at_run_time);
        assert!(
            !AVAILABLE_WORDS.is_empty(),
            "a build plays at least the ungated roles"
        );
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
];

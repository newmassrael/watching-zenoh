// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Test fixture builders for the four `wz-session-core::declare/*`
//! registries. Consumed exclusively by the AP-side
//! `#[cfg(test)] mod tests` blocks in
//! `wz-runtime-tokio/src/declare/{subscriber, queryable, liveliness,
//! liveliness_subscriber, cross_tests}.rs`.
//!
//! R311dr-sibling entry — the body migrated unchanged from
//! `wz-session-core/src/declare/test_helpers.rs` (intermediate R311dr
//! home) to this sibling crate. The intermediate feature-gated module
//! reintroduced the production-crate-feature-flag anti-pattern that
//! R71 already ratified out (see `wz-runtime-tokio-test-support`
//! header for the original R71 rationale). This crate restores R71
//! shape: production wz-session-core builds carry zero test-only
//! code paths regardless of workspace-level Cargo feature unification.
//!
//! Why a second sibling at this tier (not folded into
//! `wz-runtime-tokio-test-support`): the declare/* fixture builders
//! reach only wz-codecs types, while the R71 sibling reaches the
//! full Lua + tokio + Session surface. Folding would inflate the
//! transitive dev-dep graph for every declare/* test mod
//! unnecessarily, breaking the production-tier separation
//! (wz-codecs + wz-session-core sit a tier below wz-runtime-tokio).

use wz_codecs::decl_queryable::DeclQueryable;
use wz_codecs::decl_subscriber::DeclSubscriber;
use wz_codecs::decl_token::DeclToken;
use wz_codecs::declare::{Declare, DeclareVariant};
use wz_codecs::undecl_queryable::UndeclQueryable;
use wz_codecs::undecl_subscriber::UndeclSubscriber;
use wz_codecs::undecl_token::UndeclToken;
use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
use wz_codecs::wireexpr_local::WireexprLocal;
use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

pub fn decl_subscriber(id: u64, mapping_id: u64, suffix: Option<&str>) -> DeclSubscriber {
    let suffix_owned = suffix.map(str::to_string);
    let suffix_len = suffix.map(|s| s.len() as u64);
    let keyexpr = Wireexpr {
        body: WireexprVariant::WireexprLocal(WireexprLocal {
            id: mapping_id,
            suffix_len,
            suffix: suffix_owned,
        }),
    };
    DeclSubscriber {
        id,
        keyexpr,
        ..DeclSubscriber::default()
    }
}

pub fn decl_subscriber_nonlocal(id: u64, mapping_id: u64, suffix: Option<&str>) -> DeclSubscriber {
    let suffix_owned = suffix.map(str::to_string);
    let suffix_len = suffix.map(|s| s.len() as u64);
    let keyexpr = Wireexpr {
        body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
            id: mapping_id,
            suffix_len,
            suffix: suffix_owned,
        }),
    };
    DeclSubscriber {
        id,
        keyexpr,
        ..DeclSubscriber::default()
    }
}

pub fn undecl_subscriber(id: u64) -> UndeclSubscriber {
    UndeclSubscriber {
        id,
        ..UndeclSubscriber::default()
    }
}

pub fn decl_queryable(id: u64, mapping_id: u64, suffix: Option<&str>) -> DeclQueryable {
    let suffix_owned = suffix.map(str::to_string);
    let suffix_len = suffix.map(|s| s.len() as u64);
    let keyexpr = Wireexpr {
        body: WireexprVariant::WireexprLocal(WireexprLocal {
            id: mapping_id,
            suffix_len,
            suffix: suffix_owned,
        }),
    };
    DeclQueryable {
        id,
        keyexpr,
        ..DeclQueryable::default()
    }
}

pub fn undecl_queryable(id: u64) -> UndeclQueryable {
    UndeclQueryable {
        id,
        ..UndeclQueryable::default()
    }
}

pub fn decl_token(id: u64, mapping_id: u64, suffix: Option<&str>) -> DeclToken {
    let suffix_owned = suffix.map(str::to_string);
    let suffix_len = suffix.map(|s| s.len() as u64);
    let keyexpr = Wireexpr {
        body: WireexprVariant::WireexprLocal(WireexprLocal {
            id: mapping_id,
            suffix_len,
            suffix: suffix_owned,
        }),
    };
    DeclToken {
        id,
        keyexpr,
        ..DeclToken::default()
    }
}

pub fn undecl_token(id: u64) -> UndeclToken {
    UndeclToken {
        id,
        ..UndeclToken::default()
    }
}

pub fn declare_envelope_decl_subscriber(d: DeclSubscriber) -> Declare {
    Declare {
        body: DeclareVariant::CodecZenohDeclSubscriber(d),
        ..Declare::default()
    }
}

pub fn declare_envelope_undecl_subscriber(u: UndeclSubscriber) -> Declare {
    Declare {
        body: DeclareVariant::CodecZenohUndeclSubscriber(u),
        ..Declare::default()
    }
}

pub fn declare_envelope_decl_queryable(d: DeclQueryable) -> Declare {
    Declare {
        body: DeclareVariant::CodecZenohDeclQueryable(d),
        ..Declare::default()
    }
}

pub fn declare_envelope_undecl_queryable(u: UndeclQueryable) -> Declare {
    Declare {
        body: DeclareVariant::CodecZenohUndeclQueryable(u),
        ..Declare::default()
    }
}

pub fn declare_envelope_decl_token(d: DeclToken) -> Declare {
    Declare {
        body: DeclareVariant::CodecZenohDeclToken(d),
        ..Declare::default()
    }
}

pub fn declare_envelope_undecl_token(u: UndeclToken) -> Declare {
    Declare {
        body: DeclareVariant::CodecZenohUndeclToken(u),
        ..Declare::default()
    }
}

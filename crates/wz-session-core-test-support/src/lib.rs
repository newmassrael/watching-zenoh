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
//!
//! SCE borrowed-view + into_owned absorb: the registries store decoded
//! messages as the lifetime-free `*Owned` codec mirrors
//! (`NetworkMessage::Declare(Box<DeclareOwned>)`), so the `Decl*`
//! fixtures return the owned form. They are built through the borrowed
//! zero-copy `Foo<'a>` view (which derives `Default`) and projected via
//! `into_owned()`; the borrow is over the caller's `suffix: &str`, lives
//! only inside the builder, and is consumed by `into_owned`. The
//! `Undecl*` bodies carry no borrowed field, so SCE emits no `*Owned`
//! mirror for them — they are already lifetime-free and used directly.
//! `DeclareOwned` has no `Default`, so the envelope builders set its
//! inert framing fields (`header`/`interest_id`/`extensions`)
//! explicitly; the registries dispatch on `body` and never inspect them.

use wz_codecs::decl_queryable::{DeclQueryable, DeclQueryableOwned};
use wz_codecs::decl_subscriber::{DeclSubscriber, DeclSubscriberOwned};
use wz_codecs::decl_token::{DeclToken, DeclTokenOwned};
use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};
use wz_codecs::undecl_queryable::UndeclQueryable;
use wz_codecs::undecl_subscriber::UndeclSubscriber;
use wz_codecs::undecl_token::UndeclToken;
use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
use wz_codecs::wireexpr_local::WireexprLocal;
use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

pub fn decl_subscriber(id: u64, mapping_id: u64, suffix: Option<&str>) -> DeclSubscriberOwned {
    let suffix_len = suffix.map(|s| s.len() as u64);
    let keyexpr = Wireexpr {
        body: WireexprVariant::WireexprLocal(WireexprLocal {
            id: mapping_id,
            suffix_len,
            suffix,
        }),
    };
    DeclSubscriber {
        id,
        keyexpr,
        ..DeclSubscriber::default()
    }
    .into_owned()
}

pub fn decl_subscriber_nonlocal(
    id: u64,
    mapping_id: u64,
    suffix: Option<&str>,
) -> DeclSubscriberOwned {
    let suffix_len = suffix.map(|s| s.len() as u64);
    let keyexpr = Wireexpr {
        body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
            id: mapping_id,
            suffix_len,
            suffix,
        }),
    };
    DeclSubscriber {
        id,
        keyexpr,
        ..DeclSubscriber::default()
    }
    .into_owned()
}

pub fn undecl_subscriber(id: u64) -> UndeclSubscriber {
    UndeclSubscriber {
        id,
        ..UndeclSubscriber::default()
    }
}

pub fn decl_queryable(id: u64, mapping_id: u64, suffix: Option<&str>) -> DeclQueryableOwned {
    let suffix_len = suffix.map(|s| s.len() as u64);
    let keyexpr = Wireexpr {
        body: WireexprVariant::WireexprLocal(WireexprLocal {
            id: mapping_id,
            suffix_len,
            suffix,
        }),
    };
    DeclQueryable {
        id,
        keyexpr,
        ..DeclQueryable::default()
    }
    .into_owned()
}

pub fn undecl_queryable(id: u64) -> UndeclQueryable {
    UndeclQueryable {
        id,
        ..UndeclQueryable::default()
    }
}

pub fn decl_token(id: u64, mapping_id: u64, suffix: Option<&str>) -> DeclTokenOwned {
    let suffix_len = suffix.map(|s| s.len() as u64);
    let keyexpr = Wireexpr {
        body: WireexprVariant::WireexprLocal(WireexprLocal {
            id: mapping_id,
            suffix_len,
            suffix,
        }),
    };
    DeclToken {
        id,
        keyexpr,
        ..DeclToken::default()
    }
    .into_owned()
}

pub fn undecl_token(id: u64) -> UndeclToken {
    UndeclToken {
        id,
        ..UndeclToken::default()
    }
}

pub fn declare_envelope_decl_subscriber(d: DeclSubscriberOwned) -> DeclareOwned {
    DeclareOwned {
        header: 0,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclSubscriber(d),
    }
}

pub fn declare_envelope_undecl_subscriber(u: UndeclSubscriber) -> DeclareOwned {
    DeclareOwned {
        header: 0,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohUndeclSubscriber(u),
    }
}

pub fn declare_envelope_decl_queryable(d: DeclQueryableOwned) -> DeclareOwned {
    DeclareOwned {
        header: 0,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclQueryable(d),
    }
}

pub fn declare_envelope_undecl_queryable(u: UndeclQueryable) -> DeclareOwned {
    DeclareOwned {
        header: 0,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohUndeclQueryable(u),
    }
}

pub fn declare_envelope_decl_token(d: DeclTokenOwned) -> DeclareOwned {
    DeclareOwned {
        header: 0,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclToken(d),
    }
}

pub fn declare_envelope_undecl_token(u: UndeclToken) -> DeclareOwned {
    DeclareOwned {
        header: 0,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohUndeclToken(u),
    }
}

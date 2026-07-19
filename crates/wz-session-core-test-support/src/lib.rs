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

use wz_codecs::decl_final::DeclFinal;
use wz_codecs::decl_kexpr::{DeclKexpr, DeclKexprOwned};
use wz_codecs::decl_queryable::{DeclQueryable, DeclQueryableOwned};
use wz_codecs::decl_subscriber::{DeclSubscriber, DeclSubscriberOwned};
use wz_codecs::decl_token::{DeclToken, DeclTokenOwned};
use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};
use wz_codecs::interest::{Interest, InterestOwned};
use wz_codecs::interest_body::InterestBody;
use wz_codecs::undecl_kexpr::UndeclKexpr;
use wz_codecs::undecl_queryable::{UndeclQueryable, UndeclQueryableOwned};
use wz_codecs::undecl_subscriber::{UndeclSubscriber, UndeclSubscriberOwned};
use wz_codecs::undecl_token::{UndeclToken, UndeclTokenOwned};
use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
use wz_codecs::wireexpr_local::WireexprLocal;
use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

pub fn decl_kexpr(id: u64, keyexpr: &str) -> DeclKexprOwned {
    let keyexpr_wire = Wireexpr {
        body: WireexprVariant::WireexprLocal(WireexprLocal {
            id: 0,
            suffix_len: Some(keyexpr.len() as u64),
            suffix: Some(keyexpr),
        }),
    };
    DeclKexpr {
        id,
        keyexpr: keyexpr_wire,
        ..DeclKexpr::default()
    }
    .try_into_owned()
    .unwrap()
}

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
    .try_into_owned()
    .unwrap()
}

/// A subscriber `Interest` mirroring a zenoh-pico publisher's write-filter
/// interest (`net/filtering.c` `_z_write_filter_create`): the body carries the
/// `su` (subscribers) and `ke` (keyexpr-present) bits over a literal `keyexpr`,
/// the envelope carries the `c` (CURRENT) and `f` (FUTURE) bits, and the body
/// `ag` (AGGREGATE) bit is set per the caller. wz never SENDS one (a wz publisher
/// puts without a write filter), so this fixture exists only to drive the
/// router's inbound-interest reply path (`RouteTable::record_interest`) in tests.
/// The `c` and `f` bits also gate body presence in the wire codec (Interest
/// header 0x20 / 0x40), so setting them keeps the owned form self-consistent with
/// a real decoded interest.
pub fn interest_subscriber(
    interest_id: u64,
    keyexpr: &str,
    current: bool,
    future: bool,
    aggregate: bool,
) -> InterestOwned {
    let mut body = InterestBody::new();
    body.set_su(true);
    body.set_ke(true);
    body.set_ag(aggregate);
    body.keyexpr = Some(Wireexpr {
        body: WireexprVariant::WireexprLocal(WireexprLocal {
            id: 0,
            suffix_len: Some(keyexpr.len() as u64),
            suffix: Some(keyexpr),
        }),
    });
    let mut interest = Interest::new();
    interest.interest_id = interest_id;
    interest.set_c(current);
    interest.set_f(future);
    interest.body = Some(body);
    interest.try_into_owned().unwrap()
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
    .try_into_owned()
    .unwrap()
}

pub fn undecl_kexpr(id: u64) -> UndeclKexpr {
    UndeclKexpr {
        id,
        ..UndeclKexpr::default()
    }
}

pub fn undecl_subscriber(id: u64) -> UndeclSubscriberOwned {
    UndeclSubscriber {
        id,
        ..UndeclSubscriber::default()
    }
    .try_into_owned()
    .expect("undecl_subscriber owns no borrowed data")
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
    .try_into_owned()
    .unwrap()
}

pub fn undecl_queryable(id: u64) -> UndeclQueryableOwned {
    UndeclQueryable {
        id,
        ..UndeclQueryable::default()
    }
    .try_into_owned()
    .expect("undecl_queryable owns no borrowed data")
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
    .try_into_owned()
    .unwrap()
}

pub fn undecl_token(id: u64) -> UndeclTokenOwned {
    UndeclToken {
        id,
        ..UndeclToken::default()
    }
    .try_into_owned()
    .expect("undecl_token owns no borrowed data")
}

pub fn declare_envelope_decl_kexpr(d: DeclKexprOwned) -> DeclareOwned {
    DeclareOwned {
        header: 0,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclKexpr(d),
    }
}

pub fn declare_envelope_undecl_kexpr(u: UndeclKexpr) -> DeclareOwned {
    DeclareOwned {
        header: 0,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohUndeclKexpr(u),
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

pub fn declare_envelope_undecl_subscriber(u: UndeclSubscriberOwned) -> DeclareOwned {
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

pub fn declare_envelope_undecl_queryable(u: UndeclQueryableOwned) -> DeclareOwned {
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

pub fn declare_envelope_undecl_token(u: UndeclTokenOwned) -> DeclareOwned {
    DeclareOwned {
        header: 0,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohUndeclToken(u),
    }
}

/// A `Declare(DeclToken)` envelope tagged with an outer `interest_id`
/// — the shape a peer emits when *replying* to a CURRENT liveliness
/// Interest (the solicited-reply form consumed by
/// `LivelinessGetRegistry`). The un-tagged `declare_envelope_decl_token`
/// is the proactive (unsolicited) form with `interest_id = None`.
pub fn declare_envelope_decl_token_with_interest(
    d: DeclTokenOwned,
    interest_id: u64,
) -> DeclareOwned {
    DeclareOwned {
        header: 0,
        interest_id: Some(interest_id),
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclToken(d),
    }
}

/// A `Declare(DeclFinal)` envelope tagged with an outer `interest_id` —
/// the terminator a peer emits after replying to a CURRENT liveliness
/// Interest (consumed by `LivelinessGetRegistry` to fire `on_final`).
pub fn declare_envelope_decl_final_with_interest(interest_id: u64) -> DeclareOwned {
    DeclareOwned {
        header: 0,
        interest_id: Some(interest_id),
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclFinal(DeclFinal::default()),
    }
}

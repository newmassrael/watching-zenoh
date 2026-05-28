// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Shared fixture builders for the four declare/* registry tests.
//! Each helper composes a minimal codec record (DeclSubscriber /
//! DeclQueryable / DeclToken and their Undecl counterparts) so the
//! AP-side `#[cfg(test)] mod tests` blocks in
//! `wz-runtime-tokio/src/declare/{subscriber,queryable,liveliness,
//! liveliness_subscriber,cross_tests}.rs` share a single source for
//! fixture shape.
//!
//! Exposed under the `test-helpers` Cargo feature so the helpers
//! compile only when an explicit consumer (wz-runtime-tokio's
//! dev-dependency) opts in. Production wz-session-core artifacts
//! carry no fixture code (R311dr feature-gate contract).
//!
//! Cross-crate visibility note (R311dr migration from wz-runtime-tokio
//! `pub(super)`): the helpers are `pub` here because the consumer
//! `#[cfg(test)]` blocks live in a sibling crate. The function bodies
//! themselves remain unchanged from the pre-R311dr wz-runtime-tokio
//! home — only the visibility and module path moved.

use alloc::string::ToString;

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

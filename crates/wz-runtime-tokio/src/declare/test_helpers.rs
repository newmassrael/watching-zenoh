// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Shared `#[cfg(test)]` fixture builders for the three Remote*
//! declare registries. Each `pub(super)` helper composes a minimal
//! codec record (DeclSubscriber / DeclQueryable / DeclToken and their
//! Undecl counterparts) so the unit tests in subscriber.rs /
//! queryable.rs / liveliness.rs plus the cross-registry composability
//! tests in cross_tests.rs share a single source for fixture shape.
//!
//! Compile-gated behind `cfg(test)` — the helpers carry no production
//! runtime cost. Originally lived as private fns inside the flat
//! declare.rs `mod tests` block (pre-reorg); the sub-module split
//! lifts them here so the test files can stay focused on assertions.

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

pub(super) fn decl_subscriber(id: u64, mapping_id: u64, suffix: Option<&str>) -> DeclSubscriber {
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

pub(super) fn decl_subscriber_nonlocal(
    id: u64,
    mapping_id: u64,
    suffix: Option<&str>,
) -> DeclSubscriber {
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

pub(super) fn undecl_subscriber(id: u64) -> UndeclSubscriber {
    UndeclSubscriber {
        id,
        ..UndeclSubscriber::default()
    }
}

pub(super) fn decl_queryable(id: u64, mapping_id: u64, suffix: Option<&str>) -> DeclQueryable {
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

pub(super) fn undecl_queryable(id: u64) -> UndeclQueryable {
    UndeclQueryable {
        id,
        ..UndeclQueryable::default()
    }
}

pub(super) fn decl_token(id: u64, mapping_id: u64, suffix: Option<&str>) -> DeclToken {
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

pub(super) fn undecl_token(id: u64) -> UndeclToken {
    UndeclToken {
        id,
        ..UndeclToken::default()
    }
}

pub(super) fn declare_envelope_decl_subscriber(d: DeclSubscriber) -> Declare {
    Declare {
        body: DeclareVariant::CodecZenohDeclSubscriber(d),
        ..Declare::default()
    }
}

pub(super) fn declare_envelope_undecl_subscriber(u: UndeclSubscriber) -> Declare {
    Declare {
        body: DeclareVariant::CodecZenohUndeclSubscriber(u),
        ..Declare::default()
    }
}

pub(super) fn declare_envelope_decl_queryable(d: DeclQueryable) -> Declare {
    Declare {
        body: DeclareVariant::CodecZenohDeclQueryable(d),
        ..Declare::default()
    }
}

pub(super) fn declare_envelope_undecl_queryable(u: UndeclQueryable) -> Declare {
    Declare {
        body: DeclareVariant::CodecZenohUndeclQueryable(u),
        ..Declare::default()
    }
}

pub(super) fn declare_envelope_decl_token(d: DeclToken) -> Declare {
    Declare {
        body: DeclareVariant::CodecZenohDeclToken(d),
        ..Declare::default()
    }
}

pub(super) fn declare_envelope_undecl_token(u: UndeclToken) -> Declare {
    Declare {
        body: DeclareVariant::CodecZenohUndeclToken(u),
        ..Declare::default()
    }
}

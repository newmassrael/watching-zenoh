// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The widths zenoh gives the two identifiers a session allocates and the wire
//! carries: a key expression's scope and a request's id.
//!
//! Upstream reads both bounded, so a peer that states a wider value is refused
//! rather than truncated (`commons/zenoh-codec/src/core/wire_expr.rs` @
//! `let zodec = Zenoh080Bounded::<ExprId>::new();`,
//! `commons/zenoh-codec/src/network/request.rs` @
//! `let id: RequestId = bodec.read(&mut *reader)?;`). The codecs read them at
//! these widths (`sources/codecs/wireexpr_local.scxml`,
//! `wireexpr_nonlocal.scxml`, `request.scxml`, `response.scxml`,
//! `response_final.scxml`), which is where the refusal happens; a session holds
//! them at the same widths, so an identifier it allocates is one the wire can
//! carry and one it reads needs no narrowing.

/// A key expression's scope, and the id a `DeclareKeyExpr` maps it under
/// (`commons/zenoh-protocol/src/core/wire_expr.rs` @ `pub type ExprId = u16;`).
pub type ExprId = u16;

/// A request's id, which its responses name
/// (`commons/zenoh-protocol/src/network/request.rs` @ `pub type RequestId = u32;`).
pub type RequestId = u32;

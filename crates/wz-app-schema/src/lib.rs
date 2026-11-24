// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]

//! The readers of an application's payload schema: what a node runs once, when it is handed a
//! schema, to turn its text into the type tables it then reads every payload by.
//!
//! | module | what it is |
//! |---|---|
//! | `proto_lex` | the `.proto` tokenizer |
//! | `proto_parse` | the `.proto` parser: one file's text into its syntax tree |
//! | `proto_schema` | the schema reader: files read, imports resolved, names linked, the field tree walked |
//!
//! The typed reader and the one writer of the wire, and everything that reads or writes a sample,
//! are `wz-app-frame`'s, which re-exports these modules at its own paths. The split is the
//! boundary between what runs once and what runs per sample: the release profiles build this
//! crate for size and the other for speed.

extern crate alloc;

pub mod proto_lex;
pub mod proto_parse;
pub mod proto_schema;

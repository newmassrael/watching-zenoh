// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]

//! The readers of the documents an application describes its payloads and its messages by: what a
//! node runs once, when it is handed a schema, a profile or a message catalog, to turn its text
//! into the tables it then reads every payload by.
//!
//! | module | what it is | feature |
//! |---|---|---|
//! | `message_catalog_table` | a deployment's message catalog as static tables, for an image that links it | always |
//! | `crc_table` | the parameters of a CRC, checked, and the table derived from them once | always |
//! | `e2e_profile` | the profile of an end-to-end protection header: its data model and its reader | `alloc` |
//! | `segment_profile` | the profile of the header in front of each piece of a split message: its data model and its reader | `alloc` |
//! | `judge_config` | what a receiver's judge of a stream of frames is configured with | always |
//! | `json_doc` | a JSON document read under a bound on its nesting, the pointer a reader walks it with, and the refusal at that pointer | `alloc` |
//! | `catalog_plan` | the reader of a message catalog: every rule judged in the order a refusal is reported, the catalog resolved into plain data | `alloc` |
//! | `proto_types` | the type tables a linked schema is, whichever reader made them | `alloc` |
//! | `proto_lex` | the `.proto` tokenizer | `proto-text` |
//! | `proto_parse` | the `.proto` parser: one file's text into its syntax tree | `proto-text` |
//! | `proto_schema` | the schema reader: files read, imports resolved, names linked, the field tree walked | `proto-text` |
//!
//! The typed reader and the one writer of the wire, the profiles' frames, and everything that
//! reads or writes a sample, are `wz-app-frame`'s, which re-exports these modules at its own
//! paths. The split is the boundary between what runs once and what runs per sample: the release
//! profiles build this crate for size and the other for speed. Without `alloc` the crate is the
//! static tables, the CRC parameters and table and the judge's configuration, which an image
//! with no allocator links.
//!
//! A schema compiled when the program is built (`protoc`'s `FileDescriptorSet`) is read into
//! the same tables by `wz-app-frame`, with the protobuf reader it already has; a build that
//! takes only those leaves `proto-text` off and links no tokenizer, parser or linker.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod catalog_plan;
pub mod crc_table;
#[cfg(feature = "alloc")]
pub mod e2e_profile;
#[cfg(feature = "alloc")]
pub mod json_doc;
pub mod judge_config;
pub mod message_catalog_table;
#[cfg(feature = "proto-text")]
pub mod proto_lex;
#[cfg(feature = "proto-text")]
pub mod proto_parse;
#[cfg(feature = "proto-text")]
pub mod proto_schema;
#[cfg(feature = "alloc")]
pub mod proto_types;
#[cfg(feature = "alloc")]
pub mod segment_profile;

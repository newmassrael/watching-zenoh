// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]

//! Application frames: the header an application writes in front of its
//! payload, or in front of each piece of a message it splits over several
//! samples on one key.
//!
//! Zenoh carries such a payload as opaque bytes. The header inside it is the
//! application's: an end-to-end protection header (a CRC, a counter, a length,
//! an identifier) that lets a receiver judge whether a frame arrived intact,
//! in order and in time, or a segment header that says where a piece sits in
//! the whole message it belongs to. This crate builds, opens and judges both
//! kinds, for any node that publishes or receives them: a session runtime, a C
//! ABI, or the capture crate's analysis planes.
//!
//! # Why nothing is hard-coded
//!
//! The repository is public, and the widths, masks, field orders and CRC
//! parameters of a header a deployment uses are that deployment's. So a header
//! is described as DATA, by a profile the caller hands over, and the crate owns
//! only the mechanism. The tests run on synthetic profiles deliberately unlike
//! any deployed one; the only fixed constants are the published CRC catalogue
//! entries the CRC engine is graded against.
//!
//! # Modules
//!
//! | module | what it is | feature |
//! |---|---|---|
//! | `e2e_crc` | a CRC engine for the widths 8, 16, 32 and 64, parameterised by the Rocksoft model | always |
//! | `e2e_judge` | the receiver's judgment of one stream of frames: CRC, counter and timeout | always |
//! | `e2e_profile` | the profile of an end-to-end protection header, read from a JSON document | `alloc` |
//! | `e2e_frame` | building and opening a protected frame under a profile | `alloc` |
//! | `e2e_stream_sender` | the sender of one message: a counter per stream, and a CRC cache for an unchanged payload | `alloc` |
//! | `e2e_receiver` | the receiving judge of one message: a judge per stream or per sender, the profile's rules, a verdict per frame | `alloc` |
//! | `segment_profile` | the profile of the header in front of each piece of a split message | `alloc` |
//! | `segment_sender` | the writer of those pieces: one message cut under a segment profile | `alloc` |
//! | `message_catalog_table` | a deployment's message catalog as static tables, for an image that links it | always |
//! | `message_catalog` | the reader and judge of a message catalog, and the senders, receivers and supervision rows made from it | `alloc` |
//! | `proto_schema` | the `.proto` schema reader: files read, imports resolved, names linked, the field tree walked | `proto` |
//! | `proto_decode` | a protobuf payload read by the types its schema gives it | `proto` |
//! | `proto_lex`, `proto_parse` | the tokenizer and the parser behind the schema reader | `proto` |
//! | `instance_key` | the instance of a message a sample is, read from payload fields; a stream and a last value per instance | `instance-key` |
//!
//! `no_std`, with no third-party dependency. The CRC engine and the judge need
//! no allocator, so a build without `alloc` links none; the three profile
//! modules read a JSON document and keep its fields on the heap, and the piece
//! writer builds each piece in a `Vec`.

// The allocator is linked by the profile modules (`alloc`) and by the unit
// tests, and by nothing else: a build without `alloc` that names a `Vec` is
// refused here, by the compiler.
#[cfg(any(feature = "alloc", test))]
extern crate alloc;

// The tables the catalog generator writes name this crate by its name, as an image that links them
// does; the tests that include them are inside it.
#[cfg(test)]
extern crate self as wz_app_frame;

pub mod e2e_crc;
pub mod e2e_judge;
pub mod message_catalog_table;

#[cfg(feature = "alloc")]
pub mod e2e_frame;
#[cfg(feature = "alloc")]
pub mod e2e_profile;
#[cfg(feature = "alloc")]
pub mod e2e_receiver;
#[cfg(feature = "alloc")]
pub mod e2e_stream_sender;

// The model tests of the profile's judging rules, the receiver and the sender, on
// synthetic profiles.
#[cfg(all(test, feature = "alloc"))]
mod e2e_rules_tests;
#[cfg(feature = "instance-key")]
pub mod instance_key;
// The model tests of the instance keys, on a synthetic schema and profile.
#[cfg(all(test, feature = "instance-key"))]
mod instance_key_tests;
#[cfg(feature = "alloc")]
pub mod message_catalog;
#[cfg(feature = "proto")]
pub mod proto_decode;
#[cfg(feature = "proto")]
pub mod proto_lex;
#[cfg(feature = "proto")]
pub mod proto_parse;
#[cfg(feature = "proto")]
pub mod proto_schema;
// The model tests of the catalog reader: the synthetic catalog, its handles, the generator's
// tables of it, and the corpus of refused catalogs.
#[cfg(all(test, feature = "alloc"))]
mod message_catalog_tests;
#[cfg(feature = "alloc")]
pub mod segment_profile;
#[cfg(feature = "alloc")]
pub mod segment_sender;

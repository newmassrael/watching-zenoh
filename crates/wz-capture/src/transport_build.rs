// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A transport message BUILT from a description in which the caller sets every
//! semantic field, with the unit as the link wants it and a structural report
//! of the bytes.
//!
//! # The contract in one paragraph
//!
//! The description is JSON: `{"message":"frame","reliable":true,"sn":5,...}`.
//! Every field the wire carries that a sender CHOOSES is a key and has no
//! default the caller does not know about; what the wire DERIVES from those is
//! computed (the header flags that say a part is present, the lease unit, every
//! length, the width of every VLE, the stream prefix). The bytes are written by
//! `wz_session_core::transport_compose`, which writes through the generated
//! codecs the session TX path and the dissector use; the report is read back off
//! those bytes by [`crate::transport_layout`]. A value that does not fit its
//! field is a refusal that names the key, never a truncation.
//!
//! # The eight messages, and their keys
//!
//! | `message` | keys (all required unless marked optional) |
//! |---|---|
//! | `init_syn` | `version`, `whatami`, `zid`; optional `resolution` + `batch_size` (together), `extensions` |
//! | `init_ack` | the same, and `cookie` |
//! | `open_syn` | `lease_ms`, `initial_sn`, `cookie`; optional `lease_unit`, `sn_resolution`, `extensions` |
//! | `open_ack` | `lease_ms`, `initial_sn`; optional `lease_unit`, `sn_resolution`, `extensions` |
//! | `frame` | `reliable`, `sn`; optional `priority`, `sn_resolution`, `payload` |
//! | `fragment` | `reliable`, `more`, `sn`; optional `priority`, `first`, `drop`, `sn_resolution`, `payload` |
//! | `keep_alive` | none |
//! | `close` | `reason`, `session` |
//!
//! `Join` and `Oam` are outside this set; asking for them is a refusal that says
//! so. Admitting one is a new arm in [`build`] and a new `compose_*`, and the
//! report needs no change but its table. `lease_unit` (`"ms"` or `"s"`) names
//! the unit an OPEN's lease travels in; left out, the wire derives it.
//!
//! # Sequence numbers and the negotiated resolution
//!
//! The caller always gives sequence numbers. It MAY name the ring they live on,
//! as `sn_resolution` (`"8bit"`, `"16bit"`, `"32bit"`, `"64bit"`), and then a
//! sequence number outside it is refused with the largest value the ring holds,
//! and the report says that value and the widest the VLE can become. Without
//! the key any `u64` is written: the format has no ring of its own, a handshake
//! sizes it.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use wz_codecs::whatami::WhatAmI;
use wz_session_core::json5::Json5Value;
use wz_session_core::parse_error::MAX_EXT_CHAIN_DEPTH;
use wz_session_core::transport_compose::{
    compose_close, compose_fragment, compose_frame, compose_init, compose_keep_alive, compose_open,
    frame_unit, sn_ring_max, ComposeError, ExtBody, ExtSpec, FragmentSpec, FrameSpec, Framing,
    InitRole, InitSpec, LeaseUnit, OpenRole, OpenSpec, SizeParams,
};

use crate::e2e_profile::{
    array, at, check_keys, child, object, optional, read_bool, read_json, read_string, read_uint,
    required, DocError, Entries,
};
use crate::transport_layout::{layout, LayoutError, Row};

/// The messages this door builds, in the order the vocabulary lists them.
pub const MESSAGES: [&str; 8] = [
    "init_syn",
    "init_ack",
    "open_syn",
    "open_ack",
    "frame",
    "fragment",
    "keep_alive",
    "close",
];

/// The words a resolution is written as, indexed by the wire's two-bit code:
/// upstream's own spelling (`commons/zenoh-protocol/src/core/resolution.rs:
/// 30-33`), which the dissector's `sn_res_frame_sn` label prints as well.
pub const RESOLUTION_WORDS: [&str; 4] = ["8bit", "16bit", "32bit", "64bit"];

/// What a build produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    /// The transport message alone, with no prefix.
    pub body: Vec<u8>,
    /// The unit as the framing writes it: the prefix, then the body.
    pub unit: Vec<u8>,
    /// The width of the prefix.
    pub prefix_bytes: usize,
    /// The structural report of the bytes, prefix first when there is one.
    pub layout: Vec<Row>,
}

/// Why nothing was built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// The description is not JSON, or is JSON that does not describe one of
    /// the messages: the place is in the error.
    Description(DocError),
    /// The message composed and does not fit the framing asked for.
    Unit(String),
    /// The bytes were composed and the report could not be derived from them.
    /// Not a caller's fault: the dissector read something the table does not
    /// classify, which a test is meant to have caught first.
    Layout(LayoutError),
}

impl From<DocError> for BuildError {
    fn from(e: DocError) -> Self {
        BuildError::Description(e)
    }
}

fn invalid(path: impl Into<String>, reason: impl Into<String>) -> DocError {
    DocError::invalid(path, reason)
}

/// A compose refusal, put at the key the caller gave the value under.
fn refuse(e: ComposeError) -> DocError {
    match e {
        ComposeError::ZidLength(n) => invalid(
            "/zid",
            format!(
                "the zid is {n} bytes; the wire holds 1 to 16 (`zid_len` is four bits, stored \
                 as the length minus one)"
            ),
        ),
        ComposeError::WhatAmI(v) => invalid(
            "/whatami",
            format!("whatami {v} does not fit the two bits the wire holds (0 to 3)"),
        ),
        ComposeError::ResolutionCode(v) => invalid(
            "/resolution",
            format!("resolution code {v} does not fit the two bits the wire holds (0 to 3)"),
        ),
        ComposeError::Priority(p) => invalid(
            "/priority",
            format!(
                "priority {p} does not fit the three bits the transport QoS extension keeps \
                 it in (0 to 7)"
            ),
        ),
        ComposeError::ExtensionId { index, id } => invalid(
            format!("/extensions/{index}/id"),
            format!("extension id {id} does not fit the four bits of the entry header (0 to 15)"),
        ),
        ComposeError::ExtensionChain { entries } => invalid(
            "/extensions",
            format!(
                "{entries} extensions; the chain reader follows at most {MAX_EXT_CHAIN_DEPTH}, \
                 so a longer chain could not be read back and its layout could not be derived"
            ),
        ),
        ComposeError::LeaseNotWholeSeconds { lease_ms } => invalid(
            "/lease_unit",
            format!(
                "a lease of {lease_ms} ms is not a whole number of seconds, so it cannot be \
                 written in seconds"
            ),
        ),
        ComposeError::ExtensionBody { index } => invalid(
            format!("/extensions/{index}"),
            "this build cannot hold an extension body of that size",
        ),
        // A framing problem, not a description's: `build` reports it apart.
        ComposeError::UnitTooLong { len, max } => invalid(
            "",
            format!("the body is {len} bytes and the prefix holds at most {max}"),
        ),
    }
}

/// An unsigned integer that has to fit `max`, refused with what it was for.
fn read_bounded(value: &Json5Value, path: &str, max: u64, what: &str) -> Result<u64, DocError> {
    let v = read_uint(value, path)?;
    if v > max {
        return Err(invalid(
            path,
            format!("{v} does not fit {what}: the largest value is {max}"),
        ));
    }
    Ok(v)
}

/// A hex string of whole bytes: `"deadbeef"`, upper or lower case, no prefix.
fn read_hex(value: &Json5Value, path: &str) -> Result<Vec<u8>, DocError> {
    let text = read_string(value, path)?;
    if text.len() % 2 != 0 {
        return Err(invalid(
            path,
            format!(
                "`{text}` has {} hex digits; bytes are written as pairs of them",
                text.len()
            ),
        ));
    }
    let digit = |c: u8| -> Option<u8> { (c as char).to_digit(16).map(|d| d as u8) };
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks(2) {
        match (digit(pair[0]), digit(pair[1])) {
            (Some(hi), Some(lo)) => out.push(hi << 4 | lo),
            _ => {
                return Err(invalid(
                    path,
                    "the string is not hexadecimal digits (write the bytes as `0a1b2c`, with no \
                     `0x` and no separators)",
                ))
            }
        }
    }
    Ok(out)
}

/// A resolution word, as its two-bit code.
fn read_resolution(value: &Json5Value, path: &str) -> Result<u8, DocError> {
    let word = read_string(value, path)?;
    RESOLUTION_WORDS
        .iter()
        .position(|w| *w == word)
        .map(|i| i as u8)
        .ok_or_else(|| {
            invalid(
                path,
                format!(
                    "`{word}` is not a resolution: write one of {}",
                    RESOLUTION_WORDS.join(", ")
                ),
            )
        })
}

/// The role a `whatami` is written as: a role name, or the raw two bits.
fn read_whatami(value: &Json5Value, path: &str) -> Result<u8, DocError> {
    if let Json5Value::String(word) = value {
        let named = [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client]
            .into_iter()
            .find(|w| w.to_str() == word);
        if let Some(role) = named {
            return Ok(role.to_wire());
        }
        // A string that is not a role is read as a number, so `"3"` is the
        // reserved code and `"coordinator"` is a refusal that lists the roles.
        if read_uint(value, path).is_err() {
            return Err(invalid(
                path,
                format!(
                    "`{word}` is not a role: write router, peer, client, or the two bits (0 to 3)"
                ),
            ));
        }
    }
    Ok(read_bounded(value, path, 3, "the two bits the wire holds")? as u8)
}

/// The words a lease unit is written as.
pub const LEASE_UNIT_WORDS: [&str; 2] = ["ms", "s"];

fn read_lease_unit(value: &Json5Value, path: &str) -> Result<LeaseUnit, DocError> {
    match read_string(value, path)? {
        "ms" => Ok(LeaseUnit::Milliseconds),
        "s" => Ok(LeaseUnit::Seconds),
        other => Err(invalid(
            path,
            format!(
                "`{other}` is not a lease unit: write one of {}",
                LEASE_UNIT_WORDS.join(", ")
            ),
        )),
    }
}

/// The ring a `sn_resolution` names: the word, its code and its largest value.
struct Ring {
    word: &'static str,
    max: u64,
}

fn read_ring(entries: &Entries) -> Result<Option<Ring>, DocError> {
    let Some(value) = optional(entries, "sn_resolution") else {
        return Ok(None);
    };
    let code = read_resolution(value, "/sn_resolution")?;
    Ok(Some(Ring {
        word: RESOLUTION_WORDS[code as usize],
        max: sn_ring_max(code),
    }))
}

/// A sequence number, held to the ring when the caller named one.
fn read_sn(entries: &Entries, key: &str, ring: &Option<Ring>) -> Result<u64, DocError> {
    let path = child("", key);
    let sn = read_uint(required(entries, key, "")?, &path)?;
    if let Some(ring) = ring {
        if sn > ring.max {
            return Err(invalid(
                path,
                format!(
                    "{sn} is outside the {} ring: a sequence number there is at most {}",
                    ring.word, ring.max
                ),
            ));
        }
    }
    Ok(sn)
}

fn read_priority(entries: &Entries) -> Result<Option<u8>, DocError> {
    optional(entries, "priority")
        .map(|v| {
            read_bounded(
                v,
                "/priority",
                7,
                "the three bits the transport QoS extension keeps the priority in",
            )
            .map(|p| p as u8)
        })
        .transpose()
}

fn read_flag(entries: &Entries, key: &str, default: Option<bool>) -> Result<bool, DocError> {
    match (optional(entries, key), default) {
        (Some(v), _) => read_bool(v, &child("", key)),
        (None, Some(d)) => Ok(d),
        (None, None) => Err(invalid("", format!("the key `{key}` is required"))),
    }
}

fn read_payload(entries: &Entries) -> Result<Vec<u8>, DocError> {
    optional(entries, "payload")
        .map(|v| read_hex(v, "/payload"))
        .transpose()
        .map(Option::unwrap_or_default)
}

/// An extension as the description gives it, owning its bytes.
struct OwnedExt {
    id: u8,
    mandatory: bool,
    body: OwnedBody,
}

enum OwnedBody {
    Unit,
    Z64(u64),
    ZBuf(Vec<u8>),
}

fn read_extensions(entries: &Entries) -> Result<Vec<OwnedExt>, DocError> {
    let Some(value) = optional(entries, "extensions") else {
        return Ok(Vec::new());
    };
    let items = array(value, "/extensions")?;
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let path = at("/extensions", i);
        let ext = object(item, &path)?;
        check_keys(ext, &["id", "mandatory", "unit", "z64", "zbuf"], &path)?;
        let id = read_bounded(
            required(ext, "id", &path)?,
            &child(&path, "id"),
            255,
            "one byte",
        )? as u8;
        let mandatory = match optional(ext, "mandatory") {
            Some(v) => read_bool(v, &child(&path, "mandatory"))?,
            None => false,
        };
        let bodies = ["unit", "z64", "zbuf"]
            .into_iter()
            .filter(|k| optional(ext, k).is_some())
            .collect::<Vec<_>>();
        let body = match bodies.as_slice() {
            ["unit"] => {
                let at_unit = child(&path, "unit");
                if !read_bool(required(ext, "unit", &path)?, &at_unit)? {
                    return Err(invalid(
                        at_unit,
                        "`unit` is `true` for an extension with no body; leave the key out to \
                         choose another body",
                    ));
                }
                OwnedBody::Unit
            }
            ["z64"] => OwnedBody::Z64(read_uint(
                required(ext, "z64", &path)?,
                &child(&path, "z64"),
            )?),
            ["zbuf"] => OwnedBody::ZBuf(read_hex(
                required(ext, "zbuf", &path)?,
                &child(&path, "zbuf"),
            )?),
            _ => {
                return Err(invalid(
                    path,
                    "an extension has exactly one body: `unit`, `z64` or `zbuf`",
                ))
            }
        };
        out.push(OwnedExt {
            id,
            mandatory,
            body,
        });
    }
    Ok(out)
}

fn ext_specs(owned: &[OwnedExt]) -> Vec<ExtSpec<'_>> {
    owned
        .iter()
        .map(|e| ExtSpec {
            id: e.id,
            mandatory: e.mandatory,
            body: match &e.body {
                OwnedBody::Unit => ExtBody::Unit,
                OwnedBody::Z64(v) => ExtBody::Z64(*v),
                OwnedBody::ZBuf(b) => ExtBody::ZBuf(b),
            },
        })
        .collect()
}

/// The message, composed, and the ring the report should name.
fn compose(text: &str) -> Result<(Vec<u8>, Option<u64>), DocError> {
    let root = read_json(text)?;
    let entries = object(&root, "")?;
    let message = read_string(required(entries, "message", "")?, "/message")?;
    let unsupported = |why: &str| {
        invalid(
            "/message",
            format!(
                "`{message}` is not built here: {why}. Build one of {}",
                MESSAGES.join(", ")
            ),
        )
    };
    match message {
        "init_syn" | "init_ack" => {
            let ack = message == "init_ack";
            let allowed: &[&str] = if ack {
                &[
                    "message",
                    "version",
                    "whatami",
                    "zid",
                    "resolution",
                    "batch_size",
                    "extensions",
                    "cookie",
                ]
            } else {
                &[
                    "message",
                    "version",
                    "whatami",
                    "zid",
                    "resolution",
                    "batch_size",
                    "extensions",
                ]
            };
            check_keys(entries, allowed, "")?;
            let version = read_bounded(
                required(entries, "version", "")?,
                "/version",
                255,
                "the version byte",
            )? as u8;
            let whatami = read_whatami(required(entries, "whatami", "")?, "/whatami")?;
            let zid = read_hex(required(entries, "zid", "")?, "/zid")?;
            let size =
                match (
                    optional(entries, "resolution"),
                    optional(entries, "batch_size"),
                ) {
                    (None, None) => None,
                    (Some(resolution), Some(batch)) => {
                        let res = object(resolution, "/resolution")?;
                        check_keys(res, &["frame_sn", "request_id"], "/resolution")?;
                        Some(SizeParams {
                            frame_sn_code: read_resolution(
                                required(res, "frame_sn", "/resolution")?,
                                "/resolution/frame_sn",
                            )?,
                            request_id_code: read_resolution(
                                required(res, "request_id", "/resolution")?,
                                "/resolution/request_id",
                            )?,
                            batch_size: read_bounded(batch, "/batch_size", 65_535, "two bytes")?
                                as u16,
                        })
                    }
                    (Some(_), None) => return Err(invalid(
                        "/resolution",
                        "`resolution` and `batch_size` travel together behind the S flag: give \
                         both or neither",
                    )),
                    (None, Some(_)) => return Err(invalid(
                        "/batch_size",
                        "`resolution` and `batch_size` travel together behind the S flag: give \
                         both or neither",
                    )),
                };
            let cookie = if ack {
                read_hex(required(entries, "cookie", "")?, "/cookie")?
            } else {
                Vec::new()
            };
            let owned = read_extensions(entries)?;
            let extensions = ext_specs(&owned);
            let wire = compose_init(&InitSpec {
                role: if ack {
                    InitRole::Ack { cookie: &cookie }
                } else {
                    InitRole::Syn
                },
                version,
                whatami,
                zid: &zid,
                size,
                extensions: &extensions,
            })
            .map_err(refuse)?;
            Ok((wire, None))
        }
        "open_syn" | "open_ack" => {
            let ack = message == "open_ack";
            let allowed: &[&str] = if ack {
                &[
                    "message",
                    "lease_ms",
                    "lease_unit",
                    "initial_sn",
                    "sn_resolution",
                    "extensions",
                ]
            } else {
                &[
                    "message",
                    "lease_ms",
                    "lease_unit",
                    "initial_sn",
                    "cookie",
                    "sn_resolution",
                    "extensions",
                ]
            };
            check_keys(entries, allowed, "")?;
            let ring = read_ring(entries)?;
            let lease_ms = read_uint(required(entries, "lease_ms", "")?, "/lease_ms")?;
            let lease_unit = optional(entries, "lease_unit")
                .map(|v| read_lease_unit(v, "/lease_unit"))
                .transpose()?;
            let initial_sn = read_sn(entries, "initial_sn", &ring)?;
            let cookie = if ack {
                Vec::new()
            } else {
                read_hex(required(entries, "cookie", "")?, "/cookie")?
            };
            let owned = read_extensions(entries)?;
            let extensions = ext_specs(&owned);
            let wire = compose_open(&OpenSpec {
                role: if ack {
                    OpenRole::Ack
                } else {
                    OpenRole::Syn { cookie: &cookie }
                },
                lease_ms,
                lease_unit,
                initial_sn,
                extensions: &extensions,
            })
            .map_err(refuse)?;
            Ok((wire, ring.map(|r| r.max)))
        }
        "frame" => {
            check_keys(
                entries,
                &[
                    "message",
                    "reliable",
                    "sn",
                    "priority",
                    "sn_resolution",
                    "payload",
                ],
                "",
            )?;
            let ring = read_ring(entries)?;
            let wire = compose_frame(&FrameSpec {
                reliable: read_flag(entries, "reliable", None)?,
                sn: read_sn(entries, "sn", &ring)?,
                priority: read_priority(entries)?,
                payload: &read_payload(entries)?,
            })
            .map_err(refuse)?;
            Ok((wire, ring.map(|r| r.max)))
        }
        "fragment" => {
            check_keys(
                entries,
                &[
                    "message",
                    "reliable",
                    "more",
                    "sn",
                    "priority",
                    "first",
                    "drop",
                    "sn_resolution",
                    "payload",
                ],
                "",
            )?;
            let ring = read_ring(entries)?;
            let wire = compose_fragment(&FragmentSpec {
                reliable: read_flag(entries, "reliable", None)?,
                more: read_flag(entries, "more", None)?,
                sn: read_sn(entries, "sn", &ring)?,
                priority: read_priority(entries)?,
                first: read_flag(entries, "first", Some(false))?,
                drop_marker: read_flag(entries, "drop", Some(false))?,
                payload: &read_payload(entries)?,
            })
            .map_err(refuse)?;
            Ok((wire, ring.map(|r| r.max)))
        }
        "keep_alive" => {
            check_keys(entries, &["message"], "")?;
            Ok((compose_keep_alive(), None))
        }
        "close" => {
            check_keys(entries, &["message", "reason", "session"], "")?;
            let reason = read_bounded(
                required(entries, "reason", "")?,
                "/reason",
                255,
                "the reason byte",
            )? as u8;
            let session = read_flag(entries, "session", None)?;
            Ok((compose_close(reason, session), None))
        }
        "join" | "oam" => Err(unsupported("Join and Oam are later work")),
        _ => Err(unsupported("it names no message")),
    }
}

/// Build the message `description` describes, framed as `framing` says.
pub fn build(description: &str, framing: Framing) -> Result<Built, BuildError> {
    let (body, ring_max) = compose(description)?;
    let unit = frame_unit(framing, &body).map_err(|e| match e {
        ComposeError::UnitTooLong { len, max } => BuildError::Unit(format!(
            "the {} framing holds a body of at most {max} bytes, and this one is {len}",
            framing.name()
        )),
        other => BuildError::Description(refuse(other)),
    })?;
    let layout = layout(&unit, framing, ring_max).map_err(BuildError::Layout)?;
    Ok(Built {
        body,
        unit,
        prefix_bytes: framing.prefix_bytes(),
        layout,
    })
}

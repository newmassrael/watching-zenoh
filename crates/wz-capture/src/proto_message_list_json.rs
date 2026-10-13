// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The document of the message-list door: every message the `.proto` files
//! declare, or why the schema was refused.
//!
//! It lives beside the reader ([`crate::proto_message_list`]) and not in the C
//! ABI crate, for the reason the other documents do: one rendering.
//!
//! # `proto_message_list`
//!
//! ```text
//! {"document":{"name":"proto_message_list","revision":1},"ok":true,
//!  "messages":[{"full_name":"pkg.Outer","file":"a.proto","file_index":0,
//!               "parent":null,"nested":false},
//!              {"full_name":"pkg.Outer.Inner","file":"a.proto","file_index":0,
//!               "parent":"pkg.Outer","nested":true}]}
//! ```
//!
//! `messages` lists every message of every file given, nested ones included, in
//! the order the files were listed and, inside a file, in declaration order. Every
//! key of a row is always present:
//!
//! * `full_name` is the message's full name, package included;
//! * `file` and `file_index` say which file it is written in: the name as it was
//!   handed over and its index in the list handed over;
//! * `parent` is the full name of the message it is written inside, or `null` for
//!   a message at the top level of its file;
//! * `nested` is `parent` as a boolean, `true` exactly when `parent` is not
//!   `null`.
//!
//! The row carries no fields and no options: a message is picked from this list
//! and then described by the `proto_message` document, which is the one place
//! they are written. A `map` entry type and a `group` body are not listed.
//!
//! # A refusal
//!
//! `{"document":{...},"ok":false,"file":"a.proto","line":3,"column":9,
//! "reason":"...","message":"a.proto: line 3: ..."}`, the keys the `proto_message`
//! document gives a refusal, for the same reasons: a key that does not apply is
//! ABSENT and never `null`. A `group` or an `extend` is not a reason.

use alloc::format;
use alloc::string::String;

use wz_session_core::json::escape_into;

use crate::doc_revision::{envelope, PROTO_MESSAGE_LIST};
use crate::proto_describe_json::push_diagnostic;
use crate::proto_message_list::list_proto_messages;
use crate::proto_schema::ProtoFile;

/// The `proto_message_list` document for the schema in `files`.
pub fn proto_message_list_json(files: &[ProtoFile<'_>]) -> String {
    let head = envelope(PROTO_MESSAGE_LIST);
    match list_proto_messages(files) {
        Ok(listed) => {
            let mut out = format!("{{{head},\"ok\":true,\"messages\":[");
            for (i, message) in listed.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str("{\"full_name\":");
                escape_into(&message.full_name, &mut out);
                out.push_str(",\"file\":");
                escape_into(&message.file, &mut out);
                out.push_str(&format!(
                    ",\"file_index\":{},\"parent\":",
                    message.file_index
                ));
                match &message.parent {
                    Some(parent) => escape_into(parent, &mut out),
                    None => out.push_str("null"),
                }
                out.push_str(if message.nested() {
                    ",\"nested\":true}"
                } else {
                    ",\"nested\":false}"
                });
            }
            out.push_str("]}");
            out
        }
        Err(bad) => {
            let mut out = format!("{{{head},\"ok\":false");
            push_diagnostic(&bad, &mut out);
            out.push('}');
            out
        }
    }
}

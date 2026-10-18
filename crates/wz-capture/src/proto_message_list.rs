// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Every message a set of `.proto` files declares, with no root: the list a
//! person picks a message from before [`crate::proto_describe`] describes it.
//!
//! ## What this is for
//!
//! [`crate::proto_describe::describe_proto`] needs the full name of a root
//! message, and a program that lets a person choose a message has to show them
//! the names first. Until now that meant reading the `.proto` text a second time
//! in the program that links this library. This is the list, from the one reader
//! the description door, the declaration door and the value door already use.
//!
//! ## What comes out
//!
//! Every message of every file given, nested messages included, in the order of
//! the files as they were listed and, inside a file, in declaration order (a
//! message, then the messages written inside it, then the next message of the
//! enclosing scope). Per message: its full name (package included), the file it is
//! written in (index and name) and the full name of the message it is written
//! inside, if any.
//!
//! A `map<K, V>` field's entry type and a `group`'s body are not messages the
//! author wrote a declaration for, so they are not listed. A message is listed
//! whether or not any other message reaches it: there is no root, so nothing is
//! unreachable.
//!
//! ## What is refused
//!
//! What the other doors refuse and for the same reasons, since they share the
//! reader: a syntax error, an import that is not among the files given, a type
//! that is not defined, a repeated or reserved number, two files with one name.
//! A `group` or an `extend` is NOT a refusal here (it is only a refusal when a
//! root message reaches it), and a recursive message is listed once like any
//! other. Nothing is expanded into paths or fields.
//!
//! The list carries no options and no fields: the same fact in two documents
//! would be two copies, and [`crate::proto_describe`] is the one that gives them
//! once a message is picked.

use alloc::string::String;
use alloc::vec::Vec;

use crate::proto_schema::{Linker, ProtoDiagnostic, ProtoFile};

/// One message of the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedMessage {
    /// The full name, package included.
    pub full_name: String,
    /// The index in the files handed over of the file the message is written in.
    pub file_index: usize,
    /// The name of that file, as it was handed over.
    pub file: String,
    /// The full name of the message this one is written inside, or `None` for a
    /// message at the top level of its file.
    pub parent: Option<String>,
}

impl ListedMessage {
    /// Whether the message is written inside another message.
    pub fn nested(&self) -> bool {
        self.parent.is_some()
    }
}

/// Every message the schema in `files` declares.
///
/// # Errors
///
/// The [`ProtoDiagnostic`] of the first problem found; see the module
/// documentation for what is refused.
pub fn list_proto_messages(files: &[ProtoFile<'_>]) -> Result<Vec<ListedMessage>, ProtoDiagnostic> {
    let linker = Linker::read_all(files)?;
    // The linker registers a file's messages together, but in the order the files
    // were loaded (an import before its importer), so the file order is restored
    // here. The sort is stable: inside a file the registration order stays.
    let mut order: Vec<usize> = (0..linker.msgs.len()).collect();
    order.sort_by_key(|&idx| linker.msgs[idx].file);
    Ok(order
        .into_iter()
        .map(|idx| {
            let msg = &linker.msgs[idx];
            ListedMessage {
                full_name: msg.full_name.clone(),
                file_index: msg.file,
                file: String::from(linker.name_of(msg.file)),
                parent: msg.parent.map(|p| linker.msgs[p].full_name.clone()),
            }
        })
        .collect())
}

// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The message catalog of the pico C ABI (`wz_ext_message_catalog_*`): a catalog read from JSON5
//! text the fuzzer writes, every entry read back, and the e2e sender, receiver and supervision rows
//! the catalog makes for each message and node asked of it.
//!
//! Input: the catalog's text (to a NUL), then names (each to a NUL) the catalog is asked for as a
//! key expression and as a node, and the id their first four bytes make.
//!
//! Held beside not crashing: each door answers a code its documentation states; a refused catalog
//! leaves the gravestone and a reason, a read one no reason; each entry has a key that is UTF-8,
//! that the catalog finds again under that key and under the entry's id, and numbers that are 0
//! where its `has` bits are clear; one past the last entry is refused with a zeroed entry; a
//! direction is only the two bits; a sender, a receiver or supervision rows are made only for a
//! node that publishes or subscribes to a protected or supervised message, and the rows are one per
//! listed sender; a dropped catalog answers like a null one and drops again without harm.

#![no_main]

use std::ffi::{CStr, CString};

use libfuzzer_sys::fuzz_target;
use wz_capi_pico::e2e_receiver::{
    wz_ext_e2e_receiver_drop, wz_ext_e2e_receiver_move, wz_ext_internal_e2e_receiver_check,
    wz_ext_owned_e2e_receiver_t,
};
use wz_capi_pico::e2e_sender::{
    wz_ext_e2e_sender_drop, wz_ext_e2e_sender_move, wz_ext_internal_e2e_sender_check,
    wz_ext_owned_e2e_sender_t,
};
use wz_capi_pico::message_catalog::*;
use wz_capi_pico::result::{
    WZ_EXT_ERR_UNSUPPORTED, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_INVALID, Z_ERR_NULL, Z_OK,
};
use wz_fuzz_pico_ext::{empty_string, stated, take_string, Reader};

/// The most entries a catalog is walked for, and the nodes each is asked about: the doors are
/// the same for every index, and a walk of thousands would make each input slow.
const MOST_ENTRIES: usize = 64;
const NODES: usize = 4;
/// The most names an input asks the catalog for.
const MOST_NAMES: usize = 8;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let text = r.c_field();
    let mut names = Vec::new();
    while !r.is_empty() && names.len() < MOST_NAMES {
        names.push(r.c_field());
    }

    let mut catalog: wz_ext_owned_message_catalog_t = unsafe { core::mem::zeroed() };
    let mut refusal = empty_string();
    // SAFETY: `catalog` is writable, `text` is NUL-terminated, `refusal` is writable.
    let rc = unsafe { wz_ext_message_catalog_new(&mut catalog, text.as_ptr(), &mut refusal) };
    let why = unsafe { take_string("message_catalog_new", &mut refusal) };
    stated(
        "message_catalog_new",
        rc,
        &[Z_OK, Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE],
    );
    let holds = unsafe { wz_ext_internal_message_catalog_check(&catalog) };
    assert_eq!(
        holds,
        rc == Z_OK,
        "message_catalog_new: {rc} and a catalog held: {holds}"
    );
    if rc == Z_OK {
        assert!(
            why.is_empty(),
            "message_catalog_new: a read catalog left a refusal: {why}"
        );
    }
    if rc == Z_ERR_CONFIG_INVALID_VALUE {
        assert!(
            !why.is_empty(),
            "message_catalog_new: refused with no reason"
        );
    }

    let this = unsafe { wz_ext_message_catalog_loan(&catalog) };
    if holds {
        // SAFETY: `this` is a live loaned catalog.
        let len = unsafe { wz_ext_message_catalog_len(this) };
        for index in 0..len.min(MOST_ENTRIES) {
            let entry = entry_of(this, index);
            for node in 0..NODES {
                made_for(this, index, node, &entry);
            }
        }
        let mut past: wz_ext_message_entry_t = unsafe { core::mem::zeroed() };
        // SAFETY: `this` is a live loaned catalog; `past` is writable.
        let rc = unsafe { wz_ext_message_catalog_entry(this, len, &mut past) };
        assert_eq!(
            rc, Z_ERR_INVALID,
            "message_catalog_entry: one past the last answered {rc}"
        );
        assert!(
            past.key_expr.is_null() && past.has == 0,
            "a refused entry is not zeroed"
        );
        // SAFETY: as above.
        let _ = unsafe { wz_ext_message_catalog_supervision_start_delay(this) };
    }
    for name in &names {
        ask(this, name, holds);
    }

    // SAFETY: an owned catalog slot, dropped twice; the second is a documented no-op.
    unsafe {
        wz_ext_message_catalog_drop(wz_ext_message_catalog_move(&mut catalog));
        assert!(
            !wz_ext_internal_message_catalog_check(&catalog),
            "a dropped catalog is still held"
        );
        wz_ext_message_catalog_drop(wz_ext_message_catalog_move(&mut catalog));
        let this = wz_ext_message_catalog_loan(&catalog);
        assert_eq!(
            wz_ext_message_catalog_len(this),
            0,
            "a dropped catalog has messages"
        );
        let mut entry: wz_ext_message_entry_t = core::mem::zeroed();
        assert_eq!(
            wz_ext_message_catalog_entry(this, 0, &mut entry),
            Z_ERR_NULL,
            "a dropped catalog gave an entry"
        );
    }
});

/// Entry `index`, held to its documented shape and found again under its key and its id.
fn entry_of(this: *const wz_ext_loaned_message_catalog_t, index: usize) -> wz_ext_message_entry_t {
    let mut entry: wz_ext_message_entry_t = unsafe { core::mem::zeroed() };
    // SAFETY: `this` is a live loaned catalog; `entry` is writable.
    let rc = unsafe { wz_ext_message_catalog_entry(this, index, &mut entry) };
    assert_eq!(
        rc, Z_OK,
        "message_catalog_entry: entry {index} answered {rc}"
    );
    assert!(!entry.key_expr.is_null(), "entry {index} has no key");
    // SAFETY: a key the entry points at, valid while the catalog lives.
    let key = unsafe { CStr::from_ptr(entry.key_expr) };
    let key_text = key
        .to_str()
        .unwrap_or_else(|e| panic!("entry {index}: a key that is not UTF-8: {e}"));
    let all = WZ_EXT_MESSAGE_HAS_PERIOD
        | WZ_EXT_MESSAGE_HAS_PROTECTION
        | WZ_EXT_MESSAGE_HAS_SENDERS
        | WZ_EXT_MESSAGE_HAS_INSTANCE_KEY
        | WZ_EXT_MESSAGE_HAS_REPLAY
        | WZ_EXT_MESSAGE_HAS_SUPERVISION
        | WZ_EXT_MESSAGE_HAS_SEGMENT_PROFILE;
    assert_eq!(
        entry.has & !all,
        0,
        "entry {index}: a has bit of no name: {:#x}",
        entry.has
    );
    for (bit, value) in [
        (WZ_EXT_MESSAGE_HAS_PERIOD, u64::from(entry.period_ms)),
        (WZ_EXT_MESSAGE_HAS_REPLAY, u64::from(entry.replay_depth)),
        (
            WZ_EXT_MESSAGE_HAS_SUPERVISION,
            u64::from(entry.supervision_factor),
        ),
        (
            WZ_EXT_MESSAGE_HAS_SUPERVISION,
            u64::from(entry.supervision_awaited),
        ),
        (WZ_EXT_MESSAGE_HAS_SENDERS, u64::from(entry.senders)),
    ] {
        if entry.has & bit == 0 {
            assert_eq!(
                value, 0,
                "entry {index}: a number without its has bit {bit:#x} is {value}"
            );
        }
    }

    let mut found = usize::MAX;
    // SAFETY: `this` is a live loaned catalog; `key` is NUL-terminated; `found` is writable.
    let rc = unsafe { wz_ext_message_catalog_find(this, key.as_ptr(), &mut found) };
    assert_eq!(
        rc, Z_OK,
        "message_catalog_find: the key {key_text} of entry {index} answered {rc}"
    );
    assert_eq!(
        key_of(this, found),
        key_text,
        "message_catalog_find: {key_text} found another key"
    );
    // SAFETY: as above.
    let rc = unsafe { wz_ext_message_catalog_find_id(this, entry.id, &mut found) };
    assert_eq!(
        rc, Z_OK,
        "message_catalog_find_id: the id {} of entry {index} answered {rc}",
        entry.id
    );
    assert_eq!(
        found, index,
        "message_catalog_find_id: id {} found entry {found}, not {index}",
        entry.id
    );
    entry
}

fn key_of(this: *const wz_ext_loaned_message_catalog_t, index: usize) -> String {
    let mut entry: wz_ext_message_entry_t = unsafe { core::mem::zeroed() };
    // SAFETY: `this` is a live loaned catalog; `entry` is writable.
    let rc = unsafe { wz_ext_message_catalog_entry(this, index, &mut entry) };
    assert_eq!(
        rc, Z_OK,
        "message_catalog_entry: a found entry {index} answered {rc}"
    );
    // SAFETY: a key the entry points at, valid while the catalog lives.
    unsafe { CStr::from_ptr(entry.key_expr) }
        .to_string_lossy()
        .into_owned()
}

/// What the catalog makes for `node` of message `index`, held to the direction and the entry.
fn made_for(
    this: *const wz_ext_loaned_message_catalog_t,
    index: usize,
    node: usize,
    entry: &wz_ext_message_entry_t,
) {
    // SAFETY: `this` is a live loaned catalog.
    let direction = unsafe { wz_ext_message_catalog_direction(this, index, node) };
    assert_eq!(
        direction & !(WZ_EXT_MESSAGE_PUBLISHES | WZ_EXT_MESSAGE_SUBSCRIBES),
        0,
        "a direction of no name: {direction:#x}"
    );
    let protected = entry.has & WZ_EXT_MESSAGE_HAS_PROTECTION != 0;
    let supervised = entry.has & WZ_EXT_MESSAGE_HAS_SUPERVISION != 0;

    let mut tx: wz_ext_owned_e2e_sender_t = unsafe { core::mem::zeroed() };
    let mut refusal = empty_string();
    // SAFETY: `this` is a live loaned catalog; the outs are writable.
    let rc = unsafe {
        wz_ext_message_catalog_e2e_sender_new(
            this,
            index,
            node,
            core::ptr::null(),
            &mut tx,
            &mut refusal,
        )
    };
    let _ = unsafe { take_string("message_catalog_e2e_sender_new", &mut refusal) };
    stated(
        "message_catalog_e2e_sender_new",
        rc,
        &[Z_OK, Z_ERR_INVALID, Z_ERR_CONFIG_INVALID_VALUE],
    );
    assert_eq!(unsafe { wz_ext_internal_e2e_sender_check(&tx) }, rc == Z_OK);
    if rc == Z_OK {
        assert!(
            direction & WZ_EXT_MESSAGE_PUBLISHES != 0 && protected,
            "a sender made for node {node} of message {index}, direction {direction:#x}, has {:#x}",
            entry.has
        );
    }
    // SAFETY: an owned sender slot or its gravestone.
    unsafe { wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&mut tx)) };

    let mut rx: wz_ext_owned_e2e_receiver_t = unsafe { core::mem::zeroed() };
    let mut refusal = empty_string();
    // SAFETY: as above.
    let rc = unsafe {
        wz_ext_message_catalog_e2e_receiver_new(this, index, node, &mut rx, &mut refusal)
    };
    let _ = unsafe { take_string("message_catalog_e2e_receiver_new", &mut refusal) };
    if cfg!(feature = "e2e-sender-demux") {
        stated(
            "message_catalog_e2e_receiver_new",
            rc,
            &[Z_OK, Z_ERR_INVALID, Z_ERR_CONFIG_INVALID_VALUE],
        );
    } else {
        stated(
            "message_catalog_e2e_receiver_new",
            rc,
            &[
                Z_OK,
                Z_ERR_INVALID,
                Z_ERR_CONFIG_INVALID_VALUE,
                WZ_EXT_ERR_UNSUPPORTED,
            ],
        );
    }
    assert_eq!(
        unsafe { wz_ext_internal_e2e_receiver_check(&rx) },
        rc == Z_OK
    );
    if rc == Z_OK {
        assert!(
            direction & WZ_EXT_MESSAGE_SUBSCRIBES != 0 && protected,
            "a receiver made for node {node} of message {index}, direction {direction:#x}, has {:#x}",
            entry.has
        );
    }
    // SAFETY: an owned receiver slot or its gravestone.
    unsafe { wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(&mut rx)) };

    let mut rows = usize::MAX;
    let mut refusal = empty_string();
    // SAFETY: as above.
    let rc = unsafe {
        wz_ext_message_catalog_supervision_rows(this, index, node, &mut rows, &mut refusal)
    };
    let _ = unsafe { take_string("message_catalog_supervision_rows", &mut refusal) };
    stated(
        "message_catalog_supervision_rows",
        rc,
        &[Z_OK, Z_ERR_INVALID, Z_ERR_CONFIG_INVALID_VALUE],
    );
    if rc == Z_OK {
        assert!(
            direction & WZ_EXT_MESSAGE_SUBSCRIBES != 0 && supervised,
            "supervision rows for node {node} of message {index}, direction {direction:#x}, has {:#x}",
            entry.has
        );
        let listed = usize::try_from(entry.senders).unwrap_or(usize::MAX);
        assert_eq!(
            rows,
            listed.max(1),
            "message_catalog_supervision_rows: {rows} for {listed} senders"
        );
    }
}

/// Ask the catalog, live or the gravestone, for `name` as a key, a node and an id.
fn ask(this: *const wz_ext_loaned_message_catalog_t, name: &CString, live: bool) {
    let mut out = usize::MAX;
    let id = {
        let bytes = name.as_bytes();
        let mut word = [0u8; 4];
        let n = bytes.len().min(4);
        word[..n].copy_from_slice(&bytes[..n]);
        u32::from_le_bytes(word)
    };
    // SAFETY: `this` is a loaned catalog or the gravestone; `name` is NUL-terminated.
    let answers = unsafe {
        [
            wz_ext_message_catalog_find(this, name.as_ptr(), &mut out),
            wz_ext_message_catalog_node(this, name.as_ptr(), &mut out),
            wz_ext_message_catalog_find_id(this, id, &mut out),
        ]
    };
    for rc in answers {
        if live {
            stated("message_catalog_find", rc, &[Z_OK, Z_ERR_INVALID, Z_EINVAL]);
        } else {
            assert_eq!(rc, Z_ERR_NULL, "the gravestone answered {rc}");
        }
    }
}

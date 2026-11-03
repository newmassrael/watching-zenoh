// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The doors that judge a zenoh config a person wrote, answered in rows:
//! `wz_capi_c_config_validate_rows`, `_validate_for_build_rows` and
//! `_validate_topology_rows`, and the `wz_capi_c_config_verdict_*` readers a
//! caller walks the answer with.
//!
//! Input: a count (taken modulo five), that many config texts and then that
//! many node names (each to a NUL; an empty name is a null entry), then the
//! external endpoints (the rest, one to a NUL). A text goes through
//! `zc_config_from_str`, the line parser a caller's config text reaches; one
//! that does not parse is a null entry of the topology's array.
//!
//! Beyond each door's contract, the properties the rows documentation states:
//! a verdict that refused has a row for the refusal; findings are numbered
//! from zero, in order, and every finding has a row; an index past the end is
//! refused; every text a reader hands out is UTF-8; a second drop is a no-op.

#![no_main]

use core::ffi::c_char;
use core::mem::zeroed;

use libfuzzer_sys::fuzz_target;
use wz_capi_c::abi::{z_loaned_config_t, z_moved_config_t, z_owned_config_t, z_view_string_t};
use wz_capi_c::config::{z_config_drop, z_config_loan, zc_config_from_str};
use wz_capi_c::config_verdict_rows::*;
use wz_capi_c::result::{ZResult, Z_EINVAL, Z_ENULL, Z_EPARSE, Z_OK};
use wz_capi_c::string::{z_string_data, z_string_len, z_view_string_loan};
use wz_fuzz::Reader;

/// The most nodes of a topology a single input describes.
const MOST_NODES: u8 = 5;
/// The most external endpoints a single input names.
const MOST_EXTERNAL: usize = 8;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let nodes = usize::from(r.u8() % MOST_NODES);
    let texts: Vec<_> = (0..nodes).map(|_| r.c_field()).collect();
    let names: Vec<_> = (0..nodes).map(|_| r.c_field()).collect();
    let mut external = Vec::new();
    while !r.is_empty() && external.len() < MOST_EXTERNAL {
        external.push(r.c_field());
    }

    // SAFETY: an all-zero config slot is the gravestone the door writes first.
    let mut configs: Vec<z_owned_config_t> = (0..nodes).map(|_| unsafe { zeroed() }).collect();
    let mut loaned: Vec<*const z_loaned_config_t> = Vec::with_capacity(nodes);
    for (slot, text) in configs.iter_mut().zip(&texts) {
        // SAFETY: `slot` is writable and `text` is NUL-terminated.
        let rc = unsafe { zc_config_from_str(slot, text.as_ptr()) };
        assert!(
            matches!(rc, Z_OK | Z_EPARSE | Z_ENULL),
            "zc_config_from_str: answered {rc}"
        );
        // SAFETY: `slot` holds a config the door wrote, or its gravestone.
        loaned.push(if rc == Z_OK {
            unsafe { z_config_loan(slot) }
        } else {
            core::ptr::null()
        });
    }

    // The two single-node doors, over each config that parsed, and over none.
    for config in loaned.iter().copied().chain([core::ptr::null()]) {
        for_build_or_not(config);
    }

    // The set door: the names are null where empty, and the nodes are null
    // where their text did not parse.
    let name_ptrs: Vec<*const c_char> = names
        .iter()
        .map(|name| {
            if name.as_bytes().is_empty() {
                core::ptr::null()
            } else {
                name.as_ptr()
            }
        })
        .collect();
    let external_ptrs: Vec<*const c_char> = external.iter().map(|e| e.as_ptr()).collect();
    let mut verdict = empty_verdict();
    // SAFETY: both arrays are valid for their counts and outlive the call; each
    // entry is null or a live loaned config or a NUL-terminated string.
    let rc = unsafe {
        wz_capi_c_config_validate_topology_rows(
            loaned.as_ptr(),
            name_ptrs.as_ptr(),
            nodes,
            external_ptrs.as_ptr(),
            external_ptrs.len(),
            &mut verdict,
        )
    };
    hold("config_validate_topology_rows", rc, &mut verdict);

    // A caller passing no names array at all is as well formed.
    let mut verdict = empty_verdict();
    // SAFETY: as above; `names` and `external` may be null.
    let rc = unsafe {
        wz_capi_c_config_validate_topology_rows(
            loaned.as_ptr(),
            core::ptr::null(),
            nodes,
            core::ptr::null(),
            0,
            &mut verdict,
        )
    };
    hold("config_validate_topology_rows (no names)", rc, &mut verdict);

    for slot in &mut configs {
        // SAFETY: a config slot, dropped once; a gravestone drops as a no-op.
        unsafe { z_config_drop((slot as *mut z_owned_config_t).cast::<z_moved_config_t>()) };
    }
});

/// Ask both single-node doors about one config.
fn for_build_or_not(config: *const z_loaned_config_t) {
    let mut verdict = empty_verdict();
    // SAFETY: `config` is null or a live loaned config; `verdict` is writable.
    let rc = unsafe { wz_capi_c_config_validate_rows(config, &mut verdict) };
    hold("config_validate_rows", rc, &mut verdict);
    let mut verdict = empty_verdict();
    // SAFETY: as above.
    let rc = unsafe { wz_capi_c_config_validate_for_build_rows(config, &mut verdict) };
    hold("config_validate_for_build_rows", rc, &mut verdict);
}

fn empty_verdict() -> wz_capi_c_owned_config_verdict_t {
    // SAFETY: a zeroed handle is the slot every door writes first.
    let mut slot: wz_capi_c_owned_config_verdict_t = unsafe { zeroed() };
    // SAFETY: `slot` is writable.
    unsafe { wz_capi_c_internal_config_verdict_null(&mut slot) };
    slot
}

fn empty_view() -> z_view_string_t {
    // SAFETY: a zeroed view is a placeholder every reader overwrites.
    unsafe { zeroed() }
}

/// The text a view holds, held to being UTF-8.
fn text_of(door: &str, view: &z_view_string_t) -> String {
    // SAFETY: a view a reader wrote over text the verdict still holds.
    let (ptr, len) = unsafe {
        let loaned = z_view_string_loan(view);
        (z_string_data(loaned), z_string_len(loaned))
    };
    if len == 0 {
        return String::new();
    }
    // SAFETY: `len` bytes at `ptr`, borrowed from the verdict.
    let bytes = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    std::str::from_utf8(bytes)
        .unwrap_or_else(|e| panic!("{door}: handed out text that is not UTF-8: {e}"))
        .to_owned()
}

/// Hold a verdict door's answer to the rows documentation, and drop it.
fn hold(door: &str, rc: ZResult, verdict: &mut wz_capi_c_owned_config_verdict_t) {
    assert!(
        matches!(rc, Z_OK | Z_EINVAL | Z_EPARSE | Z_ENULL),
        "{door}: answered {rc}, a code the door does not state"
    );
    // SAFETY: `verdict` was written by the door (a verdict or the gravestone).
    let loaned = unsafe { wz_capi_c_config_verdict_loan(verdict) };
    let len = unsafe { wz_capi_c_config_verdict_len(loaned) };
    let findings = unsafe { wz_capi_c_config_verdict_finding_count(loaned) };
    assert_eq!(
        len == 0,
        findings == 0,
        "{door}: {len} row(s) for {findings} finding(s)"
    );
    assert!(
        len >= findings,
        "{door}: {findings} finding(s) in {len} row(s)"
    );
    if rc != Z_OK {
        assert!(len >= 1, "{door}: refused with {rc} and gave no row for it");
    }

    let mut previous: Option<usize> = None;
    for index in 0..len {
        let mut finding = usize::MAX;
        let rc = unsafe { wz_capi_c_config_verdict_row_finding(loaned, index, &mut finding) };
        assert_eq!(rc, Z_OK, "{door}: row {index} of {len} has no finding");
        match previous {
            None => assert_eq!(finding, 0, "{door}: the first row is of finding {finding}"),
            Some(p) => assert!(
                finding == p || finding == p + 1,
                "{door}: row {index} is of finding {finding} after {p}"
            ),
        }
        previous = Some(finding);

        let (mut variant, mut message) = (empty_view(), empty_view());
        let rc = unsafe { wz_capi_c_config_verdict_row_variant(loaned, index, &mut variant) };
        assert_eq!(rc, Z_OK, "{door}: row {index} has no variant");
        assert!(
            !text_of(door, &variant).is_empty(),
            "{door}: row {index} has an empty variant"
        );
        let rc = unsafe { wz_capi_c_config_verdict_row_message(loaned, index, &mut message) };
        assert_eq!(rc, Z_OK, "{door}: row {index} has no message");
        text_of(door, &message);

        for column in [
            wz_capi_c_config_verdict_row_node,
            wz_capi_c_config_verdict_row_key,
            wz_capi_c_config_verdict_row_endpoint,
        ] {
            let mut view = empty_view();
            if unsafe { column(loaned, index, &mut view) } {
                text_of(door, &view);
            }
        }
    }
    match previous {
        Some(last) => assert_eq!(
            last + 1,
            findings,
            "{door}: the rows end at finding {last} of {findings}"
        ),
        None => assert_eq!(findings, 0),
    }

    // One past the end is refused by every reader.
    let mut finding = 0usize;
    let rc = unsafe { wz_capi_c_config_verdict_row_finding(loaned, len, &mut finding) };
    assert!(
        matches!(rc, Z_EINVAL | Z_ENULL),
        "{door}: row {len} of {len} answered {rc}"
    );
    let mut view = empty_view();
    let rc = unsafe { wz_capi_c_config_verdict_row_variant(loaned, len, &mut view) };
    assert!(
        matches!(rc, Z_EINVAL | Z_ENULL),
        "{door}: variant of row {len} of {len} answered {rc}"
    );

    // SAFETY: an owned verdict, dropped twice: the second is a documented no-op.
    unsafe {
        let moved = (verdict as *mut wz_capi_c_owned_config_verdict_t).cast();
        wz_capi_c_config_verdict_drop(moved);
        assert!(
            !wz_capi_c_internal_config_verdict_check(verdict),
            "{door}: a dropped verdict still holds its rows"
        );
        wz_capi_c_config_verdict_drop(moved);
    }
}

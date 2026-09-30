// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The config verdict as ROWS, for a caller that does not parse prose.
//!
//! `config_verdict` answers in lines, `<VariantName>: <message>`, and says so:
//! the name is the stable half, the message is prose. That was enough for a
//! caller that SHOWS the verdict. It is not enough for one that attaches each
//! reason to the config field it is about, which is what an inspector does:
//! it needs the key path as its own value beside the reason, and, for a set
//! of nodes, the node under the name the caller gave it rather than the
//! position it was passed at. Both were in the domain types all along and were
//! flattened into the sentence at this boundary.
//!
//! ## One handle, columns read by accessor
//!
//! The rows live in an owned handle and are read one column at a time, the way
//! the group doors read a member. A result struct of strings was the other
//! shape, and it would have made every future column a layout change; an
//! accessor per column makes a new one a new symbol, which is the ABI event
//! `capi_c_abi_pin.py` already watches for and the header already says how to
//! probe. Nothing here copies text to the caller: a `z_view_string_t` borrows
//! from the handle and is valid until the handle is dropped.
//!
//! ## What a row is
//!
//! A verdict is a list of findings, and a finding can point at several places
//! (`Unreachable` at the three keys that could have given a node a peer, a
//! listen collision at every node that claims the address). The table is FLAT:
//! one row per (finding, site), the finding's own columns repeated. A caller
//! that wants defects rather than places reads `finding_count` and groups on
//! `row_finding`; a caller that wants places reads the rows. Neither has to
//! guess which rows belong together.
//!
//! ## A refusal is a row too
//!
//! A config that cannot be READ never reaches the defect list, and the string
//! doors report it as an error code plus a sentence. Here it is the same code
//! AND the rows: one per refusal, with the key at fault as a column. The set
//! door reports EVERY refusal in the call rather than the first, because a
//! caller with eight configs and a bad key in two of them should not have to
//! fix and re-ask to learn about the second. The return code is the first
//! refusal's; the verdict itself is not produced, since a verdict over a
//! subset is a different verdict (the reason the string door fails the whole
//! call, kept).
//!
//! ## The names are the caller's
//!
//! `names` is parallel to `configs`. A null array, or a null entry, leaves that
//! node to the default (its `id`, else `node[<index>]`). A name is a label and
//! not an identity: two nodes given one name are still two nodes.

#![allow(non_camel_case_types)]

use std::ffi::{c_char, CStr};

use wz_runtime_tokio::zenoh_config::{
    positional_node_name, validate_labelled_topology, LabelledNode, ZenohNodeConfig,
};
use wz_runtime_tokio::zenoh_config_finding::{BlamedSite, Finding};

use crate::abi::{z_loaned_config_t, z_view_string_t, Handle};
use crate::config_verdict::{node_config, DoorRefusal, Refusal};
use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};
use crate::string::view_string_over;

/// One row of the flat table: which finding, and which of its sites.
#[derive(Clone, Copy)]
struct Row {
    finding: usize,
    site: usize,
}

/// What a verdict handle holds. Immutable once built, which is what lets a
/// view borrow from it for the handle's whole life.
struct VerdictState {
    findings: Vec<Finding>,
    rows: Vec<Row>,
}

impl VerdictState {
    /// Flatten `findings` into rows. A finding always has at least one site
    /// (`Finding::sites` is never empty), so none is dropped by the flattening.
    fn new(findings: Vec<Finding>) -> Self {
        let rows = findings
            .iter()
            .enumerate()
            .flat_map(|(finding, f)| (0..f.sites.len()).map(move |site| Row { finding, site }))
            .collect();
        Self { findings, rows }
    }

    fn row(&self, index: usize) -> Option<(&Finding, &BlamedSite)> {
        let row = self.rows.get(index)?;
        let finding = &self.findings[row.finding];
        Some((finding, &finding.sites[row.site]))
    }
}

/// An owned verdict. One handle; wz's own type, so there is no upstream size
/// to pad to.
#[repr(C)]
pub struct wz_capi_c_owned_config_verdict_t {
    pub(crate) handle: Handle,
}

/// A loaned verdict — the same layout, so `loan` is a pointer cast.
#[repr(C)]
pub struct wz_capi_c_loaned_config_verdict_t {
    pub(crate) handle: Handle,
}

/// A moved verdict.
#[repr(C)]
pub struct wz_capi_c_moved_config_verdict_t {
    pub(crate) _this: wz_capi_c_owned_config_verdict_t,
}

impl wz_capi_c_owned_config_verdict_t {
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
        }
    }

    fn adopt(state: VerdictState) -> Self {
        Self {
            handle: Box::into_raw(Box::new(state)) as Handle,
        }
    }
}

/// # Safety
/// `this_` must be null or a valid loaned verdict.
unsafe fn verdict_state<'a>(
    this_: *const wz_capi_c_loaned_config_verdict_t,
) -> Option<&'a VerdictState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    // SAFETY: a live `VerdictState` this crate boxed.
    (!handle.is_null()).then(|| unsafe { &*(handle as *const VerdictState) })
}

/// Park the rows in `out`, and hand `code` back so a door can `return` this.
///
/// # Safety
/// `out` must be valid and writable.
unsafe fn publish(
    out: *mut wz_capi_c_owned_config_verdict_t,
    findings: Vec<Finding>,
    code: ZResult,
) -> ZResult {
    // SAFETY: the caller's contract.
    unsafe { *out = wz_capi_c_owned_config_verdict_t::adopt(VerdictState::new(findings)) };
    code
}

/// The refusals of one call, in the order they were met.
///
/// The code is the FIRST refusal's, so a caller branching on it sees the same
/// answer whether it was told about one refusal or eight; the rows carry the
/// rest.
struct Refused {
    findings: Vec<Finding>,
    code: ZResult,
}

impl Refused {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            code: Z_OK,
        }
    }

    fn add(&mut self, refusal: &Refusal, node: Option<&str>) {
        if self.code == Z_OK {
            self.code = refusal.code();
        }
        self.findings.push(refusal.finding(node));
    }

    fn any(&self) -> bool {
        !self.findings.is_empty()
    }
}

/// `wz_capi_c_config_validate`'s question, answered in rows.
///
/// Every reason this config cannot work, judged as a stock zenohd would. A
/// config that cannot be read returns the same code the string door does and
/// ONE refusal row.
///
/// # Safety
/// `config` must be null or a valid loaned config; `out` must be valid and
/// writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_validate_rows(
    config: *const z_loaned_config_t,
    out: *mut wz_capi_c_owned_config_verdict_t,
) -> ZResult {
    // SAFETY: the caller's contract, forwarded whole.
    unsafe { validate_rows_into(config, out, false) }
}

/// `wz_capi_c_config_validate_for_build`'s question, answered in rows: the
/// same verdict plus `ProtocolNotCompiledIn` for a scheme this build lacks.
///
/// # Safety
/// As `wz_capi_c_config_validate_rows`.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_validate_for_build_rows(
    config: *const z_loaned_config_t,
    out: *mut wz_capi_c_owned_config_verdict_t,
) -> ZResult {
    // SAFETY: the caller's contract, forwarded whole.
    unsafe { validate_rows_into(config, out, true) }
}

/// The shared body of the two single-node row doors — one body, for the reason
/// `validate_into` is one.
///
/// # Safety
/// As the callers'.
unsafe fn validate_rows_into(
    config: *const z_loaned_config_t,
    out: *mut wz_capi_c_owned_config_verdict_t,
    for_this_build: bool,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *out = wz_capi_c_owned_config_verdict_t::null_value() };
        // SAFETY: the caller's contract.
        match unsafe { node_config(config) } {
            Ok(node) => {
                let schemes = for_this_build.then(wz_runtime_tokio::compiled_in_link_schemes);
                let findings = node
                    .validate_for_build(schemes)
                    .iter()
                    .map(|defect| defect.finding(None))
                    .collect();
                // SAFETY: checked non-null above.
                unsafe { publish(out, findings, Z_OK) }
            }
            Err(refusal) => {
                // SAFETY: checked non-null above.
                unsafe { publish(out, vec![refusal.finding(None)], refusal.code()) }
            }
        }
    })
}

/// `wz_capi_c_config_validate_topology_with_external`'s question, answered in
/// rows and with the nodes under the caller's names.
///
/// `configs` is an array of `count` loaned configs. `names` is NULL, or an
/// array of `count` entries each NULL or a NUL-terminated, non-empty UTF-8
/// name. `external` is NULL or an array of `external_count` NUL-terminated
/// UTF-8 endpoint strings, the addresses of nodes this deployment does not
/// own; zero of them is the closed reading.
///
/// Every refusal in the call is reported, in argument order, and the verdict
/// is not produced if there is any.
///
/// # Safety
/// `configs` must be null or valid for `count` loaned-config pointers, each
/// null or valid; `names` null or valid for `count` C-string pointers, each
/// null or valid; `external` null or valid for `external_count` C-string
/// pointers; `out` valid and writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_validate_topology_rows(
    configs: *const *const z_loaned_config_t,
    names: *const *const c_char,
    count: usize,
    external: *const *const c_char,
    external_count: usize,
    out: *mut wz_capi_c_owned_config_verdict_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *out = wz_capi_c_owned_config_verdict_t::null_value() };
        if (configs.is_null() && count != 0) || (external.is_null() && external_count != 0) {
            return Z_ENULL;
        }
        let mut refused = Refused::new();

        // The names first, so a refusal about a config can carry the name it
        // would have had.
        let mut labels: Vec<Option<String>> = Vec::with_capacity(count);
        for index in 0..count {
            let raw = if names.is_null() {
                std::ptr::null()
            } else {
                // SAFETY: the caller's contract bounds `names` at `count`.
                unsafe { *names.add(index) }
            };
            if raw.is_null() {
                labels.push(None);
                continue;
            }
            // SAFETY: a NUL-terminated string, by the caller's contract.
            match unsafe { CStr::from_ptr(raw) }.to_str() {
                Ok("") => {
                    refused.add(
                        &Refusal::Door(DoorRefusal::NameEmpty { index }),
                        Some(positional_node_name(index).as_str()),
                    );
                    labels.push(None);
                }
                Ok(name) => labels.push(Some(String::from(name))),
                Err(_) => {
                    refused.add(
                        &Refusal::Door(DoorRefusal::NameNotUtf8 { index }),
                        Some(positional_node_name(index).as_str()),
                    );
                    labels.push(None);
                }
            }
        }

        let mut nodes: Vec<Option<ZenohNodeConfig>> = Vec::with_capacity(count);
        for (index, label) in labels.iter().enumerate() {
            // SAFETY: the caller's contract bounds `configs` at `count`.
            let entry = unsafe { *configs.add(index) };
            // SAFETY: each element is null or a valid loaned config.
            match unsafe { node_config(entry) } {
                Ok(node) => nodes.push(Some(node)),
                Err(refusal) => {
                    let name = label.clone().unwrap_or_else(|| positional_node_name(index));
                    refused.add(&refusal, Some(name.as_str()));
                    nodes.push(None);
                }
            }
        }

        let mut outside: Vec<String> = Vec::with_capacity(external_count);
        for index in 0..external_count {
            // SAFETY: the caller's contract bounds `external` at its count.
            let raw = unsafe { *external.add(index) };
            if raw.is_null() {
                refused.add(&Refusal::Door(DoorRefusal::NoExternal { index }), None);
                continue;
            }
            // SAFETY: a NUL-terminated string, by the caller's contract.
            match unsafe { CStr::from_ptr(raw) }.to_str() {
                Ok(text) => outside.push(String::from(text)),
                // NOT lossy-decoded, for the reason the string door records:
                // an endpoint is matched by STRING.
                Err(_) => refused.add(&Refusal::Door(DoorRefusal::ExternalNotUtf8 { index }), None),
            }
        }

        if refused.any() {
            // SAFETY: checked non-null above.
            return unsafe { publish(out, refused.findings, refused.code) };
        }
        let configs: Vec<ZenohNodeConfig> = nodes.into_iter().flatten().collect();
        let labelled: Vec<LabelledNode<'_>> = configs
            .iter()
            .zip(&labels)
            .map(|(config, label)| LabelledNode::new(label.as_deref(), config))
            .collect();
        let findings = validate_labelled_topology(&labelled, &outside)
            .defects
            .iter()
            .map(|defect| defect.finding())
            .collect();
        // SAFETY: checked non-null above.
        unsafe { publish(out, findings, Z_OK) }
    })
}

/// How many rows the verdict has; 0 for a null verdict.
///
/// # Safety
/// `this_` null or a valid loaned verdict.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_verdict_len(
    this_: *const wz_capi_c_loaned_config_verdict_t,
) -> usize {
    guard_val(0, || {
        // SAFETY: the caller's contract.
        unsafe { verdict_state(this_) }.map_or(0, |state| state.rows.len())
    })
}

/// How many findings the verdict has: the count of defects, which is the count
/// of lines the string doors would have written. 0 for a null verdict.
///
/// # Safety
/// `this_` null or a valid loaned verdict.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_verdict_finding_count(
    this_: *const wz_capi_c_loaned_config_verdict_t,
) -> usize {
    guard_val(0, || {
        // SAFETY: the caller's contract.
        unsafe { verdict_state(this_) }.map_or(0, |state| state.findings.len())
    })
}

/// Which finding row `index` belongs to, counted from 0 in the order the
/// findings were reported. Rows of one finding are adjacent and share this.
///
/// `Z_ENULL` for a null verdict or a null `out`, `Z_EINVAL` for an `index`
/// past the end.
///
/// # Safety
/// `this_` null or a valid loaned verdict; `out` null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_verdict_row_finding(
    this_: *const wz_capi_c_loaned_config_verdict_t,
    index: usize,
    out: *mut usize,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { verdict_state(this_) }) else {
            return Z_ENULL;
        };
        let Some(row) = state.rows.get(index) else {
            return Z_EINVAL;
        };
        // SAFETY: checked non-null above.
        unsafe { *out = row.finding };
        Z_OK
    })
}

/// A column every row has, as a view. `Z_ENULL` / `Z_EINVAL` as for
/// `wz_capi_c_config_verdict_row_finding`, and an empty view with them.
///
/// # Safety
/// `this_` null or a valid loaned verdict; `out` null or writable.
unsafe fn required_view(
    this_: *const wz_capi_c_loaned_config_verdict_t,
    index: usize,
    out: *mut z_view_string_t,
    pick: impl FnOnce(&Finding) -> &str,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let found = unsafe { verdict_state(this_) }.map(|state| state.row(index));
        let (text, code) = match found {
            None => ("", Z_ENULL),
            Some(None) => ("", Z_EINVAL),
            Some(Some((finding, _))) => (pick(finding), Z_OK),
        };
        // SAFETY: checked non-null above.
        unsafe { *out = view_string_over(text) };
        code
    })
}

/// A column a row may lack, as a view: `false`, with an empty view, when this
/// row has no value for it (or the verdict or index is not valid).
///
/// # Safety
/// `this_` null or a valid loaned verdict; `out` null or writable.
unsafe fn optional_view(
    this_: *const wz_capi_c_loaned_config_verdict_t,
    index: usize,
    out: *mut z_view_string_t,
    pick: impl for<'a> FnOnce(&'a Finding, &'a BlamedSite) -> Option<&'a str>,
) -> bool {
    guard_val(false, || {
        if out.is_null() {
            return false;
        }
        // SAFETY: the caller's contract.
        let text = unsafe { verdict_state(this_) }
            .and_then(|state| state.row(index))
            .and_then(|(finding, site)| pick(finding, site));
        // SAFETY: checked non-null above.
        unsafe { *out = view_string_over(text.unwrap_or("")) };
        text.is_some()
    })
}

/// The finding's variant name — the stable half, the one to branch on.
///
/// # Safety
/// As `wz_capi_c_config_verdict_row_finding`, with `out` a `z_view_string_t`.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_verdict_row_variant(
    this_: *const wz_capi_c_loaned_config_verdict_t,
    index: usize,
    out: *mut z_view_string_t,
) -> ZResult {
    // SAFETY: the caller's contract, forwarded whole.
    unsafe { required_view(this_, index, out, |finding| finding.variant.as_str()) }
}

/// The finding's prose — for showing, not branching: it may be reworded in any
/// release.
///
/// # Safety
/// As `wz_capi_c_config_verdict_row_variant`.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_verdict_row_message(
    this_: *const wz_capi_c_loaned_config_verdict_t,
    index: usize,
    out: *mut z_view_string_t,
) -> ZResult {
    // SAFETY: the caller's contract, forwarded whole.
    unsafe { required_view(this_, index, out, |finding| finding.message.as_str()) }
}

/// The node this row is about, under the name the caller gave it. `false`,
/// with an empty view, when the row is about no node: a config judged on its
/// own, or a declaration typed at argv.
///
/// # Safety
/// As `wz_capi_c_config_verdict_row_variant`.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_verdict_row_node(
    this_: *const wz_capi_c_loaned_config_verdict_t,
    index: usize,
    out: *mut z_view_string_t,
) -> bool {
    // SAFETY: the caller's contract, forwarded whole.
    unsafe { optional_view(this_, index, out, |_, site| site.node.as_deref()) }
}

/// The config key path this row is about, `/`-separated as zenoh spells it.
/// `false`, with an empty view, when the row is about no key: the document was
/// not JSON5, or the finding is about an endpoint declared at argv.
///
/// # Safety
/// As `wz_capi_c_config_verdict_row_variant`.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_verdict_row_key(
    this_: *const wz_capi_c_loaned_config_verdict_t,
    index: usize,
    out: *mut z_view_string_t,
) -> bool {
    // SAFETY: the caller's contract, forwarded whole.
    unsafe { optional_view(this_, index, out, |_, site| site.key.as_deref()) }
}

/// The endpoint the finding is about, as given. `false`, with an empty view,
/// when it is not about one.
///
/// # Safety
/// As `wz_capi_c_config_verdict_row_variant`.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_verdict_row_endpoint(
    this_: *const wz_capi_c_loaned_config_verdict_t,
    index: usize,
    out: *mut z_view_string_t,
) -> bool {
    // SAFETY: the caller's contract, forwarded whole.
    unsafe { optional_view(this_, index, out, |finding, _| finding.endpoint.as_deref()) }
}

/// Borrow a verdict.
///
/// # Safety
/// `this_` null or a valid owned verdict.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_verdict_loan(
    this_: *const wz_capi_c_owned_config_verdict_t,
) -> *const wz_capi_c_loaned_config_verdict_t {
    this_ as *const wz_capi_c_loaned_config_verdict_t
}

/// Release a verdict, and with it every view read from it. A second drop is a
/// no-op.
///
/// # Safety
/// `this_` null or a valid moved verdict.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_verdict_drop(
    this_: *mut wz_capi_c_moved_config_verdict_t,
) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        // SAFETY: the caller's contract.
        unsafe { (*this_)._this = wz_capi_c_owned_config_verdict_t::null_value() };
        if !handle.is_null() {
            // SAFETY: a live `Box<VerdictState>` this crate leaked in `adopt`.
            drop(unsafe { Box::from_raw(handle as *mut VerdictState) });
        }
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_config_verdict_null(
    this_: *mut wz_capi_c_owned_config_verdict_t,
) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = wz_capi_c_owned_config_verdict_t::null_value() };
    }
}

/// Whether the slot holds a verdict.
///
/// # Safety
/// `this_` null or a valid owned verdict.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_config_verdict_check(
    this_: *const wz_capi_c_owned_config_verdict_t,
) -> bool {
    // SAFETY: the caller's contract.
    !this_.is_null() && !unsafe { (*this_).handle }.is_null()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;

    use crate::abi::z_owned_config_t;
    use crate::config::z_config_loan;
    use crate::config_verdict::tests::{ask, config_of, topology_verdict_with_external};
    use crate::config_verdict::{wz_capi_c_config_validate, wz_capi_c_config_validate_for_build};
    use crate::result::Z_EPARSE;

    /// One row as a C caller reads it, a column at a time.
    #[derive(Debug, PartialEq)]
    struct RowView {
        finding: usize,
        variant: String,
        message: String,
        node: Option<String>,
        key: Option<String>,
        endpoint: Option<String>,
    }

    /// A view's text. A view borrows from the verdict, so this copies it out
    /// before the verdict can be dropped.
    unsafe fn text_of(view: &z_view_string_t) -> String {
        // SAFETY: a view this crate wrote over live text `len` bytes long.
        let bytes = unsafe { std::slice::from_raw_parts(view.ptr, view.len) };
        String::from_utf8(bytes.to_vec()).expect("wz emits UTF-8")
    }

    unsafe fn empty_view() -> z_view_string_t {
        // SAFETY: a zeroed view is a placeholder every door below overwrites
        // before anything reads it.
        unsafe { std::mem::zeroed() }
    }

    /// Read every row through the accessors, the way a C caller walks them.
    unsafe fn rows_of(verdict: &wz_capi_c_owned_config_verdict_t) -> Vec<RowView> {
        // SAFETY: a live owned verdict.
        let loaned = unsafe { wz_capi_c_config_verdict_loan(verdict) };
        // SAFETY: as above.
        let len = unsafe { wz_capi_c_config_verdict_len(loaned) };
        (0..len)
            .map(|index| {
                // SAFETY: `index` is below the length the same verdict reported.
                unsafe {
                    let mut finding = 0usize;
                    assert_eq!(
                        wz_capi_c_config_verdict_row_finding(loaned, index, &mut finding),
                        Z_OK
                    );
                    let (mut variant, mut message) = (empty_view(), empty_view());
                    assert_eq!(
                        wz_capi_c_config_verdict_row_variant(loaned, index, &mut variant),
                        Z_OK
                    );
                    assert_eq!(
                        wz_capi_c_config_verdict_row_message(loaned, index, &mut message),
                        Z_OK
                    );
                    let optional = |door: unsafe extern "C" fn(
                        *const wz_capi_c_loaned_config_verdict_t,
                        usize,
                        *mut z_view_string_t,
                    ) -> bool| {
                        let mut view = empty_view();
                        let present = door(loaned, index, &mut view);
                        let text = text_of(&view);
                        // The contract: absent is `false` WITH an empty view,
                        // and present is never a way of saying nothing.
                        assert_eq!(present, !text.is_empty(), "presence and text disagree");
                        present.then_some(text)
                    };
                    RowView {
                        finding,
                        variant: text_of(&variant),
                        message: text_of(&message),
                        node: optional(wz_capi_c_config_verdict_row_node),
                        key: optional(wz_capi_c_config_verdict_row_key),
                        endpoint: optional(wz_capi_c_config_verdict_row_endpoint),
                    }
                }
            })
            .collect()
    }

    unsafe fn drop_verdict(verdict: &mut wz_capi_c_owned_config_verdict_t) {
        // SAFETY: a live owned verdict; the moved shape is the same slot.
        unsafe {
            wz_capi_c_config_verdict_drop(
                (verdict as *mut wz_capi_c_owned_config_verdict_t)
                    .cast::<wz_capi_c_moved_config_verdict_t>(),
            )
        };
    }

    unsafe fn null_verdict() -> wz_capi_c_owned_config_verdict_t {
        // SAFETY: a zeroed owned verdict is this ABI's gravestone.
        unsafe { std::mem::zeroed() }
    }

    /// Ask a single-config row door.
    unsafe fn ask_rows(
        door: unsafe extern "C" fn(
            *const z_loaned_config_t,
            *mut wz_capi_c_owned_config_verdict_t,
        ) -> ZResult,
        entries: &[(&str, &str)],
    ) -> (ZResult, Vec<RowView>) {
        // SAFETY: the caller's fixture.
        let cfg = unsafe { config_of(entries) };
        // SAFETY: a zeroed owned verdict is this ABI's gravestone.
        let mut out = unsafe { null_verdict() };
        // SAFETY: a live owned config and a writable out slot.
        let rc = unsafe { door(z_config_loan(&cfg), &mut out) };
        // SAFETY: the door wrote a gravestone or a live verdict.
        let rows = unsafe { rows_of(&out) };
        // SAFETY: as above.
        unsafe { drop_verdict(&mut out) };
        (rc, rows)
    }

    /// Ask the row topology door about a set, with optional names and external
    /// listeners. `names` is one entry per node: `Some(bytes)` or `None` for a
    /// NULL entry.
    unsafe fn ask_topology_rows(
        nodes: &[Vec<(&str, &str)>],
        names: Option<&[Option<Vec<u8>>]>,
        external: &[Vec<u8>],
    ) -> (ZResult, Vec<RowView>) {
        let configs: Vec<z_owned_config_t> = nodes
            .iter()
            // SAFETY: the caller's fixtures.
            .map(|n| unsafe { config_of(n) })
            .collect();
        let loaned: Vec<*const z_loaned_config_t> = configs
            .iter()
            // SAFETY: each is a live owned config.
            .map(|c| unsafe { z_config_loan(c) })
            .collect();
        let owned_names: Option<Vec<Option<CString>>> = names.map(|all| {
            all.iter()
                .map(|n| n.as_ref().map(|b| CString::new(b.clone()).expect("no NUL")))
                .collect()
        });
        let name_ptrs: Option<Vec<*const c_char>> = owned_names.as_ref().map(|all| {
            all.iter()
                .map(|n| n.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()))
                .collect()
        });
        let owned_ext: Vec<CString> = external
            .iter()
            .map(|e| CString::new(e.clone()).expect("no NUL"))
            .collect();
        let ext: Vec<*const c_char> = owned_ext.iter().map(|c| c.as_ptr()).collect();
        // SAFETY: a zeroed owned verdict is this ABI's gravestone.
        let mut out = unsafe { null_verdict() };
        // SAFETY: every array is valid for its own length; `out` is writable.
        let rc = unsafe {
            wz_capi_c_config_validate_topology_rows(
                loaned.as_ptr(),
                name_ptrs.as_ref().map_or(std::ptr::null(), |p| p.as_ptr()),
                loaned.len(),
                ext.as_ptr(),
                ext.len(),
                &mut out,
            )
        };
        // SAFETY: the door wrote a gravestone or a live verdict.
        let rows = unsafe { rows_of(&out) };
        // SAFETY: as above.
        unsafe { drop_verdict(&mut out) };
        (rc, rows)
    }

    fn bytes(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    /// The rows are the SAME verdict as the lines, not a second opinion: every
    /// finding's variant and message are what the string door wrote for it, in
    /// its order.
    fn assert_agrees_with_lines(rows: &[RowView], text: &str) {
        let mut findings: Vec<&RowView> = Vec::new();
        for row in rows {
            if findings.last().map(|r| r.finding) != Some(row.finding) {
                findings.push(row);
            }
        }
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(findings.len(), lines.len(), "{rows:?} vs {text:?}");
        for (row, line) in findings.iter().zip(lines) {
            assert_eq!(format!("{}: {}", row.variant, row.message), line);
        }
    }

    /// Ask 1 — the key path is its own column, and for a defect found
    /// in a config it sits next to the endpoint it is about.
    #[test]
    fn a_defect_in_one_config_names_the_key_it_is_about() {
        let entries = [
            ("listen/endpoints", "[\"nonsense\"]"),
            ("connect/endpoints", "[\"also-bad\"]"),
        ];
        // SAFETY: the fixtures and doors are this test's own.
        let (rc, rows) = unsafe { ask_rows(wz_capi_c_config_validate_rows, &entries) };
        assert_eq!(rc, Z_OK);
        assert_eq!(rows.len(), 2, "{rows:?}");
        for (row, (key, endpoint)) in rows.iter().zip([
            ("listen/endpoints", "nonsense"),
            ("connect/endpoints", "also-bad"),
        ]) {
            assert_eq!(row.variant, "MalformedEndpoint");
            assert_eq!(row.key.as_deref(), Some(key));
            assert_eq!(row.endpoint.as_deref(), Some(endpoint));
            assert_eq!(row.node, None, "a config judged alone has no name");
        }
        assert_ne!(rows[0].finding, rows[1].finding);

        // SAFETY: as above.
        let (_, text) = unsafe { ask(wz_capi_c_config_validate, &entries) };
        assert_agrees_with_lines(&rows, &text);
    }

    /// A defect that points at several places is ONE finding and several rows,
    /// and the reader can tell.
    #[test]
    fn a_defect_that_points_at_three_keys_is_one_finding_and_three_rows() {
        let entries = [("scouting/multicast/enabled", "false")];
        // SAFETY: the fixtures and doors are this test's own.
        let (rc, rows) = unsafe { ask_rows(wz_capi_c_config_validate_rows, &entries) };
        assert_eq!(rc, Z_OK);
        let keys: Vec<Option<&str>> = rows.iter().map(|r| r.key.as_deref()).collect();
        assert_eq!(
            keys,
            [
                Some("connect/endpoints"),
                Some("listen/endpoints"),
                Some("scouting/multicast/enabled")
            ]
        );
        assert!(rows
            .iter()
            .all(|r| r.finding == 0 && r.variant == "Unreachable"));

        // SAFETY: a live config and a writable out slot.
        let (count, ok) = unsafe {
            let cfg = config_of(&entries);
            let mut out = null_verdict();
            let rc = wz_capi_c_config_validate_rows(z_config_loan(&cfg), &mut out);
            let count = wz_capi_c_config_verdict_finding_count(wz_capi_c_config_verdict_loan(&out));
            drop_verdict(&mut out);
            (count, rc == Z_OK)
        };
        assert!(ok);
        assert_eq!(count, 1, "three rows, one defect");

        // SAFETY: as above.
        let (_, text) = unsafe { ask(wz_capi_c_config_validate, &entries) };
        assert_agrees_with_lines(&rows, &text);
    }

    /// The build-scoped door is the same verdict plus the one the reader adds.
    #[test]
    fn the_build_scoped_row_door_agrees_with_its_string_door() {
        let entries = [("listen/endpoints", "[\"tcp/127.0.0.1:17701\"]")];
        // SAFETY: the fixtures and doors are this test's own.
        let (rc, stock) = unsafe { ask_rows(wz_capi_c_config_validate_rows, &entries) };
        assert_eq!((rc, stock.len()), (Z_OK, 0), "{stock:?}");
        // SAFETY: as above.
        let (rc, build) = unsafe { ask_rows(wz_capi_c_config_validate_for_build_rows, &entries) };
        assert_eq!(rc, Z_OK);
        // SAFETY: as above.
        let (_, text) = unsafe { ask(wz_capi_c_config_validate_for_build, &entries) };
        assert_agrees_with_lines(&build, &text);
    }

    /// Ask 1, verbatim: a refusal is `Z_EPARSE` AND a row whose key is
    /// its own column, so an inspector can put the reason under the field.
    #[test]
    fn a_refused_config_answers_with_the_key_at_fault_beside_the_reason() {
        let entries = [("transport/link/tx/batch_size", "131072")];
        // SAFETY: the fixtures and doors are this test's own.
        let (rc, rows) = unsafe { ask_rows(wz_capi_c_config_validate_rows, &entries) };
        assert_eq!(rc, Z_EPARSE);
        assert_eq!(
            rows,
            vec![RowView {
                finding: 0,
                variant: String::from("OutOfRange"),
                message: String::from("transport/link/tx/batch_size value 131072 is out of range"),
                node: None,
                key: Some(String::from("transport/link/tx/batch_size")),
                endpoint: None,
            }]
        );
        // The string door said the same words, and still does.
        // SAFETY: as above.
        let (string_rc, text) = unsafe { ask(wz_capi_c_config_validate, &entries) };
        assert_eq!(
            (string_rc, text.as_str()),
            (Z_EPARSE, rows[0].message.as_str())
        );

        // An unknown mode blames `mode`, which the reader does not put in a
        // field of the error; the key column still has it.
        // SAFETY: as above.
        let (rc, rows) =
            unsafe { ask_rows(wz_capi_c_config_validate_rows, &[("mode", "\"gateway\"")]) };
        assert_eq!(rc, Z_EPARSE);
        assert_eq!(rows[0].variant, "UnknownMode");
        assert_eq!(rows[0].key.as_deref(), Some("mode"));

        // Two stored keys that cannot both be nested blame BOTH, in two rows of
        // one finding: the caller has to find what the loser conflicts with.
        // SAFETY: as above.
        let (rc, rows) = unsafe {
            ask_rows(
                wz_capi_c_config_validate_rows,
                &[("mode", "\"client\""), ("mode/router", "\"peer\"")],
            )
        };
        assert_eq!(rc, Z_EPARSE);
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(rows
            .iter()
            .all(|r| r.variant == "NestConflict" && r.finding == 0));
        let mut keys: Vec<&str> = rows.iter().filter_map(|r| r.key.as_deref()).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["mode", "mode/router"]);
    }

    /// No config at all is `Z_ENULL` and a row that says so, not a silence.
    #[test]
    fn a_null_config_answers_z_enull_with_a_row() {
        // SAFETY: a null config is the case under test; `out` is writable.
        unsafe {
            let mut out = null_verdict();
            let rc = wz_capi_c_config_validate_rows(std::ptr::null(), &mut out);
            assert_eq!(rc, Z_ENULL);
            let rows = rows_of(&out);
            assert_eq!(rows.len(), 1, "{rows:?}");
            assert_eq!(rows[0].variant, "NoConfig");
            assert_eq!(
                (rows[0].node.as_deref(), rows[0].key.as_deref()),
                (None, None)
            );
            drop_verdict(&mut out);
            // A null `out` is the one case with nowhere to write.
            assert_eq!(
                wz_capi_c_config_validate_rows(std::ptr::null(), std::ptr::null_mut()),
                Z_ENULL
            );
        }
    }

    /// Ask 2 — the nodes are named by the caller, and every defect
    /// spells the node the way it was named.
    #[test]
    fn a_topology_verdict_names_its_nodes_the_way_the_caller_did() {
        let nodes = vec![
            vec![
                ("mode", "\"client\""),
                ("connect/endpoints", "[\"tcp/192.0.2.9:17702\"]"),
                ("scouting/multicast/enabled", "false"),
            ],
            vec![
                ("mode", "\"router\""),
                ("listen/endpoints", "[\"tcp/192.0.2.5:17703\"]"),
                ("scouting/multicast/enabled", "false"),
            ],
        ];
        let names = [Some(bytes("edge-a")), Some(bytes("hub"))];
        // SAFETY: the fixtures and doors are this test's own.
        let (rc, rows) = unsafe { ask_topology_rows(&nodes, Some(&names), &[]) };
        assert_eq!(rc, Z_OK);
        assert_eq!(
            rows,
            vec![RowView {
                finding: 0,
                variant: String::from("DanglingConnectTarget"),
                message: rows[0].message.clone(),
                node: Some(String::from("edge-a")),
                key: Some(String::from("connect/endpoints")),
                endpoint: Some(String::from("tcp/192.0.2.9:17702")),
            }]
        );
        assert!(
            rows[0].message.starts_with("edge-a connects to"),
            "the prose names the node the same way: {}",
            rows[0].message
        );

        // The same set with no names is the string door's answer, index and
        // all; the string door itself is unchanged.
        // SAFETY: as above.
        let (rc, unnamed) = unsafe { ask_topology_rows(&nodes, None, &[]) };
        assert_eq!(rc, Z_OK);
        assert_eq!(unnamed[0].node.as_deref(), Some("node[0]"));
        let (string_rc, text) = topology_verdict_with_external(&nodes, &[]);
        assert_eq!(string_rc, Z_OK);
        assert_agrees_with_lines(&unnamed, &text);
    }

    /// A NULL entry leaves that node to its default name, and a defect about
    /// every node lists every node.
    #[test]
    fn a_null_name_falls_back_and_a_defect_about_every_node_lists_them_all() {
        let clients = vec![
            vec![
                ("id", "\"a1\""),
                ("mode", "\"client\""),
                ("scouting/multicast/enabled", "false"),
            ],
            vec![
                ("mode", "\"client\""),
                ("scouting/multicast/enabled", "false"),
            ],
            vec![
                ("mode", "\"client\""),
                ("scouting/multicast/enabled", "false"),
            ],
        ];
        let names = [None, None, Some(bytes("west"))];
        // SAFETY: the fixtures and doors are this test's own.
        let (rc, rows) = unsafe { ask_topology_rows(&clients, Some(&names), &[]) };
        assert_eq!(rc, Z_OK);
        assert!(
            rows.iter().all(|r| r.variant == "NoNodeAccepts"),
            "{rows:?}"
        );
        let nodes: Vec<Option<&str>> = rows.iter().map(|r| r.node.as_deref()).collect();
        assert_eq!(
            nodes,
            [Some("a1"), Some("node[1]"), Some("west")],
            "id, then position, and the caller's name"
        );
        assert!(rows
            .iter()
            .all(|r| r.key.as_deref() == Some("mode") && r.finding == 0));
        assert!(rows.iter().all(|r| r.endpoint.is_none()));
    }

    /// The external-declaration defects live in argv, so they have no node and
    /// no key — and are still one row each, not none.
    #[test]
    fn an_external_declaration_is_a_row_with_no_node_and_no_key() {
        let nodes = vec![
            vec![
                ("listen/endpoints", "[\"tcp/127.0.0.1:17704\"]"),
                ("scouting/multicast/enabled", "false"),
            ],
            vec![
                ("connect/endpoints", "[\"tcp/127.0.0.1:17704\"]"),
                ("scouting/multicast/enabled", "false"),
            ],
        ];
        let external = [bytes("tcp/127.0.0.1:17999"), bytes("not-an-endpoint")];
        // SAFETY: the fixtures and doors are this test's own.
        let (rc, rows) = unsafe { ask_topology_rows(&nodes, None, &external) };
        assert_eq!(rc, Z_OK);
        let mut variants: Vec<(&str, Option<&str>)> = rows
            .iter()
            .map(|r| (r.variant.as_str(), r.endpoint.as_deref()))
            .collect();
        variants.sort_unstable();
        assert_eq!(
            variants,
            [
                ("MalformedExternalListener", Some("not-an-endpoint")),
                ("UnusedExternalListener", Some("tcp/127.0.0.1:17999")),
            ]
        );
        assert!(rows.iter().all(|r| r.node.is_none() && r.key.is_none()));

        // And the row door and the string door agree about the whole verdict.
        let (string_rc, text) =
            topology_verdict_with_external(&nodes, &["tcp/127.0.0.1:17999", "not-an-endpoint"]);
        assert_eq!(string_rc, Z_OK);
        assert_agrees_with_lines(&rows, &text);
    }

    /// EVERY refusal in a call is reported, under the names the caller gave,
    /// and the verdict is not produced while any config is unreadable.
    #[test]
    fn every_refused_config_in_a_set_is_reported_under_its_name() {
        let nodes = vec![
            vec![("mode", "\"gateway\"")],
            vec![("listen/endpoints", "[\"tcp/127.0.0.1:17705\"]")],
            vec![("transport/link/tx/batch_size", "131072")],
        ];
        let names = [Some(bytes("west")), None, Some(bytes("east"))];
        // SAFETY: the fixtures and doors are this test's own.
        let (rc, rows) = unsafe { ask_topology_rows(&nodes, Some(&names), &[]) };
        assert_eq!(rc, Z_EPARSE, "the first refusal's code");
        assert_eq!(rows.len(), 2, "both refusals, and no verdict: {rows:?}");
        assert_eq!(
            (
                rows[0].variant.as_str(),
                rows[0].node.as_deref(),
                rows[0].key.as_deref()
            ),
            ("UnknownMode", Some("west"), Some("mode"))
        );
        assert_eq!(
            (
                rows[1].variant.as_str(),
                rows[1].node.as_deref(),
                rows[1].key.as_deref()
            ),
            (
                "OutOfRange",
                Some("east"),
                Some("transport/link/tx/batch_size")
            )
        );
        assert_ne!(rows[0].finding, rows[1].finding);

        // The string door stops at the FIRST, and says which by index.
        let (string_rc, text) = topology_verdict_with_external(&nodes, &[]);
        assert_eq!(string_rc, Z_EPARSE);
        assert!(text.starts_with("config 0: "), "{text}");
    }

    /// A caller's own arguments can be refused too, and each is a row that says
    /// which one, with the code the string door uses for the same fault.
    #[test]
    fn an_unusable_argument_is_refused_by_name() {
        let pair = vec![
            vec![("scouting/multicast/enabled", "false")],
            vec![("scouting/multicast/enabled", "false")],
        ];

        // SAFETY: the fixtures and doors are this test's own.
        let (rc, rows) = unsafe { ask_topology_rows(&pair, Some(&[Some(bytes("")), None]), &[]) };
        assert_eq!(rc, Z_EINVAL, "an empty name");
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].variant, "NameEmpty");
        assert_eq!(rows[0].node.as_deref(), Some("node[0]"));

        // SAFETY: as above.
        let (rc, rows) =
            unsafe { ask_topology_rows(&pair, Some(&[None, Some(vec![0xff, 0xfe])]), &[]) };
        assert_eq!(rc, Z_EPARSE, "a name that is not UTF-8");
        assert_eq!(rows[0].variant, "NameNotUtf8");
        assert_eq!(rows[0].node.as_deref(), Some("node[1]"));

        // SAFETY: as above.
        let (rc, rows) = unsafe { ask_topology_rows(&pair, None, &[vec![0xff, 0xfe]]) };
        assert_eq!(rc, Z_EPARSE, "an external declaration that is not UTF-8");
        assert_eq!(rows[0].variant, "ExternalNotUtf8");
        assert_eq!(
            (rows[0].node.as_deref(), rows[0].key.as_deref()),
            (None, None)
        );
    }

    /// Bad arguments that leave nowhere to write, or nothing to read, are the
    /// gravestone and `Z_ENULL`, exactly as the string doors have them.
    #[test]
    fn a_missing_array_is_z_enull_and_a_droppable_verdict() {
        // SAFETY: null arrays with a non-zero count are the case under test.
        unsafe {
            let mut out = null_verdict();
            let rc = wz_capi_c_config_validate_topology_rows(
                std::ptr::null(),
                std::ptr::null(),
                2,
                std::ptr::null(),
                0,
                &mut out,
            );
            assert_eq!(rc, Z_ENULL);
            assert!(!wz_capi_c_internal_config_verdict_check(&out));
            drop_verdict(&mut out);

            // A count of zero is a valid question with an empty answer.
            let rc = wz_capi_c_config_validate_topology_rows(
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                &mut out,
            );
            assert_eq!(rc, Z_OK);
            assert_eq!(rows_of(&out), Vec::new());
            assert!(wz_capi_c_internal_config_verdict_check(&out));
            drop_verdict(&mut out);

            assert_eq!(
                wz_capi_c_config_validate_topology_rows(
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                ),
                Z_ENULL
            );
        }
    }

    /// The handle's own contract: an index past the end and a null verdict
    /// answer with the code or `false` and an EMPTY view, a second drop is a
    /// no-op, and the gravestone checks as absent.
    #[test]
    fn the_accessors_and_the_handle_keep_their_contracts() {
        // SAFETY: the fixtures and doors are this test's own.
        unsafe {
            let cfg = config_of(&[("scouting/multicast/enabled", "false")]);
            let mut out = null_verdict();
            assert_eq!(
                wz_capi_c_config_validate_rows(z_config_loan(&cfg), &mut out),
                Z_OK
            );
            let loaned = wz_capi_c_config_verdict_loan(&out);
            let len = wz_capi_c_config_verdict_len(loaned);
            assert_eq!(len, 3);

            let mut view = empty_view();
            let mut n = 0usize;
            assert_eq!(
                wz_capi_c_config_verdict_row_variant(loaned, len, &mut view),
                Z_EINVAL
            );
            assert_eq!(text_of(&view), "");
            assert_eq!(
                wz_capi_c_config_verdict_row_message(loaned, len, &mut view),
                Z_EINVAL
            );
            assert_eq!(
                wz_capi_c_config_verdict_row_finding(loaned, len, &mut n),
                Z_EINVAL
            );
            assert!(!wz_capi_c_config_verdict_row_node(loaned, len, &mut view));
            assert!(!wz_capi_c_config_verdict_row_key(loaned, len, &mut view));
            assert!(!wz_capi_c_config_verdict_row_endpoint(
                loaned, len, &mut view
            ));
            assert_eq!(text_of(&view), "");

            // Null everywhere.
            let none = std::ptr::null();
            assert_eq!(wz_capi_c_config_verdict_len(none), 0);
            assert_eq!(wz_capi_c_config_verdict_finding_count(none), 0);
            assert_eq!(
                wz_capi_c_config_verdict_row_variant(none, 0, &mut view),
                Z_ENULL
            );
            assert_eq!(
                wz_capi_c_config_verdict_row_finding(none, 0, &mut n),
                Z_ENULL
            );
            assert!(!wz_capi_c_config_verdict_row_key(none, 0, &mut view));
            assert_eq!(
                wz_capi_c_config_verdict_row_variant(loaned, 0, std::ptr::null_mut()),
                Z_ENULL
            );

            // Drop is idempotent and leaves the gravestone.
            assert!(wz_capi_c_internal_config_verdict_check(&out));
            drop_verdict(&mut out);
            assert!(!wz_capi_c_internal_config_verdict_check(&out));
            drop_verdict(&mut out);
            wz_capi_c_config_verdict_drop(std::ptr::null_mut());
            wz_capi_c_internal_config_verdict_null(&mut out);
            assert!(!wz_capi_c_internal_config_verdict_check(&out));
        }
    }
}

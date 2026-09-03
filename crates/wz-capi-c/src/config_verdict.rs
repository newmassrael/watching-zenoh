// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2300 (open-debt item 631) — EMITTING a zenoh config and JUDGING one,
//! reachable from C.
//!
//! # The question this answers, and the verdict
//!
//! `wz-runtime-tokio`'s `zenoh_config` renders a stock-zenoh config document
//! and validates it — one node's values, this build's link schemes, and a
//! whole topology — and until this round NONE of that was reachable through a
//! C ABI. Measured at `5226af3c`: `to_json5`, `validate_topology` and
//! `validate_for_build` occur ZERO times across all four C ABI crates.
//!
//! The verdict is that the four doors BELONG here, and it rests on facts a
//! command produced rather than on a preference:
//!
//! 1. THE AXIS DOES NOT CONFLICT. The 2026-08-31 ruling was that the ANALYSIS
//!    surfaces carry no configuration door, and `analysis_surface_config_free`
//!    derives it. That gate's own refusal text names this crate as where such a
//!    door belongs — so honouring it here is what the ruling says to do, not an
//!    exception to it. The subjects differ: an analysis surface takes capture
//!    bytes and hands back documents; this crate already TAKES configuration.
//! 2. THE SURFACE IS ALREADY CONFIGURATION'S. Nineteen `extern "C"` config
//!    doors stand in this crate, seventeen of them upstream zenoh-c's own.
//! 3. THE DEPENDENCY IS ALREADY PAID. `wz-capi-c` names `zenoh-config`
//!    unconditionally in its `wz-runtime-tokio` dependency (R2172, item 548),
//!    so all four functions are ALREADY LINKED INTO THIS LIBRARY. What was
//!    missing is only the door, which is why "it would widen the graph" is not
//!    among the reasons above — it would have been false.
//!
//! # Why these are `wz_capi_c_` doors and not `zc_` ones
//!
//! Upstream zenoh-c has no validator. Its config surface is sixteen functions
//! at the pinned checkout and not one of them judges anything, so a `zc_`
//! spelling would claim a drop-in name for something a caller could not port
//! back. `wz_capi_c_layout` and `wz_capi_c_config_honoured` already set that
//! precedent in this crate: wz's OWN doors carry wz's prefix.
//!
//! Nor do they take a new handle type. They read the `z_owned_config_t` a
//! caller ALREADY built with `zc_config_from_file` / `zc_config_insert_json5`,
//! because a second config object would put the same document under two types
//! and hand a caller the job of keeping them in step.
//!
//! # THE TWO EMIT PATHS IN THIS TREE, and which one a caller wants
//!
//! This crate holds two, they answer different questions, and R2300 found them
//! not meeting:
//!
//!   * `zc_config_to_string` renders `ConfigState` — EXACTLY the keys THIS
//!     CALLER STATED, and nothing else. It is a round trip: what comes out
//!     re-inserts identically. It is upstream's door and answers upstream's
//!     question.
//!   * [`wz_capi_c_config_to_json5`] renders `ZenohNodeConfig` — the config a
//!     STOCK ZENOH NODE would have been started with, every honoured key
//!     RESOLVED, including the ones the caller never mentioned.
//!
//! # STATED versus RESOLVED, and R2303 corrected this paragraph
//!
//! Until then it said the difference was one of SPELLING — that the first door
//! answered flat and the second nested. That was true of wz and false of the
//! contract: upstream's `zc_config_to_string` emits a NESTED document and its
//! `zc_config_from_str` refuses a flat one, both measured, so wz's flat emit was
//! a defect (open-debt item 636) rather than the other half of a pair. BOTH
//! doors nest now.
//!
//! The difference that survives is what each one is ABOUT, and it is measured
//! rather than asserted — `the_two_emit_doors_differ_by_what_they_RESOLVE`
//! states it as a predicate. For a config stating two keys: the first door
//! emits two leaves in 82 bytes; the second emits thirteen in 560, eleven of
//! them keys the caller never wrote.
//!
//! A caller writing a file for a real zenoh node wants the second; a caller
//! echoing back what it configured wants the first. Neither is a copy of the
//! other, and this module is where they finally meet — `render_nested` feeds
//! `ConfigState`'s entries INTO `ZenohNodeConfig::from_json5`, so the reader
//! that resolves them is wz's one reader and not a second parse written here.
//!
//! # The defect lists are TEXT, and that is the SSOT choice
//!
//! Each validating door writes one defect per LINE and an empty string for a
//! clean config. A line is
//!
//! ```text
//! <VariantName>: <the defect's own Display>
//! ```
//!
//! and BOTH halves come from the defect itself — the name off `Debug`, the
//! message off `Display` — so this module spells no defect name and no defect
//! message of its own. A variant added upstream reaches a C caller with no edit
//! here, and a message reworded cannot drift between the two languages. A
//! struct-per-defect ABI would have frozen the shape of the enum into a header
//! and needed a version bump for every new reason a config can be wrong.
//!
//! THE NAME IS THERE BECAUSE THE MESSAGE ALONE IS NOT BRANCHABLE, and R2300
//! learned that from a red rather than by reasoning: the first draft emitted
//! `Display` alone, and a caller wanting to know whether it was looking at
//! `MalformedEndpoint` or `ProtocolNotCompiledIn` had nothing to read but
//! English prose that starts with the endpoint. A consumer told to match on
//! wording is a consumer holding a copy of wz's message catalogue, which is the
//! second copy this whole surface exists to remove. The name is the stable half
//! and the message is the readable one; both are wanted, so both are sent.
//!
//! Stability differs between the halves, and a caller should know which is
//! which: the NAME moves only when upstream renames a variant, and that is an
//! ABI-visible event. The MESSAGE is prose and may be reworded in any round.
//! Branch on the name; show the message.

use std::ffi::c_char;

use wz_runtime_tokio::zenoh_config::{
    validate_topology_with_external, ZenohNodeConfig, ZENOH_LINK_PROTOCOLS,
};

use crate::abi::{z_loaned_config_t, z_owned_string_t};
use crate::config::config_state;
use crate::ffi::guarded;
use crate::result::{ZResult, Z_ENULL, Z_EPARSE, Z_OK};

/// Read the `ZenohNodeConfig` a loaned config denotes, or say why not.
///
/// The whole bridge, and every door below goes through it so the three ways it
/// can fail are decided once. `render_nested` is what makes the two spellings
/// meet — see this module's header — and `from_json5` is wz's ONE reader of a
/// stock config document, called rather than reimplemented.
///
/// THE REASON TRAVELS WITH THE CODE, and that is not decoration. A caller
/// handed `Z_EPARSE` alone knows only that its config was refused, and both
/// refusals here name the exact key at fault — which key could not be nested,
/// or which one wz's reader does not accept. Dropping that text would leave a
/// consumer bisecting a config document by hand; the first draft of this
/// function did drop it, and the compiler caught it as a field nobody read.
///
/// # Safety
/// `config` must be null or a valid loaned config.
unsafe fn node_config(
    config: *const z_loaned_config_t,
) -> Result<ZenohNodeConfig, (ZResult, String)> {
    // SAFETY: the caller's contract; see `get_into` for the `const` cast, whose
    // argument this shares.
    let Some(state) = (unsafe { config_state(config as *mut z_loaned_config_t) }) else {
        return Err((Z_ENULL, String::from("no config")));
    };
    let nested = state
        .render_nested()
        .map_err(|conflict| (Z_EPARSE, conflict.to_string()))?;
    ZenohNodeConfig::from_json5(&nested)
        .map(|ingest| ingest.config)
        .map_err(|why| (Z_EPARSE, why.to_string()))
}

/// One defect as the line a C caller reads: `<VariantName>: <message>`.
///
/// The name is taken from `Debug`, which opens with the variant identifier for
/// every enum shape there is, rather than from a table here — a table would be
/// a second copy of the variant list and could name a variant that no longer
/// exists. Generic over both defect enums because the rule is the same for
/// each and a second copy of THIS would be the same mistake one level down.
fn defect_line<D: std::fmt::Debug + std::fmt::Display>(defect: &D) -> String {
    let debug = format!("{defect:?}");
    let name = debug
        .split(|c: char| c == '{' || c == '(' || c.is_whitespace())
        .next()
        .unwrap_or_default();
    format!("{name}: {defect}")
}

/// Every defect as the lines a C caller reads, one per line.
fn defect_lines<D: std::fmt::Debug + std::fmt::Display>(defects: &[D]) -> String {
    defects
        .iter()
        .map(defect_line)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Write `text` through `out`, after parking a gravestone there.
///
/// The gravestone goes down FIRST and unconditionally, which is the invariant
/// every string-returning door in this crate keeps: a caller that ignores the
/// `ZResult` still holds a droppable string rather than whatever was on its
/// stack.
///
/// # Safety
/// `out` must be valid and writable for a `z_owned_string_t`.
unsafe fn write_string(out: *mut z_owned_string_t, text: &str) -> ZResult {
    // SAFETY: the caller's contract.
    unsafe { *out = crate::string::owned_string_from(text.as_bytes()) };
    Z_OK
}

/// R2300 (open-debt item 631) — render the config a STOCK ZENOH NODE would
/// have been started with, as the json5 `zenohd -c` reads.
///
/// Not `zc_config_to_string`, and the module header says which of the two a
/// caller wants: that one echoes the keys this caller inserted, this one
/// resolves them into the document a real zenoh node reads.
///
/// If the result is written to a file for `zenohd -c`, that file MUST have a
/// `.json5`, `.json` or `.yaml` extension. zenoh dispatches its config parser
/// on the extension and panics outright on a file without one, BEFORE reading
/// a single byte — so nothing about the returned text can hint at the failure,
/// which is why it is stated at the door that hands the text over.
///
/// Returns `Z_ENULL` for a null argument, `Z_EPARSE` for a config whose keys
/// cannot be nested or which wz's reader refuses, and `Z_OK` otherwise. ON AN
/// ERROR THE STRING CARRIES THE REASON, naming the key at fault, so the text
/// is only a config document when the return is `Z_OK` — check it.
///
/// # Safety
/// `config` must be null or a valid loaned config; `out_config_string` must be
/// valid and writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_to_json5(
    config: *const z_loaned_config_t,
    out_config_string: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if out_config_string.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *out_config_string = crate::string::null_string() };
        // SAFETY: as above.
        let node = match unsafe { node_config(config) } {
            Ok(node) => node,
            Err((code, why)) => {
                // SAFETY: checked non-null above.
                unsafe { write_string(out_config_string, &why) };
                return code;
            }
        };
        // SAFETY: checked non-null above.
        unsafe { write_string(out_config_string, &node.to_json5()) }
    })
}

/// R2300 (open-debt item 631) — every reason this config cannot work, ONE PER
/// LINE, judged as a STOCK zenohd would.
///
/// An empty string is a clean verdict ON A `Z_OK` RETURN — and only there. A
/// config that could not be READ returns `Z_ENULL` / `Z_EPARSE` and writes the
/// reason into the same string, because a caller whose document is malformed
/// needs the key at fault more than it needs an empty list. Check the return
/// before reading the text as a verdict; an unchecked reader sees a defect it
/// does not recognise rather than a clean bill, which is the direction of that
/// mistake worth having.
///
/// Each line is a `ConfigDefect`'s own `Display`; see the module header for why
/// the list is text.
///
/// This asks the STOCK question — every link scheme zenoh carries is assumed
/// available — which is the right one when emitting a config FOR a zenoh node.
/// To ask whether THIS library could open the same config, use
/// [`wz_capi_c_config_validate_for_build`]; the two differ by exactly the
/// `ProtocolNotCompiledIn` verdict and by nothing else.
///
/// # Safety
/// `config` must be null or a valid loaned config; `out_defects` must be valid
/// and writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_validate(
    config: *const z_loaned_config_t,
    out_defects: *mut z_owned_string_t,
) -> ZResult {
    // SAFETY: the caller's contract, forwarded whole.
    unsafe { validate_into(config, out_defects, false) }
}

/// R2300 (open-debt item 631) — every reason this config cannot work FOR THIS
/// BUILD, one per line.
///
/// [`wz_capi_c_config_validate`] plus the one verdict that depends on who is
/// reading: an endpoint whose scheme this library was not compiled with
/// collects `ProtocolNotCompiledIn` here and nothing there. A caller standing
/// up a wz node from a config wants this door; a caller writing a config for a
/// stock zenohd wants the other, which is why the answer is two doors rather
/// than one door with a flag nobody would know how to set.
///
/// The scheme set is read from `wz_runtime_tokio::compiled_in_link_schemes`,
/// so it is THIS artifact's answer about itself and not a list spelled here.
///
/// # Safety
/// `config` must be null or a valid loaned config; `out_defects` must be valid
/// and writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_validate_for_build(
    config: *const z_loaned_config_t,
    out_defects: *mut z_owned_string_t,
) -> ZResult {
    // SAFETY: the caller's contract, forwarded whole.
    unsafe { validate_into(config, out_defects, true) }
}

/// The shared body of the two single-node validators.
///
/// One body rather than two, because the doors differ by ONE argument to
/// `validate_for_build` and a second copy would be free to drift from the
/// first in every other respect.
///
/// # Safety
/// As the callers'.
unsafe fn validate_into(
    config: *const z_loaned_config_t,
    out_defects: *mut z_owned_string_t,
    for_this_build: bool,
) -> ZResult {
    guarded(|| {
        if out_defects.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *out_defects = crate::string::null_string() };
        // SAFETY: as above.
        let node = match unsafe { node_config(config) } {
            Ok(node) => node,
            Err((code, why)) => {
                // SAFETY: checked non-null above.
                unsafe { write_string(out_defects, &why) };
                return code;
            }
        };
        let schemes = for_this_build.then(wz_runtime_tokio::compiled_in_link_schemes);
        let text = defect_lines(&node.validate_for_build(schemes));
        // SAFETY: checked non-null above.
        unsafe { write_string(out_defects, &text) }
    })
}

/// R2300 (open-debt item 631) — every reason this SET of configs cannot work
/// together, one per line.
///
/// The questions a single config cannot answer: a node dialling an endpoint
/// nobody listens on, two nodes claiming one address. Each node starts
/// cleanly and nothing attaches — the failure `ConfigDefect::Unreachable` calls
/// the most expensive to diagnose, one level up from where a per-node
/// validator can look.
///
/// `configs` is an array of `count` loaned configs. A count of zero is a valid
/// question with an empty answer; a null `configs` with a non-zero count is
/// `Z_ENULL`. Any element that is null or unreadable fails the whole call
/// rather than being skipped: a topology verdict over a SUBSET is a different
/// verdict, and silently narrowing the set is how a green answer stops meaning
/// anything.
///
/// This reads the set as CLOSED. For a set that attaches to a zenoh node this
/// deployment does not own, use
/// [`wz_capi_c_config_validate_topology_with_external`] — a closed reading of a
/// fragment reports every outward dial as dangling.
///
/// # Safety
/// `configs` must be null, or valid for reading `count` loaned-config pointers,
/// each null or valid; `out_defects` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_validate_topology(
    configs: *const *const z_loaned_config_t,
    count: usize,
    out_defects: *mut z_owned_string_t,
) -> ZResult {
    // SAFETY: the caller's contract, forwarded whole. An empty external list is
    // the closed reading, which is what `validate_topology` itself passes.
    unsafe {
        wz_capi_c_config_validate_topology_with_external(
            configs,
            count,
            std::ptr::null(),
            0,
            out_defects,
        )
    }
}

/// R2300 (open-debt item 631) — [`wz_capi_c_config_validate_topology`] for a
/// set that attaches to listeners THIS DEPLOYMENT DOES NOT OWN.
///
/// `external` is an array of `external_count` NUL-terminated endpoint strings —
/// the addresses of zenoh nodes somebody else runs. Declaring them changes
/// three verdicts, and each is a real failure of a real deployment:
///
///   * a dial answered by a declared listener is no longer dangling;
///   * a declaration ANSWERING NO DIAL is `UnusedExternalListener` — the
///     deployment believes it attaches somewhere it does not;
///   * a declaration the set ALREADY answers is `ExternalShadowsListener`, and
///     one that does not parse is `MalformedExternalListener`.
///
/// # Why this door exists rather than an exemption in a gate
///
/// Those three verdicts are unreachable through the closed door — it passes an
/// empty external list, so their loop runs zero times — and R2300's population
/// gate would then have needed a table saying "these three are out of scope".
/// A reason table is an escape hatch: it survives being wrong. Widening the
/// surface until every variant is reachable removes the question instead of
/// answering it, and the deployment it serves (a set of nodes attached to a
/// zenohd somebody else runs) is the most ordinary fragment there is.
///
/// # Safety
/// `configs` must be null, or valid for reading `count` loaned-config pointers,
/// each null or valid; `external` must be null, or valid for reading
/// `external_count` NUL-terminated C strings; `out_defects` must be valid and
/// writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_validate_topology_with_external(
    configs: *const *const z_loaned_config_t,
    count: usize,
    external: *const *const c_char,
    external_count: usize,
    out_defects: *mut z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if out_defects.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *out_defects = crate::string::null_string() };
        if (configs.is_null() && count != 0) || (external.is_null() && external_count != 0) {
            return Z_ENULL;
        }
        let mut nodes = Vec::with_capacity(count);
        for i in 0..count {
            // SAFETY: the caller's contract bounds `configs` at `count`.
            let entry = unsafe { *configs.add(i) };
            // SAFETY: as above; each element is null or a valid loaned config.
            match unsafe { node_config(entry) } {
                Ok(node) => nodes.push(node),
                Err((code, why)) => {
                    // WHICH element, because a set of eight configs and a bare
                    // "unreadable" is a bisection the caller should not have to
                    // run.
                    // SAFETY: checked non-null above.
                    unsafe { write_string(out_defects, &format!("config {i}: {why}")) };
                    return code;
                }
            }
        }
        let mut outside = Vec::with_capacity(external_count);
        for i in 0..external_count {
            // SAFETY: the caller's contract bounds `external` at its count.
            let raw = unsafe { *external.add(i) };
            if raw.is_null() {
                return Z_ENULL;
            }
            // SAFETY: a NUL-terminated string, by the caller's contract.
            match unsafe { std::ffi::CStr::from_ptr(raw) }.to_str() {
                Ok(text) => outside.push(String::from(text)),
                // NOT lossy-decoded: an endpoint is matched by STRING against
                // the configs', and a replacement character would compare
                // unequal to whatever the caller meant while looking plausible
                // in the report.
                Err(_) => {
                    // SAFETY: checked non-null above.
                    unsafe { write_string(out_defects, &format!("external {i}: not UTF-8")) };
                    return Z_EPARSE;
                }
            }
        }
        let text = defect_lines(&validate_topology_with_external(&nodes, &outside).defects);
        // SAFETY: checked non-null above.
        unsafe { write_string(out_defects, &text) }
    })
}

/// R2300 (open-debt item 631) — how many link schemes THIS BUILD can bind and
/// dial, and the name of each.
///
/// The door [`wz_capi_c_config_validate_for_build`] needs to be USABLE: a
/// caller told an endpoint's protocol is not compiled in has no way to pick a
/// working one without asking the artifact what it has. Spelling the answer in
/// the consumer would be the second copy the config surface exists to remove —
/// the argument `wz_capi_c_config_honoured` records for the honoured-key list,
/// applied to the other list a config caller needs.
///
/// Returns the count; `wz_capi_c_config_link_scheme` walks it. The names are
/// `'static` and must not be freed, exactly as the honoured keys are.
///
/// # Safety
/// None; takes no arguments and touches no memory.
#[no_mangle]
pub extern "C" fn wz_capi_c_config_link_scheme_count() -> usize {
    wz_runtime_tokio::compiled_in_link_schemes().len()
}

/// R2300 (open-debt item 631) — the NUL-terminated name of link scheme
/// `index`, or NULL past the end.
///
/// NULL past the end so the end of the list is a fact a caller can FIND rather
/// than a length it has to trust — the walk `wz_capi_c_config_honoured`
/// already teaches, kept identical here so a consumer writes the loop once.
///
/// # Safety
/// Takes no pointers; the returned pointer is `'static` and must not be freed.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_link_scheme(index: usize) -> *const c_char {
    use std::sync::OnceLock;
    static NUL_TERMINATED: OnceLock<Vec<std::ffi::CString>> = OnceLock::new();
    let table = NUL_TERMINATED.get_or_init(|| {
        wz_runtime_tokio::compiled_in_link_schemes()
            .iter()
            // The schemes are ASCII literals from a `const`, so the only way
            // this could fail is an embedded NUL nobody can write by accident.
            .map(|s| std::ffi::CString::new(*s).expect("a link scheme has no interior NUL"))
            .collect()
    });
    table.get(index).map_or(std::ptr::null(), |s| s.as_ptr())
}

/// R2300 (open-debt item 631) — how many link schemes STOCK ZENOH carries, and
/// the name of each.
///
/// The other half of the pair above, and the reason both are needed: the
/// difference between the two lists is exactly the set of endpoints a stock
/// zenohd would accept and THIS build would refuse, which is the population
/// `wz_capi_c_config_validate_for_build` discriminates on. A consumer holding
/// only one list cannot compute it.
///
/// # Safety
/// None; takes no arguments and touches no memory.
#[no_mangle]
pub extern "C" fn wz_capi_c_config_zenoh_link_scheme_count() -> usize {
    ZENOH_LINK_PROTOCOLS.len()
}

/// R2300 (open-debt item 631) — the NUL-terminated name of stock zenoh's link
/// scheme `index`, or NULL past the end.
///
/// # Safety
/// Takes no pointers; the returned pointer is `'static` and must not be freed.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_config_zenoh_link_scheme(index: usize) -> *const c_char {
    use std::sync::OnceLock;
    static NUL_TERMINATED: OnceLock<Vec<std::ffi::CString>> = OnceLock::new();
    let table = NUL_TERMINATED.get_or_init(|| {
        ZENOH_LINK_PROTOCOLS
            .iter()
            .map(|s| std::ffi::CString::new(*s).expect("a link scheme has no interior NUL"))
            .collect()
    });
    table.get(index).map_or(std::ptr::null(), |s| s.as_ptr())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;
    use std::ffi::CString;

    use wz_runtime_tokio::zenoh_config::{ConfigDefect, TopologyDefect};

    use crate::abi::{z_moved_string_t, z_owned_config_t};
    use crate::config::{
        z_config_default, z_config_loan, z_config_loan_mut, zc_config_insert_json5,
    };
    use crate::string::z_string_drop;

    /// Build an owned config exactly as a C caller does — `z_config_default`
    /// then one `zc_config_insert_json5` per key.
    ///
    /// Deliberately NOT by reaching into `ConfigState`: the doors under test
    /// are reached through the C surface, and a fixture that built the state
    /// directly would skip the insert parser these keys actually pass through.
    unsafe fn config_of(entries: &[(&str, &str)]) -> z_owned_config_t {
        // SAFETY: a zeroed owned config is the gravestone this ABI defines.
        let mut cfg: z_owned_config_t = unsafe { std::mem::zeroed() };
        // SAFETY: a writable owned slot.
        assert_eq!(unsafe { z_config_default(&mut cfg) }, Z_OK);
        for (key, value) in entries {
            let k = CString::new(*key).expect("key has no NUL");
            let v = CString::new(*value).expect("value has no NUL");
            // SAFETY: a live config and two NUL-terminated strings.
            let rc = unsafe {
                zc_config_insert_json5(z_config_loan_mut(&mut cfg), k.as_ptr(), v.as_ptr())
            };
            assert_eq!(rc, Z_OK, "the C insert path refused {key} = {value}");
        }
        cfg
    }

    /// Read an owned string out and free it, the way a C caller must.
    unsafe fn take_text(out: &mut z_owned_string_t) -> String {
        let text = if out.ptr.is_null() {
            String::new()
        } else {
            // SAFETY: an owned string this crate minted, `len` bytes long.
            let bytes = unsafe { std::slice::from_raw_parts(out.ptr, out.len) };
            String::from_utf8(bytes.to_vec()).expect("wz emits UTF-8")
        };
        // SAFETY: a live owned string; freeing it is the caller's contract.
        unsafe { z_string_drop((out as *mut z_owned_string_t).cast::<z_moved_string_t>()) };
        text
    }

    /// Call a single-config door and hand back what a C caller would see.
    unsafe fn ask(
        door: unsafe extern "C" fn(*const z_loaned_config_t, *mut z_owned_string_t) -> ZResult,
        entries: &[(&str, &str)],
    ) -> (ZResult, String) {
        // SAFETY: the caller's fixture.
        let cfg = unsafe { config_of(entries) };
        // SAFETY: a zeroed owned string is this ABI's gravestone.
        let mut out: z_owned_string_t = unsafe { std::mem::zeroed() };
        // SAFETY: a live owned config and a writable out slot.
        let rc = unsafe { door(z_config_loan(&cfg), &mut out) };
        // SAFETY: the door wrote a gravestone or a live string.
        (rc, unsafe { take_text(&mut out) })
    }

    /// The variant NAME out of one line the doors emitted.
    ///
    /// Reads the door's own `<Name>: <message>` split rather than re-deriving
    /// the name from an enum value, because what is under test is the LINE a C
    /// caller receives. A test that recomputed the name from the enum would
    /// pass even if the door emitted nothing but prose — which is exactly the
    /// red that put the name there.
    ///
    /// The message half is required to be non-empty: a line that is a bare name
    /// would be branchable and unreadable, and the door promises both.
    fn variant_of(line: &str) -> String {
        let (name, message) = line
            .split_once(": ")
            .unwrap_or_else(|| panic!("a defect line must be `<Name>: <message>`, got {line:?}"));
        assert!(
            !message.trim().is_empty(),
            "a defect line must carry a message, got {line:?}"
        );
        assert!(
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric()),
            "a defect line must open with a bare variant name, got {line:?}"
        );
        name.to_owned()
    }

    /// Every name a scheme door publishes, walked the way a C caller walks it.
    fn walk(count: usize, name: unsafe extern "C" fn(usize) -> *const c_char) -> BTreeSet<String> {
        (0..count)
            .map(|i| {
                // SAFETY: `i` is below the count the same library reported.
                let p = unsafe { name(i) };
                assert!(!p.is_null(), "the walk must reach index {i}");
                // SAFETY: a `'static` NUL-terminated name.
                unsafe { std::ffi::CStr::from_ptr(p) }
                    .to_str()
                    .expect("ASCII scheme name")
                    .to_owned()
            })
            .collect()
    }

    /// Schemes stock zenoh carries that THIS BUILD does not, read from the two
    /// doors that publish them.
    ///
    /// The population for `ProtocolNotCompiledIn`, DERIVED rather than spelled:
    /// which schemes are absent is a property of the feature set this test was
    /// compiled with, and a literal would go stale the moment a leg turned one
    /// on.
    fn schemes_this_build_lacks() -> Vec<String> {
        let stock = walk(
            wz_capi_c_config_zenoh_link_scheme_count(),
            wz_capi_c_config_zenoh_link_scheme,
        );
        let mine = walk(
            wz_capi_c_config_link_scheme_count(),
            wz_capi_c_config_link_scheme,
        );
        assert!(!stock.is_empty(), "the stock scheme door reported nothing");
        assert!(
            !mine.is_empty(),
            "this build's scheme door reported nothing"
        );
        stock.difference(&mine).cloned().collect()
    }

    /// Ask the topology door about a set of configs and a list of external
    /// listeners.
    fn topology_verdict_with_external(
        nodes: &[Vec<(&str, &str)>],
        external: &[&str],
    ) -> (ZResult, String) {
        // Held in bindings for the whole call: the pointers below borrow these.
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
        let owned: Vec<CString> = external
            .iter()
            .map(|e| CString::new(*e).expect("endpoint has no NUL"))
            .collect();
        let ext: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
        // SAFETY: a zeroed owned string is this ABI's gravestone.
        let mut out: z_owned_string_t = unsafe { std::mem::zeroed() };
        // SAFETY: both arrays are valid for their own lengths and `out` is
        // writable.
        let rc = unsafe {
            wz_capi_c_config_validate_topology_with_external(
                loaned.as_ptr(),
                loaned.len(),
                ext.as_ptr(),
                ext.len(),
                &mut out,
            )
        };
        // SAFETY: the door wrote a gravestone or a live string.
        (rc, unsafe { take_text(&mut out) })
    }

    /// Ask the CLOSED topology door about a set of configs.
    fn topology_verdict(nodes: &[Vec<(&str, &str)>]) -> (ZResult, String) {
        // Held in a binding for the whole call: the loaned pointers below
        // borrow these, and building them inline would drop each config before
        // the door read it.
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
        // SAFETY: a zeroed owned string is this ABI's gravestone.
        let mut out: z_owned_string_t = unsafe { std::mem::zeroed() };
        // SAFETY: `loaned` is valid for its own length and `out` is writable.
        let rc =
            unsafe { wz_capi_c_config_validate_topology(loaned.as_ptr(), loaned.len(), &mut out) };
        // SAFETY: the door wrote a gravestone or a live string.
        (rc, unsafe { take_text(&mut out) })
    }

    /// R2300 (open-debt item 631) — EVERY `ConfigDefect` VARIANT `validate` CAN
    /// RAISE IS RAISED THROUGH THE C DOOR.
    ///
    /// The population is the enum's, not this test's: `variant_of` reads names
    /// off `Debug`, and `capi_c_config_verdict_population.py` derives the
    /// variant list from the module that DEFINES it and reds on one no case
    /// here reaches. A test asserting "some defects came back" would pass on
    /// one working rule and eight broken ones, which is the vacuity the
    /// consumer asked to be protected from by name.
    ///
    /// `ProtocolNotCompiledIn` is absent here and present in the build-scoped
    /// test below — it is the one verdict `validate` cannot raise, by
    /// construction, and the pair of tests is what pins that.
    #[test]
    fn every_stock_config_defect_is_reachable_through_the_c_door() {
        let listen_one = ("listen/endpoints", "[\"tcp/127.0.0.1:17447\"]");
        // (the config, the variant it must raise)
        let cases: Vec<(Vec<(&str, &str)>, &str)> = vec![
            (
                vec![("listen/endpoints", "[\"nonsense\"]")],
                "MalformedEndpoint",
            ),
            (
                vec![("listen/endpoints", "[\"carrier-pigeon/1.2.3.4:1\"]")],
                "UnknownProtocol",
            ),
            (
                vec![(
                    "listen/endpoints",
                    "[\"tcp/127.0.0.1:17447\",\"tcp/127.0.0.1:17447\"]",
                )],
                "DuplicateListenEndpoint",
            ),
            (vec![("scouting/multicast/enabled", "false")], "Unreachable"),
            (
                vec![
                    listen_one,
                    ("transport/unicast/qos/enabled", "true"),
                    ("transport/unicast/lowlatency", "true"),
                ],
                "QosWithLowlatency",
            ),
            (
                vec![listen_one, ("transport/link/tx/batch_size", "0")],
                "ZeroBatchSize",
            ),
            (
                vec![listen_one, ("transport/link/tx/lease", "0")],
                "ZeroLease",
            ),
            (
                vec![listen_one, ("transport/unicast/max_links", "0")],
                "ZeroMaxLinks",
            ),
        ];
        assert!(!cases.is_empty(), "a population of zero proves nothing");

        let mut covered = BTreeSet::new();
        for (entries, want) in &cases {
            // SAFETY: a fixture config and a stack out slot.
            let (rc, text) = unsafe { ask(wz_capi_c_config_validate, entries) };
            assert_eq!(rc, Z_OK, "{want}: the door refused the config: {text}");
            let raised: BTreeSet<String> = text.lines().map(variant_of).collect();
            assert!(
                raised.contains(*want),
                "{want}: the C door reported {raised:?} instead"
            );
            covered.extend(raised);
        }

        // The CLEAN control: a config with none of the defects must come back
        // empty, or "the door reports defects" would be as well explained by a
        // door that reports them unconditionally.
        // SAFETY: a fixture config and a stack out slot.
        let (rc, text) = unsafe {
            ask(
                wz_capi_c_config_validate,
                &[listen_one, ("scouting/multicast/enabled", "false")],
            )
        };
        assert_eq!(rc, Z_OK);
        assert_eq!(text, "", "a clean config must produce an empty verdict");

        // What the doors reached, printed so the population gate can be read
        // against a run rather than only against the source.
        println!("config defects reached through the C door: {covered:?}");
    }

    /// R2300 (open-debt item 631) — `ProtocolNotCompiledIn` IS THE DIFFERENCE
    /// BETWEEN THE TWO DOORS, over a population this build derives about
    /// itself.
    ///
    /// The discriminating shape the consumer asked for: a build carrying EVERY
    /// scheme would make `validate_for_build` identical to `validate` and this
    /// test vacuous, so the schemes are read from the artifact's own doors and
    /// an empty difference FAILS rather than passing quietly. Measured at
    /// R2300: default features carry `tcp` and `udp` of stock zenoh's nine, so
    /// the difference is seven.
    ///
    /// Both directions are asserted on the SAME config, which is what makes
    /// this a control rather than two observations: the build-scoped door must
    /// raise the verdict and the stock-scoped door must not.
    #[test]
    fn a_scheme_this_build_lacks_is_a_defect_only_for_this_build() {
        let absent = schemes_this_build_lacks();
        assert!(
            !absent.is_empty(),
            "this build carries every scheme stock zenoh does, so \
             validate_for_build has no discriminating power here and this test \
             would pass vacuously"
        );

        for scheme in &absent {
            let endpoint = format!("[\"{scheme}/127.0.0.1:17447\"]");
            let entries = vec![("listen/endpoints", endpoint.as_str())];

            // SAFETY: a fixture config and a stack out slot.
            let (rc, text) = unsafe { ask(wz_capi_c_config_validate_for_build, &entries) };
            assert_eq!(rc, Z_OK, "{scheme}: the door refused the config: {text}");
            let raised: BTreeSet<String> = text.lines().map(variant_of).collect();
            assert!(
                raised.contains("ProtocolNotCompiledIn"),
                "{scheme}: this build cannot bind it, so the build-scoped door \
                 must say so; it reported {raised:?}"
            );

            // THE CONTROL: the stock question about the same config.
            // SAFETY: a fixture config and a stack out slot.
            let (rc, text) = unsafe { ask(wz_capi_c_config_validate, &entries) };
            assert_eq!(rc, Z_OK);
            let stock: BTreeSet<String> = text.lines().map(variant_of).collect();
            assert!(
                !stock.contains("ProtocolNotCompiledIn"),
                "{scheme}: a stock zenohd carries it, so the stock-scoped door \
                 must not raise it; it reported {stock:?}"
            );
        }
        println!("schemes this build lacks: {absent:?}");
    }

    /// R2300 (open-debt item 631) — EVERY ONE OF `TopologyDefect`'S SIX
    /// VARIANTS IS RAISED THROUGH THE C DOORS, over sets of MORE THAN ONE node.
    ///
    /// # Six and not three, and that is why the second door exists
    ///
    /// Three of the variants — `UnusedExternalListener`,
    /// `ExternalShadowsListener`, `MalformedExternalListener` — come from a
    /// loop over the EXTERNAL listener list, which the closed door passes empty.
    /// With only that door they would have been unreachable, and this test
    /// would have needed a table saying "those three are out of scope". A
    /// reason table survives being wrong, so R2300 widened the surface instead:
    /// `wz_capi_c_config_validate_topology_with_external` makes them reachable
    /// and the exemption unnecessary. The population gate can then be a plain
    /// difference against the enum with nothing to excuse.
    #[test]
    fn every_topology_defect_is_raised_through_the_c_door() {
        // Two nodes minimum in every case — a one-node set cannot pose a set
        // question, which is the vacuity the consumer named.
        // (the nodes, the external listeners, the variant it must raise)
        /// One case: the nodes (each a list of config entries), the external
        /// listeners declared alongside them, and the variant it must raise.
        type Case<'a> = (Vec<Vec<(&'a str, &'a str)>>, Vec<&'a str>, &'a str);
        let cases: Vec<Case<'_>> = vec![
            (
                vec![
                    vec![("listen/endpoints", "[\"tcp/127.0.0.1:17451\"]")],
                    vec![("connect/endpoints", "[\"tcp/127.0.0.1:19999\"]")],
                ],
                vec![],
                "DanglingConnectTarget",
            ),
            (
                // A ROUTABLE literal, and R2300 measured why it has to be:
                // `pins_one_machine` returns false for loopback, because
                // `127.0.0.1:7447` on two machines is two separate working
                // binds and not a collision at all. A fixture on `127.0.0.1`
                // therefore cannot raise this verdict however many nodes claim
                // it — the first draft of this case used one and the door
                // correctly reported nothing. `192.0.2.0/24` is RFC 5737
                // TEST-NET-1, reserved for documentation, so nothing here can
                // route anywhere real.
                vec![
                    vec![("listen/endpoints", "[\"tcp/192.0.2.10:17452\"]")],
                    vec![("listen/endpoints", "[\"tcp/192.0.2.10:17452\"]")],
                ],
                vec![],
                "ListenEndpointCollision",
            ),
            (
                // EVERY node a client, which is the condition — a client binds
                // no listener, so a set of nothing but clients has nobody to
                // attach to. Measured at R2300: the mode is what decides this,
                // not the absence of endpoints, and a first draft that left the
                // mode at its default got `DanglingConnectTarget` instead.
                // Neither node dials, so that verdict cannot mask this one.
                vec![
                    vec![
                        ("mode", "\"client\""),
                        ("scouting/multicast/enabled", "false"),
                    ],
                    vec![
                        ("mode", "\"client\""),
                        ("scouting/multicast/enabled", "false"),
                    ],
                ],
                vec![],
                "NoNodeAccepts",
            ),
            (
                // A declared listener NOBODY dials: the deployment believes it
                // attaches somewhere it does not.
                vec![
                    vec![("listen/endpoints", "[\"tcp/127.0.0.1:17456\"]")],
                    vec![("connect/endpoints", "[\"tcp/127.0.0.1:17456\"]")],
                ],
                vec!["tcp/127.0.0.1:17999"],
                "UnusedExternalListener",
            ),
            (
                // A declaration the set ALREADY answers — the operator named an
                // outside node for an address one of their own nodes binds.
                vec![
                    vec![("listen/endpoints", "[\"tcp/127.0.0.1:17457\"]")],
                    vec![("connect/endpoints", "[\"tcp/127.0.0.1:17457\"]")],
                ],
                vec!["tcp/127.0.0.1:17457"],
                "ExternalShadowsListener",
            ),
            (
                // A declaration that is not an endpoint at all.
                vec![
                    vec![("listen/endpoints", "[\"tcp/127.0.0.1:17458\"]")],
                    vec![("connect/endpoints", "[\"tcp/127.0.0.1:17458\"]")],
                ],
                vec!["not-an-endpoint"],
                "MalformedExternalListener",
            ),
        ];
        assert!(!cases.is_empty(), "a population of zero proves nothing");

        let mut covered = BTreeSet::new();
        for (nodes, external, want) in &cases {
            assert!(
                nodes.len() >= 2,
                "{want}: a topology verdict needs more than one node"
            );
            let (rc, text) = topology_verdict_with_external(nodes, external);
            assert_eq!(rc, Z_OK, "{want}: the door refused the set: {text}");
            let raised: BTreeSet<String> = text.lines().map(variant_of).collect();
            assert!(
                raised.contains(*want),
                "{want}: the C door reported {raised:?} instead"
            );
            covered.extend(raised);
        }

        // The CLEAN control: a listener and a dialler that reaches it.
        let (rc, text) = topology_verdict(&[
            vec![("listen/endpoints", "[\"tcp/127.0.0.1:17454\"]")],
            vec![("connect/endpoints", "[\"tcp/127.0.0.1:17454\"]")],
        ]);
        assert_eq!(rc, Z_OK);
        assert_eq!(text, "", "a workable pair must produce an empty verdict");

        // AND the clean control for the external door, which is a different
        // claim: a fragment whose outward dial is answered by a declaration
        // must ALSO come back empty, or the three external verdicts above would
        // be as well explained by "declaring anything raises something".
        let (rc, text) = topology_verdict_with_external(
            &[
                vec![("connect/endpoints", "[\"tcp/127.0.0.1:17460\"]")],
                vec![("connect/endpoints", "[\"tcp/127.0.0.1:17460\"]")],
            ],
            &["tcp/127.0.0.1:17460"],
        );
        assert_eq!(rc, Z_OK);
        assert_eq!(
            text, "",
            "a fragment attached to a declared listener must be clean"
        );

        println!("topology defects reached through the C door: {covered:?}");
    }

    /// R2300 (open-debt item 631) — the closed door and the external door give
    /// the SAME verdict when the external list is empty.
    ///
    /// The closed door forwards to the wide one with an empty list, and this is
    /// what holds that forwarding honest: a caller must be able to reach for
    /// either without the answer changing under it. Asserted over a set that
    /// actually raises a defect, since two empty strings would agree for the
    /// wrong reason.
    #[test]
    fn the_closed_door_is_the_external_door_with_nothing_declared() {
        let nodes = vec![
            vec![("listen/endpoints", "[\"tcp/127.0.0.1:17461\"]")],
            vec![("connect/endpoints", "[\"tcp/127.0.0.1:19998\"]")],
        ];
        let (closed_rc, closed) = topology_verdict(&nodes);
        let (wide_rc, wide) = topology_verdict_with_external(&nodes, &[]);
        assert_eq!(closed_rc, wide_rc);
        assert_eq!(closed, wide);
        assert!(
            !closed.is_empty(),
            "this set must raise something, or the agreement is vacuous"
        );
    }

    /// R2300 (open-debt item 631) — the emitted document is the NESTED one wz's
    /// own reader takes back, values intact.
    ///
    /// The string half of the emit claim, and deliberately NOT a substitute for
    /// the other half: a round trip through wz's own reader proves only that wz
    /// agrees with itself. Whether a REAL zenohd reads it is
    /// `wz_capi_c_config_to_json5_starts_a_real_zenohd`, in this crate's
    /// `tests/`.
    #[test]
    fn the_emitted_document_round_trips_through_wzs_own_reader() {
        // SAFETY: a fixture config and a stack out slot.
        let (rc, json5) = unsafe {
            ask(
                wz_capi_c_config_to_json5,
                &[
                    ("mode", "\"client\""),
                    ("listen/endpoints", "[\"tcp/127.0.0.1:17455\"]"),
                ],
            )
        };
        assert_eq!(rc, Z_OK, "the door refused: {json5}");
        let back = ZenohNodeConfig::from_json5(&json5).expect("wz reads its own emit");
        assert_eq!(
            back.config.listen,
            vec![String::from("tcp/127.0.0.1:17455")]
        );
        assert!(
            back.named.contains(&"listen/endpoints"),
            "the emit must NAME the endpoint key; it named {:?}",
            back.named
        );
    }

    /// R2303 (open-debt item 636) — the two emit doors differ by what they
    /// RESOLVE, and this is the module header's claim as a predicate.
    ///
    /// That header used to say they differed by SPELLING — flat versus nested —
    /// and item 636 measured upstream and refuted it: upstream's
    /// `zc_config_to_string` nests and refuses a flat document, so wz's flat
    /// emit was a defect rather than the other half of a pair. BOTH doors nest
    /// now, and a header sentence that nothing measures is how the first claim
    /// survived four rounds. This runs.
    ///
    /// The population is DERIVED from the fixture: whatever keys are stated
    /// below are the set the first door must emit EXACTLY, and the set the
    /// second must strictly exceed. Adding a key to the fixture extends both
    /// halves with no edit here, and an empty fixture fails rather than passing
    /// on two empty leaf sets.
    #[test]
    fn the_two_emit_doors_differ_by_what_they_resolve() {
        use wz_runtime_tokio::json5;

        const STATED: &[(&str, &str)] = &[
            ("mode", "\"router\""),
            ("listen/endpoints", "[\"tcp/127.0.0.1:17457\"]"),
        ];
        assert!(
            !STATED.is_empty(),
            "an empty fixture makes both comparisons below vacuous"
        );
        let stated: BTreeSet<&str> = STATED.iter().map(|(k, _)| *k).collect();

        let leaves = |text: &str| -> BTreeSet<String> {
            json5::parse(text)
                .unwrap_or_else(|e| panic!("a door emitted unreadable json5: {e}\n{text}"))
                .leaf_paths()
                .into_iter()
                .collect()
        };

        // SAFETY: a fixture config and a stack out slot.
        let (rc, echoed) = unsafe { ask(crate::config::zc_config_to_string, STATED) };
        assert_eq!(rc, Z_OK, "the echo door refused: {echoed}");
        let echoed: BTreeSet<String> = leaves(&echoed);
        let want: BTreeSet<String> = stated.iter().map(|k| (*k).to_owned()).collect();
        assert_eq!(
            echoed, want,
            "zc_config_to_string must emit EXACTLY the stated keys"
        );

        // SAFETY: as above.
        let (rc, resolved) = unsafe { ask(wz_capi_c_config_to_json5, STATED) };
        assert_eq!(rc, Z_OK, "the resolving door refused: {resolved}");
        let resolved: BTreeSet<String> = leaves(&resolved);
        assert!(
            resolved.is_superset(&want),
            "the resolving door must still carry every stated key; it emitted {resolved:?}"
        );
        let unstated: BTreeSet<&String> = resolved.difference(&want).collect();
        assert!(
            !unstated.is_empty(),
            "the resolving door emitted only the stated keys, so it RESOLVED nothing \
             and the two doors are not distinguishable by this test"
        );
    }

    /// R2300 (open-debt item 631) — a config the doors cannot read is refused
    /// WITH THE REASON, not with an empty verdict.
    ///
    /// The direction that matters: an unreadable config returning `Z_OK` and an
    /// empty defect list would tell a caller its broken document is fine. Both
    /// halves are asserted — a non-`Z_OK` return AND text naming the key —
    /// because either alone is survivable and the pair is what makes the
    /// refusal usable.
    #[test]
    fn an_unreadable_config_is_refused_with_the_key_that_broke_it() {
        // A key whose path runs through another key's leaf: `mode` is a scalar
        // and `mode/router` needs it to be an object.
        let entries = [("mode", "\"client\""), ("mode/router", "\"peer\"")];
        for door in [
            wz_capi_c_config_to_json5,
            wz_capi_c_config_validate,
            wz_capi_c_config_validate_for_build,
        ] {
            // SAFETY: a fixture config and a stack out slot.
            let (rc, text) = unsafe { ask(door, &entries) };
            assert_ne!(rc, Z_OK, "an unreadable config must not return Z_OK");
            assert!(
                text.contains("mode/router"),
                "the refusal must name the key at fault, got {text:?}"
            );
        }
    }

    /// R2300 (open-debt item 631) — a null config is `Z_ENULL` at every door,
    /// and a null out slot is refused rather than written through.
    #[test]
    fn the_doors_refuse_null_rather_than_dereferencing_it() {
        for door in [
            wz_capi_c_config_to_json5,
            wz_capi_c_config_validate,
            wz_capi_c_config_validate_for_build,
        ] {
            // SAFETY: a zeroed owned string is this ABI's gravestone.
            let mut out: z_owned_string_t = unsafe { std::mem::zeroed() };
            // SAFETY: a null config is explicitly in the contract.
            let rc = unsafe { door(std::ptr::null(), &mut out) };
            assert_eq!(rc, Z_ENULL);
            // SAFETY: the door wrote a gravestone.
            let _ = unsafe { take_text(&mut out) };
            // SAFETY: a null out slot is explicitly in the contract.
            let rc = unsafe { door(std::ptr::null(), std::ptr::null_mut()) };
            assert_eq!(rc, Z_ENULL);
        }
        // SAFETY: a zeroed owned string is this ABI's gravestone.
        let mut out: z_owned_string_t = unsafe { std::mem::zeroed() };
        // SAFETY: a null array with a non-zero count is in the contract.
        let rc = unsafe { wz_capi_c_config_validate_topology(std::ptr::null(), 3, &mut out) };
        assert_eq!(rc, Z_ENULL);
        // SAFETY: the door wrote a gravestone.
        let _ = unsafe { take_text(&mut out) };

        // An EMPTY set is a valid question with an empty answer, which is a
        // different case from a null one and must not be refused with it.
        // SAFETY: a zeroed owned string is this ABI's gravestone.
        let mut out: z_owned_string_t = unsafe { std::mem::zeroed() };
        // SAFETY: count zero reads nothing through the pointer.
        let rc = unsafe { wz_capi_c_config_validate_topology(std::ptr::null(), 0, &mut out) };
        assert_eq!(rc, Z_OK);
        // SAFETY: the door wrote an empty owned string.
        assert_eq!(unsafe { take_text(&mut out) }, "");
    }

    /// R2300 (open-debt item 631) — the two scheme walks END, and end where
    /// their own counts say.
    ///
    /// The walk contract `wz_capi_c_config_honoured` teaches: NULL past the
    /// end, so a caller can FIND the end rather than trust the count. Asserted
    /// for both doors because a consumer writes one loop for both.
    #[test]
    fn the_scheme_walks_end_with_null() {
        let doors: [(usize, unsafe extern "C" fn(usize) -> *const c_char); 2] = [
            (
                wz_capi_c_config_link_scheme_count(),
                wz_capi_c_config_link_scheme,
            ),
            (
                wz_capi_c_config_zenoh_link_scheme_count(),
                wz_capi_c_config_zenoh_link_scheme,
            ),
        ];
        for (count, name) in doors {
            assert!(count > 0, "a door reporting no schemes proves nothing");
            for i in 0..count {
                // SAFETY: `i` is below the door's own count.
                assert!(!unsafe { name(i) }.is_null(), "index {i} must resolve");
            }
            // SAFETY: past the end is explicitly in the contract.
            assert!(unsafe { name(count) }.is_null(), "the walk must end");
            // SAFETY: as above.
            assert!(unsafe { name(count + 41) }.is_null());
        }
    }

    /// A defect's `Display` is what crosses the boundary, so a variant whose
    /// message went empty would hand a caller a blank line that reads as a
    /// defect with no name, and one that grew a newline would read as two.
    #[test]
    fn no_defect_renders_as_a_blank_or_multiple_line() {
        let samples: Vec<String> = vec![
            ConfigDefect::Unreachable.to_string(),
            ConfigDefect::QosWithLowlatency.to_string(),
            TopologyDefect::NoNodeAccepts.to_string(),
        ];
        assert!(!samples.is_empty());
        for text in samples {
            assert!(!text.trim().is_empty(), "a defect rendered blank");
            assert!(
                !text.contains('\n'),
                "a defect spanning lines would be read as two: {text:?}"
            );
        }
    }
}

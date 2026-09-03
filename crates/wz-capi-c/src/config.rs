// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The zenoh-c config surface `z_put.c` drives: default, from-file, and the
//! json5 key insert.
//!
//! ## What a config is here
//!
//! zenoh-c's `z_owned_config_t` is an INLINE struct the C side stack-allocates
//! — by far the largest of them, and its size is a pure function of upstream's
//! `Config`, so it moves whenever that type does (1.5.0 -> 1.10.0 moved it).
//! The number lives once, in [`crate::abi`]. wz stores a handle to a
//! [`ConfigState`] in its leading
//! pointer slot and zero-pads the rest — the C side never reads inside, it only
//! hands the struct back through `z_loan_mut` / `z_move`.
//!
//! ## The json5 values this slice understands, and the ones it refuses
//!
//! `zc_config_insert_json5` takes a json5 VALUE, and upstream's `parse_args.h`
//! passes exactly three shapes: a quoted string (`"client"`), a list of quoted
//! strings (`["tcp/127.0.0.1:7447"]`), and the bare literal `false`. This slice
//! parses those three and REFUSES anything else with
//! [`Z_EPARSE`](crate::result::Z_EPARSE) rather than storing it unparsed.
//!
//! Refusing is the load-bearing half. A config engine that silently accepted a
//! nested object would let a program believe it had configured something wz never
//! read — which is the failure mode that makes a "drop-in" claim hollow. A full
//! json5 engine is a later slice; what it must not do in the meantime is pretend.

use std::collections::BTreeMap;
use std::ffi::{c_char, CStr};

use crate::abi::{z_loaned_config_t, z_moved_config_t, z_owned_config_t, Handle};
use crate::ffi::guarded;
use crate::result::{ZResult, Z_EIO, Z_ENULL, Z_EPARSE, Z_OK};

/// zenoh-c's `mode` key (`Z_CONFIG_MODE_KEY`, `zenoh_constants.h:23`).
pub(crate) const MODE_KEY: &str = "mode";
/// `connect/endpoints` (`Z_CONFIG_CONNECT_KEY`, `:24`).
pub(crate) const CONNECT_KEY: &str = "connect/endpoints";
/// `listen/endpoints` (`Z_CONFIG_LISTEN_KEY`, `:25`).
pub(crate) const LISTEN_KEY: &str = "listen/endpoints";
/// `scouting/multicast/address` (`Z_CONFIG_MULTICAST_IPV4_ADDRESS_KEY`, `:30`) —
/// the group `z_scout` beacons onto.
pub(crate) const MULTICAST_LOCATOR_KEY: &str = "scouting/multicast/address";
/// `scouting/timeout` (`Z_CONFIG_SCOUTING_TIMEOUT_KEY`, `:32`).
pub(crate) const SCOUTING_TIMEOUT_KEY: &str = "scouting/timeout";
/// `id` — the session zid. NOT in `zenoh_constants.h`'s `Z_CONFIG_*` list (it is
/// a plain json5 field of zenoh's own config schema), which is why it is spelled
/// out here rather than cited to a `#define` that does not exist.
pub(crate) const SESSION_ZID_KEY: &str = "id";

/// One stored value: the strings it denotes, and whether the caller wrote them
/// as a LIST.
///
/// R2300 (open-debt item 631) added the second field, and it is a defect fix
/// rather than a widening. A `Vec<String>` alone cannot tell `["tcp/a"]` from
/// `"tcp/a"` — both arrive as one string — so a one-element list re-rendered as
/// a bare scalar. That was harmless for as long as the only reader was this
/// crate's own re-parser, which reads a scalar back as a one-element list;
/// `render_nested` broke the symmetry by feeding a DIFFERENT reader, and wz's
/// stock-config reader requires an ARRAY at `listen/endpoints` (`endpoints_of`
/// rejects anything else). A single-endpoint config — upstream `parse_args.h`'s
/// most common shape by far — was therefore refused. The boundary is kept where
/// it is known instead of guessed at render time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredValue {
    /// The strings the json5 value denotes.
    values: Vec<String>,
    /// Whether the json5 was `[...]`. An empty list is bracketed too, which is
    /// why this is not `values.len() != 1`.
    bracketed: bool,
}

/// The key/value store behind an owned config.
///
/// A map of [`StoredValue`] rather than of `String`: every value upstream
/// inserts is either a scalar or a LIST of endpoints, and flattening a list into
/// one string would lose the boundary the open path needs.
#[derive(Debug, Default)]
pub(crate) struct ConfigState {
    entries: BTreeMap<String, StoredValue>,
}

impl ConfigState {
    /// The first value stored under `key`, if any.
    pub(crate) fn first(&self, key: &str) -> Option<&str> {
        self.entries
            .get(key)
            .and_then(|v| v.values.first())
            .map(|s| &**s)
    }

    /// Store `value` under `key`, replacing whatever was there.
    fn insert(&mut self, key: String, value: StoredValue) {
        self.entries.insert(key, value);
    }

    /// Render one key's value back in the json5 form the insert path accepts,
    /// or `None` when the key is absent.
    ///
    /// The round trip is the contract: a scalar renders bare and a list renders
    /// bracketed with quoted elements, so `get` of an inserted value re-inserts
    /// identically. A renderer that could not be re-parsed would make the pair
    /// of exports lossy in a way only a caller would notice.
    fn render(&self, key: &str) -> Option<String> {
        Some(render_stored(self.entries.get(key)?))
    }

    /// Render every entry as a json5 object.
    fn render_all(&self) -> String {
        let body: Vec<String> = self
            .entries
            .iter()
            .map(|(key, value)| format!("  \"{key}\": {}", render_stored(value)))
            .collect();
        format!("{{\n{}\n}}", body.join(",\n"))
    }

    /// Render every entry as the NESTED json5 document wz's stock-config
    /// reader takes, or name the pair of keys that cannot both be nested.
    ///
    /// This is NOT a second emitter beside `render_all`, and the difference is
    /// exactly one of STRUCTURE: both spell their values through
    /// `render_stored`, so what a value looks like is decided in one place and
    /// this function decides only where it sits. A renderer of its own would
    /// have been the second copy the config surface already carries one of.
    ///
    /// The nesting is load-bearing rather than cosmetic, and R2300 measured why
    /// before writing it. `ConfigState` stores upstream's FLAT key spelling
    /// (`"listen/endpoints"`, the `Z_CONFIG_LISTEN_KEY` a C caller inserts),
    /// while `ZenohNodeConfig::from_json5` reads values through
    /// `Json5Value::get`, which SPLITS the path on `/` and walks nested
    /// objects. Handed `render_all`'s output the reader would ACCEPT the
    /// document — `leaf_paths` joins segments with the same `/`, so
    /// `wz_accepts` matches the flat key against the honoured table and raises
    /// nothing — and then find NONE of the values, silently returning a config
    /// carrying every zenoh default. Green, and meaning nothing: the exact
    /// shape the doors this feeds exist to refuse.
    ///
    /// A CONFLICT is refused rather than resolved. Two stored keys where one is
    /// a prefix of the other (`"mode"` and `"mode/router"`) cannot both be
    /// nested — one place would have to be an object and a scalar at once — and
    /// picking a winner would drop a value the caller stated. The pair is named
    /// instead, because a config engine that silently discards an instruction
    /// is the failure this module's own header calls hollow.
    pub(crate) fn render_nested(&self) -> Result<String, NestConflict> {
        let mut root = NestNode::default();
        for (key, value) in &self.entries {
            let segments: Vec<&str> = key.split('/').collect();
            root.insert(&segments, value, key)?;
        }
        let mut out = String::new();
        root.write(&mut out, 1);
        Ok(out)
    }

    /// An independent copy — the config is a plain value, so this is a clone.
    fn deep_copy(&self) -> Self {
        Self {
            entries: self.entries.clone(),
        }
    }
}

/// Two stored keys that cannot both be nested, because one's path runs THROUGH
/// the other's leaf.
///
/// Carries both spellings rather than only the second: a caller told
/// `"mode/router"` conflicts has to go looking for what it conflicts WITH,
/// and the answer is already in hand at the moment of refusal.
#[derive(Debug)]
pub(crate) struct NestConflict {
    /// The key already stored at the place the second one needs.
    pub(crate) held: String,
    /// The key that could not be placed.
    pub(crate) wanted: String,
}

impl core::fmt::Display for NestConflict {
    /// Names BOTH keys, because a refusal that named only the loser would send
    /// the caller looking for the other half of a collision this type is
    /// already holding.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "config key `{}` cannot be nested: `{}` already occupies that path",
            self.wanted, self.held
        )
    }
}

/// One node of the nested document [`ConfigState::render_nested`] builds.
///
/// A branch keeps its children in a `BTreeMap` so the emitted document is a
/// pure function of the entries — two states holding the same keys render
/// byte-identically whatever order they were inserted in, which is what lets a
/// caller diff two configs at all.
enum NestNode<'a> {
    /// A stored value, rendered by [`render_stored`] like any other.
    Leaf(&'a StoredValue),
    /// Named children, in key order.
    Branch(std::collections::BTreeMap<&'a str, NestNode<'a>>),
}

impl Default for NestNode<'_> {
    fn default() -> Self {
        NestNode::Branch(std::collections::BTreeMap::new())
    }
}

impl<'a> NestNode<'a> {
    /// Place `values` at `segments`, or name the key already sitting in the way.
    ///
    /// Both directions of the collision are caught, and they are NOT the same
    /// event: walking INTO a leaf means the shorter key was stored first
    /// (`"mode"` then `"mode/router"`), while finding a leaf's place already
    /// occupied by a branch means the longer one was (`"mode/router"` then
    /// `"mode"`). A check written for only the first would pass the second
    /// silently, which is why the leaf arm below refuses rather than
    /// overwrites.
    fn insert(
        &mut self,
        segments: &[&'a str],
        value: &'a StoredValue,
        key: &str,
    ) -> Result<(), NestConflict> {
        let NestNode::Branch(children) = self else {
            // Unreachable through `render_nested`, whose root is a branch and
            // which only ever recurses through the branch arm below. Stated as
            // a refusal rather than an `unreachable!` because this type is
            // reachable from a future caller, and a panic in a config renderer
            // crosses the C boundary as an abort.
            return Err(NestConflict {
                held: String::from("<a value>"),
                wanted: String::from(key),
            });
        };
        let (head, rest) = segments
            .split_first()
            .expect("a stored key splits into at least one segment");
        if rest.is_empty() {
            // Tested BEFORE inserting. Replacing first and reporting afterwards
            // would leave the tree holding the loser of a collision this
            // function is refusing to adjudicate — harmless only for as long as
            // every caller drops the tree on `Err`, which is a promise the type
            // cannot make.
            if children.contains_key(head) {
                // A branch already stands here (a `BTreeMap` cannot hold the
                // same key twice, so it is never a second leaf), which means a
                // LONGER key claimed this place first.
                return Err(NestConflict {
                    held: format!("{key}/…"),
                    wanted: String::from(key),
                });
            }
            children.insert(head, NestNode::Leaf(value));
            return Ok(());
        }
        let child = children.entry(head).or_default();
        if matches!(child, NestNode::Leaf(_)) {
            return Err(NestConflict {
                held: String::from(*head),
                wanted: String::from(key),
            });
        }
        child.insert(rest, value, key)
    }

    /// Write this node at `depth`, two spaces per level.
    fn write(&self, out: &mut String, depth: usize) {
        match self {
            NestNode::Leaf(value) => out.push_str(&render_stored(value)),
            NestNode::Branch(children) => {
                if children.is_empty() {
                    out.push_str("{}");
                    return;
                }
                let pad = "  ".repeat(depth);
                let closing = "  ".repeat(depth - 1);
                out.push_str("{\n");
                for (i, (name, child)) in children.iter().enumerate() {
                    if i > 0 {
                        out.push_str(",\n");
                    }
                    out.push_str(&pad);
                    out.push('"');
                    out.push_str(name);
                    out.push_str("\": ");
                    child.write(out, depth + 1);
                }
                out.push('\n');
                out.push_str(&closing);
                out.push('}');
            }
        }
    }
}

/// Render a stored value in the json5 form [`parse_json5_value`] accepts.
///
/// A BRACKETED value renders bracketed whatever its length, which is the whole
/// of R2300's fix: the list-ness is read off [`StoredValue`] rather than
/// inferred from the element count, so a one-endpoint `["tcp/a"]` survives the
/// round trip as a list instead of decaying into the scalar `"tcp/a"`. The
/// count can never carry that fact — `[]` and `["a"]` are both lists and one of
/// them has no elements to count.
///
/// An unbracketed single entry that parsed from a bare literal renders bare;
/// anything else renders quoted. That one case still cannot distinguish "was a
/// bare literal" from "was a quoted scalar" after the fact, so it renders bare
/// when the text is literal-shaped and quoted otherwise — which re-parses to
/// the same value either way, and unlike the list case has no reader that can
/// tell the two apart.
fn render_stored(value: &StoredValue) -> String {
    let is_bare = |text: &str| {
        text == "true"
            || text == "false"
            || (!text.is_empty()
                && text
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c == '+'))
    };
    if !value.bracketed {
        return match value.values.as_slice() {
            [one] if is_bare(one) => one.clone(),
            [one] => format!("\"{one}\""),
            // An unbracketed multi-entry value cannot be produced by
            // `parse_json5_value`, which only ever yields more than one element
            // from a `[...]`. Rendered as a list rather than panicked on: a
            // future writer of this store gets a re-parseable value, not an
            // abort across the C boundary.
            many => bracket(many),
        };
    }
    bracket(&value.values)
}

/// `["a", "b"]`, and `[]` for nothing.
fn bracket(values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|v| format!("\"{v}\"")).collect();
    format!("[{}]", items.join(", "))
}

/// Parse one json5 VALUE into the strings it denotes.
///
/// Returns `None` for a shape this slice does not implement — see the module
/// doc for why that is a refusal rather than a passthrough.
fn parse_json5_value(raw: &str) -> Option<StoredValue> {
    /// A value that was not written as a list.
    fn scalar(one: String) -> Option<StoredValue> {
        Some(StoredValue {
            values: vec![one],
            bracketed: false,
        })
    }
    let text = raw.trim();
    if text.is_empty() {
        return None;
    }
    // An OBJECT value, stored VERBATIM. R311y573 — found by running an upstream
    // program rather than by reading: `zc_config_insert_json5(cfg,
    // "timestamping", "{\"enabled\":{...}}")` is what `ze_publication_cache`
    // requires of its session, upstream accepts it, and this parser returned
    // `None` for it, i.e. `Z_EPARSE`. Upstream's config takes ANY JSON5 value at
    // ANY path; this parser exists to give wz's own open path a list of strings
    // for the handful of keys it reads, and it must not become a whitelist of
    // the SHAPES a caller may store. The bare-literal branch below already
    // stores verbatim on exactly that reasoning; an object is the same case with
    // a delimiter.
    //
    // The brace scan is QUOTE-AWARE, so a `}` inside a string does not close the
    // object early. A value whose braces do not balance is still rejected —
    // accepting it would turn a malformed insert into a silent success.
    if text.starts_with('{') {
        return if braces_balance(text) {
            scalar(text.to_owned())
        } else {
            None
        };
    }
    // A bare literal: `false` / `true` / a number. Stored verbatim; the open path
    // reads only the keys it knows.
    if !text.starts_with('[') && !text.starts_with('"') && !text.starts_with('\'') {
        return if text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            scalar(text.to_owned())
        } else {
            None
        };
    }
    // A quoted scalar.
    if let Some(inner) = unquote(text) {
        return scalar(inner);
    }
    // A list of quoted scalars. `bracketed` from here down, INCLUDING the empty
    // list: `[]` denotes no strings and is still a list, which is the case a
    // length test could never recover.
    let body = text.strip_prefix('[')?.strip_suffix(']')?.trim();
    if body.is_empty() {
        return Some(StoredValue {
            values: Vec::new(),
            bracketed: true,
        });
    }
    let mut out = Vec::new();
    for item in body.split(',') {
        out.push(unquote(item.trim())?);
    }
    Some(StoredValue {
        values: out,
        bracketed: true,
    })
}

/// Whether `text` is a brace-balanced object, ignoring braces inside strings.
///
/// Deliberately NOT a JSON5 parser: wz's open path reads a handful of known
/// keys and stores everything else verbatim, so the only question this has to
/// answer is whether the caller handed over a complete value or a truncated one.
fn braces_balance(text: &str) -> bool {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in text.chars() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    quote.is_none() && depth == 0
}

/// Strip one matching pair of `"` or `'`, or `None` if `text` is not quoted.
fn unquote(text: &str) -> Option<String> {
    let mut chars = text.chars();
    let open = chars.next()?;
    if open != '"' && open != '\'' {
        return None;
    }
    let rest = text.get(1..)?;
    let inner = rest.strip_suffix(open)?;
    // A quote inside would mean escaping rules this slice does not implement;
    // refuse rather than mis-split.
    if inner.contains(open) {
        return None;
    }
    Some(inner.to_owned())
}

/// Install a fresh [`ConfigState`] into `out`, returning its handle slot.
fn install(out: *mut z_owned_config_t, state: ConfigState) -> Handle {
    let handle = Box::into_raw(Box::new(state)) as Handle;
    // SAFETY: the caller checked `out` for null before calling.
    unsafe { *out = z_owned_config_t::from_handle(handle) };
    handle
}

/// Borrow the state behind a loaned config.
///
/// # Safety
/// `cfg` must be null or a valid loaned config whose handle slot holds a live
/// `Box::into_raw::<ConfigState>` pointer.
pub(crate) unsafe fn config_state<'a>(cfg: *mut z_loaned_config_t) -> Option<&'a mut ConfigState> {
    if cfg.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*cfg).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: as above — a live `Box<ConfigState>` leaked as a raw pointer.
    Some(unsafe { &mut *(handle as *mut ConfigState) })
}

/// Construct the default configuration (zenoh-c `z_config_default`).
///
/// # Safety
/// `this_` must be a valid, writable `z_owned_config_t`.
#[no_mangle]
pub unsafe extern "C" fn z_config_default(this_: *mut z_owned_config_t) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        install(this_, ConfigState::default());
        Z_OK
    })
}

/// Read a configuration from a json5 FILE (zenoh-c `zc_config_from_file`).
///
/// This slice reads the file so a missing or unreadable path is reported as
/// [`Z_EIO`] exactly as upstream would, and then applies the same value parser
/// the insert path uses to any `key: value` lines it recognises. A file using
/// json5 nesting is REFUSED, not partially applied — see the module doc.
///
/// # Safety
/// `this_` must be valid and writable; `path` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn zc_config_from_file(
    this_: *mut z_owned_config_t,
    path: *const c_char,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || path.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract — NUL-terminated, valid for the call.
        let Ok(path) = (unsafe { CStr::from_ptr(path) }).to_str() else {
            return Z_EPARSE;
        };
        let Ok(text) = std::fs::read_to_string(path) else {
            // The out-param is left in its gravestone state so a caller that
            // ignores the code cannot open a session on a config that was never
            // read.
            unsafe { *this_ = z_owned_config_t::null_value() };
            return Z_EIO;
        };
        let mut state = ConfigState::default();
        for line in text.lines() {
            let line = line.trim().trim_end_matches(',');
            if line.is_empty() || line.starts_with("//") || line == "{" || line == "}" {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                return Z_EPARSE;
            };
            let key = key.trim().trim_matches(['"', '\'']).to_owned();
            let Some(values) = parse_json5_value(value) else {
                return Z_EPARSE;
            };
            state.entries.insert(key, values);
        }
        install(this_, state);
        Z_OK
    })
}

/// Insert a json5 value at `key` (zenoh-c `zc_config_insert_json5`).
///
/// # Safety
/// `this_` must be a valid loaned config; `key` and `value` must be
/// NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn zc_config_insert_json5(
    this_: *mut z_loaned_config_t,
    key: *const c_char,
    value: *const c_char,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || key.is_null() || value.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract for all three pointers.
        let (Ok(key), Ok(value)) = (
            unsafe { CStr::from_ptr(key) }.to_str(),
            unsafe { CStr::from_ptr(value) }.to_str(),
        ) else {
            return Z_EPARSE;
        };
        let Some(state) = (unsafe { config_state(this_) }) else {
            return Z_ENULL;
        };
        let Some(values) = parse_json5_value(value) else {
            return Z_EPARSE;
        };
        state.entries.insert(key.to_owned(), values);
        Z_OK
    })
}

/// Borrow a config mutably (zenoh-c `z_config_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned config.
#[no_mangle]
pub unsafe extern "C" fn z_config_loan_mut(this_: *mut z_owned_config_t) -> *mut z_loaned_config_t {
    this_ as *mut z_loaned_config_t
}

/// Borrow a config immutably (zenoh-c `z_config_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned config.
#[no_mangle]
pub unsafe extern "C" fn z_config_loan(this_: *const z_owned_config_t) -> *const z_loaned_config_t {
    this_ as *const z_loaned_config_t
}

/// Free a config and reset it to its gravestone state (zenoh-c
/// `z_config_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved config whose handle is live.
#[no_mangle]
pub unsafe extern "C" fn z_config_drop(this_: *mut z_moved_config_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_)._this.handle };
    if !handle.is_null() {
        // SAFETY: a live `Box<ConfigState>` this crate leaked.
        drop(unsafe { Box::from_raw(handle as *mut ConfigState) });
        unsafe { (*this_)._this = z_owned_config_t::null_value() };
    }
}

// --- R311y564: the rest of upstream's config surface ------------------------

/// Read a configuration from json5 TEXT (zenoh-c `zc_config_from_str`).
///
/// The same line-oriented parser [`zc_config_from_file`] applies, over a string
/// the caller already has. Sharing the parser is the point: a config that opens
/// a session when read from a file and refuses when read from a string would be
/// a difference no caller could predict.
///
/// # Safety
/// `this_` must be valid and writable; `s` must be null or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn zc_config_from_str(
    this_: *mut z_owned_config_t,
    s: *const c_char,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_config_t::null_value() };
        if s.is_null() {
            return Z_ENULL;
        }
        // SAFETY: as above.
        let Ok(text) = (unsafe { CStr::from_ptr(s) }).to_str() else {
            return Z_EPARSE;
        };
        // SAFETY: `this_` is valid and currently a gravestone.
        unsafe { install_parsed(this_, text) }
    })
}

/// The counted form of [`zc_config_from_str`] (zenoh-c `zc_config_from_substr`).
///
/// # Safety
/// `this_` must be valid and writable; `s` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn zc_config_from_substr(
    this_: *mut z_owned_config_t,
    s: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_config_t::null_value() };
        if s.is_null() {
            return Z_ENULL;
        }
        // SAFETY: as above — `len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(s.cast::<u8>(), len) };
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Z_EPARSE;
        };
        // SAFETY: `this_` is valid and currently a gravestone.
        unsafe { install_parsed(this_, text) }
    })
}

/// The counted form of [`zc_config_from_file`] (zenoh-c
/// `zc_config_from_file_substr`).
///
/// # Safety
/// `this_` must be valid and writable; `path` must be null or point at `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn zc_config_from_file_substr(
    this_: *mut z_owned_config_t,
    path: *const c_char,
    len: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_config_t::null_value() };
        if path.is_null() {
            return Z_ENULL;
        }
        // SAFETY: as above — `len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(path.cast::<u8>(), len) };
        let Ok(path) = std::str::from_utf8(bytes) else {
            return Z_EPARSE;
        };
        let Ok(owned) = std::ffi::CString::new(path) else {
            return Z_EPARSE;
        };
        // SAFETY: `owned` is a live NUL-terminated string.
        unsafe { zc_config_from_file(this_, owned.as_ptr()) }
    })
}

/// The DEFAULT configuration read from the environment (zenoh-c
/// `zc_config_from_env`).
///
/// Upstream reads `ZENOH_CONFIG`, and falls back to the default configuration
/// when it is unset. Both halves are reproduced: an unset variable is not an
/// error, and a path that does not read IS.
///
/// # Safety
/// `this_` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn zc_config_from_env(this_: *mut z_owned_config_t) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        match std::env::var("ZENOH_CONFIG") {
            Ok(path) if !path.is_empty() => {
                let Ok(owned) = std::ffi::CString::new(path) else {
                    // SAFETY: the caller's contract.
                    unsafe { *this_ = z_owned_config_t::null_value() };
                    return Z_EPARSE;
                };
                // SAFETY: `owned` is a live NUL-terminated string.
                unsafe { zc_config_from_file(this_, owned.as_ptr()) }
            }
            // SAFETY: the caller's contract.
            _ => unsafe { z_config_default(this_) },
        }
    })
}

/// Parse `text` into a fresh state and install it, or leave the gravestone.
///
/// # Safety
/// `this_` must be valid, writable, and currently a gravestone.
unsafe fn install_parsed(this_: *mut z_owned_config_t, text: &str) -> ZResult {
    let mut state = ConfigState::default();
    for line in text.lines() {
        let line = line.trim().trim_end_matches(',');
        if line.is_empty() || line.starts_with("//") || line == "{" || line == "}" {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Z_EPARSE;
        };
        let key = key.trim().trim_matches(['"', '\'']).to_owned();
        let Some(values) = parse_json5_value(value) else {
            return Z_EPARSE;
        };
        state.insert(key, values);
    }
    install(this_, state);
    Z_OK
}

/// Read one config value back as a string (zenoh-c `zc_config_get_from_str`).
///
/// The rendering is json5-ish and MATCHES what the insert path accepts, so a
/// `get` of an inserted value round-trips: a scalar renders bare and a list
/// renders bracketed with quoted elements.
///
/// # Safety
/// `this_` must be null or a valid loaned config; `key` must be null or
/// NUL-terminated; `out_value_string` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn zc_config_get_from_str(
    this_: *const z_loaned_config_t,
    key: *const c_char,
    out_value_string: *mut crate::abi::z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if out_value_string.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *out_value_string = crate::string::null_string() };
        if key.is_null() {
            return Z_ENULL;
        }
        // SAFETY: as above.
        let Ok(key) = (unsafe { CStr::from_ptr(key) }).to_str() else {
            return Z_EPARSE;
        };
        // SAFETY: as above.
        unsafe { get_into(this_, key, out_value_string) }
    })
}

/// The counted-key form of [`zc_config_get_from_str`] (zenoh-c
/// `zc_config_get_from_substr`).
///
/// # Safety
/// `this_` must be null or a valid loaned config; `key` must be null or point
/// at `key_len` readable bytes; `out_value_string` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn zc_config_get_from_substr(
    this_: *const z_loaned_config_t,
    key: *const c_char,
    key_len: usize,
    out_value_string: *mut crate::abi::z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if out_value_string.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *out_value_string = crate::string::null_string() };
        if key.is_null() {
            return Z_ENULL;
        }
        // SAFETY: as above — `key_len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(key.cast::<u8>(), key_len) };
        let Ok(key) = std::str::from_utf8(bytes) else {
            return Z_EPARSE;
        };
        // SAFETY: as above.
        unsafe { get_into(this_, key, out_value_string) }
    })
}

/// The shared body of the two `get` entry points.
///
/// # Safety
/// `this_` must be null or a valid loaned config; `out` must be valid, writable
/// and currently a gravestone.
unsafe fn get_into(
    this_: *const z_loaned_config_t,
    key: &str,
    out: *mut crate::abi::z_owned_string_t,
) -> ZResult {
    // SAFETY: the caller's contract. The cast drops `const`, which is sound
    // because `config_state` only reads here — upstream types the get path
    // `const` and the insert path mutable over the same handle.
    let Some(state) = (unsafe { config_state(this_ as *mut z_loaned_config_t) }) else {
        return Z_ENULL;
    };
    let Some(rendered) = state.render(key) else {
        // Upstream distinguishes "no such key" from a bad argument; this is the
        // former, and the out-param stays a gravestone.
        return Z_EPARSE;
    };
    // SAFETY: the caller's contract.
    unsafe { *out = crate::string::owned_string_from(rendered.as_bytes()) };
    Z_OK
}

/// The counted form of [`zc_config_insert_json5`] (zenoh-c
/// `zc_config_insert_json5_from_substr`).
///
/// # Safety
/// `this_` must be null or a valid loaned config; `key` / `value` must be null
/// or point at `key_len` / `value_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn zc_config_insert_json5_from_substr(
    this_: *mut z_loaned_config_t,
    key: *const c_char,
    key_len: usize,
    value: *const c_char,
    value_len: usize,
) -> ZResult {
    guarded(|| {
        if this_.is_null() || key.is_null() || value.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract — the two counted buffers.
        let (key_bytes, value_bytes) = unsafe {
            (
                std::slice::from_raw_parts(key.cast::<u8>(), key_len),
                std::slice::from_raw_parts(value.cast::<u8>(), value_len),
            )
        };
        let (Ok(key), Ok(value)) = (
            std::str::from_utf8(key_bytes),
            std::str::from_utf8(value_bytes),
        ) else {
            return Z_EPARSE;
        };
        // SAFETY: the caller's contract for the handle.
        let Some(state) = (unsafe { config_state(this_) }) else {
            return Z_ENULL;
        };
        let Some(values) = parse_json5_value(value) else {
            return Z_EPARSE;
        };
        state.insert(key.to_owned(), values);
        Z_OK
    })
}

/// Render the whole configuration as json5 (zenoh-c `zc_config_to_string`).
///
/// # Safety
/// `config` must be null or a valid loaned config; `out_config_string` must be
/// valid and writable.
#[no_mangle]
pub unsafe extern "C" fn zc_config_to_string(
    config: *const z_loaned_config_t,
    out_config_string: *mut crate::abi::z_owned_string_t,
) -> ZResult {
    guarded(|| {
        if out_config_string.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *out_config_string = crate::string::null_string() };
        // SAFETY: as above; see `get_into` for the `const` cast.
        let Some(state) = (unsafe { config_state(config as *mut z_loaned_config_t) }) else {
            return Z_ENULL;
        };
        // SAFETY: the caller's contract.
        unsafe {
            *out_config_string = crate::string::owned_string_from(state.render_all().as_bytes())
        };
        Z_OK
    })
}

/// Deep-copy a configuration (zenoh-c `z_config_clone`).
///
/// # Safety
/// `dst` must be valid and writable; `this_` must be null or a valid loaned
/// config.
#[no_mangle]
pub unsafe extern "C" fn z_config_clone(
    dst: *mut z_owned_config_t,
    this_: *const z_loaned_config_t,
) {
    crate::ffi::guard_val((), || {
        if dst.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *dst = z_owned_config_t::null_value() };
        // SAFETY: as above; see `get_into` for the `const` cast.
        let Some(state) = (unsafe { config_state(this_ as *mut z_loaned_config_t) }) else {
            return;
        };
        install(dst, state.deep_copy());
    });
}

/// `true` iff the owned config holds a state (zenoh-c
/// `z_internal_config_check`).
///
/// # Safety
/// `this_` must be null or a valid owned config.
#[no_mangle]
pub unsafe extern "C" fn z_internal_config_check(this_: *const z_owned_config_t) -> bool {
    crate::ffi::guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Gravestone an owned config (zenoh-c `z_internal_config_null`).
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_config_null(this_: *mut z_owned_config_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_config_t::null_value() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A value the caller did NOT write as a list.
    fn scalar_of(values: &[&str]) -> Option<StoredValue> {
        Some(StoredValue {
            values: values.iter().map(|s| String::from(*s)).collect(),
            bracketed: false,
        })
    }

    /// A value the caller wrote as `[...]`.
    fn list_of(values: &[&str]) -> Option<StoredValue> {
        Some(StoredValue {
            values: values.iter().map(|s| String::from(*s)).collect(),
            bracketed: true,
        })
    }

    #[test]
    fn a_quoted_scalar_parses_to_one_value() {
        assert_eq!(parse_json5_value("\"client\""), scalar_of(&["client"]));
        assert_eq!(parse_json5_value("  'peer' "), scalar_of(&["peer"]));
    }

    #[test]
    fn an_endpoint_list_keeps_its_items_separate() {
        // The shape upstream's parse_args.h builds for connect/listen.
        assert_eq!(
            parse_json5_value("[\"tcp/127.0.0.1:7447\",\"tcp/127.0.0.1:7448\"]"),
            list_of(&["tcp/127.0.0.1:7447", "tcp/127.0.0.1:7448"])
        );
        assert_eq!(parse_json5_value("[]"), list_of(&[]));
    }

    /// R2300 (open-debt item 631) — A ONE-ELEMENT LIST IS A LIST, and this is
    /// the assertion the count could not carry.
    ///
    /// `["tcp/a"]` is upstream `parse_args.h`'s most common shape (one `-e`, one
    /// `-l`), and until this round it parsed to the same value as the scalar
    /// `"tcp/a"` and re-rendered as one. That was invisible while the only
    /// reader was this crate's own re-parser, which turns a scalar back into a
    /// one-element list; it stopped being invisible when `render_nested` began
    /// feeding wz's stock-config reader, whose `endpoints_of` REFUSES anything
    /// that is not an array. The two cases are asserted side by side because
    /// their `values` are identical — `bracketed` is the whole difference.
    #[test]
    fn a_one_element_list_is_not_the_same_value_as_a_scalar() {
        let list = parse_json5_value("[\"tcp/127.0.0.1:7447\"]");
        let scalar = parse_json5_value("\"tcp/127.0.0.1:7447\"");
        assert_eq!(list, list_of(&["tcp/127.0.0.1:7447"]));
        assert_eq!(scalar, scalar_of(&["tcp/127.0.0.1:7447"]));
        assert_ne!(list, scalar, "the shape must survive the parse");
        // And it survives the RENDER, which is where the defect showed.
        assert_eq!(
            render_stored(&list.expect("parsed")),
            "[\"tcp/127.0.0.1:7447\"]"
        );
        assert_eq!(
            render_stored(&scalar.expect("parsed")),
            "\"tcp/127.0.0.1:7447\""
        );
    }

    /// R2300 (open-debt item 631) — THE FLAT SPELLING IS ACCEPTED AND SILENTLY
    /// DROPS EVERY MULTI-SEGMENT KEY, which is why `render_nested` exists and
    /// is the control group for it.
    ///
    /// `render_all` is not a worse renderer; it answers a different question,
    /// and this test is what pins the difference so a later round cannot
    /// "simplify" the doors onto it. Handed `render_all`'s output, wz's
    /// stock-config reader:
    ///
    ///   * ACCEPTS the document — `leaf_paths` joins nested segments with `/`
    ///     and `wz_accepts` compares the result against the honoured table, so
    ///     the flat key `"listen/endpoints"` matches an honoured key exactly and
    ///     raises no unknown-key error;
    ///   * and then finds no value there, because `Json5Value::get` SPLITS its
    ///     path on `/` and walks nested objects, where nothing is nested.
    ///
    /// # The loss is PARTIAL, and R2300 measured that rather than assuming it
    ///
    /// The first draft of this test asserted that NOTHING is read, and it went
    /// red on `mode`. A SINGLE-SEGMENT key has the same spelling flat and
    /// nested — there is no `/` to split on — so `mode`, `id` and `namespace`
    /// survive `render_all` intact while every path key is dropped. That makes
    /// the defect worse rather than milder, and the two halves are asserted
    /// together here because the surviving half is exactly what would make a
    /// hand-check believe the document had been read: a caller inspecting the
    /// result sees its mode came through and has no reason to look further.
    ///
    /// Asserting the ACCEPTANCE as well as the empty read is deliberate — an
    /// error would have been a survivable defect, and what makes this one worth
    /// a test is that there is nothing to catch.
    #[test]
    fn the_flat_spelling_parses_clean_and_drops_every_path_key() {
        use wz_runtime_tokio::zenoh_config::ZenohNodeConfig;

        let mut state = ConfigState::default();
        state.insert(
            String::from(LISTEN_KEY),
            StoredValue {
                values: vec![String::from("tcp/127.0.0.1:7447")],
                bracketed: true,
            },
        );
        state.insert(
            String::from(MODE_KEY),
            StoredValue {
                values: vec![String::from("client")],
                bracketed: false,
            },
        );
        // The population is DERIVED from the keys under test rather than
        // spelled: whichever of them carries a `/` is the one the flat spelling
        // cannot deliver. A fixture changed to use only single-segment keys
        // would empty this and fail here rather than pass vacuously.
        let path_keys: Vec<&str> = [LISTEN_KEY, MODE_KEY]
            .into_iter()
            .filter(|k| k.contains('/'))
            .collect();
        assert!(
            !path_keys.is_empty(),
            "no multi-segment key under test, so this proves nothing"
        );

        // THE DEFECT, stated as an assertion rather than as a comment.
        let flat = ZenohNodeConfig::from_json5(&state.render_all())
            .expect("the flat spelling is ACCEPTED -- that is the whole problem");
        assert!(
            flat.config.listen.is_empty(),
            "the flat document must carry no endpoints; it carried {:?}",
            flat.config.listen
        );
        for key in &path_keys {
            assert!(
                !flat.named.contains(key),
                "the flat document must not name the path key {key}; it named {:?}",
                flat.named
            );
        }
        // And the half that SURVIVES, which is what makes the loss deceptive.
        assert!(
            flat.named.contains(&MODE_KEY),
            "a single-segment key spells the same either way and must survive; \
             the flat document named {:?}",
            flat.named
        );

        // THE FIX, over the same state.
        let nested =
            ZenohNodeConfig::from_json5(&state.render_nested().expect("no conflicting keys here"))
                .expect("the nested spelling is accepted too");
        assert_eq!(
            nested.config.listen,
            vec![String::from("tcp/127.0.0.1:7447")]
        );
        assert!(
            nested.named.contains(&LISTEN_KEY),
            "the nested document must NAME the key it states; it named {:?}",
            nested.named
        );
    }

    /// R2300 (open-debt item 631) — a key whose path runs through another key's
    /// leaf is REFUSED, in both orders of arrival.
    ///
    /// Both orders, because they are different events in the tree walk and a
    /// check written for one passes the other silently: arriving `"mode"` then
    /// `"mode/router"` walks INTO a leaf, while `"mode/router"` then `"mode"`
    /// finds a leaf's place already held by a branch. `BTreeMap` iteration puts
    /// the shorter key first whatever the insertion order, so the second case
    /// is reached by making the LONGER key the one that cannot be placed.
    #[test]
    fn two_keys_that_cannot_both_be_nested_are_refused_by_name() {
        let mut state = ConfigState::default();
        state.insert(
            String::from("mode"),
            StoredValue {
                values: vec![String::from("client")],
                bracketed: false,
            },
        );
        state.insert(
            String::from("mode/router"),
            StoredValue {
                values: vec![String::from("peer")],
                bracketed: false,
            },
        );
        let conflict = state
            .render_nested()
            .expect_err("a key cannot be both a value and an object");
        let text = conflict.to_string();
        assert!(
            text.contains("mode/router") && text.contains("mode"),
            "the refusal must name BOTH keys, got {text:?}"
        );

        // The control: neither key alone is a conflict, so the refusal is about
        // the PAIR and not about either spelling.
        for key in ["mode", "mode/router"] {
            let mut one = ConfigState::default();
            one.insert(
                String::from(key),
                StoredValue {
                    values: vec![String::from("client")],
                    bracketed: false,
                },
            );
            assert!(
                one.render_nested().is_ok(),
                "{key} alone must render; only the pair conflicts"
            );
        }
    }

    #[test]
    fn a_bare_literal_is_kept_verbatim() {
        // `scouting/multicast/enabled` is inserted as the bare word `false`.
        assert_eq!(parse_json5_value("false"), scalar_of(&["false"]));
    }

    /// The REFUSAL is the load-bearing half: a shape this slice cannot honour
    /// must not be stored, or a program believes it configured something wz never
    /// reads.
    ///
    /// R311y573 MOVED `{nested: 1}` OUT of this list, and the move is a
    /// correction rather than a relaxation. The list encoded "an object is a
    /// shape this slice cannot honour"; upstream accepts an object at any config
    /// path, `ze_publication_cache` REQUIRES one (`timestamping`), and refusing
    /// it made a whole upstream family unusable on wz — measured by running the
    /// probe, not argued. A balanced object now stores VERBATIM, which is what
    /// the bare-literal branch beside it has always done; an UNBALANCED one is
    /// still refused, and that case is what keeps this test discriminating.
    #[test]
    fn an_unimplemented_shape_is_refused_rather_than_stored() {
        for raw in [
            "{unbalanced: 1",
            "nested: 1}",
            "{\"quote: \"still open\"",
            "[\"unterminated",
            "[\"a\", bare]",
            "\"unbalanced'",
            "",
        ] {
            assert_eq!(parse_json5_value(raw), None, "must refuse {raw:?}");
        }
    }

    /// R311y573 — a BALANCED object is stored verbatim, braces and all. wz's
    /// open path reads the handful of keys it knows and ignores the rest, so the
    /// parser's job is to tell a complete value from a truncated one, never to
    /// whitelist the shapes a caller may store.
    #[test]
    fn a_balanced_object_is_stored_verbatim() {
        for raw in [
            "{nested: 1}",
            "{\"enabled\":{\"router\":true,\"peer\":true,\"client\":true}}",
            // A brace INSIDE a string must not close the object early.
            "{\"body\":\"}\"}",
        ] {
            assert_eq!(
                parse_json5_value(raw),
                scalar_of(&[raw]),
                "must store {raw:?} verbatim"
            );
        }
    }
}

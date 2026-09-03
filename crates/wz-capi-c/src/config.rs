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
use crate::result::{ZResult, Z_EGENERIC, Z_EIO, Z_ENULL, Z_EPARSE, Z_OK};
use wz_runtime_tokio::json5::Json5Value;

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

/// How a stored value was SPELLED in the json5 the caller wrote.
///
/// The key/value store behind an owned config: THE DOCUMENT, held as its LEAF
/// SET.
///
/// # One representation, because two of them answered differently
///
/// R2304 (open-debt item 642) settled the shape. Upstream holds a TREE and its
/// path keys are queries over it, so `insert("connect", "{\"endpoints\":[…]}")`
/// and `insert("connect/endpoints", "[…]")` build the same config and
/// `get("connect/endpoints")` answers both — measured on `libzenohc.so` 1.10.0.
/// This store kept a flat map of whatever key it was HANDED, so the two
/// spellings produced different states: the object went in as one opaque entry
/// at `connect` and nothing answered the leaf beneath it. That is not a missing
/// convenience. `session.rs`'s open path reads `connect/endpoints`, so a program
/// upstream configures correctly opened a wz session with NO endpoints and
/// connected nowhere, silently.
///
/// Leaves are the fixed point of both doors: `zc_config_insert_json5`
/// decomposes an object into them, `zc_config_from_str` walks a document into
/// them, and `render_nested` puts them back. There is no second representation
/// for the two to disagree about.
///
/// # The value type is the READER's, not a second parser's
///
/// It holds `Json5Value` — what `wz_session_core::json5::parse` produces —
/// rather than a hand-rolled `StoredValue`. R2303 left this crate with TWO
/// json5 value readers, and the hand-rolled one was LAXER: it accepted
/// `{enabled: bare}`, which is not json5, and the door then emitted a document
/// wz's own reader refused (`Z_EPARSE`, measured through the C ABI, where
/// upstream refuses the same insert at the door). One reader cannot disagree
/// with itself.
#[derive(Debug, Default)]
pub(crate) struct ConfigState {
    entries: BTreeMap<String, Json5Value>,
}

impl ConfigState {
    /// The first string the value at `key` denotes, if any.
    ///
    /// A string denotes itself; an array denotes its first STRING element. The
    /// open path reads endpoints and a mode this way, and both are spelled
    /// either bare or as a one-element list by upstream's own `parse_args.h`.
    /// Anything else — an object, a number, a bool — denotes no string, and
    /// `None` is the honest answer rather than its rendered text.
    pub(crate) fn first(&self, key: &str) -> Option<&str> {
        match self.entries.get(key)? {
            Json5Value::String(text) => Some(text),
            Json5Value::Array(items) => items.iter().find_map(|item| match item {
                Json5Value::String(text) => Some(&**text),
                _ => None,
            }),
            _ => None,
        }
    }

    /// Store one json5 VALUE at `key`, decomposing an object into the leaves it
    /// states and REPLACING whatever stood at or beneath that key.
    ///
    /// Replacing rather than merging is upstream's own semantics, measured:
    /// `insert("scouting", "{\"delay\":99}")` then
    /// `insert("scouting", "{\"timeout\":77}")` leaves `delay` back at `null`.
    /// A merge here would make wz remember an instruction upstream forgot.
    fn insert_value(&mut self, key: &str, value: Json5Value) {
        let under = format!("{key}/");
        self.entries
            .retain(|stored, _| stored != key && !stored.starts_with(&under));
        if matches!(&value, Json5Value::Object(entries) if !entries.is_empty()) {
            for (path, leaf) in value.leaf_entries() {
                self.entries.insert(format!("{key}/{path}"), leaf.clone());
            }
        } else {
            self.entries.insert(key.to_owned(), value);
        }
    }

    /// Render one key's value back in the json5 form the insert path accepts,
    /// or `None` when the key names nothing.
    ///
    /// The round trip is the contract: a value renders in the spelling it
    /// arrived in, so `get` of an inserted value re-inserts identically. A
    /// renderer that could not be re-parsed would make the pair of exports lossy
    /// in a way only a caller would notice.
    ///
    /// # A key is a QUERY OVER THE TREE, not a map lookup
    ///
    /// R2303 (open-debt item 636). Upstream holds its config as a tree and
    /// `zc_config_get_from_str` walks it, so an INTERIOR path answers with the
    /// subtree beneath it — measured on `libzenohc.so` 1.10.0, `get("scouting")`
    /// returns `{"timeout":null,"delay":99,…}`. This store holds the same tree
    /// as its LEAF SET, so the same question has to be answered by re-nesting
    /// rather than by finding an entry, and a lookup alone would have made a key
    /// unreadable at its own path the moment `zc_config_from_str` had read it
    /// out of a nested document: `{"timestamping":{"enabled":true}}` stores one
    /// leaf at `timestamping/enabled`, and `get("timestamping")` matches no
    /// entry at all.
    ///
    /// COMPACT, because that is one value rather than a document — the layout
    /// `zc_config_to_string` writes is for a human diffing a file, and upstream
    /// answers a `get` with no whitespace either.
    ///
    /// A subtree that cannot be re-nested is `None` rather than a partial
    /// answer. `NestConflict` is reachable here for the same reason it is
    /// reachable from `render_nested` — this store is a flat map and a tree is
    /// not — and half a subtree would be a value the caller could re-insert to
    /// silently lose the rest.
    fn render(&self, key: &str) -> Option<String> {
        if let Some(value) = self.entries.get(key) {
            return Some(value.to_json5_text());
        }
        let prefix = format!("{key}/");
        let mut root = NestNode::default();
        let mut found = false;
        for (stored, value) in self
            .entries
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
        {
            let segments: Vec<&str> = stored[prefix.len()..].split('/').collect();
            root.insert(&segments, value, stored).ok()?;
            found = true;
        }
        if !found {
            return None;
        }
        let mut out = String::new();
        root.write(&mut out, 1, Layout::Compact);
        Some(out)
    }

    /// Render every entry as the NESTED json5 document — the ONE document this
    /// store emits — or name the pair of keys that cannot both be nested.
    ///
    /// R2303 (open-debt item 636) made it the only one. A `render_all` stood
    /// beside it emitting the flat key map, on the belief that the flat
    /// spelling was what upstream's `zc_config_to_string` answers with; upstream
    /// was then MEASURED and emits nested, so the flat renderer answered a
    /// question no door of either implementation asks. Two emitters for one
    /// document is a place for the two to disagree, and they had.
    ///
    /// The nesting is load-bearing rather than cosmetic, and R2300 measured why
    /// before writing it. `ConfigState` stores upstream's FLAT key spelling
    /// (`"listen/endpoints"`, the `Z_CONFIG_LISTEN_KEY` a C caller inserts),
    /// while `ZenohNodeConfig::from_json5` reads values through
    /// `Json5Value::get`, which SPLITS the path on `/` and walks nested
    /// objects. Handed a FLAT document the reader would ACCEPT it —
    /// `leaf_paths` joins segments with the same `/`, so `wz_accepts` matches
    /// the flat key against the honoured table and raises nothing — and then
    /// find NONE of the values, silently returning a config carrying every
    /// zenoh default. Green, and meaning nothing: the exact shape the doors
    /// this feeds exist to refuse. The test named for that loss still asserts
    /// it, over a document it builds itself.
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
        root.write(&mut out, 1, Layout::Indented);
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
    /// A stored value, rendered by its own `to_json5_text` like any other.
    Leaf(&'a Json5Value),
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
        value: &'a Json5Value,
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

    /// Write this node at `depth`, in `layout`.
    fn write(&self, out: &mut String, depth: usize, layout: Layout) {
        match self {
            NestNode::Leaf(value) => out.push_str(&value.to_json5_text()),
            NestNode::Branch(children) => {
                if children.is_empty() {
                    out.push_str("{}");
                    return;
                }
                let (open, sep, pad, tail) = match layout {
                    Layout::Indented => (
                        "{\n",
                        ",\n",
                        "  ".repeat(depth),
                        format!("\n{}", "  ".repeat(depth - 1)),
                    ),
                    Layout::Compact => ("{", ",", String::new(), String::new()),
                };
                out.push_str(open);
                for (i, (name, child)) in children.iter().enumerate() {
                    if i > 0 {
                        out.push_str(sep);
                    }
                    out.push_str(&pad);
                    out.push('"');
                    out.push_str(name);
                    out.push_str("\":");
                    if matches!(layout, Layout::Indented) {
                        out.push(' ');
                    }
                    child.write(out, depth + 1, layout);
                }
                out.push_str(&tail);
                out.push('}');
            }
        }
    }
}

/// How a nested document is laid out.
///
/// Two call sites, one writer, because the STRUCTURE is the thing that has to
/// be decided once and the whitespace is not: a second writer for the compact
/// form would be a second place for the nesting to be wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// Two spaces per level and a newline per member — the DOCUMENT
    /// `zc_config_to_string` writes, which a human diffs against the reference
    /// config.
    Indented,
    /// No whitespace — one VALUE handed back through `zc_config_get_from_str`,
    /// where upstream is compact too and layout would be noise the caller has to
    /// strip before comparing.
    Compact,
}

/// Parse one json5 VALUE, or `None` when it is not json5.
///
/// R2304 (open-debt item 642) made this ONE LINE over the workspace's reader.
/// What stood here was a hand-rolled half-parser — a brace-balance scan, an
/// `unquote`, a comma split — and it was LAXER than the reader the document
/// doors use: it stored `{enabled: bare}`, which no json5 grammar admits, and
/// `zc_config_to_string` then emitted a document `zc_config_from_str` refused.
/// Measured through the C ABI at the real schema key `timestamping`, where
/// upstream refuses that same insert AT THE DOOR (`Z_EGENERIC`) and wz returned
/// `Z_OK` then `Z_EPARSE` on its own output.
///
/// One reader cannot disagree with itself, and the deleted code is the whole of
/// the disagreement: 155 lines of `parse_json5_value`, `render_stored`,
/// `bracket`, `delimiters_balance`, `unquote`, plus the `StoredValue` /
/// `Spelling` pair they existed to fill.
fn parse_json5_value(raw: &str) -> Option<Json5Value> {
    wz_runtime_tokio::json5::parse(raw).ok()
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
/// [`Z_EIO`] exactly as upstream would, and hands the text to `install_parsed`
/// — the one document reader every door here shares. (A CODE SPAN, not a link:
/// this item is public and that one is not, which the doc-link budget lane
/// counts as a broken link. The budget is not the thing to move.)
///
/// R2303 (open-debt item 636) made that true. This function used to carry its
/// OWN copy of the line scanner `install_parsed` held, so the two doors could
/// drift and did: this is the door a `zenohd -c` config file arrives at, and
/// every such file is NESTED, which the scanner refused.
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
        // SAFETY: `this_` is valid; the gravestone above and the caller's
        // contract leave it in the state `install_parsed` requires.
        unsafe { *this_ = z_owned_config_t::null_value() };
        // SAFETY: as above.
        unsafe { install_parsed(this_, &text) }
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
        let Some(parsed) = parse_json5_value(value) else {
            return Z_EPARSE;
        };
        state.insert_value(key, parsed);
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

/// Read a json5 DOCUMENT into a fresh state and install it, or leave the
/// gravestone.
///
/// The one reader behind every document door — `zc_config_from_str`,
/// `zc_config_from_substr`, `zc_config_from_file`, `zc_config_from_file_substr`
/// and, through the last of those, `zc_config_from_env`. R2303 (open-debt item
/// 636) made it one: `zc_config_from_file` carried a second copy of the parser
/// this replaced, so a fix applied here reached three of the five doors and the
/// other two kept reading the old way.
///
/// # It parses; it does not scan lines
///
/// What it replaced split the text on newlines and each line on its first `:`,
/// which meant wz accepted only a FLAT document — one `"key": value` per line,
/// the key spelled with the `/` path separators the insert door takes. Every
/// zenoh configuration a deployment actually holds is NESTED (`zenohd -c` reads
/// one, and upstream's own `zc_config_to_string` writes one), and upstream's
/// `zc_config_from_str` refuses the flat spelling outright — measured, at
/// `libzenohc.so` 1.10.0, `Z_EPARSE`. So the two implementations' document
/// doors could not read each other in EITHER direction, and a drop-in whose
/// config door cannot read the deployment's config file is not a drop-in.
///
/// `Json5Value::leaf_entries` joins nested segments with `/`, which is the same
/// spelling `ConfigState` stores and `zc_config_get_from_str` queries — so the
/// nesting is undone exactly once, here, and the flat path keys the rest of the
/// crate works in are unchanged. `leaf_entries` rather than `leaf_paths`
/// because the walk has to CARRY the value: a re-lookup through
/// `Json5Value::get` splits the path on `/` again, so a flat key would resolve
/// to nothing and the door would refuse a document it had just parsed. That is
/// not hypothetical — it is what the first draft of this function did, measured
/// through the C ABI before the walk was changed.
///
/// A document written FLAT therefore still reads, and that is a deliberate
/// superset rather than an accident: a top-level key containing `/` yields the
/// same leaf path as the nesting it spells. Upstream refuses the flat spelling
/// and wz accepts it, which costs the drop-in claim nothing — a program written
/// for zenoh-c never emits one, because upstream cannot read one back — while
/// refusing it would strand every config file wz's OWN `zc_config_to_string`
/// wrote before this round.
///
/// # Each leaf goes through the INSERT door's value parser
///
/// [`parse_json5_value`] is called on each leaf's json5 text rather than a
/// second value reader being written here, so "a value this config can hold" is
/// one rule and not two. A leaf it refuses fails the whole document, which is
/// the same answer `zc_config_insert_json5` gives for that same value; a
/// document that silently dropped the key would be the hollow-config shape this
/// module's own header names.
///
/// # Safety
/// `this_` must be valid, writable, and currently a gravestone.
unsafe fn install_parsed(this_: *mut z_owned_config_t, text: &str) -> ZResult {
    let Ok(document) = wz_runtime_tokio::json5::parse(text) else {
        return Z_EPARSE;
    };
    // The ROOT must be an object. `leaf_paths` yields nothing for a scalar root
    // — `5` is a leaf at no path — so without this a document of `5` would
    // install an EMPTY config and report success, which is the vacuous accept
    // this crate refuses everywhere else. Upstream refuses it too: its
    // `json5::from_str::<Config>` cannot make a struct out of a number.
    if !matches!(document, wz_runtime_tokio::json5::Json5Value::Object(_)) {
        return Z_EPARSE;
    }
    let mut state = ConfigState::default();
    for (path, leaf) in document.leaf_entries() {
        state.insert_value(&path, leaf.clone());
    }
    install(this_, state);
    Z_OK
}

/// Read one config value back as a string (zenoh-c `zc_config_get_from_str`).
///
/// The rendering is json5 and MATCHES what the insert path accepts, so a `get`
/// of an inserted value round-trips. R2304 (open-debt item 642) made that exact
/// rather than approximate: the store holds the READER's own value type, so a
/// value comes back through the emitter that is `parse`'s inverse instead of
/// through a renderer reconstructing a spelling from stored text. The sentence
/// this replaced said "a scalar renders bare", which was true of a bare literal
/// and false of a string.
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
        let Some(parsed) = parse_json5_value(value) else {
            return Z_EPARSE;
        };
        state.insert_value(key, parsed);
        Z_OK
    })
}

/// Render the whole configuration as json5 (zenoh-c `zc_config_to_string`).
///
/// # The document is NESTED, and R2303 (open-debt item 636) is why
///
/// This door used to emit the flat key map `ConfigState` stores —
/// `{"connect/endpoints": [...], "mode": "client"}` — on the belief that
/// echoing back the caller's own spelling was upstream's meaning. It is not.
/// Upstream serializes zenoh's `Config`, a TREE, so its output nests
/// (`{"mode":"client","connect":{"endpoints":[...]}}`), and its
/// `zc_config_from_str` REFUSES the flat spelling — both measured against
/// `libzenohc.so` 1.10.0 rather than read off a doc comment, which had the
/// example but not the whole.
///
/// A flat document is therefore not a variant spelling; it is one no zenoh
/// component can read, and this is the door whose output a program hands to
/// `zenohd -c` or to another zenoh library. The path spelling is not lost by
/// nesting: a `/` key is a QUERY over the tree, which is why
/// `zc_config_get_from_str("connect/endpoints")` resolves through upstream's
/// nested document and through this one.
///
/// # BYTE identity with upstream is not the contract, and cannot be
///
/// Upstream emits every field of zenoh's whole `Config` — 2,916 bytes for a
/// default at 1.10.0, most of them `null` — because that struct is what it
/// serializes. `ConfigState` holds only what a caller inserted and models no
/// schema, so the two can never agree byte for byte. What they can be held to,
/// and what `zenoh_c_config_document_oracle` holds them to, is that each side's
/// document is READ by the other with every value arriving intact.
///
/// # A config that cannot be a document is refused
///
/// `ConfigState` is a flat map, so it can hold `"mode"` and `"mode/router"` at
/// once; a tree cannot. Upstream never reaches that state (it refuses the
/// second insert, `Z_EGENERIC`), and this crate stores what the caller said
/// rather than adjudicating zenoh's schema, so the refusal lands here instead —
/// naming both keys, via `NestConflict`. [`Z_EGENERIC`] because that is what
/// upstream's own `zc_config_to_string` returns when serialization fails; a
/// parse code would claim the caller's input was malformed, and it was not.
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
        let Ok(document) = state.render_nested() else {
            return Z_EGENERIC;
        };
        // SAFETY: the caller's contract.
        unsafe { *out_config_string = crate::string::owned_string_from(document.as_bytes()) };
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

    /// A json5 STRING value.
    fn scalar_of(text: &str) -> Option<Json5Value> {
        Some(Json5Value::String(String::from(text)))
    }

    /// A json5 ARRAY of strings.
    fn list_of(values: &[&str]) -> Option<Json5Value> {
        Some(Json5Value::Array(
            values
                .iter()
                .map(|s| Json5Value::String(String::from(*s)))
                .collect(),
        ))
    }

    /// The flat document `zc_config_to_string` emitted before R2303, built from
    /// the state's own entries so the test that needs it is not holding a
    /// literal that could stop describing this store.
    ///
    /// It lives here, in the control group, because that is the only thing it
    /// was ever good for: no door of either implementation asks for the flat
    /// spelling, which is what open-debt item 636 established. It is composed
    /// from `ConfigState::render` — the surviving PER-KEY renderer, which
    /// `zc_config_get_from_str` uses — rather than being a second emitter.
    fn flat_document(state: &ConfigState) -> String {
        let body: Vec<String> = state
            .entries
            .keys()
            .map(|key| {
                format!(
                    "  \"{key}\": {}",
                    state.render(key).expect("the key is in this state")
                )
            })
            .collect();
        format!("{{\n{}\n}}", body.join(",\n"))
    }

    #[test]
    fn a_quoted_scalar_parses_to_one_value() {
        assert_eq!(parse_json5_value("\"client\""), scalar_of("client"));
        assert_eq!(parse_json5_value("  'peer' "), scalar_of("peer"));
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
    /// they denote the same ONE string and differ only in shape.
    ///
    /// R2304 (open-debt item 642) kept the test and deleted what made it hard:
    /// the store holds a `Json5Value` now, so `Array([String])` and `String` are
    /// different values by construction and no `bracketed` flag has to carry
    /// the difference by hand.
    #[test]
    fn a_one_element_list_is_not_the_same_value_as_a_scalar() {
        let list = parse_json5_value("[\"tcp/127.0.0.1:7447\"]");
        let scalar = parse_json5_value("\"tcp/127.0.0.1:7447\"");
        assert_eq!(list, list_of(&["tcp/127.0.0.1:7447"]));
        assert_eq!(scalar, scalar_of("tcp/127.0.0.1:7447"));
        assert_ne!(list, scalar, "the shape must survive the parse");
        // And it survives the RENDER, which is where the defect showed.
        assert_eq!(
            list.expect("parsed").to_json5_text(),
            "[\"tcp/127.0.0.1:7447\"]"
        );
        assert_eq!(
            scalar.expect("parsed").to_json5_text(),
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
        state.insert_value(
            LISTEN_KEY,
            list_of(&["tcp/127.0.0.1:7447"]).expect("a list"),
        );
        state.insert_value(MODE_KEY, scalar_of("client").expect("a scalar"));
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
        let flat = ZenohNodeConfig::from_json5(&flat_document(&state))
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
        // NOT through `insert_value`, which REPLACES the subtree at a key and so
        // cannot hold both halves of this collision at once. The pair is
        // reachable through the document reader instead — a caller can write
        // `{"mode": "client"}` into a config that already carries
        // `mode/router` — so the state under test is built directly.
        state
            .entries
            .insert(String::from("mode"), scalar_of("client").expect("a scalar"));
        state.entries.insert(
            String::from("mode/router"),
            scalar_of("peer").expect("a scalar"),
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
            one.insert_value(key, scalar_of("client").expect("a scalar"));
            assert!(
                one.render_nested().is_ok(),
                "{key} alone must render; only the pair conflicts"
            );
        }
    }

    /// A bare literal keeps its own type, and re-renders as itself.
    ///
    /// R2303 (open-debt item 636) put `null` here because the renderer used to
    /// get it wrong: it recognised `true`/`false`/digits as bare and QUOTED
    /// everything else, so `null` came back out as the STRING `"null"`.
    /// Upstream writes `null` at 100 of the 116 leaf paths its own
    /// `zc_config_to_string` emits, so this is not an edge. R2304 (item 642)
    /// kept the assertion and removed the class of bug: `Json5Value` has a
    /// `Null` and a `Bool`, so no renderer has to guess which it is looking at.
    #[test]
    fn a_bare_literal_keeps_its_type_and_re_renders_as_itself() {
        for (raw, want) in [
            // `scouting/multicast/enabled` is inserted as the bare word `false`.
            ("false", Json5Value::Bool(false)),
            ("true", Json5Value::Bool(true)),
            ("null", Json5Value::Null),
            ("65535", Json5Value::Number(String::from("65535"))),
        ] {
            let parsed = parse_json5_value(raw).unwrap_or_else(|| panic!("{raw:?} must parse"));
            assert_eq!(parsed, want, "{raw:?}");
            assert_eq!(
                parsed.to_json5_text(),
                raw,
                "{raw:?} must re-render as itself"
            );
        }
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
    ///
    /// R2303 (open-debt item 636) moved `["a", bare]` out on the SAME argument
    /// one delimiter over. R2304 (item 642) moved it BACK, and the reversal is
    /// the whole of that item: `["a", bare]` is not json5 — an identifier is a
    /// KEY spelling, never a value — and the hand-rolled parser that admitted it
    /// was the second, laxer reader this crate carried. Upstream refuses the
    /// same insert at the door (`Z_EGENERIC`, measured at a real schema key);
    /// wz accepted it, emitted it, and then refused its own document.
    #[test]
    fn a_value_that_is_not_json5_is_refused_rather_than_stored() {
        for raw in [
            "{unbalanced: 1",
            "nested: 1}",
            "{\"quote: \"still open\"",
            "[\"unterminated",
            // A `[` closed by a `}`.
            "{\"a\":[}",
            "\"unbalanced'",
            "",
            // R2304 — an identifier where a VALUE belongs. Both delimiters.
            "{enabled: bare}",
            "[\"a\", bare]",
        ] {
            assert_eq!(parse_json5_value(raw), None, "must refuse {raw:?}");
        }
    }

    /// A value this crate does not decompose still round-trips, because the
    /// reader keeps its structure rather than its source text.
    ///
    /// R311y573 established the rule — upstream accepts an object at any config
    /// path and `ze_publication_cache` REQUIRES one (`timestamping`), so
    /// refusing objects made a whole upstream family unusable on wz. R2303
    /// added arrays: upstream's own `zc_config_to_string` writes
    /// `plugins_loading/search_dirs`, which mixes an object with strings, and it
    /// was the ONLY leaf of 116 in a default document wz refused.
    ///
    /// The assertion is now the ROUND TRIP rather than "stored verbatim",
    /// because R2304 stopped storing text: what comes back is the same VALUE,
    /// whose spelling is the emitter's canonical one.
    #[test]
    fn a_compound_value_survives_the_round_trip() {
        for raw in [
            "{nested: 1}",
            "{\"enabled\":{\"router\":true,\"peer\":true,\"client\":true}}",
            // A brace INSIDE a string must not close the object early.
            "{\"body\":\"}\"}",
            // Upstream's `plugins_loading/search_dirs`, trimmed.
            "[{\"kind\":\"current_exe_parent\",\"value\":null},\".\"]",
            "[1,2,3]",
            "[[\"a\"],[\"b\"]]",
        ] {
            let parsed = parse_json5_value(raw).unwrap_or_else(|| panic!("{raw:?} must parse"));
            let rendered = parsed.to_json5_text();
            assert_eq!(
                parse_json5_value(&rendered),
                Some(parsed),
                "{raw:?} rendered to {rendered:?}, which is a different value"
            );
        }
    }

    /// Build an owned config through the C doors, as a caller does.
    unsafe fn config_of(entries: &[(&str, &str)]) -> z_owned_config_t {
        // SAFETY: a zeroed owned config is the gravestone this ABI defines.
        let mut cfg: z_owned_config_t = unsafe { std::mem::zeroed() };
        // SAFETY: a writable owned slot.
        assert_eq!(unsafe { z_config_default(&mut cfg) }, Z_OK);
        for (key, value) in entries {
            let k = std::ffi::CString::new(*key).expect("key has no NUL");
            let v = std::ffi::CString::new(*value).expect("value has no NUL");
            // SAFETY: a live config and two NUL-terminated strings.
            let rc = unsafe {
                zc_config_insert_json5(z_config_loan_mut(&mut cfg), k.as_ptr(), v.as_ptr())
            };
            assert_eq!(rc, Z_OK, "the C insert path refused {key} = {value}");
        }
        cfg
    }

    /// Read an owned string out and free it, the way a C caller must.
    unsafe fn take_text(out: &mut crate::abi::z_owned_string_t) -> String {
        let text = if out.ptr.is_null() {
            String::new()
        } else {
            // SAFETY: an owned string this crate minted, `len` bytes long.
            let bytes = unsafe { std::slice::from_raw_parts(out.ptr, out.len) };
            String::from_utf8(bytes.to_vec()).expect("wz emits UTF-8")
        };
        // SAFETY: a live owned string; freeing it is the caller's contract.
        unsafe {
            crate::string::z_string_drop(
                (out as *mut crate::abi::z_owned_string_t).cast::<crate::abi::z_moved_string_t>(),
            );
        }
        text
    }

    /// `zc_config_get_from_str`, as a C caller reads it.
    unsafe fn get_text(cfg: &z_owned_config_t, key: &str) -> (ZResult, String) {
        let k = std::ffi::CString::new(key).expect("key has no NUL");
        // SAFETY: a zeroed owned string is this ABI's gravestone.
        let mut out: crate::abi::z_owned_string_t = unsafe { std::mem::zeroed() };
        // SAFETY: a live config, a NUL-terminated key, a writable out-param.
        let rc = unsafe { zc_config_get_from_str(z_config_loan(cfg), k.as_ptr(), &mut out) };
        // SAFETY: the out-param the call just wrote.
        (rc, unsafe { take_text(&mut out) })
    }

    /// The keys THIS MODULE declares as upstream's `Z_CONFIG_*`, paired with a
    /// value each. The population is the constant list itself, so a key added
    /// beside them is covered here without an edit; the cross-implementation
    /// half derives its own population from upstream's header instead
    /// (`zenoh_c_config_document_oracle`).
    fn declared_keys() -> Vec<(&'static str, &'static str)> {
        vec![
            (MODE_KEY, "\"client\""),
            (CONNECT_KEY, "[\"tcp/127.0.0.1:17447\"]"),
            (LISTEN_KEY, "[\"tcp/127.0.0.1:17448\"]"),
            (MULTICAST_LOCATOR_KEY, "\"224.0.0.224:7446\""),
            (SCOUTING_TIMEOUT_KEY, "1234"),
            (SESSION_ZID_KEY, "\"0102030405\""),
        ]
    }

    /// R2303 (open-debt item 636) — the DOCUMENT round trip through the C
    /// doors: what `zc_config_to_string` writes, `zc_config_from_str` reads,
    /// with every value intact.
    ///
    /// Asserted per KEY rather than by comparing the two documents, because a
    /// document comparison passes when both are empty. The multi-segment keys
    /// are what carry the test: those are the ones the flat spelling used to
    /// emit and the nested reader now has to walk back, and the assertion below
    /// refuses to run if the population has lost them.
    #[test]
    fn the_emitted_document_reads_back_through_the_c_doors() {
        let keys = declared_keys();
        assert!(
            keys.iter().filter(|(k, _)| k.contains('/')).count() >= 2,
            "without multi-segment keys this proves nothing about nesting"
        );
        // SAFETY: the fixture drives the same doors a C caller does.
        let cfg = unsafe { config_of(&keys) };

        // SAFETY: a zeroed owned string is this ABI's gravestone.
        let mut doc: crate::abi::z_owned_string_t = unsafe { std::mem::zeroed() };
        // SAFETY: a live config and a writable out-param.
        assert_eq!(
            unsafe { zc_config_to_string(z_config_loan(&cfg), &mut doc) },
            Z_OK
        );
        // SAFETY: the out-param just written.
        let document = unsafe { take_text(&mut doc) };
        assert!(
            document.contains("\"connect\": {"),
            "the emitted document must NEST, got {document}"
        );

        let text = std::ffi::CString::new(document.clone()).expect("no interior NUL");
        // SAFETY: a zeroed owned config is the gravestone this ABI defines.
        let mut back: z_owned_config_t = unsafe { std::mem::zeroed() };
        // SAFETY: a writable slot and a NUL-terminated document.
        assert_eq!(
            unsafe { zc_config_from_str(&mut back, text.as_ptr()) },
            Z_OK,
            "wz must read its own document back:\n{document}"
        );
        for (key, _) in &keys {
            // SAFETY: two live configs.
            let (want_rc, want) = unsafe { get_text(&cfg, key) };
            // SAFETY: as above.
            let (got_rc, got) = unsafe { get_text(&back, key) };
            assert_eq!((want_rc, &want), (got_rc, &got), "{key} did not survive");
        }
        // SAFETY: both configs are live and owned here.
        unsafe {
            z_config_drop((&mut { cfg } as *mut z_owned_config_t).cast());
            z_config_drop((&mut { back } as *mut z_owned_config_t).cast());
        }
    }

    /// R2303 (open-debt item 636) — the FLAT spelling still loads, and loads to
    /// the same state as the nested one.
    ///
    /// A deliberate superset over upstream, which refuses flat: every config
    /// file wz's own `zc_config_to_string` wrote before this round is flat, and
    /// a reader that could not open them would strand them. Stated as a
    /// predicate here rather than as a sentence in the door's doc, because a
    /// sentence is what nobody re-measures.
    #[test]
    fn the_flat_spelling_this_crate_used_to_emit_still_loads() {
        let keys = declared_keys();
        // SAFETY: the fixture drives the C doors.
        let nested_src = unsafe { config_of(&keys) };
        let state =
            unsafe { config_state(z_config_loan(&nested_src) as *mut _) }.expect("a live state");
        let flat = flat_document(state);
        assert!(
            flat.contains("\"connect/endpoints\""),
            "the fixture must be FLAT, got {flat}"
        );

        let text = std::ffi::CString::new(flat.clone()).expect("no interior NUL");
        // SAFETY: a zeroed owned config is the gravestone this ABI defines.
        let mut back: z_owned_config_t = unsafe { std::mem::zeroed() };
        // SAFETY: a writable slot and a NUL-terminated document.
        assert_eq!(
            unsafe { zc_config_from_str(&mut back, text.as_ptr()) },
            Z_OK,
            "the flat spelling must still load:\n{flat}"
        );
        for (key, _) in &keys {
            // SAFETY: two live configs.
            let (want_rc, want) = unsafe { get_text(&nested_src, key) };
            // SAFETY: as above.
            let (got_rc, got) = unsafe { get_text(&back, key) };
            assert_eq!((want_rc, &want), (got_rc, &got), "{key} did not survive");
        }
        // SAFETY: both configs are live and owned here.
        unsafe {
            z_config_drop((&mut { nested_src } as *mut z_owned_config_t).cast());
            z_config_drop((&mut { back } as *mut z_owned_config_t).cast());
        }
    }

    /// R2303 (open-debt item 636) — an INTERIOR path answers with the subtree
    /// beneath it, as upstream's does.
    ///
    /// This is what makes the document round trip observationally faithful
    /// rather than merely successful: reading `{"connect":{"endpoints":[…]}}`
    /// stores one leaf at `connect/endpoints`, so a store that answered only
    /// exact entries would have lost `connect` — a key the document plainly
    /// states — the moment the reader learned to nest.
    ///
    /// The three cases are asserted together because each one alone can pass
    /// with the others broken: an exact leaf, an interior node above it, and a
    /// path that names nothing at all.
    #[test]
    fn an_interior_path_answers_with_the_subtree_beneath_it() {
        // SAFETY: the fixture drives the C doors.
        let cfg = unsafe {
            config_of(&[
                (CONNECT_KEY, "[\"tcp/127.0.0.1:17447\"]"),
                (SCOUTING_TIMEOUT_KEY, "1234"),
                (MULTICAST_LOCATOR_KEY, "\"224.0.0.224:7446\""),
            ])
        };
        // The exact leaf.
        // SAFETY: a live config.
        assert_eq!(
            unsafe { get_text(&cfg, CONNECT_KEY) },
            (Z_OK, String::from("[\"tcp/127.0.0.1:17447\"]"))
        );
        // The interior node ABOVE two leaves, re-nested and compact.
        // SAFETY: as above.
        assert_eq!(
            unsafe { get_text(&cfg, "scouting") },
            (
                Z_OK,
                String::from("{\"multicast\":{\"address\":\"224.0.0.224:7446\"},\"timeout\":1234}")
            )
        );
        // And a path naming nothing is still absent — the widening must not
        // turn every string into a hit.
        // SAFETY: as above.
        assert_eq!(unsafe { get_text(&cfg, "scout") }.0, Z_EPARSE);
        // SAFETY: as above.
        assert_eq!(unsafe { get_text(&cfg, "connect/endpoints/0") }.0, Z_EPARSE);
        // SAFETY: the config is live and owned here.
        unsafe { z_config_drop((&mut { cfg } as *mut z_owned_config_t).cast()) };
    }

    /// R2303 (open-debt item 636) — a config that cannot BE a document is
    /// refused by the emit door rather than emitted lossily.
    ///
    /// The state is reachable only because `ConfigState` is a flat map, which
    /// upstream's tree is not; `render_nested`'s refusal is what keeps the door
    /// from picking a winner between two keys the caller stated.
    #[test]
    fn a_config_that_cannot_nest_is_refused_by_the_emit_door() {
        // SAFETY: the fixture drives the C doors.
        let cfg = unsafe { config_of(&[("mode", "\"client\""), ("mode/router", "\"peer\"")]) };
        // SAFETY: a zeroed owned string is this ABI's gravestone.
        let mut out: crate::abi::z_owned_string_t = unsafe { std::mem::zeroed() };
        // SAFETY: a live config and a writable out-param.
        let rc = unsafe { zc_config_to_string(z_config_loan(&cfg), &mut out) };
        assert_eq!(rc, Z_EGENERIC, "a config that cannot nest must not emit");
        // SAFETY: the out-param, left as the gravestone the door installed.
        assert!(unsafe { take_text(&mut out) }.is_empty());
        // SAFETY: the config is live and owned here.
        unsafe { z_config_drop((&mut { cfg } as *mut z_owned_config_t).cast()) };
    }

    /// R2304 (open-debt item 642) — STATING A SUBTREE AS AN OBJECT AND STATING
    /// ITS LEAF BUILD THE SAME CONFIG.
    ///
    /// This is what the item was about, at the store rather than at the ABI.
    /// `ConfigState` used to keep whatever key it was HANDED, so
    /// `insert("connect", "{\"endpoints\":[…]}")` left one opaque entry at
    /// `connect` and nothing answered `connect/endpoints` — the very key
    /// `session.rs` reads to find where to connect. Upstream answers either
    /// spelling, measured.
    ///
    /// The population is DERIVED: every key here that carries a `/` is split at
    /// its last separator and stated both ways, and a fixture with no such key
    /// fails rather than passing on nothing.
    #[test]
    fn stating_an_object_and_stating_its_leaf_build_the_same_config() {
        let cases = [
            (CONNECT_KEY, "[\"tcp/127.0.0.1:17447\"]"),
            (LISTEN_KEY, "[\"tcp/127.0.0.1:17448\"]"),
            (SCOUTING_TIMEOUT_KEY, "1234"),
            (MULTICAST_LOCATOR_KEY, "\"224.0.0.224:7446\""),
        ];
        let multi = cases.iter().filter(|(k, _)| k.contains('/')).count();
        assert!(
            multi >= 3,
            "only {multi} multi-segment key(s), so this proves little"
        );

        for (path, value) in cases {
            let Some((parent, leaf)) = path.rsplit_once('/') else {
                continue;
            };
            let mut by_leaf = ConfigState::default();
            by_leaf.insert_value(path, parse_json5_value(value).expect("a value"));

            let mut by_object = ConfigState::default();
            let object = format!("{{\"{leaf}\": {value}}}");
            by_object.insert_value(parent, parse_json5_value(&object).expect("an object"));

            assert_eq!(
                by_object.render(path),
                by_leaf.render(path),
                "stating `{object}` at {parent} must reach {path}"
            );
            assert_eq!(
                by_object.first(path),
                by_leaf.first(path),
                "the OPEN path reads {path}, and it must see the same either way"
            );
            assert_eq!(
                by_object.render_nested().expect("no conflict"),
                by_leaf.render_nested().expect("no conflict"),
                "the two spellings must emit the same document"
            );
        }
    }

    /// R2304 (open-debt item 642) — re-stating a key REPLACES its subtree,
    /// which is upstream's own semantics rather than a choice made here.
    ///
    /// Measured on `libzenohc.so` 1.10.0: `insert("scouting", "{\"delay\":99}")`
    /// then `insert("scouting", "{\"timeout\":77}")` leaves `delay` back at
    /// `null`. A merge would make wz remember an instruction upstream forgot,
    /// and a caller clearing a subtree by re-stating it would find the old
    /// members still there.
    #[test]
    fn re_stating_a_key_replaces_its_subtree() {
        let mut state = ConfigState::default();
        state.insert_value(
            "scouting",
            parse_json5_value("{\"delay\": 99, \"timeout\": 1}").expect("an object"),
        );
        assert_eq!(state.render("scouting/delay").as_deref(), Some("99"));
        state.insert_value(
            "scouting",
            parse_json5_value("{\"timeout\": 77}").expect("an object"),
        );
        assert_eq!(
            state.render("scouting/delay"),
            None,
            "a member the second statement did not mention must be gone"
        );
        assert_eq!(state.render("scouting/timeout").as_deref(), Some("77"));
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A real loadable storage volume, written the way a third party would write one.
//!
//! Its whole dependency list is `wz-volume-abi`. That is the demonstration: the
//! ABI crate is sufficient to author a volume, with no session, no runtime and no
//! wz internals behind it. If this file ever needs another wz crate to compile,
//! the ABI has leaked and the leak is the bug.
//!
//! ## Why it is durable
//!
//! The host keeps an in-memory read mirror over any backend, because the in-tree
//! `StorageBackend::get` returns a BORROWED value and a store that deserialised
//! on every read could not satisfy that borrow. A consequence is that a volatile
//! volume's proof is weak: every read inside one process is answered by the
//! host's mirror, so "the host called through the vtable" and "the host answered
//! itself" look identical.
//!
//! Surviving a PROCESS restart is not like that. Only the `.so` can supply a
//! value the previous process stored, and it can only reach the new host through
//! `store_entries`. So this volume writes one file per key under a root the host
//! hands it in `configure`, and the witness discriminates on the restart.
//!
//! ## Format
//!
//! One file per key: `k<hex-of-utf8-key>.wzv`, or `r.wzv` for the mount-root
//! slot. Hex because a key legally contains `/`, and a distinct one-letter prefix
//! because the root slot is the ABSENCE of a key rather than the empty key —
//! encoding it as empty hex would make the two indistinguishable, and hex digits
//! can never collide with `r`.
//!
//! Each file is a little-endian record of the fields
//! [`wz_volume_abi::StoredEntry`] carries. Writes go to a temp file and are
//! renamed into place, so a reader never observes a half-written value.
//!
//! ## Observability, out of band
//!
//! [`wz_volume_example_puts`] and [`wz_volume_example_creates`] are exported
//! counters that are deliberately NOT in the vtable. A test that read them
//! THROUGH the vtable would be asking the mechanism under test to vouch for
//! itself; resolving a separate symbol makes the count evidence about the vtable
//! rather than evidence from it.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use wz_volume_abi::{
    EntrySink, StoreConfig, StoreHandle, StoredEntry, VolumeCapability, VolumeEntry, VolumeVTable,
    DELETED, ERR, HISTORY_LATEST, INSERTED, OK, PERSISTENCE_DURABLE, PERSISTENCE_VOLATILE,
    REPLACED,
};

const ID: &[u8] = b"wzvol_example\0";
const NAME: &[u8] = b"wz-volume-example (durable file volume)\0";
const VERSION: &[u8] = b"0.1.0\0";

/// Times `store_put` completed a write. Read via [`wz_volume_example_puts`].
static PUTS: AtomicU32 = AtomicU32::new(0);
/// Times `create_store` handed back a live store.
static CREATES: AtomicU32 = AtomicU32::new(0);

/// The configured root, or `None` until `configure` has been called with one.
///
/// A `Mutex` rather than a `OnceLock`: the host may load the same `.so` into a
/// process that reconfigures it, and a write-once cell would make the second
/// configuration silently ineffective instead of visible.
static ROOT: Mutex<Option<PathBuf>> = Mutex::new(None);

/// One live store — a directory the keys of one hosted storage live under.
struct Store {
    dir: PathBuf,
}

unsafe extern "C" fn id() -> *const c_char {
    ID.as_ptr().cast()
}

unsafe extern "C" fn name() -> *const c_char {
    NAME.as_ptr().cast()
}

unsafe extern "C" fn version() -> *const c_char {
    VERSION.as_ptr().cast()
}

/// This volume is durable ONLY once it has somewhere to write.
///
/// Reporting `Durable` with no root would be a claim the volume cannot keep, and
/// the host reads this to decide whether the storage above it may skip a
/// newer-wins pass — so an unconfigured volume reports `Volatile` and means it.
unsafe extern "C" fn capability() -> VolumeCapability {
    let configured = ROOT.lock().map(|guard| guard.is_some()).unwrap_or(false);
    VolumeCapability {
        persistence: if configured {
            PERSISTENCE_DURABLE
        } else {
            PERSISTENCE_VOLATILE
        },
        history: HISTORY_LATEST,
    }
}

/// Read a NUL-terminated C string, or `None` for a null pointer.
///
/// # Safety
/// `ptr` is null or points at a NUL-terminated string valid for this call.
unsafe fn opt_str(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the caller's contract — NUL-terminated and valid for the call.
    let raw = unsafe { CStr::from_ptr(ptr) };
    raw.to_str().ok().map(str::to_owned)
}

/// Take the operator's root directory.
///
/// # Safety
/// `config` is null or a NUL-terminated C string valid for this call.
unsafe extern "C" fn configure(config: *const c_char) -> c_int {
    // SAFETY: the caller's contract, delegated to `opt_str`.
    let Some(text) = (unsafe { opt_str(config) }) else {
        // No root: refuse rather than silently become a volatile in-memory
        // volume. A host that asked for THIS volume asked for durability, and
        // quietly not providing it is the failure mode that is discovered later,
        // by data loss, instead of now.
        return ERR;
    };
    let text = text.trim();
    // The refusal path, driven by the host's own config rather than a build flag,
    // so ONE loaded `.so` can exercise both arms of the loader's configure-failure
    // handling in one test process.
    //
    // A REFUSAL FAILS CLOSED: any previously configured root is cleared before
    // returning. A volume that kept writing to a root the operator has since
    // replaced — because the replacement was rejected — would be persisting data
    // somewhere nobody named any more, which is worse than persisting none.
    if text.is_empty() || text == "refuse" {
        clear_root();
        return ERR;
    }
    let root = PathBuf::from(text);
    if fs::create_dir_all(&root).is_err() {
        clear_root();
        return ERR;
    }
    match ROOT.lock() {
        Ok(mut guard) => {
            *guard = Some(root);
            OK
        }
        Err(_) => ERR,
    }
}

/// Forget the configured root, so [`capability`] reports Volatile and
/// [`create_store`] refuses. Used by every `configure` failure path — see the
/// fail-closed note there.
fn clear_root() {
    if let Ok(mut guard) = ROOT.lock() {
        *guard = None;
    }
}

/// `k<hex>` for a key, `r` for the mount-root slot; see the module doc.
fn file_stem(key: Option<&str>) -> String {
    match key {
        None => String::from("r"),
        Some(k) => {
            let mut s = String::with_capacity(1 + k.len() * 2);
            s.push('k');
            for b in k.as_bytes() {
                s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
                s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
            }
            s
        }
    }
}

/// Inverse of [`file_stem`]: `Some(None)` is the root slot, `None` is "not one of
/// ours" (a stray file, which is skipped rather than guessed at).
fn key_from_stem(stem: &str) -> Option<Option<String>> {
    let mut chars = stem.chars();
    match chars.next()? {
        'r' if chars.next().is_none() => Some(None),
        'k' => {
            let hex: Vec<char> = chars.collect();
            if hex.len() % 2 != 0 {
                return None;
            }
            let mut bytes = Vec::with_capacity(hex.len() / 2);
            for pair in hex.chunks(2) {
                let hi = pair[0].to_digit(16)?;
                let lo = pair[1].to_digit(16)?;
                bytes.push((hi * 16 + lo) as u8);
            }
            String::from_utf8(bytes).ok().map(Some)
        }
        _ => None,
    }
}

/// A length-prefixed byte block.
fn put_block(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Read a length-prefixed byte block, advancing `at`.
fn take_block<'a>(buf: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let end = at.checked_add(4)?;
    let len = u32::from_le_bytes(buf.get(*at..end)?.try_into().ok()?) as usize;
    let body_end = end.checked_add(len)?;
    let body = buf.get(end..body_end)?;
    *at = body_end;
    Some(body)
}

/// Serialise one value. Field order mirrors [`StoredEntry`]'s declaration so the
/// two stay easy to read against each other.
fn encode(entry: &StoredEntry, payload: &[u8], zid: &[u8], schema: Option<&str>) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + zid.len() + 32);
    out.extend_from_slice(&entry.ts_time.to_le_bytes());
    put_block(&mut out, zid);
    out.push(u8::from(entry.has_encoding != 0));
    out.extend_from_slice(&entry.encoding_packed_id.to_le_bytes());
    put_block(&mut out, schema.unwrap_or("").as_bytes());
    put_block(&mut out, payload);
    out
}

/// One decoded value, owned so the sink call borrows from locals.
struct Decoded {
    ts_time: u64,
    zid: Vec<u8>,
    has_encoding: bool,
    packed_id: u32,
    schema: Option<String>,
    payload: Vec<u8>,
}

fn decode(buf: &[u8]) -> Option<Decoded> {
    let mut at = 0usize;
    let ts_time = u64::from_le_bytes(buf.get(0..8)?.try_into().ok()?);
    at += 8;
    let zid = take_block(buf, &mut at)?.to_vec();
    let has_encoding = *buf.get(at)? != 0;
    at += 1;
    let end = at.checked_add(4)?;
    let packed_id = u32::from_le_bytes(buf.get(at..end)?.try_into().ok()?);
    at = end;
    let schema_bytes = take_block(buf, &mut at)?;
    let schema = if schema_bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8(schema_bytes.to_vec()).ok()?)
    };
    let payload = take_block(buf, &mut at)?.to_vec();
    Some(Decoded {
        ts_time,
        zid,
        has_encoding,
        packed_id,
        schema,
        payload,
    })
}

/// Write `bytes` to `path` via a temp file + rename, so a concurrent reader sees
/// either the old value or the new one and never a partial record.
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.to_path_buf();
    tmp.set_extension("wzv.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// A store's file for `key`.
fn key_path(dir: &Path, key: Option<&str>) -> PathBuf {
    dir.join(format!("{}.wzv", file_stem(key)))
}

/// Create one store, or null.
///
/// # Safety
/// `config` points at a valid [`StoreConfig`] whose string fields are
/// NUL-terminated and valid for this call.
unsafe extern "C" fn create_store(config: *const StoreConfig) -> StoreHandle {
    if config.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: non-null per the check above, and valid per the caller's contract.
    let cfg = unsafe { &*config };
    // SAFETY: the config's `name` is NUL-terminated per the ABI.
    let Some(name) = (unsafe { opt_str(cfg.name) }) else {
        return std::ptr::null_mut();
    };
    let Ok(guard) = ROOT.lock() else {
        return std::ptr::null_mut();
    };
    let Some(root) = guard.as_ref() else {
        // Unconfigured: refuse. This is the same position `configure` takes —
        // never quietly serve a store with nowhere to persist it.
        return std::ptr::null_mut();
    };
    // The storage NAME picks the subdirectory, so two storages on one volume do
    // not share a key space. Non-alphanumerics are mapped rather than rejected:
    // the name arrives over the wire, and a volume that panics on an odd byte is
    // a volume a foreign client can take down.
    let safe: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let dir = root.join(safe);
    if fs::create_dir_all(&dir).is_err() {
        return std::ptr::null_mut();
    }
    CREATES.fetch_add(1, Ordering::SeqCst);
    Box::into_raw(Box::new(Store { dir })).cast()
}

/// Borrow a store from its handle.
///
/// The returned lifetime is the CALLER's choice, not `'static`: the allocation
/// does outlive any one call (it is a leaked `Box`), but it ends at `store_drop`,
/// and claiming `'static` would say otherwise.
///
/// # Safety
/// `handle` is a live handle from [`create_store`] that has not been dropped.
unsafe fn store_of<'a>(handle: StoreHandle) -> Option<&'a Store> {
    if handle.is_null() {
        return None;
    }
    // SAFETY: the caller's contract — a live `Box<Store>` leaked as a raw
    // pointer, whose lifetime the host manages via `store_drop`.
    Some(unsafe { &*handle.cast::<Store>() })
}

/// The three borrowed slices a [`StoredEntry`] carries, extracted once.
///
/// The slices borrow for as long as the `entry` reference does, which is exactly
/// the ABI's guarantee — the host owns those buffers for the duration of the call
/// and no longer.
///
/// # Safety
/// `entry` is a valid [`StoredEntry`] whose pointers are valid for this call.
unsafe fn entry_parts(entry: &StoredEntry) -> (Option<String>, &[u8], &[u8]) {
    // SAFETY: NUL-terminated or null per the ABI.
    let key = unsafe { opt_str(entry.key) };
    let payload = if entry.payload.is_null() || entry.payload_len == 0 {
        &[][..]
    } else {
        // SAFETY: `payload_len` bytes at a non-null pointer, per the ABI, valid
        // for the duration of the call — which is all this is used for.
        unsafe { std::slice::from_raw_parts(entry.payload, entry.payload_len) }
    };
    let zid = if entry.ts_zid.is_null() || entry.ts_zid_len == 0 {
        &[][..]
    } else {
        // SAFETY: as above, for the timestamp's zid prefix.
        unsafe { std::slice::from_raw_parts(entry.ts_zid, entry.ts_zid_len) }
    };
    (key, payload, zid)
}

/// Store one value.
///
/// # Safety
/// `handle` is live and `entry` is valid for this call.
unsafe extern "C" fn store_put(handle: StoreHandle, entry: *const StoredEntry) -> c_int {
    if entry.is_null() {
        return ERR;
    }
    // SAFETY: non-null per the check, valid per the caller's contract.
    let e = unsafe { &*entry };
    // SAFETY: the caller's contract, delegated.
    let Some(store) = (unsafe { store_of(handle) }) else {
        return ERR;
    };
    // SAFETY: as above.
    let (key, payload, zid) = unsafe { entry_parts(e) };
    // SAFETY: NUL-terminated or null per the ABI.
    let schema = unsafe { opt_str(e.encoding_schema) };
    let path = key_path(&store.dir, key.as_deref());
    let existed = path.exists();
    if write_atomically(&path, &encode(e, payload, zid, schema.as_deref())).is_err() {
        return ERR;
    }
    PUTS.fetch_add(1, Ordering::SeqCst);
    if existed {
        REPLACED
    } else {
        INSERTED
    }
}

/// Remove one key. [`DELETED`] even when absent — the in-tree seam's contract.
///
/// # Safety
/// `handle` is live and `entry` is valid for this call.
unsafe extern "C" fn store_delete(handle: StoreHandle, entry: *const StoredEntry) -> c_int {
    if entry.is_null() {
        return ERR;
    }
    // SAFETY: non-null per the check, valid per the caller's contract.
    let e = unsafe { &*entry };
    // SAFETY: the caller's contract, delegated.
    let Some(store) = (unsafe { store_of(handle) }) else {
        return ERR;
    };
    // SAFETY: NUL-terminated or null per the ABI.
    let key = unsafe { opt_str(e.key) };
    let path = key_path(&store.dir, key.as_deref());
    match fs::remove_file(&path) {
        Ok(()) => DELETED,
        // An absent key is still Deleted; anything else is a real I/O failure.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => DELETED,
        Err(_) => ERR,
    }
}

/// Report every stored value through `sink`.
///
/// # Safety
/// `handle` is live, and `sink` is a valid function pointer that does not unwind.
unsafe extern "C" fn store_entries(
    handle: StoreHandle,
    sink: EntrySink,
    ctx: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract, delegated.
    let Some(store) = (unsafe { store_of(handle) }) else {
        return ERR;
    };
    let Ok(entries) = fs::read_dir(&store.dir) else {
        return ERR;
    };
    for dirent in entries.flatten() {
        let path = dirent.path();
        // Only this volume's own records, and only well-formed ones. A stray
        // file is SKIPPED rather than reported as an empty value: inventing a
        // key the host never stored would be worse than losing a file nobody
        // wrote through this ABI.
        if path.extension().and_then(|e| e.to_str()) != Some("wzv") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(key) = key_from_stem(stem) else {
            continue;
        };
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Some(d) = decode(&bytes) else {
            continue;
        };
        // The C strings must outlive the sink call, so they are built into locals
        // here rather than in a helper that would drop them at its own return.
        let key_c = key.as_ref().map(|k| {
            let mut v = k.clone().into_bytes();
            v.push(0);
            v
        });
        let schema_c = d.schema.as_ref().map(|s| {
            let mut v = s.clone().into_bytes();
            v.push(0);
            v
        });
        let out = StoredEntry {
            key: key_c
                .as_ref()
                .map_or(std::ptr::null(), |v| v.as_ptr().cast()),
            payload: d.payload.as_ptr(),
            payload_len: d.payload.len(),
            has_encoding: c_int::from(d.has_encoding),
            encoding_packed_id: d.packed_id,
            encoding_schema: schema_c
                .as_ref()
                .map_or(std::ptr::null(), |v| v.as_ptr().cast()),
            ts_time: d.ts_time,
            ts_zid: d.zid.as_ptr(),
            ts_zid_len: d.zid.len(),
        };
        // SAFETY: `sink` is the host's, per the ABI; `out`'s pointers borrow
        // locals that outlive this call.
        unsafe { sink(ctx, &out as *const StoredEntry) };
    }
    OK
}

/// Release a store.
///
/// # Safety
/// `handle` came from [`create_store`] and is dropped exactly once.
unsafe extern "C" fn store_drop(handle: StoreHandle) {
    if handle.is_null() {
        return;
    }
    // SAFETY: the caller's contract — reclaim the `Box` `create_store` leaked.
    drop(unsafe { Box::from_raw(handle.cast::<Store>()) });
}

static VTABLE: VolumeVTable = VolumeVTable {
    id,
    name,
    version,
    capability,
    configure,
    create_store,
    store_put,
    store_delete,
    store_entries,
    store_drop,
};

static ENTRY: VolumeEntry = VolumeEntry::new(&VTABLE as *const VolumeVTable);

/// The one symbol the host resolves. See `wz_volume_abi::ENTRY_SYMBOL`.
///
/// # Safety
/// Returns a pointer to a `static`, so it is valid for as long as this library
/// stays loaded — the lifetime the ABI contract requires.
#[no_mangle]
pub unsafe extern "C" fn wz_volume_entry() -> *const VolumeEntry {
    &ENTRY as *const VolumeEntry
}

/// Out-of-band witness: how many values this volume has written.
///
/// Deliberately NOT part of the vtable — see the module doc.
///
/// # Safety
/// Reads a `static` atomic; safe to call from any thread at any time.
#[no_mangle]
pub unsafe extern "C" fn wz_volume_example_puts() -> u32 {
    PUTS.load(Ordering::SeqCst)
}

/// Out-of-band witness: how many stores this volume has created.
///
/// # Safety
/// As [`wz_volume_example_puts`].
#[no_mangle]
pub unsafe extern "C" fn wz_volume_example_creates() -> u32 {
    CREATES.load(Ordering::SeqCst)
}

// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.24 — the DYNAMIC storage-volume host: `dlopen` loading, the ABI gate, and
//! the adapter that makes a loaded `.so` an ordinary
//! [`Volume`](wz_session_core::storage_volume::Volume).
//!
//! ## The atom R311y256 deprecated on a condition that has now fired
//!
//! R311y256 deprecated `storage-mgr-dynamic-volume-loading` as OBVIATED, on the
//! ground that wz composes volumes at BUILD time through cargo features and
//! `cfg`. That was true, and the round wrote the condition into the reason rather
//! than dropping the atom: *"if `plugin-dynamic-loading` is ever built, this
//! returns with it."* R311y492 built `plugin-dynamic-loading`; R311y496 moved this
//! atom back to `reserved` and made Layer A5 PRINT it as OPEN on every run so the
//! condition could not be forgotten a second time. This module closes it.
//!
//! ## Why the adapter is an ordinary `Volume` and not a new seam
//!
//! [`DynamicVolume`] implements the same runtime-agnostic
//! [`Volume`](wz_session_core::storage_volume::Volume) trait
//! [`MemoryVolume`](wz_session_core::storage_volume::MemoryVolume) and
//! [`FilesystemVolume`](crate::filesystem_storage::FilesystemVolume) do, so
//! `RuntimeStorageManager::register_volume` takes it with no change and every
//! storage-manager feature above it — strip-prefix, the complete flag, GC,
//! wildcard updates — composes over a loaded volume for free. A dynamic volume
//! that needed its own registry would have made all of that conditional.
//!
//! ## The read mirror, and what it means for what this proves
//!
//! [`StorageBackend::get`](wz_session_core::storage_backend::StorageBackend::get)
//! returns a BORROWED [`StoredData`], so a backend must own the value it hands
//! back. A store that deserialised across the ABI on every read could not satisfy
//! that borrow. [`DynamicStore`] therefore does exactly what
//! [`FilesystemStorage`](crate::filesystem_storage::FilesystemStorage) does: it
//! keeps an in-memory mirror for reads and writes THROUGH to the volume.
//!
//! The honest consequence, stated because it bounds every claim made about this
//! atom: within one process, a read is answered by the mirror, so a read alone
//! cannot distinguish a working volume from a broken one. What CANNOT come from
//! the mirror is a value the PREVIOUS process stored — that reaches a fresh host
//! only through
//! [`store_entries`](wz_volume_abi::VolumeVTable::store_entries) at
//! [`create_storage`](wz_session_core::storage_volume::Volume::create_storage)
//! time. Durability across a restart is therefore the discriminator the witness
//! uses, not a bonus leg.
//!
//! ## Lifetime: `Arc<Library>`, not a leak
//!
//! `crate::plugin` leaks its registry because a plugin's effects (a thread it
//! spawned, a `&'static str` it returned) can outlive any handle the host holds,
//! so there is no moment at which `dlclose` is provably safe. A volume is
//! different in one specific way: every pointer into its library that the host
//! keeps is reachable from a [`DynamicStore`] or the [`DynamicVolume`] itself, and
//! both are ordinary owned values. So this module shares one
//! [`Arc`](std::sync::Arc)`<Library>` between the volume and every store it
//! creates, which makes the mapping outlive its last user by construction instead
//! of by argument. Dropping the last store after the volume is a correct order,
//! and so is the reverse.

use std::collections::BTreeMap;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use wz_session_core::sample::{EncodingHint, TimestampHint};
use wz_session_core::storage_backend::{
    History, StorageBackend, StorageInsertionResult, StoredData,
};
use wz_session_core::storage_config::StorageConfig;
use wz_session_core::storage_volume::{Capability, Persistence, Volume, VolumeError};
use wz_volume_abi::{
    Compatibility, EntryFn, StoreConfig, StoreHandle, StoredEntry, VolumeEntry, VolumeVTable,
    DELETED, ENTRY_SYMBOL, HISTORY_ALL, INSERTED, OK, PERSISTENCE_DURABLE, REPLACED,
};

/// Why loading or configuring a dynamic volume refused.
///
/// Every variant names its operand. "volume failed to load" with no path, or
/// "incompatible" with no numbers, is the diagnostic that sends the next reader
/// into this file.
#[derive(Debug)]
pub enum DynamicVolumeError {
    /// `dlopen` refused — missing file, missing dependency, not an ELF.
    Open { path: PathBuf, source: String },
    /// The library loaded but exports no `wz_volume_entry`.
    NoEntrySymbol { path: PathBuf, source: String },
    /// The entry function returned null.
    NullEntry { path: PathBuf },
    /// The ABI gate refused. Carries which check failed and both operands.
    Incompatible {
        path: PathBuf,
        verdict: Compatibility,
    },
    /// The descriptor's vtable pointer was null.
    NullVTable { path: PathBuf },
    /// A metadata getter returned a string that is not UTF-8.
    BadMetadata { path: PathBuf, field: &'static str },
    /// `configure` returned non-zero. No store is created from a volume that
    /// refused its configuration.
    ConfigureRefused { id: String, code: i32 },
    /// The operator's config string contains an interior NUL, so it cannot cross
    /// a C ABI at all. Reported rather than truncated: a silently shortened
    /// directory path is a volume rooted somewhere the operator did not ask for.
    ConfigNotCString { id: String },
}

impl std::fmt::Display for DynamicVolumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open { path, source } => {
                write!(f, "dlopen {} failed: {source}", path.display())
            }
            Self::NoEntrySymbol { path, source } => write!(
                f,
                "{} exports no `wz_volume_entry`: {source} — is it a wz storage volume?",
                path.display()
            ),
            Self::NullEntry { path } => {
                write!(f, "{}'s wz_volume_entry returned null", path.display())
            }
            Self::Incompatible { path, verdict } => write!(
                f,
                "{} failed the volume ABI gate: {verdict:?} — rebuild it against \
                 this host's wz-volume-abi",
                path.display()
            ),
            Self::NullVTable { path } => {
                write!(f, "{}'s entry carries a null vtable", path.display())
            }
            Self::BadMetadata { path, field } => {
                write!(f, "{}'s `{field}` is not valid UTF-8", path.display())
            }
            Self::ConfigureRefused { id, code } => write!(
                f,
                "volume `{id}` refused its configuration (code {code}); no storage \
                 will be hosted on it"
            ),
            Self::ConfigNotCString { id } => write!(
                f,
                "volume `{id}`'s configuration contains an interior NUL and cannot \
                 cross the C ABI"
            ),
        }
    }
}

impl std::error::Error for DynamicVolumeError {}

/// Copy a NUL-terminated C string out of a volume getter.
///
/// # Safety
/// `ptr` must be a valid NUL-terminated string for the duration of the call.
unsafe fn copy_cstr(
    ptr: *const c_char,
    path: &Path,
    field: &'static str,
) -> Result<String, DynamicVolumeError> {
    if ptr.is_null() {
        return Err(DynamicVolumeError::BadMetadata {
            path: path.to_path_buf(),
            field,
        });
    }
    // SAFETY: the caller's contract, and the ABI's, is a NUL-terminated string
    // valid for the library's lifetime; this copies out of it immediately.
    let raw = unsafe { CStr::from_ptr(ptr) };
    raw.to_str()
        .map(str::to_owned)
        .map_err(|_| DynamicVolumeError::BadMetadata {
            path: path.to_path_buf(),
            field,
        })
}

/// One `dlopen`ed storage volume, usable anywhere a
/// [`Volume`](wz_session_core::storage_volume::Volume) is.
pub struct DynamicVolume {
    id: String,
    name: String,
    version: String,
    path: PathBuf,
    vtable: *const VolumeVTable,
    /// Shared with every [`DynamicStore`] this volume creates, so the mapping
    /// outlives its last user by construction — see the module doc.
    library: Arc<libloading::Library>,
}

impl std::fmt::Debug for DynamicVolume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicVolume")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl DynamicVolume {
    /// `dlopen` `path`, resolve the entry symbol, run the ABI gate, and copy the
    /// metadata out.
    ///
    /// `configure` is NOT called. Loading and configuring are separate on
    /// purpose: a host may want to know what a `.so` claims to be before letting
    /// it act, and an ABI gate that ran after the volume had already been handed
    /// a directory would be worth nothing.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, DynamicVolumeError> {
        let path = path.as_ref().to_path_buf();
        // SAFETY: `dlopen` runs the library's initialisers, which is arbitrary
        // code from a file the operator named. That is the irreducible trust in
        // dynamic loading and is why this atom is AP/std/unix-only and opt-in;
        // the host makes no claim beyond "the operator asked for this path".
        let library =
            unsafe { libloading::Library::new(&path) }.map_err(|e| DynamicVolumeError::Open {
                path: path.clone(),
                source: e.to_string(),
            })?;

        // SAFETY: the symbol's type is the ABI contract's `EntryFn`. If the
        // library exports something else under that name, the gate below is the
        // only thing between us and it — which is exactly why the entry function
        // is specified to do nothing but return a pointer.
        let entry_fn = unsafe { library.get::<EntryFn>(ENTRY_SYMBOL) }.map_err(|e| {
            DynamicVolumeError::NoEntrySymbol {
                path: path.clone(),
                source: e.to_string(),
            }
        })?;

        // SAFETY: calling the resolved symbol. Its contract is to return a
        // pointer to a `static` and run no initialisation.
        let entry: *const VolumeEntry = unsafe { entry_fn() };
        if entry.is_null() {
            return Err(DynamicVolumeError::NullEntry { path });
        }
        // SAFETY: non-null, and the contract makes it valid for the library's
        // lifetime. Only the plain data fields are read here — the vtable pointer
        // is not followed until the gate below passes, which is the whole
        // ordering the compatibility check depends on.
        let entry_ref = unsafe { &*entry };

        let verdict = entry_ref.compatibility();
        if !verdict.is_ok() {
            return Err(DynamicVolumeError::Incompatible { path, verdict });
        }

        let vtable = entry_ref.vtable;
        if vtable.is_null() {
            return Err(DynamicVolumeError::NullVTable { path });
        }
        // SAFETY: the gate passed, so this host's `VolumeVTable` / `StoredEntry`
        // and the volume's agree on ABI, size and alignment; the pointer is
        // non-null and valid for the library's lifetime.
        let vt = unsafe { &*vtable };

        // SAFETY (x3): the getters are the gated vtable's, and their contract is
        // a NUL-terminated UTF-8 string valid for the library's lifetime. Copied
        // immediately, so no caller ends up holding a pointer into the mapping.
        let id = unsafe { copy_cstr((vt.id)(), &path, "id") }?;
        let name = unsafe { copy_cstr((vt.name)(), &path, "name") }?;
        let version = unsafe { copy_cstr((vt.version)(), &path, "version") }?;

        // `entry_fn` is a `Symbol<'_>` borrowing `library`; its last use is the
        // call above, so NLL releases the borrow before `library` moves into the
        // Arc below. No explicit drop — `Symbol` implements no `Drop`, so one
        // would be a no-op that reads like a lifetime fix (clippy::drop_non_drop
        // says exactly this).
        Ok(Self {
            id,
            name,
            version,
            path,
            vtable,
            library: Arc::new(library),
        })
    }

    /// The `volume_id` a [`StorageConfig`] names to be hosted here — the volume's
    /// own claim, not the operator's.
    ///
    /// Taking it from the `.so` rather than from a CLI flag is deliberate: an
    /// operator-supplied id would let two different `.so`s be registered under one
    /// name, and the storage that named it would then be hosted on whichever was
    /// loaded last.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Its human name, as declared.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Its version string, as declared.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Where it was loaded from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Hand the volume its operator configuration. Call once, before hosting any
    /// storage on it.
    ///
    /// A refusal is an error rather than a warning: the whole point of a
    /// configured volume is that it was given somewhere to keep data, and hosting
    /// storages on one that rejected its configuration is how an operator ends up
    /// with a durable-looking storage that persists nothing.
    pub fn configure(&self, config: Option<&str>) -> Result<(), DynamicVolumeError> {
        let owned = match config {
            None => None,
            Some(c) => Some(
                CString::new(c).map_err(|_| DynamicVolumeError::ConfigNotCString {
                    id: self.id.clone(),
                })?,
            ),
        };
        let ptr = owned
            .as_ref()
            .map_or(std::ptr::null(), |c| c.as_ptr().cast());
        // SAFETY: the gated vtable's `configure`; `ptr` is null or a valid
        // NUL-terminated string owned by `owned`, which outlives the call.
        let rc = unsafe { ((*self.vtable).configure)(ptr) };
        if rc != OK {
            return Err(DynamicVolumeError::ConfigureRefused {
                id: self.id.clone(),
                code: rc,
            });
        }
        Ok(())
    }
}

// NO `unsafe impl Send for DynamicVolume`, deliberately.
//
// One was written here first, with a justification that read well and was not
// true: it said a registered volume must be movable across worker threads. It
// need not be. `VolumeRegistry::register_volume` takes `Box<dyn Volume>` with no
// `Send` bound, so a manager holding volumes is itself not `Send` — which is a
// property the storage host already relies on (`run_storage_host` keeps its
// manager TASK-LOCAL for exactly this reason). The impl therefore had no
// consumer, and an `unsafe impl` with no consumer is unjustified `unsafe`: it
// asserts a property nothing checks, for a use nobody makes.
//
// [`DynamicStore`] is the opposite case and does carry one — see the SAFETY note
// there. It is REQUIRED: `Volume::create_storage` returns
// `Box<dyn StorageBackend + Send>`, so without it a loaded volume could not
// satisfy its own trait.
impl Volume for DynamicVolume {
    fn capability(&self) -> Capability {
        // SAFETY: the gated vtable's `capability`, a pure getter per the ABI.
        let cap = unsafe { ((*self.vtable).capability)() };
        Capability {
            // An unrecognised code reads as the CONSERVATIVE value in both axes.
            // Persistence decides whether an operator's data survives, so a
            // volume that garbled the field must not thereby claim durability;
            // history decides whether the newer-wins gate above is skipped, and
            // skipping it wrongly loses versions.
            persistence: if cap.persistence == PERSISTENCE_DURABLE {
                Persistence::Durable
            } else {
                Persistence::Volatile
            },
            history: if cap.history == HISTORY_ALL {
                History::All
            } else {
                History::Latest
            },
        }
    }

    fn create_storage(
        &self,
        config: &StorageConfig,
    ) -> Result<Box<dyn StorageBackend + Send>, VolumeError> {
        // Every string crossing the boundary is built here so it outlives the
        // call; an interior NUL is a refusal rather than a truncation, since a
        // silently shortened keyexpr is a storage mounted somewhere else.
        let name = CString::new(config.name.as_str()).map_err(|_| {
            VolumeError::CreateFailed(format!(
                "storage name `{}` contains an interior NUL and cannot cross the \
                 volume ABI",
                config.name
            ))
        })?;
        let key_expr = CString::new(config.key_expr.as_str()).map_err(|_| {
            VolumeError::CreateFailed(format!(
                "storage key_expr `{}` contains an interior NUL and cannot cross \
                 the volume ABI",
                config.key_expr
            ))
        })?;
        let strip = match config.strip_prefix.as_deref() {
            None => None,
            Some(s) => Some(CString::new(s).map_err(|_| {
                VolumeError::CreateFailed(format!(
                    "storage strip_prefix `{s}` contains an interior NUL and cannot \
                     cross the volume ABI"
                ))
            })?),
        };
        let abi_config = StoreConfig {
            name: name.as_ptr(),
            key_expr: key_expr.as_ptr(),
            strip_prefix: strip.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
        };

        // SAFETY: the gated vtable's `create_store`; `abi_config`'s pointers
        // borrow the CStrings above, which outlive the call.
        let handle = unsafe { ((*self.vtable).create_store)(&abi_config as *const StoreConfig) };
        if handle.is_null() {
            return Err(VolumeError::CreateFailed(format!(
                "volume `{}` ({}) refused to create a store for `{}`",
                self.id,
                self.path.display(),
                config.name
            )));
        }

        let mut store = DynamicStore {
            handle,
            vtable: self.vtable,
            mirror: BTreeMap::new(),
            history: self.capability().history,
            _library: Arc::clone(&self.library),
        };
        // Rebuild the read mirror from whatever the volume already holds. THIS is
        // where durability becomes observable: a value a previous process wrote
        // reaches this host only here, and nowhere else.
        store.load_mirror();
        Ok(Box::new(store))
    }
}

/// One store created by a [`DynamicVolume`]: the opaque handle plus the read
/// mirror the borrowed-`get` seam needs.
pub struct DynamicStore {
    handle: StoreHandle,
    vtable: *const VolumeVTable,
    /// The read path. Kept write-through-consistent with the volume; rebuilt from
    /// it at creation. Identical in role to
    /// [`FilesystemStorage`](crate::filesystem_storage::FilesystemStorage)'s
    /// mirror, and identical in its consequence for what a same-process read can
    /// prove (see the module doc).
    mirror: BTreeMap<Option<String>, StoredData>,
    history: History,
    /// Held, never read: it keeps the mapping the `vtable` and `handle` point into
    /// alive for exactly as long as this store exists.
    _library: Arc<libloading::Library>,
}

impl std::fmt::Debug for DynamicStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicStore")
            .field("keys", &self.mirror.len())
            .field("history", &self.history)
            .finish_non_exhaustive()
    }
}

// SAFETY: the non-`Send` fields are the `handle` and `vtable` POINTERS into a
// mapping the `Arc<Library>` beside them keeps alive for exactly this store's
// lifetime; `libloading::Library` is itself `Send + Sync`, so moving the store
// moves pointers whose target outlives it. The remaining question is whether the
// VOLUME tolerates that, and the ABI answers it explicitly: a `StoreHandle` may be
// used from another thread but never from two at once (wz-volume-abi's module
// doc). The host upholds that by construction — a store is owned by exactly one
// `StorageService`, which touches it through `&mut self` for mutations and `&self`
// for reads.
//
// It is REQUIRED, not a convenience: `Volume::create_storage` returns
// `Box<dyn StorageBackend + Send>` so that a volume-created backend can drive an
// async runtime storage service across tokio worker threads (the R311y61 `+ Send`
// bound). Without this impl a dynamic volume could not satisfy its own trait.
unsafe impl Send for DynamicStore {}

/// The mirror-rebuild callback's context.
struct SinkCtx<'a> {
    mirror: &'a mut BTreeMap<Option<String>, StoredData>,
}

/// Receive one entry from the volume during a mirror rebuild.
///
/// # Safety
/// Called only by a volume's `store_entries`, with `ctx` the pointer handed to it
/// and `entry` valid for this call — the [`EntrySink`](wz_volume_abi::EntrySink)
/// contract.
///
/// A panic here (an allocation failure, a corrupted record) aborts rather than
/// unwinding across the boundary, which is what `extern "C"` already guarantees
/// and the right outcome: a half-built mirror would serve a storage that silently
/// lost keys.
unsafe extern "C" fn mirror_sink(ctx: *mut c_void, entry: *const StoredEntry) {
    if ctx.is_null() || entry.is_null() {
        return;
    }
    // SAFETY: `ctx` is the `&mut SinkCtx` this host passed to `store_entries`,
    // which borrows the mirror for the duration of that call and is not aliased.
    let ctx = unsafe { &mut *ctx.cast::<SinkCtx<'_>>() };
    // SAFETY: non-null per the check, valid per the sink contract.
    let e = unsafe { &*entry };

    // SAFETY: NUL-terminated or null per the ABI; copied out immediately, so no
    // pointer into the volume's memory is retained.
    let key = unsafe { cstr_to_owned(e.key) };
    let payload = if e.payload.is_null() || e.payload_len == 0 {
        Vec::new()
    } else {
        // SAFETY: `payload_len` readable bytes at a non-null pointer, per the ABI.
        unsafe { std::slice::from_raw_parts(e.payload, e.payload_len) }.to_vec()
    };
    let zid = if e.ts_zid.is_null() || e.ts_zid_len == 0 {
        Vec::new()
    } else {
        // SAFETY: as above, for the timestamp's zid prefix.
        unsafe { std::slice::from_raw_parts(e.ts_zid, e.ts_zid_len) }.to_vec()
    };
    let encoding = if e.has_encoding != 0 {
        Some(EncodingHint {
            packed_id: e.encoding_packed_id,
            // SAFETY: NUL-terminated or null per the ABI.
            schema: unsafe { cstr_to_owned(e.encoding_schema) },
        })
    } else {
        None
    };
    ctx.mirror.insert(
        key,
        StoredData {
            payload,
            encoding,
            timestamp: TimestampHint {
                time: e.ts_time,
                zid,
            },
        },
    );
}

/// `None` for a null pointer, else the copied string. Lossy on invalid UTF-8
/// rather than dropping the entry: a key that does not round-trip is still a key
/// the volume holds, and losing it silently is worse than rendering it oddly.
///
/// # Safety
/// `ptr` is null or a valid NUL-terminated string for this call.
unsafe fn cstr_to_owned(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let raw = unsafe { CStr::from_ptr(ptr) };
    Some(raw.to_string_lossy().into_owned())
}

/// Build the `StoredEntry` for a mutation and run `f` on it.
///
/// The CStrings and slices live in this function's frame, so the entry's pointers
/// are valid for exactly the call `f` makes and no longer — which is the ABI's
/// borrow contract, expressed as a scope instead of a comment.
fn with_entry<R>(
    key: Option<&str>,
    payload: &[u8],
    encoding: Option<&EncodingHint>,
    timestamp: &TimestampHint,
    f: impl FnOnce(&StoredEntry) -> R,
) -> R {
    // A key or schema with an interior NUL cannot cross a C ABI at all. Neither is
    // truncated — a truncated key would be stored under a DIFFERENT key, which is
    // the worse of the two failures — and neither is dropped SILENTLY, because a
    // key that becomes the mount-root slot is also a key stored somewhere the
    // caller did not ask for. wz keyexprs cannot contain NUL, so this is
    // defence-in-depth rather than a live path; it is logged so that if it ever
    // becomes a live path, it is visible rather than inferred from missing data.
    let key_c = key.and_then(|k| match CString::new(k) {
        Ok(c) => Some(c),
        Err(_) => {
            log::error!(
                "wz dynamic volume: key {k:?} contains an interior NUL and cannot cross \
                 the volume ABI; it is being written to the mount-root slot instead"
            );
            None
        }
    });
    let schema_c = encoding
        .and_then(|e| e.schema.as_deref())
        .and_then(|s| match CString::new(s) {
            Ok(c) => Some(c),
            Err(_) => {
                log::error!(
                    "wz dynamic volume: encoding schema {s:?} contains an interior NUL \
                     and cannot cross the volume ABI; the value is stored without it"
                );
                None
            }
        });
    let entry = StoredEntry {
        key: key_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
        payload: if payload.is_empty() {
            std::ptr::null()
        } else {
            payload.as_ptr()
        },
        payload_len: payload.len(),
        has_encoding: c_int::from(encoding.is_some()),
        encoding_packed_id: encoding.map_or(0, |e| e.packed_id),
        encoding_schema: schema_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
        ts_time: timestamp.time,
        ts_zid: if timestamp.zid.is_empty() {
            std::ptr::null()
        } else {
            timestamp.zid.as_ptr()
        },
        ts_zid_len: timestamp.zid.len(),
    };
    f(&entry)
}

impl DynamicStore {
    /// REPLACE the mirror with the volume's own contents.
    ///
    /// The clear is load-bearing rather than tidiness, even though the only
    /// current caller runs on a fresh empty store. Without it this is a MERGE, and
    /// a merge means any later re-synchronisation would keep serving a key the
    /// volume has since deleted — a stale read that no test on the create path
    /// could see. The name says replace, so it replaces.
    fn load_mirror(&mut self) {
        self.mirror.clear();
        let mut ctx = SinkCtx {
            mirror: &mut self.mirror,
        };
        // SAFETY: the gated vtable's `store_entries` on a live handle; the sink
        // is this module's and `ctx` outlives the call, which is the whole
        // duration the volume may use it for.
        let rc = unsafe {
            ((*self.vtable).store_entries)(
                self.handle,
                mirror_sink,
                (&mut ctx) as *mut SinkCtx<'_> as *mut c_void,
            )
        };
        if rc != OK {
            // Fail CLEARLY and keep serving what was mirrored: refusing to host
            // the storage would take the node's admin surface down with it, and an
            // operator diagnosing a volume needs the node reachable.
            log::error!(
                "wz dynamic volume: store_entries returned {rc}; the read mirror may \
                 be incomplete and keys the volume holds will not be served"
            );
        }
    }

    /// How many keys the mirror holds — the read-path size, for diagnostics.
    pub fn len(&self) -> usize {
        self.mirror.len()
    }

    /// Whether the mirror holds no keys.
    pub fn is_empty(&self) -> bool {
        self.mirror.is_empty()
    }
}

impl Drop for DynamicStore {
    fn drop(&mut self) {
        // SAFETY: the gated vtable's `store_drop`, called exactly once on a
        // handle `create_storage` produced and never with null (a null handle is
        // an error there, so no store is built around one).
        unsafe { ((*self.vtable).store_drop)(self.handle) };
    }
}

impl StorageBackend for DynamicStore {
    fn put(
        &mut self,
        key: Option<&str>,
        payload: Vec<u8>,
        encoding: Option<EncodingHint>,
        timestamp: TimestampHint,
    ) -> StorageInsertionResult {
        let rc = with_entry(key, &payload, encoding.as_ref(), &timestamp, |entry| {
            // SAFETY: the gated vtable's `store_put` on a live handle; the
            // entry's pointers are valid for this call, per `with_entry`.
            unsafe { ((*self.vtable).store_put)(self.handle, entry as *const StoredEntry) }
        });
        // Anything that is not one of the two DOCUMENTED successes is a failure,
        // not just the `ERR` sentinel. A volume returning an unrecognised code is
        // out of contract, and reading it as success is how a value that was never
        // written comes to be believed persisted.
        if rc != INSERTED && rc != REPLACED {
            // The mirror is still updated, exactly as the filesystem backend does
            // under this infallible seam: a subsequent read in this process must
            // reflect what the caller just did, and the write failure is reported
            // rather than swallowed.
            log::error!(
                "wz dynamic volume: store_put did not report a write (code {rc}) for key \
                 {key:?}; the value serves from memory but is NOT persisted in the volume"
            );
        }
        // The RESULT is the mirror's, not the volume's. That is the same choice
        // the filesystem backend makes and for the same reason: Inserted vs
        // Replaced is a statement about what this store now serves, which the
        // mirror is authoritative for.
        let data = StoredData {
            payload,
            encoding,
            timestamp,
        };
        match self.mirror.insert(key.map(String::from), data) {
            Some(_) => StorageInsertionResult::Replaced,
            None => StorageInsertionResult::Inserted,
        }
    }

    fn delete(&mut self, key: Option<&str>, timestamp: TimestampHint) -> StorageInsertionResult {
        let rc = with_entry(key, &[], None, &timestamp, |entry| {
            // SAFETY: as `put`'s.
            unsafe { ((*self.vtable).store_delete)(self.handle, entry as *const StoredEntry) }
        });
        // As `put`: only the documented success counts as one.
        if rc != DELETED {
            log::error!(
                "wz dynamic volume: store_delete did not report a removal (code {rc}) for \
                 key {key:?}; the key is gone from memory but may remain in the volume"
            );
        }
        self.mirror.remove(&key.map(String::from));
        // Deleted unconditionally, including for an absent key — the seam's
        // contract (zenoh memory_backend `remove_entry` then `Deleted`).
        StorageInsertionResult::Deleted
    }

    fn get(&self, key: Option<&str>) -> Option<&StoredData> {
        self.mirror.get(&key.map(String::from))
    }

    fn get_all_entries(&self) -> Vec<(Option<String>, TimestampHint)> {
        self.mirror
            .iter()
            .map(|(k, v)| (k.clone(), v.timestamp.clone()))
            .collect()
    }

    fn history(&self) -> History {
        // The VOLUME's declared history, not a hardcoded Latest: a loaded volume
        // that keeps every version must not have the newer-wins gate above it
        // silently dropping them.
        self.history
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises every leg that CONFIGURES the example volume.
    ///
    /// A loaded volume's configuration is process-global — it must be, since
    /// `dlopen` of an already-mapped library returns the SAME mapping and the ABI
    /// specifies `configure` as once-per-volume. cargo runs a crate's unit tests
    /// as THREADS in one process, so two legs each configuring the volume stomp
    /// each other's root. That is not hypothetical: without this lock three of
    /// these legs failed, and the out-of-band put counter read 5 where the leg
    /// had made 2 puts — the other legs' writes.
    ///
    /// The lock is how a test binary that must configure REPEATEDLY keeps each
    /// leg's window exclusive. It is not papering over a defect in the volume: a
    /// host loads and configures a volume exactly once, which is what the ABI
    /// asks for.
    static VOLUME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take [`VOLUME_LOCK`], recovering from poisoning.
    ///
    /// A poisoned lock means an earlier leg panicked while holding it. Its root is
    /// about to be replaced by this leg's anyway, so continuing is correct;
    /// propagating the poison would bury the original failure under a second,
    /// less informative one.
    fn volume_guard() -> std::sync::MutexGuard<'static, ()> {
        VOLUME_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The example volume's `.so`, built by the same cargo invocation that runs
    /// these tests (it is a workspace member and a `dev-dependency` of nothing —
    /// so the lane builds it explicitly; see Layer C1bv).
    fn example_so() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.push("target");
        p.push("debug");
        p.push(if cfg!(target_os = "macos") {
            "libwz_volume_example.dylib"
        } else {
            "libwz_volume_example.so"
        });
        p
    }

    /// The example `.so`, or `None` with a LOUD note.
    ///
    /// The note is not decoration: several legs below return early on `None`, and
    /// a silent early return is a green test that proved nothing — this project's
    /// own anti-masked-skip rule. Layer C1bv builds the `.so` first and is where
    /// its absence is a hard failure; here the worst case is visible rather than
    /// invisible.
    fn require_example() -> Option<PathBuf> {
        let p = example_so();
        if p.exists() {
            return Some(p);
        }
        eprintln!(
            "skip: {} not built — run `cargo build -p wz-volume-example` (Layer C1bv does)",
            p.display()
        );
        None
    }

    fn ts(time: u64) -> TimestampHint {
        TimestampHint {
            time,
            zid: vec![0xAB, 0xCD],
        }
    }

    #[test]
    fn a_missing_library_names_the_path_it_could_not_open() {
        let err = DynamicVolume::load("/nonexistent/wz-not-a-volume.so").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("/nonexistent/wz-not-a-volume.so") && msg.contains("dlopen"),
            "the error names the path and the operation\n  got: {msg}"
        );
    }

    #[test]
    fn a_library_without_the_entry_symbol_is_refused_by_name() {
        // libc / libm are real, loadable shared objects that are emphatically not
        // wz volumes — the honest negative, rather than a file crafted to fail.
        for candidate in ["libm.so.6", "libc.so.6"] {
            if let Ok(v) = DynamicVolume::load(candidate) {
                panic!("{candidate} must not load as a wz volume, got {v:?}");
            }
        }
    }

    /// A wz PLUGIN is not a wz VOLUME, and the distinct entry symbol is what makes
    /// that a refusal rather than a mis-resolved vtable.
    ///
    /// This is the leg that justifies `wz-volume-abi` having its own
    /// `ENTRY_SYMBOL`: were the two the same, this load would succeed, the volume
    /// loader would read a `PluginVTable` through a `VolumeVTable` pointer, and
    /// the ABI gate would pass while doing it (the plugin's descriptor carries the
    /// plugin's own layout numbers).
    #[test]
    fn a_wz_plugin_so_is_not_accepted_as_a_volume() {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.push("target");
        p.push("debug");
        p.push(if cfg!(target_os = "macos") {
            "libwz_plugin_example.dylib"
        } else {
            "libwz_plugin_example.so"
        });
        if !p.exists() {
            eprintln!("skip: {} not built (Layer C1bv builds it)", p.display());
            return;
        }
        let err =
            DynamicVolume::load(&p).expect_err("a plugin .so must not load as a storage volume");
        assert!(
            matches!(err, DynamicVolumeError::NoEntrySymbol { .. }),
            "the refusal must be the MISSING VOLUME ENTRY SYMBOL — anything else \
             means the loader got far enough to read a plugin's vtable as a \
             volume's\n  got: {err}"
        );
    }

    #[test]
    fn the_real_example_loads_and_declares_itself() {
        let Some(so) = require_example() else {
            return;
        };
        let vol = DynamicVolume::load(&so).expect("the example volume loads");
        assert_eq!(vol.id(), "wzvol_example");
        assert!(!vol.version().is_empty());
        assert_eq!(vol.path(), so.as_path());
    }

    #[test]
    fn an_unconfigured_volume_is_volatile_and_hosts_nothing() {
        let Some(so) = require_example() else {
            return;
        };
        let _guard = volume_guard();
        let vol = DynamicVolume::load(&so).expect("loads");
        // FORCE the unconfigured state rather than assume it: another leg may
        // already have configured the shared mapping, and a leg that skipped in
        // that case would be a green test that asserted nothing. A refused
        // `configure` fails CLOSED in the example volume — it clears any root it
        // held — so this establishes the precondition instead of hoping for it.
        assert!(
            vol.configure(Some("refuse")).is_err(),
            "the example refuses this config; the refusal is what clears the root"
        );
        assert_eq!(
            vol.capability().persistence,
            Persistence::Volatile,
            "a volume with nowhere to write must not claim durability"
        );
        // `let Err(..) else` rather than `expect_err`: the Ok type is
        // `Box<dyn StorageBackend + Send>`, which is not `Debug`.
        let Err(err) = vol.create_storage(&StorageConfig::new("s", "demo/**", "wzvol_example"))
        else {
            panic!("an unconfigured volume must refuse to create a store");
        };
        assert!(
            err.to_string().contains("wzvol_example"),
            "the refusal names the volume\n  got: {err}"
        );
    }

    #[test]
    fn a_refusing_configure_is_an_error_that_names_the_volume() {
        let Some(so) = require_example() else {
            return;
        };
        let _guard = volume_guard();
        let vol = DynamicVolume::load(&so).expect("loads");
        let err = vol
            .configure(Some("refuse"))
            .expect_err("the example refuses this config");
        assert!(
            matches!(err, DynamicVolumeError::ConfigureRefused { .. }),
            "a refusal must be reported as ConfigureRefused, not swallowed\n  got: {err}"
        );
        assert!(err.to_string().contains("wzvol_example"));
    }

    #[test]
    fn the_configured_volume_round_trips_through_the_abi_and_is_durable() {
        let Some(so) = require_example() else {
            return;
        };
        let _guard = volume_guard();
        let dir = tempfile::tempdir().expect("tempdir");
        let vol = DynamicVolume::load(&so).expect("loads");
        vol.configure(Some(dir.path().to_str().expect("utf-8 tempdir")))
            .expect("the example accepts a real directory");
        assert_eq!(
            vol.capability(),
            Capability {
                persistence: Persistence::Durable,
                history: History::Latest,
            },
            "a configured file volume declares itself durable"
        );

        let cfg = StorageConfig::new("dyn", "demo/**", "wzvol_example");
        {
            let mut store = vol.create_storage(&cfg).expect("create a store");
            assert_eq!(
                store.put(Some("a"), b"v1".to_vec(), None, ts(10)),
                StorageInsertionResult::Inserted
            );
            assert_eq!(
                store.put(Some("a"), b"v2".to_vec(), None, ts(11)),
                StorageInsertionResult::Replaced,
                "a second put on the same key replaces"
            );
            // The mount-root slot: a strip-configured storage's exact-match value,
            // which is the `None` key the ABI encodes as a null pointer.
            assert_eq!(
                store.put(None, b"root".to_vec(), None, ts(12)),
                StorageInsertionResult::Inserted
            );
            assert_eq!(
                store.get(Some("a")).map(|d| d.payload.clone()),
                Some(b"v2".to_vec())
            );
            // Through the SEAM (`get_all_entries`) rather than the inherent
            // `len`, because `create_storage` hands back a
            // `Box<dyn StorageBackend + Send>` — which is also what the storage
            // service holds, so this is the count the service would see.
            assert_eq!(store.get_all_entries().len(), 2);
        } // dropped: store_drop crosses the ABI, the files remain

        // A SECOND store over the same configured volume sees what the first
        // wrote. Nothing in this process is carrying it: the first store is
        // dropped, and the mirror is rebuilt from `store_entries` alone.
        let store2 = vol.create_storage(&cfg).expect("re-create the store");
        assert_eq!(
            store2.get(Some("a")).map(|d| d.payload.clone()),
            Some(b"v2".to_vec()),
            "the value crossed the ABI to disk and back through store_entries"
        );
        assert_eq!(
            store2.get(None).map(|d| d.payload.clone()),
            Some(b"root".to_vec()),
            "the mount-root (None) slot round-trips as the null key, distinctly \
             from the empty-string key"
        );
        let keys: Vec<Option<String>> = store2
            .get_all_entries()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(keys, vec![None, Some(String::from("a"))]);
        assert_eq!(
            store2.get(Some("a")).map(|d| d.timestamp.time),
            Some(11),
            "the version timestamp round-trips, not just the payload"
        );
    }

    #[test]
    fn the_encoding_and_zid_round_trip_across_the_boundary() {
        let Some(so) = require_example() else {
            return;
        };
        let _guard = volume_guard();
        let dir = tempfile::tempdir().expect("tempdir");
        let vol = DynamicVolume::load(&so).expect("loads");
        vol.configure(Some(dir.path().to_str().expect("utf-8 tempdir")))
            .expect("configure");
        let cfg = StorageConfig::new("enc", "demo/**", "wzvol_example");
        {
            let mut store = vol.create_storage(&cfg).expect("create");
            store.put(
                Some("k"),
                b"body".to_vec(),
                Some(EncodingHint {
                    packed_id: 0x2B,
                    schema: Some(String::from("application/json")),
                }),
                TimestampHint {
                    time: 0xDEAD_BEEF,
                    zid: vec![1, 2, 3, 4],
                },
            );
        }
        let store2 = vol.create_storage(&cfg).expect("re-create");
        let d = store2.get(Some("k")).expect("present after reload");
        assert_eq!(d.payload, b"body".to_vec());
        assert_eq!(d.timestamp.time, 0xDEAD_BEEF);
        assert_eq!(
            d.timestamp.zid,
            vec![1, 2, 3, 4],
            "the timestamp zid is what the newer-wins gate breaks ties on, so it \
             has to survive the crossing"
        );
        let enc = d.encoding.as_ref().expect("the encoding survived");
        assert_eq!(enc.packed_id, 0x2B);
        assert_eq!(enc.schema.as_deref(), Some("application/json"));
    }

    #[test]
    fn a_delete_crosses_the_abi_and_does_not_come_back() {
        let Some(so) = require_example() else {
            return;
        };
        let _guard = volume_guard();
        let dir = tempfile::tempdir().expect("tempdir");
        let vol = DynamicVolume::load(&so).expect("loads");
        vol.configure(Some(dir.path().to_str().expect("utf-8 tempdir")))
            .expect("configure");
        let cfg = StorageConfig::new("del", "demo/**", "wzvol_example");
        {
            let mut store = vol.create_storage(&cfg).expect("create");
            store.put(Some("a"), b"v".to_vec(), None, ts(1));
            assert_eq!(
                store.delete(Some("a"), ts(2)),
                StorageInsertionResult::Deleted
            );
            assert_eq!(
                store.delete(Some("absent"), ts(3)),
                StorageInsertionResult::Deleted,
                "an absent-key delete is still Deleted — the seam's contract"
            );
        }
        // The delete has to have reached the VOLUME, not only the mirror: a fresh
        // store rebuilds from `store_entries`, so a key the volume still held
        // would reappear here.
        let store2 = vol.create_storage(&cfg).expect("re-create");
        assert!(
            store2.get(Some("a")).is_none(),
            "the deleted key came back after a reload, so the delete never crossed \
             the ABI"
        );
        assert!(store2.get_all_entries().is_empty());
    }

    /// The OUT-OF-BAND witness: the example exports counters that are not in the
    /// vtable, so a test can establish the host really called THROUGH it rather
    /// than asking the mechanism under test to vouch for itself.
    #[test]
    fn the_volumes_own_counters_confirm_the_host_called_through_the_vtable() {
        let Some(so) = require_example() else {
            return;
        };
        // The counters are process-global, so the DELTA is only this leg's while
        // no other leg is putting. The lock is what makes the delta a measurement.
        let _guard = volume_guard();
        let dir = tempfile::tempdir().expect("tempdir");
        let vol = DynamicVolume::load(&so).expect("loads");
        vol.configure(Some(dir.path().to_str().expect("utf-8 tempdir")))
            .expect("configure");

        // Resolved through a SEPARATE dlopen of the same library, so the count is
        // read outside the vtable this leg is checking.
        // SAFETY: the same file this test already loaded; `dlopen` of a mapped
        // library returns the same mapping, and the symbols are `extern "C"`
        // getters over `static` atomics.
        let lib = unsafe { libloading::Library::new(&so) }.expect("second dlopen");
        // SAFETY: the example's documented out-of-band witness symbols.
        let puts = unsafe { lib.get::<unsafe extern "C" fn() -> u32>(b"wz_volume_example_puts\0") }
            .expect("the example exports its put counter");
        let creates =
            // SAFETY: as above.
            unsafe { lib.get::<unsafe extern "C" fn() -> u32>(b"wz_volume_example_creates\0") }
                .expect("the example exports its create counter");

        // SAFETY: both are the resolved getters; they read a static atomic.
        let (puts_before, creates_before) = unsafe { (puts(), creates()) };
        let cfg = StorageConfig::new("count", "demo/**", "wzvol_example");
        let mut store = vol.create_storage(&cfg).expect("create");
        store.put(Some("a"), b"v".to_vec(), None, ts(1));
        store.put(Some("b"), b"v".to_vec(), None, ts(2));
        // SAFETY: as above.
        let (puts_after, creates_after) = unsafe { (puts(), creates()) };

        assert_eq!(
            puts_after - puts_before,
            2,
            "the volume's own counter must record BOTH puts; the host's mirror \
             would report success either way, which is why this is read out of band"
        );
        assert_eq!(
            creates_after - creates_before,
            1,
            "exactly one store was created through the vtable"
        );
    }
}

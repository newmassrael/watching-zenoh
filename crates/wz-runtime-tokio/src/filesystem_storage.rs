// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y279 — the `storage-backend-filesystem` atom (§5.24 storage): a
//! **durable, filesystem-backed** [`Volume`] / [`StorageBackend`], the wz
//! counterpart of zenoh's `zenoh-backend-filesystem` plugin. Built on `std`
//! (`std::fs`) with no *new* third-party dependency (only the `log` facade,
//! already in the tree); it plugs into the same runtime-agnostic seam
//! ([`wz_session_core::storage_backend`] / [`wz_session_core::storage_volume`])
//! the in-memory [`MemoryStorage`](wz_session_core::storage_backend::MemoryStorage)
//! / [`MemoryVolume`](wz_session_core::storage_volume::MemoryVolume) implement.
//!
//! Because the seam's [`std::fs`]-using code cannot live in the `no_std`
//! kernel, this concrete backend lives in the std runtime crate — mirroring
//! how the storage *service* driver ([`crate::storage_service`]) is an
//! AP/std binding over the no_std storage kernel.
//!
//! ## Model: in-memory mirror + write-through to disk
//!
//! [`StorageBackend::get`] returns `Option<&StoredData>` — a *reference* — so
//! a backend must own the value it hands back; a pure-disk store (that
//! deserialized into a local on each `get`) could not satisfy the borrow.
//! The durable backend therefore keeps an in-memory mirror (identical
//! in-process semantics to [`MemoryStorage`]) and *write-through*-persists
//! every mutation:
//!
//! - **load-on-open**: [`FilesystemStorage::open`] rebuilds the mirror from
//!   the on-disk files (this is what makes the store survive a restart).
//! - **write-through-on-mutation**: each [`put`](StorageBackend::put) /
//!   [`delete`](StorageBackend::delete) atomically rewrites / removes the
//!   key's file and `fsync`s the file **and** the directory before returning,
//!   so a committed mutation survives a power loss, not merely a graceful
//!   process restart (that is what upgrades the volume from
//!   [`Persistence::Volatile`] to [`Persistence::Durable`]).
//!
//! ## A write that fails (R311y831)
//!
//! A filesystem write can fail (`ENOSPC` / `EACCES` / `EIO`) where an
//! in-memory map cannot, and until R311y831 the seam had no way to say so:
//! `put` / `delete` returned a bare
//! [`StorageInsertionResult`](wz_session_core::storage_backend::StorageInsertionResult),
//! this backend logged the I/O error and **updated the mirror anyway**, and
//! the caller was told the mutation had succeeded. The consequence was not
//! confined to one process: the newer-wins record above the backend
//! (`StorageState::latest`) is what
//! [`replication_events`](wz_session_core::storage_state::StorageState::replication_events)
//! and the aligner digest are derived from, so a `Durable` store advertised to
//! every aligning peer that it held a value it had never written — and a peer
//! that believes you hold it does not send it.
//!
//! The seam now carries
//! [`StorageWriteError`](wz_session_core::storage_backend::StorageWriteError)
//! (zenoh's `ZResult<StorageInsertionResult>`, whose own filesystem backend
//! propagates the write error with `?`, `zenoh-backend-filesystem/src/lib.rs:294-353`),
//! and this backend holds two invariants:
//!
//! - **the mirror shows what a reopen would show** — a write that never
//!   reached the target path does not move it, and one that landed but was not
//!   fsync-confirmed does (see [`Unpersisted`]);
//! - **`Err` means nothing above may record the mutation** — the newer-wins
//!   version record, the replication log and the digest all stay silent, which
//!   is exactly what upstream's storage service does on a failed `put`
//!   (`storages_mgt/service.rs:352-366` skips the cache insert on `Err`), so
//!   the peer re-sends instead of assuming convergence.
//!
//! On a healthy filesystem this is genuinely `Durable`; a disk fault is an
//! environmental error surfaced loudly AND refused, not a silent lie.
//! Volume-*open* failure has always been reported
//! ([`create_storage`](Volume::create_storage) returns
//! [`VolumeError::CreateFailed`]).
//!
//! ## Concurrency
//!
//! One [`FilesystemStorage`] owns its directory. A store is single-threaded
//! (`&mut self` serializes every mutation) and **one live instance per
//! directory** is required — the storage manager upholds this by hosting one
//! storage per configured name. Two live instances over the same directory
//! would keep divergent mirrors; std exposes no portable advisory file lock,
//! so this invariant is a documented contract rather than a runtime guard.
//! (Temp files are given process-unique names so even an accidental
//! concurrent write cannot corrupt a shared temp path.)

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use wz_session_core::sample::{EncodingHint, TimestampHint};
use wz_session_core::storage_backend::{
    History, StorageBackend, StorageInsertionResult, StorageWriteError, StorageWriteResult,
    StoredData,
};
use wz_session_core::storage_config::StorageConfig;
use wz_session_core::storage_volume::{Capability, Persistence, Volume, VolumeError};

/// On-disk record magic + format version. Bumping the trailing digit is a
/// format-version bump; [`deserialize`] refuses any other magic (an unknown
/// version reads as a foreign/corrupt file, never a mis-parse).
const MAGIC: &[u8; 4] = b"WZS1";

/// The reserved filename for the `None` (exact-prefix-match / mount-root)
/// key slot. Starts with `_`, so it cannot collide with a `k…` data
/// filename or a temp / quarantine suffix.
const ROOT_SENTINEL: &str = "__root__";

/// Suffix of a temp file mid-write (crash leftover); [`FilesystemStorage::open`]
/// sweeps these.
const TMP_SUFFIX: &str = ".tmp";

/// Suffix of a quarantined corrupt file; [`FilesystemStorage::open`] leaves
/// these in place (for forensics) and skips them.
const CORRUPT_SUFFIX: &str = ".corrupt";

/// Process-lifetime temp-file counter, so concurrently-written temp files
/// never share a path (paired with the pid).
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// FNV-1a 64-bit — the deterministic, std-only hash used both for the
/// fixed-width filename of a key and for the per-record integrity checksum.
/// Not cryptographic; it is a collision/torn-write *detector*, and key
/// filename collisions are resolved by probing (see [`FilesystemStorage::allocate_filename`]).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Lowercase 16-hex-digit rendering of a 64-bit word — the fixed-width body
/// of a data filename, so the filename length is bounded independent of the
/// key length (a key of any length maps to a 17-char `k################`).
fn hex16(word: u64) -> String {
    format!("{word:016x}")
}

/// Whether every char is a lowercase hex digit.
fn is_all_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `name` is one of *our* data filenames — the `None` sentinel, a
/// `k<hex>` key file, or a `k<hex>_<n>` collision-probe file. Used to decide
/// whether an unreadable / unparseable file is ours-but-damaged (→ quarantine)
/// vs a foreign file (→ ignore entirely: never read, never deleted). Any file
/// this rejects is left untouched.
fn is_our_key_filename(name: &str) -> bool {
    if name == ROOT_SENTINEL {
        return true;
    }
    let Some(rest) = name.strip_prefix('k') else {
        return false;
    };
    match rest.split_once('_') {
        // k<hex>_<probe-digits>
        Some((body, probe)) => {
            is_all_hex(body) && !probe.is_empty() && probe.bytes().all(|b| b.is_ascii_digit())
        }
        // k<hex>
        None => is_all_hex(rest),
    }
}

/// Whether `name` is a single safe path component (no separators, not `.` /
/// `..`, non-empty, no NUL) — a [`StorageConfig::name`] is free-form, so it
/// is validated before being joined onto the volume root (path-traversal
/// guard).
fn is_safe_component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

/// One stored value plus the on-disk filename that backs it (so `put`
/// overwrites and `delete` removes the exact file without re-deriving it).
#[derive(Debug)]
struct Entry {
    data: StoredData,
    file: String,
}

/// A durable, filesystem-backed [`StorageBackend`]: an in-memory mirror
/// (a `key -> `[`StoredData`]` map) kept write-through-consistent with one
/// file per key in a directory. Survives a restart by reloading the files.
#[derive(Debug)]
pub struct FilesystemStorage {
    dir: PathBuf,
    /// The in-memory mirror `get` borrows from + the source of `get_all_entries`.
    map: BTreeMap<Option<String>, Entry>,
    /// The set of filenames currently in use, for O(log n) collision probing
    /// when allocating a filename for a new key.
    used: BTreeSet<String>,
}

impl FilesystemStorage {
    /// Open (creating if absent) the store rooted at `dir`, rebuilding the
    /// in-memory mirror from the on-disk files. This load-on-open is what
    /// makes the store durable across restarts.
    ///
    /// Robustness policy — one damaged, unreadable, or foreign file never
    /// denies access to every other key (the whole point of a per-key layout):
    /// - only listing the directory itself is fatal; every per-entry error is
    ///   logged and skipped (a per-file `EIO` bad sector / `EACCES` / an
    ///   `ENOENT` race must not brick the store);
    /// - one of *our own* leftover temp files (`.wztmp.*.tmp`, from a crash
    ///   mid-write) is swept; a foreign `*.tmp` is left alone;
    /// - a previously-quarantined `*.corrupt` file is skipped;
    /// - a file whose name is not our scheme is a foreign file and is ignored
    ///   entirely (never read, never deleted);
    /// - one of *our* data files whose content fails to deserialize (bad
    ///   magic / checksum / bounds) or fails to read is **quarantined**
    ///   (renamed aside with [`CORRUPT_SUFFIX`] + logged) and loading continues.
    pub fn open(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        let mut map: BTreeMap<Option<String>, Entry> = BTreeMap::new();
        let mut used: BTreeSet<String> = BTreeSet::new();

        // Failing to LIST the directory is a genuine open failure; a failure on
        // any individual entry is not (log + skip).
        for dirent in fs::read_dir(&dir)? {
            let dirent = match dirent {
                Ok(d) => d,
                Err(e) => {
                    log::warn!(
                        "wz-fs-storage: skipping unreadable dir entry in {} ({e})",
                        dir.display()
                    );
                    continue;
                }
            };
            match dirent.file_type() {
                Ok(ft) if ft.is_file() => {}
                Ok(_) => continue, // not a regular file
                Err(e) => {
                    log::warn!("wz-fs-storage: skipping entry with unknown type ({e})");
                    continue;
                }
            }
            let name = dirent.file_name().to_string_lossy().into_owned();
            let path = dirent.path();

            // Our own crash-leftover temp — sweep it. A foreign `*.tmp` is NOT
            // ours to delete, so it falls through to the foreign-file skip.
            if name.starts_with(".wztmp.") && name.ends_with(TMP_SUFFIX) {
                let _ = fs::remove_file(&path);
                continue;
            }
            if name.ends_with(CORRUPT_SUFFIX) {
                continue;
            }
            // Foreign file (not our naming scheme): ignore entirely — never
            // read it, never delete it.
            if !is_our_key_filename(&name) {
                continue;
            }

            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    // Our file, but unreadable (bad sector / perms / race).
                    // Log and skip so the rest of the store still loads.
                    log::error!("wz-fs-storage: cannot read store file {name} ({e}); skipping");
                    continue;
                }
            };
            match deserialize(&bytes) {
                Ok((key, data)) => {
                    // One key always maps to one file (its allocated filename
                    // is reused on rewrite), so a duplicate key here means
                    // external tampering. Keep the latter, quarantine the
                    // former, and never leak the orphaned filename.
                    if let Some(old) = map.remove(&key) {
                        log::warn!(
                            "wz-fs-storage: duplicate on-disk key {key:?} (files {} and {name}); keeping the latter",
                            old.file
                        );
                        used.remove(&old.file);
                        let _ =
                            fs::rename(dir.join(&old.file), dir.join(quarantine_name(&old.file)));
                    }
                    used.insert(name.clone());
                    map.insert(key, Entry { data, file: name });
                }
                Err(e) => {
                    log::error!("wz-fs-storage: corrupt store file {name} ({e}); quarantining");
                    let _ = fs::rename(&path, dir.join(quarantine_name(&name)));
                }
            }
        }

        Ok(Self { dir, map, used })
    }

    /// Allocate an on-disk filename for a not-yet-stored key. `None` is the
    /// fixed [`ROOT_SENTINEL`]; a `Some` key is `k` + the 16-hex FNV of its
    /// bytes, with a `_<n>` probe suffix appended on the (astronomically
    /// rare) hash collision so two distinct keys never share a file.
    fn allocate_filename(&self, key: &Option<String>) -> String {
        let Some(key) = key else {
            return ROOT_SENTINEL.to_string();
        };
        let base = format!("k{}", hex16(fnv1a64(key.as_bytes())));
        if !self.used.contains(&base) {
            return base;
        }
        for n in 1u64.. {
            let cand = format!("{base}_{n}");
            if !self.used.contains(&cand) {
                return cand;
            }
        }
        unreachable!("u64 probe space is never exhausted")
    }

    /// Atomically persist `(key, data)` to `file` in the store directory:
    /// serialize, write a process-unique temp file, `fsync` it, `rename` it
    /// over the target, then `fsync` the directory so the rename itself
    /// survives a power loss.
    fn persist(&self, file: &str, key: Option<&str>, data: &StoredData) -> Result<(), Unpersisted> {
        let bytes = serialize(key, data);
        let tmp_name = format!(
            ".wztmp.{}.{}{}",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
            TMP_SUFFIX
        );
        let tmp_path = self.dir.join(&tmp_name);
        let write_tmp = || -> io::Result<()> {
            let mut f = fs::File::create(&tmp_path)?;
            f.write_all(&bytes)?;
            f.sync_all()
        };
        if let Err(err) = write_tmp() {
            // The temp file never became the target; leave no debris behind
            // (a crash leftover is swept on the next `open`, but a live store
            // should not accumulate them).
            let _ = fs::remove_file(&tmp_path);
            return Err(Unpersisted {
                visible: false,
                err,
            });
        }
        if let Err(err) = fs::rename(&tmp_path, self.dir.join(file)) {
            let _ = fs::remove_file(&tmp_path);
            return Err(Unpersisted {
                visible: false,
                err,
            });
        }
        // The rename LANDED: the directory now resolves `file` to the new
        // bytes, so a reopen in this process's lifetime reads them. Only the
        // durability of that directory entry is unconfirmed.
        fsync_dir(&self.dir).map_err(|err| Unpersisted { visible: true, err })
    }
}

/// A filesystem mutation that did not complete, and — the part the caller
/// needs — WHICH side of it did not.
///
/// The in-memory mirror's contract is that it shows what a *reopen of the
/// directory* would show, so "did the visible filesystem change?" is exactly
/// the question that decides whether the mirror moves. `visible == false`
/// means nothing reached the target path and the mirror must stay put;
/// `visible == true` means the target path already resolves to the new state
/// (the rename landed / the file is unlinked) but that directory entry is not
/// confirmed durable, so the mirror MUST move — otherwise the store would
/// serve one thing and a reopen another, which is the same class of lie in the
/// opposite direction.
///
/// Either way the seam answer is [`StorageWriteError`]: the mutation is not
/// committed and nothing above may record it.
struct Unpersisted {
    visible: bool,
    err: io::Error,
}

impl StorageBackend for FilesystemStorage {
    fn put(
        &mut self,
        key: Option<&str>,
        payload: Vec<u8>,
        encoding: Option<EncodingHint>,
        timestamp: TimestampHint,
    ) -> StorageWriteResult {
        let key_owned = key.map(String::from);
        let data = StoredData {
            payload,
            encoding,
            timestamp,
        };
        let (file, existed) = match self.map.get(&key_owned) {
            Some(e) => (e.file.clone(), true),
            None => (self.allocate_filename(&key_owned), false),
        };
        // Write-through FIRST: the disk decides, and the mirror follows it.
        // R311y831 — before, the mirror was updated even when the write failed
        // and the seam had no way to say so, so a Durable store served (and,
        // through the newer-wins record, ADVERTISED to aligning peers) a value
        // it had not written. `visible` splits the two failure sides; see
        // [`Unpersisted`].
        let outcome = self.persist(&file, key_owned.as_deref(), &data);
        if let Err(Unpersisted { visible, err }) = &outcome {
            log::error!(
                "wz-fs-storage: persist of key {key_owned:?} to {} failed ({err}); the {} \
                 (this put is NOT committed)",
                self.dir.join(&file).display(),
                if *visible {
                    "bytes are in place but the directory entry is not confirmed durable"
                } else {
                    "stored value is unchanged"
                }
            );
            if !*visible {
                return Err(StorageWriteError);
            }
        }
        self.used.insert(file.clone());
        self.map.insert(key_owned, Entry { data, file });
        match outcome {
            // Landed but unconfirmed: the mirror had to move (a reopen sees
            // the new bytes) and the caller still must not record it.
            Err(_) => Err(StorageWriteError),
            Ok(()) if existed => Ok(StorageInsertionResult::Replaced),
            Ok(()) => Ok(StorageInsertionResult::Inserted),
        }
    }

    fn delete(&mut self, key: Option<&str>, _timestamp: TimestampHint) -> StorageWriteResult {
        let key_owned = key.map(String::from);
        // Look the entry up WITHOUT removing it: an unlink the filesystem
        // refuses leaves the record on disk, so the mirror must keep it too
        // (R311y831 — it used to be removed first, which made a failed unlink
        // read back as a successful delete).
        let Some(file) = self.map.get(&key_owned).map(|e| e.file.clone()) else {
            // Absent-key delete is still `Deleted` — the seam contract, and
            // upstream's own `if file.exists()` rule (`files_mgt.rs:198`).
            return Ok(StorageInsertionResult::Deleted);
        };
        let path = self.dir.join(&file);
        let durable = match fs::remove_file(&path) {
            // Persist the unlink itself (dir fsync), so the delete survives a
            // power loss like a put does. A failure here leaves the record
            // already gone from the live directory, so the mirror still
            // follows — only the caller's answer changes.
            Ok(()) => match fsync_dir(&self.dir) {
                Ok(()) => true,
                Err(e) => {
                    log::error!(
                        "wz-fs-storage: dir fsync after delete of {} failed ({e}); the record \
                         is unlinked but the removal is not confirmed durable (this delete is \
                         NOT committed)",
                        path.display()
                    );
                    false
                }
            },
            // Already absent: the removal this call was asked for has happened.
            Err(e) if e.kind() == io::ErrorKind::NotFound => true,
            Err(e) => {
                log::error!(
                    "wz-fs-storage: remove of {} failed ({e}); the key is NOT deleted (its \
                     record is still on disk and still served)",
                    path.display()
                );
                return Err(StorageWriteError);
            }
        };
        self.map.remove(&key_owned);
        self.used.remove(&file);
        if durable {
            Ok(StorageInsertionResult::Deleted)
        } else {
            Err(StorageWriteError)
        }
    }

    fn get(&self, key: Option<&str>) -> Option<&StoredData> {
        self.map.get(&key.map(String::from)).map(|e| &e.data)
    }

    fn get_all_entries(&self) -> Vec<(Option<String>, TimestampHint)> {
        self.map
            .iter()
            .map(|(k, e)| (k.clone(), e.data.timestamp.clone()))
            .collect()
    }
    // history() defaults to History::Latest — a single-version durable store;
    // History::All is the separate `storage-history` atom.
}

/// A durable [`Volume`] that creates one [`FilesystemStorage`] per named
/// storage, each rooted at `root/<config.name>`. The wz counterpart of
/// zenoh's `zenoh-backend-filesystem` volume; [`capability`](Volume::capability)
/// advertises `{ Durable, Latest }`.
#[derive(Debug, Clone)]
pub struct FilesystemVolume {
    root: PathBuf,
}

impl FilesystemVolume {
    /// A filesystem volume whose per-storage directories live under `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl Volume for FilesystemVolume {
    fn capability(&self) -> Capability {
        Capability {
            persistence: Persistence::Durable,
            history: History::Latest,
        }
    }

    fn create_storage(
        &self,
        config: &StorageConfig,
    ) -> Result<Box<dyn StorageBackend + Send>, VolumeError> {
        // The storage's directory is `root/<name>`; `name` is free-form, so
        // reject anything that is not a single safe path component before the
        // join (a `..` / absolute / separator name would escape `root`).
        if !is_safe_component(&config.name) {
            return Err(VolumeError::CreateFailed(format!(
                "invalid storage name {:?}: must be a single path component (no '/', '\\', '.', '..')",
                config.name
            )));
        }
        // Config-agnostic beyond `name`: applying key_expr / strip_prefix /
        // complete above the backend is the storage manager / service's job
        // (same documented divergence as MemoryVolume).
        FilesystemStorage::open(self.root.join(&config.name))
            .map(|s| Box::new(s) as Box<dyn StorageBackend + Send>)
            .map_err(|e| VolumeError::CreateFailed(e.to_string()))
    }
}

/// `fsync` a directory so a `rename` / `unlink` within it is persisted (on
/// Linux, opening the directory read-only and `sync_all`-ing its fd flushes
/// the directory entry).
fn fsync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

/// The quarantine filename for a corrupt / displaced data file.
fn quarantine_name(file: &str) -> String {
    format!("{file}{CORRUPT_SUFFIX}")
}

/// The on-disk frame encodes every field length as a `u32` (see the format
/// table in [`deserialize`]). That is the frame's invariant: no single key /
/// zid / schema / payload exceeds `u32::MAX` bytes — which no zenoh/pico wire
/// value can (there is no ~4 GiB single sample in this system). This helper
/// makes the invariant explicit: a `debug_assert` catches a violation in debug
/// builds, and for every reachable length `n as u32 == n`, so the release path
/// (and the on-disk bytes) are unchanged. Without the guard an oversized field
/// would silently truncate its length prefix and be quarantined on reopen — a
/// silent divergence from the in-memory [`MemoryStorage`]; the assert documents
/// and (in debug) traps that.
fn len_u32(n: usize) -> u32 {
    debug_assert!(
        n <= u32::MAX as usize,
        "wz-fs-storage: field length {n} exceeds the u32 on-disk frame limit"
    );
    n as u32
}

/// Serialize `(key, data)` to the self-describing on-disk frame (see the
/// format table in [`deserialize`]). Little-endian; a trailing FNV-1a
/// checksum over every preceding byte detects a torn / bit-rotted file.
fn serialize(key: Option<&str>, data: &StoredData) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    match key {
        None => out.push(0),
        Some(k) => {
            out.push(1);
            out.extend_from_slice(&len_u32(k.len()).to_le_bytes());
            out.extend_from_slice(k.as_bytes());
        }
    }
    out.extend_from_slice(&data.timestamp.time.to_le_bytes());
    out.extend_from_slice(&len_u32(data.timestamp.zid.len()).to_le_bytes());
    out.extend_from_slice(&data.timestamp.zid);
    match &data.encoding {
        None => out.push(0),
        Some(enc) => {
            out.push(1);
            out.extend_from_slice(&enc.packed_id.to_le_bytes());
            match &enc.schema {
                None => out.push(0),
                Some(s) => {
                    out.push(1);
                    out.extend_from_slice(&len_u32(s.len()).to_le_bytes());
                    out.extend_from_slice(s.as_bytes());
                }
            }
        }
    }
    out.extend_from_slice(&len_u32(data.payload.len()).to_le_bytes());
    out.extend_from_slice(&data.payload);
    let checksum = fnv1a64(&out);
    out.extend_from_slice(&checksum.to_le_bytes());
    out
}

/// A bounds-checked forward reader over the record body.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(bad)?;
        if end > self.buf.len() {
            return Err(bad());
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    /// A `u8` that must be exactly 0 or 1 (a presence flag).
    fn flag(&mut self) -> io::Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(bad()),
        }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

fn bad() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "corrupt wz-fs-storage record")
}

/// Deserialize a record written by [`serialize`], validating the magic, the
/// trailing checksum, every length bound, and the presence flags.
///
/// Frame (little-endian):
/// ```text
/// magic[4]="WZS1" | key_present:u8 | [key_len:u32 + key bytes]
///   | time:u64 | zid_len:u32 + zid | enc_present:u8
///   | [packed_id:u32 | schema_present:u8 | [schema_len:u32 + schema]]
///   | payload_len:u32 + payload | checksum:u64 (FNV-1a of all preceding bytes)
/// ```
fn deserialize(bytes: &[u8]) -> io::Result<(Option<String>, StoredData)> {
    if bytes.len() < 12 {
        return Err(bad());
    }
    let (body, checksum_bytes) = bytes.split_at(bytes.len() - 8);
    let stored = u64::from_le_bytes(checksum_bytes.try_into().unwrap());
    if fnv1a64(body) != stored {
        return Err(bad());
    }

    let mut r = Reader::new(body);
    if r.take(4)? != MAGIC {
        return Err(bad());
    }
    let key = if r.flag()? {
        let len = r.u32()? as usize;
        let raw = r.take(len)?;
        Some(String::from_utf8(raw.to_vec()).map_err(|_| bad())?)
    } else {
        None
    };
    let time = r.u64()?;
    let zid_len = r.u32()? as usize;
    let zid = r.take(zid_len)?.to_vec();
    let encoding = if r.flag()? {
        let packed_id = r.u32()?;
        let schema = if r.flag()? {
            let len = r.u32()? as usize;
            Some(String::from_utf8(r.take(len)?.to_vec()).map_err(|_| bad())?)
        } else {
            None
        };
        Some(EncodingHint { packed_id, schema })
    } else {
        None
    };
    let payload_len = r.u32()? as usize;
    let payload = r.take(payload_len)?.to_vec();
    // Reject trailing garbage: the body must be fully consumed.
    if r.remaining() != 0 {
        return Err(bad());
    }

    Ok((
        key,
        StoredData {
            payload,
            encoding,
            timestamp: TimestampHint { time, zid },
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn ts(time: u64) -> TimestampHint {
        TimestampHint {
            time,
            zid: vec![0x01, 0x02, 0x03],
        }
    }

    fn enc() -> Option<EncodingHint> {
        Some(EncodingHint {
            packed_id: 0x11,
            schema: Some("text/plain".to_string()),
        })
    }

    // ---- in-process seam parity (mirror of MemoryStorage's contract) ----

    #[test]
    fn put_get_roundtrip_and_replace() {
        let dir = tempdir().unwrap();
        let mut s = FilesystemStorage::open(dir.path().to_path_buf()).unwrap();
        assert_eq!(
            s.put(Some("demo/a"), vec![1, 2, 3], None, ts(10)).unwrap(),
            StorageInsertionResult::Inserted
        );
        assert_eq!(s.get(Some("demo/a")).unwrap().payload, vec![1, 2, 3]);
        assert_eq!(
            s.put(Some("demo/a"), vec![4], None, ts(20)).unwrap(),
            StorageInsertionResult::Replaced
        );
        assert_eq!(s.get(Some("demo/a")).unwrap().payload, vec![4]);
    }

    #[test]
    fn delete_removes_and_absent_delete_is_deleted() {
        let dir = tempdir().unwrap();
        let mut s = FilesystemStorage::open(dir.path().to_path_buf()).unwrap();
        s.put(Some("demo/a"), vec![1], None, ts(10)).unwrap();
        assert_eq!(
            s.delete(Some("demo/a"), ts(20)).unwrap(),
            StorageInsertionResult::Deleted
        );
        assert!(s.get(Some("demo/a")).is_none());
        assert_eq!(
            s.delete(Some("demo/missing"), ts(1)).unwrap(),
            StorageInsertionResult::Deleted
        );
    }

    #[test]
    fn none_root_slot_is_independent() {
        let dir = tempdir().unwrap();
        let mut s = FilesystemStorage::open(dir.path().to_path_buf()).unwrap();
        assert_eq!(
            s.put(None, vec![7], None, ts(10)).unwrap(),
            StorageInsertionResult::Inserted
        );
        s.put(Some("a"), vec![1], None, ts(10)).unwrap();
        assert_eq!(s.get(None).unwrap().payload, vec![7]);
        assert_eq!(s.get(Some("a")).unwrap().payload, vec![1]);
    }

    #[test]
    fn get_all_entries_orders_none_first() {
        let dir = tempdir().unwrap();
        let mut s = FilesystemStorage::open(dir.path().to_path_buf()).unwrap();
        s.put(Some("demo/a"), vec![1], None, ts(10)).unwrap();
        s.put(None, vec![9], None, ts(20)).unwrap();
        let entries = s.get_all_entries();
        assert_eq!(
            entries,
            vec![(None, ts(20)), (Some("demo/a".to_string()), ts(10))]
        );
    }

    // ---- durability (the atom's whole point) ----

    #[test]
    fn durability_survives_reopen() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        {
            let mut s = FilesystemStorage::open(root.clone()).unwrap();
            s.put(Some("demo/a"), vec![1, 2, 3], enc(), ts(10)).unwrap();
            s.put(Some("wild/*/x"), vec![9], None, ts(11)).unwrap();
            s.put(None, vec![0xff], None, ts(12)).unwrap();
            s.put(Some("to/delete"), vec![5], None, ts(13)).unwrap();
            s.delete(Some("to/delete"), ts(14)).unwrap();
        } // drop -> a fresh instance must see only the on-disk state
        let s = FilesystemStorage::open(root).unwrap();
        assert_eq!(s.get(Some("demo/a")).unwrap().payload, vec![1, 2, 3]);
        assert_eq!(s.get(Some("demo/a")).unwrap().encoding, enc());
        assert_eq!(s.get(Some("demo/a")).unwrap().timestamp, ts(10));
        assert_eq!(s.get(Some("wild/*/x")).unwrap().payload, vec![9]);
        assert_eq!(s.get(None).unwrap().payload, vec![0xff]);
        assert!(s.get(Some("to/delete")).is_none(), "delete must persist");
    }

    #[test]
    fn overwrite_persists_and_reuses_one_file() {
        // The write-through overwrite path reuses the SAME on-disk file for a
        // key (no orphaned v1), and a fresh reopen must see v2, not stale v1.
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        {
            let mut s = FilesystemStorage::open(root.clone()).unwrap();
            s.put(Some("k/1"), vec![1], None, ts(10)).unwrap();
            s.put(Some("k/1"), vec![2], enc(), ts(20)).unwrap(); // overwrite same key
        }
        let s = FilesystemStorage::open(root.clone()).unwrap();
        assert_eq!(
            s.get(Some("k/1")).unwrap().payload,
            vec![2],
            "reopen sees v2"
        );
        assert_eq!(s.get(Some("k/1")).unwrap().encoding, enc());
        // Exactly one of our data files exists (no orphaned v1 file).
        let data_files = fs::read_dir(&root)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                is_our_key_filename(&n)
            })
            .count();
        assert_eq!(
            data_files, 1,
            "overwrite must reuse the key's file, not orphan it"
        );
    }

    #[test]
    fn long_key_persists() {
        // Regression for the hex-filename length overflow: a key longer than
        // NAME_MAX/2 would overflow a 1:1 hex filename; the hashed filename is
        // fixed-width, and the key rides in the file content.
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let key = "k/".to_string() + &"segment/".repeat(64); // ~520 bytes
        {
            let mut s = FilesystemStorage::open(root.clone()).unwrap();
            assert_eq!(
                s.put(Some(&key), vec![42], None, ts(1)).unwrap(),
                StorageInsertionResult::Inserted
            );
        }
        let s = FilesystemStorage::open(root).unwrap();
        assert_eq!(s.get(Some(&key)).unwrap().payload, vec![42]);
    }

    // ---- write failure: what a store that could not persist may claim ----

    /// Break every subsequent persist for EVERY uid (root included) by
    /// removing the store directory: the temp-file `create` then fails
    /// `ENOENT`. A read-only-directory fixture would be uid-dependent.
    fn break_persistence(root: &Path) {
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_put_whose_persist_fails_does_not_replace_the_durable_value() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let mut s = FilesystemStorage::open(root.clone()).unwrap();
        s.put(Some("demo/a"), vec![1], None, ts(10)).unwrap();
        break_persistence(&root);
        assert!(
            s.put(Some("demo/a"), vec![2], None, ts(20)).is_err(),
            "a put that could not be persisted must be reported to the caller"
        );
        assert_eq!(
            s.get(Some("demo/a")).map(|d| d.payload.clone()),
            Some(vec![1]),
            "a Durable store must keep serving the last value it actually \
             persisted, not one it failed to write"
        );
    }

    #[test]
    fn a_new_key_whose_first_persist_fails_is_not_served_at_all() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let mut s = FilesystemStorage::open(root.clone()).unwrap();
        break_persistence(&root);
        assert!(s.put(Some("demo/a"), vec![1], None, ts(10)).is_err());
        assert!(
            s.get(Some("demo/a")).is_none(),
            "a key that never reached the disk must not be readable"
        );
    }

    #[test]
    fn a_delete_whose_unlink_fails_keeps_serving_the_key() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let mut s = FilesystemStorage::open(root.clone()).unwrap();
        s.put(Some("demo/a"), vec![1], None, ts(10)).unwrap();
        // Replace the key's data file with a DIRECTORY of the same name:
        // `unlink` on a directory is an error for every uid, root included.
        let file = fs::read_dir(&root)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| is_our_key_filename(&p.file_name().unwrap().to_string_lossy()))
            .expect("the put allocated exactly one data file");
        fs::remove_file(&file).unwrap();
        fs::create_dir(&file).unwrap();
        assert!(
            s.delete(Some("demo/a"), ts(20)).is_err(),
            "a delete that could not remove the record must be reported"
        );
        assert!(
            s.get(Some("demo/a")).is_some(),
            "a key whose on-disk record the store could not remove is not deleted"
        );
    }

    // ---- file-format round-trip ----

    #[test]
    fn format_roundtrips_all_shapes() {
        let cases = vec![
            (
                Some("demo/a"),
                StoredData {
                    payload: vec![1, 2, 3],
                    encoding: enc(),
                    timestamp: ts(10),
                },
            ),
            (
                None,
                StoredData {
                    payload: vec![],
                    encoding: None,
                    timestamp: TimestampHint {
                        time: 0,
                        zid: vec![],
                    },
                },
            ),
            (
                Some(""),
                StoredData {
                    payload: vec![0; 300],
                    encoding: Some(EncodingHint {
                        packed_id: 0x2,
                        schema: None,
                    }),
                    timestamp: ts(u64::MAX),
                },
            ),
        ];
        for (key, data) in cases {
            let bytes = serialize(key, &data);
            let (k2, d2) = deserialize(&bytes).unwrap();
            assert_eq!(k2.as_deref(), key);
            assert_eq!(d2, data);
        }
    }

    #[test]
    fn deserialize_rejects_corruption() {
        let data = StoredData {
            payload: vec![1, 2, 3],
            encoding: enc(),
            timestamp: ts(10),
        };
        let good = serialize(Some("k"), &data);
        // bad magic
        let mut m = good.clone();
        m[0] ^= 0xff;
        assert!(deserialize(&m).is_err());
        // flipped payload byte -> checksum mismatch
        let mut c = good.clone();
        let n = c.len();
        c[n - 10] ^= 0xff;
        assert!(deserialize(&c).is_err());
        // truncated
        assert!(deserialize(&good[..good.len() - 3]).is_err());
        // trailing garbage (checksum now covers the extra byte -> also caught)
        assert!(deserialize(&[good.as_slice(), &[0u8]].concat()).is_err());
        // too short
        assert!(deserialize(&[0u8; 4]).is_err());
    }

    // ---- open-time robustness ----

    #[test]
    fn open_quarantines_corrupt_and_ignores_foreign() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        {
            let mut s = FilesystemStorage::open(root.clone()).unwrap();
            s.put(Some("good/key"), vec![7], None, ts(10)).unwrap();
        }
        // A file with an "ours" name (k + hex) but garbage content.
        let corrupt = root.join(format!("k{}", "0".repeat(16)));
        fs::write(&corrupt, b"not a valid record").unwrap();
        // A foreign file.
        fs::write(root.join("README.txt"), b"hello").unwrap();

        let s = FilesystemStorage::open(root.clone()).unwrap();
        // The good key survived; the whole store was not bricked.
        assert_eq!(s.get(Some("good/key")).unwrap().payload, vec![7]);
        // The corrupt file was quarantined; the foreign file was left as-is.
        assert!(root
            .join(quarantine_name(&format!("k{}", "0".repeat(16))))
            .exists());
        assert!(root.join("README.txt").exists());
    }

    #[test]
    fn open_recovers_after_single_file_corruption() {
        let dir = tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let file_of_b;
        {
            let mut s = FilesystemStorage::open(root.clone()).unwrap();
            s.put(Some("a"), vec![1], None, ts(10)).unwrap();
            s.put(Some("b"), vec![2], None, ts(11)).unwrap();
            file_of_b = s.map.get(&Some("b".to_string())).unwrap().file.clone();
        }
        // Corrupt exactly one key's file (flip a byte).
        let path = root.join(&file_of_b);
        let mut bytes = fs::read(&path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        fs::write(&path, &bytes).unwrap();

        let s = FilesystemStorage::open(root).unwrap();
        assert_eq!(
            s.get(Some("a")).unwrap().payload,
            vec![1],
            "sibling survives"
        );
        assert!(s.get(Some("b")).is_none(), "corrupt key quarantined");
    }

    // ---- Volume ----

    #[test]
    fn volume_capability_is_durable_latest() {
        let dir = tempdir().unwrap();
        let vol = FilesystemVolume::new(dir.path());
        assert_eq!(
            vol.capability(),
            Capability {
                persistence: Persistence::Durable,
                history: History::Latest,
            }
        );
    }

    #[test]
    fn volume_creates_durable_independent_storage() {
        let dir = tempdir().unwrap();
        let vol = FilesystemVolume::new(dir.path());
        let cfg = StorageConfig::new("demo", "demo/**", "fs");
        {
            let mut s = vol.create_storage(&cfg).unwrap();
            assert_eq!(
                s.put(Some("demo/a"), vec![1, 2, 3], None, ts(10)).unwrap(),
                StorageInsertionResult::Inserted
            );
        } // drop the backend, then re-create over the same name -> durable
        let s = vol.create_storage(&cfg).unwrap();
        assert_eq!(
            s.get(Some("demo/a")).unwrap().payload,
            vec![1, 2, 3],
            "a storage re-created over the same name reloads its data"
        );
        // A different name is a separate, empty store.
        let other = vol
            .create_storage(&StorageConfig::new("other", "o/**", "fs"))
            .unwrap();
        assert!(other.get(Some("demo/a")).is_none());
    }

    #[test]
    fn volume_rejects_unsafe_storage_name() {
        let dir = tempdir().unwrap();
        let vol = FilesystemVolume::new(dir.path());
        for bad in ["../evil", "/etc/passwd", "a/b", "..", "."] {
            let cfg = StorageConfig::new(bad, "k/**", "fs");
            assert!(
                matches!(vol.create_storage(&cfg), Err(VolumeError::CreateFailed(_))),
                "name {bad:?} must be rejected"
            );
        }
    }
}
